// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package k8s

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
)

func TestPodIdentity(t *testing.T) {
	t.Run("POD_NAME wins over the hostname", func(t *testing.T) {
		t.Setenv("POD_NAME", "auth-service-abc123")

		assert.Equal(t, "auth-service-abc123", PodIdentity())
	})

	t.Run("falls back to the hostname when POD_NAME is unset", func(t *testing.T) {
		t.Setenv("POD_NAME", "")

		host, err := os.Hostname()
		require.NoError(t, err)
		require.NotEmpty(t, host, "this test needs a resolvable hostname")

		assert.Equal(t, host, PodIdentity())
	})

	t.Run("never returns empty, because an empty identity cannot hold a lease", func(t *testing.T) {
		t.Setenv("POD_NAME", "")

		assert.NotEmpty(t, PodIdentity())
	})
}

func TestPodNamespace(t *testing.T) {
	t.Run("POD_NAMESPACE wins over the service-account file", func(t *testing.T) {
		t.Setenv("POD_NAMESPACE", "lfx-staging")

		assert.Equal(t, "lfx-staging", PodNamespace())
	})

	t.Run("is empty off-cluster, which the caller reads as do-not-start", func(t *testing.T) {
		t.Setenv("POD_NAMESPACE", "")

		// The service-account path does not exist outside a pod. If it somehow
		// does, the value it holds is the correct answer and not a failure.
		const serviceAccountNamespace = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
		if _, err := os.Stat(serviceAccountNamespace); err == nil {
			t.Skip("running inside a pod, so the fallback file is present")
		}

		assert.Empty(t, PodNamespace())
	})
}

func TestRunAsLeaderValidation(t *testing.T) {
	// Validation is the one failure retrying cannot fix, so it must return
	// rather than spin. Each case would otherwise reach the API server.
	cases := []struct {
		name   string
		config LeaseConfig
	}{
		{"no name", LeaseConfig{Namespace: "lfx", Identity: "pod-1"}},
		{"no namespace", LeaseConfig{Name: "lease", Identity: "pod-1"}},
		{"no identity", LeaseConfig{Name: "lease", Namespace: "lfx"}},
		{"nothing set", LeaseConfig{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false

			err := RunAsLeader(t.Context(), tc.config, func(context.Context) { called = true })

			require.Error(t, err, "an unusable config must be reported, not retried forever")
			assert.False(t, called, "fn must never run without a lease")
		})
	}
}

func TestRunAsLeaderReturnsOnCancelledContext(t *testing.T) {
	// A context that is already done must not enter the loop at all: the
	// caller runs this fire-and-forget, so a hang here would be invisible.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	config := LeaseConfig{Name: "lease", Namespace: "lfx", Identity: "pod-1"}
	called := false

	done := make(chan error, 1)
	go func() {
		done <- RunAsLeader(ctx, config, func(context.Context) { called = true })
	}()

	select {
	case err := <-done:
		assert.NoError(t, err, "a cancelled context is an ordinary shutdown")
		assert.False(t, called)
	case <-time.After(5 * time.Second):
		t.Fatal("RunAsLeader did not return on a cancelled context")
	}
}

func TestWaitBeforeRejoin(t *testing.T) {
	t.Run("returns early when the context ends", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		start := time.Now()
		waitBeforeRejoin(ctx)

		assert.Less(t, time.Since(start), rejoinDelay,
			"a shutdown must not wait out the full rejoin delay")
	})
}

// withNewClient swaps the clientset factory for the duration of a test.
func withNewClient(t *testing.T, fn func(context.Context) (kubernetes.Interface, error)) {
	t.Helper()
	original := newClient
	newClient = fn
	t.Cleanup(func() { newClient = original })
}

func testLease() LeaseConfig {
	return LeaseConfig{Name: "test-lease", Namespace: "lfx", Identity: "pod-1"}
}

func TestRunAsLeaderRunsFnUnderLeadership(t *testing.T) {
	withNewClient(t, func(context.Context) (kubernetes.Interface, error) {
		return fake.NewSimpleClientset(), nil
	})

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	var (
		mu      sync.Mutex
		runs    int
		running bool
		overlap bool
	)
	led := make(chan struct{})

	done := make(chan error, 1)
	go func() {
		done <- RunAsLeader(ctx, testLease(), func(leaderCtx context.Context) {
			mu.Lock()
			runs++
			if running {
				overlap = true
			}
			running = true
			first := runs == 1
			mu.Unlock()

			if first {
				close(led)
			}
			<-leaderCtx.Done()

			mu.Lock()
			running = false
			mu.Unlock()
		})
	}()

	select {
	case <-led:
	case <-time.After(20 * time.Second):
		t.Fatal("never acquired leadership against the fake clientset")
	}

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(20 * time.Second):
		t.Fatal("RunAsLeader did not return after cancellation")
	}

	mu.Lock()
	defer mu.Unlock()
	assert.False(t, overlap, "fn must never run twice concurrently on one pod")
	assert.False(t, running, "RunAsLeader must wait for fn to unwind before returning")
	assert.GreaterOrEqual(t, runs, 1)
}

func TestRunAsLeaderRetriesClientConstruction(t *testing.T) {
	// The point of the refactor: a one-time failure building the clientset
	// must not retire the pod from the election for the rest of its life.
	var attempts atomic.Int32
	withNewClient(t, func(context.Context) (kubernetes.Interface, error) {
		if attempts.Add(1) == 1 {
			return nil, errors.NewUnexpected("transient: service account token not mounted yet")
		}
		return fake.NewSimpleClientset(), nil
	})

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	led := make(chan struct{})
	var once sync.Once

	done := make(chan error, 1)
	go func() {
		done <- RunAsLeader(ctx, testLease(), func(leaderCtx context.Context) {
			once.Do(func() { close(led) })
			<-leaderCtx.Done()
		})
	}()

	select {
	case <-led:
	case err := <-done:
		t.Fatalf("returned instead of retrying the client build: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("never recovered from the first client-build failure")
	}

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(20 * time.Second):
		t.Fatal("RunAsLeader did not return after cancellation")
	}

	assert.GreaterOrEqual(t, attempts.Load(), int32(2), "the failed build must be retried, not returned")
}
