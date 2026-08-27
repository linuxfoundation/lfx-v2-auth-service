// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package k8s

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
