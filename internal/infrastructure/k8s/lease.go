// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package k8s

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/util/homedir"

	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
)

// LeaseConfig identifies the lease a group of replicas competes for.
type LeaseConfig struct {
	// Name of the Lease object.
	Name string

	// Namespace the Lease lives in.
	Namespace string

	// Identity distinguishes this replica from its peers. It must be unique
	// per pod, so it is the pod name.
	Identity string
}

// Lease durations. A holder renews every RetryPeriod and must renew within
// RenewDeadline or it stops; a peer may only take over after LeaseDuration.
// The gap between RenewDeadline and LeaseDuration is what stops two replicas
// believing they hold it at once.
const (
	leaseDuration = 15 * time.Second
	renewDeadline = 10 * time.Second
	retryPeriod   = 2 * time.Second
)

// rejoinDelay spaces out re-entry into the election after leadership is lost,
// so a replica that cannot reach the API server does not spin against it.
const rejoinDelay = 5 * time.Second

// RunAsLeader runs fn on exactly one replica at a time.
//
// fn is given a context cancelled the moment leadership is lost, so whatever
// it owns must stop when that context is done. It may be called again if this
// replica reacquires the lease. RunAsLeader returns when ctx is cancelled, or
// immediately if config is invalid — the one failure retrying cannot fix.
func RunAsLeader(ctx context.Context, config LeaseConfig, fn func(context.Context)) error {
	if config.Name == "" || config.Namespace == "" || config.Identity == "" {
		return errors.NewValidation("lease name, namespace and identity are all required")
	}

	// Held across iterations so a working client is not rebuilt every round,
	// and rebuilt only after one could not be made.
	var client kubernetes.Interface

	// Run returns whenever this replica stops holding the lease, not only when
	// ctx ends. Returning with it would retire the pod from the election for
	// the rest of its life over one failed renewal, and a shared API-server
	// blip would do that to every replica at once, leaving the stream unread
	// with nothing reporting an error. Re-entering keeps it a candidate.
	//
	// Client and elector construction are retried in here for the same reason:
	// the caller runs this fire-and-forget, so a slow-mounted service-account
	// token or a cold API-server DNS lookup at startup would otherwise disable
	// provisioning for the life of the pod behind a single log line.
	for ctx.Err() == nil {
		if client == nil {
			built, err := newClient(ctx)
			if err != nil {
				slog.ErrorContext(ctx, "failed to build the Kubernetes client, retrying",
					"lease", config.Name,
					"error", err,
					"after", rejoinDelay,
				)
				waitBeforeRejoin(ctx)
				continue
			}
			client = built
		}

		lock := &resourcelock.LeaseLock{
			LeaseMeta: metav1.ObjectMeta{
				Name:      config.Name,
				Namespace: config.Namespace,
			},
			Client: client.CoordinationV1(),
			LockConfig: resourcelock.ResourceLockConfig{
				Identity: config.Identity,
			},
		}

		// client-go runs OnStartedLeading in a goroutine and does not wait for
		// it when Run returns, so fn may still be unwinding — it can be inside
		// a call that takes seconds to time out. Rejoining before it returns
		// would put two of them on one pod, which is the thing the lease is
		// here to prevent.
		var (
			stopped = make(chan struct{})
			led     atomic.Bool
		)

		elector, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
			Lock:          lock,
			LeaseDuration: leaseDuration,
			RenewDeadline: renewDeadline,
			RetryPeriod:   retryPeriod,
			// A pod that is shutting down should hand the lease over rather
			// than let its peers wait out the full duration.
			ReleaseOnCancel: true,
			Callbacks: leaderelection.LeaderCallbacks{
				OnStartedLeading: func(leaderCtx context.Context) {
					led.Store(true)
					defer close(stopped)
					fn(leaderCtx)
				},
				OnStoppedLeading: func() {
					// client-go calls this whenever the elector exits, including
					// on a standby replica that never led.
					if !led.Load() {
						return
					}
					slog.WarnContext(ctx, "lost leadership", "lease", config.Name, "identity", config.Identity)
				},
				OnNewLeader: func(identity string) {
					if identity == config.Identity {
						return
					}
					slog.InfoContext(ctx, "standing by, another replica holds the lease",
						"lease", config.Name,
						"leader", identity,
					)
				},
			},
		})
		if err != nil {
			slog.ErrorContext(ctx, "failed to create the leader elector, retrying",
				"lease", config.Name,
				"error", err,
				"after", rejoinDelay,
			)
			waitBeforeRejoin(ctx)
			continue
		}

		elector.Run(ctx)

		// Waited for on shutdown as well as before rejoining. ReleaseOnCancel
		// hands the lease over as soon as ctx ends, so returning while fn is
		// still unwinding would let the next holder start alongside it —
		// the same overlap, just across pods instead of within one.
		//
		// led can still be false for the instant between client-go creating
		// the callback goroutine and it running, but fn has not started in
		// that window and the context it will get is already cancelled, so
		// there is nothing to overlap with.
		if led.Load() {
			<-stopped
		}

		if ctx.Err() != nil {
			break
		}

		slog.InfoContext(ctx, "rejoining the lease election",
			"lease", config.Name,
			"identity", config.Identity,
			"after", rejoinDelay,
		)
		waitBeforeRejoin(ctx)
	}

	return nil
}

// waitBeforeRejoin spaces out re-entry, returning early if ctx ends first.
func waitBeforeRejoin(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-time.After(rejoinDelay):
	}
}

// PodIdentity returns a value unique to this pod, for use as a lease identity.
func PodIdentity() string {
	if name := os.Getenv("POD_NAME"); name != "" {
		return name
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		return host
	}
	return "unknown"
}

// PodNamespace returns the namespace this pod runs in.
func PodNamespace() string {
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		return ns
	}
	const serviceAccountNamespace = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	if data, err := os.ReadFile(serviceAccountNamespace); err == nil {
		return string(data)
	}
	return ""
}

// newClient is a variable so tests can substitute a fake clientset and drive a
// real election through the retry and rejoin branches, which are otherwise
// unreachable without a cluster.
var newClient = func(ctx context.Context) (kubernetes.Interface, error) {
	config, err := restConfig(ctx)
	if err != nil {
		return nil, errors.NewUnexpected("failed to find Kubernetes config", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, errors.NewUnexpected("failed to create Kubernetes client", err)
	}
	return client, nil
}

func restConfig(ctx context.Context) (*rest.Config, error) {
	if _, inCluster := os.LookupEnv("KUBERNETES_SERVICE_HOST"); inCluster {
		slog.DebugContext(ctx, "using in-cluster Kubernetes config")
		return rest.InClusterConfig()
	}

	kubeconfigPath := os.Getenv("KUBECONFIG")
	if kubeconfigPath == "" {
		if home := homedir.HomeDir(); home != "" {
			kubeconfigPath = filepath.Join(home, ".kube", "config")
		}
	}
	return clientcmd.BuildConfigFromFlags("", kubeconfigPath)
}
