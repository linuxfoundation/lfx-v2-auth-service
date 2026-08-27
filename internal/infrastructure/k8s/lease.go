// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package k8s

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
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

// RunAsLeader runs fn on exactly one replica at a time.
//
// fn is given a context cancelled the moment leadership is lost, so whatever
// it owns must stop when that context is done. It may be called again if this
// replica reacquires the lease. RunAsLeader returns when ctx is cancelled.
func RunAsLeader(ctx context.Context, config LeaseConfig, fn func(context.Context)) error {
	if config.Name == "" || config.Namespace == "" || config.Identity == "" {
		return errors.NewValidation("lease name, namespace and identity are all required")
	}

	client, err := newClient(ctx)
	if err != nil {
		return err
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

	elector, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock:          lock,
		LeaseDuration: leaseDuration,
		RenewDeadline: renewDeadline,
		RetryPeriod:   retryPeriod,
		// A pod that is shutting down should hand the lease over rather than
		// let its peers wait out the full duration.
		ReleaseOnCancel: true,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: fn,
			OnStoppedLeading: func() {
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
		return errors.NewUnexpected("failed to create the leader elector", err)
	}

	elector.Run(ctx)
	return nil
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

func newClient(ctx context.Context) (kubernetes.Interface, error) {
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
