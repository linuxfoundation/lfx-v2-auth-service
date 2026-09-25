// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package k8s

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

const (
	// KindConfigMap is the kind of the ConfigMap
	KindConfigMap = "configmap"
	// KindSecret is the kind of the Secret
	KindSecret = "secret"
	// KindDaemonSet is the kind of the DaemonSet
	KindDaemonSet = "daemonSet"
)

// K8sOrchestrator is a wrapper around the Kubernetes client
type K8sOrchestrator struct {
	k8sClient kubernetes.Interface

	namespace     string
	configmapName string
	daemonSetName string
	secretName    string
}

func (k *K8sOrchestrator) ConfigMap(ctx context.Context, key string) (any, error) {

	slog.DebugContext(ctx, "loading users from ConfigMap",
		"configmap", k.configmapName,
		"namespace", k.namespace,
	)

	// Get ConfigMap
	configMap, err := k.k8sClient.CoreV1().ConfigMaps(k.namespace).Get(
		ctx, k.configmapName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get ConfigMap: %w", err)
	}

	data, exists := configMap.Data[key]
	if !exists {
		slog.InfoContext(ctx, "data not found in ConfigMap", "key", key)
		return data, errors.NewNotFound("data not found in ConfigMap")
	}

	return data, nil
}

func (k *K8sOrchestrator) Get(ctx context.Context, kind string, key any) (any, error) {

	switch kind {
	case KindConfigMap:
		return k.ConfigMap(ctx, key.(string))
	default:
		return nil, errors.NewUnexpected("unsupported kind")
	}
}

// RestartDaemonSet restarts the DaemonSet
func (k *K8sOrchestrator) RestartDaemonSet(ctx context.Context) error {
	if k.k8sClient == nil {
		return errors.NewUnexpected("kubernetes client not available")
	}

	client := k.k8sClient.AppsV1().DaemonSets(k.namespace)
	daemonSet, err := client.Get(ctx, k.daemonSetName, metav1.GetOptions{})
	if err != nil {
		return errors.NewUnexpected("failed to get DaemonSet", err)
	}

	// Add/update restart annotation to trigger rolling restart
	if daemonSet.Spec.Template.Annotations == nil {
		daemonSet.Spec.Template.Annotations = make(map[string]string)
	}

	// Use current timestamp as annotation value to trigger restart
	restartTime := time.Now().Format(time.RFC3339)
	daemonSet.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] = restartTime

	// Update the daemonset
	_, err = client.Update(ctx, daemonSet, metav1.UpdateOptions{})
	if err != nil {
		return errors.NewUnexpected("failed to update DaemonSet", err)
	}

	slog.DebugContext(ctx, "restarted DaemonSet", "name", k.daemonSetName)

	return nil
}

// UpdateSecrets updates only the specified entries in the secret
func (k *K8sOrchestrator) UpdateSecrets(ctx context.Context, changedEntries map[string][]byte) error {
	if k.k8sClient == nil {
		return errors.NewUnexpected("kubernetes client not available")
	}

	// Skip if no changes
	if len(changedEntries) == 0 {
		slog.DebugContext(ctx, "no changes to Secret, skipping update")
		return nil
	}

	// Get the existing Secret
	secretsClient := k.k8sClient.CoreV1().Secrets(k.namespace)
	existingSecret, errGet := secretsClient.Get(ctx, k.secretName, metav1.GetOptions{})
	if errGet != nil {
		return errors.NewUnexpected("failed to get Secret", errGet)
	}

	// Initialize data map if it doesn't exist
	if existingSecret.Data == nil {
		existingSecret.Data = make(map[string][]byte)
	}

	// Update changed entries
	for username, password := range changedEntries {
		existingSecret.Data[username] = password
	}

	// Update the secret
	_, errUpdate := secretsClient.Update(ctx, existingSecret, metav1.UpdateOptions{})
	if errUpdate != nil {
		return errors.NewUnexpected("failed to update Secret", errUpdate)
	}

	slog.DebugContext(ctx, "updated Secret", "name", k.secretName)

	return nil
}

// UpdateConfigMap updates the ConfigMap with the given YAML data
func (k *K8sOrchestrator) UpdateConfigMap(ctx context.Context, key string, yamlData []byte) error {

	if k.k8sClient == nil {
		return errors.NewUnexpected("kubernetes client not available")
	}

	client := k.k8sClient.CoreV1().ConfigMaps(k.namespace)

	configMap, err := client.Get(ctx, k.configmapName, metav1.GetOptions{})
	if err != nil {
		return errors.NewUnexpected("failed to get ConfigMap", err)
	}

	if configMap.Data == nil {
		configMap.Data = make(map[string]string)
	}
	configMap.Data[key] = string(yamlData)

	_, errUpdate := client.Update(ctx, configMap, metav1.UpdateOptions{})
	if errUpdate != nil {
		return errors.NewUnexpected("failed to update ConfigMap", errUpdate)
	}

	slog.DebugContext(ctx, "updated ConfigMap", "name", k.configmapName)

	return nil
}

func (k *K8sOrchestrator) Update(ctx context.Context, kind string, data ...any) error {

	switch kind {
	case KindConfigMap:

		for _, d := range data {
			if d, ok := d.(map[string][]byte); ok {
				for key, value := range d {

					slog.DebugContext(ctx, "updating ConfigMap",
						"name", k.configmapName,
						"key", key,
					)

					errUpdate := k.UpdateConfigMap(ctx, key, value)
					if errUpdate != nil {
						return errUpdate
					}
				}
			}
		}

	case KindSecret:

		for _, d := range data {
			if d, ok := d.(map[string][]byte); ok {

				slog.DebugContext(ctx, "updating Secrets",
					"name", k.secretName,
				)

				errUpdate := k.UpdateSecrets(ctx, d)
				if errUpdate != nil {
					return errUpdate
				}

			}
		}

	case KindDaemonSet:
		errRestart := k.RestartDaemonSet(ctx)
		if errRestart != nil {
			return errRestart
		}

	default:
		return errors.NewUnexpected("unsupported kind")
	}

	return nil
}

func (k *K8sOrchestrator) client(ctx context.Context) error {

	findConfig := func() (*rest.Config, error) {
		if _, exists := os.LookupEnv("KUBERNETES_SERVICE_HOST"); exists {
			slog.DebugContext(ctx, "using in-cluster Kubernetes config")
			return rest.InClusterConfig()
		}
		kubeconfigPath := os.Getenv("KUBECONFIG")
		if kubeconfigPath == "" {
			slog.DebugContext(ctx, "using local kubeconfig")
			if home := homedir.HomeDir(); home != "" {
				kubeconfigPath = filepath.Join(home, ".kube", "config")
			}
		}
		return clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	}

	k8sConfig, errFindConfig := findConfig()
	if errFindConfig != nil {
		return errors.NewUnexpected("failed to find Kubernetes config", errFindConfig)
	}

	// Create Kubernetes client if config was loaded successfully
	if k8sConfig != nil {
		k8sClient, errNewForConfig := kubernetes.NewForConfig(k8sConfig)
		if errNewForConfig != nil {
			return errors.NewUnexpected("failed to create Kubernetes client", errNewForConfig)
		}
		k.k8sClient = k8sClient
		return nil
	}

	return errors.NewUnexpected("failed to find Kubernetes config", errFindConfig)
}

// NewK8sOrchestrator creates a new k8s orchestrator with auto-configured Kubernetes client
func NewK8sOrchestrator(ctx context.Context, config map[string]string) (port.UserOrchestrator, error) {

	validate := func(attribute, input string) (string, error) {
		if input == "" {
			return "", errors.NewUnexpected(fmt.Sprintf("missing required configuration value: %s", attribute))
		}
		return input, nil
	}

	configmapName, err := validate("configmap-name", config["configmap-name"])
	if err != nil {
		return nil, err
	}

	namespace, err := validate("namespace", config["namespace"])
	if err != nil {
		return nil, err
	}

	daemonSetName, err := validate("daemon-set-name", config["daemon-set-name"])
	if err != nil {
		return nil, err
	}

	secretName, err := validate("secret-name", config["secret-name"])
	if err != nil {
		return nil, err
	}

	k := &K8sOrchestrator{
		configmapName: configmapName,
		namespace:     namespace,
		daemonSetName: daemonSetName,
		secretName:    secretName,
	}

	errClient := k.client(ctx)
	if errClient != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", errClient)
	}

	return k, nil
}
