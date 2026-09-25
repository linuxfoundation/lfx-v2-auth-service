// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package authelia

import (
	"context"
	"fmt"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/k8s"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"gopkg.in/yaml.v3"
)

// UserOrchestrator defines the behavior of the orchestrator which is responsible
// for syncing users within the environment
//
// They are required only in the Authelia context
type internalOrchestrator interface {
	LoadUsersOrigin(ctx context.Context) (map[string]any, error)
	UpdateOrigin(ctx context.Context, yamlData []byte) error
	RestartOrigin(ctx context.Context) error
	UpdateSecrets(ctx context.Context, secretData map[string][]byte) error
}

type k8sOrchestrator struct {
	config       map[string]string
	orchestrator port.UserOrchestrator
}

func (k *k8sOrchestrator) LoadUsersOrigin(ctx context.Context) (map[string]any, error) {

	usersFile, errGetUsersFile := k.orchestrator.Get(ctx, k8s.KindConfigMap, "users_database.yml")
	if errGetUsersFile != nil {
		return nil, errGetUsersFile
	}
	userFileStr, ok := usersFile.(string)
	if !ok {
		return nil, errors.NewUnexpected("invalid users file format")
	}

	var users map[string]any
	if err := yaml.Unmarshal([]byte(userFileStr), &users); err != nil {
		return nil, fmt.Errorf("failed to unmarshal users file: %w", err)
	}

	return users, nil

}

func (k *k8sOrchestrator) UpdateOrigin(ctx context.Context, yamlData []byte) error {

	errUpdate := k.orchestrator.Update(ctx, k8s.KindConfigMap, map[string][]byte{
		"users_database.yml": yamlData,
	})
	if errUpdate != nil {
		return errUpdate
	}

	return nil
}

func (k *k8sOrchestrator) RestartOrigin(ctx context.Context) error {

	errRestart := k.orchestrator.Update(ctx, k8s.KindDaemonSet)
	if errRestart != nil {
		return errRestart
	}

	return nil
}

func (k *k8sOrchestrator) UpdateSecrets(ctx context.Context, secretData map[string][]byte) error {

	errUpdate := k.orchestrator.Update(ctx, k8s.KindSecret, secretData)
	if errUpdate != nil {
		return errUpdate
	}

	return nil
}

func newK8sUserOrchestrator(ctx context.Context, config map[string]string) (internalOrchestrator, error) {

	k := &k8sOrchestrator{
		config: config,
	}

	orchestrator, errNewK8sOrchestrator := k8s.NewK8sOrchestrator(ctx, config)
	if errNewK8sOrchestrator != nil {
		return nil, errNewK8sOrchestrator
	}
	k.orchestrator = orchestrator

	return k, nil
}
