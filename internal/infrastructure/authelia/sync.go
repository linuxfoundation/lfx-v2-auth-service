// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package authelia

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/concurrent"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/password"
	"go.yaml.in/yaml/v2"
)

const (
	actionNeededOrchestratorCreation = "orchestrator_creation"
	actionNeededOrchestratorUpdate   = "orchestrator_update"
	actionNeededStorageCreation      = "storage_creation"
	actionNeededNone                 = "none"
)

type sync struct {
	usersStorageMap     map[string]*AutheliaUser
	userOrchestratorMap map[string]*AutheliaUser
}

func (s *sync) compareUsers(storage, orchestrator map[string]*AutheliaUser) map[string]*AutheliaUser {

	merged := make(map[string]*AutheliaUser)

	// If any record in the storage is missing in the orchestrator,
	// we will need to recreate the configmap and restart the daemonset
	for key, user := range storage {
		user.SetUsername(key)
		orchestratorUser, exists := orchestrator[key]
		if !exists {
			user.actionNeeded = actionNeededOrchestratorCreation
			merged[key] = user
			continue
		}

		// Email from the storage takes precedence over the primary email from the orchestrator
		if user.Email != orchestratorUser.Email {
			user.actionNeeded = actionNeededOrchestratorUpdate
			merged[key] = user
			continue
		}

		// No changes needed
		user.actionNeeded = actionNeededNone
		if merged[key] != nil && merged[key].actionNeeded != "" {
			user.actionNeeded = merged[key].actionNeeded
		}
		merged[key] = user
	}

	// Add users from orchestrator if not present in storage
	for key, user := range orchestrator {
		user.SetUsername(key)
		_, exists := storage[key]
		if !exists {
			user.actionNeeded = actionNeededStorageCreation
			merged[key] = user
			continue
		}

		// differences are already handled above
		user.actionNeeded = actionNeededNone
		if merged[key] != nil && merged[key].actionNeeded != "" {
			user.actionNeeded = merged[key].actionNeeded
		}
		merged[key] = user
	}

	return merged

}

func (s *sync) loadUsers(ctx context.Context, storage internalStorageReaderWriter, orchestrator internalOrchestrator) error {

	functions := []func() error{
		// get users from NATS KV
		func() error {
			usersStorageMap, errListUsers := storage.ListUsers(ctx)
			if errListUsers != nil {
				slog.ErrorContext(ctx, "failed to list users from storage", "error", errListUsers)
				return errListUsers
			}
			s.usersStorageMap = usersStorageMap
			return nil
		},

		// get users from ConfigMap
		func() error {
			userOrchestratorMap, errConfigMap := orchestrator.LoadUsersOrigin(ctx)
			if errConfigMap != nil {
				slog.ErrorContext(ctx, "failed to load users from ConfigMap", "error", errConfigMap)
				return errConfigMap
			}
			userAutheliaOrchestratorMap := make(map[string]*AutheliaUser)
			for _, users := range userOrchestratorMap {

				usersList, ok := users.(map[string]any)
				if !ok {
					slog.ErrorContext(ctx, "invalid users format from ConfigMap")
					return errors.NewUnexpected("invalid users format from ConfigMap")
				}

				for key, user := range usersList {

					bytes, errMarshal := json.Marshal(user)
					if errMarshal != nil {
						slog.ErrorContext(ctx, "failed to marshal user from ConfigMap",
							"error", errMarshal,
							"key", key,
						)
						return errors.NewUnexpected("failed to marshal user from ConfigMap", errMarshal)
					}
					var autheliaUser AutheliaUser
					errUnmarshal := json.Unmarshal(bytes, &autheliaUser)
					if errUnmarshal != nil {
						slog.ErrorContext(ctx, "failed to unmarshal user from ConfigMap",
							"error", errUnmarshal,
							"key", key,
						)
						return errors.NewUnexpected("failed to unmarshal user from ConfigMap", errUnmarshal)
					}
					userAutheliaOrchestratorMap[key] = &autheliaUser
				}
			}
			s.userOrchestratorMap = userAutheliaOrchestratorMap
			return nil
		},
	}

	return concurrent.NewWorkerPool(len(functions)).Run(ctx, functions...)
}

func (s *sync) syncUsers(ctx context.Context, storage internalStorageReaderWriter, orchestrator internalOrchestrator) error {

	errLoadUsers := s.loadUsers(ctx, storage, orchestrator)
	if errLoadUsers != nil {
		slog.ErrorContext(ctx, "failed to load users", "error", errLoadUsers)
		return errLoadUsers
	}

	updateOrchestratorOrigin := false
	changedSecretsEntries := make(map[string][]byte)

	usersToSync := s.compareUsers(s.usersStorageMap, s.userOrchestratorMap)
	for username, user := range usersToSync {
		slog.DebugContext(ctx, "user needs action",
			"username", username,
			"action", user.actionNeeded,
		)

		switch user.actionNeeded {
		case actionNeededStorageCreation:
			_, errUpdate := storage.SetUser(ctx, user)
			if errUpdate != nil {
				slog.ErrorContext(ctx, "failed to update user in storage", "error", errUpdate)
				return errors.NewUnexpected("failed to update user in storage", errUpdate)
			}
		case actionNeededOrchestratorCreation, actionNeededOrchestratorUpdate:

			// if the user is being created, we need to generate a new password
			// to be able to save the plain password in the Secrets
			plainPassword, bcryptHash, errGeneratePasswordPair := password.GeneratePasswordPair(20)
			if errGeneratePasswordPair != nil {
				slog.ErrorContext(ctx, "failed to generate password pair", "error", errGeneratePasswordPair)
				return errors.NewUnexpected("failed to generate password pair", errGeneratePasswordPair)
			}
			user.Password = bcryptHash

			changedSecretsEntries[username] = []byte(plainPassword)

			// update the user in the storage
			_, errUpdate := storage.SetUser(ctx, user)
			if errUpdate != nil {
				slog.ErrorContext(ctx, "failed to update user in storage", "error", errUpdate)
				return errors.NewUnexpected("failed to update user in storage", errUpdate)
			}

			updateOrchestratorOrigin = true

		}
	}

	if updateOrchestratorOrigin {
		// Convert users to Authelia YAML format
		autheliaFormat := convertUsersToAutheliaFormat(usersToSync)

		var buf strings.Builder
		encoder := yaml.NewEncoder(&buf)
		defer encoder.Close()
		if err := encoder.Encode(autheliaFormat); err != nil {
			return errors.NewUnexpected("failed to marshal YAML", err)
		}

		errUpdate := orchestrator.UpdateOrigin(ctx, []byte(buf.String()))
		if errUpdate != nil {
			slog.ErrorContext(ctx, "failed to update origin in orchestrator", "error", errUpdate)
			return errors.NewUnexpected("failed to update origin in orchestrator", errUpdate)
		}

		if len(changedSecretsEntries) > 0 {
			errUpdate := orchestrator.UpdateSecrets(ctx, changedSecretsEntries)
			if errUpdate != nil {
				slog.ErrorContext(ctx, "failed to update secrets in orchestrator", "error", errUpdate)
				return errors.NewUnexpected("failed to update secrets in orchestrator", errUpdate)
			}
		}

		errRestart := orchestrator.RestartOrigin(ctx)
		if errRestart != nil {
			slog.ErrorContext(ctx, "failed to restart origin in orchestrator", "error", errRestart)
			return errors.NewUnexpected("failed to restart origin in orchestrator", errRestart)
		}
	}

	return nil
}
