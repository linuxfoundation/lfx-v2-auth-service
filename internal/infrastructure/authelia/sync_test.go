// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package authelia

import (
	"context"
	"errors"
	"testing"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
)

// Mock implementations for testing
type mockStorageReaderWriter struct {
	users            map[string]*AutheliaUser
	getUserErr       error
	listErr          error
	setErr           error
	setUserLookupErr error
}

func (m *mockStorageReaderWriter) GetUser(ctx context.Context, key string) (*AutheliaUser, error) {
	if m.getUserErr != nil {
		return nil, m.getUserErr
	}
	if key == "" {
		return nil, errors.New("key is required")
	}
	if foundUser, exists := m.users[key]; exists {
		return foundUser, nil
	}
	return nil, errors.New("user not found")
}

func (m *mockStorageReaderWriter) BuildLookupKey(ctx context.Context, lookupKey, key string) string {
	// Simple mock implementation - just concatenate with a separator
	return lookupKey + ":" + key
}

func (m *mockStorageReaderWriter) ListUsers(ctx context.Context) (map[string]*AutheliaUser, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.users, nil
}

func (m *mockStorageReaderWriter) SetUser(ctx context.Context, user *AutheliaUser) (any, error) {
	if m.setErr != nil {
		return nil, m.setErr
	}
	if m.users == nil {
		m.users = make(map[string]*AutheliaUser)
	}
	m.users[user.Username] = user
	return "success", nil
}

func (m *mockStorageReaderWriter) GetUserWithRevision(ctx context.Context, key string) (*AutheliaUser, uint64, error) {
	user, err := m.GetUser(ctx, key)
	if err != nil {
		return nil, 0, err
	}
	return user, 1, nil // Return revision 1 for testing
}

func (m *mockStorageReaderWriter) UpdateUserWithRevision(ctx context.Context, user *AutheliaUser, revision uint64) error {
	if m.setErr != nil {
		return m.setErr
	}
	if m.users == nil {
		m.users = make(map[string]*AutheliaUser)
	}
	m.users[user.Username] = user
	return nil
}

func (m *mockStorageReaderWriter) CreateVerificationCode(ctx context.Context, email, otp string) error {
	return nil
}

func (m *mockStorageReaderWriter) GetVerificationCode(ctx context.Context, email string) (string, error) {
	return "123456", nil
}

type mockOrchestrator struct {
	users               map[string]any
	loadErr             error
	updateOriginErr     error
	updateSecretsErr    error
	restartErr          error
	updateOriginCalled  bool
	updateSecretsCalled bool
	restartCalled       bool
	lastYAMLData        []byte
	lastSecretData      map[string][]byte
	setUserLookupErr    error
}

func (m *mockOrchestrator) LoadUsersOrigin(ctx context.Context) (map[string]any, error) {
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	return m.users, nil
}

func (m *mockOrchestrator) UpdateOrigin(ctx context.Context, yamlData []byte) error {
	m.updateOriginCalled = true
	m.lastYAMLData = yamlData
	return m.updateOriginErr
}

func (m *mockOrchestrator) RestartOrigin(ctx context.Context) error {
	m.restartCalled = true
	return m.restartErr
}

func (m *mockOrchestrator) UpdateSecrets(ctx context.Context, secretData map[string][]byte) error {
	m.updateSecretsCalled = true
	m.lastSecretData = secretData
	return m.updateSecretsErr
}

func TestSync_CompareUsers(t *testing.T) {
	tests := []struct {
		name         string
		storage      map[string]*AutheliaUser
		orchestrator map[string]*AutheliaUser
		expected     map[string]string // username -> expected action
	}{
		{
			name: "user missing from orchestrator",
			storage: map[string]*AutheliaUser{
				"user1": {
					User:  &model.User{Username: "user1", PrimaryEmail: "user1@example.com"},
					Email: "user1@example.com",
				},
			},
			orchestrator: map[string]*AutheliaUser{},
			expected: map[string]string{
				"user1": actionNeededOrchestratorCreation,
			},
		},
		{
			name:    "user missing from storage",
			storage: map[string]*AutheliaUser{},
			orchestrator: map[string]*AutheliaUser{
				"user1": {
					User:  &model.User{Username: "user1"},
					Email: "user1@example.com",
				},
			},
			expected: map[string]string{
				"user1": actionNeededStorageCreation,
			},
		},
		{
			name: "email mismatch requires update",
			storage: map[string]*AutheliaUser{
				"user1": {
					User:  &model.User{Username: "user1", PrimaryEmail: "new@example.com"},
					Email: "new@example.com",
				},
			},
			orchestrator: map[string]*AutheliaUser{
				"user1": {
					User:  &model.User{Username: "user1"},
					Email: "old@example.com", // Different email
				},
			},
			expected: map[string]string{
				"user1": actionNeededOrchestratorUpdate,
			},
		},
		{
			name: "no changes needed",
			storage: map[string]*AutheliaUser{
				"user1": {
					User:     &model.User{Username: "user1", PrimaryEmail: "user1@example.com"},
					Password: "hash1",
					Email:    "user1@example.com",
				},
			},
			orchestrator: map[string]*AutheliaUser{
				"user1": {
					User:     &model.User{Username: "user1"},
					Password: "hash1",
					Email:    "user1@example.com",
				},
			},
			expected: map[string]string{
				"user1": actionNeededNone,
			},
		},
		{
			name: "multiple users with different actions",
			storage: map[string]*AutheliaUser{
				"user1": {
					User:  &model.User{Username: "user1", PrimaryEmail: "user1@example.com"},
					Email: "user1@example.com",
				},
				"user2": {
					User:     &model.User{Username: "user2", PrimaryEmail: "user2@example.com"},
					Password: "hash2",
					Email:    "user2@example.com",
				},
			},
			orchestrator: map[string]*AutheliaUser{
				"user1": {
					User:  &model.User{Username: "user1"},
					Email: "user1@example.com",
				},
				"user3": {
					User:  &model.User{Username: "user3"},
					Email: "user3@example.com",
				},
			},
			expected: map[string]string{
				"user1": actionNeededNone,                 // No changes
				"user2": actionNeededOrchestratorCreation, // Missing from orchestrator
				"user3": actionNeededStorageCreation,      // Missing from storage
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &sync{}
			result := s.compareUsers(tt.storage, tt.orchestrator)

			if len(result) != len(tt.expected) {
				t.Errorf("compareUsers() returned %d users, want %d", len(result), len(tt.expected))
			}

			for username, expectedAction := range tt.expected {
				user, exists := result[username]
				if !exists {
					t.Errorf("compareUsers() missing user %q", username)
					continue
				}

				if user.actionNeeded != expectedAction {
					t.Errorf("compareUsers() user %q action = %q, want %q", username, user.actionNeeded, expectedAction)
				}

				// Verify username is set correctly
				if user.Username != username {
					t.Errorf("compareUsers() user %q username = %q, want %q", username, user.Username, username)
				}
			}
		})
	}
}

func TestSync_LoadUsers(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name               string
		storageUsers       map[string]*AutheliaUser
		storageErr         error
		orchestratorUsers  map[string]any
		orchestratorErr    error
		expectError        bool
		expectedStorageLen int
		expectedOrchLen    int
	}{
		{
			name: "successful load from both sources",
			storageUsers: map[string]*AutheliaUser{
				"user1": {
					User:     &model.User{Username: "user1"},
					Password: "hash1",
				},
			},
			orchestratorUsers: map[string]any{
				"users": map[string]any{
					"user2": map[string]any{
						"password":    "hash2",
						"email":       "user2@example.com",
						"displayname": "User Two",
					},
				},
			},
			expectError:        false,
			expectedStorageLen: 1,
			expectedOrchLen:    1,
		},
		{
			name:         "storage error",
			storageUsers: nil,
			storageErr:   errors.New("storage failed"),
			orchestratorUsers: map[string]any{
				"users": map[string]any{},
			},
			expectError: true,
		},
		{
			name: "orchestrator error",
			storageUsers: map[string]*AutheliaUser{
				"user1": {User: &model.User{Username: "user1"}},
			},
			orchestratorUsers: nil,
			orchestratorErr:   errors.New("orchestrator failed"),
			expectError:       true,
		},
		{
			name: "invalid orchestrator format",
			storageUsers: map[string]*AutheliaUser{
				"user1": {User: &model.User{Username: "user1"}},
			},
			orchestratorUsers: map[string]any{
				"users": "invalid_format", // Should be map[string]any
			},
			expectError: true,
		},
		{
			name:               "empty sources",
			storageUsers:       map[string]*AutheliaUser{},
			orchestratorUsers:  map[string]any{"users": map[string]any{}},
			expectError:        false,
			expectedStorageLen: 0,
			expectedOrchLen:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &sync{}

			mockStorage := &mockStorageReaderWriter{
				users:   tt.storageUsers,
				listErr: tt.storageErr,
			}

			mockOrch := &mockOrchestrator{
				users:   tt.orchestratorUsers,
				loadErr: tt.orchestratorErr,
			}

			err := s.loadUsers(ctx, mockStorage, mockOrch)

			if tt.expectError {
				if err == nil {
					t.Error("loadUsers() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("loadUsers() unexpected error: %v", err)
				return
			}

			if len(s.usersStorageMap) != tt.expectedStorageLen {
				t.Errorf("loadUsers() storage map length = %d, want %d", len(s.usersStorageMap), tt.expectedStorageLen)
			}

			if len(s.userOrchestratorMap) != tt.expectedOrchLen {
				t.Errorf("loadUsers() orchestrator map length = %d, want %d", len(s.userOrchestratorMap), tt.expectedOrchLen)
			}
		})
	}
}

func TestSync_SyncUsers(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name                string
		storageUsers        map[string]*AutheliaUser
		orchestratorUsers   map[string]any
		expectUpdateOrigin  bool
		expectUpdateSecrets bool
		expectRestart       bool
		expectError         bool
		storageErr          error
		updateOriginErr     error
		updateSecretsErr    error
		restartErr          error
		setUserLookupErr    error
	}{
		{
			name: "no sync needed - users match",
			storageUsers: map[string]*AutheliaUser{
				"user1": {
					User:     &model.User{Username: "user1", PrimaryEmail: "user1@example.com"},
					Password: "hash1",
					Email:    "user1@example.com",
				},
			},
			orchestratorUsers: map[string]any{
				"users": map[string]any{
					"user1": map[string]any{
						"password":    "hash1",
						"email":       "user1@example.com",
						"displayname": "User One",
					},
				},
			},
			expectUpdateOrigin:  false,
			expectUpdateSecrets: false,
			expectRestart:       false,
			expectError:         false,
			setUserLookupErr:    nil,
		},
		{
			name: "sync needed - user missing from orchestrator",
			storageUsers: map[string]*AutheliaUser{
				"user1": {
					User:     &model.User{Username: "user1", PrimaryEmail: "user1@example.com"},
					Password: "hash1",
					Email:    "user1@example.com",
				},
			},
			orchestratorUsers: map[string]any{
				"users": map[string]any{},
			},
			expectUpdateOrigin:  true,
			expectUpdateSecrets: true,
			expectRestart:       true,
			expectError:         false,
			setUserLookupErr:    nil,
		},
		{
			name: "sync needed - password mismatch",
			storageUsers: map[string]*AutheliaUser{
				"user1": {
					User:     &model.User{Username: "user1", PrimaryEmail: "user1@example.com"},
					Password: "hash1",
					Email:    "user1@example.com",
				},
			},
			orchestratorUsers: map[string]any{
				"users": map[string]any{
					"user1": map[string]any{
						"password":    "different_hash",
						"email":       "user1@example.com",
						"displayname": "User One",
					},
				},
			},
			expectUpdateOrigin:  false,
			expectUpdateSecrets: false,
			expectRestart:       false,
			expectError:         false,
			setUserLookupErr:    nil,
		},
		{
			name:             "load users error",
			storageUsers:     nil,
			storageErr:       errors.New("storage failed"),
			expectError:      true,
			setUserLookupErr: nil,
		},
		{
			name: "update origin error",
			storageUsers: map[string]*AutheliaUser{
				"user1": {
					User:     &model.User{Username: "user1", PrimaryEmail: "user1@example.com"},
					Password: "hash1",
					Email:    "user1@example.com",
				},
			},
			orchestratorUsers: map[string]any{
				"users": map[string]any{},
			},
			updateOriginErr:  errors.New("update origin failed"),
			expectError:      true,
			setUserLookupErr: nil,
		},
		{
			name: "update secrets error",
			storageUsers: map[string]*AutheliaUser{
				"user1": {
					User:     &model.User{Username: "user1", PrimaryEmail: "user1@example.com"},
					Password: "hash1",
					Email:    "user1@example.com",
				},
			},
			orchestratorUsers: map[string]any{
				"users": map[string]any{},
			},
			updateSecretsErr: errors.New("update secrets failed"),
			expectError:      true,
			setUserLookupErr: nil,
		},
		{
			name: "restart error",
			storageUsers: map[string]*AutheliaUser{
				"user1": {
					User:     &model.User{Username: "user1", PrimaryEmail: "user1@example.com"},
					Password: "hash1",
					Email:    "user1@example.com",
				},
			},
			orchestratorUsers: map[string]any{
				"users": map[string]any{},
			},
			restartErr:       errors.New("restart failed"),
			expectError:      true,
			setUserLookupErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &sync{}

			mockStorage := &mockStorageReaderWriter{
				users:            tt.storageUsers,
				listErr:          tt.storageErr,
				setUserLookupErr: tt.setUserLookupErr,
			}

			mockOrch := &mockOrchestrator{
				users:            tt.orchestratorUsers,
				updateOriginErr:  tt.updateOriginErr,
				updateSecretsErr: tt.updateSecretsErr,
				restartErr:       tt.restartErr,
				setUserLookupErr: tt.setUserLookupErr,
			}

			err := s.syncUsers(ctx, mockStorage, mockOrch)

			if tt.expectError {
				if err == nil {
					t.Error("syncUsers() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("syncUsers() unexpected error: %v", err)
				return
			}

			if mockOrch.updateOriginCalled != tt.expectUpdateOrigin {
				t.Errorf("syncUsers() updateOriginCalled = %v, want %v", mockOrch.updateOriginCalled, tt.expectUpdateOrigin)
			}

			if mockOrch.updateSecretsCalled != tt.expectUpdateSecrets {
				t.Errorf("syncUsers() updateSecretsCalled = %v, want %v", mockOrch.updateSecretsCalled, tt.expectUpdateSecrets)
			}

			if mockOrch.restartCalled != tt.expectRestart {
				t.Errorf("syncUsers() restartCalled = %v, want %v", mockOrch.restartCalled, tt.expectRestart)
			}

			// Verify YAML data is generated when expected
			if tt.expectUpdateOrigin && len(mockOrch.lastYAMLData) == 0 {
				t.Error("syncUsers() expected YAML data to be generated")
			}

			// Verify secret data is generated when expected
			if tt.expectUpdateSecrets && len(mockOrch.lastSecretData) == 0 {
				t.Error("syncUsers() expected secret data to be generated")
			}
		})
	}
}

func TestSync_SyncUsers_PasswordGeneration(t *testing.T) {
	ctx := context.Background()

	// Test that new passwords are generated for orchestrator creation/update
	storageUsers := map[string]*AutheliaUser{
		"user1": {
			User:     &model.User{Username: "user1", PrimaryEmail: "user1@example.com"},
			Password: "old_hash",
			Email:    "user1@example.com",
		},
	}

	orchestratorUsers := map[string]any{
		"users": map[string]any{}, // Empty - will trigger orchestrator creation
	}

	s := &sync{}
	mockStorage := &mockStorageReaderWriter{users: storageUsers}
	mockOrch := &mockOrchestrator{users: orchestratorUsers}

	err := s.syncUsers(ctx, mockStorage, mockOrch)
	if err != nil {
		t.Fatalf("syncUsers() failed: %v", err)
	}

	// Verify password was updated in storage
	updatedUser := mockStorage.users["user1"]
	if updatedUser.Password == "old_hash" {
		t.Error("syncUsers() should have generated new password")
	}

	// Verify plain password was stored in secrets
	if len(mockOrch.lastSecretData) == 0 {
		t.Error("syncUsers() should have generated secret data")
	}

	if _, exists := mockOrch.lastSecretData["user1"]; !exists {
		t.Error("syncUsers() should have secret for user1")
	}
}

func TestSync_SyncUsers_StorageCreation(t *testing.T) {
	ctx := context.Background()

	// Test that users from orchestrator are added to storage
	storageUsers := map[string]*AutheliaUser{}

	orchestratorUsers := map[string]any{
		"users": map[string]any{
			"user1": map[string]any{
				"password":    "hash1",
				"email":       "user1@example.com",
				"displayname": "User One",
			},
		},
	}

	s := &sync{}
	mockStorage := &mockStorageReaderWriter{users: storageUsers}
	mockOrch := &mockOrchestrator{users: orchestratorUsers}

	err := s.syncUsers(ctx, mockStorage, mockOrch)
	if err != nil {
		t.Fatalf("syncUsers() failed: %v", err)
	}

	// Verify user was added to storage
	if _, exists := mockStorage.users["user1"]; !exists {
		t.Error("syncUsers() should have added user1 to storage")
	}

	// Should not update orchestrator for storage creation
	if mockOrch.updateOriginCalled {
		t.Error("syncUsers() should not update orchestrator for storage creation")
	}
}
