// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package authelia

import (
	"context"
	"testing"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/converters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserWriter_UpdateUser_MetadataPatchBehavior(t *testing.T) {
	ctx := context.Background()

	// Test that the Patch method is called and behaves correctly
	existingUser := &AutheliaUser{
		User: &model.User{
			Username: "testuser",
			UserMetadata: &model.UserMetadata{
				Name:         converters.StringPtr("John Doe"),
				JobTitle:     converters.StringPtr("Engineer"),
				Organization: converters.StringPtr("ACME Corp"),
				Country:      converters.StringPtr("USA"),
			},
		},
	}

	inputUser := &model.User{
		Username: "testuser",
		UserMetadata: &model.UserMetadata{
			Name:     converters.StringPtr("Jane Doe"), // Update
			JobTitle: nil,                              // Should not change existing
			City:     converters.StringPtr("New York"), // New field
			// Organization and Country not specified - should be preserved
		},
	}

	mockStorage := &mockStorageReaderWriter{
		users: map[string]*AutheliaUser{
			"testuser": existingUser,
		},
	}

	userWriter := &userReaderWriter{
		storage: mockStorage,
	}

	result, err := userWriter.UpdateUser(ctx, inputUser)
	if err != nil {
		t.Fatalf("UpdateUser() failed: %v", err)
	}

	if result.UserMetadata == nil {
		t.Fatal("UpdateUser() result should have UserMetadata")
	}

	// Verify updated field
	if result.UserMetadata.Name == nil || *result.UserMetadata.Name != "Jane Doe" {
		t.Error("UpdateUser() should update Name field")
	}

	// Verify preserved fields (not specified in input)
	if result.UserMetadata.JobTitle == nil || *result.UserMetadata.JobTitle != "Engineer" {
		t.Error("UpdateUser() should preserve JobTitle when not specified in input")
	}
	if result.UserMetadata.Organization == nil || *result.UserMetadata.Organization != "ACME Corp" {
		t.Error("UpdateUser() should preserve Organization when not specified in input")
	}
	if result.UserMetadata.Country == nil || *result.UserMetadata.Country != "USA" {
		t.Error("UpdateUser() should preserve Country when not specified in input")
	}

	// Verify new field
	if result.UserMetadata.City == nil || *result.UserMetadata.City != "New York" {
		t.Error("UpdateUser() should add new City field")
	}
}

// TestUserReaderWriter_GetUser_Identities tests that GetUser correctly returns the identities
// stored in the backing store without any transformation.
func TestUserReaderWriter_GetUser_Identities(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name               string
		storageUsers       map[string]*AutheliaUser
		storageErr         error
		inputUser          *model.User
		expectError        bool
		expectedIdentities []model.Identity
	}{
		{
			name: "GetUser_WithLinkedIdentities",
			storageUsers: map[string]*AutheliaUser{
				"testuser": {
					User: &model.User{
						Username: "testuser",
						Identities: []model.Identity{
							{Provider: "google-oauth2", IdentityID: "g123", IsSocial: true, Email: "u@gmail.com", EmailVerified: true},
						},
					},
				},
			},
			inputUser: &model.User{Username: "testuser"},
			expectedIdentities: []model.Identity{
				{Provider: "google-oauth2", IdentityID: "g123", IsSocial: true, Email: "u@gmail.com", EmailVerified: true},
			},
		},
		{
			name: "GetUser_WithNoIdentities",
			storageUsers: map[string]*AutheliaUser{
				"testuser": {
					User: &model.User{
						Username: "testuser",
					},
				},
			},
			inputUser:          &model.User{Username: "testuser"},
			expectedIdentities: nil,
		},
		{
			name: "GetUser_WithMultipleIdentities",
			storageUsers: map[string]*AutheliaUser{
				"testuser": {
					User: &model.User{
						Username: "testuser",
						Identities: []model.Identity{
							{Provider: "google-oauth2", IdentityID: "g123", IsSocial: true},
							{Provider: "github", IdentityID: "gh456", IsSocial: true, Nickname: "octocat"},
						},
					},
				},
			},
			inputUser: &model.User{Username: "testuser"},
			expectedIdentities: []model.Identity{
				{Provider: "google-oauth2", IdentityID: "g123", IsSocial: true},
				{Provider: "github", IdentityID: "gh456", IsSocial: true, Nickname: "octocat"},
			},
		},
		{
			name:         "GetUser_UserNotFound",
			storageUsers: map[string]*AutheliaUser{},
			inputUser:    &model.User{Username: "unknown"},
			expectError:  true,
		},
		{
			name:        "GetUser_NilInput",
			inputUser:   nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rw := &userReaderWriter{
				storage: &mockStorageReaderWriter{
					users:      tt.storageUsers,
					getUserErr: tt.storageErr,
				},
			}

			got, err := rw.GetUser(ctx, tt.inputUser)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, got)
			require.Len(t, got.Identities, len(tt.expectedIdentities))

			for i, want := range tt.expectedIdentities {
				assert.Equal(t, want.Provider, got.Identities[i].Provider, "identity[%d].Provider", i)
				assert.Equal(t, want.IdentityID, got.Identities[i].IdentityID, "identity[%d].IdentityID", i)
				assert.Equal(t, want.IsSocial, got.Identities[i].IsSocial, "identity[%d].IsSocial", i)
				assert.Equal(t, want.Email, got.Identities[i].Email, "identity[%d].Email", i)
				assert.Equal(t, want.Nickname, got.Identities[i].Nickname, "identity[%d].Nickname", i)
			}
		})
	}
}

// TestUserReaderWriter_MetadataLookup tests the MetadataLookup method for Authelia implementation
func TestUserReaderWriter_MetadataLookup(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name         string
		input        string
		expectError  bool
		errorMessage string
	}{
		{
			name:         "empty input",
			input:        "",
			expectError:  true,
			errorMessage: "input is required",
		},
		{
			name:        "invalid token - should fail OIDC fetch",
			input:       "invalid-token",
			expectError: false, // Now handled as username lookup
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create userReaderWriter without OIDC configuration
			// This will cause fetchOIDCUserInfo to fail, which is expected for most tests
			writer := &userReaderWriter{}

			user, err := writer.MetadataLookup(ctx, tt.input)

			// Check error expectation
			if tt.expectError {
				if err == nil {
					t.Errorf("MetadataLookup() expected error but got none")
					return
				}
				if tt.errorMessage != "" && err.Error() != tt.errorMessage {
					t.Errorf("MetadataLookup() error = %q, expected %q", err.Error(), tt.errorMessage)
				}
				return
			}

			// Check no error when not expected
			if err != nil {
				t.Errorf("MetadataLookup() unexpected error: %v", err)
				return
			}

			// Check user is not nil
			if user == nil {
				t.Errorf("MetadataLookup() returned nil user")
				return
			}
		})
	}
}
