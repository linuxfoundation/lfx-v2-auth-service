// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package authelia

import (
	"context"
	"testing"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/converters"
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

// TestUserReaderWriter_MetadataLookup tests the MetadataLookup method for Authelia implementation
func TestUserReaderWriter_MetadataLookup(t *testing.T) {
	ctx := context.Background()
	writer := &userReaderWriter{}

	tests := []struct {
		name                 string
		input                string
		expectedCanonical    bool
		expectedSub          string
		expectedUserID       string
		expectedUsername     string
		expectedPrimaryEmail string
	}{
		{
			name:                 "canonical lookup with valid UUID",
			input:                "550e8400-e29b-41d4-a716-446655440000",
			expectedCanonical:    true,
			expectedSub:          "550e8400-e29b-41d4-a716-446655440000",
			expectedUserID:       "550e8400-e29b-41d4-a716-446655440000",
			expectedUsername:     "550e8400-e29b-41d4-a716-446655440000",
			expectedPrimaryEmail: "",
		},
		{
			name:                 "canonical lookup with another valid UUID",
			input:                "123e4567-e89b-12d3-a456-426614174000",
			expectedCanonical:    true,
			expectedSub:          "123e4567-e89b-12d3-a456-426614174000",
			expectedUserID:       "123e4567-e89b-12d3-a456-426614174000",
			expectedUsername:     "123e4567-e89b-12d3-a456-426614174000",
			expectedPrimaryEmail: "",
		},
		{
			name:                 "search lookup with username - invalid UUID",
			input:                "john.doe",
			expectedCanonical:    false,
			expectedSub:          "",
			expectedUserID:       "",
			expectedUsername:     "john.doe",
			expectedPrimaryEmail: "",
		},
		{
			name:                 "search lookup with username containing numbers",
			input:                "developer123",
			expectedCanonical:    false,
			expectedSub:          "",
			expectedUserID:       "",
			expectedUsername:     "developer123",
			expectedPrimaryEmail: "",
		},
		{
			name:                 "search lookup with username containing special chars",
			input:                "jane_smith-dev",
			expectedCanonical:    false,
			expectedSub:          "",
			expectedUserID:       "",
			expectedUsername:     "jane_smith-dev",
			expectedPrimaryEmail: "",
		},
		{
			name:                 "search lookup with invalid UUID format",
			input:                "not-a-valid-uuid-format",
			expectedCanonical:    false,
			expectedSub:          "",
			expectedUserID:       "",
			expectedUsername:     "not-a-valid-uuid-format",
			expectedPrimaryEmail: "",
		},
		{
			name:                 "search lookup with UUID-like but invalid",
			input:                "550e8400-e29b-41d4-a716-44665544000g", // Invalid character 'g'
			expectedCanonical:    false,
			expectedSub:          "",
			expectedUserID:       "",
			expectedUsername:     "550e8400-e29b-41d4-a716-44665544000g",
			expectedPrimaryEmail: "",
		},
		{
			name:                 "search lookup with short UUID-like string",
			input:                "550e8400-e29b-41d4-a716", // Too short
			expectedCanonical:    false,
			expectedSub:          "",
			expectedUserID:       "",
			expectedUsername:     "550e8400-e29b-41d4-a716",
			expectedPrimaryEmail: "",
		},
		{
			name:                 "empty input",
			input:                "",
			expectedCanonical:    false,
			expectedSub:          "",
			expectedUserID:       "",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
		},
		{
			name:                 "whitespace only input",
			input:                "   ",
			expectedCanonical:    false,
			expectedSub:          "",
			expectedUserID:       "",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
		},
		{
			name:                 "input with leading/trailing whitespace - valid UUID",
			input:                "  550e8400-e29b-41d4-a716-446655440000  ",
			expectedCanonical:    true,
			expectedSub:          "550e8400-e29b-41d4-a716-446655440000",
			expectedUserID:       "550e8400-e29b-41d4-a716-446655440000",
			expectedUsername:     "550e8400-e29b-41d4-a716-446655440000",
			expectedPrimaryEmail: "",
		},
		{
			name:                 "input with leading/trailing whitespace - invalid UUID",
			input:                "  john.doe  ",
			expectedCanonical:    false,
			expectedSub:          "",
			expectedUserID:       "",
			expectedUsername:     "john.doe",
			expectedPrimaryEmail: "",
		},
		{
			name:                 "uppercase UUID",
			input:                "550E8400-E29B-41D4-A716-446655440000",
			expectedCanonical:    true,
			expectedSub:          "550e8400-e29b-41d4-a716-446655440000", // UUID.String() normalizes to lowercase
			expectedUserID:       "550e8400-e29b-41d4-a716-446655440000", // UUID.String() normalizes to lowercase
			expectedUsername:     "550E8400-E29B-41D4-A716-446655440000", // Username preserves original input
			expectedPrimaryEmail: "",
		},
		{
			name:                 "mixed case UUID",
			input:                "550e8400-E29B-41d4-A716-446655440000",
			expectedCanonical:    true,
			expectedSub:          "550e8400-e29b-41d4-a716-446655440000", // UUID.String() normalizes to lowercase
			expectedUserID:       "550e8400-e29b-41d4-a716-446655440000", // UUID.String() normalizes to lowercase
			expectedUsername:     "550e8400-E29B-41d4-A716-446655440000", // Username preserves original input
			expectedPrimaryEmail: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &model.User{}

			isCanonical := writer.MetadataLookup(ctx, tt.input, user)

			// Check canonical vs search lookup decision
			if isCanonical != tt.expectedCanonical {
				t.Errorf("MetadataLookup() canonical = %v, expected %v", isCanonical, tt.expectedCanonical)
			}

			// Check user fields are set correctly
			if user.Sub != tt.expectedSub {
				t.Errorf("MetadataLookup() Sub = %q, expected %q", user.Sub, tt.expectedSub)
			}

			if user.UserID != tt.expectedUserID {
				t.Errorf("MetadataLookup() UserID = %q, expected %q", user.UserID, tt.expectedUserID)
			}

			if user.Username != tt.expectedUsername {
				t.Errorf("MetadataLookup() Username = %q, expected %q", user.Username, tt.expectedUsername)
			}

			if user.PrimaryEmail != tt.expectedPrimaryEmail {
				t.Errorf("MetadataLookup() PrimaryEmail = %q, expected %q", user.PrimaryEmail, tt.expectedPrimaryEmail)
			}
		})
	}
}
