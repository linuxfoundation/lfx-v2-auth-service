// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package mock

import (
	"context"
	"testing"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
)

// TestUserReaderWriter_MetadataLookup tests the MetadataLookup method for Mock implementation
func TestUserReaderWriter_MetadataLookup(t *testing.T) {
	ctx := context.Background()
	writer := &userWriter{}

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
			name:                 "canonical lookup with pipe separator - auth0 format",
			input:                "auth0|123456789",
			expectedCanonical:    true,
			expectedSub:          "auth0|123456789",
			expectedUserID:       "auth0|123456789",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
		},
		{
			name:                 "canonical lookup with google oauth format",
			input:                "google-oauth2|987654321",
			expectedCanonical:    true,
			expectedSub:          "google-oauth2|987654321",
			expectedUserID:       "google-oauth2|987654321",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
		},
		{
			name:                 "canonical lookup with github oauth format",
			input:                "github|456789123",
			expectedCanonical:    true,
			expectedSub:          "github|456789123",
			expectedUserID:       "github|456789123",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
		},
		{
			name:                 "canonical lookup with saml enterprise format",
			input:                "samlp|enterprise|user123",
			expectedCanonical:    true,
			expectedSub:          "samlp|enterprise|user123",
			expectedUserID:       "samlp|enterprise|user123",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
		},
		{
			name:                 "canonical lookup with linkedin oauth format",
			input:                "linkedin|789123456",
			expectedCanonical:    true,
			expectedSub:          "linkedin|789123456",
			expectedUserID:       "linkedin|789123456",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
		},
		{
			name:                 "canonical lookup with custom provider format",
			input:                "custom-provider|user-id-12345",
			expectedCanonical:    true,
			expectedSub:          "custom-provider|user-id-12345",
			expectedUserID:       "custom-provider|user-id-12345",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
		},
		{
			name:                 "search lookup with email format",
			input:                "john.doe@example.com",
			expectedCanonical:    false,
			expectedSub:          "",
			expectedUserID:       "",
			expectedUsername:     "",
			expectedPrimaryEmail: "john.doe@example.com",
		},
		{
			name:                 "search lookup with email format - complex domain",
			input:                "jane.smith@company.co.uk",
			expectedCanonical:    false,
			expectedSub:          "",
			expectedUserID:       "",
			expectedUsername:     "",
			expectedPrimaryEmail: "jane.smith@company.co.uk",
		},
		{
			name:                 "search lookup with email format - subdomain",
			input:                "developer@mail.example.org",
			expectedCanonical:    false,
			expectedSub:          "",
			expectedUserID:       "",
			expectedUsername:     "",
			expectedPrimaryEmail: "developer@mail.example.org",
		},
		{
			name:                 "search lookup with username - no email format",
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
			name:                 "search lookup with simple username",
			input:                "testuser",
			expectedCanonical:    false,
			expectedSub:          "",
			expectedUserID:       "",
			expectedUsername:     "testuser",
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
			name:                 "input with leading/trailing whitespace - canonical",
			input:                "  auth0|123456789  ",
			expectedCanonical:    true,
			expectedSub:          "auth0|123456789",
			expectedUserID:       "auth0|123456789",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
		},
		{
			name:                 "input with leading/trailing whitespace - email",
			input:                "  john.doe@example.com  ",
			expectedCanonical:    false,
			expectedSub:          "",
			expectedUserID:       "",
			expectedUsername:     "",
			expectedPrimaryEmail: "john.doe@example.com",
		},
		{
			name:                 "input with leading/trailing whitespace - username",
			input:                "  john.doe  ",
			expectedCanonical:    false,
			expectedSub:          "",
			expectedUserID:       "",
			expectedUsername:     "john.doe",
			expectedPrimaryEmail: "",
		},
		{
			name:                 "edge case - single pipe character",
			input:                "|",
			expectedCanonical:    true,
			expectedSub:          "|",
			expectedUserID:       "|",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
		},
		{
			name:                 "edge case - pipe at end",
			input:                "provider|",
			expectedCanonical:    true,
			expectedSub:          "provider|",
			expectedUserID:       "provider|",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
		},
		{
			name:                 "edge case - pipe at beginning",
			input:                "|userid",
			expectedCanonical:    true,
			expectedSub:          "|userid",
			expectedUserID:       "|userid",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
		},
		{
			name:                 "edge case - multiple pipes",
			input:                "provider|connection|userid",
			expectedCanonical:    true,
			expectedSub:          "provider|connection|userid",
			expectedUserID:       "provider|connection|userid",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
		},
		{
			name:                 "edge case - email with pipe (should be canonical)",
			input:                "user@domain.com|provider",
			expectedCanonical:    true,
			expectedSub:          "user@domain.com|provider",
			expectedUserID:       "user@domain.com|provider",
			expectedUsername:     "",
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
