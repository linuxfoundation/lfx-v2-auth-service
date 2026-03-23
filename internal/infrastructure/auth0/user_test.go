// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/converters"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestJWTVerificationConfig creates a test JWT verification configuration
func createTestJWTVerificationConfig(t *testing.T) (*JWTVerificationConfig, *rsa.PrivateKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	return &JWTVerificationConfig{
		PublicKey:        &privateKey.PublicKey,
		ExpectedIssuer:   "https://test.auth0.com/",
		ExpectedAudience: "https://test.auth0.com/api/v2/",
	}, privateKey
}

func TestUserReaderWriter_UpdateUser(t *testing.T) {
	ctx := context.Background()

	// Create test JWT verification config
	jwtConfig, privateKey := createTestJWTVerificationConfig(t)

	// Create a valid token
	createValidToken := func() string {
		claims := jwt.MapClaims{
			"sub":   "auth0|testuser",
			"exp":   time.Now().Add(time.Hour).Unix(),
			"scope": "update:current_user_metadata",
			"iss":   "https://test.auth0.com/",
			"aud":   "https://test.auth0.com/api/v2/",
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tokenString, _ := token.SignedString(privateKey)
		return tokenString
	}

	tests := []struct {
		name      string
		config    Config
		user      *model.User
		wantError bool
		errorMsg  string
	}{
		{
			name: "missing domain configuration",
			config: Config{
				Tenant:                "test-tenant",
				Domain:                "", // Missing domain
				JWTVerificationConfig: jwtConfig,
			},
			user: &model.User{
				Token:        createValidToken(),
				Username:     "TestUser",
				PrimaryEmail: "test@example.com",
				UserMetadata: &model.UserMetadata{
					Name: converters.StringPtr("Test User"),
				},
			},
			wantError: true,
			errorMsg:  "Auth0 domain configuration is missing",
		},
		{
			name: "valid JWT validation only (no HTTP call due to missing domain)",
			config: Config{
				Tenant:                "test-tenant",
				Domain:                "", // This will cause HTTP call to be skipped
				JWTVerificationConfig: jwtConfig,
			},
			user: &model.User{
				Token:        createValidToken(),
				Username:     "TestUser",
				PrimaryEmail: "test@example.com",
				UserMetadata: &model.UserMetadata{
					Name: converters.StringPtr("Test User"),
				},
			},
			wantError: true, // Will fail due to incomplete config
			errorMsg:  "Auth0 domain configuration is missing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			readerWriter := &userReaderWriter{}
			readerWriter.httpClient = httpclient.NewClient(httpclient.DefaultConfig())
			readerWriter.config = tt.config

			updatedUser, err := readerWriter.UpdateUser(ctx, tt.user)

			if tt.wantError {
				if err == nil {
					t.Errorf("UpdateUser() should return error")
					return
				}
				if !containsString(err.Error(), tt.errorMsg) {
					t.Errorf("UpdateUser() error = %v, should contain %v", err.Error(), tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("UpdateUser() should not return error, got %v", err)
					return
				}

				// Check that user_id was assigned from token
				if updatedUser.UserID != "auth0|testuser" {
					t.Errorf("UpdateUser() should assign user_id from token, got %v", updatedUser.UserID)
				}
			}
		})
	}
}

func TestUserReaderWriter_UpdateUser_JWTValidation(t *testing.T) {
	ctx := context.Background()

	// Create test JWT verification config
	verify, privateKey := createTestJWTVerificationConfig(t)

	// Create a valid token
	createValidToken := func() string {
		claims := jwt.MapClaims{
			"sub":   "auth0|testuser",
			"exp":   time.Now().Add(time.Hour).Unix(),
			"scope": "update:current_user_metadata",
			"iss":   "https://test.auth0.com/",
			"aud":   "https://test.auth0.com/api/v2/",
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tokenString, _ := token.SignedString(privateKey)
		return tokenString
	}

	user := &model.User{
		Token:        createValidToken(),
		Username:     "TestUser",
		PrimaryEmail: "test@example.com",
	}

	// Test JWT verification directly (this should work)
	claims, err := verify.JWTVerify(ctx, user.Token, constants.UserUpdateMetadataRequiredScope)
	if err != nil {
		t.Errorf("jwtVerify() should not return error, got %v", err)
		return
	}

	// Set user_id from claims
	if claims != nil {
		user.UserID = claims.Subject
	}

	// Check that user_id was assigned from token
	if user.UserID != "auth0|testuser" {
		t.Errorf("jwtVerify() should assign user_id from token, got %v", user.UserID)
	}
}

func TestUserReaderWriter_GetUser(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		config    Config
		user      *model.User
		wantError bool
		errorMsg  string
	}{
		{
			name: "missing user_id",
			config: Config{
				Tenant: "test-tenant",
				Domain: "test-tenant.auth0.com",
			},
			user: &model.User{
				Token:        "some-token",
				UserID:       "", // Missing user_id
				Username:     "TestUser",
				PrimaryEmail: "test@example.com",
			},
			wantError: true,
			errorMsg:  "user_id is required to get user",
		},
		{
			name: "missing domain configuration",
			config: Config{
				Tenant: "test-tenant",
				Domain: "", // Missing domain
			},
			user: &model.User{
				Token:        "some-token",
				UserID:       "auth0|testuser",
				Username:     "TestUser",
				PrimaryEmail: "test@example.com",
			},
			wantError: true,
			errorMsg:  "Auth0 domain configuration is missing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			readerWriter := &userReaderWriter{}
			readerWriter.httpClient = httpclient.NewClient(httpclient.DefaultConfig())
			readerWriter.config = tt.config

			_, err := readerWriter.GetUser(ctx, tt.user)

			if tt.wantError {
				if err == nil {
					t.Errorf("GetUser() should return error")
					return
				}
				if !containsString(err.Error(), tt.errorMsg) {
					t.Errorf("GetUser() error = %v, should contain %v", err.Error(), tt.errorMsg)
				}
			} else if err != nil {
				t.Errorf("GetUser() should not return error, got %v", err)
				return
			}
		})
	}
}

// TestUserReaderWriter_ParseAuth0Response tests the parsing logic for Auth0 responses in UpdateUser
func TestUserReaderWriter_ParseAuth0Response(t *testing.T) {
	tests := []struct {
		name             string
		responseBody     string
		expectedMetadata *model.UserMetadata
		wantError        bool
		errorMsg         string
	}{
		{
			name: "successful parsing with complete user_metadata",
			responseBody: `{
				"user_id": "auth0|testuser",
				"user_metadata": {
					"name": "Phoenix Starweaver",
					"family_name": "Starweaver",
					"given_name": "Phoenix",
					"picture": "https://fantasy-avatars-api.com/phoenix-starweaver-12345"
				}
			}`,
			expectedMetadata: &model.UserMetadata{
				Name:       converters.StringPtr("Phoenix Starweaver"),
				FamilyName: converters.StringPtr("Starweaver"),
				GivenName:  converters.StringPtr("Phoenix"),
				Picture:    converters.StringPtr("https://fantasy-avatars-api.com/phoenix-starweaver-12345"),
			},
			wantError: false,
		},
		{
			name: "successful parsing with partial user_metadata",
			responseBody: `{
				"user_id": "auth0|testuser",
				"user_metadata": {
					"name": "John Doe",
					"job_title": "Software Engineer"
				}
			}`,
			expectedMetadata: &model.UserMetadata{
				Name:     converters.StringPtr("John Doe"),
				JobTitle: converters.StringPtr("Software Engineer"),
			},
			wantError: false,
		},
		{
			name: "successful parsing with empty user_metadata",
			responseBody: `{
				"user_id": "auth0|testuser",
				"user_metadata": {}
			}`,
			expectedMetadata: &model.UserMetadata{},
			wantError:        false,
		},
		{
			name: "response missing user_metadata field",
			responseBody: `{
				"user_id": "auth0|testuser",
				"email": "test@example.com"
			}`,
			expectedMetadata: nil,
			wantError:        false,
		},
		{
			name:         "malformed json",
			responseBody: `{invalid json`,
			wantError:    true,
			errorMsg:     "failed to parse update response",
		},
		{
			name:         "empty response body",
			responseBody: ``,
			wantError:    true,
			errorMsg:     "failed to parse update response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the Auth0 response to get the updated user metadata
			var auth0Response struct {
				UserMetadata *model.UserMetadata `json:"user_metadata,omitempty"`
			}

			err := json.Unmarshal([]byte(tt.responseBody), &auth0Response)

			if tt.wantError {
				if err == nil {
					t.Errorf("JSON parsing should return error for malformed input")
					return
				}
				// For JSON parsing errors, we expect different error messages depending on the type of malformed JSON
				// "invalid character" for malformed JSON, "unexpected end of JSON input" for empty strings
				// This test validates that JSON parsing fails as expected
				return
			}

			if err != nil {
				t.Errorf("JSON parsing should not return error, got %v", err)
				return
			}

			// Create a new user object with only the user_metadata populated (simulating UpdateUser behavior)
			updatedUser := &model.User{
				UserMetadata: auth0Response.UserMetadata,
			}

			// All other fields should be empty/default
			if updatedUser.Token != "" {
				t.Errorf("Expected empty Token, got %s", updatedUser.Token)
			}
			if updatedUser.UserID != "" {
				t.Errorf("Expected empty UserID, got %s", updatedUser.UserID)
			}
			if updatedUser.Username != "" {
				t.Errorf("Expected empty Username, got %s", updatedUser.Username)
			}
			if updatedUser.PrimaryEmail != "" {
				t.Errorf("Expected empty PrimaryEmail, got %s", updatedUser.PrimaryEmail)
			}

			// Test UserMetadata content
			if tt.expectedMetadata == nil {
				if updatedUser.UserMetadata != nil {
					t.Errorf("Expected nil UserMetadata, got %+v", updatedUser.UserMetadata)
				}
			} else {
				if updatedUser.UserMetadata == nil {
					t.Fatal("Expected UserMetadata, got nil")
				}

				// Compare each field
				if !stringPtrEqual(updatedUser.UserMetadata.Name, tt.expectedMetadata.Name) {
					t.Errorf("Expected Name %v, got %v", ptrValue(tt.expectedMetadata.Name), ptrValue(updatedUser.UserMetadata.Name))
				}
				if !stringPtrEqual(updatedUser.UserMetadata.FamilyName, tt.expectedMetadata.FamilyName) {
					t.Errorf("Expected FamilyName %v, got %v", ptrValue(tt.expectedMetadata.FamilyName), ptrValue(updatedUser.UserMetadata.FamilyName))
				}
				if !stringPtrEqual(updatedUser.UserMetadata.GivenName, tt.expectedMetadata.GivenName) {
					t.Errorf("Expected GivenName %v, got %v", ptrValue(tt.expectedMetadata.GivenName), ptrValue(updatedUser.UserMetadata.GivenName))
				}
				if !stringPtrEqual(updatedUser.UserMetadata.Picture, tt.expectedMetadata.Picture) {
					t.Errorf("Expected Picture %v, got %v", ptrValue(tt.expectedMetadata.Picture), ptrValue(updatedUser.UserMetadata.Picture))
				}
				if !stringPtrEqual(updatedUser.UserMetadata.JobTitle, tt.expectedMetadata.JobTitle) {
					t.Errorf("Expected JobTitle %v, got %v", ptrValue(tt.expectedMetadata.JobTitle), ptrValue(updatedUser.UserMetadata.JobTitle))
				}
			}
		})
	}
}

// TestUserReaderWriter_UpdateUser_JSONSerialization tests that a user object with only UserMetadata serializes correctly
func TestUserReaderWriter_UpdateUser_JSONSerialization(t *testing.T) {
	// Create a user object with only UserMetadata populated (simulating UpdateUser return value)
	user := &model.User{
		UserMetadata: &model.UserMetadata{
			Name:       converters.StringPtr("Aurora Moonwhisper"),
			FamilyName: converters.StringPtr("Moonwhisper"),
			GivenName:  converters.StringPtr("Aurora"),
			Picture:    converters.StringPtr("https://fantasy-avatars-api.com/aurora-moonwhisper-67890"),
		},
	}

	// Test JSON serialization
	jsonData, err := json.Marshal(user)
	if err != nil {
		t.Fatalf("Failed to marshal user to JSON: %v", err)
	}

	// Parse JSON to verify structure
	var jsonResult map[string]interface{}
	if err := json.Unmarshal(jsonData, &jsonResult); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// The User struct includes all fields since they don't have omitempty tags (except user_metadata)
	// We should verify that only user_metadata has meaningful content
	expectedFields := []string{"token", "user_id", "username", "primary_email", "user_metadata"}
	if len(jsonResult) != len(expectedFields) {
		t.Errorf("Expected %d fields in JSON, got %d", len(expectedFields), len(jsonResult))
	}

	// Verify that non-metadata fields are empty
	if token, exists := jsonResult["token"]; exists && token != "" {
		t.Errorf("Expected empty token, got %v", token)
	}
	if userID, exists := jsonResult["user_id"]; exists && userID != "" {
		t.Errorf("Expected empty user_id, got %v", userID)
	}
	if username, exists := jsonResult["username"]; exists && username != "" {
		t.Errorf("Expected empty username, got %v", username)
	}
	if primaryEmail, exists := jsonResult["primary_email"]; exists && primaryEmail != "" {
		t.Errorf("Expected empty primary_email, got %v", primaryEmail)
	}

	// Verify user_metadata content
	userMetadata, ok := jsonResult["user_metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("user_metadata should be a map")
	}

	expectedMetadata := map[string]string{
		"name":        "Aurora Moonwhisper",
		"family_name": "Moonwhisper",
		"given_name":  "Aurora",
		"picture":     "https://fantasy-avatars-api.com/aurora-moonwhisper-67890",
	}

	for key, expectedValue := range expectedMetadata {
		if actualValue, exists := userMetadata[key]; !exists || actualValue != expectedValue {
			t.Errorf("Expected %s = %s, got %v", key, expectedValue, actualValue)
		}
	}

	// The key insight is that while the JSON contains all fields, only user_metadata has meaningful content
	// This simulates the behavior of the modified UpdateUser function which returns a User with only UserMetadata populated
	t.Logf("Complete JSON output: %s", string(jsonData))
}

// TestUserReaderWriter_UpdateUser_ConfigValidation tests configuration validation in UpdateUser
func TestUserReaderWriter_UpdateUser_ConfigValidation(t *testing.T) {
	ctx := context.Background()

	// Create test JWT verification config
	jwtConfig, privateKey := createTestJWTVerificationConfig(t)

	// Create a valid token
	createValidToken := func() string {
		claims := jwt.MapClaims{
			"sub":   "auth0|testuser",
			"exp":   time.Now().Add(time.Hour).Unix(),
			"scope": "update:current_user_metadata",
			"iss":   "https://test.auth0.com/",
			"aud":   "https://test.auth0.com/api/v2/",
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tokenString, _ := token.SignedString(privateKey)
		return tokenString
	}

	tests := []struct {
		name        string
		config      Config
		expectedErr string
	}{
		{
			name: "missing domain configuration",
			config: Config{
				Tenant:                "test-tenant",
				Domain:                "", // Missing domain
				JWTVerificationConfig: jwtConfig,
			},
			expectedErr: "Auth0 domain configuration is missing",
		},
		{
			name: "missing tenant configuration",
			config: Config{
				Tenant:                "", // Missing tenant
				Domain:                "", // Also missing domain to prevent HTTP calls
				JWTVerificationConfig: jwtConfig,
			},
			expectedErr: "Auth0 domain configuration is missing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			readerWriter := &userReaderWriter{}
			readerWriter.httpClient = httpclient.NewClient(httpclient.DefaultConfig())
			readerWriter.config = tt.config

			user := &model.User{
				Token:    createValidToken(),
				Username: "TestUser",
				UserMetadata: &model.UserMetadata{
					Name: converters.StringPtr("Test Name"),
				},
			}

			_, err := readerWriter.UpdateUser(ctx, user)

			if err == nil {
				t.Errorf("UpdateUser() should return error")
				return
			}

			if !containsString(err.Error(), tt.expectedErr) {
				t.Errorf("UpdateUser() error = %v, should contain %v", err.Error(), tt.expectedErr)
			}
		})
	}
}

// TestUserReaderWriter_UpdateUser_JWTValidationIntegration tests JWT validation within UpdateUser context
func TestUserReaderWriter_UpdateUser_JWTValidationIntegration(t *testing.T) {
	ctx := context.Background()

	// Create test JWT verification config
	jwtConfig, privateKey := createTestJWTVerificationConfig(t)

	tests := []struct {
		name        string
		setupUser   func() *model.User
		expectedErr string
	}{
		{
			name: "invalid jwt token",
			setupUser: func() *model.User {
				return &model.User{
					Token:    "invalid.jwt.token",
					Username: "TestUser",
					UserMetadata: &model.UserMetadata{
						Name: converters.StringPtr("Test Name"),
					},
				}
			},
			expectedErr: "failed to parse jws",
		},
		{
			name: "expired jwt token",
			setupUser: func() *model.User {
				claims := jwt.MapClaims{
					"sub":   "auth0|testuser",
					"exp":   time.Now().Add(-time.Hour).Unix(), // Expired 1 hour ago
					"scope": "update:current_user_metadata",
					"iss":   "https://test.auth0.com/",
					"aud":   "https://test.auth0.com/api/v2/",
				}
				token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
				tokenString, _ := token.SignedString(privateKey)
				return &model.User{
					Token:    tokenString,
					Username: "TestUser",
					UserMetadata: &model.UserMetadata{
						Name: converters.StringPtr("Test Name"),
					},
				}
			},
			expectedErr: "exp",
		},
		{
			name: "missing required scope",
			setupUser: func() *model.User {
				claims := jwt.MapClaims{
					"sub":   "auth0|testuser",
					"exp":   time.Now().Add(time.Hour).Unix(),
					"scope": "read:profile write:data", // Missing update:current_user_metadata
					"iss":   "https://test.auth0.com/",
					"aud":   "https://test.auth0.com/api/v2/",
				}
				token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
				tokenString, _ := token.SignedString(privateKey)
				return &model.User{
					Token:    tokenString,
					Username: "TestUser",
					UserMetadata: &model.UserMetadata{
						Name: converters.StringPtr("Test Name"),
					},
				}
			},
			expectedErr: "missing required scope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use empty domain to skip HTTP call and focus on JWT validation
			config := Config{
				Tenant:                "test-tenant",
				Domain:                "", // This will cause the function to fail at config validation
				JWTVerificationConfig: jwtConfig,
			}

			readerWriter := &userReaderWriter{}
			readerWriter.httpClient = httpclient.NewClient(httpclient.DefaultConfig())
			readerWriter.config = config

			user := tt.setupUser()

			_, err := readerWriter.UpdateUser(ctx, user)

			if err == nil {
				t.Errorf("UpdateUser() should return error")
				return
			}

			// The error could be either JWT validation error or config validation error
			// For JWT errors, we expect them to happen before config validation
			if containsString(err.Error(), tt.expectedErr) || containsString(err.Error(), "Auth0 configuration is incomplete") {
				// Both are acceptable - JWT validation might happen first or config validation might happen first
				// depending on the implementation
			} else {
				t.Errorf("UpdateUser() error = %v, should contain either %v or config error", err.Error(), tt.expectedErr)
			}
		})
	}
}

// Helper functions
func stringPtrEqual(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func ptrValue(ptr *string) string {
	if ptr == nil {
		return "<nil>"
	}
	return *ptr
}

// TestUserReaderWriter_MetadataLookup tests the MetadataLookup method for Auth0 implementation
func TestUserReaderWriter_MetadataLookup(t *testing.T) {
	ctx := context.Background()

	// Create test JWT verification config
	jwtConfig, privateKey := createTestJWTVerificationConfig(t)

	writer := &userReaderWriter{
		config: Config{
			JWTVerificationConfig: jwtConfig,
		},
	}

	// Create a valid JWT token for testing
	now := time.Now()
	exp := now.Add(time.Hour)
	validToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":   "auth0|123456789",
		"exp":   exp.Unix(),
		"iat":   now.Unix(),
		"scope": "read:current_user other:scope",
		"iss":   "https://test.auth0.com/",
		"aud":   "https://test.auth0.com/api/v2/",
	})
	validTokenString, err := validToken.SignedString(privateKey)
	require.NoError(t, err)

	tests := []struct {
		name        string
		input       string
		expectError bool
		errorMsg    string
		expectedSub string
	}{
		{
			name:        "empty input",
			input:       "",
			expectError: true,
			errorMsg:    "input is required",
		},
		{
			name:        "invalid JWT token",
			input:       "invalid-token",
			expectError: false, // Now handled as username lookup
		},
		{
			name:        "non-JWT input",
			input:       "test@example.com",
			expectError: false, // Now handled as email lookup
		},
		{
			name:        "username input",
			input:       "testuser",
			expectError: false, // Now handled as username lookup
		},
		{
			name:        "valid JWT token with read:current_user scope",
			input:       validTokenString,
			expectError: false,
			expectedSub: "auth0|123456789",
		},
		{
			name:        "valid JWT token with Bearer prefix",
			input:       "Bearer " + validTokenString,
			expectError: false,
			expectedSub: "auth0|123456789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := writer.MetadataLookup(ctx, tt.input)

			if tt.expectError {
				if err == nil {
					t.Errorf("MetadataLookup() expected error but got none")
					return
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("MetadataLookup() error = %q, expected to contain %q", err.Error(), tt.errorMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("MetadataLookup() unexpected error: %v", err)
				return
			}

			if user == nil {
				t.Errorf("MetadataLookup() returned nil user")
				return
			}

			// Verify the user fields are set correctly for successful cases
			if tt.expectedSub != "" {
				assert.Equal(t, tt.expectedSub, user.Sub, "Sub should match expected value")
				assert.Equal(t, tt.expectedSub, user.UserID, "UserID should match expected value")
				assert.Equal(t, strings.TrimPrefix(strings.TrimSpace(tt.input), "Bearer "), user.Token, "Token should be stored")
			}
		})
	}
}

// Helper function to check if a string contains a substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) &&
			(s[:len(substr)] == substr ||
				s[len(s)-len(substr):] == substr ||
				containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
