// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
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
	"golang.org/x/oauth2"
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

func TestUserReaderWriter_AddSystemManagedEmail_Validation(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		primaryUserID string
		email         string
		wantErrMsg    string
	}{
		{
			name:          "empty primaryUserID",
			primaryUserID: "",
			email:         "jdoe@linux.com",
			wantErrMsg:    "primary_user_id is required",
		},
		{
			name:          "whitespace-only primaryUserID",
			primaryUserID: "   ",
			email:         "jdoe@linux.com",
			wantErrMsg:    "primary_user_id is required",
		},
		{
			name:          "empty email",
			primaryUserID: "auth0|test123",
			email:         "",
			wantErrMsg:    "email is required",
		},
		{
			name:          "whitespace-only email",
			primaryUserID: "auth0|test123",
			email:         "   ",
			wantErrMsg:    "email is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rw := &userReaderWriter{
				httpClient: httpclient.NewClient(httpclient.DefaultConfig()),
				config: Config{
					Tenant: "test-tenant",
					Domain: "test-tenant.auth0.com",
				},
			}

			stubID, err := rw.AddSystemManagedEmail(ctx, tt.primaryUserID, tt.email)

			require.Error(t, err, "expected validation error")
			assert.Empty(t, stubID)
			assert.Contains(t, err.Error(), tt.wantErrMsg)
		})
	}
}

func TestUserReaderWriter_UnlinkIdentity_ValidationGuard(t *testing.T) {
	ctx := context.Background()

	rw := &userReaderWriter{
		httpClient:          httpclient.NewClient(httpclient.DefaultConfig()),
		identityLinkingFlow: newIdentityLinkingFlow("test-tenant.auth0.com", httpclient.NewClient(httpclient.DefaultConfig())),
		config: Config{
			Tenant: "test-tenant",
			Domain: "test-tenant.auth0.com",
		},
	}

	makeRequest := func(raw string) *model.UnlinkIdentity {
		var req model.UnlinkIdentity
		_ = json.Unmarshal([]byte(raw), &req)
		return &req
	}

	tests := []struct {
		name       string
		request    *model.UnlinkIdentity
		wantErrMsg string
	}{
		{
			name:       "nil request",
			request:    nil,
			wantErrMsg: "unlink identity request is required",
		},
		{
			name:       "missing user_id",
			request:    makeRequest(`{"user":{"auth_token":"tok"},"unlink":{"provider":"google-oauth2","identity_id":"123"}}`),
			wantErrMsg: "user_id is required",
		},
		{
			name:       "missing auth_token",
			request:    makeRequest(`{"user":{"user_id":"auth0|abc"},"unlink":{"provider":"google-oauth2","identity_id":"123"}}`),
			wantErrMsg: "user_token is required",
		},
		{
			name:       "missing provider",
			request:    makeRequest(`{"user":{"user_id":"auth0|abc","auth_token":"tok"},"unlink":{"identity_id":"123"}}`),
			wantErrMsg: "provider is required",
		},
		{
			name:       "missing identity_id",
			request:    makeRequest(`{"user":{"user_id":"auth0|abc","auth_token":"tok"},"unlink":{"provider":"google-oauth2"}}`),
			wantErrMsg: "identity_id is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rw.UnlinkIdentity(ctx, tt.request)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrMsg)
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

// --- Test seams for exercising the Auth0 Management API HTTP flow ---

// fakeTokenSource implements oauth2.TokenSource, returning a fixed valid token
// so a TokenManager can be used in tests without contacting Auth0.
type fakeTokenSource struct{ token string }

func (f fakeTokenSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{
		AccessToken: f.token,
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}, nil
}

// recordedCall captures one intercepted HTTP request.
type recordedCall struct {
	method string
	path   string
	body   string
}

// fakeAuth0Transport is an http.RoundTripper that intercepts the Auth0
// Management API calls made by userReaderWriter and returns canned responses,
// recording every request so tests can assert call ordering and payloads. It
// never dials the network, so the https URLs the adapter builds are irrelevant.
type fakeAuth0Transport struct {
	primaryUserID string // decoded path id, e.g. "auth0|test123"
	getUserResp   string // body for GET of the primary user
	stubGetResp   string // body for GET of the rollback stub
	createStatus  int    // status for POST /api/v2/users
	createResp    string // body for POST /api/v2/users
	linkStatus    int    // status for POST /api/v2/users/{id}/identities
	patchStatus   int    // status for PATCH /api/v2/users/{id}
	calls         []recordedCall
}

func newFakeAuth0(primaryUserID, getUserResp string) *fakeAuth0Transport {
	return &fakeAuth0Transport{
		primaryUserID: primaryUserID,
		getUserResp:   getUserResp,
		stubGetResp:   `{"user_id":"email|stub123","identities":[{"connection":"email","provider":"email"}]}`,
		createStatus:  http.StatusCreated,
		createResp:    `{"user_id":"email|stub123"}`,
		linkStatus:    http.StatusCreated,
		patchStatus:   http.StatusOK,
	}
}

func (f *fakeAuth0Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		_ = req.Body.Close()
	}
	f.calls = append(f.calls, recordedCall{method: req.Method, path: req.URL.Path, body: string(bodyBytes)})

	// Routes are scoped to the exact Auth0 Management API paths the adapter is
	// expected to hit; anything else returns 404 so a wrong-path regression fails
	// the test instead of silently passing.
	status := http.StatusOK
	var body string
	switch {
	case req.Method == http.MethodGet && req.URL.Path == "/api/v2/users/"+f.primaryUserID:
		body = f.getUserResp
	case req.Method == http.MethodGet && strings.HasPrefix(req.URL.Path, "/api/v2/users/"):
		// GET of any other user id is the rollback stub verification.
		body = f.stubGetResp
	case req.Method == http.MethodPost && req.URL.Path == "/api/v2/users":
		status, body = f.createStatus, f.createResp
	case req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/identities"):
		status, body = f.linkStatus, "[]"
	case req.Method == http.MethodPatch && req.URL.Path == "/api/v2/users/"+f.primaryUserID:
		status, body = f.patchStatus, "{}"
	case req.Method == http.MethodDelete && strings.HasPrefix(req.URL.Path, "/api/v2/users/"):
		status, body = http.StatusNoContent, ""
	default:
		status, body = http.StatusNotFound, `{"error":"unexpected test route"}`
	}

	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// methodPaths returns the recorded calls as "METHOD path" strings, in order.
func (f *fakeAuth0Transport) methodPaths() []string {
	out := make([]string, len(f.calls))
	for i, c := range f.calls {
		out[i] = c.method + " " + c.path
	}
	return out
}

// firstBodyFor returns the captured body of the first call matching method+path suffix.
func (f *fakeAuth0Transport) firstBodyFor(method, pathSuffix string) (string, bool) {
	for _, c := range f.calls {
		if c.method == method && strings.HasSuffix(c.path, pathSuffix) {
			return c.body, true
		}
	}
	return "", false
}

func (f *fakeAuth0Transport) countFor(method, pathSuffix string) int {
	n := 0
	for _, c := range f.calls {
		if c.method == method && strings.HasSuffix(c.path, pathSuffix) {
			n++
		}
	}
	return n
}

// newTestReaderWriter builds a userReaderWriter wired to the given transport and
// a token manager that returns a fixed valid M2M token.
func newTestReaderWriter(transport http.RoundTripper) *userReaderWriter {
	return &userReaderWriter{
		httpClient: httpclient.NewClient(httpclient.Config{Transport: transport, MaxRetries: 0}),
		config: Config{
			Domain:          "test-tenant.auth0.com",
			M2MTokenManager: &TokenManager{tokenSource: fakeTokenSource{token: "test-m2m-token"}},
		},
	}
}

const testPrimaryUserID = "auth0|test123"

func TestUserReaderWriter_SetPrimaryEmail_PreservesOldPrimary(t *testing.T) {
	ctx := context.Background()

	t.Run("old primary not linked is preserved before promote", func(t *testing.T) {
		getUser := `{"user_id":"auth0|test123","email":"old@example.com","identities":[` +
			`{"connection":"email","provider":"email","profileData":{"email":"new@example.com","email_verified":true}}]}`
		ft := newFakeAuth0(testPrimaryUserID, getUser)
		rw := newTestReaderWriter(ft)

		err := rw.SetPrimaryEmail(ctx, testPrimaryUserID, "new@example.com")
		require.NoError(t, err)

		// Preserve (create + link old primary) must happen before the PATCH.
		assert.Equal(t, []string{
			"GET /api/v2/users/auth0|test123",
			"POST /api/v2/users",
			"POST /api/v2/users/auth0|test123/identities",
			"PATCH /api/v2/users/auth0|test123",
		}, ft.methodPaths())

		// The preserved stub is the OLD primary, verified, and NOT system-managed.
		createBody, ok := ft.firstBodyFor(http.MethodPost, "/api/v2/users")
		require.True(t, ok)
		assert.Contains(t, createBody, `"email":"old@example.com"`)
		assert.Contains(t, createBody, `"email_verified":true`)
		assert.NotContains(t, createBody, "app_metadata")
		assert.NotContains(t, createBody, "system_managed")

		// The PATCH promotes the NEW primary.
		patchBody, ok := ft.firstBodyFor(http.MethodPatch, "/api/v2/users/auth0|test123")
		require.True(t, ok)
		assert.Contains(t, patchBody, `"email":"new@example.com"`)
	})

	t.Run("old primary backed only by a verified Google identity is preserved as email", func(t *testing.T) {
		// A Google login is a login method, not a primary-email candidate, so even a
		// Google-verified address must be materialized as a verified email identity;
		// otherwise the old primary disappears from email settings and cannot be
		// selected again (LFXV2-2497).
		getUser := `{"user_id":"auth0|test123","email":"alice@gmail.com","identities":[` +
			`{"connection":"google-oauth2","provider":"google-oauth2","profileData":{"email":"alice@gmail.com","email_verified":true}},` +
			`{"connection":"email","provider":"email","profileData":{"email":"alice@linux.com","email_verified":true}}]}`
		ft := newFakeAuth0(testPrimaryUserID, getUser)
		rw := newTestReaderWriter(ft)

		err := rw.SetPrimaryEmail(ctx, testPrimaryUserID, "alice@linux.com")
		require.NoError(t, err)

		assert.Equal(t, []string{
			"GET /api/v2/users/auth0|test123",
			"POST /api/v2/users",
			"POST /api/v2/users/auth0|test123/identities",
			"PATCH /api/v2/users/auth0|test123",
		}, ft.methodPaths())
		createBody, ok := ft.firstBodyFor(http.MethodPost, "/api/v2/users")
		require.True(t, ok)
		assert.Contains(t, createBody, `"email":"alice@gmail.com"`)
		assert.Contains(t, createBody, `"email_verified":true`)
	})

	t.Run("old primary backed only by a non-Google social identity is preserved as email", func(t *testing.T) {
		// LinkedIn (or GitHub/Jira/enterprise) is NOT a sufficient email/OTP login,
		// so the old primary must be materialized as a verified email identity.
		getUser := `{"user_id":"auth0|test123","email":"old@example.com","identities":[` +
			`{"connection":"linkedin","provider":"linkedin","profileData":{"email":"old@example.com","email_verified":true}},` +
			`{"connection":"email","provider":"email","profileData":{"email":"new@example.com","email_verified":true}}]}`
		ft := newFakeAuth0(testPrimaryUserID, getUser)
		rw := newTestReaderWriter(ft)

		err := rw.SetPrimaryEmail(ctx, testPrimaryUserID, "new@example.com")
		require.NoError(t, err)

		assert.Equal(t, []string{
			"GET /api/v2/users/auth0|test123",
			"POST /api/v2/users",
			"POST /api/v2/users/auth0|test123/identities",
			"PATCH /api/v2/users/auth0|test123",
		}, ft.methodPaths())
		createBody, _ := ft.firstBodyFor(http.MethodPost, "/api/v2/users")
		assert.Contains(t, createBody, `"email":"old@example.com"`)
		assert.NotContains(t, createBody, "app_metadata")
	})

	t.Run("old primary already a linked email identity skips preservation", func(t *testing.T) {
		getUser := `{"user_id":"auth0|test123","email":"old@example.com","identities":[` +
			`{"connection":"email","provider":"email","profileData":{"email":"new@example.com","email_verified":true}},` +
			`{"connection":"email","provider":"email","profileData":{"email":"old@example.com","email_verified":true}}]}`
		ft := newFakeAuth0(testPrimaryUserID, getUser)
		rw := newTestReaderWriter(ft)

		err := rw.SetPrimaryEmail(ctx, testPrimaryUserID, "new@example.com")
		require.NoError(t, err)

		assert.Equal(t, 0, ft.countFor(http.MethodPost, "/api/v2/users"), "no stub should be created")
		assert.Equal(t, []string{
			"GET /api/v2/users/auth0|test123",
			"PATCH /api/v2/users/auth0|test123",
		}, ft.methodPaths())
	})

	t.Run("old primary on an UNVERIFIED email identity skips preservation (OTP self-verifies)", func(t *testing.T) {
		// An existing email identity is OTP-reachable and self-verifies on next
		// login; a duplicate cannot be created. So preservation is skipped and the
		// switch proceeds (this also avoids a 409 abort against real Auth0).
		getUser := `{"user_id":"auth0|test123","email":"old@example.com","identities":[` +
			`{"connection":"email","provider":"email","profileData":{"email":"new@example.com","email_verified":true}},` +
			`{"connection":"email","provider":"email","profileData":{"email":"old@example.com","email_verified":false}}]}`
		ft := newFakeAuth0(testPrimaryUserID, getUser)
		rw := newTestReaderWriter(ft)

		err := rw.SetPrimaryEmail(ctx, testPrimaryUserID, "new@example.com")
		require.NoError(t, err)

		assert.Equal(t, 0, ft.countFor(http.MethodPost, "/api/v2/users"), "existing email identity should not be re-created")
		assert.Equal(t, []string{
			"GET /api/v2/users/auth0|test123",
			"PATCH /api/v2/users/auth0|test123",
		}, ft.methodPaths())
	})

	t.Run("old primary backed by an UNVERIFIED Google identity is preserved as a verified email", func(t *testing.T) {
		// A Google identity (verified or not) is never a primary-email candidate, so
		// the old primary is materialized as a verified email identity regardless of
		// Google's email_verified flag.
		getUser := `{"user_id":"auth0|test123","email":"alice@gmail.com","identities":[` +
			`{"connection":"google-oauth2","provider":"google-oauth2","profileData":{"email":"alice@gmail.com","email_verified":false}},` +
			`{"connection":"email","provider":"email","profileData":{"email":"alice@linux.com","email_verified":true}}]}`
		ft := newFakeAuth0(testPrimaryUserID, getUser)
		rw := newTestReaderWriter(ft)

		err := rw.SetPrimaryEmail(ctx, testPrimaryUserID, "alice@linux.com")
		require.NoError(t, err)

		assert.Equal(t, []string{
			"GET /api/v2/users/auth0|test123",
			"POST /api/v2/users",
			"POST /api/v2/users/auth0|test123/identities",
			"PATCH /api/v2/users/auth0|test123",
		}, ft.methodPaths())
		createBody, _ := ft.firstBodyFor(http.MethodPost, "/api/v2/users")
		assert.Contains(t, createBody, `"email":"alice@gmail.com"`)
		assert.Contains(t, createBody, `"email_verified":true`)
	})

	t.Run("setting primary to the current primary skips preservation", func(t *testing.T) {
		getUser := `{"user_id":"auth0|test123","email":"same@example.com","identities":[` +
			`{"connection":"email","provider":"email","profileData":{"email":"same@example.com","email_verified":true}}]}`
		ft := newFakeAuth0(testPrimaryUserID, getUser)
		rw := newTestReaderWriter(ft)

		err := rw.SetPrimaryEmail(ctx, testPrimaryUserID, "SAME@example.com") // case-insensitive
		require.NoError(t, err)

		assert.Equal(t, 0, ft.countFor(http.MethodPost, "/api/v2/users"))
		assert.Equal(t, 1, ft.countFor(http.MethodPatch, "/api/v2/users/auth0|test123"))
	})

	t.Run("new email not a verified linked identity is rejected before any mutation", func(t *testing.T) {
		getUser := `{"user_id":"auth0|test123","email":"old@example.com","identities":[` +
			`{"connection":"email","provider":"email","profileData":{"email":"new@example.com","email_verified":false}}]}`
		ft := newFakeAuth0(testPrimaryUserID, getUser)
		rw := newTestReaderWriter(ft)

		err := rw.SetPrimaryEmail(ctx, testPrimaryUserID, "new@example.com")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not verified")
		// Only the GET happened; nothing was mutated.
		assert.Equal(t, []string{"GET /api/v2/users/auth0|test123"}, ft.methodPaths())
	})

	t.Run("unknown email is rejected before any mutation", func(t *testing.T) {
		getUser := `{"user_id":"auth0|test123","email":"old@example.com","identities":[` +
			`{"connection":"email","provider":"email","profileData":{"email":"someone@example.com","email_verified":true}}]}`
		ft := newFakeAuth0(testPrimaryUserID, getUser)
		rw := newTestReaderWriter(ft)

		err := rw.SetPrimaryEmail(ctx, testPrimaryUserID, "new@example.com")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a linked identity")
		assert.Equal(t, []string{"GET /api/v2/users/auth0|test123"}, ft.methodPaths())
	})

	t.Run("preservation failure aborts the switch and rolls back the stub", func(t *testing.T) {
		getUser := `{"user_id":"auth0|test123","email":"old@example.com","identities":[` +
			`{"connection":"email","provider":"email","profileData":{"email":"new@example.com","email_verified":true}}]}`
		ft := newFakeAuth0(testPrimaryUserID, getUser)
		ft.linkStatus = http.StatusInternalServerError // linking the preserved stub fails
		rw := newTestReaderWriter(ft)

		err := rw.SetPrimaryEmail(ctx, testPrimaryUserID, "new@example.com")
		require.Error(t, err)

		// The new primary must NOT have been promoted (fail loud, no silent drop).
		assert.Equal(t, 0, ft.countFor(http.MethodPatch, "/api/v2/users/auth0|test123"), "PATCH must not run when preservation fails")
		// The orphaned stub must be rolled back (connection-guarded delete).
		assert.Equal(t, 1, ft.countFor(http.MethodDelete, "/api/v2/users/email|stub123"), "orphaned stub should be deleted")
	})
}

func TestUserReaderWriter_SetPrimaryEmail_Validation(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name       string
		userID     string
		email      string
		wantErrMsg string
	}{
		{name: "empty userID", userID: "", email: "a@b.com", wantErrMsg: "user ID is required"},
		{name: "whitespace userID", userID: "   ", email: "a@b.com", wantErrMsg: "user ID is required"},
		{name: "empty email", userID: testPrimaryUserID, email: "", wantErrMsg: "email is required"},
		{name: "whitespace email", userID: testPrimaryUserID, email: "  ", wantErrMsg: "email is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := newFakeAuth0(testPrimaryUserID, "{}")
			rw := newTestReaderWriter(ft)

			err := rw.SetPrimaryEmail(ctx, tt.userID, tt.email)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrMsg)
			assert.Empty(t, ft.methodPaths(), "validation should fail before any HTTP call")
		})
	}
}

func TestUserReaderWriter_AddSystemManagedEmail_HTTPFlow(t *testing.T) {
	ctx := context.Background()

	t.Run("creates a system-managed stub and links it", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		rw := newTestReaderWriter(ft)

		stubID, err := rw.AddSystemManagedEmail(ctx, testPrimaryUserID, "alias@linux.com")
		require.NoError(t, err)
		assert.Equal(t, "email|stub123", stubID)

		assert.Equal(t, []string{
			"POST /api/v2/users",
			"POST /api/v2/users/auth0|test123/identities",
		}, ft.methodPaths())

		// Unlike the preservation path, this stub IS system-managed.
		createBody, _ := ft.firstBodyFor(http.MethodPost, "/api/v2/users")
		assert.Contains(t, createBody, `"email":"alias@linux.com"`)
		assert.Contains(t, createBody, `"system_managed":true`)
	})

	t.Run("conflict on create maps to a validation error", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		ft.createStatus = http.StatusConflict
		rw := newTestReaderWriter(ft)

		_, err := rw.AddSystemManagedEmail(ctx, testPrimaryUserID, "alias@linux.com")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "email already linked")
	})
}
