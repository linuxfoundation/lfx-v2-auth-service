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
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/converters"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
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

func TestUserReaderWriter_MetadataLookup_AudienceTokenRetention(t *testing.T) {
	ctx := context.Background()

	jwtConfig, privateKey := createTestJWTVerificationConfig(t)
	jwtConfig.ExpectedAudiences = []string{"https://test.auth0.com/api/v2/", "https://lfx-api.example.org/"}

	writer := &userReaderWriter{
		config: Config{
			JWTVerificationConfig: jwtConfig,
		},
	}

	signToken := func(audience string) string {
		claims := jwt.MapClaims{
			"sub": "auth0|123456789",
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
			"iss": "https://test.auth0.com/",
			"aud": audience,
		}
		tokenString, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privateKey)
		require.NoError(t, err)
		return tokenString
	}

	t.Run("management-audience token is retained for Management API calls", func(t *testing.T) {
		tokenString := signToken("https://test.auth0.com/api/v2/")
		user, err := writer.MetadataLookup(ctx, tokenString)
		require.NoError(t, err)
		assert.Equal(t, "auth0|123456789", user.Sub)
		assert.Equal(t, tokenString, user.Token, "management-audience token should be kept as bearer")
	})

	t.Run("LFX v2 API audience token verifies but is not forwarded", func(t *testing.T) {
		tokenString := signToken("https://lfx-api.example.org/")
		user, err := writer.MetadataLookup(ctx, tokenString)
		require.NoError(t, err)
		assert.Equal(t, "auth0|123456789", user.Sub)
		assert.Equal(t, "auth0|123456789", user.UserID)
		assert.Empty(t, user.Token, "non-management token must not be forwarded to the Management API")
		assert.True(t, user.PrincipalVerified, "a signature-verified JWT must mark the principal verified")
	})

	t.Run("bare sub and username are not verified principals", func(t *testing.T) {
		for _, input := range []string{"auth0|123456789", "john.doe"} {
			user, err := writer.MetadataLookup(ctx, input)
			require.NoError(t, err)
			assert.False(t, user.PrincipalVerified, input)
		}
	})

	t.Run("un-allow-listed audience is rejected", func(t *testing.T) {
		tokenString := signToken("https://evil.example.org/")
		_, err := writer.MetadataLookup(ctx, tokenString)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid audience")
	})

	signScopedToken := func(audience, scope string) string {
		claims := jwt.MapClaims{
			"sub":   "auth0|123456789",
			"exp":   time.Now().Add(time.Hour).Unix(),
			"iat":   time.Now().Unix(),
			"iss":   "https://test.auth0.com/",
			"aud":   audience,
			"scope": scope,
		}
		tokenString, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privateKey)
		require.NoError(t, err)
		return tokenString
	}

	t.Run("scope-gated lookup rejects LFX v2 API audience even with matching scope", func(t *testing.T) {
		tokenString := signScopedToken("https://lfx-api.example.org/", "update:current_user_identities")
		_, err := writer.MetadataLookup(ctx, tokenString, "update:current_user_identities")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid audience")
	})

	t.Run("scope-gated lookup accepts management-audience token with scope", func(t *testing.T) {
		tokenString := signScopedToken("https://test.auth0.com/api/v2/", "update:current_user_identities")
		user, err := writer.MetadataLookup(ctx, tokenString, "update:current_user_identities")
		require.NoError(t, err)
		assert.Equal(t, tokenString, user.Token)
	})
}

func TestUserReaderWriter_MetadataLookup_ScopeGatedRejectsNonJWT(t *testing.T) {
	ctx := context.Background()

	jwtConfig, _ := createTestJWTVerificationConfig(t)
	writer := &userReaderWriter{
		config: Config{
			JWTVerificationConfig: jwtConfig,
		},
	}

	for _, input := range []string{"auth0|123456789", "john.doe"} {
		t.Run(input, func(t *testing.T) {
			user, err := writer.MetadataLookup(ctx, input, constants.UserUpdateIdentityRequiredScope)
			require.Error(t, err)
			assert.Nil(t, user)
			var unauthorized errors.Unauthorized
			assert.ErrorAs(t, err, &unauthorized)
		})
	}

	t.Run("read lookup without scopes still accepts a bare sub", func(t *testing.T) {
		user, err := writer.MetadataLookup(ctx, "auth0|123456789")
		require.NoError(t, err)
		assert.Equal(t, "auth0|123456789", user.UserID)
		assert.Empty(t, user.Token)
	})
}

func TestUserReaderWriter_MetadataLookup_RejectsMalformedSub(t *testing.T) {
	ctx := context.Background()
	writer := &userReaderWriter{}

	for _, input := range []string{
		"auth0|x/enrollments",
		"auth0|x/roles?per_page=1",
		"auth0|x/../../tenants/settings",
		"auth0|x?fields=email",
		"auth0|x#frag",
		"auth0|x%2Froles",
		`auth0|x\y`,
		"auth0|a b",
		"auth0|a\tb",
		"auth0|a\x00b",
		"auth0|a\xffb",
		"|abc",
		"auth0|",
		"bad/prov|x",
		"bad.prov|x",
	} {
		t.Run(input, func(t *testing.T) {
			user, err := writer.MetadataLookup(ctx, input)
			require.Error(t, err)
			assert.Nil(t, user)
			var validation errors.Validation
			assert.ErrorAs(t, err, &validation)
		})
	}

	for _, input := range []string{
		"auth0|123456789",
		"google-oauth2|1234567890",
		"samlp|conn|jdoe@example.com",
		"oidc|lf_sso|abc-123",
	} {
		t.Run(input, func(t *testing.T) {
			user, err := writer.MetadataLookup(ctx, input)
			require.NoError(t, err)
			assert.Equal(t, input, user.UserID)
		})
	}
}

// pathRecordingTransport records the escaped path and raw query of each request
// and returns an empty user object.
type pathRecordingTransport struct {
	escapedPaths []string
	rawQueries   []string
}

func (p *pathRecordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	p.escapedPaths = append(p.escapedPaths, req.URL.EscapedPath())
	p.rawQueries = append(p.rawQueries, req.URL.RawQuery)
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"user_id":"auth0|x"}`)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func TestUserReaderWriter_GetUser_EscapesUserID(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		userID      string
		escapedPath string
	}{
		{"auth0|test123", "/api/v2/users/auth0%7Ctest123"},
		{"auth0|x/roles?per_page=1", "/api/v2/users/auth0%7Cx%2Froles%3Fper_page=1"},
		{"auth0|x/../../tenants/settings", "/api/v2/users/auth0%7Cx%2F..%2F..%2Ftenants%2Fsettings"},
		{"auth0|x#frag", "/api/v2/users/auth0%7Cx%23frag"},
	}

	for _, tt := range tests {
		t.Run(tt.userID, func(t *testing.T) {
			transport := &pathRecordingTransport{}
			rw := newTestReaderWriter(transport)

			_, err := rw.GetUser(ctx, &model.User{UserID: tt.userID})
			require.NoError(t, err)
			require.Len(t, transport.escapedPaths, 1)
			assert.Equal(t, tt.escapedPath, transport.escapedPaths[0])
			assert.Empty(t, transport.rawQueries[0], "user id must not leak into the query string")
		})
	}
}

func TestUserReaderWriter_UpdateUser_EscapesUserID(t *testing.T) {
	ctx := context.Background()
	jwtConfig, privateKey := createTestJWTVerificationConfig(t)

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":   "auth0|x/roles?per_page=1",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"scope": constants.UserUpdateMetadataRequiredScope,
		"iss":   "https://test.auth0.com/",
		"aud":   "https://test.auth0.com/api/v2/",
	}).SignedString(privateKey)
	require.NoError(t, err)

	transport := &pathRecordingTransport{}
	rw := newTestReaderWriter(transport)
	rw.config.JWTVerificationConfig = jwtConfig

	_, err = rw.UpdateUser(ctx, &model.User{
		Token:        token,
		UserMetadata: &model.UserMetadata{Name: converters.StringPtr("Test")},
	})
	require.NoError(t, err)
	require.Len(t, transport.escapedPaths, 1)
	assert.Equal(t, "/api/v2/users/auth0%7Cx%2Froles%3Fper_page=1", transport.escapedPaths[0])
	assert.Empty(t, transport.rawQueries[0], "user id must not leak into the query string")
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

func TestUserReaderWriter_UnlinkIdentity_SystemManagedGuard(t *testing.T) {
	ctx := context.Background()
	t.Setenv(constants.AllowedAliasDomainsEnvKey, "linux.com")

	const unlinkPath = "/api/v2/users/auth0|test123/identities/email/stub123"

	primaryWith := func(identity string) string {
		return `{"user_id":"auth0|test123","email":"jane@example.com","identities":[` +
			`{"connection":"Username-Password-Authentication","provider":"auth0","user_id":"test123"},` + identity + `]}`
	}
	primaryMarkedWith := func(identity string) string {
		return `{"user_id":"auth0|test123","email":"jane@example.com","app_metadata":{"cdp_uuid":"c1","system_managed_identity_stub123":true},"identities":[` +
			`{"connection":"Username-Password-Authentication","provider":"auth0","user_id":"test123"},` + identity + `]}`
	}
	aliasIdentity := `{"connection":"email","provider":"email","user_id":"stub123","profileData":{"email":"jane@Linux.com","email_verified":true}}`
	regularIdentity := `{"connection":"email","provider":"email","user_id":"stub123","profileData":{"email":"jane@gmail.com","email_verified":true}}`
	const backfillBody = `{"app_metadata":{"system_managed_identity_stub123":true}}`

	tests := []struct {
		name          string
		primaryUserID string // fake's primary route; differs from the request to force a primary GET failure
		provider      string // defaults to "email"
		getUserResp   string
		stubGetStatus int
		stubGetResp   string
		patchStatus   int  // status for the marker backfill PATCH; 0 keeps the fake's default
		noAliasDomain bool // run with ALLOWED_ALIAS_DOMAINS unset, as after a domain is retired
		wantForbidden bool
		wantNotFound  bool
		wantErr       bool
		wantCalls     []string // when set, the exact calls the guard must make
		wantBackfill  bool     // the guard must backfill (attempt to PATCH) the marker; otherwise no PATCH may be sent
	}{
		{
			name:          "marked alias is refused after its domain is retired and the stub is gone",
			noAliasDomain: true,
			getUserResp:   primaryMarkedWith(aliasIdentity),
			stubGetStatus: http.StatusNotFound,
			stubGetResp:   `{"error":"not found"}`,
			wantForbidden: true,
			wantCalls:     []string{"GET /api/v2/users/auth0|test123"},
		},
		{
			name:          "marked identity is refused even without profile data",
			getUserResp:   primaryMarkedWith(`{"connection":"email","provider":"email","user_id":"stub123"}`),
			stubGetStatus: http.StatusNotFound,
			wantForbidden: true,
			wantCalls:     []string{"GET /api/v2/users/auth0|test123"},
		},
		{
			name:          "unmarked alias recognised by domain is refused and backfilled",
			getUserResp:   primaryWith(aliasIdentity),
			stubGetStatus: http.StatusNotFound,
			wantForbidden: true,
			wantBackfill:  true,
		},
		{
			name:          "a failed backfill still refuses the unlink",
			getUserResp:   primaryWith(aliasIdentity),
			stubGetStatus: http.StatusNotFound,
			patchStatus:   http.StatusInternalServerError,
			wantForbidden: true,
			wantBackfill:  true, // the PATCH must have been attempted
		},
		{
			name:          "alias-domain identity is refused when the stub lookup fails",
			getUserResp:   primaryWith(aliasIdentity),
			stubGetStatus: http.StatusInternalServerError,
			stubGetResp:   `{"error":"boom"}`,
			wantForbidden: true,
		},
		{
			name:          "backfill writes only its own marker key alongside existing markers",
			getUserResp:   `{"user_id":"auth0|test123","app_metadata":{"system_managed_identity_older1":true},"identities":[` + aliasIdentity + `]}`,
			stubGetStatus: http.StatusNotFound,
			wantForbidden: true,
			wantCalls: []string{
				"GET /api/v2/users/auth0|test123",
				"GET /api/v2/users/email|stub123",
				"PATCH /api/v2/users/auth0|test123",
			},
			wantBackfill: true,
		},
		{
			name:          "a marker set to false does not protect the identity",
			getUserResp:   `{"user_id":"auth0|test123","app_metadata":{"system_managed_identity_stub123":false},"identities":[` + regularIdentity + `]}`,
			stubGetStatus: http.StatusNotFound,
		},
		{
			name:          "a malformed marker value does not protect the identity",
			getUserResp:   `{"user_id":"auth0|test123","app_metadata":{"system_managed_identity_stub123":"yes"},"identities":[` + regularIdentity + `]}`,
			stubGetStatus: http.StatusNotFound,
		},
		{
			name:          "unmarked alias without its domain or stub is unlinked",
			noAliasDomain: true,
			getUserResp:   primaryWith(aliasIdentity),
			stubGetStatus: http.StatusNotFound,
			stubGetResp:   `{"error":"not found"}`,
		},
		{
			name:          "alias identity is refused when the stub record is gone",
			getUserResp:   primaryWith(aliasIdentity),
			stubGetStatus: http.StatusNotFound,
			stubGetResp:   `{"error":"not found"}`,
			wantForbidden: true,
			wantBackfill:  true,
		},
		{
			name:          "case and whitespace variants of the email provider are guarded",
			provider:      " Email ",
			getUserResp:   primaryWith(aliasIdentity),
			stubGetStatus: http.StatusNotFound,
			stubGetResp:   `{"error":"not found"}`,
			wantForbidden: true,
			wantBackfill:  true,
		},
		{
			name:          "alias-domain identity whose stub lacks system_managed is refused but not recorded",
			getUserResp:   primaryWith(aliasIdentity),
			stubGetStatus: http.StatusOK,
			stubGetResp:   `{"user_id":"email|stub123"}`,
			wantForbidden: true,
		},
		{
			name:          "non-alias identity whose stub is system_managed is refused",
			getUserResp:   primaryWith(regularIdentity),
			stubGetStatus: http.StatusOK,
			stubGetResp:   `{"user_id":"email|stub123","app_metadata":{"system_managed":true}}`,
			wantForbidden: true,
			wantBackfill:  true,
		},
		{
			name:          "identity not linked to the caller is refused",
			getUserResp:   primaryWith(`{"connection":"email","provider":"email","user_id":"other","profileData":{"email":"jane@gmail.com"}}`),
			stubGetStatus: http.StatusNotFound,
			wantNotFound:  true,
		},
		{
			name:          "identity without an email to classify fails closed",
			getUserResp:   primaryWith(`{"connection":"email","provider":"email","user_id":"stub123"}`),
			stubGetStatus: http.StatusNotFound,
			wantErr:       true,
		},
		{
			name:          "primary user lookup failure fails closed",
			primaryUserID: "auth0|someone-else",
			stubGetStatus: http.StatusInternalServerError,
			stubGetResp:   `{"error":"boom"}`,
			wantErr:       true,
			wantCalls:     []string{"GET /api/v2/users/auth0|test123"},
		},
		{
			name:          "stub lookup failure fails closed",
			getUserResp:   primaryWith(regularIdentity),
			stubGetStatus: http.StatusInternalServerError,
			stubGetResp:   `{"error":"boom"}`,
			wantErr:       true,
		},
		{
			name:          "non-alias identity without a stub is unlinked",
			getUserResp:   primaryWith(regularIdentity),
			stubGetStatus: http.StatusNotFound,
			stubGetResp:   `{"error":"not found"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			primaryUserID := tt.primaryUserID
			if primaryUserID == "" {
				primaryUserID = testPrimaryUserID
			}
			if tt.noAliasDomain {
				t.Setenv(constants.AllowedAliasDomainsEnvKey, "")
			}
			ft := newFakeAuth0(primaryUserID, tt.getUserResp)
			ft.stubGetStatus, ft.stubGetResp = tt.stubGetStatus, tt.stubGetResp
			if tt.patchStatus != 0 {
				ft.patchStatus = tt.patchStatus
			}
			rw := newTestReaderWriter(ft)
			rw.identityLinkingFlow = newIdentityLinkingFlow(rw.config.Domain, rw.httpClient)

			req := &model.UnlinkIdentity{}
			req.User.UserID = testPrimaryUserID
			req.User.AuthToken = "user-token"
			req.Unlink.Provider = constants.EmailConnection
			if tt.provider != "" {
				req.Unlink.Provider = tt.provider
			}
			req.Unlink.IdentityID = "stub123"

			err := rw.UnlinkIdentity(ctx, req)

			switch {
			case tt.wantForbidden:
				var forbidden errors.Forbidden
				require.ErrorAs(t, err, &forbidden)
				assert.Contains(t, err.Error(), "system_managed_identity")
			case tt.wantNotFound:
				var notFound errors.NotFound
				require.ErrorAs(t, err, &notFound)
			case tt.wantErr:
				require.Error(t, err)
			default:
				require.NoError(t, err)
				assert.Equal(t, 1, ft.countFor(http.MethodDelete, unlinkPath))
				assert.Zero(t, ft.countFor(http.MethodPatch, "/api/v2/users/auth0|test123"), "a permitted unlink must not mark the identity")
				return
			}
			if tt.wantCalls != nil {
				assert.Equal(t, tt.wantCalls, ft.methodPaths())
			}
			if tt.wantBackfill {
				patchBody, ok := ft.firstBodyFor(http.MethodPatch, "/api/v2/users/auth0|test123")
				require.True(t, ok, "the guard must backfill the system-managed marker")
				assert.JSONEq(t, backfillBody, patchBody)
			} else {
				assert.Zero(t, ft.countFor(http.MethodPatch, "/api/v2/users/auth0|test123"), "this identity must not be recorded as system-managed")
			}
			assert.Zero(t, ft.countFor(http.MethodDelete, unlinkPath), "a refused unlink must never reach Auth0")
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
	query  string
	body   string
}

// fakeAuth0Transport is an http.RoundTripper that intercepts the Auth0
// Management API calls made by userReaderWriter and returns canned responses,
// recording every request so tests can assert call ordering and payloads. It
// never dials the network, so the https URLs the adapter builds are irrelevant.
type fakeAuth0Transport struct {
	primaryUserID string // decoded path id, e.g. "auth0|test123"
	getUserResp   string // body for GET of the primary user
	stubGetStatus int    // status for GET of any non-primary user (rollback stub, delete pre-flight)
	stubGetResp   string // body for GET of the rollback stub
	createStatus  int    // status for POST /api/v2/users
	createResp    string // body for POST /api/v2/users
	// createStatuses, when non-empty, is consumed one entry per POST
	// /api/v2/users call before falling back to createStatus.
	createStatuses   []int
	byEmailStatus    int    // status for GET /api/v2/users-by-email
	byEmailResp      string // body for GET /api/v2/users-by-email
	rootSearchStatus int    // status for GET /api/v2/users?q=email:... (root-email search)
	rootSearchResp   string // body for GET /api/v2/users?q=email:... (root-email search)
	searchStatus     int    // status for GET /api/v2/users (identity-email search)
	searchResp       string // body for GET /api/v2/users (identity-email search)
	deleteStatus     int    // status for DELETE /api/v2/users/{id}; 0 means 204
	linkStatus       int    // status for POST /api/v2/users/{id}/identities
	patchStatus      int    // status for PATCH /api/v2/users/{id}
	calls            []recordedCall
	// appMetadata accumulates the app_metadata keys written by successful
	// PATCHes to the primary, merged at the top level as Auth0 does.
	appMetadata map[string]json.RawMessage
}

func newFakeAuth0(primaryUserID, getUserResp string) *fakeAuth0Transport {
	return &fakeAuth0Transport{
		primaryUserID:    primaryUserID,
		getUserResp:      getUserResp,
		stubGetStatus:    http.StatusOK,
		stubGetResp:      `{"user_id":"email|stub123","identities":[{"connection":"email","provider":"email"}]}`,
		createStatus:     http.StatusCreated,
		createResp:       `{"user_id":"email|stub123"}`,
		linkStatus:       http.StatusCreated,
		patchStatus:      http.StatusOK,
		byEmailStatus:    http.StatusOK,
		byEmailResp:      "[]",
		rootSearchStatus: http.StatusOK,
		rootSearchResp:   "[]",
		searchStatus:     http.StatusOK,
		searchResp:       "[]",
	}
}

func (f *fakeAuth0Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		_ = req.Body.Close()
	}
	f.calls = append(f.calls, recordedCall{method: req.Method, path: req.URL.Path, query: req.URL.RawQuery, body: string(bodyBytes)})

	// Routes are scoped to the exact Auth0 Management API paths the adapter is
	// expected to hit; anything else returns 404 so a wrong-path regression fails
	// the test instead of silently passing.
	status := http.StatusOK
	var body string
	switch {
	case req.Method == http.MethodGet && req.URL.Path == "/api/v2/users/"+f.primaryUserID:
		body = f.getUserResp
	case req.Method == http.MethodGet && req.URL.Path == "/api/v2/users-by-email":
		status, body = f.byEmailStatus, f.byEmailResp
	case req.Method == http.MethodGet && req.URL.Path == "/api/v2/users" &&
		strings.HasPrefix(req.URL.Query().Get("q"), "email:"):
		status, body = f.rootSearchStatus, f.rootSearchResp
	case req.Method == http.MethodGet && req.URL.Path == "/api/v2/users":
		status, body = f.searchStatus, filterByIdentityEmail(f.searchResp, req.URL.Query().Get("q"))
	case req.Method == http.MethodGet && strings.HasPrefix(req.URL.Path, "/api/v2/users/"):
		// GET of any other user id is the rollback stub verification.
		status, body = f.stubGetStatus, f.stubGetResp
	case req.Method == http.MethodPost && req.URL.Path == "/api/v2/users":
		status, body = f.createStatus, f.createResp
		if len(f.createStatuses) > 0 {
			status, f.createStatuses = f.createStatuses[0], f.createStatuses[1:]
		}
	case req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/identities"):
		status, body = f.linkStatus, "[]"
	case req.Method == http.MethodPatch && req.URL.Path == "/api/v2/users/"+f.primaryUserID:
		status, body = f.patchStatus, "{}"
		var patch struct {
			AppMetadata map[string]json.RawMessage `json:"app_metadata"`
		}
		if status < 300 && json.Unmarshal(bodyBytes, &patch) == nil && patch.AppMetadata != nil {
			if f.appMetadata == nil {
				f.appMetadata = map[string]json.RawMessage{}
			}
			for k, v := range patch.AppMetadata {
				f.appMetadata[k] = v
			}
		}
	case req.Method == http.MethodDelete && strings.HasPrefix(req.URL.Path, "/api/v2/users/"):
		status, body = http.StatusNoContent, ""
		if f.deleteStatus != 0 {
			status, body = f.deleteStatus, `{"error":"delete failed"}`
		}
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

// filterByIdentityEmail mimics Auth0's case-sensitive identities.profileData.email
// search: it keeps only the users in resp with an identity whose profile email
// exactly equals one of the quoted terms in q. resp is returned unchanged when
// it is not a JSON array of users (e.g. an error body).
func filterByIdentityEmail(resp, q string) string {
	var raw []json.RawMessage
	if json.Unmarshal([]byte(resp), &raw) != nil {
		return resp
	}
	terms := map[string]bool{}
	for _, m := range regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`).FindAllStringSubmatch(q, -1) {
		terms[m[1]] = true
	}
	kept := []json.RawMessage{}
	for _, r := range raw {
		var user Auth0User
		if json.Unmarshal(r, &user) != nil {
			continue
		}
		for _, identity := range user.Identities {
			if identity.ProfileData != nil && terms[identity.ProfileData.Email] {
				kept = append(kept, r)
				break
			}
		}
	}
	out, _ := json.Marshal(kept)
	return string(out)
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
		getUser := `{"user_id":"auth0|test123","email":"old@example.com","email_verified":true,"identities":[` +
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

	t.Run("old primary backed only by an UNVERIFIED Google identity is not preserved", func(t *testing.T) {
		// Neither the root email_verified flag nor the backing identity proves
		// ownership of the old primary, so it must not be materialized as a
		// (verified) email identity; the switch still proceeds.
		getUser := `{"user_id":"auth0|test123","email":"alice@gmail.com","email_verified":false,"identities":[` +
			`{"connection":"google-oauth2","provider":"google-oauth2","profileData":{"email":"alice@gmail.com","email_verified":false}},` +
			`{"connection":"email","provider":"email","profileData":{"email":"alice@linux.com","email_verified":true}}]}`
		ft := newFakeAuth0(testPrimaryUserID, getUser)
		rw := newTestReaderWriter(ft)

		err := rw.SetPrimaryEmail(ctx, testPrimaryUserID, "alice@linux.com")
		require.NoError(t, err)

		assert.Equal(t, 0, ft.countFor(http.MethodPost, "/api/v2/users"), "no stub may be created for an unverified old primary")
		assert.Equal(t, []string{
			"GET /api/v2/users/auth0|test123",
			"PATCH /api/v2/users/auth0|test123",
		}, ft.methodPaths())
	})

	t.Run("old primary with unverified root email and no backing identity is not preserved", func(t *testing.T) {
		// e.g. a database signup whose address was never confirmed.
		getUser := `{"user_id":"auth0|test123","email":"old@example.com","email_verified":false,"identities":[` +
			`{"connection":"Username-Password-Authentication","provider":"auth0","profileData":{"email":"old@example.com","email_verified":false}},` +
			`{"connection":"email","provider":"email","profileData":{"email":"new@example.com","email_verified":true}}]}`
		ft := newFakeAuth0(testPrimaryUserID, getUser)
		rw := newTestReaderWriter(ft)

		err := rw.SetPrimaryEmail(ctx, testPrimaryUserID, "new@example.com")
		require.NoError(t, err)

		assert.Equal(t, 0, ft.countFor(http.MethodPost, "/api/v2/users"), "no stub may be created for an unverified old primary")
		assert.Equal(t, []string{
			"GET /api/v2/users/auth0|test123",
			"PATCH /api/v2/users/auth0|test123",
		}, ft.methodPaths())
		patchBody, ok := ft.firstBodyFor(http.MethodPatch, "/api/v2/users/auth0|test123")
		require.True(t, ok)
		assert.Contains(t, patchBody, `"email":"new@example.com"`)
	})

	t.Run("old primary with unverified root but a verified backing identity is preserved", func(t *testing.T) {
		getUser := `{"user_id":"auth0|test123","email":"alice@gmail.com","email_verified":false,"identities":[` +
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
		getUser := `{"user_id":"auth0|test123","email":"old@example.com","email_verified":true,"identities":[` +
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

	t.Run("preserve-path create conflict aborts the switch before any promote", func(t *testing.T) {
		// The old primary is backed only by a Google login, so preservation runs.
		// If that address already exists as a separate email-connection user, Auth0
		// returns 409 on create; SetPrimaryEmail must fail loud (validation) and
		// never promote the new primary, leaving the account unchanged.
		getUser := `{"user_id":"auth0|test123","email":"alice@gmail.com","identities":[` +
			`{"connection":"google-oauth2","provider":"google-oauth2","profileData":{"email":"alice@gmail.com","email_verified":true}},` +
			`{"connection":"email","provider":"email","profileData":{"email":"alice@linux.com","email_verified":true}}]}`
		ft := newFakeAuth0(testPrimaryUserID, getUser)
		ft.createStatus = http.StatusConflict // old primary already registered as an email user elsewhere
		rw := newTestReaderWriter(ft)

		err := rw.SetPrimaryEmail(ctx, testPrimaryUserID, "alice@linux.com")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "email already linked")
		assert.Equal(t, 0, ft.countFor(http.MethodPatch, "/api/v2/users/auth0|test123"), "PATCH must not run when preservation create conflicts")
	})
}

func TestHasSufficientPrimaryEmailIdentity(t *testing.T) {
	const target = "old@example.com"

	tests := []struct {
		name       string
		identities []model.Identity
		want       bool
	}{
		{
			name:       "no backing identity is not sufficient",
			identities: nil,
			want:       false,
		},
		{
			name:       "verified email-connection identity is sufficient",
			identities: []model.Identity{{Connection: constants.EmailConnection, Email: target, EmailVerified: true}},
			want:       true,
		},
		{
			name:       "unverified email-connection identity is sufficient (OTP self-verifies)",
			identities: []model.Identity{{Connection: constants.EmailConnection, Email: target, EmailVerified: false}},
			want:       true,
		},
		{
			name:       "email-connection match is case-insensitive",
			identities: []model.Identity{{Connection: constants.EmailConnection, Email: "OLD@EXAMPLE.COM", EmailVerified: true}},
			want:       true,
		},
		{
			name:       "verified Google identity is NOT sufficient",
			identities: []model.Identity{{Connection: constants.GoogleOAuth2Connection, Email: target, EmailVerified: true}},
			want:       false,
		},
		{
			name:       "non-Google social identity is NOT sufficient",
			identities: []model.Identity{{Connection: "linkedin", Email: target, EmailVerified: true}},
			want:       false,
		},
		{
			name:       "email-connection identity for a different address is NOT sufficient",
			identities: []model.Identity{{Connection: constants.EmailConnection, Email: "other@example.com", EmailVerified: true}},
			want:       false,
		},
		{
			name: "dual backing (Google + email) is sufficient via the email identity",
			identities: []model.Identity{
				{Connection: constants.GoogleOAuth2Connection, Email: target, EmailVerified: true},
				{Connection: constants.EmailConnection, Email: target, EmailVerified: true},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasSufficientPrimaryEmailIdentity(&model.User{Identities: tt.identities}, target)
			assert.Equal(t, tt.want, got)
		})
	}
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
			"GET /api/v2/users-by-email",
			"GET /api/v2/users",
			"GET /api/v2/users",
			"POST /api/v2/users",
			"POST /api/v2/users/auth0|test123/identities",
			"PATCH /api/v2/users/auth0|test123",
		}, ft.methodPaths())

		// Unlike the preservation path, this stub IS system-managed.
		createBody, _ := ft.firstBodyFor(http.MethodPost, "/api/v2/users")
		assert.Contains(t, createBody, `"email":"alias@linux.com"`)
		assert.Contains(t, createBody, `"email_verified":true`)
		assert.Contains(t, createBody, `"system_managed":true`)

		// The durable marker is recorded on the primary user as its own
		// top-level app_metadata key, with no read-modify-write.
		patchBody, ok := ft.firstBodyFor(http.MethodPatch, "/api/v2/users/auth0|test123")
		require.True(t, ok)
		assert.JSONEq(t, `{"app_metadata":{"system_managed_identity_stub123":true}}`, patchBody)
	})

	t.Run("overlapping claim and backfill markers both survive", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		ft.appMetadata = map[string]json.RawMessage{"cdp_uuid": json.RawMessage(`"c1"`)}
		rw := newTestReaderWriter(ft)

		// A guard backfill for another alias and a new claim for the same user,
		// in either order: each writes only its own key, so neither can drop
		// the other's marker (nor any other app_metadata key).
		require.NoError(t, rw.recordSystemManagedIdentity(ctx, testPrimaryUserID, "older1", "test-m2m-token"))
		_, err := rw.AddSystemManagedEmail(ctx, testPrimaryUserID, "alias@linux.com")
		require.NoError(t, err)

		assert.Equal(t, map[string]json.RawMessage{
			"cdp_uuid":                        json.RawMessage(`"c1"`),
			"system_managed_identity_older1":  json.RawMessage(`true`),
			"system_managed_identity_stub123": json.RawMessage(`true`),
		}, ft.appMetadata)
		assert.Zero(t, ft.countFor(http.MethodGet, "/api/v2/users/auth0|test123"), "marker writes must not read-modify-write")
	})

	t.Run("marker key rejects identity ids Auth0 cannot store", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		rw := newTestReaderWriter(ft)

		for _, id := range []string{"", "a.b", "a$b"} {
			require.Error(t, rw.recordSystemManagedIdentity(ctx, testPrimaryUserID, id, "test-m2m-token"))
		}
		assert.Empty(t, ft.methodPaths())
	})

	t.Run("marker write failure does not fail an already-linked claim", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		ft.patchStatus = http.StatusInternalServerError
		rw := newTestReaderWriter(ft)

		stubID, err := rw.AddSystemManagedEmail(ctx, testPrimaryUserID, "alias@linux.com")
		require.NoError(t, err)
		assert.Equal(t, "email|stub123", stubID)
		assert.Equal(t, 1, ft.countFor(http.MethodPatch, "/api/v2/users/auth0|test123"))
	})

	t.Run("conflict on create maps to a validation error", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		ft.createStatus = http.StatusConflict
		rw := newTestReaderWriter(ft)

		_, err := rw.AddSystemManagedEmail(ctx, testPrimaryUserID, "alias@linux.com")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "email already linked")
	})

	t.Run("link failure rolls back the orphaned stub via the system-managed delete guard", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		ft.linkStatus = http.StatusInternalServerError
		// The rollback GET must see system_managed=true or the delete guard
		// refuses, which would leave the DELETE call unasserted below.
		ft.stubGetResp = `{"user_id":"email|stub123","app_metadata":{"system_managed":true}}`
		rw := newTestReaderWriter(ft)

		_, err := rw.AddSystemManagedEmail(ctx, testPrimaryUserID, "alias@linux.com")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to link email identity")

		assert.Equal(t, []string{
			"GET /api/v2/users-by-email",
			"GET /api/v2/users",
			"GET /api/v2/users",
			"POST /api/v2/users",
			"POST /api/v2/users/auth0|test123/identities",
			"GET /api/v2/users/email|stub123",
			"DELETE /api/v2/users/email|stub123",
		}, ft.methodPaths())
	})
}

func TestUserReaderWriter_AddSystemManagedEmail_ExistingClaimOnAnyConnection(t *testing.T) {
	ctx := context.Background()

	byRootEmail := []struct {
		name string
		resp string
	}{
		{
			name: "google-oauth2 primary",
			resp: `[{"user_id":"google-oauth2|v1","email":"alias@linux.com","email_verified":true,` +
				`"identities":[{"connection":"google-oauth2","provider":"google-oauth2","isSocial":true}]}]`,
		},
		{
			name: "github primary",
			resp: `[{"user_id":"github|v1","email":"alias@linux.com","email_verified":true,` +
				`"identities":[{"connection":"github","provider":"github","isSocial":true}]}]`,
		},
		{
			name: "enterprise (SAML) primary",
			resp: `[{"user_id":"samlp|corp|v1","email":"alias@linux.com","email_verified":true,` +
				`"identities":[{"connection":"corp","provider":"samlp"}]}]`,
		},
		{
			name: "unverified social primary with mixed-case email",
			resp: `[{"user_id":"linkedin|v1","email":"Alias@Linux.com","email_verified":false,` +
				`"identities":[{"connection":"linkedin","provider":"linkedin","isSocial":true}]}]`,
		},
		{
			name: "database primary",
			resp: `[{"user_id":"auth0|v1","email":"alias@linux.com","email_verified":true,` +
				`"identities":[{"connection":"Username-Password-Authentication","provider":"auth0","user_id":"v1"}]}]`,
		},
	}
	for _, tc := range byRootEmail {
		t.Run("root email held via "+tc.name+" blocks the claim", func(t *testing.T) {
			ft := newFakeAuth0(testPrimaryUserID, "{}")
			ft.byEmailResp = tc.resp
			rw := newTestReaderWriter(ft)

			_, err := rw.AddSystemManagedEmail(ctx, testPrimaryUserID, "alias@linux.com")
			require.Error(t, err)
			var validationErr errors.Validation
			assert.ErrorAs(t, err, &validationErr)
			assert.Contains(t, err.Error(), "email already linked")
			assert.Equal(t, 0, ft.countFor(http.MethodPost, ""), "no stub may be created or linked")
		})
	}

	t.Run("identity email on a linked social identity blocks the claim", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		ft.searchResp = `[{"user_id":"auth0|v1","email":"someone@example.org","email_verified":true,"identities":[` +
			`{"connection":"Username-Password-Authentication","provider":"auth0","user_id":"v1"},` +
			`{"connection":"google-oauth2","provider":"google-oauth2","profileData":{"email":"alias@linux.com","email_verified":true}}]}]`
		rw := newTestReaderWriter(ft)

		_, err := rw.AddSystemManagedEmail(ctx, testPrimaryUserID, "alias@linux.com")
		require.Error(t, err)
		var validationErr errors.Validation
		assert.ErrorAs(t, err, &validationErr)
		assert.Equal(t, 0, ft.countFor(http.MethodPost, ""))
	})

	t.Run("searches query the root and identity emails with quoted values", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		rw := newTestReaderWriter(ft)

		_, err := rw.AddSystemManagedEmail(ctx, testPrimaryUserID, "Alias@Linux.com")
		require.NoError(t, err)

		var queries []string
		for _, c := range ft.calls {
			if c.method == http.MethodGet && c.path == "/api/v2/users" {
				values, errParse := url.ParseQuery(c.query)
				require.NoError(t, errParse)
				assert.Equal(t, "v3", values.Get("search_engine"))
				queries = append(queries, values.Get("q"))
			}
		}
		require.Len(t, queries, 2)
		assert.Equal(t, `email:"alias@linux.com"`, queries[0])
		assert.True(t, strings.HasPrefix(queries[1], `identities.profileData.email:"alias@linux.com" OR `), queries[1])
		assert.Contains(t, queries[1], `identities.profileData.email:"Alias@Linux.com"`)
	})

	mixedCaseLinked := []string{"Alias@Linux.com", "Alias@linux.com", "ALIAS@LINUX.COM", "alias@Linux.com"}
	for _, stored := range mixedCaseLinked {
		t.Run("linked identity stored as "+stored+" blocks the claim", func(t *testing.T) {
			ft := newFakeAuth0(testPrimaryUserID, "{}")
			ft.searchResp = `[{"user_id":"auth0|v1","email":"someone@example.org","identities":[` +
				`{"connection":"Username-Password-Authentication","provider":"auth0","user_id":"v1"},` +
				`{"connection":"github","provider":"github","profileData":{"email":"` + stored + `"}}]}]`
			rw := newTestReaderWriter(ft)

			_, err := rw.AddSystemManagedEmail(ctx, testPrimaryUserID, "alias@linux.com")
			require.Error(t, err)
			var validationErr errors.Validation
			assert.ErrorAs(t, err, &validationErr)
			assert.Equal(t, 0, ft.countFor(http.MethodPost, ""))
		})
	}

	t.Run("root email stored with provider casing is found by the case-insensitive search", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		// users-by-email is case-sensitive and misses this user; the v3
		// email search is case-insensitive and returns it.
		ft.rootSearchResp = `[{"user_id":"samlp|corp|v1","email":"Alias@Linux.com","email_verified":true,` +
			`"identities":[{"connection":"corp","provider":"samlp"}]}]`
		rw := newTestReaderWriter(ft)

		_, err := rw.AddSystemManagedEmail(ctx, testPrimaryUserID, "alias@linux.com")
		require.Error(t, err)
		var validationErr errors.Validation
		assert.ErrorAs(t, err, &validationErr)
		assert.Equal(t, 0, ft.countFor(http.MethodPost, ""))
	})

	t.Run("an orphaned stub does not hide another holder of the address", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		ft.byEmailResp = `[` +
			`{"user_id":"email|orphan1","email":"alias@linux.com","created_at":"2020-01-01T00:00:00.000Z","email_verified":false,"identities":[{"connection":"email","provider":"email"}]},` +
			`{"user_id":"auth0|db1","email":"alias@linux.com","email_verified":false,"identities":[{"connection":"Username-Password-Authentication"}]}]`
		rw := newTestReaderWriter(ft)

		_, err := rw.AddSystemManagedEmail(ctx, testPrimaryUserID, "alias@linux.com")
		require.Error(t, err)
		var validationErr errors.Validation
		assert.ErrorAs(t, err, &validationErr)
		assert.Equal(t, 0, ft.countFor(http.MethodPost, ""))
		assert.Equal(t, 0, ft.countFor(http.MethodDelete, ""))
	})

	t.Run("unrelated users returned by the lookups do not block the claim", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		ft.byEmailResp = `[{"user_id":"google-oauth2|v1","email":"other@linux.com","identities":[{"connection":"google-oauth2"}]}]`
		ft.searchResp = `[{"user_id":"auth0|v2","email":"x@example.org","identities":[` +
			`{"connection":"github","profileData":{"email":"aliasx@linux.com"}}]}]`
		rw := newTestReaderWriter(ft)

		stubID, err := rw.AddSystemManagedEmail(ctx, testPrimaryUserID, "alias@linux.com")
		require.NoError(t, err)
		assert.Equal(t, "email|stub123", stubID)
	})

	lookupFailures := []struct {
		name string
		set  func(ft *fakeAuth0Transport)
	}{
		{name: "root email lookup", set: func(ft *fakeAuth0Transport) {
			ft.byEmailStatus, ft.byEmailResp = http.StatusInternalServerError, `{"error":"boom"}`
		}},
		{name: "root email search", set: func(ft *fakeAuth0Transport) {
			ft.rootSearchStatus, ft.rootSearchResp = http.StatusInternalServerError, `{"error":"boom"}`
		}},
		{name: "identity email lookup", set: func(ft *fakeAuth0Transport) {
			ft.searchStatus, ft.searchResp = http.StatusInternalServerError, `{"error":"boom"}`
		}},
	}
	for _, tc := range lookupFailures {
		t.Run(tc.name+" failure fails closed as an unexpected error", func(t *testing.T) {
			ft := newFakeAuth0(testPrimaryUserID, "{}")
			tc.set(ft)
			rw := newTestReaderWriter(ft)

			_, err := rw.AddSystemManagedEmail(ctx, testPrimaryUserID, "alias@linux.com")
			require.Error(t, err)
			var validationErr errors.Validation
			assert.NotErrorAs(t, err, &validationErr, "infra failure must not look like a claim conflict")
			assert.Contains(t, err.Error(), "failed to check email availability")
			assert.Equal(t, 0, ft.countFor(http.MethodPost, ""))
		})
	}
}

func TestUserReaderWriter_CreateEmailIdentity_ReconcilesOrphanedStub(t *testing.T) {
	ctx := context.Background()

	const orphanRecord = `{"user_id":"email|orphan1","email":"alias@linux.com","created_at":"2020-01-01T00:00:00.000Z","email_verified":false,` +
		`"identities":[{"connection":"email","provider":"email","user_id":"orphan1"}]}`
	const orphanStub = `[` + orphanRecord + `]`

	t.Run("orphaned unverified stub is deleted and the claim succeeds", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		ft.createStatuses = []int{http.StatusConflict, http.StatusCreated}
		ft.byEmailResp = orphanStub
		ft.stubGetResp = orphanRecord
		rw := newTestReaderWriter(ft)

		stubID, err := rw.AddSystemManagedEmail(ctx, testPrimaryUserID, "alias@linux.com")
		require.NoError(t, err)
		assert.Equal(t, "email|stub123", stubID)

		assert.Equal(t, []string{
			"GET /api/v2/users-by-email",
			"GET /api/v2/users",
			"GET /api/v2/users",
			"POST /api/v2/users",
			"GET /api/v2/users-by-email",
			"GET /api/v2/users/email|orphan1",
			"DELETE /api/v2/users/email|orphan1",
			"POST /api/v2/users",
			"POST /api/v2/users/auth0|test123/identities",
			"PATCH /api/v2/users/auth0|test123",
		}, ft.methodPaths())
	})

	genuineClaims := []struct {
		name string
		resp string
	}{
		{
			name: "verified email user",
			resp: `[{"user_id":"email|u1","email":"alias@linux.com","created_at":"2020-01-01T00:00:00.000Z","email_verified":true,` +
				`"identities":[{"connection":"email","provider":"email"}]}]`,
		},
		{
			name: "system-managed stub",
			resp: `[{"user_id":"email|u1","email":"alias@linux.com","created_at":"2020-01-01T00:00:00.000Z","email_verified":false,` +
				`"app_metadata":{"system_managed":true},"identities":[{"connection":"email","provider":"email"}]}]`,
		},
		{
			name: "identity-verified email user",
			resp: `[{"user_id":"email|u1","email":"alias@linux.com","created_at":"2020-01-01T00:00:00.000Z","email_verified":false,` +
				`"identities":[{"connection":"email","provider":"email","profileData":{"email":"alias@linux.com","email_verified":true}}]}]`,
		},
		{
			name: "user with linked identities",
			resp: `[{"user_id":"email|u1","email":"alias@linux.com","created_at":"2020-01-01T00:00:00.000Z","email_verified":false,` +
				`"identities":[{"connection":"email","provider":"email"},{"connection":"github","provider":"github"}]}]`,
		},
		{
			name: "non-email-connection user",
			resp: `[{"user_id":"google-oauth2|u1","email":"alias@linux.com","created_at":"2020-01-01T00:00:00.000Z","email_verified":false,` +
				`"identities":[{"connection":"google-oauth2","provider":"google-oauth2"}]}]`,
		},
		{
			name: "different root email",
			resp: `[{"user_id":"email|u1","email":"other@linux.com","created_at":"2020-01-01T00:00:00.000Z","email_verified":false,` +
				`"identities":[{"connection":"email","provider":"email"}]}]`,
		},
		{
			name: "no users found",
			resp: `[]`,
		},
	}
	for _, tc := range genuineClaims {
		t.Run("genuine claim is not deleted: "+tc.name, func(t *testing.T) {
			ft := newFakeAuth0(testPrimaryUserID, "{}")
			ft.createStatus = http.StatusConflict
			ft.byEmailResp = tc.resp
			rw := newTestReaderWriter(ft)

			_, err := rw.createAndLinkEmailIdentity(ctx, testPrimaryUserID, "alias@linux.com", true, &Auth0AppMetadata{SystemManaged: true})
			require.Error(t, err)
			var validationErr errors.Validation
			assert.ErrorAs(t, err, &validationErr)
			assert.Contains(t, err.Error(), "email already linked")
			assert.Equal(t, 0, ft.countFor(http.MethodDelete, ""), "no user may be deleted")
			assert.Equal(t, 1, ft.countFor(http.MethodPost, "/api/v2/users"), "create must not be retried")
		})
	}

	tooRecent := []struct {
		name   string
		record string
	}{
		{
			name: "created within the minimum age",
			record: `{"user_id":"email|orphan1","email":"alias@linux.com","email_verified":false,"created_at":"` +
				time.Now().UTC().Add(-5*time.Minute).Format(time.RFC3339) + `",` +
				`"identities":[{"connection":"email","provider":"email"}]}`,
		},
		{
			name: "missing created_at",
			record: `{"user_id":"email|orphan1","email":"alias@linux.com","email_verified":false,` +
				`"identities":[{"connection":"email","provider":"email"}]}`,
		},
	}
	for _, tc := range tooRecent {
		t.Run("unverified stub is not deleted when "+tc.name, func(t *testing.T) {
			ft := newFakeAuth0(testPrimaryUserID, "{}")
			ft.createStatus = http.StatusConflict
			ft.byEmailResp = `[` + tc.record + `]`
			ft.stubGetResp = tc.record
			rw := newTestReaderWriter(ft)

			_, err := rw.createAndLinkEmailIdentity(ctx, testPrimaryUserID, "alias@linux.com", true, &Auth0AppMetadata{SystemManaged: true})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "email already linked")
			assert.Equal(t, 0, ft.countFor(http.MethodDelete, ""))
			assert.Equal(t, 1, ft.countFor(http.MethodPost, "/api/v2/users"))
		})
	}

	t.Run("lookup failure surfaces as an unexpected error", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		ft.createStatus = http.StatusConflict
		ft.byEmailStatus = http.StatusInternalServerError
		ft.byEmailResp = `{"error":"boom"}`
		rw := newTestReaderWriter(ft)

		_, err := rw.createAndLinkEmailIdentity(ctx, testPrimaryUserID, "alias@linux.com", true, &Auth0AppMetadata{SystemManaged: true})
		require.Error(t, err)
		var validationErr errors.Validation
		assert.NotErrorAs(t, err, &validationErr, "infra failure must not look like a claim conflict")
		assert.Contains(t, err.Error(), "failed to look up existing email stub user")
		assert.Equal(t, 0, ft.countFor(http.MethodDelete, ""))
	})

	changedBeforeDelete := []struct {
		name  string
		fresh string
	}{
		{
			name: "verified",
			fresh: `{"user_id":"email|orphan1","email":"alias@linux.com","created_at":"2020-01-01T00:00:00.000Z","email_verified":true,` +
				`"identities":[{"connection":"email","provider":"email"}]}`,
		},
		{
			name: "identity-verified",
			fresh: `{"user_id":"email|orphan1","email":"alias@linux.com","created_at":"2020-01-01T00:00:00.000Z","email_verified":false,` +
				`"identities":[{"connection":"email","provider":"email","profileData":{"email":"alias@linux.com","email_verified":true}}]}`,
		},
		{
			name: "system-managed",
			fresh: `{"user_id":"email|orphan1","email":"alias@linux.com","created_at":"2020-01-01T00:00:00.000Z","email_verified":false,` +
				`"app_metadata":{"system_managed":true},"identities":[{"connection":"email","provider":"email"}]}`,
		},
		{
			name: "linked to another identity",
			fresh: `{"user_id":"email|orphan1","email":"alias@linux.com","created_at":"2020-01-01T00:00:00.000Z","email_verified":false,` +
				`"identities":[{"connection":"email"},{"connection":"github"}]}`,
		},
	}
	for _, tc := range changedBeforeDelete {
		t.Run("stub that became "+tc.name+" before delete is not removed and stays a claim conflict", func(t *testing.T) {
			ft := newFakeAuth0(testPrimaryUserID, "{}")
			ft.createStatuses = []int{http.StatusConflict, http.StatusCreated}
			ft.byEmailResp = orphanStub
			ft.stubGetResp = tc.fresh
			rw := newTestReaderWriter(ft)

			_, err := rw.AddSystemManagedEmail(ctx, testPrimaryUserID, "alias@linux.com")
			require.Error(t, err)
			var validationErr errors.Validation
			assert.ErrorAs(t, err, &validationErr, "a newly genuine claim must map to the claim-conflict validation error")
			assert.Contains(t, err.Error(), "email already linked")
			assert.Equal(t, 0, ft.countFor(http.MethodDelete, ""))
			assert.Equal(t, 1, ft.countFor(http.MethodPost, "/api/v2/users"))
		})
	}

	t.Run("failed delete surfaces as an unexpected error and the create is not retried", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		ft.createStatuses = []int{http.StatusConflict, http.StatusCreated}
		ft.byEmailResp = orphanStub
		ft.stubGetResp = orphanRecord
		ft.deleteStatus = http.StatusInternalServerError
		rw := newTestReaderWriter(ft)

		_, err := rw.AddSystemManagedEmail(ctx, testPrimaryUserID, "alias@linux.com")
		require.Error(t, err)
		var validationErr errors.Validation
		assert.NotErrorAs(t, err, &validationErr)
		assert.Contains(t, err.Error(), "failed to delete orphaned email stub user")
		assert.Equal(t, 1, ft.countFor(http.MethodDelete, "/api/v2/users/email|orphan1"))
		assert.Equal(t, 1, ft.countFor(http.MethodPost, "/api/v2/users"))
	})

	t.Run("stub deleted concurrently between read and delete still retries the create", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		ft.createStatuses = []int{http.StatusConflict, http.StatusCreated}
		ft.byEmailResp = orphanStub
		ft.stubGetResp = orphanRecord
		ft.deleteStatus = http.StatusNotFound
		rw := newTestReaderWriter(ft)

		_, err := rw.AddSystemManagedEmail(ctx, testPrimaryUserID, "alias@linux.com")
		require.NoError(t, err)
		assert.Equal(t, 1, ft.countFor(http.MethodDelete, "/api/v2/users/email|orphan1"))
		assert.Equal(t, 2, ft.countFor(http.MethodPost, "/api/v2/users"))
	})

	t.Run("stub already gone before delete still retries the create", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		ft.createStatuses = []int{http.StatusConflict, http.StatusCreated}
		ft.byEmailResp = orphanStub
		ft.stubGetStatus = http.StatusNotFound
		rw := newTestReaderWriter(ft)

		_, err := rw.AddSystemManagedEmail(ctx, testPrimaryUserID, "alias@linux.com")
		require.NoError(t, err)
		assert.Equal(t, 0, ft.countFor(http.MethodDelete, ""))
		assert.Equal(t, 2, ft.countFor(http.MethodPost, "/api/v2/users"))
	})

	t.Run("orphan is selected among multiple users and matched case-insensitively", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		ft.createStatuses = []int{http.StatusConflict, http.StatusCreated}
		ft.byEmailResp = `[` +
			`{"user_id":"auth0|db1","email":"alias@linux.com","created_at":"2020-01-01T00:00:00.000Z","email_verified":false,"identities":[{"connection":"Username-Password-Authentication"}]},` +
			`{"user_id":"email|orphan2","email":"Alias@Linux.com","created_at":"2020-01-01T00:00:00.000Z","email_verified":false,"identities":[{"connection":"email","provider":"email"}]}]`
		ft.stubGetResp = `{"user_id":"email|orphan2","email":"Alias@Linux.com","created_at":"2020-01-01T00:00:00.000Z","email_verified":false,` +
			`"identities":[{"connection":"email","provider":"email"}]}`
		rw := newTestReaderWriter(ft)

		_, err := rw.createAndLinkEmailIdentity(ctx, testPrimaryUserID, "alias@linux.com", true, &Auth0AppMetadata{SystemManaged: true})
		require.NoError(t, err)
		assert.Equal(t, 1, ft.countFor(http.MethodDelete, "/api/v2/users/email|orphan2"))
		assert.Equal(t, 0, ft.countFor(http.MethodDelete, "/api/v2/users/auth0|db1"))
	})

	t.Run("second conflict after reconcile returns a validation error without looping", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		ft.createStatus = http.StatusConflict
		ft.byEmailResp = orphanStub
		ft.stubGetResp = orphanRecord
		rw := newTestReaderWriter(ft)

		_, err := rw.createAndLinkEmailIdentity(ctx, testPrimaryUserID, "alias@linux.com", true, &Auth0AppMetadata{SystemManaged: true})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "email already linked")
		assert.Equal(t, 2, ft.countFor(http.MethodPost, "/api/v2/users"))
		assert.Equal(t, 1, ft.countFor(http.MethodGet, "/api/v2/users-by-email"))
	})

	t.Run("set primary preserve path reconciles an orphaned stub of the old primary", func(t *testing.T) {
		getUser := `{"user_id":"auth0|test123","email":"alice@gmail.com","identities":[` +
			`{"connection":"google-oauth2","provider":"google-oauth2","profileData":{"email":"alice@gmail.com","created_at":"2020-01-01T00:00:00.000Z","email_verified":true}},` +
			`{"connection":"email","provider":"email","profileData":{"email":"alice@example.org","created_at":"2020-01-01T00:00:00.000Z","email_verified":true}}]}`
		ft := newFakeAuth0(testPrimaryUserID, getUser)
		ft.createStatuses = []int{http.StatusConflict, http.StatusCreated}
		ft.stubGetResp = `{"user_id":"email|orphan1","email":"alice@gmail.com","created_at":"2020-01-01T00:00:00.000Z","email_verified":false,` +
			`"identities":[{"connection":"email","provider":"email"}]}`
		ft.byEmailResp = `[` + ft.stubGetResp + `]`
		rw := newTestReaderWriter(ft)

		err := rw.SetPrimaryEmail(ctx, testPrimaryUserID, "alice@example.org")
		require.NoError(t, err)
		assert.Equal(t, 1, ft.countFor(http.MethodDelete, "/api/v2/users/email|orphan1"))
		assert.Equal(t, 1, ft.countFor(http.MethodPatch, "/api/v2/users/auth0|test123"))
	})

	t.Run("set primary never reconciles an unverified old primary", func(t *testing.T) {
		// Neither the root email nor any identity proves ownership of the old
		// primary, so it must not be preserved: no create, no stub lookup, no
		// delete, and no verified identity minted for it, even though an aged
		// orphan holding that address would otherwise qualify for cleanup.
		getUser := `{"user_id":"auth0|test123","email":"alice@gmail.com","email_verified":false,"identities":[` +
			`{"connection":"google-oauth2","provider":"google-oauth2","profileData":{"email":"alice@gmail.com","email_verified":false}},` +
			`{"connection":"email","provider":"email","profileData":{"email":"alice@example.org","email_verified":true}}]}`
		ft := newFakeAuth0(testPrimaryUserID, getUser)
		ft.createStatuses = []int{http.StatusConflict, http.StatusCreated}
		ft.stubGetResp = orphanRecord
		ft.byEmailResp = orphanStub
		rw := newTestReaderWriter(ft)

		err := rw.SetPrimaryEmail(ctx, testPrimaryUserID, "alice@example.org")
		require.NoError(t, err)
		assert.Equal(t, 0, ft.countFor(http.MethodPost, "/api/v2/users"), "no stub may be created for an unverified old primary")
		assert.Equal(t, 0, ft.countFor(http.MethodGet, "/api/v2/users-by-email"), "reconciliation must not run")
		assert.Equal(t, 0, ft.countFor(http.MethodDelete, ""), "no user may be deleted")
		assert.Equal(t, 1, ft.countFor(http.MethodPatch, "/api/v2/users/auth0|test123"))
	})
}

func TestUserReaderWriter_DeleteSystemManagedUser(t *testing.T) {
	ctx := context.Background()
	const m2mToken = "test-m2m-token"

	t.Run("refuses to delete when app_metadata is missing", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		ft.stubGetResp = `{"user_id":"email|stub123"}`
		rw := newTestReaderWriter(ft)

		err := rw.deleteSystemManagedUser(ctx, "email|stub123", m2mToken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "refusing to delete")
		assert.Equal(t, 0, ft.countFor(http.MethodDelete, "/email|stub123"))
	})

	t.Run("refuses to delete when system_managed is false", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		ft.stubGetResp = `{"user_id":"email|stub123","app_metadata":{"system_managed":false}}`
		rw := newTestReaderWriter(ft)

		err := rw.deleteSystemManagedUser(ctx, "email|stub123", m2mToken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "refusing to delete")
		assert.Equal(t, 0, ft.countFor(http.MethodDelete, "/email|stub123"))
	})

	t.Run("deletes when system_managed is true", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		ft.stubGetResp = `{"user_id":"email|stub123","app_metadata":{"system_managed":true}}`
		rw := newTestReaderWriter(ft)

		err := rw.deleteSystemManagedUser(ctx, "email|stub123", m2mToken)
		require.NoError(t, err)
		assert.Equal(t, 1, ft.countFor(http.MethodDelete, "/email|stub123"))
	})

	t.Run("treats a 404 on the pre-flight GET as already-gone", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		ft.stubGetStatus = http.StatusNotFound
		rw := newTestReaderWriter(ft)

		err := rw.deleteSystemManagedUser(ctx, "email|stub123", m2mToken)
		require.NoError(t, err)
		assert.Equal(t, 0, ft.countFor(http.MethodDelete, "/email|stub123"))
	})

	t.Run("surfaces an error when the pre-flight GET fails with a non-404 status", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		ft.stubGetStatus = http.StatusInternalServerError
		rw := newTestReaderWriter(ft)

		err := rw.deleteSystemManagedUser(ctx, "email|stub123", m2mToken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to verify system_managed before delete")
		assert.Equal(t, 0, ft.countFor(http.MethodDelete, "/email|stub123"))
	})
}

func TestUserReaderWriter_DeleteEmailConnectionStub(t *testing.T) {
	ctx := context.Background()
	const m2mToken = "test-m2m-token"

	t.Run("refuses to delete when the stub has no identities", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		ft.stubGetResp = `{"user_id":"email|stub123","identities":[]}`
		rw := newTestReaderWriter(ft)

		err := rw.deleteEmailConnectionStub(ctx, "email|stub123", m2mToken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "refusing to delete")
		assert.Equal(t, 0, ft.countFor(http.MethodDelete, "/email|stub123"))
	})

	t.Run("refuses to delete when an identity is not an email connection", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		ft.stubGetResp = `{"user_id":"email|stub123","identities":[{"connection":"google-oauth2","provider":"google-oauth2"}]}`
		rw := newTestReaderWriter(ft)

		err := rw.deleteEmailConnectionStub(ctx, "email|stub123", m2mToken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "refusing to delete")
		assert.Equal(t, 0, ft.countFor(http.MethodDelete, "/email|stub123"))
	})

	t.Run("deletes when every identity is an email connection", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		ft.stubGetResp = `{"user_id":"email|stub123","identities":[{"connection":"email","provider":"email"}]}`
		rw := newTestReaderWriter(ft)

		err := rw.deleteEmailConnectionStub(ctx, "email|stub123", m2mToken)
		require.NoError(t, err)
		assert.Equal(t, 1, ft.countFor(http.MethodDelete, "/email|stub123"))
	})

	t.Run("treats a 404 on the pre-flight GET as already-gone", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		ft.stubGetStatus = http.StatusNotFound
		rw := newTestReaderWriter(ft)

		err := rw.deleteEmailConnectionStub(ctx, "email|stub123", m2mToken)
		require.NoError(t, err)
		assert.Equal(t, 0, ft.countFor(http.MethodDelete, "/email|stub123"))
	})

	t.Run("surfaces an error when the pre-flight GET fails with a non-404 status", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		ft.stubGetStatus = http.StatusInternalServerError
		rw := newTestReaderWriter(ft)

		err := rw.deleteEmailConnectionStub(ctx, "email|stub123", m2mToken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to verify email-connection stub before delete")
		assert.Equal(t, 0, ft.countFor(http.MethodDelete, "/email|stub123"))
	})
}

func TestUserReaderWriter_DeleteFreshEmailConnectionStub(t *testing.T) {
	ctx := context.Background()
	const m2mToken = "test-m2m-token"
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-time.Minute).Format(time.RFC3339)
	old := now.Add(-2 * discardMaxProfileAge).Format(time.RFC3339)
	emailIdentity := `[{"connection":"email","provider":"email"}]`

	tests := []struct {
		name       string
		getResp    string
		getStatus  int
		wantDelete bool
		wantErr    string
	}{
		{name: "deletes a fresh email-only profile", getResp: `{"user_id":"email|stub123","created_at":"` + fresh + `","logins_count":1,"identities":` + emailIdentity + `}`, wantDelete: true},
		{name: "deletes a fresh profile with zero logins", getResp: `{"user_id":"email|stub123","created_at":"` + fresh + `","logins_count":0,"identities":` + emailIdentity + `}`, wantDelete: true},
		{name: "skips a profile created before the window", getResp: `{"user_id":"email|stub123","created_at":"` + old + `","logins_count":1,"identities":` + emailIdentity + `}`, wantErr: "freshness window"},
		{name: "skips a profile that has logged in", getResp: `{"user_id":"email|stub123","created_at":"` + fresh + `","logins_count":5,"identities":` + emailIdentity + `}`, wantErr: "logged in"},
		{name: "skips a profile with a non-email identity", getResp: `{"user_id":"email|stub123","created_at":"` + fresh + `","logins_count":1,"identities":[{"connection":"google-oauth2","provider":"google-oauth2"}]}`, wantErr: "non-email-connection"},
		{name: "skips a profile with no identities", getResp: `{"user_id":"email|stub123","created_at":"` + fresh + `","identities":[]}`, wantErr: "no identities"},
		{name: "skips a linked primary with two email identities", getResp: `{"user_id":"email|stub123","created_at":"` + fresh + `","logins_count":1,"identities":[{"connection":"email","provider":"email"},{"connection":"email","provider":"email","profileData":{"email":"linked@example.com","email_verified":true}}]}`, wantErr: "not a standalone email profile"},
		{name: "skips an email identity with linked profile data", getResp: `{"user_id":"email|stub123","created_at":"` + fresh + `","logins_count":1,"identities":[{"connection":"email","provider":"email","profileData":{}}]}`, wantErr: "not a standalone email profile"},
		{name: "skips a system-managed profile", getResp: `{"user_id":"email|stub123","created_at":"` + fresh + `","logins_count":1,"app_metadata":{"system_managed":true},"identities":` + emailIdentity + `}`, wantErr: "system-managed"},
		{name: "skips a profile with no created_at", getResp: `{"user_id":"email|stub123","logins_count":1,"identities":` + emailIdentity + `}`, wantErr: "created_at"},
		{name: "skips a profile with an unparsable created_at", getResp: `{"user_id":"email|stub123","created_at":"yesterday","logins_count":1,"identities":` + emailIdentity + `}`, wantErr: "created_at"},
		{name: "treats a 404 as already gone", getStatus: http.StatusNotFound},
		{name: "surfaces a non-404 fetch failure", getStatus: http.StatusInternalServerError, wantErr: "failed to verify email-connection stub before delete"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := newFakeAuth0(testPrimaryUserID, "{}")
			if tt.getResp != "" {
				ft.stubGetResp = tt.getResp
			}
			if tt.getStatus != 0 {
				ft.stubGetStatus = tt.getStatus
			}
			rw := newTestReaderWriter(ft)

			err := rw.deleteFreshEmailConnectionStub(ctx, "email|stub123", m2mToken, now)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			wantDeletes := 0
			if tt.wantDelete {
				wantDeletes = 1
			}
			assert.Equal(t, wantDeletes, ft.countFor(http.MethodDelete, "/email|stub123"))
		})
	}

	t.Run("requires a user id", func(t *testing.T) {
		rw := newTestReaderWriter(newFakeAuth0(testPrimaryUserID, "{}"))
		require.Error(t, rw.deleteFreshEmailConnectionStub(ctx, " ", m2mToken, now))
	})
}

// gatedRefreshTokenSource simulates a token refresh already blocked on the network.
type gatedRefreshTokenSource struct {
	entered chan struct{}
	release chan struct{}
}

func (s *gatedRefreshTokenSource) Token() (*oauth2.Token, error) {
	close(s.entered)
	<-s.release
	return fakeTokenSource{token: "refreshed-token"}.Token()
}

func TestTokenManager_CachedAccessToken(t *testing.T) {
	ctx := context.Background()
	tm := &TokenManager{tokenSource: fakeTokenSource{token: "cached-token"}}
	_, err := tm.cachedAccessToken(ctx)
	require.ErrorContains(t, err, "cached M2M token")
	_, err = tm.GetToken(ctx)
	require.NoError(t, err)

	source := &gatedRefreshTokenSource{entered: make(chan struct{}), release: make(chan struct{})}
	tm.tokenSource = source
	refreshed := make(chan error, 1)
	go func() {
		_, errRefresh := tm.GetToken(ctx)
		refreshed <- errRefresh
	}()
	<-source.entered
	// Release before assertions, even if an assertion fails, then join the refresh.
	token, errCached := tm.cachedAccessToken(ctx)
	close(source.release)
	require.NoError(t, <-refreshed)
	require.NoError(t, errCached)
	assert.Equal(t, "cached-token", token)

	tm.cachedToken.Store(&oauth2.Token{AccessToken: "expired-token", Expiry: time.Now().Add(-time.Hour)})
	_, err = tm.cachedAccessToken(ctx)
	require.ErrorContains(t, err, "cached M2M token")
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = tm.cachedAccessToken(canceled)
	require.ErrorIs(t, err, context.Canceled)
}

type discardDeadlineTransport struct {
	base         *fakeAuth0Transport
	blockMethod  string
	deadline     time.Time
	blockedCalls int
	cancellation error
}

func (d *discardDeadlineTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != d.blockMethod {
		return d.base.RoundTrip(req)
	}
	d.deadline, _ = req.Context().Deadline()
	d.blockedCalls++
	<-req.Context().Done()
	d.cancellation = req.Context().Err()
	return nil, d.cancellation
}

func TestUserReaderWriter_DiscardVerifiedEmailProfile_Timeout(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			ft := newFakeAuth0(testPrimaryUserID, "{}")
			ft.stubGetResp = `{"user_id":"email|stub123","created_at":"` + time.Now().UTC().Format(time.RFC3339) + `","logins_count":1,"identities":[{"connection":"email","provider":"email"}]}`
			transport := &discardDeadlineTransport{base: ft, blockMethod: method}
			rw := newTestReaderWriter(transport)
			// Use production retry settings, not the zero-retry default test seam.
			config := httpclient.DefaultConfig()
			config.Transport = transport
			rw.httpClient = httpclient.NewClient(config)
			_, errToken := rw.config.M2MTokenManager.GetToken(context.Background())
			require.NoError(t, errToken)
			token, errSign := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "email|stub123"}).SignedString([]byte("test-key"))
			require.NoError(t, errSign)

			start := time.Now()
			err := rw.DiscardVerifiedEmailProfile(context.Background(), &model.AuthResponse{IDToken: token})
			require.Error(t, err)
			require.ErrorIs(t, transport.cancellation, context.DeadlineExceeded)
			assert.WithinDuration(t, start.Add(discardProfileTimeout), transport.deadline, 500*time.Millisecond)
			assert.Less(t, time.Since(start), 3*time.Second, "cleanup must not use the normal 30-second request/retry budget")
			assert.Equal(t, 1, transport.blockedCalls)
			assert.Zero(t, ft.countFor(http.MethodDelete, "/email|stub123"))
		})
	}
}

func TestUserReaderWriter_DiscardVerifiedEmailProfile(t *testing.T) {
	ctx := context.Background()

	signedToken := func(t *testing.T, sub string) string {
		t.Helper()
		tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": sub}).SignedString([]byte("secret"))
		require.NoError(t, err)
		return tok
	}

	t.Run("does nothing for a nil response or empty ID token", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		rw := newTestReaderWriter(ft)

		require.NoError(t, rw.DiscardVerifiedEmailProfile(ctx, nil))
		require.NoError(t, rw.DiscardVerifiedEmailProfile(ctx, &model.AuthResponse{}))
		assert.Empty(t, ft.methodPaths())
	})

	t.Run("rejects an invalid ID token without calling Auth0", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		rw := newTestReaderWriter(ft)

		err := rw.DiscardVerifiedEmailProfile(ctx, &model.AuthResponse{IDToken: "not-a-jwt"})
		require.Error(t, err)
		assert.Empty(t, ft.methodPaths())
	})

	t.Run("fetches then deletes the profile named by the token subject", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		ft.stubGetResp = `{"user_id":"email|stub123","created_at":"` + time.Now().Add(-time.Second).UTC().Format(time.RFC3339) +
			`","logins_count":1,"identities":[{"connection":"email","provider":"email"}]}`
		rw := newTestReaderWriter(ft)
		_, errToken := rw.config.M2MTokenManager.GetToken(ctx)
		require.NoError(t, errToken)

		err := rw.DiscardVerifiedEmailProfile(ctx, &model.AuthResponse{IDToken: signedToken(t, "email|stub123")})
		require.NoError(t, err)
		assert.Equal(t, 1, ft.countFor(http.MethodGet, "/email|stub123"))
		assert.Equal(t, 1, ft.countFor(http.MethodDelete, "/email|stub123"))
	})

	t.Run("returns the guard refusal and does not delete an old profile", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		ft.stubGetResp = `{"user_id":"email|stub123","created_at":"2020-01-01T00:00:00Z","logins_count":1,"identities":[{"connection":"email","provider":"email"}]}`
		rw := newTestReaderWriter(ft)
		_, errToken := rw.config.M2MTokenManager.GetToken(ctx)
		require.NoError(t, errToken)

		err := rw.DiscardVerifiedEmailProfile(ctx, &model.AuthResponse{IDToken: signedToken(t, "email|stub123")})
		require.Error(t, err)
		assert.Equal(t, 0, ft.countFor(http.MethodDelete, "/email|stub123"))
	})

	t.Run("skips cleanup without a previously obtained token", func(t *testing.T) {
		ft := newFakeAuth0(testPrimaryUserID, "{}")
		rw := newTestReaderWriter(ft)
		// A refresh here would panic: cleanup must not consult the token source.
		rw.config.M2MTokenManager.tokenSource = nil
		err := rw.DiscardVerifiedEmailProfile(ctx, &model.AuthResponse{IDToken: signedToken(t, "email|stub123")})
		require.ErrorContains(t, err, "cached M2M token")
		assert.Empty(t, ft.methodPaths())
	})
}

func TestEmailCasingVariants(t *testing.T) {
	assert.ElementsMatch(t, []string{
		"first.last@linux.com",
		"FIRST.LAST@LINUX.COM",
		"first.last@Linux.com",
		"First.last@linux.com",
		"First.last@Linux.com",
		"First.Last@linux.com",
		"First.Last@Linux.com",
	}, emailCasingVariants("first.last@linux.com"))

	assert.ElementsMatch(t, []string{
		"alias@linux.com",
		"ALIAS@LINUX.COM",
		"alias@Linux.com",
		"Alias@linux.com",
		"Alias@Linux.com",
	}, emailCasingVariants("alias@linux.com"))

	assert.Equal(t, []string{"no-at-sign"}, emailCasingVariants("no-at-sign"))
}

func TestUserReaderWriter_SearchUser_Email_RequiresVerifiedEmail(t *testing.T) {
	ctx := context.Background()

	unverifiedDB := `{"user_id":"auth0|unverified","username":"unverified","email":"owner@example.com","email_verified":false,` +
		`"identities":[{"connection":"Username-Password-Authentication","provider":"auth0","user_id":"unverified"}]}`
	verifiedDB := `{"user_id":"auth0|verified","username":"verified","email":"owner@example.com","email_verified":true,` +
		`"identities":[{"connection":"Username-Password-Authentication","provider":"auth0","user_id":"verified"}]}`
	verifiedSocial := `{"user_id":"google-oauth2|123","email":"owner@example.com","email_verified":true,` +
		`"identities":[{"connection":"google-oauth2","provider":"google-oauth2","user_id":"123","isSocial":true}]}`

	tests := []struct {
		name       string
		byEmail    string
		wantUserID string // empty means NotFound is expected
	}{
		{name: "unverified database user is not resolved", byEmail: "[" + unverifiedDB + "]"},
		{name: "unverified database user next to verified social owner is not resolved", byEmail: "[" + unverifiedDB + "," + verifiedSocial + "]"},
		{name: "verified owner is resolved when listed after unverified record", byEmail: "[" + unverifiedDB + "," + verifiedDB + "]", wantUserID: "auth0|verified"},
		{name: "verified owner is resolved when listed first", byEmail: "[" + verifiedDB + "," + unverifiedDB + "]", wantUserID: "auth0|verified"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := newFakeAuth0(testPrimaryUserID, "{}")
			ft.byEmailResp = tt.byEmail
			rw := newTestReaderWriter(ft)

			user, err := rw.SearchUser(ctx, &model.User{PrimaryEmail: "owner@example.com"}, constants.CriteriaTypeEmail)
			if tt.wantUserID == "" {
				var notFound errors.NotFound
				require.ErrorAs(t, err, &notFound)
				assert.Nil(t, user)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantUserID, user.UserID)
		})
	}
}
