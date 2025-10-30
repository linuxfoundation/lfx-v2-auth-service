// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package mock

import (
	"context"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	jwtpkg "github.com/linuxfoundation/lfx-v2-auth-service/pkg/jwt"
)

// TestUserReaderWriter_MetadataLookup tests the MetadataLookup method for Mock implementation
func TestUserReaderWriter_MetadataLookup(t *testing.T) {
	ctx := context.Background()
	writer := &userWriter{}

	tests := []struct {
		name                 string
		input                string
		expectedSub          string
		expectedUserID       string
		expectedUsername     string
		expectedPrimaryEmail string
		expectError          bool
		errorMessage         string
	}{
		// JWT test cases
		{
			name:                 "JWT token with auth0 sub",
			input:                createTestJWT(t, "auth0|123456789"),
			expectedSub:          "auth0|123456789",
			expectedUserID:       "auth0|123456789",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
			expectError:          false,
		},
		{
			name:                 "JWT token with google oauth sub",
			input:                createTestJWT(t, "google-oauth2|987654321"),
			expectedSub:          "google-oauth2|987654321",
			expectedUserID:       "google-oauth2|987654321",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
			expectError:          false,
		},
		{
			name:                 "JWT token with github sub",
			input:                createTestJWT(t, "github|456789123"),
			expectedSub:          "github|456789123",
			expectedUserID:       "github|456789123",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
			expectError:          false,
		},
		{
			name:                 "invalid JWT token",
			input:                "eyJinvalid.jwt.token",
			expectedSub:          "",
			expectedUserID:       "",
			expectedUsername:     "eyJinvalid.jwt.token",
			expectedPrimaryEmail: "",
			expectError:          false, // Should fall back to username lookup
		},
		// Regular test cases
		{
			name:                 "canonical lookup with pipe separator - auth0 format",
			input:                "auth0|123456789",
			expectedSub:          "auth0|123456789",
			expectedUserID:       "auth0|123456789",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
			expectError:          false,
		},
		{
			name:                 "canonical lookup with google oauth format",
			input:                "google-oauth2|987654321",
			expectedSub:          "google-oauth2|987654321",
			expectedUserID:       "google-oauth2|987654321",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
			expectError:          false,
		},
		{
			name:                 "canonical lookup with github oauth format",
			input:                "github|456789123",
			expectedSub:          "github|456789123",
			expectedUserID:       "github|456789123",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
			expectError:          false,
		},
		{
			name:                 "canonical lookup with saml enterprise format",
			input:                "samlp|enterprise|user123",
			expectedSub:          "samlp|enterprise|user123",
			expectedUserID:       "samlp|enterprise|user123",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
			expectError:          false,
		},
		{
			name:                 "canonical lookup with linkedin oauth format",
			input:                "linkedin|789123456",
			expectedSub:          "linkedin|789123456",
			expectedUserID:       "linkedin|789123456",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
			expectError:          false,
		},
		{
			name:                 "canonical lookup with custom provider format",
			input:                "custom-provider|user-id-12345",
			expectedSub:          "custom-provider|user-id-12345",
			expectedUserID:       "custom-provider|user-id-12345",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
			expectError:          false,
		},
		{
			name:                 "search lookup with email format",
			input:                "john.doe@example.com",
			expectedSub:          "",
			expectedUserID:       "",
			expectedUsername:     "",
			expectedPrimaryEmail: "john.doe@example.com",
			expectError:          false,
		},
		{
			name:                 "search lookup with email format - complex domain",
			input:                "jane.smith@company.co.uk",
			expectedSub:          "",
			expectedUserID:       "",
			expectedUsername:     "",
			expectedPrimaryEmail: "jane.smith@company.co.uk",
			expectError:          false,
		},
		{
			name:                 "search lookup with email format - subdomain",
			input:                "developer@mail.example.org",
			expectedSub:          "",
			expectedUserID:       "",
			expectedUsername:     "",
			expectedPrimaryEmail: "developer@mail.example.org",
			expectError:          false,
		},
		{
			name:                 "search lookup with username - no email format",
			input:                "john.doe",
			expectedSub:          "",
			expectedUserID:       "",
			expectedUsername:     "john.doe",
			expectedPrimaryEmail: "",
			expectError:          false,
		},
		{
			name:                 "search lookup with username containing numbers",
			input:                "developer123",
			expectedSub:          "",
			expectedUserID:       "",
			expectedUsername:     "developer123",
			expectedPrimaryEmail: "",
			expectError:          false,
		},
		{
			name:                 "search lookup with username containing special chars",
			input:                "jane_smith-dev",
			expectedSub:          "",
			expectedUserID:       "",
			expectedUsername:     "jane_smith-dev",
			expectedPrimaryEmail: "",
			expectError:          false,
		},
		{
			name:                 "search lookup with simple username",
			input:                "testuser",
			expectedSub:          "",
			expectedUserID:       "",
			expectedUsername:     "testuser",
			expectedPrimaryEmail: "",
			expectError:          false,
		},
		{
			name:                 "empty input",
			input:                "",
			expectedSub:          "",
			expectedUserID:       "",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
			expectError:          true,
			errorMessage:         "input is required",
		},
		{
			name:                 "whitespace only input",
			input:                "   ",
			expectedSub:          "",
			expectedUserID:       "",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
			expectError:          true,
			errorMessage:         "input is required",
		},
		{
			name:                 "input with leading/trailing whitespace - canonical",
			input:                "  auth0|123456789  ",
			expectedSub:          "auth0|123456789",
			expectedUserID:       "auth0|123456789",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
			expectError:          false,
		},
		{
			name:                 "input with leading/trailing whitespace - email",
			input:                "  john.doe@example.com  ",
			expectedSub:          "",
			expectedUserID:       "",
			expectedUsername:     "",
			expectedPrimaryEmail: "john.doe@example.com",
			expectError:          false,
		},
		{
			name:                 "input with leading/trailing whitespace - username",
			input:                "  john.doe  ",
			expectedSub:          "",
			expectedUserID:       "",
			expectedUsername:     "john.doe",
			expectedPrimaryEmail: "",
			expectError:          false,
		},
		{
			name:                 "edge case - single pipe character",
			input:                "|",
			expectedSub:          "|",
			expectedUserID:       "|",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
			expectError:          false,
		},
		{
			name:                 "edge case - pipe at end",
			input:                "provider|",
			expectedSub:          "provider|",
			expectedUserID:       "provider|",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
			expectError:          false,
		},
		{
			name:                 "edge case - pipe at beginning",
			input:                "|userid",
			expectedSub:          "|userid",
			expectedUserID:       "|userid",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
			expectError:          false,
		},
		{
			name:                 "edge case - multiple pipes",
			input:                "provider|connection|userid",
			expectedSub:          "provider|connection|userid",
			expectedUserID:       "provider|connection|userid",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
			expectError:          false,
		},
		{
			name:                 "edge case - email with pipe (should be canonical)",
			input:                "user@domain.com|provider",
			expectedSub:          "user@domain.com|provider",
			expectedUserID:       "user@domain.com|provider",
			expectedUsername:     "",
			expectedPrimaryEmail: "",
			expectError:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

// createTestJWT creates a test JWT token with the given sub claim
func createTestJWT(t *testing.T, sub string) string {
	t.Helper()

	// Create a new token with the sub claim
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": sub,
		"iss": "test-issuer",
		"aud": "test-audience",
		"exp": 9999999999, // Far future expiration
		"iat": 1000000000, // Past issued at
	})

	// Sign the token with a test secret (for mock purposes)
	tokenString, err := token.SignedString([]byte("test-secret"))
	if err != nil {
		t.Fatalf("Failed to create test JWT: %v", err)
	}

	return tokenString
}

// TestEmailLinkingFlow tests the complete email linking flow
func TestEmailLinkingFlow(t *testing.T) {
	ctx := context.Background()

	// Create a mock user reader writer with test user
	writer := NewUserReaderWriter(ctx)

	// Test Step 1: Send verification email
	testEmail := "new-email@example.com"
	err := writer.SendVerificationAlternateEmail(ctx, testEmail)
	if err != nil {
		t.Fatalf("SendVerificationAlternateEmail() error = %v", err)
	}

	// Get the generated OTP from logs (in a real test, we'd need to access it)
	// For now, we'll use reflection to get the OTP from the writer
	uw, ok := writer.(*userWriter)
	if !ok {
		t.Fatal("Failed to cast to userWriter")
	}

	uw.otpMutex.RLock()
	normalizedEmail := "new-email@example.com"
	entry, exists := uw.otps[normalizedEmail]
	uw.otpMutex.RUnlock()

	if !exists {
		t.Fatal("OTP not found in storage")
	}

	otp := entry.otp
	if len(otp) != 6 {
		t.Errorf("OTP length = %d, expected 6", len(otp))
	}

	// Test Step 2: Verify email with OTP
	emailModel := &model.Email{
		Email: testEmail,
		OTP:   otp,
	}

	authResponse, err := writer.VerifyAlternateEmail(ctx, emailModel)
	if err != nil {
		t.Fatalf("VerifyAlternateEmail() error = %v", err)
	}

	if authResponse == nil {
		t.Fatal("VerifyAlternateEmail() returned nil response")
	}

	if authResponse.IDToken == "" {
		t.Error("VerifyAlternateEmail() IDToken is empty")
	}

	if authResponse.TokenType != "Bearer" {
		t.Errorf("VerifyAlternateEmail() TokenType = %q, expected \"Bearer\"", authResponse.TokenType)
	}

	if authResponse.ExpiresIn != 3600 {
		t.Errorf("VerifyAlternateEmail() ExpiresIn = %d, expected 3600", authResponse.ExpiresIn)
	}

	// Test Step 3: Link identity to user
	// Use a user from the YAML file
	linkRequest := &model.LinkIdentity{}
	linkRequest.User.UserID = "auth0|zephyr001" // This exists in users.yaml
	linkRequest.LinkWith.IdentityToken = authResponse.IDToken

	err = writer.LinkIdentity(ctx, linkRequest)
	if err != nil {
		t.Fatalf("LinkIdentity() error = %v (user_id: %s, token exists: %t)",
			err, linkRequest.User.UserID, linkRequest.LinkWith.IdentityToken != "")
	}

	// Verify the email was added to user's alternate emails
	user := &model.User{UserID: "auth0|zephyr001"}
	updatedUser, err := writer.GetUser(ctx, user)
	if err != nil {
		t.Fatalf("GetUser() error = %v", err)
	}

	found := false
	for _, altEmail := range updatedUser.AlternateEmails {
		if altEmail.Email == testEmail && altEmail.Verified {
			found = true
			break
		}
	}

	if !found {
		t.Error("Linked email not found in user's alternate emails")
	}
}

// TestSendVerificationAlternateEmail tests the SendVerificationAlternateEmail method
func TestSendVerificationAlternateEmail(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		email       string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid email",
			email:       "test@example.com",
			expectError: false,
		},
		{
			name:        "valid email with subdomain",
			email:       "user@mail.example.com",
			expectError: false,
		},
		{
			name:        "invalid email format",
			email:       "not-an-email",
			expectError: true,
			errorMsg:    "invalid email format",
		},
		{
			name:        "empty email",
			email:       "",
			expectError: true,
			errorMsg:    "invalid email format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writer := NewUserReaderWriter(ctx)
			err := writer.SendVerificationAlternateEmail(ctx, tt.email)

			if tt.expectError {
				if err == nil {
					t.Error("SendVerificationAlternateEmail() expected error but got none")
					return
				}
				if tt.errorMsg != "" && err.Error() != tt.errorMsg {
					t.Errorf("SendVerificationAlternateEmail() error = %q, expected %q", err.Error(), tt.errorMsg)
				}
			} else if err != nil {
				t.Errorf("SendVerificationAlternateEmail() unexpected error: %v", err)
			}
		})
	}
}

// TestVerifyAlternateEmail tests the VerifyAlternateEmail method
func TestVerifyAlternateEmail(t *testing.T) {
	ctx := context.Background()

	t.Run("successful verification", func(t *testing.T) {
		writer := NewUserReaderWriter(ctx)
		testEmail := "verify@example.com"

		// First send verification
		err := writer.SendVerificationAlternateEmail(ctx, testEmail)
		if err != nil {
			t.Fatalf("SendVerificationAlternateEmail() error = %v", err)
		}

		// Get the OTP
		uw := writer.(*userWriter)
		uw.otpMutex.RLock()
		entry := uw.otps[testEmail]
		uw.otpMutex.RUnlock()

		// Verify with correct OTP
		emailModel := &model.Email{
			Email: testEmail,
			OTP:   entry.otp,
		}

		authResponse, err := writer.VerifyAlternateEmail(ctx, emailModel)
		if err != nil {
			t.Fatalf("VerifyAlternateEmail() error = %v", err)
		}

		if authResponse == nil || authResponse.IDToken == "" {
			t.Error("VerifyAlternateEmail() returned invalid response")
		}
	})

	t.Run("invalid OTP", func(t *testing.T) {
		writer := NewUserReaderWriter(ctx)
		testEmail := "invalid-otp@example.com"

		// First send verification
		err := writer.SendVerificationAlternateEmail(ctx, testEmail)
		if err != nil {
			t.Fatalf("SendVerificationAlternateEmail() error = %v", err)
		}

		// Verify with wrong OTP
		emailModel := &model.Email{
			Email: testEmail,
			OTP:   "000000",
		}

		_, err = writer.VerifyAlternateEmail(ctx, emailModel)
		if err == nil {
			t.Error("VerifyAlternateEmail() expected error for invalid OTP but got none")
		}
	})

	t.Run("OTP not found", func(t *testing.T) {
		writer := NewUserReaderWriter(ctx)

		emailModel := &model.Email{
			Email: "nonexistent@example.com",
			OTP:   "123456",
		}

		_, err := writer.VerifyAlternateEmail(ctx, emailModel)
		if err == nil {
			t.Error("VerifyAlternateEmail() expected error for nonexistent OTP but got none")
		}
	})
}

// TestLinkIdentity tests the LinkIdentity method
func TestLinkIdentity(t *testing.T) {
	ctx := context.Background()

	t.Run("missing request", func(t *testing.T) {
		writer := NewUserReaderWriter(ctx)
		err := writer.LinkIdentity(ctx, nil)
		if err == nil {
			t.Error("LinkIdentity() expected error for nil request but got none")
		}
	})

	t.Run("missing user_id", func(t *testing.T) {
		writer := NewUserReaderWriter(ctx)
		request := &model.LinkIdentity{}
		request.LinkWith.IdentityToken = "some-token"

		err := writer.LinkIdentity(ctx, request)
		if err == nil {
			t.Error("LinkIdentity() expected error for missing user_id but got none")
		}
	})

	t.Run("missing identity_token", func(t *testing.T) {
		writer := NewUserReaderWriter(ctx)
		request := &model.LinkIdentity{}
		request.User.UserID = "test-user"

		err := writer.LinkIdentity(ctx, request)
		if err == nil {
			t.Error("LinkIdentity() expected error for missing identity_token but got none")
		}
	})

	t.Run("user not found", func(t *testing.T) {
		writer := NewUserReaderWriter(ctx)

		// Create a valid identity token
		jwtGen := jwtpkg.HMACIdentityTokenOptions("test@example.com", []byte("test-secret"))
		idToken, err := jwtpkg.Generate(jwtGen)
		if err != nil {
			t.Fatalf("Failed to generate test token: %v", err)
		}

		request := &model.LinkIdentity{}
		request.User.UserID = "nonexistent-user"
		request.LinkWith.IdentityToken = idToken

		err = writer.LinkIdentity(ctx, request)
		if err == nil {
			t.Error("LinkIdentity() expected error for nonexistent user but got none")
		}
	})
}
