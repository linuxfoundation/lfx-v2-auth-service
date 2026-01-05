// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
)

func TestJWTVerification(t *testing.T) {
	// Generate a test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// Create JWT verification config
	jwtVerify := &JWTVerificationConfig{
		PublicKey:        publicKey,
		ExpectedIssuer:   "https://test.auth0.com/",
		ExpectedAudience: "https://test.auth0.com/api/v2/",
	}

	tests := []struct {
		name        string
		token       string
		expectError bool
	}{
		{
			name:        "valid JWT with signature verification",
			token:       createValidJWT(t, privateKey),
			expectError: false,
		},
		{
			name:        "invalid signature",
			token:       createInvalidSignatureJWT(t),
			expectError: true,
		},
		{
			name:        "expired JWT",
			token:       createExpiredJWT(t, privateKey),
			expectError: true,
		},
		{
			name:        "wrong issuer",
			token:       createWrongIssuerJWT(t, privateKey),
			expectError: true,
		},
		{
			name:        "wrong audience",
			token:       createWrongAudienceJWT(t, privateKey),
			expectError: true,
		},
		{
			name:        "missing required scope",
			token:       createMissingScopeJWT(t, privateKey),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			user := &model.User{
				Token: tt.token,
			}

			claims, err := jwtVerify.JWTVerify(ctx, user.Token, userUpdateRequiredScope)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if claims != nil {
					user.UserID = claims.Subject
				}
				if user.UserID != "test-user-123" {
					t.Errorf("Expected user ID 'test-user-123', got '%s'", user.UserID)
				}
			}
		})
	}
}

func TestMetadataLookupWithJWTVerification(t *testing.T) {
	// Generate a test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// Create JWT verification config
	jwtConfig := &JWTVerificationConfig{
		PublicKey:        publicKey,
		ExpectedIssuer:   "https://test.auth0.com/",
		ExpectedAudience: "https://test.auth0.com/api/v2/",
	}

	// Create Auth0 config
	config := Config{
		Domain:                "test.auth0.com",
		JWTVerificationConfig: jwtConfig,
	}

	// Create user reader writer
	httpConfig := httpclient.Config{}
	userRW := &userReaderWriter{
		config:        config,
		httpClient:    httpclient.NewClient(httpConfig),
		errorResponse: NewErrorResponse(),
	}

	tests := []struct {
		name        string
		token       string
		expectError bool
	}{
		{
			name:        "valid JWT for metadata lookup",
			token:       createValidMetadataJWT(t, privateKey),
			expectError: false,
		},
		{
			name:        "invalid signature for metadata lookup",
			token:       createInvalidSignatureJWT(t),
			expectError: true,
		},
		{
			name:        "missing read scope for metadata lookup",
			token:       createMissingReadScopeJWT(t, privateKey),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			user, err := userRW.MetadataLookup(ctx, tt.token, "read:current_user")

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if user == nil {
					t.Error("Expected user but got nil")
				} else if user.UserID != "test-user-123" {
					t.Errorf("Expected user ID 'test-user-123', got '%s'", user.UserID)
				}
			}
		})
	}
}

func createValidJWT(t *testing.T, privateKey *rsa.PrivateKey) string {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":   "test-user-123",
		"iss":   "https://test.auth0.com/",
		"aud":   "https://test.auth0.com/api/v2/",
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"scope": "read:current_user update:current_user_metadata",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	return tokenString
}

func createValidMetadataJWT(t *testing.T, privateKey *rsa.PrivateKey) string {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":   "test-user-123",
		"iss":   "https://test.auth0.com/",
		"aud":   "https://test.auth0.com/api/v2/",
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"scope": "read:current_user",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	return tokenString
}

func createInvalidSignatureJWT(t *testing.T) string {
	// Create a token with a different key (invalid signature)
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate wrong key: %v", err)
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"sub":   "test-user-123",
		"iss":   "https://test.auth0.com/",
		"aud":   "https://test.auth0.com/api/v2/",
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"scope": "read:current_user update:current_user_metadata",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(wrongKey)
	if err != nil {
		t.Fatalf("Failed to sign token with wrong key: %v", err)
	}

	return tokenString
}

func createExpiredJWT(t *testing.T, privateKey *rsa.PrivateKey) string {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":   "test-user-123",
		"iss":   "https://test.auth0.com/",
		"aud":   "https://test.auth0.com/api/v2/",
		"exp":   now.Add(-time.Hour).Unix(), // Expired 1 hour ago
		"iat":   now.Add(-2 * time.Hour).Unix(),
		"scope": "read:current_user update:current_user_metadata",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign expired token: %v", err)
	}

	return tokenString
}

func createWrongIssuerJWT(t *testing.T, privateKey *rsa.PrivateKey) string {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":   "test-user-123",
		"iss":   "https://wrong.auth0.com/", // Wrong issuer
		"aud":   "https://test.auth0.com/api/v2/",
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"scope": "read:current_user update:current_user_metadata",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign token with wrong issuer: %v", err)
	}

	return tokenString
}

func createWrongAudienceJWT(t *testing.T, privateKey *rsa.PrivateKey) string {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":   "test-user-123",
		"iss":   "https://test.auth0.com/",
		"aud":   "https://wrong.auth0.com/api/v2/", // Wrong audience
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"scope": "read:current_user update:current_user_metadata",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign token with wrong audience: %v", err)
	}

	return tokenString
}

func createMissingScopeJWT(t *testing.T, privateKey *rsa.PrivateKey) string {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":   "test-user-123",
		"iss":   "https://test.auth0.com/",
		"aud":   "https://test.auth0.com/api/v2/",
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"scope": "read:current_user", // Missing update:current_user_metadata scope
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign token with missing scope: %v", err)
	}

	return tokenString
}

func createMissingReadScopeJWT(t *testing.T, privateKey *rsa.PrivateKey) string {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":   "test-user-123",
		"iss":   "https://test.auth0.com/",
		"aud":   "https://test.auth0.com/api/v2/",
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"scope": "update:current_user_metadata", // Missing read:current_user scope
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign token with missing read scope: %v", err)
	}

	return tokenString
}

func TestMetadataLookupWithoutJWTVerificationConfig(t *testing.T) {
	// Create Auth0 config without JWT verification config
	config := Config{
		Domain: "test.auth0.com",
		// JWTVerificationConfig is nil
	}

	// Create user reader writer
	httpConfig := httpclient.Config{}
	userRW := &userReaderWriter{
		config:        config,
		httpClient:    httpclient.NewClient(httpConfig),
		errorResponse: NewErrorResponse(),
	}

	tests := []struct {
		name        string
		token       string
		expectError bool
	}{
		{
			name:        "missing JWT verification config for metadata lookup",
			token:       "any-token",
			expectError: false, // Now handled as username lookup with M2M token
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			user, err := userRW.MetadataLookup(ctx, tt.token)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if user == nil {
					t.Error("Expected user but got nil")
				}
			}
		})
	}
}
