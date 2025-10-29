// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseUnverified(t *testing.T) {
	ctx := context.Background()

	t.Run("valid token with all claims", func(t *testing.T) {
		// Create a test token
		now := time.Now()
		exp := now.Add(time.Hour)
		iat := now.Add(-time.Minute)

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub":   "user123",
			"exp":   exp.Unix(),
			"iat":   iat.Unix(),
			"iss":   "test-issuer",
			"aud":   "test-audience",
			"scope": "read write update:current_user_metadata",
		})

		tokenString, err := token.SignedString([]byte("secret"))
		require.NoError(t, err)

		claims, err := ParseUnverified(ctx, tokenString, DefaultParseOptions())
		require.NoError(t, err)

		assert.Equal(t, "user123", claims.Subject)
		assert.NotNil(t, claims.ExpiresAt)
		assert.WithinDuration(t, exp, *claims.ExpiresAt, time.Second)
		assert.NotNil(t, claims.IssuedAt)
		assert.WithinDuration(t, iat, *claims.IssuedAt, time.Second)
		assert.Equal(t, "test-issuer", claims.Issuer)
		assert.Equal(t, "test-audience", claims.Audience)
		assert.Equal(t, "read write update:current_user_metadata", claims.Scope)
	})

	t.Run("token with Bearer prefix", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "user123",
			"exp": time.Now().Add(time.Hour).Unix(),
		})

		tokenString, err := token.SignedString([]byte("secret"))
		require.NoError(t, err)

		bearerToken := "Bearer " + tokenString
		claims, err := ParseUnverified(ctx, bearerToken, DefaultParseOptions())
		require.NoError(t, err)

		assert.Equal(t, "user123", claims.Subject)
	})

	t.Run("expired token", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "user123",
			"exp": time.Now().Add(-time.Hour).Unix(), // Expired
		})

		tokenString, err := token.SignedString([]byte("secret"))
		require.NoError(t, err)

		_, err = ParseUnverified(ctx, tokenString, DefaultParseOptions())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exp")
	})

	t.Run("missing required scope", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub":   "user123",
			"exp":   time.Now().Add(time.Hour).Unix(),
			"scope": "read write",
		})

		tokenString, err := token.SignedString([]byte("secret"))
		require.NoError(t, err)

		opts := &ParseOptions{
			RequireExpiration: true,
			RequiredScopes:    []string{"update:current_user_metadata"},
			AllowBearerPrefix: true,
		}

		_, err = ParseUnverified(ctx, tokenString, opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing required scope")
	})

	t.Run("valid token with required scope", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub":   "user123",
			"exp":   time.Now().Add(time.Hour).Unix(),
			"scope": "read write update:current_user_metadata",
		})

		tokenString, err := token.SignedString([]byte("secret"))
		require.NoError(t, err)

		opts := &ParseOptions{
			RequireExpiration: true,
			RequiredScopes:    []string{"update:current_user_metadata"},
			AllowBearerPrefix: true,
		}

		claims, err := ParseUnverified(ctx, tokenString, opts)
		require.NoError(t, err)
		assert.Equal(t, "user123", claims.Subject)
		assert.True(t, claims.HasScope("update:current_user_metadata"))
		assert.True(t, claims.HasScope("read"))
		assert.False(t, claims.HasScope("admin"))
	})

	t.Run("empty token", func(t *testing.T) {
		_, err := ParseUnverified(ctx, "", DefaultParseOptions())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token is required")
	})

	t.Run("invalid token format", func(t *testing.T) {
		_, err := ParseUnverified(ctx, "invalid.token", DefaultParseOptions())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse JWT token")
	})
}

func TestExtractSubject(t *testing.T) {
	ctx := context.Background()

	t.Run("valid token", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "user123",
		})

		tokenString, err := token.SignedString([]byte("secret"))
		require.NoError(t, err)

		subject, err := ExtractSubject(ctx, tokenString)
		require.NoError(t, err)
		assert.Equal(t, "user123", subject)
	})

	t.Run("token with Bearer prefix", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "user456",
		})

		tokenString, err := token.SignedString([]byte("secret"))
		require.NoError(t, err)

		bearerToken := "Bearer " + tokenString
		subject, err := ExtractSubject(ctx, bearerToken)
		require.NoError(t, err)
		assert.Equal(t, "user456", subject)
	})

	t.Run("missing sub claim", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"iss": "test-issuer",
		})

		tokenString, err := token.SignedString([]byte("secret"))
		require.NoError(t, err)

		_, err = ExtractSubject(ctx, tokenString)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing or invalid 'sub' claim")
	})

	t.Run("empty sub claim", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "",
		})

		tokenString, err := token.SignedString([]byte("secret"))
		require.NoError(t, err)

		_, err = ExtractSubject(ctx, tokenString)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing or invalid 'sub' claim")
	})
}

func TestExtractEmail(t *testing.T) {
	ctx := context.Background()

	t.Run("valid token with email", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"email": "user@example.com",
		})

		tokenString, err := token.SignedString([]byte("secret"))
		require.NoError(t, err)

		email, err := ExtractEmail(ctx, tokenString)
		require.NoError(t, err)
		assert.Equal(t, "user@example.com", email)
	})

	t.Run("valid token with email and other claims", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"email": "john.doe@company.com",
			"sub":   "auth0|123456789",
			"iss":   "https://test.auth0.com/",
		})

		tokenString, err := token.SignedString([]byte("secret"))
		require.NoError(t, err)

		email, err := ExtractEmail(ctx, tokenString)
		require.NoError(t, err)
		assert.Equal(t, "john.doe@company.com", email)
	})

	t.Run("token with Bearer prefix", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"email": "bearer-test@example.com",
		})

		tokenString, err := token.SignedString([]byte("secret"))
		require.NoError(t, err)

		bearerToken := "Bearer " + tokenString
		email, err := ExtractEmail(ctx, bearerToken)
		require.NoError(t, err)
		assert.Equal(t, "bearer-test@example.com", email)
	})

	t.Run("missing email claim", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "user123",
			"iss": "test-issuer",
		})

		tokenString, err := token.SignedString([]byte("secret"))
		require.NoError(t, err)

		_, err = ExtractEmail(ctx, tokenString)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing or invalid 'email' claim")
	})

	t.Run("empty email claim", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"email": "",
		})

		tokenString, err := token.SignedString([]byte("secret"))
		require.NoError(t, err)

		_, err = ExtractEmail(ctx, tokenString)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing or invalid 'email' claim")
	})

	t.Run("whitespace-only email claim", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"email": "   ",
		})

		tokenString, err := token.SignedString([]byte("secret"))
		require.NoError(t, err)

		_, err = ExtractEmail(ctx, tokenString)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing or invalid 'email' claim")
	})

	t.Run("invalid token format", func(t *testing.T) {
		_, err := ExtractEmail(ctx, "invalid.token")
		assert.Error(t, err)
	})

	t.Run("empty token", func(t *testing.T) {
		_, err := ExtractEmail(ctx, "")
		assert.Error(t, err)
	})

	t.Run("identity token with verified email", func(t *testing.T) {
		// Simulates an identity token from email verification flow
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"email":          "verified@example.com",
			"email_verified": true,
			"sub":            "passwordless|654321",
		})

		tokenString, err := token.SignedString([]byte("secret"))
		require.NoError(t, err)

		email, err := ExtractEmail(ctx, tokenString)
		require.NoError(t, err)
		assert.Equal(t, "verified@example.com", email)
	})
}

func TestClaimsHelpers(t *testing.T) {
	claims := &Claims{
		Subject: "user123",
		Scope:   "read write admin",
		Raw: jwt.MapClaims{
			"custom_field": "custom_value",
			"number_field": 42,
		},
	}

	t.Run("GetClaim", func(t *testing.T) {
		value, exists := claims.GetClaim("custom_field")
		assert.True(t, exists)
		assert.Equal(t, "custom_value", value)

		_, exists = claims.GetClaim("nonexistent")
		assert.False(t, exists)
	})

	t.Run("GetStringClaim", func(t *testing.T) {
		value, ok := claims.GetStringClaim("custom_field")
		assert.True(t, ok)
		assert.Equal(t, "custom_value", value)

		_, ok = claims.GetStringClaim("number_field")
		assert.False(t, ok) // Not a string

		_, ok = claims.GetStringClaim("nonexistent")
		assert.False(t, ok)
	})

	t.Run("HasScope", func(t *testing.T) {
		assert.True(t, claims.HasScope("read"))
		assert.True(t, claims.HasScope("write"))
		assert.True(t, claims.HasScope("admin"))
		assert.False(t, claims.HasScope("delete"))
	})
}

func TestParseVerified(t *testing.T) {
	// Generate a test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// Create a test JWT token
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

	tests := []struct {
		name        string
		token       string
		opts        *ParseOptions
		expectError bool
		errorType   error
	}{
		{
			name:  "valid token with signature verification",
			token: tokenString,
			opts: &ParseOptions{
				VerifySignature:   true,
				SigningKey:        publicKey,
				ExpectedIssuer:    "https://test.auth0.com/",
				ExpectedAudience:  "https://test.auth0.com/api/v2/",
				RequireExpiration: true,
				RequireSubject:    true,
				RequiredScopes:    []string{"read:current_user"},
			},
			expectError: false,
		},
		{
			name:  "valid token with Bearer prefix",
			token: "Bearer " + tokenString,
			opts: &ParseOptions{
				VerifySignature:   true,
				SigningKey:        publicKey,
				ExpectedIssuer:    "https://test.auth0.com/",
				ExpectedAudience:  "https://test.auth0.com/api/v2/",
				RequireExpiration: true,
				RequireSubject:    true,
				AllowBearerPrefix: true,
			},
			expectError: false,
		},
		{
			name:  "invalid signature",
			token: tokenString,
			opts: &ParseOptions{
				VerifySignature:   true,
				SigningKey:        &rsa.PublicKey{}, // Wrong key
				ExpectedIssuer:    "https://test.auth0.com/",
				ExpectedAudience:  "https://test.auth0.com/api/v2/",
				RequireExpiration: true,
				RequireSubject:    true,
			},
			expectError: true,
		},
		{
			name:  "wrong issuer",
			token: tokenString,
			opts: &ParseOptions{
				VerifySignature:   true,
				SigningKey:        publicKey,
				ExpectedIssuer:    "https://wrong.auth0.com/",
				ExpectedAudience:  "https://test.auth0.com/api/v2/",
				RequireExpiration: true,
				RequireSubject:    true,
			},
			expectError: true,
		},
		{
			name:  "wrong audience",
			token: tokenString,
			opts: &ParseOptions{
				VerifySignature:   true,
				SigningKey:        publicKey,
				ExpectedIssuer:    "https://test.auth0.com/",
				ExpectedAudience:  "https://wrong.auth0.com/api/v2/",
				RequireExpiration: true,
				RequireSubject:    true,
			},
			expectError: true,
		},
		{
			name:  "expired token",
			token: createExpiredToken(t, privateKey),
			opts: &ParseOptions{
				VerifySignature:   true,
				SigningKey:        publicKey,
				ExpectedIssuer:    "https://test.auth0.com/",
				ExpectedAudience:  "https://test.auth0.com/api/v2/",
				RequireExpiration: true,
				RequireSubject:    true,
			},
			expectError: true,
		},
		{
			name:  "missing required scope",
			token: tokenString,
			opts: &ParseOptions{
				VerifySignature:   true,
				SigningKey:        publicKey,
				ExpectedIssuer:    "https://test.auth0.com/",
				ExpectedAudience:  "https://test.auth0.com/api/v2/",
				RequireExpiration: true,
				RequireSubject:    true,
				RequiredScopes:    []string{"admin:all"}, // Not in token
			},
			expectError: true,
		},
		{
			name:  "missing signing key",
			token: tokenString,
			opts: &ParseOptions{
				VerifySignature:   true,
				SigningKey:        nil,
				ExpectedIssuer:    "https://test.auth0.com/",
				ExpectedAudience:  "https://test.auth0.com/api/v2/",
				RequireExpiration: true,
				RequireSubject:    true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			claims, err := ParseVerified(ctx, tt.token, tt.opts)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if tt.errorType != nil {
					// Check if error is of expected type (simplified check)
					if err.Error() == "" {
						t.Errorf("Expected error type %v, got %v", tt.errorType, err)
					}
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if claims == nil {
				t.Error("Expected claims but got nil")
				return
			}

			if claims.Subject != "test-user-123" {
				t.Errorf("Expected subject 'test-user-123', got '%s'", claims.Subject)
			}
		})
	}
}

func TestLoadRSAPublicKeyFromJWK(t *testing.T) {
	// Generate a test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create JWK data
	jwkData := []byte(`{
		"kty": "RSA",
		"use": "sig",
		"kid": "test-key-1",
		"alg": "RS256",
		"n": "` + encodeBase64URL(privateKey.N.Bytes()) + `",
		"e": "` + encodeBase64URL([]byte{1, 0, 1}) + `"
	}`)

	// Test loading the key
	loadedKey, err := LoadRSAPublicKeyFromJWK(jwkData)
	if err != nil {
		t.Fatalf("Failed to load RSA public key from JWK: %v", err)
	}

	if loadedKey.N.Cmp(privateKey.N) != 0 {
		t.Error("Loaded key modulus doesn't match original")
	}

	if loadedKey.E != privateKey.E {
		t.Error("Loaded key exponent doesn't match original")
	}
}

func createExpiredToken(t *testing.T, privateKey *rsa.PrivateKey) string {
	// Create an expired JWT token
	claims := jwt.MapClaims{
		"sub":   "test-user-123",
		"iss":   "https://test.auth0.com/",
		"aud":   "https://test.auth0.com/api/v2/",
		"exp":   time.Now().Add(-time.Hour).Unix(), // Expired 1 hour ago
		"iat":   time.Now().Add(-2 * time.Hour).Unix(),
		"scope": "read:current_user",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign expired token: %v", err)
	}

	return tokenString
}

func encodeBase64URL(data []byte) string {
	// Convert to base64url encoding
	encoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(data)
	return encoded
}

func TestLooksLikeJWT(t *testing.T) {
	tests := []struct {
		name           string
		tokenStr       string
		expectedToken  string
		expectedResult bool
		description    string
	}{
		{
			name:           "empty string",
			tokenStr:       "",
			expectedToken:  "",
			expectedResult: false,
			description:    "Empty string should not be recognized as JWT",
		},
		{
			name:           "whitespace only",
			tokenStr:       "   ",
			expectedToken:  "",
			expectedResult: false,
			description:    "Whitespace-only string should not be recognized as JWT",
		},
		{
			name:          "valid JWT without Bearer prefix",
			tokenStr:      "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdXRoMHwxMjM0NTY3ODkiLCJleHAiOjE2MzQ1Njc4OTAsImlhdCI6MTYzNDU2NDI5MCwic2NvcGUiOiJyZWFkOmN1cnJlbnRfdXNlciJ9.signature",
			expectedToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdXRoMHwxMjM0NTY3ODkiLCJleHAiOjE2MzQ1Njc4OTAsImlhdCI6MTYzNDU2NDI5MCwic2NvcGUiOiJyZWFkOmN1cnJlbnRfdXNlciJ9.signature", expectedResult: true,
			description: "Valid JWT structure should be recognized",
		},
		{
			name:     "valid JWT with Bearer prefix",
			tokenStr: "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdXRoMHwxMjM0NTY3ODkiLCJleHAiOjE2MzQ1Njc4OTAsImlhdCI6MTYzNDU2NDI5MCwic2NvcGUiOiJyZWFkOmN1cnJlbnRfdXNlciJ9.signature", expectedToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdXRoMHwxMjM0NTY3ODkiLCJleHAiOjE2MzQ1Njc4OTAsImlhdCI6MTYzNDU2NDI5MCwic2NvcGUiOiJyZWFkOmN1cnJlbnRfdXNlciJ9.signature", expectedResult: true,
			description: "Valid JWT with Bearer prefix should be recognized and cleaned",
		},
		{
			name:     "invalid JWT - only two parts",
			tokenStr: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdXRoMHwxMjM0NTY3ODki", expectedToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdXRoMHwxMjM0NTY3ODki",
			expectedResult: false,
			description:    "JWT with only two parts should not be recognized",
		},
		{
			name:           "invalid JWT - malformed structure",
			tokenStr:       "not.a.valid.jwt",
			expectedToken:  "not.a.valid.jwt",
			expectedResult: false,
			description:    "Malformed JWT structure should not be recognized",
		},
		{
			name:           "username - should not be JWT",
			tokenStr:       "john.doe",
			expectedToken:  "john.doe",
			expectedResult: false,
			description:    "Username should not be recognized as JWT",
		},
		{
			name:           "sub with pipe - should not be JWT",
			tokenStr:       "auth0|123456789",
			expectedToken:  "auth0|123456789",
			expectedResult: false,
			description:    "Sub with pipe should not be recognized as JWT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanToken, isJWT := LooksLikeJWT(tt.tokenStr)

			// Check the boolean result
			if isJWT != tt.expectedResult {
				t.Errorf("LooksLikeJWT() %s: result = %v, expected %v", tt.name, isJWT, tt.expectedResult)
			}

			// Check the cleaned token
			if cleanToken != tt.expectedToken {
				t.Errorf("LooksLikeJWT() %s: cleanToken = %q, expected %q", tt.name, cleanToken, tt.expectedToken)
			}
		})
	}
}
