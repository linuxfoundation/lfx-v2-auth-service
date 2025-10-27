// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateAccessToken(t *testing.T) {
	// Generate test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	publicKey := &privateKey.PublicKey

	t.Run("access token with RSA signing", func(t *testing.T) {
		opts := &GeneratorOptions{
			TokenType:     TokenTypeAccess,
			Subject:       "auth0|123456789",
			Issuer:        "https://test.auth0.com/",
			Audience:      "https://test.auth0.com/api/v2/",
			Scope:         "read:current_user update:current_user_metadata",
			ExpiresIn:     time.Hour,
			IssuedAt:      time.Now(),
			SigningMethod: jwa.RS256,
			SigningKey:    privateKey,
		}

		tokenString, err := Generate(opts)
		require.NoError(t, err)
		assert.NotEmpty(t, tokenString)

		// Verify the token can be parsed and validated
		ctx := context.Background()
		parseOpts := &ParseOptions{
			VerifySignature:   true,
			SigningKey:        publicKey,
			ExpectedIssuer:    opts.Issuer,
			ExpectedAudience:  opts.Audience,
			RequireExpiration: true,
			RequireSubject:    true,
		}
		claims, err := ParseVerified(ctx, tokenString, parseOpts)
		require.NoError(t, err)

		assert.Equal(t, opts.Subject, claims.Subject)
		assert.Equal(t, opts.Issuer, claims.Issuer)
		assert.Equal(t, opts.Audience, claims.Audience)
		assert.Equal(t, opts.Scope, claims.Scope)
		assert.NotNil(t, claims.ExpiresAt)
		assert.NotNil(t, claims.IssuedAt)
	})

	t.Run("access token with HMAC signing", func(t *testing.T) {
		secret := []byte("test-secret-key-for-hmac-signing")
		opts := &GeneratorOptions{
			TokenType:     TokenTypeAccess,
			Subject:       "user123",
			Issuer:        "test-issuer",
			Scope:         "read write",
			ExpiresIn:     time.Hour,
			IssuedAt:      time.Now(),
			SigningMethod: jwa.HS256,
			SigningKey:    secret,
		}

		tokenString, err := Generate(opts)
		require.NoError(t, err)
		assert.NotEmpty(t, tokenString)

		// Parse without verification
		ctx := context.Background()
		parseOpts := &ParseOptions{
			RequireExpiration: true,
			RequireSubject:    true,
		}
		claims, err := ParseUnverified(ctx, tokenString, parseOpts)
		require.NoError(t, err)

		assert.Equal(t, opts.Subject, claims.Subject)
		assert.Equal(t, opts.Issuer, claims.Issuer)
		assert.Equal(t, opts.Scope, claims.Scope)
	})

	t.Run("missing subject for access token", func(t *testing.T) {
		opts := &GeneratorOptions{
			TokenType:     TokenTypeAccess,
			ExpiresIn:     time.Hour,
			SigningMethod: jwa.RS256,
			SigningKey:    privateKey,
		}

		_, err := Generate(opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "subject is required")
	})
}

func TestGenerateIdentityToken(t *testing.T) {
	// Generate test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	publicKey := &privateKey.PublicKey

	t.Run("identity token with RSA signing", func(t *testing.T) {
		opts := &GeneratorOptions{
			TokenType:     TokenTypeIdentity,
			Email:         "user@example.com",
			Issuer:        "https://test.auth0.com/",
			Audience:      "https://test.auth0.com/api/v2/",
			ExpiresIn:     30 * time.Minute,
			IssuedAt:      time.Now(),
			SigningMethod: jwa.RS256,
			SigningKey:    privateKey,
		}

		tokenString, err := Generate(opts)
		require.NoError(t, err)
		assert.NotEmpty(t, tokenString)

		// Verify the token can be parsed
		ctx := context.Background()
		parseOpts := &ParseOptions{
			VerifySignature:   true,
			SigningKey:        publicKey,
			ExpectedIssuer:    opts.Issuer,
			ExpectedAudience:  opts.Audience,
			RequireExpiration: true,
			RequireSubject:    false, // Identity tokens may not have subject
		}
		claims, err := ParseVerified(ctx, tokenString, parseOpts)
		require.NoError(t, err)

		// Check email claim
		email, ok := claims.GetStringClaim("email")
		assert.True(t, ok)
		assert.Equal(t, opts.Email, email)
		assert.Equal(t, opts.Issuer, claims.Issuer)
		assert.Equal(t, opts.Audience, claims.Audience)
	})

	t.Run("identity token with HMAC signing", func(t *testing.T) {
		secret := []byte("test-secret-key-for-hmac-signing")
		opts := &GeneratorOptions{
			TokenType:     TokenTypeIdentity,
			Email:         "user@example.com",
			Issuer:        "test-issuer",
			ExpiresIn:     time.Hour,
			IssuedAt:      time.Now(),
			SigningMethod: jwa.HS256,
			SigningKey:    secret,
		}

		tokenString, err := Generate(opts)
		require.NoError(t, err)
		assert.NotEmpty(t, tokenString)

		// Parse without verification
		ctx := context.Background()
		parseOpts := &ParseOptions{
			RequireExpiration: true,
			RequireSubject:    false,
		}
		claims, err := ParseUnverified(ctx, tokenString, parseOpts)
		require.NoError(t, err)

		email, ok := claims.GetStringClaim("email")
		assert.True(t, ok)
		assert.Equal(t, opts.Email, email)
		assert.Equal(t, opts.Issuer, claims.Issuer)
	})

	t.Run("identity token with additional claims", func(t *testing.T) {
		opts := &GeneratorOptions{
			TokenType:     TokenTypeIdentity,
			Email:         "user@example.com",
			Issuer:        "https://custom.issuer.com/",
			ExpiresIn:     2 * time.Hour,
			IssuedAt:      time.Now(),
			SigningMethod: jwa.RS256,
			SigningKey:    privateKey,
			CustomClaims: map[string]any{
				"verification_code": "ABC123",
				"purpose":           "email-verification",
			},
		}

		tokenString, err := Generate(opts)
		require.NoError(t, err)
		assert.NotEmpty(t, tokenString)

		// Verify custom claims are present
		ctx := context.Background()
		parseOpts := &ParseOptions{
			VerifySignature: true,
			SigningKey:      publicKey,
			ExpectedIssuer:  opts.Issuer,
			RequireSubject:  false,
		}
		claims, err := ParseVerified(ctx, tokenString, parseOpts)
		require.NoError(t, err)

		code, ok := claims.GetStringClaim("verification_code")
		assert.True(t, ok)
		assert.Equal(t, "ABC123", code)

		purpose, ok := claims.GetStringClaim("purpose")
		assert.True(t, ok)
		assert.Equal(t, "email-verification", purpose)
	})

	t.Run("identity token with NotBefore claim", func(t *testing.T) {
		// Set NotBefore to past time so token is already valid
		notBefore := time.Now().Add(-1 * time.Minute)
		opts := &GeneratorOptions{
			TokenType:     TokenTypeIdentity,
			Email:         "user@example.com",
			ExpiresIn:     time.Hour,
			IssuedAt:      time.Now(),
			NotBefore:     &notBefore,
			SigningMethod: jwa.RS256,
			SigningKey:    privateKey,
		}

		tokenString, err := Generate(opts)
		require.NoError(t, err)
		assert.NotEmpty(t, tokenString)

		// Parse and check NotBefore
		ctx := context.Background()
		parseOpts := &ParseOptions{
			VerifySignature:   true,
			SigningKey:        publicKey,
			RequireExpiration: true,
			RequireSubject:    false,
		}
		claims, err := ParseVerified(ctx, tokenString, parseOpts)
		require.NoError(t, err)

		assert.NotNil(t, claims.NotBefore)
		assert.WithinDuration(t, notBefore, *claims.NotBefore, time.Second)
	})

	t.Run("identity token with subject", func(t *testing.T) {
		// Identity tokens can also have a subject along with email
		opts := &GeneratorOptions{
			TokenType:     TokenTypeIdentity,
			Email:         "user@example.com",
			Subject:       "auth0|123456789",
			Issuer:        "https://test.auth0.com/",
			ExpiresIn:     time.Hour,
			IssuedAt:      time.Now(),
			SigningMethod: jwa.RS256,
			SigningKey:    privateKey,
		}

		tokenString, err := Generate(opts)
		require.NoError(t, err)

		// Parse and verify both email and subject are present
		ctx := context.Background()
		parseOpts := &ParseOptions{
			VerifySignature: true,
			SigningKey:      publicKey,
			ExpectedIssuer:  opts.Issuer,
			RequireSubject:  true,
		}
		claims, err := ParseVerified(ctx, tokenString, parseOpts)
		require.NoError(t, err)

		assert.Equal(t, "auth0|123456789", claims.Subject)
		email, ok := claims.GetStringClaim("email")
		assert.True(t, ok)
		assert.Equal(t, "user@example.com", email)
	})

	t.Run("missing signing key", func(t *testing.T) {
		opts := &GeneratorOptions{
			Email:     "user@example.com",
			ExpiresIn: time.Hour,
		}

		_, err := Generate(opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "signing key is required")
	})

	t.Run("missing email", func(t *testing.T) {
		opts := &GeneratorOptions{
			TokenType:     TokenTypeIdentity,
			ExpiresIn:     time.Hour,
			SigningMethod: jwa.RS256,
			SigningKey:    privateKey,
		}

		_, err := Generate(opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "email is required")
	})

	t.Run("nil options", func(t *testing.T) {
		_, err := Generate(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "generator options are required")
	})
}

func TestGenerateAccessTokenConvenience(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	publicKey := &privateKey.PublicKey

	tokenString, err := GenerateAccessToken(
		"auth0|123456789",
		"https://test.auth0.com/",
		"https://test.auth0.com/api/v2/",
		"read:current_user update:current_user_metadata",
		time.Hour,
		privateKey,
	)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	// Verify the token
	ctx := context.Background()
	parseOpts := &ParseOptions{
		VerifySignature:   true,
		SigningKey:        publicKey,
		ExpectedIssuer:    "https://test.auth0.com/",
		ExpectedAudience:  "https://test.auth0.com/api/v2/",
		RequireExpiration: true,
		RequireSubject:    true,
		RequiredScopes:    []string{"read:current_user"},
	}
	claims, err := ParseVerified(ctx, tokenString, parseOpts)
	require.NoError(t, err)
	assert.Equal(t, "auth0|123456789", claims.Subject)
	assert.True(t, claims.HasScope("update:current_user_metadata"))
}

func TestGenerateIdentityTokenConvenience(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	publicKey := &privateKey.PublicKey

	tokenString, err := GenerateIdentityToken(
		"user@example.com",
		"https://test.auth0.com/",
		"https://test.auth0.com/api/v2/",
		30*time.Minute,
		privateKey,
	)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	// Verify the token
	ctx := context.Background()
	parseOpts := &ParseOptions{
		VerifySignature:   true,
		SigningKey:        publicKey,
		ExpectedIssuer:    "https://test.auth0.com/",
		ExpectedAudience:  "https://test.auth0.com/api/v2/",
		RequireExpiration: true,
		RequireSubject:    false,
	}
	claims, err := ParseVerified(ctx, tokenString, parseOpts)
	require.NoError(t, err)

	email, ok := claims.GetStringClaim("email")
	assert.True(t, ok)
	assert.Equal(t, "user@example.com", email)
}

func TestGenerateTestAccessToken(t *testing.T) {
	t.Run("generate with default test key", func(t *testing.T) {
		token, err := GenerateTestAccessToken(
			"test-user-123",
			"https://test.auth0.com/",
			"https://test.auth0.com/api/v2/",
			"read:current_user",
			time.Hour,
		)
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify token can be parsed
		ctx := context.Background()
		claims, err := ParseUnverified(ctx, token, DefaultParseOptions())
		require.NoError(t, err)
		assert.Equal(t, "test-user-123", claims.Subject)
	})

	t.Run("tokens use same key (singleton)", func(t *testing.T) {
		token1, err := GenerateTestAccessToken("user1", "https://test.com/", "https://api.test.com/", "read", time.Hour)
		require.NoError(t, err)

		token2, err := GenerateTestAccessToken("user2", "https://test.com/", "https://api.test.com/", "read", time.Hour)
		require.NoError(t, err)

		// Both tokens should be verifiable with the same public key
		publicKey, err := GetDefaultTestPublicKey()
		require.NoError(t, err)

		ctx := context.Background()
		parseOpts := &ParseOptions{
			VerifySignature: true,
			SigningKey:      publicKey,
		}

		_, err = ParseVerified(ctx, token1, parseOpts)
		require.NoError(t, err)

		_, err = ParseVerified(ctx, token2, parseOpts)
		require.NoError(t, err)
	})
}

func TestGenerateTestIdentityToken(t *testing.T) {
	t.Run("generate with default test key", func(t *testing.T) {
		token, err := GenerateTestIdentityToken(
			"test@example.com",
			"https://test.auth0.com/",
			"https://test.auth0.com/api/v2/",
			30*time.Minute,
		)
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		// Verify token can be parsed
		ctx := context.Background()
		parseOpts := &ParseOptions{
			RequireExpiration: true,
			RequireSubject:    false,
		}
		claims, err := ParseUnverified(ctx, token, parseOpts)
		require.NoError(t, err)

		email, ok := claims.GetStringClaim("email")
		assert.True(t, ok)
		assert.Equal(t, "test@example.com", email)
	})

	t.Run("tokens use same key (singleton)", func(t *testing.T) {
		token1, err := GenerateTestIdentityToken("user1@test.com", "https://test.com/", "https://api.test.com/", time.Hour)
		require.NoError(t, err)

		token2, err := GenerateTestIdentityToken("user2@test.com", "https://test.com/", "https://api.test.com/", time.Hour)
		require.NoError(t, err)

		// Both tokens should be verifiable with the same public key
		publicKey, err := GetDefaultTestPublicKey()
		require.NoError(t, err)

		ctx := context.Background()
		parseOpts := &ParseOptions{
			VerifySignature: true,
			SigningKey:      publicKey,
			RequireSubject:  false,
		}

		_, err = ParseVerified(ctx, token1, parseOpts)
		require.NoError(t, err)

		_, err = ParseVerified(ctx, token2, parseOpts)
		require.NoError(t, err)
	})
}

func TestGenerateTestHMACIdentityToken(t *testing.T) {
	token, err := GenerateTestHMACIdentityToken(
		"hmac-identity@example.com",
		"test-issuer",
		"test-audience",
		time.Hour,
	)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Parse token
	ctx := context.Background()
	parseOpts := &ParseOptions{
		RequireSubject: false,
	}
	claims, err := ParseUnverified(ctx, token, parseOpts)
	require.NoError(t, err)

	email, ok := claims.GetStringClaim("email")
	assert.True(t, ok)
	assert.Equal(t, "hmac-identity@example.com", email)
}

func TestGenerateSimpleTestAccessToken(t *testing.T) {
	// Super simple - just subject and expiration
	token, err := GenerateSimpleTestAccessToken("simple-user", time.Hour)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Verify it has default values
	ctx := context.Background()
	claims, err := ParseUnverified(ctx, token, DefaultParseOptions())
	require.NoError(t, err)

	assert.Equal(t, "simple-user", claims.Subject)
	assert.Equal(t, "https://test.any.com/", claims.Issuer)
	assert.Equal(t, "https://test.any.com/api/v2/", claims.Audience)
	assert.Equal(t, "read:current_user", claims.Scope)
}

func TestGenerateSimpleTestIdentityToken(t *testing.T) {
	// Super simple - just email and expiration
	token, err := GenerateSimpleTestIdentityToken("simple@example.com", 30*time.Minute)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Verify it has default values
	ctx := context.Background()
	parseOpts := &ParseOptions{
		RequireSubject: false,
	}
	claims, err := ParseUnverified(ctx, token, parseOpts)
	require.NoError(t, err)

	email, ok := claims.GetStringClaim("email")
	assert.True(t, ok)
	assert.Equal(t, "simple@example.com", email)
	assert.Equal(t, "https://test.any.com/", claims.Issuer)
	assert.Equal(t, "https://test.any.com/api/v2/", claims.Audience)
}

func TestGetDefaultTestPublicKey(t *testing.T) {
	// Get public key multiple times
	key1, err := GetDefaultTestPublicKey()
	require.NoError(t, err)
	assert.NotNil(t, key1)

	key2, err := GetDefaultTestPublicKey()
	require.NoError(t, err)
	assert.NotNil(t, key2)

	// Should be the same key (pointer equality)
	assert.Equal(t, key1, key2)

	// Verify it matches the private key
	privateKey, err := getDefaultTestKey()
	require.NoError(t, err)
	assert.Equal(t, &privateKey.PublicKey, key1)
}

func TestIdentityTokenOptions(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	opts := IdentityTokenOptions("user@example.com", privateKey)

	assert.Equal(t, "user@example.com", opts.Email)
	assert.Equal(t, time.Hour, opts.ExpiresIn)
	assert.Equal(t, jwa.RS256, opts.SigningMethod)
	assert.Equal(t, privateKey, opts.SigningKey)
	assert.False(t, opts.IssuedAt.IsZero())
}

func TestHMACIdentityTokenOptions(t *testing.T) {
	secret := []byte("test-secret")

	opts := HMACIdentityTokenOptions("identity@example.com", secret)

	assert.Equal(t, "identity@example.com", opts.Email)
	assert.Equal(t, time.Hour, opts.ExpiresIn)
	assert.Equal(t, jwa.HS256, opts.SigningMethod)
	assert.Equal(t, secret, opts.SigningKey)
	assert.False(t, opts.IssuedAt.IsZero())
}

func TestDefaultGeneratorOptions(t *testing.T) {
	opts := DefaultGeneratorOptions()

	assert.Equal(t, time.Hour, opts.ExpiresIn)
	assert.Equal(t, jwa.RS256, opts.SigningMethod)
	assert.False(t, opts.IssuedAt.IsZero())
}

func TestTokenExpiration(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	t.Run("token expires correctly", func(t *testing.T) {
		opts := &GeneratorOptions{
			TokenType:     TokenTypeIdentity,
			Email:         "user@example.com",
			ExpiresIn:     100 * time.Millisecond, // Very short expiration
			IssuedAt:      time.Now(),
			SigningMethod: jwa.RS256,
			SigningKey:    privateKey,
		}

		tokenString, err := Generate(opts)
		require.NoError(t, err)

		// Wait for token to expire
		time.Sleep(200 * time.Millisecond)

		// Try to parse - should fail due to expiration
		ctx := context.Background()
		parseOpts := &ParseOptions{
			RequireExpiration: true,
			RequireSubject:    false,
		}
		_, err = ParseUnverified(ctx, tokenString, parseOpts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exp")
	})
}
