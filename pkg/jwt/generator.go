// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
)

var (
	// defaultTestKey is a singleton RSA key pair for testing purposes only
	defaultTestKey     *rsa.PrivateKey
	defaultTestKeyOnce sync.Once
	defaultTestKeyErr  error

	// defaultHMACSecret is a default HMAC secret for testing purposes only
	defaultHMACSecret = []byte("test-hmac-secret-key-for-development-only-do-not-use-in-production")
)

// getDefaultTestKey returns a singleton RSA private key for testing purposes.
// WARNING: This key is generated once and reused. DO NOT use in production!
func getDefaultTestKey() (*rsa.PrivateKey, error) {
	defaultTestKeyOnce.Do(func() {
		defaultTestKey, defaultTestKeyErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	return defaultTestKey, defaultTestKeyErr
}

// GetDefaultTestPublicKey returns the public key corresponding to the default test private key.
// This is useful for verifying tokens generated with the default test key.
// WARNING: For testing purposes only!
func GetDefaultTestPublicKey() (*rsa.PublicKey, error) {
	key, err := getDefaultTestKey()
	if err != nil {
		return nil, err
	}
	return &key.PublicKey, nil
}

// TokenType represents the type of token being generated
type TokenType string

const (
	// TokenTypeAccess represents an access token with a subject claim
	TokenTypeAccess TokenType = "access"
	// TokenTypeIdentity represents an identity token with an email claim
	TokenTypeIdentity TokenType = "identity"
)

// GeneratorOptions configures JWT token generation
type GeneratorOptions struct {
	// TokenType specifies the type of token (access or identity)
	TokenType TokenType
	// Subject is the 'sub' claim (required for access tokens)
	Subject string
	// Email is the 'email' claim (required for identity tokens)
	Email string
	// Scope is the 'scope' claim (space-separated permissions, for access tokens)
	Scope string
	// Issuer is the 'iss' claim
	Issuer string
	// Audience is the 'aud' claim
	Audience string
	// ExpiresIn is the duration until the token expires (defaults to 1 hour)
	ExpiresIn time.Duration
	// IssuedAt is the 'iat' claim (defaults to now)
	IssuedAt time.Time
	// NotBefore is the 'nbf' claim (optional)
	NotBefore *time.Time
	// CustomClaims allows adding additional custom claims
	CustomClaims map[string]any
	// SigningMethod is the algorithm to use for signing (RS256, HS256, etc.)
	SigningMethod jwa.SignatureAlgorithm
	// SigningKey is the key used to sign the token (RSA private key or HMAC secret)
	SigningKey any
}

// DefaultGeneratorOptions returns sensible defaults for token generation
func DefaultGeneratorOptions() *GeneratorOptions {
	return &GeneratorOptions{
		ExpiresIn:     time.Hour,
		IssuedAt:      time.Now(),
		SigningMethod: jwa.RS256,
	}
}

// AccessTokenOptions creates options for generating an access token
func AccessTokenOptions(subject string, signingKey *rsa.PrivateKey) *GeneratorOptions {
	return &GeneratorOptions{
		TokenType:     TokenTypeAccess,
		Subject:       subject,
		ExpiresIn:     time.Hour,
		IssuedAt:      time.Now(),
		SigningMethod: jwa.RS256,
		SigningKey:    signingKey,
	}
}

// IdentityTokenOptions creates options for generating an identity token
func IdentityTokenOptions(email string, signingKey *rsa.PrivateKey) *GeneratorOptions {
	return &GeneratorOptions{
		TokenType:     TokenTypeIdentity,
		Email:         email,
		ExpiresIn:     time.Hour,
		IssuedAt:      time.Now(),
		SigningMethod: jwa.RS256,
		SigningKey:    signingKey,
	}
}

// HMACIdentityTokenOptions creates options for generating an HMAC-signed identity token (useful for testing)
func HMACIdentityTokenOptions(email string, secret []byte) *GeneratorOptions {
	return &GeneratorOptions{
		TokenType:     TokenTypeIdentity,
		Email:         email,
		ExpiresIn:     time.Hour,
		IssuedAt:      time.Now(),
		SigningMethod: jwa.HS256,
		SigningKey:    secret,
	}
}

// Generate creates and signs a JWT token based on the provided options
func Generate(opts *GeneratorOptions) (string, error) {
	if opts == nil {
		return "", errors.NewValidation("generator options are required")
	}

	if opts.SigningKey == nil {
		return "", errors.NewValidation("signing key is required")
	}

	// Validate token type specific requirements
	switch opts.TokenType {
	case TokenTypeAccess:
		if opts.Subject == "" {
			return "", errors.NewValidation("subject is required for access tokens")
		}
	case TokenTypeIdentity:
		if opts.Email == "" {
			return "", errors.NewValidation("email is required for identity tokens")
		}
	default:
		return "", errors.NewValidation("token type is required")
	}

	// Create a new JWT builder
	builder := jwt.NewBuilder()

	// Set issued at time
	if opts.IssuedAt.IsZero() {
		opts.IssuedAt = time.Now()
	}
	builder = builder.IssuedAt(opts.IssuedAt)

	// Set expiration
	if opts.ExpiresIn > 0 {
		builder = builder.Expiration(opts.IssuedAt.Add(opts.ExpiresIn))
	}

	// Set not before if specified
	if opts.NotBefore != nil {
		builder = builder.NotBefore(*opts.NotBefore)
	}

	// Set issuer if specified
	if opts.Issuer != "" {
		builder = builder.Issuer(opts.Issuer)
	}

	// Set audience if specified
	if opts.Audience != "" {
		builder = builder.Audience([]string{opts.Audience})
	}

	// Set token type specific claims
	switch opts.TokenType {
	case TokenTypeAccess:
		builder = builder.Subject(opts.Subject)
		if opts.Scope != "" {
			builder = builder.Claim("scope", opts.Scope)
		}

	case TokenTypeIdentity:
		builder = builder.Claim("email", opts.Email)
		// Identity tokens can also have a subject
		if opts.Subject != "" {
			builder = builder.Subject(opts.Subject)
		}
	}

	// Add any custom claims
	for key, value := range opts.CustomClaims {
		builder = builder.Claim(key, value)
	}

	// Build the token
	token, err := builder.Build()
	if err != nil {
		return "", errors.NewUnexpected("failed to build JWT token", err)
	}

	// Sign the token
	signed, err := jwt.Sign(token, jwt.WithKey(opts.SigningMethod, opts.SigningKey))
	if err != nil {
		return "", errors.NewUnexpected("failed to sign JWT token", err)
	}

	return string(signed), nil
}

// GenerateAccessToken is a convenience function to generate an access token with a subject
func GenerateAccessToken(subject, issuer, audience, scope string, expiresIn time.Duration, signingKey *rsa.PrivateKey) (string, error) {
	opts := &GeneratorOptions{
		TokenType:     TokenTypeAccess,
		Subject:       subject,
		Issuer:        issuer,
		Audience:      audience,
		Scope:         scope,
		ExpiresIn:     expiresIn,
		IssuedAt:      time.Now(),
		SigningMethod: jwa.RS256,
		SigningKey:    signingKey,
	}
	return Generate(opts)
}

// GenerateIdentityToken is a convenience function to generate an identity token with an email
func GenerateIdentityToken(email, issuer, audience string, expiresIn time.Duration, signingKey *rsa.PrivateKey) (string, error) {
	opts := &GeneratorOptions{
		TokenType:     TokenTypeIdentity,
		Email:         email,
		Issuer:        issuer,
		Audience:      audience,
		ExpiresIn:     expiresIn,
		IssuedAt:      time.Now(),
		SigningMethod: jwa.RS256,
		SigningKey:    signingKey,
	}
	return Generate(opts)
}

// GenerateHMACAccessToken is a convenience function to generate an HMAC-signed access token (useful for testing)
func GenerateHMACAccessToken(subject, issuer, audience, scope string, expiresIn time.Duration, secret []byte) (string, error) {
	opts := &GeneratorOptions{
		TokenType:     TokenTypeAccess,
		Subject:       subject,
		Issuer:        issuer,
		Audience:      audience,
		Scope:         scope,
		ExpiresIn:     expiresIn,
		IssuedAt:      time.Now(),
		SigningMethod: jwa.HS256,
		SigningKey:    secret,
	}
	return Generate(opts)
}

// GenerateHMACIdentityToken is a convenience function to generate an HMAC-signed identity token (useful for testing)
func GenerateHMACIdentityToken(email, issuer, audience string, expiresIn time.Duration, secret []byte) (string, error) {
	opts := &GeneratorOptions{
		TokenType:     TokenTypeIdentity,
		Email:         email,
		Issuer:        issuer,
		Audience:      audience,
		ExpiresIn:     expiresIn,
		IssuedAt:      time.Now(),
		SigningMethod: jwa.HS256,
		SigningKey:    secret,
	}
	return Generate(opts)
}

// GenerateTestAccessToken generates an access token using the default test signing key.
// This is a convenience method for testing that doesn't require providing a signing key.
// WARNING: For testing purposes only!
func GenerateTestAccessToken(subject, issuer, audience, scope string, expiresIn time.Duration) (string, error) {
	key, err := getDefaultTestKey()
	if err != nil {
		return "", errors.NewUnexpected("failed to get default test key", err)
	}
	return GenerateAccessToken(subject, issuer, audience, scope, expiresIn, key)
}

// GenerateTestIdentityToken generates an identity token using the default test signing key.
// This is a convenience method for testing that doesn't require providing a signing key.
// WARNING: For testing purposes only!
func GenerateTestIdentityToken(email, issuer, audience string, expiresIn time.Duration) (string, error) {
	key, err := getDefaultTestKey()
	if err != nil {
		return "", errors.NewUnexpected("failed to get default test key", err)
	}
	return GenerateIdentityToken(email, issuer, audience, expiresIn, key)
}

// GenerateTestHMACAccessToken generates an HMAC-signed access token using the default HMAC secret.
// This is a convenience method for testing that doesn't require providing a secret.
// WARNING: For testing purposes only!
func GenerateTestHMACAccessToken(subject, issuer, audience, scope string, expiresIn time.Duration) (string, error) {
	return GenerateHMACAccessToken(subject, issuer, audience, scope, expiresIn, defaultHMACSecret)
}

// GenerateTestHMACIdentityToken generates an HMAC-signed identity token using the default HMAC secret.
// This is a convenience method for testing that doesn't require providing a secret.
// WARNING: For testing purposes only!
func GenerateTestHMACIdentityToken(email, issuer, audience string, expiresIn time.Duration) (string, error) {
	return GenerateHMACIdentityToken(email, issuer, audience, expiresIn, defaultHMACSecret)
}

// GenerateSimpleTestAccessToken generates an access token with minimal configuration for quick testing.
// Uses default test issuer, audience, and scope. Only requires a subject and expiration.
// WARNING: For testing purposes only!
func GenerateSimpleTestAccessToken(subject string, expiresIn time.Duration) (string, error) {
	return GenerateTestAccessToken(
		subject,
		"https://test.any.com/",
		"https://test.any.com/api/v2/",
		"read:current_user",
		expiresIn,
	)
}

// GenerateSimpleTestIdentityToken generates an identity token with minimal configuration for quick testing.
// Uses default test issuer and audience. Only requires an email and expiration.
// WARNING: For testing purposes only!
func GenerateSimpleTestIdentityToken(email string, expiresIn time.Duration) (string, error) {
	return GenerateTestIdentityToken(
		email,
		"https://test.any.com/",
		"https://test.any.com/api/v2/",
		expiresIn,
	)
}

// GenerateSimpleTestIdentityTokenWithSubject generates an identity token with a custom subject claim.
// Uses default test issuer and audience. Requires an email, subject, and expiration.
// WARNING: For testing purposes only!
func GenerateSimpleTestIdentityTokenWithSubject(email, subject string, expiresIn time.Duration) (string, error) {
	key, err := getDefaultTestKey()
	if err != nil {
		return "", errors.NewUnexpected("failed to get default test key", err)
	}

	opts := &GeneratorOptions{
		TokenType:     TokenTypeIdentity,
		Email:         email,
		Subject:       subject,
		Issuer:        "https://test.any.com/",
		Audience:      "https://test.any.com/api/v2/",
		ExpiresIn:     expiresIn,
		IssuedAt:      time.Now(),
		SigningMethod: jwa.RS256,
		SigningKey:    key,
	}
	return Generate(opts)
}
