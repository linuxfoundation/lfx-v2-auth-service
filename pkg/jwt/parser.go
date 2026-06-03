// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package jwt

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Claims represents the parsed JWT claims with commonly used fields
type Claims struct {
	Subject   string         `json:"sub"`
	Email     string         `json:"email,omitempty"`
	ExpiresAt *time.Time     `json:"exp,omitempty"`
	IssuedAt  *time.Time     `json:"iat,omitempty"`
	NotBefore *time.Time     `json:"nbf,omitempty"`
	Issuer    string         `json:"iss,omitempty"`
	Audience  string         `json:"aud,omitempty"`
	Scope     string         `json:"scope,omitempty"`
	Raw       map[string]any `json:"-"` // Raw claims for additional fields
}

// ParseOptions configures JWT parsing behavior
type ParseOptions struct {
	// RequireExpiration validates that the token has an 'exp' claim and is not expired
	RequireExpiration bool
	// RequiredScopes validates that the token contains all specified scopes
	RequiredScopes []string
	// AllowBearerPrefix allows tokens with "Bearer " prefix
	AllowBearerPrefix bool
	// RequireSubject validates that the token has a non-empty 'sub' claim
	RequireSubject bool
	// VerifySignature enables signature verification
	VerifySignature bool
	// SigningKey is the key used for signature verification (RSA public key)
	SigningKey *rsa.PublicKey
	// ExpectedIssuer validates the 'iss' claim matches this value
	ExpectedIssuer string
	// ExpectedAudience validates the 'aud' claim matches this value
	ExpectedAudience string
}

// DefaultParseOptions returns sensible default options
func DefaultParseOptions() *ParseOptions {
	return &ParseOptions{
		RequireExpiration: true,
		AllowBearerPrefix: true,
		RequireSubject:    true,
	}
}

// ParseUnverified parses a JWT token without signature verification and returns the claims.
// This is useful for extracting information from tokens when signature verification
// is handled elsewhere or not required (e.g., in mock/test environments).
func ParseUnverified(ctx context.Context, tokenString string, opts *ParseOptions) (*Claims, error) {
	if opts == nil {
		opts = DefaultParseOptions()
	}

	if strings.TrimSpace(tokenString) == "" {
		return nil, errors.NewValidation("token is required")
	}

	// Remove optional Bearer prefix (case-insensitive) and trim
	cleanToken := strings.TrimSpace(tokenString)
	if opts.AllowBearerPrefix {
		parts := strings.Fields(tokenString)
		if len(parts) > 1 && strings.EqualFold(parts[0], "Bearer") {
			cleanToken = strings.Join(parts[1:], " ")
		}
	}

	// Parse the token without verification using jwx
	token, err := jwt.Parse([]byte(cleanToken), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, errors.NewValidation("failed to parse JWT token: %w", err)
	}

	claims, err := extractClaimsFromJWT(token)
	if err != nil {
		return nil, err
	}

	// Validate expiration if required
	if opts.RequireExpiration {
		if err := validateExpiration(claims); err != nil {
			return nil, err
		}
	}

	// Validate subject if required
	if opts.RequireSubject {
		if err := validateSubject(claims); err != nil {
			return nil, err
		}
	}

	// Validate required scopes if specified
	if len(opts.RequiredScopes) > 0 {
		if err := validateScopes(claims, opts.RequiredScopes); err != nil {
			return nil, err
		}
	}

	slog.DebugContext(ctx, "JWT parsed successfully",
		"sub", claims.Subject,
		"expires_at", claims.ExpiresAt,
		"scope", claims.Scope)

	return claims, nil
}

// ParseVerified parses a JWT token with signature verification and returns the claims.
// This function validates the token signature using the provided public key.
func ParseVerified(ctx context.Context, tokenString string, opts *ParseOptions) (*Claims, error) {
	if opts == nil {
		opts = DefaultParseOptions()
	}

	if strings.TrimSpace(tokenString) == "" {
		return nil, errors.NewValidation("token is required")
	}

	// Remove optional Bearer prefix (case-insensitive) and trim
	cleanToken := strings.TrimSpace(tokenString)
	if opts.AllowBearerPrefix {
		parts := strings.Fields(tokenString)
		if len(parts) > 1 && strings.EqualFold(parts[0], "Bearer") {
			cleanToken = strings.Join(parts[1:], " ")
		}
	}

	// Parse the token with jwx
	token, errParse := jwt.Parse([]byte(cleanToken), jwt.WithKey(jwa.RS256, opts.SigningKey))
	if errParse != nil {
		return nil, errParse
	}

	// Extract claims
	claims, err := extractClaimsFromJWT(token)
	if err != nil {
		return nil, err
	}

	// Validate issuer if specified
	if opts.ExpectedIssuer != "" {
		if err := validateIssuer(claims, opts.ExpectedIssuer); err != nil {
			return nil, err
		}
	}

	// Validate audience if specified
	if opts.ExpectedAudience != "" {
		if err := validateAudience(claims, opts.ExpectedAudience); err != nil {
			return nil, err
		}
	}

	// Validate expiration if required
	if opts.RequireExpiration {
		if err := validateExpiration(claims); err != nil {
			return nil, err
		}
	}

	// Validate subject if required
	if opts.RequireSubject {
		if err := validateSubject(claims); err != nil {
			return nil, err
		}
	}

	// Validate required scopes if specified
	if len(opts.RequiredScopes) > 0 {
		if err := validateScopes(claims, opts.RequiredScopes); err != nil {
			return nil, err
		}
	}

	slog.DebugContext(ctx, "JWT parsed and verified successfully",
		"sub", claims.Subject,
		"issuer", claims.Issuer,
		"audience", claims.Audience,
		"expires_at", claims.ExpiresAt,
		"scope", claims.Scope,
	)

	return claims, nil
}

// extractClaimsFromJWT extracts claims from a jwx JWT token
func extractClaimsFromJWT(token jwt.Token) (*Claims, error) {
	claims := &Claims{
		Raw: make(map[string]any),
	}

	// Extract standard claims using jwx methods
	claims.Subject = token.Subject()
	claims.Issuer = token.Issuer()

	// Handle audience (jwx returns []string)
	audience := token.Audience()
	if len(audience) > 0 {
		claims.Audience = audience[0] // Take the first audience
	}

	// Extract email from private claims
	if email, ok := token.Get("email"); ok {
		if emailStr, ok := email.(string); ok {
			claims.Email = emailStr
		}
	}

	// Extract scope from private claims
	if scope, ok := token.Get("scope"); ok {
		if scopeStr, ok := scope.(string); ok {
			claims.Scope = scopeStr
		}
	}

	// Extract time-based claims
	exp := token.Expiration()
	if !exp.IsZero() {
		claims.ExpiresAt = &exp
	}

	iat := token.IssuedAt()
	if !iat.IsZero() {
		claims.IssuedAt = &iat
	}

	nbf := token.NotBefore()
	if !nbf.IsZero() {
		claims.NotBefore = &nbf
	}

	// Store all raw claims
	maps.Copy(claims.Raw, token.PrivateClaims())

	return claims, nil
}

// ExtractSubject is a convenience function that extracts only the 'sub' claim from a JWT token
func ExtractSubject(ctx context.Context, tokenString string) (string, error) {
	opts := &ParseOptions{
		RequireExpiration: false,
		AllowBearerPrefix: true,
		RequireSubject:    false, // We validate manually below
	}

	claims, err := ParseUnverified(ctx, tokenString, opts)
	if err != nil {
		return "", err
	}

	if strings.TrimSpace(claims.Subject) == "" {
		return "", errors.NewValidation("missing or invalid 'sub' claim in token")
	}

	slog.DebugContext(ctx, "extracted subject from JWT", "sub", claims.Subject)
	return claims.Subject, nil
}

// ExtractEmail is a convenience function that extracts only the 'email' claim from a JWT token
func ExtractEmail(ctx context.Context, tokenString string) (string, error) {
	opts := &ParseOptions{
		RequireExpiration: false,
		AllowBearerPrefix: true,
		RequireSubject:    false,
	}

	claims, err := ParseUnverified(ctx, tokenString, opts)
	if err != nil {
		return "", err
	}

	if strings.TrimSpace(claims.Email) == "" {
		return "", errors.NewValidation("missing or invalid 'email' claim in token")
	}

	slog.DebugContext(ctx, "extracted email from JWT", "email", claims.Email)
	return claims.Email, nil
}

// validateSubject checks if the token has a valid subject
func validateSubject(claims *Claims) error {
	if strings.TrimSpace(claims.Subject) == "" {
		return errors.NewValidation("missing or invalid 'sub' claim in token")
	}
	return nil
}

// validateExpiration checks if the token is expired
func validateExpiration(claims *Claims) error {
	if claims.ExpiresAt == nil {
		return errors.NewValidation("missing 'exp' claim in token")
	}

	if time.Now().After(*claims.ExpiresAt) {
		return errors.NewValidation(fmt.Sprintf("token has expired at %v", *claims.ExpiresAt))
	}

	return nil
}

// validateScopes checks if the token contains all required scopes
func validateScopes(claims *Claims, requiredScopes []string) error {
	if claims.Scope == "" {
		return errors.NewValidation("missing 'scope' claim in token")
	}

	tokenScopes := strings.Fields(claims.Scope) // Split by whitespace

	for _, requiredScope := range requiredScopes {
		if !slices.Contains(tokenScopes, requiredScope) {
			return errors.NewValidation("missing required scope")
		}
	}

	return nil
}

// validateIssuer checks if the token issuer matches the expected value
func validateIssuer(claims *Claims, expectedIssuer string) error {
	if claims.Issuer == "" {
		return errors.NewValidation("missing 'iss' claim in token")
	}

	if claims.Issuer != expectedIssuer {
		return errors.NewValidation(fmt.Sprintf("invalid issuer '%s', expected '%s'", claims.Issuer, expectedIssuer))
	}

	return nil
}

// validateAudience checks if the token audience matches the expected value
func validateAudience(claims *Claims, expectedAudience string) error {
	if claims.Audience == "" {
		return errors.NewValidation("missing 'aud' claim in token")
	}

	if claims.Audience != expectedAudience {
		return errors.NewValidation("invalid audience")
	}

	return nil
}

// GetClaim is a helper to extract a specific claim from the raw claims
func (c *Claims) GetClaim(key string) (interface{}, bool) {
	if c.Raw == nil {
		return nil, false
	}
	value, exists := c.Raw[key]
	return value, exists
}

// GetStringClaim is a helper to extract a string claim
func (c *Claims) GetStringClaim(key string) (string, bool) {
	value, exists := c.GetClaim(key)
	if !exists {
		return "", false
	}
	str, ok := value.(string)
	return str, ok
}

// HasScope checks if the token has a specific scope
func (c *Claims) HasScope(scope string) bool {
	if c.Scope == "" {
		return false
	}
	scopes := strings.Fields(c.Scope)
	return slices.Contains(scopes, scope)
}

// LooksLikeJWT checks if a string looks like a JWT token by attempting to parse it
// without verification. Returns the cleaned token and true if the string can be parsed as a valid JWT structure.
func LooksLikeJWT(tokenStr string) (string, bool) {
	if strings.TrimSpace(tokenStr) == "" {
		return "", false
	}

	// Remove optional Bearer prefix (case-insensitive) and trim
	cleanToken := strings.TrimSpace(tokenStr)
	parts := strings.Fields(tokenStr)
	if len(parts) > 1 && strings.EqualFold(parts[0], "Bearer") {
		cleanToken = strings.Join(parts[1:], " ")
	}

	// Try to parse the token without verification
	_, err := jwt.Parse([]byte(cleanToken), jwt.WithVerify(false))
	if err == jwt.ErrInvalidJWT() {
		return cleanToken, false
	}
	return cleanToken, true
}

// LoadRSAPublicKeyFromJWK loads an RSA public key from JWK (JSON Web Key) format
func LoadRSAPublicKeyFromJWK(jwkData []byte) (*rsa.PublicKey, error) {
	// Parse JWK using jwx
	key, err := jwk.ParseKey(jwkData)
	if err != nil {
		return nil, errors.NewValidation("failed to parse JWK: %w", err)
	}

	// Get the raw RSA public key
	var rsaKey rsa.PublicKey
	if err := key.Raw(&rsaKey); err != nil {
		return nil, errors.NewValidation("failed to get RSA public key from JWK: %w", err)
	}

	return &rsaKey, nil
}
