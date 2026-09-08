// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
	jwtparser "github.com/linuxfoundation/lfx-v2-auth-service/pkg/jwt"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

// JWTVerificationConfig holds configuration for JWT signature verification
type JWTVerificationConfig struct {
	// PublicKey is the RSA public key for signature verification
	PublicKey *rsa.PublicKey
	// ExpectedIssuer is the expected JWT issuer (e.g., "https://your-domain.auth0.com/")
	ExpectedIssuer string
	// ExpectedAudience is the Auth0 Management API audience. Tokens carrying it
	// may be forwarded to the Management API on the user's behalf. Required for
	// scope-gated verification, which narrows to this audience and rejects the
	// request when it is empty.
	ExpectedAudience string
	// ExpectedAudiences is the full audience allow-list for JWT verification
	// (Management API plus, when configured, the LFX v2 API audience)
	ExpectedAudiences []string
	// JWKSURL is the URL to fetch JSON Web Key Set (optional, alternative to PublicKey)
	JWKSURL string
}

// JWTVerify verifies a JWT token with the specified required scope
// https://auth0.com/docs/secure/tokens/json-web-tokens/validate-json-web-tokens
func (j *JWTVerificationConfig) JWTVerify(ctx context.Context, token string, requiredScope ...string) (*jwtparser.Claims, error) {
	// JWT verification config is required
	if j == nil {
		return nil, errors.NewValidation("JWT verification configuration is required")
	}

	// Configure JWT parsing options with signature verification
	opts := &jwtparser.ParseOptions{
		RequireExpiration: true,
		AllowBearerPrefix: true,
		RequireSubject:    true,
		VerifySignature:   true,
		SigningKey:        j.PublicKey,
		ExpectedIssuer:    j.ExpectedIssuer,
		ExpectedAudience:  j.ExpectedAudience,
		ExpectedAudiences: j.ExpectedAudiences,
	}

	if len(requiredScope) > 0 {
		opts.RequiredScopes = requiredScope
		// Required scopes are Auth0 Management API scopes, which are only
		// meaningful on Management-API-audience tokens. Restricting scope-gated
		// verifications (the write-authorizing paths) to that audience keeps
		// broader-audience tokens — accepted for read-only lookups via
		// ExpectedAudiences — from ever authorizing a write, even if another
		// resource server were to define an identically named scope.
		//
		// Refuse to narrow to an absent audience: the parser skips audience
		// validation entirely when the allow-list is empty, so clearing
		// ExpectedAudiences without a Management audience to fall back on would
		// silently drop the only audience constraint on a write path.
		if strings.TrimSpace(j.ExpectedAudience) == "" {
			return nil, errors.NewValidation("Management API audience is required for scope-gated JWT verification")
		}
		opts.ExpectedAudiences = nil
	}

	// Parse and validate the JWT token with signature verification
	claims, err := jwtparser.ParseVerified(ctx, token, opts)
	if err != nil {
		slog.ErrorContext(ctx, "JWT signature verification failed",
			"error", err,
			"required_scope", requiredScope)
		return nil, err
	}

	slog.DebugContext(ctx, "JWT signature verification successful",
		"user_id", redaction.Redact(claims.Subject),
		"issuer", claims.Issuer,
		"audience", claims.Audience,
		"expires_at", claims.ExpiresAt,
		"scope", claims.Scope,
		"required_scope", requiredScope)

	return claims, nil
}

// NewJWTVerificationConfig creates a JWT verification configuration
func NewJWTVerificationConfig(ctx context.Context, domain string, httpClient *httpclient.Client) (*JWTVerificationConfig, error) {
	// Try to load from JWKS URL first (recommended for Auth0)
	jwksURL := fmt.Sprintf("https://%s/.well-known/jwks.json", domain)

	// Fetch JWKS from Auth0 using the existing httpclient
	apiRequest := httpclient.NewAPIRequest(
		httpClient,
		httpclient.WithMethod(http.MethodGet),
		httpclient.WithURL(jwksURL),
		httpclient.WithDescription("fetch Auth0 JWKS"),
	)

	// Parse JWKS and extract the first RSA key
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Use string `json:"use,omitempty"`
			Kid string `json:"kid,omitempty"`
			Alg string `json:"alg,omitempty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}

	statusCode, err := apiRequest.Call(ctx, &jwks)
	if err != nil {
		return nil, errors.NewUnexpected("failed to fetch JWKS", err)
	}

	if statusCode != http.StatusOK {
		return nil, errors.NewUnexpected(fmt.Sprintf("JWKS endpoint returned status %d", statusCode))
	}

	// Find the first RSA key suitable for signature verification
	for _, key := range jwks.Keys {
		if key.Kty == "RSA" && (key.Use == "sig" || key.Use == "") {
			// Convert JWK to RSA public key
			jwkData, err := json.Marshal(key)
			if err != nil {
				continue
			}

			publicKey, err := jwtparser.LoadRSAPublicKeyFromJWK(jwkData)
			if err != nil {
				return nil, errors.NewUnexpected("failed to load RSA public key from JWK", err)
			}

			expectedIssuer := fmt.Sprintf("https://%s/", domain)
			expectedAudience := fmt.Sprintf("https://%s/api/v2/", domain)
			if override := strings.TrimSpace(os.Getenv(constants.Auth0ManagementAudienceEnvKey)); override != "" {
				expectedAudience = override
			}

			expectedAudiences := audienceAllowList(expectedAudience)

			slog.InfoContext(ctx, "JWT signature verification enabled",
				"issuer", expectedIssuer,
				"audience", expectedAudience,
				"audiences", expectedAudiences,
				"key_id", key.Kid)

			return &JWTVerificationConfig{
				PublicKey:         publicKey,
				ExpectedIssuer:    expectedIssuer,
				ExpectedAudience:  expectedAudience,
				ExpectedAudiences: expectedAudiences,
				JWKSURL:           jwksURL,
			}, nil
		}
	}

	return nil, errors.NewUnexpected("no suitable RSA key found in JWKS for signature verification")
}

// audienceAllowList returns the audiences accepted for JWT verification.
//
// User-facing access tokens and impersonation tokens carry the LFX v2 API
// audience rather than the Management API audience; accept it for verification
// when configured. Such tokens are never forwarded to the Management API
// (see MetadataLookup), and scope-gated verification narrows back to
// managementAudience alone.
func audienceAllowList(managementAudience string) []string {
	audiences := []string{managementAudience}

	lfxAPIAudience := strings.TrimSpace(os.Getenv(constants.Auth0LFXv2APIAudienceEnvKey))
	if lfxAPIAudience != "" && lfxAPIAudience != managementAudience {
		audiences = append(audiences, lfxAPIAudience)
	}

	return audiences
}
