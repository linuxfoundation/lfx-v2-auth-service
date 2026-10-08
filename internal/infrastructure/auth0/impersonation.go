// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

// canImpersonateClaim is the custom claim an LFX V2 access token must carry,
// set to boolean true, for its bearer to be allowed to impersonate other users.
const canImpersonateClaim = "http://lfx.dev/claims/can_impersonate"

// impersonationFlow performs Auth0 Custom Token Exchange for LFX impersonation.
type impersonationFlow struct {
	clientID   string
	privateKey *rsa.PrivateKey
	domain     string
	// lfxV2Audience is the LFX V2 API identifier used as both subject_token_type
	// and audience in the Custom Token Exchange request.
	lfxV2Audience string
	// subjectTokenVerifier verifies the caller-supplied subject_token against the
	// tenant JWKS, issuer and the LFX V2 API audience before the service lends
	// its M2M client assertion to the exchange.
	subjectTokenVerifier *JWTVerificationConfig
	httpClient           *httpclient.Client
}

type cteResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// NewImpersonationFlow creates an impersonation flow loaded from environment variables.
// It reuses AUTH0_M2M_CLIENT_ID and AUTH0_M2M_PRIVATE_BASE64_KEY, plus the new
// AUTH0_LFX_V2_API_AUDIENCE for the CTE subject_token_type / audience.
func NewImpersonationFlow(ctx context.Context, domain string) (port.Impersonator, error) {
	clientID := os.Getenv(constants.Auth0M2MClientIDEnvKey)
	if clientID == "" {
		return nil, errors.NewUnexpected(constants.Auth0M2MClientIDEnvKey + " is required")
	}

	lfxV2Audience := os.Getenv(constants.Auth0LFXv2APIAudienceEnvKey)
	if lfxV2Audience == "" {
		return nil, errors.NewUnexpected(constants.Auth0LFXv2APIAudienceEnvKey + " is required")
	}

	privateKeyRaw := os.Getenv(constants.Auth0M2MPrivateBase64KeyEnvKey)
	if privateKeyRaw == "" {
		return nil, errors.NewUnexpected(constants.Auth0M2MPrivateBase64KeyEnvKey + " is required")
	}

	privateKeyPEM, err := decodePrivateKey(privateKeyRaw)
	if err != nil {
		return nil, err
	}

	rsaKey, err := parseRSAPrivateKey([]byte(privateKeyPEM))
	if err != nil {
		return nil, errors.NewUnexpected("failed to parse private key", err)
	}

	httpClient := httpclient.NewClient(httpclient.Config{Timeout: 10 * time.Second})

	jwtConfig, err := NewJWTVerificationConfig(ctx, domain, httpClient)
	if err != nil {
		return nil, errors.NewUnexpected("failed to create subject token verification config", err)
	}

	slog.DebugContext(ctx, "impersonation flow initialized",
		"client_id", clientID,
		"domain", domain,
		"lfx_v2_audience", lfxV2Audience,
	)

	return &impersonationFlow{
		clientID:      clientID,
		privateKey:    rsaKey,
		domain:        domain,
		lfxV2Audience: lfxV2Audience,
		// Only LFX V2 API tokens are valid subject tokens: the exchange declares
		// subject_token_type as the LFX V2 audience, so Management API tokens
		// (accepted elsewhere via audienceAllowList) are deliberately excluded.
		subjectTokenVerifier: &JWTVerificationConfig{
			PublicKey:         jwtConfig.PublicKey,
			ExpectedIssuer:    jwtConfig.ExpectedIssuer,
			ExpectedAudiences: []string{lfxV2Audience},
			JWKSURL:           jwtConfig.JWKSURL,
		},
		httpClient: httpClient,
	}, nil
}

// authorizeSubjectToken verifies that subjectToken is a genuine, unexpired LFX
// V2 access token issued by this tenant and that its bearer is permitted to
// impersonate. It fails closed if the verifier is not fully configured.
func (f *impersonationFlow) authorizeSubjectToken(ctx context.Context, subjectToken string) error {
	v := f.subjectTokenVerifier
	if v == nil || v.PublicKey == nil || strings.TrimSpace(v.ExpectedIssuer) == "" ||
		len(v.ExpectedAudiences) == 0 || slices.Contains(v.ExpectedAudiences, "") {
		return errors.NewUnexpected("subject token verification is not configured")
	}

	// The token is forwarded to Auth0 as-is, so accept only the compact JWS form
	// the verifier sees unchanged (no Bearer prefix or JSON serialization).
	if !isCompactJWS(subjectToken) {
		return errors.NewUnauthorized("invalid subject_token")
	}

	// JWTVerify logs the specific failure; the reply stays generic.
	claims, err := v.JWTVerify(ctx, subjectToken)
	if err != nil {
		return errors.NewUnauthorized("invalid subject_token")
	}

	canImpersonate, _ := claims.GetClaim(canImpersonateClaim)
	if allowed, ok := canImpersonate.(bool); !ok || !allowed {
		slog.WarnContext(ctx, "impersonation denied: subject token lacks impersonation permission",
			"sub", redaction.Redact(claims.Subject),
		)
		return errors.NewForbidden("subject_token is not authorized to impersonate")
	}

	return nil
}

// isCompactJWS reports whether token is three base64url segments joined by dots.
func isCompactJWS(token string) bool {
	if strings.Count(token, ".") != 2 {
		return false
	}
	for _, r := range token {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

// ImpersonateUser exchanges subjectToken (a valid LFX V2 access token belonging
// to an authorized impersonator) for a new LFX V2 access token representing
// targetUser (email or username). The subject token is verified and its
// impersonation permission checked before the service's client credentials are
// used; an unauthorized request never reaches the token endpoint.
func (f *impersonationFlow) ImpersonateUser(ctx context.Context, subjectToken, targetUser string) (string, error) {
	if err := f.authorizeSubjectToken(ctx, subjectToken); err != nil {
		return "", err
	}

	slog.DebugContext(ctx, "performing impersonation token exchange",
		"target_user", redaction.RedactEmail(targetUser),
	)

	tokenEndpoint := "https://" + f.domain + "/oauth/token"
	assertionAudience := "https://" + f.domain + "/"

	assertion, err := f.buildClientAssertion(assertionAudience)
	if err != nil {
		return "", fmt.Errorf("failed to build client assertion: %w", err)
	}

	form := url.Values{
		"grant_type":            {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":             {f.clientID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
		"subject_token":         {subjectToken},
		"subject_token_type":    {f.lfxV2Audience},
		"audience":              {f.lfxV2Audience},
		"target_user":           {targetUser},
	}

	httpResp, err := f.httpClient.Do(ctx, httpclient.Request{
		Method:  http.MethodPost,
		URL:     tokenEndpoint,
		Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		Body:    strings.NewReader(form.Encode()),
	})
	if err != nil && httpResp == nil {
		return "", fmt.Errorf("token exchange request failed: %w", err)
	}

	var cteResp cteResponse
	if err := json.Unmarshal(httpResp.Body, &cteResp); err != nil {
		return "", fmt.Errorf("failed to parse token exchange response: %w", err)
	}

	if cteResp.Error != "" {
		slog.WarnContext(ctx, "impersonation token exchange denied",
			"error", cteResp.Error,
			"error_description", cteResp.ErrorDesc,
			"target_user", redaction.RedactEmail(targetUser),
		)
		return "", fmt.Errorf("%s: %s", cteResp.Error, cteResp.ErrorDesc)
	}

	if cteResp.AccessToken == "" {
		return "", fmt.Errorf("token exchange returned empty access token (status %d)", httpResp.StatusCode)
	}

	slog.DebugContext(ctx, "impersonation token exchange succeeded", "target_user", redaction.RedactEmail(targetUser))
	return cteResp.AccessToken, nil
}

// buildClientAssertion creates a signed RS256 JWT for private key JWT auth (RFC 7523).
func (f *impersonationFlow) buildClientAssertion(audience string) (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    f.clientID,
		Subject:   f.clientID,
		Audience:  jwt.ClaimStrings{audience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(60 * time.Second)),
		ID:        uuid.New().String(),
	}
	return jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(f.privateKey)
}

// parseRSAPrivateKey parses a PEM-encoded RSA private key (PKCS#8 or PKCS#1).
func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	// Try PKCS#8 first (most common for Auth0 private keys).
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is not RSA")
		}
		return rsaKey, nil
	}

	// Fall back to PKCS#1.
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
