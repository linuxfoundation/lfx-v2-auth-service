// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
)

// impersonationFlow performs Auth0 Custom Token Exchange for LFX impersonation.
type impersonationFlow struct {
	clientID   string
	privateKey *rsa.PrivateKey
	domain     string
	// lfxV2Audience is the LFX V2 API identifier used as both subject_token_type
	// and audience in the Custom Token Exchange request.
	lfxV2Audience string
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
func NewImpersonationFlow(ctx context.Context, domain string) (*impersonationFlow, error) {
	clientID := os.Getenv(constants.Auth0M2MClientIDEnvKey)
	if clientID == "" {
		return nil, errors.NewUnexpected(constants.Auth0M2MClientIDEnvKey + " is required")
	}

	lfxV2Audience := os.Getenv(constants.Auth0LFXv2APIAudienceEnvKey)
	if lfxV2Audience == "" {
		return nil, errors.NewUnexpected(constants.Auth0LFXv2APIAudienceEnvKey + " is required")
	}

	privateKeyB64 := os.Getenv(constants.Auth0M2MPrivateBase64KeyEnvKey)
	if privateKeyB64 == "" {
		return nil, errors.NewUnexpected(constants.Auth0M2MPrivateBase64KeyEnvKey + " is required")
	}

	decoded, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return nil, errors.NewUnexpected("failed to base64-decode "+constants.Auth0M2MPrivateBase64KeyEnvKey, err)
	}

	rsaKey, err := parseRSAPrivateKey(decoded)
	if err != nil {
		return nil, errors.NewUnexpected("failed to parse private key", err)
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
	}, nil
}

// ImpersonateUser exchanges subjectToken (a valid LFX V2 access token belonging
// to an authorized impersonator) for a new LFX V2 access token representing
// targetUser (email or username).
func (f *impersonationFlow) ImpersonateUser(ctx context.Context, subjectToken, targetUser string) (string, error) {
	slog.DebugContext(ctx, "performing impersonation token exchange",
		"target_user", targetUser,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read token exchange response: %w", err)
	}

	var cteResp cteResponse
	if err := json.Unmarshal(body, &cteResp); err != nil {
		return "", fmt.Errorf("failed to parse token exchange response: %w", err)
	}

	if cteResp.Error != "" {
		slog.WarnContext(ctx, "impersonation token exchange denied",
			"error", cteResp.Error,
			"error_description", cteResp.ErrorDesc,
			"target_user", targetUser,
		)
		return "", fmt.Errorf("%s: %s", cteResp.Error, cteResp.ErrorDesc)
	}

	if cteResp.AccessToken == "" {
		return "", fmt.Errorf("token exchange returned empty access token (status %d)", resp.StatusCode)
	}

	slog.DebugContext(ctx, "impersonation token exchange succeeded", "target_user", targetUser)
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
