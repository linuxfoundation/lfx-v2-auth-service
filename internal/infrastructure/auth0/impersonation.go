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
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

// canImpersonateClaim is the custom claim an LFX V2 access token must carry,
// set to boolean true, for its bearer to be allowed to impersonate other users.
const canImpersonateClaim = "http://lfx.dev/claims/can_impersonate"

const (
	// jwksTTL bounds how long fetched signing keys are trusted before they are
	// refetched, so keys removed from the tenant JWKS stop verifying tokens.
	jwksTTL = time.Hour
	// jwksMinRefreshInterval limits JWKS fetches triggered by unknown key IDs or
	// failed fetches, so arbitrary tokens cannot drive request volume to Auth0.
	jwksMinRefreshInterval = time.Minute
)

// impersonationFlow performs Auth0 Custom Token Exchange for LFX impersonation.
type impersonationFlow struct {
	clientID   string
	privateKey *rsa.PrivateKey
	domain     string
	// lfxV2Audience is the LFX V2 API identifier used as both subject_token_type
	// and audience in the Custom Token Exchange request.
	lfxV2Audience string
	// issuer is the expected 'iss' of subject tokens (https://<domain>/).
	issuer string
	// subjectKeys supplies the tenant signing keys used to verify the
	// caller-supplied subject_token before the service lends its M2M client
	// assertion to the exchange.
	subjectKeys *subjectTokenKeys
	httpClient  *httpclient.Client
}

// subjectTokenKeys caches the tenant JWKS and selects verification keys by key
// ID, refetching when the cache is stale or a token names an unknown key so
// Auth0 signing key rotation does not require a restart.
type subjectTokenKeys struct {
	jwksURL    string
	httpClient *httpclient.Client
	now        func() time.Time

	mu          sync.Mutex
	set         jwk.Set
	fetchedAt   time.Time
	lastAttempt time.Time
}

func newSubjectTokenKeys(domain string, httpClient *httpclient.Client) *subjectTokenKeys {
	return &subjectTokenKeys{
		jwksURL:    "https://" + domain + "/.well-known/jwks.json",
		httpClient: httpClient,
		now:        time.Now,
	}
}

// prefetch loads the JWKS ahead of the first request. A failure is logged and
// retried on demand, so a transient outage at startup does not disable
// impersonation for the life of the process.
func (k *subjectTokenKeys) prefetch(ctx context.Context) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.attemptRefreshLocked(ctx, k.now())
}

// key returns the RSA signing key published under kid. It fails closed when no
// JWKS fetched within jwksTTL is available.
func (k *subjectTokenKeys) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	now := k.now()
	if k.isFreshLocked(now) {
		if key, ok := k.set.LookupKeyID(kid); ok {
			return rsaSigningKey(key)
		}
	}

	if k.lastAttempt.IsZero() || now.Sub(k.lastAttempt) >= jwksMinRefreshInterval {
		k.attemptRefreshLocked(ctx, now)
	}

	if !k.isFreshLocked(now) {
		return nil, errors.NewServiceUnavailable("impersonation signing keys are unavailable")
	}
	key, ok := k.set.LookupKeyID(kid)
	if !ok {
		return nil, errors.NewUnauthorized("invalid subject_token")
	}
	return rsaSigningKey(key)
}

func (k *subjectTokenKeys) isFreshLocked(now time.Time) bool {
	return k.set != nil && now.Sub(k.fetchedAt) < jwksTTL
}

// attemptRefreshLocked fetches the JWKS, keeping the cached set on failure.
func (k *subjectTokenKeys) attemptRefreshLocked(ctx context.Context, now time.Time) {
	k.lastAttempt = now

	resp, err := k.httpClient.Do(ctx, httpclient.Request{Method: http.MethodGet, URL: k.jwksURL})
	if err == nil && resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}
	var set jwk.Set
	if err == nil {
		set, err = jwk.Parse(resp.Body)
	}
	if err == nil && set.Len() == 0 {
		err = fmt.Errorf("JWKS contains no keys")
	}
	if err != nil {
		slog.WarnContext(ctx, "failed to fetch impersonation signing keys", "error", err)
		return
	}

	k.set = set
	k.fetchedAt = now
}

// rsaSigningKey returns key as an RSA public key if it is usable for RS256
// signature verification.
func rsaSigningKey(key jwk.Key) (*rsa.PublicKey, error) {
	if key.KeyType() != jwa.RSA {
		return nil, errors.NewUnauthorized("invalid subject_token")
	}
	if use := key.KeyUsage(); use != "" && use != string(jwk.ForSignature) {
		return nil, errors.NewUnauthorized("invalid subject_token")
	}
	if alg := key.Algorithm().String(); alg != "" && alg != jwa.RS256.String() {
		return nil, errors.NewUnauthorized("invalid subject_token")
	}
	var pub rsa.PublicKey
	if err := key.Raw(&pub); err != nil {
		return nil, errors.NewUnauthorized("invalid subject_token")
	}
	return &pub, nil
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

	subjectKeys := newSubjectTokenKeys(domain, httpClient)
	subjectKeys.prefetch(ctx)

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
		issuer:        "https://" + domain + "/",
		subjectKeys:   subjectKeys,
		httpClient:    httpClient,
	}, nil
}

// authorizeSubjectToken verifies that subjectToken is a genuine, unexpired LFX
// V2 access token issued by this tenant and that its bearer is permitted to
// impersonate. It fails closed if the verifier is not fully configured.
func (f *impersonationFlow) authorizeSubjectToken(ctx context.Context, subjectToken string) error {
	if f.subjectKeys == nil || strings.TrimSpace(f.issuer) == "" || strings.TrimSpace(f.lfxV2Audience) == "" {
		return errors.NewUnexpected("subject token verification is not configured")
	}

	// The token is forwarded to Auth0 as-is, so accept only the compact JWS form
	// the verifier sees unchanged (no Bearer prefix or JSON serialization).
	if !isCompactJWS(subjectToken) {
		return errors.NewUnauthorized("invalid subject_token")
	}

	msg, err := jws.Parse([]byte(subjectToken))
	if err != nil || len(msg.Signatures()) != 1 {
		return errors.NewUnauthorized("invalid subject_token")
	}
	kid := msg.Signatures()[0].ProtectedHeaders().KeyID()
	if kid == "" {
		return errors.NewUnauthorized("invalid subject_token")
	}

	signingKey, err := f.subjectKeys.key(ctx, kid)
	if err != nil {
		return err
	}

	// Only LFX V2 API tokens are valid subject tokens: the exchange declares
	// subject_token_type as the LFX V2 audience, so Management API tokens
	// (accepted elsewhere via audienceAllowList) are deliberately excluded.
	verifier := &JWTVerificationConfig{
		PublicKey:         signingKey,
		ExpectedIssuer:    f.issuer,
		ExpectedAudiences: []string{f.lfxV2Audience},
	}

	// JWTVerify logs the specific failure; the reply stays generic.
	claims, err := verifier.JWTVerify(ctx, subjectToken)
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
