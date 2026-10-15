// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	stderrors "errors"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
)

// registerTestTenantKeys installs a shared signing key cache for domain backed
// by fa and clock, prefetched as the production constructors do.
func registerTestTenantKeys(t *testing.T, domain string, fa *fakeAuth0, clock *testClock) *subjectTokenKeys {
	t.Helper()
	httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second, Transport: fa})
	keys := newSubjectTokenKeys(domain, httpClient)
	keys.now = clock.now
	keys.prefetch(context.Background())

	tenantKeysMu.Lock()
	tenantKeys[domain] = keys
	tenantKeysMu.Unlock()
	t.Cleanup(func() {
		tenantKeysMu.Lock()
		delete(tenantKeys, domain)
		tenantKeysMu.Unlock()
	})
	return keys
}

func userTokenClaims(mutate func(jwt.MapClaims)) jwt.MapClaims {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":   "auth0|victim",
		"iss":   testImpersonationIssuer,
		"aud":   []string{testMgmtAudience},
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
		"scope": constants.UserUpdateMetadataRequiredScope,
	}
	if mutate != nil {
		mutate(claims)
	}
	return claims
}

func newKeyedJWTVerificationConfig(keys signingKeySource) *JWTVerificationConfig {
	return &JWTVerificationConfig{
		Keys:              keys,
		ExpectedIssuer:    testImpersonationIssuer,
		ExpectedAudience:  testMgmtAudience,
		ExpectedAudiences: []string{testMgmtAudience},
	}
}

func TestJWTVerify_SelectsKeyByKID(t *testing.T) {
	key1 := generateKey(t)
	key2 := generateKey(t)
	attackerKey := generateKey(t)
	fa := &fakeAuth0{}
	fa.publish(t, map[string]*rsa.PrivateKey{"k1": key1, "k2": key2})
	keys := registerTestTenantKeys(t, testImpersonationDomain, fa, newTestClock())
	cfg := newKeyedJWTVerificationConfig(keys)
	ctx := context.Background()

	for _, tc := range []struct {
		name  string
		key   *rsa.PrivateKey
		kid   string
		token string
	}{
		{name: "first published key", key: key1, kid: "k1"},
		{name: "second published key", key: key2, kid: "k2"},
		{name: "bearer prefixed", key: key1, kid: "k1", token: "Bearer " + signRS256(t, key1, "k1", userTokenClaims(nil))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := tc.token
			if token == "" {
				token = signRS256(t, tc.key, tc.kid, userTokenClaims(nil))
			}
			claims, err := cfg.JWTVerify(ctx, token, constants.UserUpdateMetadataRequiredScope)
			if err != nil {
				t.Fatalf("expected token to verify, got %v", err)
			}
			if claims.Subject != "auth0|victim" {
				t.Errorf("unexpected subject %q", claims.Subject)
			}
		})
	}

	tenantPubDER, err := x509.MarshalPKIXPublicKey(&key1.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	tenantPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: tenantPubDER})
	mislabeled := jwt.NewWithClaims(jwt.SigningMethodRS256, userTokenClaims(nil))
	mislabeled.Header["kid"] = "k1"
	mislabeled.Header["alg"] = "PS256"
	mislabeledToken, err := mislabeled.SignedString(key1)
	if err != nil {
		t.Fatalf("failed to sign mislabeled token: %v", err)
	}

	for _, tc := range []struct {
		name  string
		token string
	}{
		{name: "foreign key under published kid", token: signRS256(t, attackerKey, "k1", userTokenClaims(nil))},
		{name: "unknown kid", token: signRS256(t, attackerKey, "attacker", userTokenClaims(nil))},
		{name: "missing kid", token: signRS256(t, key1, "", userTokenClaims(nil))},
		{name: "header alg not RS256", token: mislabeledToken},
		{name: "HS256 keyed with tenant public key", token: signToken(t, jwt.SigningMethodHS256, tenantPubPEM, "k1", userTokenClaims(nil))},
		{name: "unsigned", token: signToken(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, "k1", userTokenClaims(nil))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := cfg.JWTVerify(ctx, tc.token); err == nil {
				t.Fatal("expected token to be rejected")
			}
		})
	}
}

func TestJWTVerify_RemovedSigningKeyStopsVerifying(t *testing.T) {
	oldKey := generateKey(t)
	newKey := generateKey(t)
	fa := &fakeAuth0{}
	fa.publish(t, map[string]*rsa.PrivateKey{"old": oldKey, "new": newKey})
	clock := newTestClock()
	cfg := newKeyedJWTVerificationConfig(registerTestTenantKeys(t, testImpersonationDomain, fa, clock))
	ctx := context.Background()
	oldToken := signRS256(t, oldKey, "old", userTokenClaims(nil))

	if _, err := cfg.JWTVerify(ctx, oldToken); err != nil {
		t.Fatalf("expected token signed by a published key to verify: %v", err)
	}

	// Auth0 revokes the old key; once the cache refreshes it no longer verifies.
	fa.publish(t, map[string]*rsa.PrivateKey{"new": newKey})
	clock.advance(jwksRefreshAfter)

	if _, err := cfg.JWTVerify(ctx, oldToken); err == nil {
		t.Fatal("expected token signed by a removed key to be rejected")
	}
	if _, err := cfg.JWTVerify(ctx, signRS256(t, newKey, "new", userTokenClaims(nil))); err != nil {
		t.Fatalf("expected token signed by the remaining key to verify: %v", err)
	}
}

func TestJWTVerify_RotatedSigningKeyVerifiesWithoutRestart(t *testing.T) {
	oldKey := generateKey(t)
	newKey := generateKey(t)
	fa := &fakeAuth0{}
	fa.publish(t, map[string]*rsa.PrivateKey{"old": oldKey})
	clock := newTestClock()
	cfg := newKeyedJWTVerificationConfig(registerTestTenantKeys(t, testImpersonationDomain, fa, clock))
	ctx := context.Background()

	fa.publish(t, map[string]*rsa.PrivateKey{"old": oldKey, "new": newKey})
	clock.advance(jwksMinRefreshInterval)

	if _, err := cfg.JWTVerify(ctx, signRS256(t, newKey, "new", userTokenClaims(nil))); err != nil {
		t.Fatalf("expected token signed by a newly published key to verify: %v", err)
	}
	if fa.jwksFetches() != 2 {
		t.Errorf("expected a refetch for the unknown kid, got %d fetches", fa.jwksFetches())
	}
}

func TestJWTVerify_StaleSigningKeysFailClosed(t *testing.T) {
	tenantKey := generateKey(t)
	fa := &fakeAuth0{}
	fa.publish(t, map[string]*rsa.PrivateKey{testTenantKID: tenantKey})
	clock := newTestClock()
	cfg := newKeyedJWTVerificationConfig(registerTestTenantKeys(t, testImpersonationDomain, fa, clock))

	fa.setJWKSStatus(http.StatusInternalServerError)
	clock.advance(jwksTTL)

	_, err := cfg.JWTVerify(context.Background(), signRS256(t, tenantKey, testTenantKID, userTokenClaims(nil)))
	var unavailable errors.ServiceUnavailable
	if !stderrors.As(err, &unavailable) {
		t.Fatalf("expected service unavailable when cached keys are stale and JWKS is unreachable, got %v", err)
	}
}

func TestJWTVerify_RequiresVerificationKey(t *testing.T) {
	tenantKey := generateKey(t)
	cfg := &JWTVerificationConfig{
		ExpectedIssuer:    testImpersonationIssuer,
		ExpectedAudience:  testMgmtAudience,
		ExpectedAudiences: []string{testMgmtAudience},
	}
	if _, err := cfg.JWTVerify(context.Background(), signRS256(t, tenantKey, testTenantKID, userTokenClaims(nil))); err == nil {
		t.Fatal("expected verification without a key source to fail")
	}
}

func TestNewJWTVerificationConfig_UsesSharedTenantKeys(t *testing.T) {
	t.Setenv(constants.Auth0ManagementAudienceEnvKey, "")
	t.Setenv(constants.Auth0LFXv2APIAudienceEnvKey, "")
	tenantKey := generateKey(t)
	fa := &fakeAuth0{}
	fa.publish(t, map[string]*rsa.PrivateKey{testTenantKID: tenantKey})
	keys := registerTestTenantKeys(t, testImpersonationDomain, fa, newTestClock())

	cfg, err := NewJWTVerificationConfig(context.Background(), testImpersonationDomain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Keys != keys {
		t.Fatal("expected the verifier to use the shared tenant key cache")
	}
	if cfg.PublicKey != nil {
		t.Error("expected no pinned public key")
	}
	if cfg.ExpectedIssuer != testImpersonationIssuer || cfg.ExpectedAudience != testMgmtAudience {
		t.Errorf("unexpected issuer/audience %q %q", cfg.ExpectedIssuer, cfg.ExpectedAudience)
	}
	if _, err := cfg.JWTVerify(context.Background(), signRS256(t, tenantKey, testTenantKID, userTokenClaims(nil))); err != nil {
		t.Fatalf("expected token to verify: %v", err)
	}
}

func TestNewJWTVerificationConfig_FailsWithoutJWKS(t *testing.T) {
	fa := &fakeAuth0{}
	fa.setJWKSStatus(http.StatusServiceUnavailable)
	registerTestTenantKeys(t, testImpersonationDomain, fa, newTestClock())

	if _, err := NewJWTVerificationConfig(context.Background(), testImpersonationDomain); err == nil {
		t.Fatal("expected an error when the JWKS cannot be loaded")
	}
	// One prefetch plus the initial attempt and each retry.
	if want := jwksStartupRetries + 2; fa.jwksFetches() != want {
		t.Errorf("expected %d JWKS fetches, got %d", want, fa.jwksFetches())
	}
}

// TestRemovedSigningKeyRejectedByAllVerifiers asserts that the impersonation
// subject-token check and JWTVerify share one key source, so a key removed
// from the tenant JWKS stops verifying on both paths at the same time.
func TestRemovedSigningKeyRejectedByAllVerifiers(t *testing.T) {
	t.Setenv(constants.Auth0ManagementAudienceEnvKey, "")
	t.Setenv(constants.Auth0LFXv2APIAudienceEnvKey, testImpersonationAudience)
	t.Setenv(constants.Auth0M2MClientIDEnvKey, "test-client-id")
	m2mKey := generateKey(t)
	m2mDER, err := x509.MarshalPKCS8PrivateKey(m2mKey)
	if err != nil {
		t.Fatalf("failed to marshal M2M key: %v", err)
	}
	t.Setenv(constants.Auth0M2MPrivateBase64KeyEnvKey,
		base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: m2mDER})))

	oldKey := generateKey(t)
	newKey := generateKey(t)
	fa := &fakeAuth0{}
	fa.publish(t, map[string]*rsa.PrivateKey{"old": oldKey, "new": newKey})
	clock := newTestClock()
	keys := registerTestTenantKeys(t, testImpersonationDomain, fa, clock)
	ctx := context.Background()

	impersonator, err := NewImpersonationFlow(ctx, testImpersonationDomain)
	if err != nil {
		t.Fatalf("failed to build impersonation flow: %v", err)
	}
	flow := impersonator.(*impersonationFlow)
	// Route the token exchange to the fake tenant as well.
	flow.httpClient = httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second, Transport: fa})

	cfg, err := NewJWTVerificationConfig(ctx, testImpersonationDomain)
	if err != nil {
		t.Fatalf("failed to build JWT verifier: %v", err)
	}
	if flow.subjectKeys != keys || cfg.Keys != keys {
		t.Fatal("expected impersonation and JWTVerify to share the tenant key cache")
	}

	oldSubject := signRS256(t, oldKey, "old", subjectClaims(nil))
	oldUser := signRS256(t, oldKey, "old", userTokenClaims(nil))
	if _, err := flow.ImpersonateUser(ctx, oldSubject, "victim@example.com"); err != nil {
		t.Fatalf("expected impersonation to accept a published key: %v", err)
	}
	if _, err := cfg.JWTVerify(ctx, oldUser); err != nil {
		t.Fatalf("expected JWTVerify to accept a published key: %v", err)
	}

	fa.publish(t, map[string]*rsa.PrivateKey{"new": newKey})
	clock.advance(jwksRefreshAfter)

	var unauthorized errors.Unauthorized
	if _, err := flow.ImpersonateUser(ctx, oldSubject, "victim@example.com"); !stderrors.As(err, &unauthorized) {
		t.Fatalf("expected impersonation to reject a removed key as unauthorized, got %v", err)
	}
	if _, err := cfg.JWTVerify(ctx, oldUser); !stderrors.As(err, &unauthorized) {
		t.Fatalf("expected JWTVerify to reject a key the impersonation verifier rejects as unauthorized, got %v", err)
	}
	if _, err := flow.ImpersonateUser(ctx, signRS256(t, newKey, "new", subjectClaims(nil)), "victim@example.com"); err != nil {
		t.Fatalf("expected impersonation to accept the remaining key: %v", err)
	}
	if _, err := cfg.JWTVerify(ctx, signRS256(t, newKey, "new", userTokenClaims(nil))); err != nil {
		t.Fatalf("expected JWTVerify to accept the remaining key: %v", err)
	}
}
