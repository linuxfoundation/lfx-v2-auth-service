// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	stderrors "errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
)

const (
	testImpersonationDomain   = "test.auth0.com"
	testImpersonationIssuer   = "https://test.auth0.com/"
	testImpersonationAudience = "https://api.lfx.dev"
	testMgmtAudience          = "https://test.auth0.com/api/v2/"
	testTenantKID             = "tenant-key-1"
)

// fakeAuth0 serves the tenant JWKS and records token endpoint requests,
// answering them with a successful Custom Token Exchange response.
type fakeAuth0 struct {
	mu         sync.Mutex
	jwks       []byte
	jwksStatus int
	jwksCalls  int
	forms      []url.Values
}

func (fa *fakeAuth0) RoundTrip(req *http.Request) (*http.Response, error) {
	fa.mu.Lock()
	defer fa.mu.Unlock()

	if req.URL.Path == "/.well-known/jwks.json" {
		fa.jwksCalls++
		status := fa.jwksStatus
		if status == 0 {
			status = http.StatusOK
		}
		return &http.Response{
			StatusCode: status,
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       io.NopCloser(strings.NewReader(string(fa.jwks))),
			Request:    req,
		}, nil
	}

	body, _ := io.ReadAll(req.Body)
	form, _ := url.ParseQuery(string(body))
	fa.forms = append(fa.forms, form)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"access_token":"minted-token","token_type":"Bearer","expires_in":300}`)),
		Request:    req,
	}, nil
}

func (fa *fakeAuth0) calls() int {
	fa.mu.Lock()
	defer fa.mu.Unlock()
	return len(fa.forms)
}

func (fa *fakeAuth0) jwksFetches() int {
	fa.mu.Lock()
	defer fa.mu.Unlock()
	return fa.jwksCalls
}

func (fa *fakeAuth0) publish(t *testing.T, keys map[string]*rsa.PrivateKey) {
	t.Helper()
	set := jwk.NewSet()
	for kid, priv := range keys {
		key, err := jwk.FromRaw(&priv.PublicKey)
		if err != nil {
			t.Fatalf("failed to build JWK: %v", err)
		}
		_ = key.Set(jwk.KeyIDKey, kid)
		_ = key.Set(jwk.AlgorithmKey, jwa.RS256)
		_ = key.Set(jwk.KeyUsageKey, jwk.ForSignature)
		if err := set.AddKey(key); err != nil {
			t.Fatalf("failed to add JWK: %v", err)
		}
	}
	data, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("failed to marshal JWKS: %v", err)
	}
	fa.mu.Lock()
	fa.jwks = data
	fa.mu.Unlock()
}

func (fa *fakeAuth0) setJWKSStatus(status int) {
	fa.mu.Lock()
	fa.jwksStatus = status
	fa.mu.Unlock()
}

// testClock is a manually advanced clock for the signing key cache.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// newTestImpersonationFlow builds a flow backed by fa and prefetches the JWKS
// as NewImpersonationFlow does.
func newTestImpersonationFlow(t *testing.T, fa *fakeAuth0, clock *testClock) *impersonationFlow {
	t.Helper()
	m2mKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate M2M key: %v", err)
	}
	httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second, Transport: fa})
	keys := newSubjectTokenKeys(testImpersonationDomain, httpClient)
	keys.now = clock.now
	keys.prefetch(context.Background())
	return &impersonationFlow{
		clientID:      "test-client-id",
		privateKey:    m2mKey,
		domain:        testImpersonationDomain,
		lfxV2Audience: testImpersonationAudience,
		issuer:        testImpersonationIssuer,
		subjectKeys:   keys,
		httpClient:    httpClient,
	}
}

func newTestClock() *testClock {
	return &testClock{t: time.Now()}
}

func generateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return key
}

func subjectClaims(mutate func(jwt.MapClaims)) jwt.MapClaims {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":               "auth0|impersonator",
		"iss":               testImpersonationIssuer,
		"aud":               []string{testImpersonationAudience},
		"iat":               now.Unix(),
		"exp":               now.Add(time.Hour).Unix(),
		canImpersonateClaim: true,
	}
	if mutate != nil {
		mutate(claims)
	}
	return claims
}

func signToken(t *testing.T, method jwt.SigningMethod, key any, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return signed
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	return signToken(t, jwt.SigningMethodRS256, key, kid, claims)
}

func TestImpersonateUser_AuthorizedSubjectToken(t *testing.T) {
	tenantKey := generateKey(t)
	fa := &fakeAuth0{}
	fa.publish(t, map[string]*rsa.PrivateKey{testTenantKID: tenantKey})
	flow := newTestImpersonationFlow(t, fa, newTestClock())

	subjectToken := signRS256(t, tenantKey, testTenantKID, subjectClaims(nil))
	accessToken, err := flow.ImpersonateUser(context.Background(), subjectToken, "target@example.com")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if accessToken != "minted-token" {
		t.Errorf("expected minted token, got %q", accessToken)
	}
	if fa.calls() != 1 {
		t.Fatalf("expected exactly one token endpoint call, got %d", fa.calls())
	}
	form := fa.forms[0]
	if got := form.Get("subject_token"); got != subjectToken {
		t.Errorf("subject_token not forwarded as verified")
	}
	if got := form.Get("target_user"); got != "target@example.com" {
		t.Errorf("unexpected target_user %q", got)
	}
	if fa.jwksFetches() != 1 {
		t.Errorf("expected the prefetched JWKS to be reused, got %d fetches", fa.jwksFetches())
	}
}

func TestImpersonateUser_RejectsUnauthorizedSubjectTokens(t *testing.T) {
	tenantKey := generateKey(t)
	attackerKey := generateKey(t)

	unsigned := signToken(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, testTenantKID, subjectClaims(nil))
	hmacSigned := signToken(t, jwt.SigningMethodHS256, []byte("shared-secret"), testTenantKID, subjectClaims(nil))
	// Algorithm confusion: HS256 keyed with the tenant's public key.
	tenantPubDER, err := x509.MarshalPKIXPublicKey(&tenantKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal tenant public key: %v", err)
	}
	tenantPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: tenantPubDER})
	algConfused := signToken(t, jwt.SigningMethodHS256, tenantPubPEM, testTenantKID, subjectClaims(nil))
	valid := signRS256(t, tenantKey, testTenantKID, subjectClaims(nil))
	// RS256 signature by the tenant key under a header claiming another alg.
	mislabeled := jwt.NewWithClaims(jwt.SigningMethodRS256, subjectClaims(nil))
	mislabeled.Header["kid"] = testTenantKID
	mislabeled.Header["alg"] = "PS256"
	mislabeledToken, err := mislabeled.SignedString(tenantKey)
	if err != nil {
		t.Fatalf("failed to sign mislabeled token: %v", err)
	}

	tests := []struct {
		name          string
		token         string
		wantForbidden bool
	}{
		{name: "not a JWT", token: "not-a-jwt"},
		{name: "unsigned (alg none)", token: unsigned},
		{name: "HS256 signed", token: hmacSigned},
		{name: "HS256 keyed with tenant public key", token: algConfused},
		{name: "Bearer prefixed", token: "Bearer " + valid},
		{name: "JSON serialized", token: `{"payload":"` + valid + `"}`},
		{name: "header alg not RS256", token: mislabeledToken},
		{name: "missing kid", token: signRS256(t, tenantKey, "", subjectClaims(nil))},
		{name: "unknown kid", token: signRS256(t, attackerKey, "attacker-key", subjectClaims(nil))},
		{name: "forged with foreign key under tenant kid", token: signRS256(t, attackerKey, testTenantKID, subjectClaims(nil))},
		{name: "expired", token: signRS256(t, tenantKey, testTenantKID, subjectClaims(func(c jwt.MapClaims) {
			c["exp"] = time.Now().Add(-time.Minute).Unix()
		}))},
		{name: "missing exp", token: signRS256(t, tenantKey, testTenantKID, subjectClaims(func(c jwt.MapClaims) {
			delete(c, "exp")
		}))},
		{name: "not yet valid", token: signRS256(t, tenantKey, testTenantKID, subjectClaims(func(c jwt.MapClaims) {
			c["nbf"] = time.Now().Add(time.Hour).Unix()
		}))},
		{name: "wrong issuer", token: signRS256(t, tenantKey, testTenantKID, subjectClaims(func(c jwt.MapClaims) {
			c["iss"] = "https://evil.example.com/"
		}))},
		{name: "management API audience", token: signRS256(t, tenantKey, testTenantKID, subjectClaims(func(c jwt.MapClaims) {
			c["aud"] = []string{testMgmtAudience}
		}))},
		{name: "missing audience", token: signRS256(t, tenantKey, testTenantKID, subjectClaims(func(c jwt.MapClaims) {
			delete(c, "aud")
		}))},
		{name: "missing subject", token: signRS256(t, tenantKey, testTenantKID, subjectClaims(func(c jwt.MapClaims) {
			delete(c, "sub")
		}))},
		{name: "non-impersonator: claim missing", wantForbidden: true, token: signRS256(t, tenantKey, testTenantKID, subjectClaims(func(c jwt.MapClaims) {
			delete(c, canImpersonateClaim)
		}))},
		{name: "non-impersonator: claim false", wantForbidden: true, token: signRS256(t, tenantKey, testTenantKID, subjectClaims(func(c jwt.MapClaims) {
			c[canImpersonateClaim] = false
		}))},
		{name: "non-impersonator: claim is string", wantForbidden: true, token: signRS256(t, tenantKey, testTenantKID, subjectClaims(func(c jwt.MapClaims) {
			c[canImpersonateClaim] = "true"
		}))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fa := &fakeAuth0{}
			fa.publish(t, map[string]*rsa.PrivateKey{testTenantKID: tenantKey})
			flow := newTestImpersonationFlow(t, fa, newTestClock())

			accessToken, err := flow.ImpersonateUser(context.Background(), tt.token, "victim@example.com")
			if err == nil {
				t.Fatalf("expected error, got token %q", accessToken)
			}
			if accessToken != "" {
				t.Errorf("expected no access token, got %q", accessToken)
			}
			if fa.calls() != 0 {
				t.Errorf("expected no token endpoint call, got %d", fa.calls())
			}
			var forbidden errors.Forbidden
			if tt.wantForbidden != stderrors.As(err, &forbidden) {
				t.Errorf("unexpected error type %T: %v", err, err)
			}
		})
	}
}

func TestImpersonateUser_SigningKeyRotation(t *testing.T) {
	oldKey := generateKey(t)
	newKey := generateKey(t)
	fa := &fakeAuth0{}
	fa.publish(t, map[string]*rsa.PrivateKey{"old": oldKey})
	clock := newTestClock()
	flow := newTestImpersonationFlow(t, fa, clock)
	ctx := context.Background()

	if _, err := flow.ImpersonateUser(ctx, signRS256(t, oldKey, "old", subjectClaims(nil)), "victim@example.com"); err != nil {
		t.Fatalf("expected token signed by the current key to be accepted: %v", err)
	}

	// Auth0 rotates: the new key is published after the cache was filled.
	fa.publish(t, map[string]*rsa.PrivateKey{"old": oldKey, "new": newKey})
	clock.advance(jwksMinRefreshInterval)

	if _, err := flow.ImpersonateUser(ctx, signRS256(t, newKey, "new", subjectClaims(nil)), "victim@example.com"); err != nil {
		t.Fatalf("expected token signed by the rotated key to be accepted: %v", err)
	}
	if fa.jwksFetches() != 2 {
		t.Errorf("expected one refetch for the unknown kid, got %d fetches", fa.jwksFetches())
	}
	if fa.calls() != 2 {
		t.Errorf("expected two token endpoint calls, got %d", fa.calls())
	}
}

func TestImpersonateUser_UnknownKIDRefreshIsRateLimited(t *testing.T) {
	tenantKey := generateKey(t)
	attackerKey := generateKey(t)
	fa := &fakeAuth0{}
	fa.publish(t, map[string]*rsa.PrivateKey{testTenantKID: tenantKey})
	clock := newTestClock()
	flow := newTestImpersonationFlow(t, fa, clock)
	ctx := context.Background()

	forged := func(kid string) string { return signRS256(t, attackerKey, kid, subjectClaims(nil)) }

	// Within the minimum interval of the prefetch, unknown kids never refetch.
	for _, kid := range []string{"a", "b", "c"} {
		if _, err := flow.ImpersonateUser(ctx, forged(kid), "victim@example.com"); err == nil {
			t.Fatal("expected unknown kid to be rejected")
		}
	}
	if fa.jwksFetches() != 1 {
		t.Fatalf("expected no refetch within the minimum interval, got %d fetches", fa.jwksFetches())
	}

	clock.advance(jwksMinRefreshInterval)
	for _, kid := range []string{"d", "e"} {
		if _, err := flow.ImpersonateUser(ctx, forged(kid), "victim@example.com"); err == nil {
			t.Fatal("expected unknown kid to be rejected")
		}
	}
	if fa.jwksFetches() != 2 {
		t.Errorf("expected exactly one refetch per interval, got %d fetches", fa.jwksFetches())
	}
	if fa.calls() != 0 {
		t.Errorf("expected no token endpoint call, got %d", fa.calls())
	}
}

func TestImpersonateUser_RecoversFromStartupJWKSFailure(t *testing.T) {
	tenantKey := generateKey(t)
	fa := &fakeAuth0{}
	fa.publish(t, map[string]*rsa.PrivateKey{testTenantKID: tenantKey})
	fa.setJWKSStatus(http.StatusServiceUnavailable)
	clock := newTestClock()
	flow := newTestImpersonationFlow(t, fa, clock)
	ctx := context.Background()
	token := signRS256(t, tenantKey, testTenantKID, subjectClaims(nil))

	var unavailable errors.ServiceUnavailable
	if _, err := flow.ImpersonateUser(ctx, token, "victim@example.com"); !stderrors.As(err, &unavailable) {
		t.Fatalf("expected service unavailable while JWKS is down, got %v", err)
	}
	if fa.calls() != 0 {
		t.Fatalf("expected no token endpoint call, got %d", fa.calls())
	}

	fa.setJWKSStatus(http.StatusOK)
	clock.advance(jwksMinRefreshInterval)
	if _, err := flow.ImpersonateUser(ctx, token, "victim@example.com"); err != nil {
		t.Fatalf("expected recovery once JWKS is reachable, got %v", err)
	}
}

func TestImpersonateUser_StaleSigningKeysFailClosed(t *testing.T) {
	tenantKey := generateKey(t)
	fa := &fakeAuth0{}
	fa.publish(t, map[string]*rsa.PrivateKey{testTenantKID: tenantKey})
	clock := newTestClock()
	flow := newTestImpersonationFlow(t, fa, clock)
	ctx := context.Background()

	fa.setJWKSStatus(http.StatusInternalServerError)
	clock.advance(jwksTTL)

	token := signRS256(t, tenantKey, testTenantKID, subjectClaims(nil))
	var unavailable errors.ServiceUnavailable
	if _, err := flow.ImpersonateUser(ctx, token, "victim@example.com"); !stderrors.As(err, &unavailable) {
		t.Fatalf("expected service unavailable when cached keys are stale and JWKS is unreachable, got %v", err)
	}
	if fa.jwksFetches() != 2 {
		t.Errorf("expected a refetch attempt for the stale set, got %d fetches", fa.jwksFetches())
	}
	if fa.calls() != 0 {
		t.Errorf("expected no token endpoint call, got %d", fa.calls())
	}
}

func TestImpersonateUser_EarlyRefreshSurvivesFailedFetch(t *testing.T) {
	tenantKey := generateKey(t)
	fa := &fakeAuth0{}
	fa.publish(t, map[string]*rsa.PrivateKey{testTenantKID: tenantKey})
	clock := newTestClock()
	flow := newTestImpersonationFlow(t, fa, clock)
	ctx := context.Background()
	token := signRS256(t, tenantKey, testTenantKID, subjectClaims(nil))

	// The refresh attempted after jwksRefreshAfter fails, but the cached keys
	// are still within jwksTTL and keep verifying.
	fa.setJWKSStatus(http.StatusInternalServerError)
	clock.advance(jwksRefreshAfter)
	if _, err := flow.ImpersonateUser(ctx, token, "victim@example.com"); err != nil {
		t.Fatalf("expected cached keys to keep verifying before jwksTTL, got %v", err)
	}
	if fa.jwksFetches() != 2 {
		t.Errorf("expected an early refresh attempt, got %d fetches", fa.jwksFetches())
	}

	// A later retry succeeds and renews the cache past the original jwksTTL.
	fa.setJWKSStatus(http.StatusOK)
	clock.advance(jwksMinRefreshInterval)
	if _, err := flow.ImpersonateUser(ctx, token, "victim@example.com"); err != nil {
		t.Fatalf("expected retry to succeed, got %v", err)
	}
	clock.advance(jwksTTL - jwksRefreshAfter)
	if _, err := flow.ImpersonateUser(ctx, token, "victim@example.com"); err != nil {
		t.Fatalf("expected renewed keys to verify past the original TTL, got %v", err)
	}
}

func TestImpersonateUser_RemovedSigningKeyStopsVerifying(t *testing.T) {
	oldKey := generateKey(t)
	newKey := generateKey(t)
	fa := &fakeAuth0{}
	fa.publish(t, map[string]*rsa.PrivateKey{"old": oldKey, "new": newKey})
	clock := newTestClock()
	flow := newTestImpersonationFlow(t, fa, clock)
	ctx := context.Background()

	// Auth0 drops the old key; once the cache refreshes it no longer verifies.
	fa.publish(t, map[string]*rsa.PrivateKey{"new": newKey})
	clock.advance(jwksRefreshAfter)

	if _, err := flow.ImpersonateUser(ctx, signRS256(t, oldKey, "old", subjectClaims(nil)), "victim@example.com"); err == nil {
		t.Fatal("expected token signed by a removed key to be rejected")
	}
	if _, err := flow.ImpersonateUser(ctx, signRS256(t, newKey, "new", subjectClaims(nil)), "victim@example.com"); err != nil {
		t.Fatalf("expected token signed by the remaining key to be accepted: %v", err)
	}
	if fa.calls() != 1 {
		t.Errorf("expected one token endpoint call, got %d", fa.calls())
	}
}

func TestImpersonateUser_ConcurrentRequests(t *testing.T) {
	tenantKey := generateKey(t)
	attackerKey := generateKey(t)
	fa := &fakeAuth0{}
	fa.publish(t, map[string]*rsa.PrivateKey{testTenantKID: tenantKey})
	clock := newTestClock()
	flow := newTestImpersonationFlow(t, fa, clock)
	valid := signRS256(t, tenantKey, testTenantKID, subjectClaims(nil))
	forged := signRS256(t, attackerKey, "unknown", subjectClaims(nil))

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := flow.ImpersonateUser(context.Background(), valid, "victim@example.com"); err != nil {
				t.Errorf("expected valid token to be accepted: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := flow.ImpersonateUser(context.Background(), forged, "victim@example.com"); err == nil {
				t.Error("expected forged token to be rejected")
			}
		}()
	}
	wg.Wait()

	if fa.jwksFetches() != 1 {
		t.Errorf("expected no refetch within the minimum interval, got %d fetches", fa.jwksFetches())
	}
	if fa.calls() != 20 {
		t.Errorf("expected 20 token endpoint calls, got %d", fa.calls())
	}
}

func TestRSASigningKey(t *testing.T) {
	rsaKey := generateKey(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}

	build := func(raw any, set map[string]any) jwk.Key {
		t.Helper()
		key, err := jwk.FromRaw(raw)
		if err != nil {
			t.Fatalf("failed to build JWK: %v", err)
		}
		for k, v := range set {
			if err := key.Set(k, v); err != nil {
				t.Fatalf("failed to set %s: %v", k, err)
			}
		}
		return key
	}

	tests := []struct {
		name    string
		key     jwk.Key
		wantErr bool
	}{
		{name: "RSA signing key", key: build(&rsaKey.PublicKey, map[string]any{jwk.KeyUsageKey: jwk.ForSignature, jwk.AlgorithmKey: jwa.RS256})},
		{name: "RSA key without use or alg", key: build(&rsaKey.PublicKey, nil)},
		{name: "encryption key", wantErr: true, key: build(&rsaKey.PublicKey, map[string]any{jwk.KeyUsageKey: jwk.ForEncryption})},
		{name: "RS512 key", wantErr: true, key: build(&rsaKey.PublicKey, map[string]any{jwk.AlgorithmKey: jwa.RS512})},
		{name: "PS256 key", wantErr: true, key: build(&rsaKey.PublicKey, map[string]any{jwk.AlgorithmKey: jwa.PS256})},
		{name: "EC key", wantErr: true, key: build(&ecKey.PublicKey, nil)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, err := rsaSigningKey(tt.key)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected key to be rejected")
				}
				return
			}
			if err != nil {
				t.Fatalf("expected key to be accepted: %v", err)
			}
			if !pub.Equal(&rsaKey.PublicKey) {
				t.Error("returned key does not match")
			}
		})
	}
}

func TestImpersonateUser_FailsClosedWithoutVerifier(t *testing.T) {
	tenantKey := generateKey(t)
	subjectToken := signRS256(t, tenantKey, testTenantKID, subjectClaims(nil))

	tests := []struct {
		name   string
		mutate func(f *impersonationFlow)
	}{
		{name: "nil signing keys", mutate: func(f *impersonationFlow) { f.subjectKeys = nil }},
		{name: "empty issuer", mutate: func(f *impersonationFlow) { f.issuer = "" }},
		{name: "empty audience", mutate: func(f *impersonationFlow) { f.lfxV2Audience = "" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fa := &fakeAuth0{}
			fa.publish(t, map[string]*rsa.PrivateKey{testTenantKID: tenantKey})
			flow := newTestImpersonationFlow(t, fa, newTestClock())
			tt.mutate(flow)

			if _, err := flow.ImpersonateUser(context.Background(), subjectToken, "victim@example.com"); err == nil {
				t.Fatal("expected error when verification is not configured")
			}
			if fa.calls() != 0 {
				t.Errorf("expected no token endpoint call, got %d", fa.calls())
			}
		})
	}
}
