// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
)

const (
	testImpersonationDomain   = "test.auth0.com"
	testImpersonationIssuer   = "https://test.auth0.com/"
	testImpersonationAudience = "https://api.lfx.dev"
	testMgmtAudience          = "https://test.auth0.com/api/v2/"
)

// recordingTransport captures token endpoint requests and answers with a
// successful Custom Token Exchange response.
type recordingTransport struct {
	mu    sync.Mutex
	forms []url.Values
}

func (rt *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(req.Body)
	form, _ := url.ParseQuery(string(body))
	rt.mu.Lock()
	rt.forms = append(rt.forms, form)
	rt.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"access_token":"minted-token","token_type":"Bearer","expires_in":300}`)),
		Request:    req,
	}, nil
}

func (rt *recordingTransport) calls() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return len(rt.forms)
}

func newTestImpersonationFlow(t *testing.T, tenantKey *rsa.PrivateKey, rt http.RoundTripper) *impersonationFlow {
	t.Helper()
	m2mKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate M2M key: %v", err)
	}
	return &impersonationFlow{
		clientID:      "test-client-id",
		privateKey:    m2mKey,
		domain:        testImpersonationDomain,
		lfxV2Audience: testImpersonationAudience,
		subjectTokenVerifier: &JWTVerificationConfig{
			PublicKey:         &tenantKey.PublicKey,
			ExpectedIssuer:    testImpersonationIssuer,
			ExpectedAudiences: []string{testImpersonationAudience},
		},
		httpClient: httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second, Transport: rt}),
	}
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

func signRS256(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return token
}

func TestImpersonateUser_AuthorizedSubjectToken(t *testing.T) {
	tenantKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate tenant key: %v", err)
	}
	rt := &recordingTransport{}
	flow := newTestImpersonationFlow(t, tenantKey, rt)

	subjectToken := signRS256(t, tenantKey, subjectClaims(nil))
	accessToken, err := flow.ImpersonateUser(context.Background(), subjectToken, "target@example.com")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if accessToken != "minted-token" {
		t.Errorf("expected minted token, got %q", accessToken)
	}
	if rt.calls() != 1 {
		t.Fatalf("expected exactly one token endpoint call, got %d", rt.calls())
	}
	form := rt.forms[0]
	if got := form.Get("subject_token"); got != subjectToken {
		t.Errorf("subject_token not forwarded as verified")
	}
	if got := form.Get("target_user"); got != "target@example.com" {
		t.Errorf("unexpected target_user %q", got)
	}
}

func TestImpersonateUser_RejectsUnauthorizedSubjectTokens(t *testing.T) {
	tenantKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate tenant key: %v", err)
	}
	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate attacker key: %v", err)
	}

	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, subjectClaims(nil)).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("failed to build unsigned token: %v", err)
	}
	hmacSigned, err := jwt.NewWithClaims(jwt.SigningMethodHS256, subjectClaims(nil)).SignedString([]byte("shared-secret"))
	if err != nil {
		t.Fatalf("failed to build HS256 token: %v", err)
	}
	// Algorithm confusion: HS256 keyed with the tenant's public key.
	tenantPubDER, err := x509.MarshalPKIXPublicKey(&tenantKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal tenant public key: %v", err)
	}
	tenantPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: tenantPubDER})
	algConfused, err := jwt.NewWithClaims(jwt.SigningMethodHS256, subjectClaims(nil)).SignedString(tenantPubPEM)
	if err != nil {
		t.Fatalf("failed to build alg-confused token: %v", err)
	}
	valid := signRS256(t, tenantKey, subjectClaims(nil))

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
		{name: "forged with foreign key", token: signRS256(t, attackerKey, subjectClaims(nil))},
		{name: "expired", token: signRS256(t, tenantKey, subjectClaims(func(c jwt.MapClaims) {
			c["exp"] = time.Now().Add(-time.Minute).Unix()
		}))},
		{name: "missing exp", token: signRS256(t, tenantKey, subjectClaims(func(c jwt.MapClaims) {
			delete(c, "exp")
		}))},
		{name: "not yet valid", token: signRS256(t, tenantKey, subjectClaims(func(c jwt.MapClaims) {
			c["nbf"] = time.Now().Add(time.Hour).Unix()
		}))},
		{name: "wrong issuer", token: signRS256(t, tenantKey, subjectClaims(func(c jwt.MapClaims) {
			c["iss"] = "https://evil.example.com/"
		}))},
		{name: "management API audience", token: signRS256(t, tenantKey, subjectClaims(func(c jwt.MapClaims) {
			c["aud"] = []string{testMgmtAudience}
		}))},
		{name: "missing audience", token: signRS256(t, tenantKey, subjectClaims(func(c jwt.MapClaims) {
			delete(c, "aud")
		}))},
		{name: "missing subject", token: signRS256(t, tenantKey, subjectClaims(func(c jwt.MapClaims) {
			delete(c, "sub")
		}))},
		{name: "non-impersonator: claim missing", wantForbidden: true, token: signRS256(t, tenantKey, subjectClaims(func(c jwt.MapClaims) {
			delete(c, canImpersonateClaim)
		}))},
		{name: "non-impersonator: claim false", wantForbidden: true, token: signRS256(t, tenantKey, subjectClaims(func(c jwt.MapClaims) {
			c[canImpersonateClaim] = false
		}))},
		{name: "non-impersonator: claim is string", wantForbidden: true, token: signRS256(t, tenantKey, subjectClaims(func(c jwt.MapClaims) {
			c[canImpersonateClaim] = "true"
		}))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := &recordingTransport{}
			flow := newTestImpersonationFlow(t, tenantKey, rt)

			accessToken, err := flow.ImpersonateUser(context.Background(), tt.token, "victim@example.com")
			if err == nil {
				t.Fatalf("expected error, got token %q", accessToken)
			}
			if accessToken != "" {
				t.Errorf("expected no access token, got %q", accessToken)
			}
			if rt.calls() != 0 {
				t.Errorf("expected no token endpoint call, got %d", rt.calls())
			}
			var forbidden errors.Forbidden
			if tt.wantForbidden != stderrors.As(err, &forbidden) {
				t.Errorf("unexpected error type %T: %v", err, err)
			}
		})
	}
}

func TestImpersonateUser_FailsClosedWithoutVerifier(t *testing.T) {
	tenantKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate tenant key: %v", err)
	}
	subjectToken := signRS256(t, tenantKey, subjectClaims(nil))

	tests := []struct {
		name   string
		mutate func(f *impersonationFlow)
	}{
		{name: "nil verifier", mutate: func(f *impersonationFlow) { f.subjectTokenVerifier = nil }},
		{name: "nil public key", mutate: func(f *impersonationFlow) { f.subjectTokenVerifier.PublicKey = nil }},
		{name: "empty issuer", mutate: func(f *impersonationFlow) { f.subjectTokenVerifier.ExpectedIssuer = "" }},
		{name: "no audiences", mutate: func(f *impersonationFlow) { f.subjectTokenVerifier.ExpectedAudiences = nil }},
		{name: "blank audience", mutate: func(f *impersonationFlow) { f.subjectTokenVerifier.ExpectedAudiences = []string{""} }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := &recordingTransport{}
			flow := newTestImpersonationFlow(t, tenantKey, rt)
			tt.mutate(flow)

			if _, err := flow.ImpersonateUser(context.Background(), subjectToken, "victim@example.com"); err == nil {
				t.Fatal("expected error when verifier is not configured")
			}
			if rt.calls() != 0 {
				t.Errorf("expected no token endpoint call, got %d", rt.calls())
			}
		})
	}
}
