// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"context"
	"crypto/rsa"
	stderrors "errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
)

func TestParseUserSearchTerms(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []string
		wantErr bool
	}{
		{name: "single term", input: "jdoe", want: []string{"jdoe"}},
		{name: "lowercases and splits on whitespace", input: "  John   SMITH ", want: []string{"john", "smith"}},
		{name: "drops a term still being typed", input: "john s", want: []string{"john"}},
		{name: "keeps an email prefix", input: "jdoe@exa", want: []string{"jdoe@exa"}},
		{name: "punctuation separates terms", input: "smith, john", want: []string{"smith", "john"}},
		{name: "range operators are separators, not syntax", input: ">aaa <bbb", want: []string{"aaa", "bbb"}},
		{name: "unsupported characters cannot form a term", input: `a=b&c`, wantErr: true},
		{name: "name particles do not count towards the cap", input: "juan de la vega de", want: []string{"juan", "vega"}},
		{name: "too many raw words", input: "a b c d e f g h i j k", wantErr: true},
		{name: "keeps allowed punctuation", input: "o'brien j.doe_x-y+z", want: []string{"o'brien", "j.doe_x-y+z"}},
		{name: "keeps non-ASCII letters", input: "José Núñez", want: []string{"josé", "núñez"}},
		{name: "all terms too short", input: "jo s", wantErr: true},
		{name: "empty", input: "   ", wantErr: true},
		{name: "too many terms", input: "aaa bbb ccc ddd eee", wantErr: true},
		{name: "too long", input: strings.Repeat("a", userSearchMaxQueryLength+1), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseUserSearchTerms(tt.input)
			if tt.wantErr {
				var validation errors.Validation
				if !stderrors.As(err, &validation) {
					t.Fatalf("expected a validation error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEscapeLucene(t *testing.T) {
	tests := map[string]string{
		"jdoe":          "jdoe",
		"j.doe@x.org":   "j.doe@x.org",
		"a+b":           `a\+b`,
		"first-last":    `first\-last`,
		`a"b`:           `a\"b`,
		"(x)":           `\(x\)`,
		"a&&b||c":       `a\&\&b\|\|c`,
		`back\slash`:    `back\\slash`,
		"wild*card?":    `wild\*card\?`,
		"path/with:col": `path\/with\:col`,
	}
	for input, want := range tests {
		if got := escapeLucene(input); got != want {
			t.Errorf("escapeLucene(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestBuildUserSearchQuery(t *testing.T) {
	tests := []struct {
		name  string
		terms []string
		want  string
	}{
		{
			name:  "single term searches every field",
			terms: []string{"jdoe"},
			want: `(name:jdoe* OR given_name:jdoe* OR family_name:jdoe* OR username:jdoe* OR identities.user_id:jdoe* OR email:jdoe*)` +
				` AND identities.connection:"Username-Password-Authentication"`,
		},
		{
			name:  "terms are AND-ed",
			terms: []string{"john", "smith"},
			want: `(name:john* OR given_name:john* OR family_name:john* OR username:john* OR identities.user_id:john* OR email:john*)` +
				` AND (name:smith* OR given_name:smith* OR family_name:smith* OR username:smith* OR identities.user_id:smith* OR email:smith*)` +
				` AND identities.connection:"Username-Password-Authentication"`,
		},
		{
			name:  "email term only searches email",
			terms: []string{"jdoe@exa"},
			want:  `email:jdoe@exa* AND identities.connection:"Username-Password-Authentication"`,
		},
		{
			name:  "operators are escaped",
			terms: []string{"a)or(b"},
			want: `(name:a\)or\(b* OR given_name:a\)or\(b* OR family_name:a\)or\(b* OR username:a\)or\(b* OR identities.user_id:a\)or\(b* OR email:a\)or\(b*)` +
				` AND identities.connection:"Username-Password-Authentication"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildUserSearchQuery(tt.terms); got != tt.want {
				t.Fatalf("got\n%s\nwant\n%s", got, tt.want)
			}
		})
	}
}

func TestClampUserSearchLimit(t *testing.T) {
	for limit, want := range map[int]int{-1: userSearchDefaultLimit, 0: userSearchDefaultLimit, 5: 5, userSearchMaxLimit: userSearchMaxLimit, 1000: userSearchMaxLimit} {
		if got := clampUserSearchLimit(limit); got != want {
			t.Errorf("clampUserSearchLimit(%d) = %d, want %d", limit, got, want)
		}
	}
}

func lfidIdentity(username string) Auth0Identity {
	return Auth0Identity{Connection: constants.Auth0UsernamePasswordConnection, UserID: username}
}

func TestToUserSearchResults(t *testing.T) {
	users := []Auth0User{
		{UserID: "auth0|a", Username: "alice", Name: "Alice A", Email: "alice@example.com", EmailVerified: true, Identities: []Auth0Identity{lfidIdentity("alice")}},
		// Root username empty: falls back to the LFID identity.
		{UserID: "auth0|b", GivenName: "Bob", FamilyName: "B", Email: "bob@example.com", EmailVerified: true, Identities: []Auth0Identity{lfidIdentity("bob")}},
		// Unverified root email is never surfaced.
		{UserID: "auth0|c", Username: "carol", Name: "Carol C", Email: "carol@example.com", Identities: []Auth0Identity{lfidIdentity("carol")}},
		// No LFID (social only): dropped.
		{UserID: "github|d", Username: "dave", Name: "Dave D", Email: "dave@example.com", EmailVerified: true, Identities: []Auth0Identity{{Connection: "github", UserID: "123"}}},
		// Linked account whose root username is the social primary's, not the LFID.
		{UserID: "github|f", Username: "social-handle", Name: "Frank F", Email: "frank@example.com", EmailVerified: true, Identities: []Auth0Identity{{Connection: "github", UserID: "123"}, lfidIdentity("linkedlfid")}},
		// Matched an email identity and an LFID identity on different identities: still has an LFID.
		{UserID: "auth0|e", Username: "erin", Identities: []Auth0Identity{{Connection: constants.EmailConnection, UserID: "x"}, lfidIdentity("erin")}},
	}

	got := toUserSearchResults(users)
	want := []model.UserSearchResult{
		{UserID: "auth0|a", Username: "alice", Name: "Alice A", Email: "alice@example.com"},
		{UserID: "auth0|b", Username: "bob", Name: "Bob B", Email: "bob@example.com"},
		{UserID: "auth0|c", Username: "carol", Name: "Carol C"},
		{UserID: "github|f", Username: "linkedlfid", Name: "Frank F", Email: "frank@example.com"},
		{UserID: "auth0|e", Username: "erin"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d results %+v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("result %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestRankUserSearchResults(t *testing.T) {
	results := []model.UserSearchResult{
		{Username: "zed", Name: "John Smith"},
		{Username: "johnny", Email: "x@example.com"},
		{Username: "aaa", Email: "john@example.com"},
		{Username: "john"},
		{Username: "bbb", Email: "johnson@example.com"},
	}
	got := rankUserSearchResults(results, []string{"john"})

	var order []string
	for _, r := range got {
		order = append(order, r.Username)
	}
	// exact username, username prefix, email prefix (aaa then bbb by username), other.
	want := "john,johnny,aaa,bbb,zed"
	if strings.Join(order, ",") != want {
		t.Fatalf("order = %s, want %s", strings.Join(order, ","), want)
	}
}

// fakeManagementAPI records Management API requests and answers searches.
type fakeManagementAPI struct {
	mu       sync.Mutex
	requests []*http.Request
	status   int
	body     string
	// respond, when set, chooses the status and body from the q parameter.
	respond func(q string) (int, string)
}

func (f *fakeManagementAPI) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, req)
	status, body := f.status, f.body
	if f.respond != nil {
		status, body = f.respond(req.URL.Query().Get("q"))
	}
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

func (f *fakeManagementAPI) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

type searchTokenSource struct {
	token string
	err   error
}

func (f searchTokenSource) GetToken(context.Context) (string, error) { return f.token, f.err }

func newTestUserSearch(t *testing.T, api *fakeManagementAPI, tokens managementTokenSource) (*userSearch, *rsa.PrivateKey) {
	t.Helper()
	tenantKey := generateKey(t)
	fa := &fakeAuth0{}
	fa.publish(t, map[string]*rsa.PrivateKey{testTenantKID: tenantKey})
	flow := newTestImpersonationFlow(t, fa, newTestClock())

	return &userSearch{
		domain:     testImpersonationDomain,
		authorizer: flow,
		tokens:     tokens,
		httpClient: newUserSearchHTTPClient(api),
	}, tenantKey
}

func TestSearchUsers_ReturnsRankedLFIDUsers(t *testing.T) {
	api := &fakeManagementAPI{body: `[
		{"user_id":"auth0|2","username":"johnny","name":"Johnny B","email":"jb@example.com","email_verified":true,"identities":[{"connection":"Username-Password-Authentication","user_id":"johnny"}]},
		{"user_id":"auth0|1","username":"john","name":"John Smith","email":"john@example.com","email_verified":true,"identities":[{"connection":"Username-Password-Authentication","user_id":"john"}]},
		{"user_id":"github|3","username":"social","name":"John Social","identities":[{"connection":"github","user_id":"3"}]}
	]`}
	search, tenantKey := newTestUserSearch(t, api, searchTokenSource{token: "m2m-token"})
	token := signRS256(t, tenantKey, testTenantKID, subjectClaims(nil))

	got, err := search.SearchUsers(context.Background(), token, "John Smith", 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[0].Username != "john" || got[1].Username != "johnny" {
		t.Fatalf("unexpected results: %+v", got)
	}

	if api.count() != 1 {
		t.Fatalf("expected one Management API call, got %d", api.count())
	}
	req := api.requests[0]
	if req.Method != http.MethodGet || req.URL.Path != "/api/v2/users" {
		t.Errorf("unexpected request %s %s", req.Method, req.URL.Path)
	}
	if auth := req.Header.Get("Authorization"); auth != "Bearer m2m-token" {
		t.Errorf("the M2M token must be used, not the caller's token; got %q", auth)
	}
	q := req.URL.Query()
	if q.Get("search_engine") != "v3" || q.Get("per_page") != "10" {
		t.Errorf("unexpected params: %v", q)
	}
	if !strings.Contains(q.Get("q"), "(name:john* OR") || !strings.Contains(q.Get("q"), "(name:smith* OR") {
		t.Errorf("unexpected q: %s", q.Get("q"))
	}
	if strings.Contains(req.URL.RawQuery, "John") {
		t.Errorf("terms must be lowercased: %s", req.URL.RawQuery)
	}
}

func TestSearchUsers_TruncatesToLimit(t *testing.T) {
	api := &fakeManagementAPI{body: `[
		{"user_id":"auth0|1","username":"aaa1","identities":[{"connection":"Username-Password-Authentication","user_id":"aaa1"}]},
		{"user_id":"auth0|2","username":"aaa2","identities":[{"connection":"Username-Password-Authentication","user_id":"aaa2"}]},
		{"user_id":"auth0|3","username":"aaa3","identities":[{"connection":"Username-Password-Authentication","user_id":"aaa3"}]}
	]`}
	search, tenantKey := newTestUserSearch(t, api, searchTokenSource{token: "m2m-token"})
	token := signRS256(t, tenantKey, testTenantKID, subjectClaims(nil))

	got, err := search.SearchUsers(context.Background(), token, "aaa", 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 results, got %d", len(got))
	}
	if per := api.requests[0].URL.Query().Get("per_page"); per != "4" {
		t.Errorf("expected over-fetch of limit*2, got per_page=%s", per)
	}
}

// An unauthorized caller must never reach the Management API, whatever its query.
func TestSearchUsers_RejectsUnauthorizedCallers(t *testing.T) {
	tenantKey := generateKey(t)
	otherKey := generateKey(t)

	tests := []struct {
		name  string
		token func() string
		want  string
	}{
		{"empty token", func() string { return "" }, "unauthorized"},
		{"not a JWT", func() string { return "not-a-token" }, "unauthorized"},
		{"forged signature", func() string {
			return signRS256(t, otherKey, testTenantKID, subjectClaims(nil))
		}, "unauthorized"},
		{"wrong audience", func() string {
			return signRS256(t, tenantKey, testTenantKID, subjectClaims(func(c jwt.MapClaims) { c["aud"] = []string{"https://other"} }))
		}, "unauthorized"},
		{"expired", func() string {
			return signRS256(t, tenantKey, testTenantKID, subjectClaims(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }))
		}, "unauthorized"},
		{"missing can_impersonate", func() string {
			return signRS256(t, tenantKey, testTenantKID, subjectClaims(func(c jwt.MapClaims) { delete(c, canImpersonateClaim) }))
		}, "forbidden"},
		{"can_impersonate not boolean true", func() string {
			return signRS256(t, tenantKey, testTenantKID, subjectClaims(func(c jwt.MapClaims) { c[canImpersonateClaim] = "true" }))
		}, "forbidden"},
		{"can_impersonate false", func() string {
			return signRS256(t, tenantKey, testTenantKID, subjectClaims(func(c jwt.MapClaims) { c[canImpersonateClaim] = false }))
		}, "forbidden"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := &fakeManagementAPI{body: `[]`}
			fa := &fakeAuth0{}
			fa.publish(t, map[string]*rsa.PrivateKey{testTenantKID: tenantKey})
			search := &userSearch{
				domain:     testImpersonationDomain,
				authorizer: newTestImpersonationFlow(t, fa, newTestClock()),
				tokens:     searchTokenSource{token: "m2m-token"},
				httpClient: newUserSearchHTTPClient(api),
			}

			_, err := search.SearchUsers(context.Background(), tt.token(), "john", 10)
			if err == nil {
				t.Fatal("expected an error")
			}
			switch tt.want {
			case "unauthorized":
				var target errors.Unauthorized
				if !stderrors.As(err, &target) {
					t.Fatalf("expected Unauthorized, got %T: %v", err, err)
				}
			case "forbidden":
				var target errors.Forbidden
				if !stderrors.As(err, &target) {
					t.Fatalf("expected Forbidden, got %T: %v", err, err)
				}
			}
			if api.count() != 0 {
				t.Fatalf("Management API must not be called for an unauthorized caller, got %d calls", api.count())
			}
		})
	}
}

func TestSearchUsers_ValidatesQueryAfterAuthorizing(t *testing.T) {
	api := &fakeManagementAPI{body: `[]`}
	search, tenantKey := newTestUserSearch(t, api, searchTokenSource{token: "m2m-token"})
	token := signRS256(t, tenantKey, testTenantKID, subjectClaims(nil))

	_, err := search.SearchUsers(context.Background(), token, "jo", 10)
	var validation errors.Validation
	if !stderrors.As(err, &validation) {
		t.Fatalf("expected a validation error, got %v", err)
	}
	if api.count() != 0 {
		t.Fatalf("an invalid query must not reach Auth0")
	}
}

func TestSearchUsers_UpstreamFailureDoesNotLeakDetails(t *testing.T) {
	api := &fakeManagementAPI{status: http.StatusServiceUnavailable, body: `{"message":"query john@example.com timed out"}`}
	search, tenantKey := newTestUserSearch(t, api, searchTokenSource{token: "m2m-token"})
	token := signRS256(t, tenantKey, testTenantKID, subjectClaims(nil))

	_, err := search.SearchUsers(context.Background(), token, "john", 10)
	var unavailable errors.ServiceUnavailable
	if !stderrors.As(err, &unavailable) {
		t.Fatalf("expected ServiceUnavailable, got %T: %v", err, err)
	}
	if strings.Contains(err.Error(), "john") {
		t.Errorf("error must not echo the query: %v", err)
	}
}

func TestSearchUsers_TokenFailure(t *testing.T) {
	api := &fakeManagementAPI{body: `[]`}
	search, tenantKey := newTestUserSearch(t, api, searchTokenSource{err: stderrors.New("boom: client_secret rejected")})
	token := signRS256(t, tenantKey, testTenantKID, subjectClaims(nil))

	_, err := search.SearchUsers(context.Background(), token, "john", 10)
	var unavailable errors.ServiceUnavailable
	if !stderrors.As(err, &unavailable) {
		t.Fatalf("expected ServiceUnavailable, got %T: %v", err, err)
	}
	if strings.Contains(err.Error(), "boom") {
		t.Errorf("the token error must not reach the caller: %v", err)
	}
	if api.count() != 0 {
		t.Fatal("no search without an M2M token")
	}
}

// Input must stay inside the q parameter, whatever characters it contains.
func TestSearchUsers_InputCannotInjectParameters(t *testing.T) {
	api := &fakeManagementAPI{body: `[]`}
	search, tenantKey := newTestUserSearch(t, api, searchTokenSource{token: "m2m-token"})
	token := signRS256(t, tenantKey, testTenantKID, subjectClaims(nil))

	if _, err := search.SearchUsers(context.Background(), token, "abc&per_page=1000", 10); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	q := api.requests[0].URL.Query()
	if q.Get("per_page") != "20" || q.Get("fields") != userSearchFields {
		t.Fatalf("input injected parameters: per_page=%s fields=%s", q.Get("per_page"), q.Get("fields"))
	}
}

const lfidUser = `{"user_id":"auth0|%s","username":"%s","name":"%s","email":"%s@example.com","email_verified":true,"identities":[{"connection":"Username-Password-Authentication","user_id":"%s"}]}`

func userJSON(id string) string {
	return strings.NewReplacer("%s", id).Replace(lfidUser)
}

// A short exact LFID must surface even when Auth0's unranked prefix page does
// not contain it.
func TestSearchUsers_ExactUsernameOutsidePrefixPage(t *testing.T) {
	api := &fakeManagementAPI{respond: func(q string) (int, string) {
		if strings.HasPrefix(q, "(username:john OR") {
			return 200, "[" + userJSON("john") + "]"
		}
		// The prefix page: many other users, not the exact one.
		return 200, "[" + userJSON("johnny") + "," + userJSON("johnson") + "]"
	}}
	search, tenantKey := newTestUserSearch(t, api, searchTokenSource{token: "m2m-token"})
	token := signRS256(t, tenantKey, testTenantKID, subjectClaims(nil))

	got, err := search.SearchUsers(context.Background(), token, "john", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 || got[0].Username != "john" {
		t.Fatalf("the exact username must rank first, got %+v", got)
	}
	if api.count() != 2 {
		t.Fatalf("expected the prefix and the exact query, got %d calls", api.count())
	}
}

func TestSearchUsers_ExactEmailLookup(t *testing.T) {
	var exactQueries []string
	api := &fakeManagementAPI{respond: func(q string) (int, string) {
		if !strings.Contains(q, "*") {
			exactQueries = append(exactQueries, q)
			return 200, "[" + userJSON("jdoe") + "]"
		}
		return 200, "[]"
	}}
	search, tenantKey := newTestUserSearch(t, api, searchTokenSource{token: "m2m-token"})
	token := signRS256(t, tenantKey, testTenantKID, subjectClaims(nil))

	got, err := search.SearchUsers(context.Background(), token, "jdoe@example.com", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Username != "jdoe" {
		t.Fatalf("unexpected results: %+v", got)
	}
	if len(exactQueries) != 1 || exactQueries[0] != `email:jdoe@example.com AND identities.connection:"Username-Password-Authentication"` {
		t.Fatalf("unexpected exact query: %v", exactQueries)
	}
}

func TestSearchUsers_ExactLookupDedupesAndToleratesFailure(t *testing.T) {
	t.Run("same user from both queries appears once", func(t *testing.T) {
		api := &fakeManagementAPI{body: "[" + userJSON("john") + "]"}
		search, tenantKey := newTestUserSearch(t, api, searchTokenSource{token: "m2m-token"})
		token := signRS256(t, tenantKey, testTenantKID, subjectClaims(nil))

		got, err := search.SearchUsers(context.Background(), token, "john", 10)
		if err != nil || len(got) != 1 {
			t.Fatalf("got %+v, err %v", got, err)
		}
	})

	t.Run("a failed exact lookup falls back to the prefix page", func(t *testing.T) {
		api := &fakeManagementAPI{respond: func(q string) (int, string) {
			if strings.HasPrefix(q, "(username:john OR") {
				return http.StatusServiceUnavailable, "{}"
			}
			return 200, "[" + userJSON("johnny") + "]"
		}}
		search, tenantKey := newTestUserSearch(t, api, searchTokenSource{token: "m2m-token"})
		token := signRS256(t, tenantKey, testTenantKID, subjectClaims(nil))

		got, err := search.SearchUsers(context.Background(), token, "john", 10)
		if err != nil || len(got) != 1 || got[0].Username != "johnny" {
			t.Fatalf("got %+v, err %v", got, err)
		}
	})
}

func TestSearchUsers_MultipleTermsHaveNoExactLookup(t *testing.T) {
	api := &fakeManagementAPI{body: "[]"}
	search, tenantKey := newTestUserSearch(t, api, searchTokenSource{token: "m2m-token"})
	token := signRS256(t, tenantKey, testTenantKID, subjectClaims(nil))

	if _, err := search.SearchUsers(context.Background(), token, "john smith", 10); err != nil {
		t.Fatal(err)
	}
	if api.count() != 1 {
		t.Fatalf("expected only the prefix query, got %d calls", api.count())
	}
}

func TestBuildExactUserSearchQuery(t *testing.T) {
	if q, ok := buildExactUserSearchQuery([]string{"jdoe"}); !ok ||
		q != `(username:jdoe OR identities.user_id:jdoe) AND identities.connection:"Username-Password-Authentication"` {
		t.Errorf("got %q, %v", q, ok)
	}
	if q, ok := buildExactUserSearchQuery([]string{"a.b@x.org"}); !ok ||
		q != `email:a.b@x.org AND identities.connection:"Username-Password-Authentication"` {
		t.Errorf("got %q, %v", q, ok)
	}
	if _, ok := buildExactUserSearchQuery([]string{"john", "smith"}); ok {
		t.Error("several terms have no single exact value")
	}
}

// Search terms are other people's names and emails, so they must not reach
// traces: client spans record the full request URL.
func TestUserSearchHTTPClient_KeepsQueriesOutOfTraces(t *testing.T) {
	api := &fakeManagementAPI{body: `[]`}
	call := func(client *httpclient.Client) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, "https://"+testImpersonationDomain+"/api/v2/users?q=email%3Asecret.person%40example.com", nil)
		if _, err := client.Do(context.Background(), httpclient.Request{Method: req.Method, URL: req.URL.String()}); err != nil {
			t.Fatalf("request failed: %v", err)
		}
	}

	t.Run("user search client records no span", func(t *testing.T) {
		recorder := tracetest.NewSpanRecorder()
		provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
		call(newUserSearchHTTPClient(api, otelhttp.WithTracerProvider(provider)))
		if n := len(recorder.Ended()); n != 0 {
			t.Fatalf("expected no spans, got %d", n)
		}
	})

	// Control: the default client does record the URL, so the test above proves something.
	t.Run("default client records the URL", func(t *testing.T) {
		recorder := tracetest.NewSpanRecorder()
		provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
		call(httpclient.NewClient(httpclient.Config{
			Timeout:     5 * time.Second,
			Transport:   api,
			OTelOptions: []otelhttp.Option{otelhttp.WithTracerProvider(provider)},
		}))
		spans := recorder.Ended()
		if len(spans) != 1 {
			t.Fatalf("expected one span, got %d", len(spans))
		}
		found := false
		for _, attr := range spans[0].Attributes() {
			if strings.Contains(attr.Value.Emit(), "secret.person") {
				found = true
			}
		}
		if !found {
			t.Fatal("control: expected the default client's span to carry the query")
		}
	})
}
