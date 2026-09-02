// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/cdp"
	lferrors "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
)

type stubCDPClient struct {
	resolveFn func(ctx context.Context, lfid, verifiedEmail string) (cdp.ResolveResult, error)
	listFn    func(ctx context.Context, memberID string) ([]cdp.MemberIdentity, error)
}

func (s stubCDPClient) Resolve(ctx context.Context, lfid, verifiedEmail string) (cdp.ResolveResult, error) {
	return s.resolveFn(ctx, lfid, verifiedEmail)
}

func (s stubCDPClient) ListIdentities(ctx context.Context, memberID string) ([]cdp.MemberIdentity, error) {
	return s.listFn(ctx, memberID)
}

func (s stubCDPClient) CreateMember(context.Context, string, cdp.Identity) (cdp.CreateResult, error) {
	panic("unexpected CreateMember call")
}

func (s stubCDPClient) AttachIdentity(context.Context, string, cdp.Identity) (cdp.AttachResult, error) {
	panic("unexpected AttachIdentity call")
}

type fakeTokenProvider struct {
	token string
	err   error
}

func (f fakeTokenProvider) GetToken(context.Context) (string, error) {
	return f.token, f.err
}

type rewriteTransport struct {
	target *url.URL
	inner  http.RoundTripper
}

func (rt *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = rt.target.Scheme
	req.URL.Host = rt.target.Host
	return rt.inner.RoundTrip(req)
}

// flakyTransport drops the first `failures` requests before the wire, the way
// a transport error surfaces to the retry loop as a negative status.
type flakyTransport struct {
	failures int
	calls    int
	inner    http.RoundTripper
}

func (ft *flakyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ft.calls++
	if ft.calls <= ft.failures {
		return nil, fmt.Errorf("connection dropped")
	}
	return ft.inner.RoundTrip(req)
}

func TestRequiredSampleSize(t *testing.T) {
	t.Run("default gate sizing is 99% confidence below 0.1%", func(t *testing.T) {
		n, err := requiredSampleSize(0.99, 0.001)
		require.NoError(t, err)
		assert.Equal(t, 4603, n)
	})

	t.Run("rejects invalid confidence", func(t *testing.T) {
		_, err := requiredSampleSize(1.0, 0.001)
		require.Error(t, err)
	})

	t.Run("rejects invalid ceiling", func(t *testing.T) {
		_, err := requiredSampleSize(0.99, 0)
		require.Error(t, err)
	})

	t.Run("rejects a ceiling too small to sample", func(t *testing.T) {
		// 1-1e-20 rounds to 1; plain Log would divide by zero and the cast
		// would go negative. Log1p keeps the size finite and the bound
		// rejects it.
		_, err := requiredSampleSize(0.99, 1e-20)
		require.Error(t, err)
	})

	t.Run("rejects NaN inputs", func(t *testing.T) {
		// NaN passes plain range checks (every comparison is false) and
		// would panic sampleUsers via a negative n.
		_, err := requiredSampleSize(math.NaN(), 0.001)
		require.Error(t, err)
		_, err = requiredSampleSize(0.99, math.NaN())
		require.Error(t, err)
	})
}

func TestSampleUsers(t *testing.T) {
	population := []gateUser{
		{UserID: "auth0|1", StoredUUID: "aaa"},
		{UserID: "auth0|2", StoredUUID: "bbb"},
		{UserID: "auth0|3", StoredUUID: "ccc"},
		{UserID: "auth0|4", StoredUUID: "ddd"},
	}

	t.Run("deterministic for a fixed seed", func(t *testing.T) {
		first := sampleUsers(population, 2, 42)
		second := sampleUsers(population, 2, 42)
		assert.Equal(t, first, second)
		assert.Len(t, first, 2)
	})

	t.Run("census when n exceeds population", func(t *testing.T) {
		sampled := sampleUsers(population, 10, 1)
		assert.Equal(t, population, sampled)
	})
}

func TestSplitCheckable(t *testing.T) {
	population := []gateUser{
		{UserID: "auth0|1", Username: "alice"},
		{UserID: "google-oauth2|2"},
		{UserID: "auth0|3", Username: "  "},
		{UserID: "auth0|4", Username: "dave"},
	}
	checkable, skipped := splitCheckable(population)
	assert.Equal(t, 2, skipped)
	require.Len(t, checkable, 2)
	assert.Equal(t, "alice", checkable[0].Username)
	assert.Equal(t, "dave", checkable[1].Username)
}

func TestBoundedRetryAfter(t *testing.T) {
	assert.Equal(t, defaultRateLimitWait, boundedRetryAfter(0), "missing hint falls back to the default")
	assert.Equal(t, 30*time.Second, boundedRetryAfter(30*time.Second), "sane hint is honored")
	assert.Equal(t, maxRateLimitWait, boundedRetryAfter(12*time.Hour), "oversized hint is clamped")
}

func TestIdentityMatchesUser(t *testing.T) {
	user := gateUser{
		Username:      "psmith",
		Email:         "P@Example.org",
		EmailVerified: true,
	}

	t.Run("LFID match is platform-qualified and case-insensitive", func(t *testing.T) {
		ok := identityMatchesUser(user, []cdp.MemberIdentity{{
			Platform: "lfid",
			Type:     "username",
			Value:    "PSMITH",
			Verified: true,
		}})
		assert.True(t, ok)
	})

	t.Run("email match ignores platform and requires verified email on both sides", func(t *testing.T) {
		ok := identityMatchesUser(user, []cdp.MemberIdentity{{
			Type:     "email",
			Value:    "p@example.org",
			Verified: true,
		}})
		assert.True(t, ok)
	})

	t.Run("unverified email on the user is not consulted", func(t *testing.T) {
		unverified := user
		unverified.EmailVerified = false
		ok := identityMatchesUser(unverified, []cdp.MemberIdentity{{
			Type:     "email",
			Value:    "p@example.org",
			Verified: true,
		}})
		assert.False(t, ok)
	})

	t.Run("unverified member identity still matches, mirroring holdsLFID", func(t *testing.T) {
		ok := identityMatchesUser(user, []cdp.MemberIdentity{{
			Platform: "lfid",
			Type:     "username",
			Value:    "psmith",
			Verified: false,
		}})
		assert.True(t, ok, "provisioning's holdsLFID never gates on verified")
	})

	t.Run("identity values are trimmed before comparison", func(t *testing.T) {
		ok := identityMatchesUser(user, []cdp.MemberIdentity{{
			Platform: "lfid",
			Type:     "username",
			Value:    "  psmith \n",
		}})
		assert.True(t, ok, "provisioning trims identity values; the gate must not diverge")
	})
}

func TestCheckUser(t *testing.T) {
	ctx := context.Background()
	pace := newLimiter(6000)

	baseUser := gateUser{
		UserID:        "auth0|1",
		Username:      "psmith",
		Email:         "p@example.org",
		EmailVerified: true,
		StoredUUID:    "member-a",
	}

	t.Run("skips users with no LFID username", func(t *testing.T) {
		user := baseUser
		user.Username = ""
		verdict, _, err := checkUser(ctx, stubCDPClient{}, pace, user)
		require.NoError(t, err)
		assert.Equal(t, verdictSkippedNoLFID, verdict)
	})

	t.Run("agrees on a single match", func(t *testing.T) {
		client := stubCDPClient{
			resolveFn: func(_ context.Context, lfid, email string) (cdp.ResolveResult, error) {
				assert.Equal(t, "psmith", lfid)
				assert.Equal(t, "p@example.org", email)
				return cdp.ResolveResult{Outcome: cdp.OutcomeFound, MemberID: "member-a"}, nil
			},
		}
		verdict, resolved, err := checkUser(ctx, client, pace, baseUser)
		require.NoError(t, err)
		assert.Equal(t, verdictAgreeSingle, verdict)
		assert.Equal(t, "member-a", resolved)
	})

	t.Run("does not send email when Auth0 says it is unverified", func(t *testing.T) {
		user := baseUser
		user.EmailVerified = false
		client := stubCDPClient{
			resolveFn: func(_ context.Context, _, email string) (cdp.ResolveResult, error) {
				assert.Empty(t, email)
				return cdp.ResolveResult{Outcome: cdp.OutcomeFound, MemberID: "member-a"}, nil
			},
		}
		verdict, _, err := checkUser(ctx, client, pace, user)
		require.NoError(t, err)
		assert.Equal(t, verdictAgreeSingle, verdict)
	})

	t.Run("disagrees when resolve returns a different member", func(t *testing.T) {
		client := stubCDPClient{
			resolveFn: func(context.Context, string, string) (cdp.ResolveResult, error) {
				return cdp.ResolveResult{Outcome: cdp.OutcomeFound, MemberID: "member-b"}, nil
			},
		}
		verdict, resolved, err := checkUser(ctx, client, pace, baseUser)
		require.NoError(t, err)
		assert.Equal(t, verdictDisagreeOther, verdict)
		assert.Equal(t, "member-b", resolved)
	})

	t.Run("reports unresolvable when resolve returns 404", func(t *testing.T) {
		client := stubCDPClient{
			resolveFn: func(context.Context, string, string) (cdp.ResolveResult, error) {
				return cdp.ResolveResult{Outcome: cdp.OutcomeNoMatch}, nil
			},
		}
		verdict, _, err := checkUser(ctx, client, pace, baseUser)
		require.NoError(t, err)
		assert.Equal(t, verdictUnresolvable, verdict)
	})

	t.Run("agrees on multi-match when stored member still matches", func(t *testing.T) {
		client := stubCDPClient{
			resolveFn: func(context.Context, string, string) (cdp.ResolveResult, error) {
				return cdp.ResolveResult{Outcome: cdp.OutcomeConflict}, nil
			},
			listFn: func(_ context.Context, memberID string) ([]cdp.MemberIdentity, error) {
				assert.Equal(t, "member-a", memberID)
				return []cdp.MemberIdentity{{
					Platform: "lfid",
					Type:     "username",
					Value:    "psmith",
					Verified: true,
				}}, nil
			},
		}
		verdict, resolved, err := checkUser(ctx, client, pace, baseUser)
		require.NoError(t, err)
		assert.Equal(t, verdictAgreeMulti, verdict)
		assert.Equal(t, "member-a", resolved)
	})

	t.Run("disagrees on multi-match when stored member no longer matches", func(t *testing.T) {
		client := stubCDPClient{
			resolveFn: func(context.Context, string, string) (cdp.ResolveResult, error) {
				return cdp.ResolveResult{Outcome: cdp.OutcomeConflict}, nil
			},
			listFn: func(context.Context, string) ([]cdp.MemberIdentity, error) {
				return []cdp.MemberIdentity{{
					Platform: "lfid",
					Type:     "username",
					Value:    "someone-else",
					Verified: true,
				}}, nil
			},
		}
		verdict, _, err := checkUser(ctx, client, pace, baseUser)
		require.NoError(t, err)
		assert.Equal(t, verdictDisagreeOther, verdict)
	})

	t.Run("reports member gone when identity list returns 404", func(t *testing.T) {
		client := stubCDPClient{
			resolveFn: func(context.Context, string, string) (cdp.ResolveResult, error) {
				return cdp.ResolveResult{Outcome: cdp.OutcomeConflict}, nil
			},
			listFn: func(context.Context, string) ([]cdp.MemberIdentity, error) {
				return nil, cdp.ErrMemberNotFound
			},
		}
		verdict, _, err := checkUser(ctx, client, pace, baseUser)
		require.NoError(t, err)
		assert.Equal(t, verdictDisagreeGone, verdict)
	})
}

func TestCallWithRateLimitRetry(t *testing.T) {
	ctx := context.Background()
	pace := newLimiter(6000)

	t.Run("waits and retries on bare RateLimited", func(t *testing.T) {
		attempts := 0
		start := time.Now()
		result, err := callWithRateLimitRetry(ctx, pace, func(context.Context) (string, error) {
			attempts++
			if attempts == 1 {
				return "", lferrors.NewRateLimited("rate limited", 10*time.Millisecond)
			}
			return "ok", nil
		})
		require.NoError(t, err)
		assert.Equal(t, "ok", result)
		assert.Equal(t, 2, attempts)
		assert.GreaterOrEqual(t, time.Since(start), 10*time.Millisecond)
	})

	t.Run("returns the last error once retries are exhausted", func(t *testing.T) {
		attempts := 0
		_, err := callWithRateLimitRetry(ctx, pace, func(context.Context) (string, error) {
			attempts++
			return "", lferrors.NewRateLimited("rate limited", time.Millisecond)
		})
		require.Error(t, err)
		assert.Equal(t, cdpCallMaxAttempts, attempts)
	})
}

func TestPopulationWalker(t *testing.T) {
	t.Run("walks with updated_at bounds and deduplicates overlap", func(t *testing.T) {
		pageOne := []mgmtUser{{
			UserID:    "auth0|1",
			Username:  "alice",
			UpdatedAt: "2026-01-01T00:00:00.000Z",
			AppMetadata: map[string]any{
				"cdp_uuid": "UUID-1",
			},
		}, {
			UserID:    "auth0|2",
			Username:  "bob",
			UpdatedAt: "2026-01-02T00:00:00.000Z",
			AppMetadata: map[string]any{
				"cdp_uuid": "uuid-2",
			},
		}}
		pageTwo := []mgmtUser{{
			UserID:    "auth0|2",
			Username:  "bob",
			UpdatedAt: "2026-01-02T00:00:00.000Z",
			AppMetadata: map[string]any{
				"cdp_uuid": "uuid-2",
			},
		}, {
			UserID:    "auth0|3",
			Username:  "carol",
			UpdatedAt: "2026-01-03T00:00:00.000Z",
			AppMetadata: map[string]any{
				"cdp_uuid": "uuid-3",
			},
		}}

		var queries []string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			queries = append(queries, r.URL.RawQuery)
			switch {
			case strings.Contains(r.URL.RawQuery, "1970-01-01"):
				require.NoError(t, json.NewEncoder(w).Encode(pageOne))
			case strings.Contains(r.URL.RawQuery, "2026-01-02"):
				require.NoError(t, json.NewEncoder(w).Encode(pageTwo))
			default:
				require.NoError(t, json.NewEncoder(w).Encode([]mgmtUser{}))
			}
		}))
		defer server.Close()

		target, err := url.Parse(server.URL)
		require.NoError(t, err)

		walker := &populationWalker{
			httpClient: httpclient.NewClient(httpclient.Config{
				Transport: &rewriteTransport{target: target, inner: server.Client().Transport},
			}),
			domain: "tenant.auth0.com",
			tokens: fakeTokenProvider{token: "mgmt-token"},
		}

		population, malformed, err := walker.listCDPUUIDHolders(context.Background())
		require.NoError(t, err)
		assert.Empty(t, malformed)
		require.Len(t, population, 3)
		assert.Equal(t, "uuid-1", population[0].StoredUUID)
		assert.Equal(t, "uuid-2", population[1].StoredUUID)
		assert.Equal(t, "uuid-3", population[2].StoredUUID)
		require.GreaterOrEqual(t, len(queries), 2)
		assert.Contains(t, queries[0], "_exists_%3Aapp_metadata.cdp_uuid")
		assert.Contains(t, queries[0], "updated_at%3A%5B1970-01-01T00%3A00%3A00.000Z+TO+%2A%5D")
		assert.Contains(t, queries[1], "updated_at%3A%5B2026-01-02T00%3A00%3A00.000Z+TO+%2A%5D")
	})

	t.Run("reports malformed cdp_uuid holders and blanks non-database usernames", func(t *testing.T) {
		page := []mgmtUser{{
			UserID:      "auth0|bad",
			Username:    "mallory",
			UpdatedAt:   "2026-01-01T00:00:00.000Z",
			AppMetadata: map[string]any{"cdp_uuid": 42},
		}, {
			UserID:      "google-oauth2|123",
			Username:    "social-handle",
			UpdatedAt:   "2026-01-02T00:00:00.000Z",
			AppMetadata: map[string]any{"cdp_uuid": "uuid-social"},
		}}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.RawQuery, "1970-01-01") {
				require.NoError(t, json.NewEncoder(w).Encode(page))
				return
			}
			require.NoError(t, json.NewEncoder(w).Encode([]mgmtUser{}))
		}))
		defer server.Close()

		target, err := url.Parse(server.URL)
		require.NoError(t, err)

		walker := &populationWalker{
			httpClient: httpclient.NewClient(httpclient.Config{
				Transport: &rewriteTransport{target: target, inner: server.Client().Transport},
			}),
			domain: "tenant.auth0.com",
			tokens: fakeTokenProvider{token: "mgmt-token"},
		}

		population, malformed, err := walker.listCDPUUIDHolders(context.Background())
		require.NoError(t, err)
		assert.Equal(t, []string{"auth0|bad"}, malformed)
		require.Len(t, population, 1)
		assert.Equal(t, "google-oauth2|123", population[0].UserID)
		assert.Empty(t, population[0].Username, "a social-primary root username is not an LFID")
	})

	newTieWalker := func(t *testing.T, server *httptest.Server) *populationWalker {
		t.Helper()
		target, err := url.Parse(server.URL)
		require.NoError(t, err)
		return &populationWalker{
			httpClient: httpclient.NewClient(httpclient.Config{
				Transport: &rewriteTransport{target: target, inner: server.Client().Transport},
			}),
			domain:       "tenant.auth0.com",
			tokens:       fakeTokenProvider{token: "mgmt-token"},
			retryBackoff: time.Millisecond,
		}
	}

	const tie = "2026-01-01T00:00:00.000Z"
	makeTiePage := func() []mgmtUser {
		tiePage := make([]mgmtUser, walkPageSize)
		for i := range tiePage {
			tiePage[i] = mgmtUser{
				UserID:      fmt.Sprintf("auth0|tie-%03d", i),
				Username:    fmt.Sprintf("tie%03d", i),
				UpdatedAt:   tie,
				AppMetadata: map[string]any{"cdp_uuid": fmt.Sprintf("uuid-tie-%03d", i)},
			}
		}
		return tiePage
	}

	t.Run("drains a full page of one shared updated_at with a count-verified exact query", func(t *testing.T) {
		tiePage := makeTiePage()
		tail := []mgmtUser{{
			UserID:      "auth0|after",
			Username:    "after",
			UpdatedAt:   "2026-01-02T00:00:00.000Z",
			AppMetadata: map[string]any{"cdp_uuid": "uuid-after"},
		}}

		var sawDrain, sawExclusive bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query().Get("q")
			switch {
			case strings.Contains(q, "1970-01-01"):
				// The whole population starts at one shared timestamp.
				require.NoError(t, json.NewEncoder(w).Encode(tiePage))
			case r.URL.Query().Get("include_totals") == "true":
				// The exact-timestamp drain, verified against the total.
				sawDrain = true
				require.Contains(t, q, fmt.Sprintf("updated_at:[%s TO %s]", tie, tie))
				require.NoError(t, json.NewEncoder(w).Encode(mgmtUserPage{Total: len(tiePage), Users: tiePage}))
			case strings.Contains(q, "updated_at:{"+tie):
				// The exclusive bound steps strictly past the drained block.
				sawExclusive = true
				require.NoError(t, json.NewEncoder(w).Encode(tail))
			case strings.Contains(q, "updated_at:["+tie):
				// The inclusive bound re-presents the full tie page: the
				// bound cannot advance, forcing the drain.
				require.NoError(t, json.NewEncoder(w).Encode(tiePage))
			case strings.Contains(q, "2026-01-02"):
				require.NoError(t, json.NewEncoder(w).Encode(tail))
			default:
				require.NoError(t, json.NewEncoder(w).Encode([]mgmtUser{}))
			}
		}))
		defer server.Close()

		population, malformed, err := newTieWalker(t, server).listCDPUUIDHolders(context.Background())
		require.NoError(t, err)
		assert.Empty(t, malformed)
		assert.Len(t, population, walkPageSize+1, "the tie block and the row after it are all enumerated")
		assert.True(t, sawDrain, "the tie block must be drained through the exact-timestamp query")
		assert.True(t, sawExclusive, "the walk must resume strictly past the drained timestamp")
	})

	t.Run("fails when a tie block cannot be proven complete", func(t *testing.T) {
		tiePage := makeTiePage()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("include_totals") == "true" {
				// One more holder than any pass ever returns — the reshuffle
				// omission the count check exists to catch.
				require.NoError(t, json.NewEncoder(w).Encode(mgmtUserPage{Total: len(tiePage) + 1, Users: tiePage}))
				return
			}
			require.NoError(t, json.NewEncoder(w).Encode(tiePage))
		}))
		defer server.Close()

		_, _, err := newTieWalker(t, server).listCDPUUIDHolders(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "incomplete after")
	})

	t.Run("aborts a tie block past Auth0's 1,000-result window", func(t *testing.T) {
		tiePage := makeTiePage()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("include_totals") == "true" {
				require.NoError(t, json.NewEncoder(w).Encode(mgmtUserPage{Total: walkOffsetLimit + 1, Users: tiePage}))
				return
			}
			require.NoError(t, json.NewEncoder(w).Encode(tiePage))
		}))
		defer server.Close()

		_, _, err := newTieWalker(t, server).listCDPUUIDHolders(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot enumerate")
	})

	t.Run("retries a 5xx page and succeeds", func(t *testing.T) {
		var calls int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			if calls == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			require.NoError(t, json.NewEncoder(w).Encode([]mgmtUser{}))
		}))
		defer server.Close()

		population, malformed, err := newTieWalker(t, server).listCDPUUIDHolders(context.Background())
		require.NoError(t, err)
		assert.Empty(t, population)
		assert.Empty(t, malformed)
		assert.Equal(t, 2, calls, "the transient 503 is retried exactly once")
	})

	t.Run("fails immediately on a non-retryable 4xx", func(t *testing.T) {
		var calls int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.WriteHeader(http.StatusBadRequest)
		}))
		defer server.Close()

		_, _, err := newTieWalker(t, server).listCDPUUIDHolders(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "status code: 400")
		assert.Equal(t, 1, calls, "a 4xx is a caller bug, never retried")
	})

	t.Run("retries a transport failure like a 5xx", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			require.NoError(t, json.NewEncoder(w).Encode([]mgmtUser{}))
		}))
		defer server.Close()

		target, err := url.Parse(server.URL)
		require.NoError(t, err)
		transport := &flakyTransport{
			failures: 1,
			inner:    &rewriteTransport{target: target, inner: server.Client().Transport},
		}
		walker := &populationWalker{
			httpClient:   httpclient.NewClient(httpclient.Config{Transport: transport}),
			domain:       "tenant.auth0.com",
			tokens:       fakeTokenProvider{token: "mgmt-token"},
			retryBackoff: time.Millisecond,
		}

		population, malformed, errWalk := walker.listCDPUUIDHolders(context.Background())
		require.NoError(t, errWalk)
		assert.Empty(t, population)
		assert.Empty(t, malformed)
		assert.Equal(t, 2, transport.calls, "the dropped connection is retried")
	})
}

func TestReportExitCode(t *testing.T) {
	t.Run("zero when every sampled user agrees", func(t *testing.T) {
		code := reportExitCode(report{SampleSize: 1, Counts: map[string]int{"agree_single": 1}})
		assert.Equal(t, 0, code)
	})

	t.Run("one when a disagreement or unresolvable user is present", func(t *testing.T) {
		assert.Equal(t, 1, reportExitCode(report{Disagreements: []disagreement{{Kind: "disagree_other_member"}}}))
		assert.Equal(t, 1, reportExitCode(report{Unresolvable: []string{"auth0|1"}}))
	})

	t.Run("two when the run is inconclusive", func(t *testing.T) {
		assert.Equal(t, 2, reportExitCode(report{Errors: []checkError{{UserID: "auth0|1"}}}))
		assert.Equal(t, 2, reportExitCode(report{Unchecked: 3}))
	})

	t.Run("a disagreement outranks an inconclusive error", func(t *testing.T) {
		code := reportExitCode(report{
			Disagreements: []disagreement{{Kind: "disagree_other_member"}},
			Errors:        []checkError{{UserID: "auth0|1"}},
		})
		assert.Equal(t, 1, code, "the hard failure must not be masked by the re-run-to-settle code")
	})

	t.Run("two when the enumeration carried warnings", func(t *testing.T) {
		code := reportExitCode(report{
			SampleSize:          1,
			Counts:              map[string]int{"agree_single": 1},
			EnumerationWarnings: []checkError{{UserID: "auth0|junk"}},
		})
		assert.Equal(t, 2, code, "an unreadable stored value is never assumed to agree")
	})

	t.Run("two when no user was actually checked", func(t *testing.T) {
		assert.Equal(t, 2, reportExitCode(report{DryRun: true, SampleSize: 5, Counts: map[string]int{}}), "dry run")
		assert.Equal(t, 2, reportExitCode(report{Counts: map[string]int{}}), "empty population")
		assert.Equal(t, 2, reportExitCode(report{SampleSize: 2, Counts: map[string]int{"skipped_no_lfid": 2}}), "all skipped")
	})
}

func TestWriteReportRestrictsPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0o644))

	require.NoError(t, writeReport(report{Counts: map[string]int{}}, path))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

// populationServer serves one page of holders for the initial bound and an
// empty page for every later query.
func populationServer(t *testing.T, users []mgmtUser) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("q"), "1970-01-01") {
			require.NoError(t, json.NewEncoder(w).Encode(users))
			return
		}
		require.NoError(t, json.NewEncoder(w).Encode([]mgmtUser{}))
	}))
}

func testRunClients(t *testing.T, client cdp.Client, server *httptest.Server) func(context.Context) (cdp.Client, *populationWalker, error) {
	t.Helper()
	target, err := url.Parse(server.URL)
	require.NoError(t, err)
	return func(context.Context) (cdp.Client, *populationWalker, error) {
		walker := &populationWalker{
			httpClient: httpclient.NewClient(httpclient.Config{
				Transport: &rewriteTransport{target: target, inner: server.Client().Transport},
			}),
			domain:       "tenant.auth0.com",
			tokens:       fakeTokenProvider{token: "mgmt-token"},
			retryBackoff: time.Millisecond,
		}
		return client, walker, nil
	}
}

func TestRun(t *testing.T) {
	mkUser := func(i int, uuid any) mgmtUser {
		return mgmtUser{
			UserID:        fmt.Sprintf("auth0|u%d", i),
			Username:      fmt.Sprintf("user%d", i),
			Email:         fmt.Sprintf("u%d@example.org", i),
			EmailVerified: true,
			UpdatedAt:     fmt.Sprintf("2026-01-0%dT00:00:00.000Z", i),
			AppMetadata:   map[string]any{"cdp_uuid": uuid},
		}
	}
	// agreeingClient resolves userN to uuid-N, the value mkUser stores.
	agreeingClient := stubCDPClient{
		resolveFn: func(_ context.Context, lfid, _ string) (cdp.ResolveResult, error) {
			return cdp.ResolveResult{Outcome: cdp.OutcomeFound, MemberID: "uuid-" + strings.TrimPrefix(lfid, "user")}, nil
		},
	}
	readReport := func(t *testing.T, path string) report {
		t.Helper()
		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		var rep report
		require.NoError(t, json.Unmarshal(raw, &rep))
		return rep
	}

	t.Run("census agreement exits 0 with the requested confidence", func(t *testing.T) {
		server := populationServer(t, []mgmtUser{mkUser(1, "uuid-1"), mkUser(2, "uuid-2"), mkUser(3, "uuid-3")})
		defer server.Close()
		outPath := filepath.Join(t.TempDir(), "report.json")

		code, err := run(context.Background(), testRunClients(t, agreeingClient, server), 0.99, 0.5, 0, 6000, false, 42, outPath)
		require.NoError(t, err)
		assert.Equal(t, 0, code)

		rep := readReport(t, outPath)
		assert.True(t, rep.Census, "the whole checkable population fits under the derived n")
		assert.InDelta(t, 0.99, rep.Confidence, 1e-9, "a census retains the requested confidence")
		assert.Equal(t, 3, rep.Counts[string(verdictAgreeSingle)])
	})

	t.Run("undersized override reports the achieved confidence", func(t *testing.T) {
		server := populationServer(t, []mgmtUser{
			mkUser(1, "uuid-1"), mkUser(2, "uuid-2"), mkUser(3, "uuid-3"), mkUser(4, "uuid-4"), mkUser(5, "uuid-5"),
		})
		defer server.Close()
		outPath := filepath.Join(t.TempDir(), "report.json")

		code, err := run(context.Background(), testRunClients(t, agreeingClient, server), 0.99, 0.5, 2, 6000, false, 42, outPath)
		require.NoError(t, err)
		assert.Equal(t, 0, code)

		rep := readReport(t, outPath)
		assert.False(t, rep.Census)
		assert.Equal(t, 2, rep.SampleSize)
		assert.InDelta(t, 0.75, rep.Confidence, 1e-9, "n=2 at ceiling 0.5 proves 1-(1-0.5)^2, not the requested 0.99")
	})

	t.Run("a disagreement beside an error still exits 1", func(t *testing.T) {
		server := populationServer(t, []mgmtUser{mkUser(1, "uuid-1"), mkUser(2, "uuid-2")})
		defer server.Close()
		client := stubCDPClient{
			resolveFn: func(_ context.Context, lfid, _ string) (cdp.ResolveResult, error) {
				if lfid == "user1" {
					return cdp.ResolveResult{Outcome: cdp.OutcomeFound, MemberID: "uuid-other"}, nil
				}
				return cdp.ResolveResult{}, fmt.Errorf("cdp unavailable")
			},
		}
		outPath := filepath.Join(t.TempDir(), "report.json")

		code, err := run(context.Background(), testRunClients(t, client, server), 0.99, 0.5, 0, 6000, false, 42, outPath)
		require.NoError(t, err)
		assert.Equal(t, 1, code, "the hard failure outranks the inconclusive error")

		rep := readReport(t, outPath)
		require.Len(t, rep.Disagreements, 1)
		require.Len(t, rep.Errors, 1)
	})

	t.Run("a malformed stored value is an enumeration warning, not a check error", func(t *testing.T) {
		server := populationServer(t, []mgmtUser{mkUser(1, "uuid-1"), mkUser(2, 42)})
		defer server.Close()
		outPath := filepath.Join(t.TempDir(), "report.json")

		code, err := run(context.Background(), testRunClients(t, agreeingClient, server), 0.99, 0.5, 0, 6000, false, 42, outPath)
		require.NoError(t, err)
		assert.Equal(t, 2, code, "an unreadable stored value keeps the run inconclusive")

		rep := readReport(t, outPath)
		require.Len(t, rep.EnumerationWarnings, 1)
		assert.Equal(t, "auth0|u2", rep.EnumerationWarnings[0].UserID)
		assert.Empty(t, rep.Errors, "enumeration warnings stay apart from per-user check errors")
		assert.Equal(t, 1, rep.Counts[string(verdictAgreeSingle)], "the readable holder is still checked")
	})
}
