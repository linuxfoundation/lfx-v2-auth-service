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

	t.Run("unverified identity is ignored", func(t *testing.T) {
		ok := identityMatchesUser(user, []cdp.MemberIdentity{{
			Platform: "lfid",
			Type:     "username",
			Value:    "psmith",
			Verified: false,
		}})
		assert.False(t, ok)
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
		assert.Contains(t, queries[0], "app_metadata.cdp_uuid%3D%2A")
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

	t.Run("drains a full page of one shared updated_at with deeper pages", func(t *testing.T) {
		const tie = "2026-01-01T00:00:00.000Z"
		tiePage := make([]mgmtUser, walkPageSize)
		for i := range tiePage {
			tiePage[i] = mgmtUser{
				UserID:      fmt.Sprintf("auth0|tie-%03d", i),
				Username:    fmt.Sprintf("tie%03d", i),
				UpdatedAt:   tie,
				AppMetadata: map[string]any{"cdp_uuid": fmt.Sprintf("uuid-tie-%03d", i)},
			}
		}
		tail := []mgmtUser{{
			UserID:      "auth0|after",
			Username:    "after",
			UpdatedAt:   "2026-01-02T00:00:00.000Z",
			AppMetadata: map[string]any{"cdp_uuid": "uuid-after"},
		}}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			page := r.URL.Query().Get("page")
			q := r.URL.Query().Get("q")
			switch {
			case strings.Contains(q, "1970-01-01"):
				// The whole population starts at one shared timestamp.
				require.NoError(t, json.NewEncoder(w).Encode(tiePage))
			case strings.Contains(q, "2026-01-01") && page == "0":
				// The inclusive bound re-presents the full tie page: the
				// bound cannot advance, forcing the deeper-page drain.
				require.NoError(t, json.NewEncoder(w).Encode(tiePage))
			case strings.Contains(q, "2026-01-01") && page == "1":
				require.NoError(t, json.NewEncoder(w).Encode(tail))
			case strings.Contains(q, "2026-01-02"):
				require.NoError(t, json.NewEncoder(w).Encode(tail))
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
		assert.Len(t, population, walkPageSize+1, "the tie block and the row after it are all enumerated")
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
