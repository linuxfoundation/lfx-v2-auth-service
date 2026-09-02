// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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

		population, err := walker.listCDPUUIDHolders(context.Background())
		require.NoError(t, err)
		require.Len(t, population, 3)
		assert.Equal(t, "uuid-1", population[0].StoredUUID)
		assert.Equal(t, "uuid-2", population[1].StoredUUID)
		assert.Equal(t, "uuid-3", population[2].StoredUUID)
		require.GreaterOrEqual(t, len(queries), 2)
		assert.Contains(t, queries[0], "app_metadata.cdp_uuid%3D%2A")
		assert.Contains(t, queries[0], "updated_at%3A%5B1970-01-01T00%3A00%3A00.000Z+TO+%2A%5D")
		assert.Contains(t, queries[1], "updated_at%3A%5B2026-01-02T00%3A00%3A00.000Z+TO+%2A%5D")
	})
}

func TestReportExitCode(t *testing.T) {
	t.Run("zero when every sampled user agrees", func(t *testing.T) {
		code := reportExitCode(report{Counts: map[string]int{"agree_single": 1}})
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
}
