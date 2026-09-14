// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"errors"
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

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/auth0/holderwalk"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/cdp"
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

	t.Run("email match ignores platform and the member identity's verified flag; only the Auth0 email-verified flag gates", func(t *testing.T) {
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

	t.Run("unverified member identity never matches, mirroring resolve", func(t *testing.T) {
		ok := identityMatchesUser(user, []cdp.MemberIdentity{{
			Platform: "lfid",
			Type:     "username",
			Value:    "psmith",
			Verified: false,
		}})
		assert.False(t, ok, "resolve filters verified=true; an unverified identity cannot have produced the 409")
	})

	t.Run("identity values are trimmed before comparison", func(t *testing.T) {
		ok := identityMatchesUser(user, []cdp.MemberIdentity{{
			Platform: "lfid",
			Type:     "username",
			Value:    "  psmith \n",
			Verified: true,
		}})
		assert.True(t, ok, "resolve trims identity values; the gate must not diverge")
	})
}

func TestCheckUser(t *testing.T) {
	ctx := context.Background()
	pace := holderwalk.NewLimiter(6000)

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

	t.Run("reports unresolvable when resolve returns 404 but the stored member still exists", func(t *testing.T) {
		client := stubCDPClient{
			resolveFn: func(context.Context, string, string) (cdp.ResolveResult, error) {
				return cdp.ResolveResult{Outcome: cdp.OutcomeNoMatch}, nil
			},
			listFn: func(_ context.Context, memberID string) ([]cdp.MemberIdentity, error) {
				assert.Equal(t, "member-a", memberID)
				return []cdp.MemberIdentity{}, nil
			},
		}
		verdict, _, err := checkUser(ctx, client, pace, baseUser)
		require.NoError(t, err)
		assert.Equal(t, verdictUnresolvable, verdict)
	})

	t.Run("reports member gone when resolve returns 404 and the stored member is deleted", func(t *testing.T) {
		client := stubCDPClient{
			resolveFn: func(context.Context, string, string) (cdp.ResolveResult, error) {
				return cdp.ResolveResult{Outcome: cdp.OutcomeNoMatch}, nil
			},
			listFn: func(context.Context, string) ([]cdp.MemberIdentity, error) {
				return nil, cdp.ErrMemberNotFound
			},
		}
		verdict, _, err := checkUser(ctx, client, pace, baseUser)
		require.NoError(t, err)
		assert.Equal(t, verdictDisagreeGone, verdict)
	})

	t.Run("reports an error when the no-match membership read fails", func(t *testing.T) {
		client := stubCDPClient{
			resolveFn: func(context.Context, string, string) (cdp.ResolveResult, error) {
				return cdp.ResolveResult{Outcome: cdp.OutcomeNoMatch}, nil
			},
			listFn: func(context.Context, string) ([]cdp.MemberIdentity, error) {
				return nil, errors.New("boom")
			},
		}
		verdict, _, err := checkUser(ctx, client, pace, baseUser)
		require.Error(t, err)
		assert.Equal(t, verdictError, verdict)
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
func populationServer(t *testing.T, users []holderwalk.MgmtUser) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("q"), "1970-01-01") {
			require.NoError(t, json.NewEncoder(w).Encode(users))
			return
		}
		require.NoError(t, json.NewEncoder(w).Encode([]holderwalk.MgmtUser{}))
	}))
}

func testRunClients(t *testing.T, client cdp.Client, server *httptest.Server) func(context.Context) (cdp.Client, *holderwalk.Walker, error) {
	t.Helper()
	target, err := url.Parse(server.URL)
	require.NoError(t, err)
	return func(context.Context) (cdp.Client, *holderwalk.Walker, error) {
		walker := &holderwalk.Walker{
			HTTPClient: httpclient.NewClient(httpclient.Config{
				Transport: &rewriteTransport{target: target, inner: server.Client().Transport},
			}),
			Domain:       "tenant.auth0.com",
			Tokens:       fakeTokenProvider{token: "mgmt-token"},
			RetryBackoff: time.Millisecond,
		}
		return client, walker, nil
	}
}

func TestRun(t *testing.T) {
	mkUser := func(i int, uuid any) holderwalk.MgmtUser {
		return holderwalk.MgmtUser{
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
		server := populationServer(t, []holderwalk.MgmtUser{mkUser(1, "uuid-1"), mkUser(2, "uuid-2"), mkUser(3, "uuid-3")})
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
		server := populationServer(t, []holderwalk.MgmtUser{
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
		server := populationServer(t, []holderwalk.MgmtUser{mkUser(1, "uuid-1"), mkUser(2, "uuid-2")})
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
		server := populationServer(t, []holderwalk.MgmtUser{mkUser(1, "uuid-1"), mkUser(2, 42)})
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
