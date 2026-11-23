// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package holderwalk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	lferrors "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
)

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

func TestBoundedRetryAfter(t *testing.T) {
	assert.Equal(t, defaultRateLimitWait, BoundedRetryAfter(0), "missing hint falls back to the default")
	assert.Equal(t, 30*time.Second, BoundedRetryAfter(30*time.Second), "sane hint is honored")
	assert.Equal(t, maxRateLimitWait, BoundedRetryAfter(12*time.Hour), "oversized hint is clamped")
}

func TestCallWithRateLimitRetry(t *testing.T) {
	ctx := context.Background()
	pace := NewLimiter(6000)

	t.Run("waits and retries on bare RateLimited", func(t *testing.T) {
		attempts := 0
		start := time.Now()
		result, err := CallWithRateLimitRetry(ctx, pace, func(context.Context) (string, error) {
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
		_, err := CallWithRateLimitRetry(ctx, pace, func(context.Context) (string, error) {
			attempts++
			return "", lferrors.NewRateLimited("rate limited", time.Millisecond)
		})
		require.Error(t, err)
		assert.Equal(t, cdpCallMaxAttempts, attempts)
	})
}

func TestPopulationWalker(t *testing.T) {
	epoch, err := time.Parse(time.RFC3339Nano, walkInitialBound)
	require.NoError(t, err)
	ts := func(d time.Duration) string { return epoch.Add(d).Format(updatedAtLayout) }
	pinnedAt := func(d time.Duration) func() time.Time {
		return func() time.Time { return epoch.Add(d) }
	}
	walkerFor := func(t *testing.T, server *httptest.Server, now func() time.Time) *Walker {
		t.Helper()
		target, err := url.Parse(server.URL)
		require.NoError(t, err)
		return &Walker{
			HTTPClient: httpclient.NewClient(httpclient.Config{
				Transport: &rewriteTransport{target: target, inner: server.Client().Transport},
			}),
			Domain:       "tenant.auth0.com",
			Tokens:       fakeTokenProvider{token: "mgmt-token"},
			RetryBackoff: time.Millisecond,
			now:          now,
		}
	}
	holder := func(id, updatedAt string) MgmtUser {
		return MgmtUser{
			UserID:      "auth0|" + id,
			Username:    id,
			UpdatedAt:   updatedAt,
			AppMetadata: map[string]any{"cdp_uuid": "UUID-" + id},
		}
	}
	// queryLog serves each query from respond and records the q parameters.
	queryLog := func(t *testing.T, respond func(q string, w http.ResponseWriter)) (*httptest.Server, *[]string) {
		t.Helper()
		var queries []string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query().Get("q")
			queries = append(queries, q)
			respond(q, w)
		}))
		t.Cleanup(server.Close)
		return server, &queries
	}
	encode := func(t *testing.T, w http.ResponseWriter, rows []MgmtUser) {
		t.Helper()
		require.NoError(t, json.NewEncoder(w).Encode(rows))
	}
	rangeOf := func(lower, upper string) string {
		if upper == "*" {
			return fmt.Sprintf("%s AND updated_at:[%s TO *]", holderQuery, lower)
		}
		return fmt.Sprintf("%s AND updated_at:[%s TO %s}", holderQuery, lower, upper)
	}

	t.Run("walks with updated_at bounds and deduplicates overlap", func(t *testing.T) {
		fullPage := make([]MgmtUser, walkPageSize)
		for i := range fullPage {
			fullPage[i] = holder(fmt.Sprintf("p1-%03d", i), fmt.Sprintf("2026-01-01T00:%02d:%02d.000Z", i/60, i%60))
		}
		fullPage[0].AppMetadata["cdp_uuid"] = "UUID-MIXED-CASE"
		last := fullPage[walkPageSize-1]
		server, queries := queryLog(t, func(q string, w http.ResponseWriter) {
			switch q {
			case rangeOf(walkInitialBound, "*"):
				encode(t, w, fullPage)
			case rangeOf(last.UpdatedAt, "*"):
				// The inclusive bound re-presents the last row.
				encode(t, w, []MgmtUser{last, holder("p2", "2026-01-02T00:00:00.000Z")})
			default:
				t.Errorf("unexpected query %q", q)
				encode(t, w, nil)
			}
		})

		population, malformed, err := walkerFor(t, server, nil).ListCDPUUIDHolders(context.Background())
		require.NoError(t, err)
		assert.Empty(t, malformed)
		require.Len(t, population, walkPageSize+1, "the overlap row is counted once")
		assert.Equal(t, "uuid-mixed-case", population[0].StoredUUID)
		assert.Equal(t, "uuid-p2", population[walkPageSize].StoredUUID)
		assert.Equal(t, []string{rangeOf(walkInitialBound, "*"), rangeOf(last.UpdatedAt, "*")}, *queries,
			"an unbounded walk that Auth0 answers needs no windows")
	})

	t.Run("narrows the window on a 503 and continues without a gap", func(t *testing.T) {
		server, queries := queryLog(t, func(q string, w http.ResponseWriter) {
			switch q {
			case rangeOf(walkInitialBound, "*"):
				w.WriteHeader(http.StatusServiceUnavailable)
			case rangeOf(walkInitialBound, ts(48*time.Hour)):
				encode(t, w, []MgmtUser{holder("early", ts(time.Hour))})
			case rangeOf(ts(48*time.Hour), "*"):
				encode(t, w, []MgmtUser{holder("late", ts(72*time.Hour))})
			default:
				t.Errorf("unexpected query %q", q)
				encode(t, w, nil)
			}
		})

		population, malformed, err := walkerFor(t, server, pinnedAt(96*time.Hour)).ListCDPUUIDHolders(context.Background())
		require.NoError(t, err)
		assert.Empty(t, malformed)
		require.Len(t, population, 2)
		assert.Equal(t, []string{
			rangeOf(walkInitialBound, "*"),
			rangeOf(walkInitialBound, ts(48*time.Hour)),
			rangeOf(ts(48*time.Hour), "*"),
		}, *queries, "the 503 halves the window instead of re-sending it; the next window starts where it ended")
	})

	t.Run("keeps a narrowed window's upper bound across full pages and a tie drain", func(t *testing.T) {
		windowEnd := ts(48 * time.Hour)
		firstPage := make([]MgmtUser, walkPageSize)
		for i := range firstPage {
			firstPage[i] = holder(fmt.Sprintf("w-%03d", i), ts(time.Hour+time.Duration(i)*time.Second))
		}
		lastOfFirst := firstPage[walkPageSize-1].UpdatedAt
		tie := ts(2 * time.Hour)
		tiePage := make([]MgmtUser, walkPageSize)
		for i := range tiePage {
			tiePage[i] = holder(fmt.Sprintf("tie-%03d", i), tie)
		}
		drain := fmt.Sprintf("%s AND updated_at:[%s TO %s]", holderQuery, tie, tie)
		pastTie := fmt.Sprintf("%s AND updated_at:{%s TO %s}", holderQuery, tie, windowEnd)

		server, queries := queryLog(t, func(q string, w http.ResponseWriter) {
			switch q {
			case rangeOf(walkInitialBound, "*"):
				w.WriteHeader(http.StatusServiceUnavailable)
			case rangeOf(walkInitialBound, windowEnd):
				encode(t, w, firstPage)
			case rangeOf(lastOfFirst, windowEnd), rangeOf(tie, windowEnd):
				// A block of one shared timestamp fills the page: the first
				// read advances the bound onto it, the second cannot.
				encode(t, w, tiePage)
			case drain:
				require.NoError(t, json.NewEncoder(w).Encode(mgmtUserPage{Total: len(tiePage), Users: tiePage}))
			case pastTie:
				encode(t, w, []MgmtUser{holder("after-tie", ts(3*time.Hour))})
			case rangeOf(windowEnd, "*"):
				encode(t, w, nil)
			default:
				t.Errorf("unexpected query %q", q)
				encode(t, w, nil)
			}
		})

		population, malformed, err := walkerFor(t, server, pinnedAt(96*time.Hour)).ListCDPUUIDHolders(context.Background())
		require.NoError(t, err)
		assert.Empty(t, malformed)
		assert.Len(t, population, 2*walkPageSize+1)
		assert.Equal(t, []string{
			rangeOf(walkInitialBound, "*"),
			rangeOf(walkInitialBound, windowEnd),
			rangeOf(lastOfFirst, windowEnd),
			rangeOf(tie, windowEnd),
			drain,
			pastTie,
			rangeOf(windowEnd, "*"),
		}, *queries, "pages and the post-drain exclusive bound stay inside the narrowed window")
	})

	t.Run("grows empty windows past the cap but caps windows that held rows", func(t *testing.T) {
		const day = 24 * time.Hour
		half := 200 * day
		cases := []struct {
			name       string
			firstRows  []MgmtUser
			nextWindow string
		}{
			{"empty", nil, rangeOf(ts(half), "*")},
			{"with rows", []MgmtUser{holder("first", ts(day))}, rangeOf(ts(half), ts(half+walkMaxWindow))},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				server, queries := queryLog(t, func(q string, w http.ResponseWriter) {
					switch q {
					case rangeOf(walkInitialBound, "*"):
						w.WriteHeader(http.StatusServiceUnavailable)
					case rangeOf(walkInitialBound, ts(half)):
						encode(t, w, tc.firstRows)
					default:
						encode(t, w, nil)
					}
				})

				_, _, err := walkerFor(t, server, pinnedAt(2*half)).ListCDPUUIDHolders(context.Background())
				require.NoError(t, err)
				require.GreaterOrEqual(t, len(*queries), 3)
				assert.Equal(t, tc.nextWindow, (*queries)[2])
			})
		}
	})

	t.Run("reports malformed cdp_uuid holders, blanks bare social usernames, and derives LFIDs from linked database identities", func(t *testing.T) {
		page := []MgmtUser{{
			UserID:      "auth0|bad",
			Username:    "mallory",
			UpdatedAt:   "2026-01-01T00:00:00.000Z",
			AppMetadata: map[string]any{"cdp_uuid": 42},
		}, {
			UserID:      "google-oauth2|123",
			Username:    "social-handle",
			UpdatedAt:   "2026-01-02T00:00:00.000Z",
			AppMetadata: map[string]any{"cdp_uuid": "uuid-social"},
		}, {
			UserID:      "google-oauth2|456",
			Username:    "social-handle",
			UpdatedAt:   "2026-01-03T00:00:00.000Z",
			AppMetadata: map[string]any{"cdp_uuid": "uuid-linked"},
			Identities: []MgmtIdentity{
				{Connection: "google-oauth2", UserID: "123"},
				{Connection: "Username-Password-Authentication", UserID: "linkedlfid"},
			},
		}, {
			UserID:      "google-oauth2|789",
			Username:    "social-handle",
			UpdatedAt:   "2026-01-04T00:00:00.000Z",
			AppMetadata: map[string]any{"cdp_uuid": "uuid-nonstring"},
			Identities: []MgmtIdentity{
				{Connection: "Username-Password-Authentication", UserID: 42},
			},
		}}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.RawQuery, "1970-01-01") {
				require.NoError(t, json.NewEncoder(w).Encode(page))
				return
			}
			require.NoError(t, json.NewEncoder(w).Encode([]MgmtUser{}))
		}))
		defer server.Close()

		population, malformed, err := walkerFor(t, server, nil).ListCDPUUIDHolders(context.Background())
		require.NoError(t, err)
		assert.Equal(t, []string{"auth0|bad"}, malformed)
		require.Len(t, population, 3)
		assert.Equal(t, "google-oauth2|123", population[0].UserID)
		assert.Empty(t, population[0].Username, "a social-primary root username is not an LFID")
		assert.Equal(t, "google-oauth2|456", population[1].UserID)
		assert.Equal(t, "linkedlfid", population[1].Username, "a linked database identity carries the LFID")
		assert.Equal(t, "google-oauth2|789", population[2].UserID)
		assert.Empty(t, population[2].Username, "a non-string database user id derives nothing")
	})

	const tie = "2026-01-01T00:00:00.000Z"
	makeTiePage := func() []MgmtUser {
		tiePage := make([]MgmtUser, walkPageSize)
		for i := range tiePage {
			tiePage[i] = MgmtUser{
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
		tail := []MgmtUser{{
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
				require.NoError(t, json.NewEncoder(w).Encode([]MgmtUser{}))
			}
		}))
		defer server.Close()

		population, malformed, err := walkerFor(t, server, nil).ListCDPUUIDHolders(context.Background())
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

		_, _, err := walkerFor(t, server, nil).ListCDPUUIDHolders(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "incomplete after")
	})

	t.Run("fails closed on a tie block at Auth0's 1,000-result cap", func(t *testing.T) {
		tiePage := makeTiePage()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("include_totals") == "true" {
				// Auth0 caps the reported total at the window itself, so the
				// cap is the largest value the guard will ever see.
				require.NoError(t, json.NewEncoder(w).Encode(mgmtUserPage{Total: walkOffsetLimit, Users: tiePage}))
				return
			}
			require.NoError(t, json.NewEncoder(w).Encode(tiePage))
		}))
		defer server.Close()

		_, _, err := walkerFor(t, server, nil).ListCDPUUIDHolders(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot enumerate")
	})

	t.Run("retries a 503 with backoff once the window cannot narrow", func(t *testing.T) {
		var calls int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			if calls == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			require.NoError(t, json.NewEncoder(w).Encode([]MgmtUser{}))
		}))
		defer server.Close()

		// Started within walkMinWindow of the initial bound: nothing is left
		// to halve, so the 503 is treated as an outage.
		population, malformed, err := walkerFor(t, server, pinnedAt(30*time.Second)).ListCDPUUIDHolders(context.Background())
		require.NoError(t, err)
		assert.Empty(t, population)
		assert.Empty(t, malformed)
		assert.Equal(t, 2, calls, "the 503 is retried exactly once")
	})

	t.Run("fails immediately on a non-retryable 4xx", func(t *testing.T) {
		var calls int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.WriteHeader(http.StatusBadRequest)
		}))
		defer server.Close()

		_, _, err := walkerFor(t, server, nil).ListCDPUUIDHolders(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "status code: 400")
		assert.Equal(t, 1, calls, "a 4xx is a caller bug, never retried")
	})

	t.Run("retries a transport failure like a 5xx", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			require.NoError(t, json.NewEncoder(w).Encode([]MgmtUser{}))
		}))
		defer server.Close()

		target, err := url.Parse(server.URL)
		require.NoError(t, err)
		transport := &flakyTransport{
			failures: 1,
			inner:    &rewriteTransport{target: target, inner: server.Client().Transport},
		}
		walker := &Walker{
			HTTPClient:   httpclient.NewClient(httpclient.Config{Transport: transport}),
			Domain:       "tenant.auth0.com",
			Tokens:       fakeTokenProvider{token: "mgmt-token"},
			RetryBackoff: time.Millisecond,
		}

		population, malformed, errWalk := walker.ListCDPUUIDHolders(context.Background())
		require.NoError(t, errWalk)
		assert.Empty(t, population)
		assert.Empty(t, malformed)
		assert.Equal(t, 2, transport.calls, "the dropped connection is retried")
	})
}
