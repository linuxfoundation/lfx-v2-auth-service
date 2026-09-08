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
	t.Run("walks with updated_at bounds and deduplicates overlap", func(t *testing.T) {
		pageOne := []MgmtUser{{
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
		pageTwo := []MgmtUser{{
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
				require.NoError(t, json.NewEncoder(w).Encode([]MgmtUser{}))
			}
		}))
		defer server.Close()

		target, err := url.Parse(server.URL)
		require.NoError(t, err)

		walker := &Walker{
			HTTPClient: httpclient.NewClient(httpclient.Config{
				Transport: &rewriteTransport{target: target, inner: server.Client().Transport},
			}),
			Domain: "tenant.auth0.com",
			Tokens: fakeTokenProvider{token: "mgmt-token"},
		}

		population, malformed, err := walker.ListCDPUUIDHolders(context.Background())
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

		target, err := url.Parse(server.URL)
		require.NoError(t, err)

		walker := &Walker{
			HTTPClient: httpclient.NewClient(httpclient.Config{
				Transport: &rewriteTransport{target: target, inner: server.Client().Transport},
			}),
			Domain: "tenant.auth0.com",
			Tokens: fakeTokenProvider{token: "mgmt-token"},
		}

		population, malformed, err := walker.ListCDPUUIDHolders(context.Background())
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

	newTieWalker := func(t *testing.T, server *httptest.Server) *Walker {
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
		}
	}

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

		population, malformed, err := newTieWalker(t, server).ListCDPUUIDHolders(context.Background())
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

		_, _, err := newTieWalker(t, server).ListCDPUUIDHolders(context.Background())
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

		_, _, err := newTieWalker(t, server).ListCDPUUIDHolders(context.Background())
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
			require.NoError(t, json.NewEncoder(w).Encode([]MgmtUser{}))
		}))
		defer server.Close()

		population, malformed, err := newTieWalker(t, server).ListCDPUUIDHolders(context.Background())
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

		_, _, err := newTieWalker(t, server).ListCDPUUIDHolders(context.Background())
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
