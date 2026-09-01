// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// userSearchTransport answers a search with a canned body and keeps the URL it
// was asked for, so a test can assert what was actually sent to Auth0.
type userSearchTransport struct {
	status int
	body   string
	header http.Header
	urls   []*url.URL
}

func (u *userSearchTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u.urls = append(u.urls, req.URL)

	status := u.status
	if status == 0 {
		status = http.StatusOK
	}
	body := u.body
	if body == "" {
		body = "[]"
	}
	header := u.header
	if header == nil {
		header = make(http.Header)
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     header,
	}, nil
}

func newTestUserSearcher(transport http.RoundTripper) port.UserSearcher {
	searcher, err := NewUserSearcher(
		httpclient.Config{Transport: transport, MaxRetries: 0},
		Config{
			Domain:          "test-tenant.auth0.com",
			M2MTokenManager: &TokenManager{tokenSource: fakeTokenSource{token: "test-m2m-token"}},
		},
	)
	if err != nil {
		panic(err)
	}
	return searcher
}

func TestNewUserSearcherValidation(t *testing.T) {
	t.Run("a missing token manager is refused at construction", func(t *testing.T) {
		_, err := NewUserSearcher(httpclient.DefaultConfig(), Config{Domain: "test.auth0.com"})
		require.Error(t, err, "misconfiguration must surface here, not on the first request")
	})

	t.Run("a missing domain is refused at construction", func(t *testing.T) {
		_, err := NewUserSearcher(httpclient.DefaultConfig(), Config{
			M2MTokenManager: &TokenManager{tokenSource: fakeTokenSource{token: "t"}},
		})
		require.Error(t, err)
	})
}

func TestSearchUsersSendsTheQueryVerbatim(t *testing.T) {
	// A marked copy of the canonical population-sweep query. If this string is
	// ever rewritten in transit the sweep silently selects a different cohort,
	// so the assertion is on byte equality rather than on a shape.
	const canonical = `identities.connection:"Username-Password-Authentication" AND ` +
		`email_verified:true AND NOT app_metadata.cdp_uuid_source=* AND ` +
		`updated_at:[2026-08-01T00:00:00Z TO *]`

	transport := &userSearchTransport{}
	searcher := newTestUserSearcher(transport)

	_, err := searcher.SearchUsers(context.Background(), port.UserSearch{
		Query:   canonical,
		Page:    0,
		PerPage: 20,
	})
	require.NoError(t, err)
	require.Len(t, transport.urls, 1)

	query := transport.urls[0].Query()
	assert.Equal(t, canonical, query.Get("q"),
		"the query must reach Auth0 exactly as the caller wrote it")
	assert.Equal(t, "v3", query.Get("search_engine"),
		"field-existence and range clauses need the v3 engine")
	assert.Equal(t, "updated_at:1", query.Get("sort"),
		"ascending order is what makes the last row a usable lower bound")
	assert.Equal(t, "20", query.Get("per_page"))
	assert.Equal(t, "0", query.Get("page"))
	assert.Equal(t, "false", query.Get("include_totals"),
		"totals would wrap the array and count against the 1000 cap regardless")
}

func TestSearchUsersRejectsAnEmptyQuery(t *testing.T) {
	transport := &userSearchTransport{}
	searcher := newTestUserSearcher(transport)

	_, err := searcher.SearchUsers(context.Background(), port.UserSearch{Query: "   "})
	require.Error(t, err)
	assert.Empty(t, transport.urls, "an empty query must not reach Auth0")
}

func TestSearchUsersDefaultsThePageSize(t *testing.T) {
	transport := &userSearchTransport{}
	searcher := newTestUserSearcher(transport)

	_, err := searcher.SearchUsers(context.Background(), port.UserSearch{Query: "email_verified:true"})
	require.NoError(t, err)
	require.Len(t, transport.urls, 1)
	assert.Equal(t, "20", transport.urls[0].Query().Get("per_page"))
}

func TestSearchUsersMapsTheResponse(t *testing.T) {
	transport := &userSearchTransport{body: `[
	  {
	    "user_id": "auth0|db-user",
	    "username": "lfid-alice",
	    "email": "alice@example.org",
	    "email_verified": true,
	    "updated_at": "2026-08-17T09:30:00.123Z",
	    "identities": [{"connection": "Username-Password-Authentication", "provider": "auth0"}],
	    "app_metadata": {
	      "cdp_uuid_source": "login-resolve",
	      "cdp_uuid_checked_at": "2026-08-17T09:30:00Z"
	    }
	  }
	]`}
	searcher := newTestUserSearcher(transport)

	users, err := searcher.SearchUsers(context.Background(), port.UserSearch{Query: "email_verified:true"})
	require.NoError(t, err)
	require.Len(t, users, 1)

	user := users[0]
	assert.Equal(t, "auth0|db-user", user.UserID)
	assert.Equal(t, "lfid-alice", user.Username)
	assert.Equal(t, "alice@example.org", user.Email)
	assert.True(t, user.EmailVerified)
	assert.Equal(t, time.Date(2026, 8, 17, 9, 30, 0, 123000000, time.UTC), user.UpdatedAt)
	assert.Empty(t, user.UUID, "a no-match row carries a source with no uuid")
	assert.Equal(t, "login-resolve", user.Source)
	assert.Equal(t, "2026-08-17T09:30:00Z", user.CheckedAt)
}

func TestSearchUsersLeavesUsernameEmptyForASocialOnlyUser(t *testing.T) {
	// A social provider's nickname is not an LFID. Handing it to `resolve`
	// would produce a miss that then gets cached as a no-match for somebody
	// who was never actually looked up.
	transport := &userSearchTransport{body: `[
	  {
	    "user_id": "google-oauth2|123",
	    "username": "not-an-lfid",
	    "email": "bob@example.org",
	    "email_verified": true,
	    "updated_at": "2026-08-17T09:30:00Z",
	    "identities": [{"connection": "google-oauth2", "provider": "google-oauth2", "isSocial": true}]
	  }
	]`}
	searcher := newTestUserSearcher(transport)

	users, err := searcher.SearchUsers(context.Background(), port.UserSearch{Query: "email_verified:true"})
	require.NoError(t, err)
	require.Len(t, users, 1)
	assert.Empty(t, users[0].Username,
		"only a database-connection identity carries an LFID")
}

func TestSearchUsersReportsAnUnparseableTimestampAsZero(t *testing.T) {
	transport := &userSearchTransport{body: `[
	  {"user_id": "auth0|x", "updated_at": "not-a-timestamp", "identities": []}
	]`}
	searcher := newTestUserSearcher(transport)

	users, err := searcher.SearchUsers(context.Background(), port.UserSearch{Query: "email_verified:true"})
	require.NoError(t, err)
	require.Len(t, users, 1)
	assert.True(t, users[0].UpdatedAt.IsZero(),
		"a caller must be able to tell it cannot advance a cursor past this row")
}

func TestSearchUsersReportsRateLimitingAsTheSharedTypedError(t *testing.T) {
	header := make(http.Header)
	header.Set("Retry-After", "42")
	transport := &userSearchTransport{status: http.StatusTooManyRequests, header: header}
	searcher := newTestUserSearcher(transport)

	_, err := searcher.SearchUsers(context.Background(), port.UserSearch{Query: "email_verified:true"})
	require.Error(t, err)

	var rateLimited errors.RateLimited
	require.ErrorAs(t, err, &rateLimited,
		"callers pace themselves off this type; a plain error would be retried blindly")
}

func TestSearchUsersReportsOtherFailuresAsErrors(t *testing.T) {
	// A rejected search is not an empty cohort. Returning no users here would
	// let a sweep advance its cursor over a range it never actually read.
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusInternalServerError} {
		transport := &userSearchTransport{status: status}
		searcher := newTestUserSearcher(transport)

		users, err := searcher.SearchUsers(context.Background(), port.UserSearch{Query: "email_verified:true"})
		require.Error(t, err, "status %d must be an error", status)
		assert.Empty(t, users)
	}
}
