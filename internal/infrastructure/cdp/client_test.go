// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package cdp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
)

// fakeTokenProvider returns a fixed token.
type fakeTokenProvider struct {
	token string
	err   error
}

func (f fakeTokenProvider) GetToken(_ context.Context) (string, error) {
	return f.token, f.err
}

// recordingTransport answers with a canned status and body, recording the
// requests it saw so tests can assert on the wire format.
type recordingTransport struct {
	status   int
	body     string
	header   http.Header
	requests []recordedRequest
}

type recordedRequest struct {
	method string
	url    string
	auth   string
	body   string
}

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	recorded := recordedRequest{
		method: req.Method,
		url:    req.URL.String(),
		auth:   req.Header.Get("Authorization"),
	}
	if req.Body != nil {
		raw, _ := io.ReadAll(req.Body)
		recorded.body = string(raw)
	}
	r.requests = append(r.requests, recorded)

	body := r.body
	if body == "" {
		body = "{}"
	}
	header := r.header
	if header == nil {
		header = make(http.Header)
	}
	return &http.Response{
		StatusCode: r.status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     header,
	}, nil
}

func newTestClient(transport *recordingTransport) Client {
	return NewClient(Config{
		BaseURL:      "https://cdp.example.org",
		TokenManager: fakeTokenProvider{token: "test-token"},
		Transport:    transport,
	})
}

func TestResolve(t *testing.T) {
	t.Run("200 returns the member id", func(t *testing.T) {
		transport := &recordingTransport{status: http.StatusOK, body: `{"memberId":"abc-123"}`}
		result, err := newTestClient(transport).Resolve(context.Background(), "psmith", "p@example.org")

		require.NoError(t, err)
		assert.Equal(t, OutcomeFound, result.Outcome)
		assert.Equal(t, "abc-123", result.MemberID)

		require.Len(t, transport.requests, 1)
		assert.Equal(t, http.MethodPost, transport.requests[0].method)
		assert.Equal(t, "https://cdp.example.org/v1/members/resolve", transport.requests[0].url)
		assert.Equal(t, "Bearer test-token", transport.requests[0].auth)

		var sent resolveRequest
		require.NoError(t, json.Unmarshal([]byte(transport.requests[0].body), &sent))
		assert.Equal(t, []string{"psmith"}, sent.LFIDs)
		assert.Equal(t, []string{"p@example.org"}, sent.Emails)
	})

	t.Run("404 is a no-match, not an error", func(t *testing.T) {
		transport := &recordingTransport{status: http.StatusNotFound}
		result, err := newTestClient(transport).Resolve(context.Background(), "psmith", "")

		require.NoError(t, err)
		assert.Equal(t, OutcomeNoMatch, result.Outcome)
		assert.Empty(t, result.MemberID)
	})

	t.Run("409 is a conflict, not an error", func(t *testing.T) {
		transport := &recordingTransport{status: http.StatusConflict}
		result, err := newTestClient(transport).Resolve(context.Background(), "psmith", "")

		require.NoError(t, err)
		assert.Equal(t, OutcomeConflict, result.Outcome)
	})

	t.Run("a 400 validation response is an error, never a no-match", func(t *testing.T) {
		// Caching a caller defect as "this person has no CDP member" would be
		// invisible and permanent, so the two must not collapse.
		transport := &recordingTransport{status: http.StatusBadRequest}
		result, err := newTestClient(transport).Resolve(context.Background(), "psmith", "")

		require.Error(t, err)
		assert.NotEqual(t, OutcomeNoMatch, result.Outcome)
	})

	t.Run("an empty lfid is refused without calling CDP", func(t *testing.T) {
		transport := &recordingTransport{status: http.StatusOK, body: `{"memberId":"abc"}`}
		_, err := newTestClient(transport).Resolve(context.Background(), "   ", "p@example.org")

		require.Error(t, err)
		assert.Empty(t, transport.requests, "an email-only body must never reach the provider")
	})

	t.Run("the email is omitted when absent", func(t *testing.T) {
		transport := &recordingTransport{status: http.StatusOK, body: `{"memberId":"abc"}`}
		_, err := newTestClient(transport).Resolve(context.Background(), "psmith", "")

		require.NoError(t, err)
		require.Len(t, transport.requests, 1)
		assert.NotContains(t, transport.requests[0].body, "emails")
	})

	t.Run("an empty member id on a 200 is an error", func(t *testing.T) {
		transport := &recordingTransport{status: http.StatusOK, body: `{"memberId":""}`}
		_, err := newTestClient(transport).Resolve(context.Background(), "psmith", "")

		require.Error(t, err)
	})

	t.Run("a token failure does not call CDP", func(t *testing.T) {
		transport := &recordingTransport{status: http.StatusOK}
		client := NewClient(Config{
			BaseURL:      "https://cdp.example.org",
			TokenManager: fakeTokenProvider{err: assert.AnError},
			Transport:    transport,
		})

		_, err := client.Resolve(context.Background(), "psmith", "")
		require.Error(t, err)
		assert.Empty(t, transport.requests)
	})
}

func TestCreateMember(t *testing.T) {
	identity := Identity{Value: "psmith", Platform: "lfid", Type: "username", Source: "lfxV2AuthService", Verified: true, VerifiedBy: "psmith"}

	t.Run("201 returns the member id", func(t *testing.T) {
		transport := &recordingTransport{status: http.StatusCreated, body: `{"memberId":"new-1"}`}
		result, err := newTestClient(transport).CreateMember(context.Background(), "P. Smith", identity)

		require.NoError(t, err)
		assert.Equal(t, OutcomeFound, result.Outcome)
		assert.Equal(t, "new-1", result.MemberID)
		assert.Equal(t, "https://cdp.example.org/v1/members", transport.requests[0].url)
	})

	t.Run("409 is a conflict carrying no member id", func(t *testing.T) {
		// The provider's conflict body omits the member id, so recovery has to
		// be a re-resolve rather than reading it from here.
		transport := &recordingTransport{status: http.StatusConflict, body: `{"platform":"lfid","value":"psmith","type":"username"}`}
		result, err := newTestClient(transport).CreateMember(context.Background(), "P. Smith", identity)

		require.NoError(t, err)
		assert.Equal(t, OutcomeConflict, result.Outcome)
		assert.Empty(t, result.MemberID)
	})

	t.Run("a 500 is an error", func(t *testing.T) {
		transport := &recordingTransport{status: http.StatusInternalServerError}
		_, err := newTestClient(transport).CreateMember(context.Background(), "P. Smith", identity)

		require.Error(t, err)
	})
}

func TestListIdentities(t *testing.T) {
	t.Run("200 returns the member's identities", func(t *testing.T) {
		transport := &recordingTransport{
			status: http.StatusOK,
			body:   `{"identities":[{"id":"i-1","value":"psmith","platform":"lfid","type":"username","verified":true}]}`,
		}
		identities, err := newTestClient(transport).ListIdentities(context.Background(), "mem-1")

		require.NoError(t, err)
		require.Len(t, identities, 1)
		assert.Equal(t, "psmith", identities[0].Value)
		assert.Equal(t, "lfid", identities[0].Platform)
		assert.Equal(t, http.MethodGet, transport.requests[0].method)
		assert.Equal(t, "https://cdp.example.org/v1/members/mem-1/identities", transport.requests[0].url)
	})

	t.Run("404 is reported, not read as an empty list", func(t *testing.T) {
		// The member vanished between the resolve and this call. Reading that
		// as "holds no identities" is indistinguishable from a free member,
		// and on the create-conflict path the caller then returns the dead id
		// to be stored write-once as a Segment user_id.
		transport := &recordingTransport{status: http.StatusNotFound}
		identities, err := newTestClient(transport).ListIdentities(context.Background(), "mem-1")

		require.ErrorIs(t, err, ErrMemberNotFound,
			"callers branch on this, so it must survive errors.Is")
		assert.Empty(t, identities)
	})

	t.Run("an empty member id is rejected before the call", func(t *testing.T) {
		transport := &recordingTransport{status: http.StatusOK}
		_, err := newTestClient(transport).ListIdentities(context.Background(), "")

		require.Error(t, err)
		assert.Empty(t, transport.requests)
	})

	t.Run("a 500 is an error", func(t *testing.T) {
		transport := &recordingTransport{status: http.StatusInternalServerError}
		_, err := newTestClient(transport).ListIdentities(context.Background(), "mem-1")

		require.Error(t, err)
	})
}

func TestAttachIdentity(t *testing.T) {
	identity := Identity{Value: "psmith", Platform: "lfid", Type: "username"}

	t.Run("201 succeeds and escapes the member id in the path", func(t *testing.T) {
		transport := &recordingTransport{status: http.StatusCreated}
		attached, err := newTestClient(transport).AttachIdentity(context.Background(), "mem/1", identity)

		require.NoError(t, err)
		assert.Equal(t, OutcomeFound, attached.Outcome)
		assert.Equal(t, "https://cdp.example.org/v1/members/mem%2F1/identities", transport.requests[0].url)
	})

	t.Run("200 is the idempotent re-attach", func(t *testing.T) {
		// Delivery is at-least-once. The provider finds the exact identity on
		// this member and answers 200, so a replay is not a conflict.
		transport := &recordingTransport{status: http.StatusOK}
		attached, err := newTestClient(transport).AttachIdentity(context.Background(), "mem-1", identity)

		require.NoError(t, err)
		assert.Equal(t, OutcomeFound, attached.Outcome)
	})

	t.Run("409 is a conflict, not a success", func(t *testing.T) {
		// The provider reserves 409 for an identity verified on a *different*
		// member. Reporting it as success would let the caller store a member
		// id whose LFID was never attached.
		transport := &recordingTransport{status: http.StatusConflict}
		attached, err := newTestClient(transport).AttachIdentity(context.Background(), "mem-1", identity)

		require.NoError(t, err)
		assert.Equal(t, OutcomeConflict, attached.Outcome)
		assert.Empty(t, attached.ConflictMemberID, "a body naming nobody reports nobody")
	})

	t.Run("409 reports the member that holds the identity", func(t *testing.T) {
		// The provider looks this up on the primary while building the error,
		// so it is authoritative in a way a re-resolve against a read replica
		// is not.
		transport := &recordingTransport{
			status: http.StatusConflict,
			body: `{"error":{"code":"CONFLICT","message":"Identity already exists on another member",` +
				`"context":{"memberId":"mem-1","platform":"lfid","value":"psmith","type":"username",` +
				`"conflictMemberId":"mem-2"}}}`,
		}
		attached, err := newTestClient(transport).AttachIdentity(context.Background(), "mem-1", identity)

		require.NoError(t, err)
		assert.Equal(t, OutcomeConflict, attached.Outcome)
		assert.Equal(t, "mem-2", attached.ConflictMemberID)
	})

	t.Run("a malformed 409 body degrades to no member rather than failing", func(t *testing.T) {
		transport := &recordingTransport{status: http.StatusConflict, body: `not json`}
		attached, err := newTestClient(transport).AttachIdentity(context.Background(), "mem-1", identity)

		require.NoError(t, err)
		assert.Equal(t, OutcomeConflict, attached.Outcome)
		assert.Empty(t, attached.ConflictMemberID)
	})

	t.Run("an error carries the status, not the provider body", func(t *testing.T) {
		// CDP error bodies echo the identity back. The shared client keeps the
		// body out of Error() and sanitize() drops the carrier too; this pins
		// that neither path puts it back.
		transport := &recordingTransport{status: http.StatusInternalServerError, body: `{"platform":"lfid","value":"psmith","type":"username"}`}
		_, err := newTestClient(transport).AttachIdentity(context.Background(), "mem-1", identity)

		require.Error(t, err)
		assert.NotContains(t, err.Error(), "psmith")
	})

	t.Run("an empty member id is refused without calling CDP", func(t *testing.T) {
		transport := &recordingTransport{status: http.StatusCreated}
		_, err := newTestClient(transport).AttachIdentity(context.Background(), "", identity)

		require.Error(t, err)
		assert.Empty(t, transport.requests)
	})
}

func TestRateLimit(t *testing.T) {
	// Every call below draws on one shared budget, so each has to report a 429
	// as a wait. Reported as an ordinary failure it would instead cost the
	// event one of its bounded attempts and, often enough, abandon the user.
	operations := []struct {
		name string
		call func(Client) error
	}{
		{"resolve", func(c Client) error {
			_, err := c.Resolve(context.Background(), "psmith", "")
			return err
		}},
		{"list identities", func(c Client) error {
			_, err := c.ListIdentities(context.Background(), "member-1")
			return err
		}},
		{"create member", func(c Client) error {
			_, err := c.CreateMember(context.Background(), "P Smith", Identity{Value: "psmith"})
			return err
		}},
		{"attach identity", func(c Client) error {
			_, err := c.AttachIdentity(context.Background(), "member-1", Identity{Value: "psmith"})
			return err
		}},
	}

	for _, operation := range operations {
		t.Run(operation.name+" reports a 429 with the server's Retry-After", func(t *testing.T) {
			transport := &recordingTransport{
				status: http.StatusTooManyRequests,
				header: http.Header{"Retry-After": []string{"45"}},
			}

			err := operation.call(newTestClient(transport))

			var rateLimited errors.RateLimited
			require.ErrorAs(t, err, &rateLimited,
				"a wrapped rate limit is invisible to the consumer, which is what makes it cost an attempt")
			assert.Equal(t, 45*time.Second, rateLimited.RetryAfter)
		})

		t.Run(operation.name+" reports a 429 with no wait when the server named none", func(t *testing.T) {
			transport := &recordingTransport{status: http.StatusTooManyRequests}

			err := operation.call(newTestClient(transport))

			var rateLimited errors.RateLimited
			require.ErrorAs(t, err, &rateLimited)
			assert.Zero(t, rateLimited.RetryAfter, "the caller falls back to its own backoff")
		})
	}
}
