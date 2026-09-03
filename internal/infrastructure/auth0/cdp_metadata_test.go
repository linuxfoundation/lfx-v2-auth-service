// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cdpMetadataTransport answers the GET with a canned user record and records
// every request, so a test can assert both the write-once decision and whether
// a PATCH was issued at all.
type cdpMetadataTransport struct {
	getBody     string
	getStatus   int
	patchStatus int
	header      http.Header
	requests    []cdpRecordedRequest
}

type cdpRecordedRequest struct {
	method string
	body   string
}

func (c *cdpMetadataTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	recorded := cdpRecordedRequest{method: req.Method}
	if req.Body != nil {
		raw, _ := io.ReadAll(req.Body)
		recorded.body = string(raw)
	}
	c.requests = append(c.requests, recorded)

	status := c.getStatus
	body := c.getBody
	if req.Method == http.MethodPatch {
		status = c.patchStatus
		body = "{}"
	}
	if status == 0 {
		status = http.StatusOK
	}
	if body == "" {
		body = "{}"
	}

	header := c.header
	if header == nil {
		header = make(http.Header)
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     header,
	}, nil
}

func (c *cdpMetadataTransport) patches() []cdpRecordedRequest {
	var out []cdpRecordedRequest
	for _, request := range c.requests {
		if request.method == http.MethodPatch {
			out = append(out, request)
		}
	}
	return out
}

func newTestCDPWriter(transport http.RoundTripper) port.CDPMetadataReaderWriter {
	writer, err := NewCDPMetadataWriter(
		httpclient.Config{Transport: transport, MaxRetries: 0},
		Config{
			Domain:          "test-tenant.auth0.com",
			M2MTokenManager: &TokenManager{tokenSource: fakeTokenSource{token: "test-m2m-token"}},
		},
	)
	if err != nil {
		panic(err)
	}
	return writer
}

func TestNewCDPMetadataWriterValidation(t *testing.T) {
	t.Run("a missing token manager is refused at construction", func(t *testing.T) {
		_, err := NewCDPMetadataWriter(httpclient.DefaultConfig(), Config{Domain: "test.auth0.com"})
		require.Error(t, err, "misconfiguration must surface here, not as a panic on the first request")
	})

	t.Run("a missing domain is refused at construction", func(t *testing.T) {
		_, err := NewCDPMetadataWriter(httpclient.DefaultConfig(), Config{
			M2MTokenManager: &TokenManager{tokenSource: fakeTokenSource{token: "t"}},
		})
		require.Error(t, err)
	})
}

func TestWriteCDPMetadataWriteOnce(t *testing.T) {
	ctx := context.Background()

	t.Run("absent to present is allowed", func(t *testing.T) {
		transport := &cdpMetadataTransport{getBody: `{"user_id":"auth0|1","app_metadata":{}}`}
		err := newTestCDPWriter(transport).WriteCDPMetadata(ctx, "auth0|1", port.CDPMetadata{
			UUID:   "uuid-1",
			Source: constants.CDPUUIDSourceProvisioning,
		})

		require.NoError(t, err)
		patches := transport.patches()
		require.Len(t, patches, 1)

		var sent cdpMetadataPatch
		require.NoError(t, json.Unmarshal([]byte(patches[0].body), &sent))
		assert.Equal(t, "uuid-1", sent.AppMetadata.CDPUUID)
		assert.Equal(t, constants.CDPUUIDSourceProvisioning, sent.AppMetadata.CDPUUIDSource)
		assert.NotEmpty(t, sent.AppMetadata.CDPUUIDCheckedAt)
	})

	t.Run("overwriting with a different uuid is rejected and never patched", func(t *testing.T) {
		transport := &cdpMetadataTransport{getBody: `{"user_id":"auth0|1","app_metadata":{"cdp_uuid":"uuid-1"}}`}
		err := newTestCDPWriter(transport).WriteCDPMetadata(ctx, "auth0|1", port.CDPMetadata{
			UUID:   "uuid-2",
			Source: constants.CDPUUIDSourceBackfill,
		})

		require.Error(t, err)
		assert.Empty(t, transport.patches(), "a rejected write must not reach Auth0")
	})

	t.Run("clearing a stored uuid is rejected", func(t *testing.T) {
		// A no-match marker written over a found user would lose the identity.
		transport := &cdpMetadataTransport{getBody: `{"user_id":"auth0|1","app_metadata":{"cdp_uuid":"uuid-1"}}`}
		err := newTestCDPWriter(transport).WriteCDPMetadata(ctx, "auth0|1", port.CDPMetadata{
			Source: constants.CDPUUIDSourceLoginResolve,
		})

		require.Error(t, err)
		assert.Empty(t, transport.patches())
	})

	t.Run("rewriting the same uuid refreshes source and checked_at", func(t *testing.T) {
		transport := &cdpMetadataTransport{getBody: `{"user_id":"auth0|1","app_metadata":{"cdp_uuid":"uuid-1"}}`}
		err := newTestCDPWriter(transport).WriteCDPMetadata(ctx, "auth0|1", port.CDPMetadata{
			UUID:      "uuid-1",
			Source:    constants.CDPUUIDSourceLoginResolve,
			CheckedAt: "2026-08-14T00:00:00Z",
		})

		require.NoError(t, err)
		patches := transport.patches()
		require.Len(t, patches, 1)
		assert.Contains(t, patches[0].body, "2026-08-14T00:00:00Z")
	})

	t.Run("a no-match marker is allowed when no uuid is stored", func(t *testing.T) {
		transport := &cdpMetadataTransport{getBody: `{"user_id":"auth0|1","app_metadata":{}}`}
		err := newTestCDPWriter(transport).WriteCDPMetadata(ctx, "auth0|1", port.CDPMetadata{
			Source: constants.CDPUUIDSourceBackfill,
		})

		require.NoError(t, err)
		patches := transport.patches()
		require.Len(t, patches, 1)

		// `omitempty` keeps the key out entirely rather than writing an empty
		// string, which is what makes "checked, no member" distinguishable.
		assert.NotContains(t, patches[0].body, "cdp_uuid\"")
		assert.Contains(t, patches[0].body, "cdp_uuid_source")
	})

	t.Run("the patch carries only the CDP keys", func(t *testing.T) {
		// Building the body from a prior read would reintroduce the
		// lost-update race the partial patch exists to avoid.
		transport := &cdpMetadataTransport{
			getBody: `{"user_id":"auth0|1","app_metadata":{"system_managed":true,"stopforumspam":"x"}}`,
		}
		err := newTestCDPWriter(transport).WriteCDPMetadata(ctx, "auth0|1", port.CDPMetadata{
			UUID:   "uuid-1",
			Source: constants.CDPUUIDSourceProvisioning,
		})

		require.NoError(t, err)
		patches := transport.patches()
		require.Len(t, patches, 1)
		assert.NotContains(t, patches[0].body, "system_managed")
		assert.NotContains(t, patches[0].body, "stopforumspam")
	})

	t.Run("an unknown source is rejected", func(t *testing.T) {
		transport := &cdpMetadataTransport{getBody: `{"user_id":"auth0|1","app_metadata":{}}`}
		err := newTestCDPWriter(transport).WriteCDPMetadata(ctx, "auth0|1", port.CDPMetadata{
			UUID:   "uuid-1",
			Source: "made-up",
		})

		require.Error(t, err)
		assert.Empty(t, transport.requests, "an invalid source must be caught before any Auth0 call")
	})

	t.Run("a missing source is rejected", func(t *testing.T) {
		transport := &cdpMetadataTransport{getBody: `{"user_id":"auth0|1","app_metadata":{}}`}
		err := newTestCDPWriter(transport).WriteCDPMetadata(ctx, "auth0|1", port.CDPMetadata{UUID: "uuid-1"})

		require.Error(t, err)
	})
}

func TestReadCDPMetadata(t *testing.T) {
	ctx := context.Background()

	t.Run("returns the stored record", func(t *testing.T) {
		transport := &cdpMetadataTransport{
			getBody: `{"user_id":"auth0|1","app_metadata":{"cdp_uuid":"uuid-1","cdp_uuid_source":"backfill","cdp_uuid_checked_at":"2026-08-01T00:00:00Z"}}`,
		}
		record, err := newTestCDPWriter(transport).ReadCDPMetadata(ctx, "auth0|1")

		require.NoError(t, err)
		assert.Equal(t, "uuid-1", record.UUID)
		assert.Equal(t, "backfill", record.Source)
		assert.Equal(t, "2026-08-01T00:00:00Z", record.CheckedAt)
	})

	t.Run("a user with no app_metadata reads as empty", func(t *testing.T) {
		transport := &cdpMetadataTransport{getBody: `{"user_id":"auth0|1"}`}
		record, err := newTestCDPWriter(transport).ReadCDPMetadata(ctx, "auth0|1")

		require.NoError(t, err)
		assert.Empty(t, record.UUID)
	})

	t.Run("an empty user id is refused", func(t *testing.T) {
		transport := &cdpMetadataTransport{}
		_, err := newTestCDPWriter(transport).ReadCDPMetadata(ctx, "")

		require.Error(t, err)
		assert.Empty(t, transport.requests)
	})
}

func TestReadProvisioningState(t *testing.T) {
	ctx := context.Background()

	t.Run("returns the fields the gate depends on in one call", func(t *testing.T) {
		transport := &cdpMetadataTransport{getBody: `{
			"user_id":"auth0|1",
			"username":"psmith",
			"name":"P. Smith",
			"email_verified":true,
			"identities":[{"connection":"google-oauth2"},{"connection":"Username-Password-Authentication"}],
			"app_metadata":{"cdp_uuid":"uuid-1","cdp_uuid_source":"backfill"}
		}`}

		state, err := newTestCDPWriter(transport).ReadProvisioningState(ctx, "auth0|1")

		require.NoError(t, err)
		assert.True(t, state.EmailVerified)
		assert.Equal(t, "psmith", state.Username)
		assert.True(t, state.HasDatabaseIdentity)
		assert.Equal(t, "P. Smith", state.Name)
		assert.Equal(t, "uuid-1", state.UUID)
		assert.Len(t, transport.requests, 1, "the gate must cost one Auth0 call, not four")
	})

	t.Run("the username is ignored when the primary identity is not the database", func(t *testing.T) {
		// The root username belongs to the primary identity. Handing another
		// connection's username to CDP as an LFID would store a wrong id
		// permanently, so this reports no username and the caller skips.
		transport := &cdpMetadataTransport{getBody: `{
			"user_id":"google-oauth2|1",
			"username":"not-an-lfid",
			"email_verified":true,
			"identities":[{"connection":"google-oauth2"},{"connection":"Username-Password-Authentication"}]
		}`}

		state, err := newTestCDPWriter(transport).ReadProvisioningState(ctx, "google-oauth2|1")

		require.NoError(t, err)
		assert.True(t, state.HasDatabaseIdentity, "the linked database identity is still visible")
		assert.Empty(t, state.Username, "but its username is not readable, so none is reported")
	})

	t.Run("a social-only user has no database identity", func(t *testing.T) {
		transport := &cdpMetadataTransport{getBody: `{
			"user_id":"google-oauth2|1",
			"email_verified":true,
			"identities":[{"connection":"google-oauth2"}]
		}`}

		state, err := newTestCDPWriter(transport).ReadProvisioningState(ctx, "google-oauth2|1")

		require.NoError(t, err)
		assert.False(t, state.HasDatabaseIdentity)
	})

	t.Run("an unverified user reports as unverified", func(t *testing.T) {
		transport := &cdpMetadataTransport{getBody: `{"user_id":"auth0|1","email_verified":false}`}

		state, err := newTestCDPWriter(transport).ReadProvisioningState(ctx, "auth0|1")

		require.NoError(t, err)
		assert.False(t, state.EmailVerified)
	})

	t.Run("a missing user is a not-found error", func(t *testing.T) {
		transport := &cdpMetadataTransport{getStatus: http.StatusNotFound}

		_, err := newTestCDPWriter(transport).ReadProvisioningState(ctx, "auth0|missing")

		require.Error(t, err)
	})
}

func TestCDPMetadataRateLimit(t *testing.T) {
	ctx := context.Background()
	record := port.CDPMetadata{UUID: "member-1", Source: constants.CDPUUIDSourceProvisioning}

	t.Run("a 429 on the read is reported as a rate limit", func(t *testing.T) {
		transport := &cdpMetadataTransport{
			getStatus: http.StatusTooManyRequests,
			header:    http.Header{"Retry-After": []string{"20"}},
		}

		_, err := newTestCDPWriter(transport).ReadCDPMetadata(ctx, "auth0|1")

		var rateLimited errors.RateLimited
		require.ErrorAs(t, err, &rateLimited)
		assert.Equal(t, 20*time.Second, rateLimited.RetryAfter)
	})

	t.Run("a 429 on the write is reported as a rate limit", func(t *testing.T) {
		transport := &cdpMetadataTransport{
			getBody:     `{"user_id":"auth0|1","app_metadata":{}}`,
			patchStatus: http.StatusTooManyRequests,
			header:      http.Header{"Retry-After": []string{"20"}},
		}

		err := newTestCDPWriter(transport).WriteCDPMetadata(ctx, "auth0|1", record)

		var rateLimited errors.RateLimited
		require.ErrorAs(t, err, &rateLimited)
		assert.Equal(t, 20*time.Second, rateLimited.RetryAfter)
	})

	t.Run("a 429 with no Retry-After still reports a rate limit", func(t *testing.T) {
		transport := &cdpMetadataTransport{getStatus: http.StatusTooManyRequests}

		_, err := newTestCDPWriter(transport).ReadCDPMetadata(ctx, "auth0|1")

		var rateLimited errors.RateLimited
		require.ErrorAs(t, err, &rateLimited)
		assert.Zero(t, rateLimited.RetryAfter)
	})
}
