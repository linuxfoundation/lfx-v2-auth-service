// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestAnnouncementStore(transport http.RoundTripper) *userAnnouncementStore {
	store, err := NewUserAnnouncementStore(
		httpclient.Config{Transport: transport, MaxRetries: 0},
		Config{
			Domain:          "test-tenant.auth0.com",
			M2MTokenManager: &TokenManager{tokenSource: fakeTokenSource{token: "test-m2m-token"}},
		},
	)
	if err != nil {
		panic(err)
	}
	return store.(*userAnnouncementStore)
}

func TestNewUserAnnouncementStoreValidation(t *testing.T) {
	_, err := NewUserAnnouncementStore(httpclient.DefaultConfig(), Config{Domain: "test.auth0.com"})
	require.Error(t, err, "a missing token manager is refused at construction")
}

func TestReadAnnouncementState(t *testing.T) {
	ctx := context.Background()

	t.Run("a database user's LFID and marker are read", func(t *testing.T) {
		transport := &cdpMetadataTransport{getBody: `{"user_id":"auth0|1","email":"jane@example.com","email_verified":true,"username":"jane","app_metadata":{"email_verified_announced_at":"2026-11-24T12:00:00Z"}}`}

		state, err := newTestAnnouncementStore(transport).ReadAnnouncementState(ctx, "auth0|1")

		require.NoError(t, err)
		assert.True(t, state.EmailVerified)
		assert.Equal(t, "jane@example.com", state.Email)
		assert.Equal(t, "jane", state.Username)
		assert.Equal(t, "2026-11-24T12:00:00Z", state.AnnouncedAt)
	})

	t.Run("a social-primary user has no LFID username", func(t *testing.T) {
		transport := &cdpMetadataTransport{getBody: `{"user_id":"google-oauth2|1","email":"jane@example.com","email_verified":true,"username":"not-an-lfid"}`}

		state, err := newTestAnnouncementStore(transport).ReadAnnouncementState(ctx, "google-oauth2|1")

		require.NoError(t, err)
		assert.Empty(t, state.Username)
		assert.Empty(t, state.AnnouncedAt)
	})

	t.Run("a blank user id is refused before any request", func(t *testing.T) {
		transport := &cdpMetadataTransport{}

		_, err := newTestAnnouncementStore(transport).ReadAnnouncementState(ctx, " ")

		require.Error(t, err)
		assert.Empty(t, transport.requests)
	})
}

func TestMarkAnnounced(t *testing.T) {
	ctx := context.Background()

	t.Run("only the announcement key is patched", func(t *testing.T) {
		transport := &cdpMetadataTransport{}

		err := newTestAnnouncementStore(transport).MarkAnnounced(ctx, "auth0|1", "2026-11-24T12:00:00Z")

		require.NoError(t, err)
		patches := transport.patches()
		require.Len(t, patches, 1)

		var sent map[string]map[string]any
		require.NoError(t, json.Unmarshal([]byte(patches[0].body), &sent))
		assert.Equal(t, map[string]any{"email_verified_announced_at": "2026-11-24T12:00:00Z"}, sent["app_metadata"],
			"the CDP keys must not be sent, or Auth0 would treat them as writes")
	})

	t.Run("a rejected patch is an error", func(t *testing.T) {
		transport := &cdpMetadataTransport{patchStatus: http.StatusInternalServerError}

		require.Error(t, newTestAnnouncementStore(transport).MarkAnnounced(ctx, "auth0|1", "2026-11-24T12:00:00Z"))
	})

	t.Run("blank arguments are refused before any request", func(t *testing.T) {
		transport := &cdpMetadataTransport{}
		store := newTestAnnouncementStore(transport)

		require.Error(t, store.MarkAnnounced(ctx, "", "2026-11-24T12:00:00Z"))
		require.Error(t, store.MarkAnnounced(ctx, "auth0|1", ""))
		assert.Empty(t, transport.requests)
	})
}
