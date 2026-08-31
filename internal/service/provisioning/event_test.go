// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package provisioning

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseEvent(t *testing.T) {
	t.Run("reads a user nested under data.object", func(t *testing.T) {
		raw := []byte(`{
			"id": "evt_1",
			"type": "user.updated",
			"data": {
				"object": {
					"user_id": "auth0|1",
					"username": "psmith",
					"email": "p@example.org",
					"email_verified": true,
					"identities": [{"connection": "Username-Password-Authentication"}]
				}
			}
		}`)

		event, user, err := ParseEvent(raw)

		require.NoError(t, err)
		assert.Equal(t, "evt_1", event.ID)
		assert.Equal(t, EventTypeUserUpdated, event.Type)
		assert.Equal(t, "auth0|1", user.UserID)
		assert.Equal(t, "psmith", user.Username)
	})

	t.Run("reads a user inlined on data", func(t *testing.T) {
		// The documented shape and the real one may differ; accepting both
		// means a payload variation is not an outage.
		raw := []byte(`{"id":"evt_2","type":"user.created","data":{"user_id":"auth0|2","username":"jdoe"}}`)

		_, user, err := ParseEvent(raw)

		require.NoError(t, err)
		assert.Equal(t, "auth0|2", user.UserID)
		assert.Equal(t, "jdoe", user.Username)
	})

	t.Run("invalid JSON is rejected", func(t *testing.T) {
		_, _, err := ParseEvent([]byte(`not json`))
		require.Error(t, err)
	})

	t.Run("a payload with no user_id is rejected", func(t *testing.T) {
		_, _, err := ParseEvent([]byte(`{"id":"evt_3","type":"user.updated","data":{"object":{}}}`))
		require.Error(t, err)
	})

	t.Run("a payload with no data is rejected", func(t *testing.T) {
		_, _, err := ParseEvent([]byte(`{"id":"evt_4","type":"user.updated"}`))
		require.Error(t, err)
	})
}

func TestEventUserToRequest(t *testing.T) {
	t.Run("a null email_verified stays unknown rather than becoming false", func(t *testing.T) {
		// Absent is a third state. Collapsing it to false here would let the
		// gate skip the user without ever asking Auth0.
		_, user, err := ParseEvent([]byte(`{"id":"e","type":"user.updated","data":{"object":{"user_id":"auth0|1","email_verified":null}}}`))
		require.NoError(t, err)

		assert.Nil(t, user.ToRequest().EmailVerified)
	})

	t.Run("an omitted email_verified stays unknown", func(t *testing.T) {
		_, user, err := ParseEvent([]byte(`{"id":"e","type":"user.updated","data":{"object":{"user_id":"auth0|1"}}}`))
		require.NoError(t, err)

		assert.Nil(t, user.ToRequest().EmailVerified)
	})

	t.Run("false email_verified is preserved", func(t *testing.T) {
		_, user, err := ParseEvent([]byte(`{"id":"e","type":"user.updated","data":{"object":{"user_id":"auth0|1","email_verified":false}}}`))
		require.NoError(t, err)

		verified := user.ToRequest().EmailVerified
		require.NotNil(t, verified)
		assert.False(t, *verified)
	})

	t.Run("a stored cdp_uuid is carried onto the request", func(t *testing.T) {
		_, user, err := ParseEvent([]byte(`{"id":"e","type":"user.updated","data":{"object":{"user_id":"auth0|1","app_metadata":{"cdp_uuid":"uuid-1"}}}}`))
		require.NoError(t, err)

		assert.Equal(t, "uuid-1", user.ToRequest().StoredCDPUUID)
	})

	t.Run("a social-only user is not a database user", func(t *testing.T) {
		_, user, err := ParseEvent([]byte(`{"id":"e","type":"user.updated","data":{"object":{"user_id":"google-oauth2|1","identities":[{"connection":"google-oauth2"}]}}}`))
		require.NoError(t, err)

		assert.False(t, user.ToRequest().HasDatabaseIdentity)
	})

	t.Run("a database identity is detected", func(t *testing.T) {
		_, user, err := ParseEvent([]byte(`{"id":"e","type":"user.updated","data":{"object":{"user_id":"auth0|1","identities":[{"connection":"google-oauth2"},{"connection":"Username-Password-Authentication"}]}}}`))
		require.NoError(t, err)

		assert.True(t, user.ToRequest().HasDatabaseIdentity)
	})

	t.Run("an omitted identity list falls back to the user id prefix", func(t *testing.T) {
		_, user, err := ParseEvent([]byte(`{"id":"e","type":"user.updated","data":{"object":{"user_id":"auth0|1"}}}`))
		require.NoError(t, err)

		assert.True(t, user.ToRequest().HasDatabaseIdentity)
	})
}
