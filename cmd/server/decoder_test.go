// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRequestDecoderRawBody covers the transport, which the service-level
// tests bypass entirely.
//
// A goa `Bytes` payload is decoded with encoding/json, and that accepts only a
// base64 string for a byte slice — so the default decoder rejects an ordinary
// JSON body before any handler runs. On this endpoint that meant every real
// Auth0 delivery would have been refused, and the 400 would have told Auth0 to
// stop retrying.
func TestRequestDecoderRawBody(t *testing.T) {
	t.Run("a JSON object body arrives verbatim", func(t *testing.T) {
		payload := `{"id":"evt_1","type":"user.updated","data":{"object":{"user_id":"auth0|1"}}}`
		request := httptest.NewRequest(http.MethodPost, "/webhooks/auth0/cdp-provisioning", strings.NewReader(payload))
		request.Header.Set("Content-Type", "application/json")

		var body []byte
		require.NoError(t, requestDecoder(request).Decode(&body))
		assert.JSONEq(t, payload, string(body))
	})

	t.Run("a non-JSON body is passed through unchanged", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("not json at all"))

		var body []byte
		require.NoError(t, requestDecoder(request).Decode(&body))
		assert.Equal(t, "not json at all", string(body))
	})

	t.Run("an empty body reports as missing rather than as empty bytes", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(""))

		var body []byte
		// io.EOF specifically: goa maps it to a missing-payload response, so a
		// generic error here would change what the caller sees.
		require.ErrorIs(t, requestDecoder(request).Decode(&body), io.EOF)
	})

	t.Run("a non-bytes target still uses the standard decoder", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"name":"value"}`))
		request.Header.Set("Content-Type", "application/json")

		var target struct {
			Name string `json:"name"`
		}
		require.NoError(t, requestDecoder(request).Decode(&target))
		assert.Equal(t, "value", target.Name)
	})
}
