// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	stderrors "errors"
	"net/http"
	"testing"

	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
)

func TestAuth0ErrorCode(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: "",
		},
		{
			name:     "non-retryable error",
			err:      stderrors.New("dial tcp: connection refused"),
			expected: "",
		},
		{
			name: "mfa required",
			err: &httpclient.RetryableError{
				StatusCode: http.StatusForbidden,
				RawBody:    `{"error":"mfa_required","mfa_token":"tok"}`,
			},
			expected: mfaRequiredErrorCode,
		},
		{
			name: "invalid grant",
			err: &httpclient.RetryableError{
				StatusCode: http.StatusForbidden,
				RawBody:    `{"error":"invalid_grant","error_description":"Wrong email or password."}`,
			},
			expected: "invalid_grant",
		},
		{
			name: "non-json body",
			err: &httpclient.RetryableError{
				StatusCode: http.StatusForbidden,
				RawBody:    "Forbidden",
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := auth0ErrorCode(tt.err); got != tt.expected {
				t.Errorf("auth0ErrorCode() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestErrorMessage_FromRawBody pins that the provider's message survives the
// status-only RetryableError.Error(), and that an unparseable body never leaks.
func TestErrorMessage_FromRawBody(t *testing.T) {
	tests := []struct {
		name     string
		rawBody  string
		expected string
	}{
		{
			name:     "auth0 message field",
			rawBody:  `{"statusCode":404,"error":"Not Found","message":"The user does not exist."}`,
			expected: "The user does not exist.",
		},
		{
			name:     "error field only",
			rawBody:  `{"statusCode":403,"error":"Forbidden"}`,
			expected: "Forbidden",
		},
		{
			name:     "non-json body is not echoed",
			rawBody:  "victim@example.com is already taken",
			expected: unknownAuth0Error,
		},
		{
			name:     "empty body",
			rawBody:  "",
			expected: unknownAuth0Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewErrorResponse().ErrorMessage(tt.rawBody); got != tt.expected {
				t.Errorf("ErrorMessage() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestResponseBody_RoundTrip pins the accessor GetUser relies on to reach the
// provider payload now that Error() is status-only.
func TestResponseBody_RoundTrip(t *testing.T) {
	body := `{"statusCode":404,"message":"The user does not exist."}`
	err := &httpclient.RetryableError{StatusCode: http.StatusNotFound, RawBody: body}

	if got := httpclient.ResponseBody(err); got != body {
		t.Errorf("ResponseBody() = %q, want %q", got, body)
	}
	if got := httpclient.ResponseBody(stderrors.New("not retryable")); got != "" {
		t.Errorf("ResponseBody() on non-retryable = %q, want empty", got)
	}
	if msg := NewErrorResponse().ErrorMessage(httpclient.ResponseBody(err)); msg != "The user does not exist." {
		t.Errorf("provider message lost through the accessor: %q", msg)
	}
}
