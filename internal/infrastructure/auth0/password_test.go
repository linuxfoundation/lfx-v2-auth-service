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
