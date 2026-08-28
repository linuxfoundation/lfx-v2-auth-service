// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"context"
	stderrors "errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"

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

// stubTransport routes every request to a canned response, so
// validateCurrentPassword can be driven end to end without a real Auth0 tenant.
type stubTransport struct {
	statusCode int
	body       string
}

func (s *stubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: s.statusCode,
		Body:       io.NopCloser(strings.NewReader(s.body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Request:    req,
	}, nil
}

// TestValidateCurrentPassword_ErrorClassification drives the real code path, so a
// future reorder that drops the mfa_required branch fails here rather than only
// in the auth0ErrorCode unit test.
func TestValidateCurrentPassword_ErrorClassification(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		assert     func(t *testing.T, err error)
	}{
		{
			name:       "403 mfa_required is forbidden, not wrong password",
			statusCode: http.StatusForbidden,
			body:       `{"error":"mfa_required","mfa_token":"tok"}`,
			assert: func(t *testing.T, err error) {
				var forbidden errors.Forbidden
				if !stderrors.As(err, &forbidden) {
					t.Fatalf("expected Forbidden for mfa_required, got %T: %v", err, err)
				}
				var unauthorized errors.Unauthorized
				if stderrors.As(err, &unauthorized) {
					t.Error("mfa_required must not be reported as a wrong password")
				}
			},
		},
		{
			name:       "403 invalid_grant is a wrong password",
			statusCode: http.StatusForbidden,
			body:       `{"error":"invalid_grant","error_description":"Wrong email or password."}`,
			assert: func(t *testing.T, err error) {
				var unauthorized errors.Unauthorized
				if !stderrors.As(err, &unauthorized) {
					t.Fatalf("expected Unauthorized, got %T: %v", err, err)
				}
			},
		},
		{
			name:       "401 is a wrong password",
			statusCode: http.StatusUnauthorized,
			body:       `{"error":"invalid_grant"}`,
			assert: func(t *testing.T, err error) {
				var unauthorized errors.Unauthorized
				if !stderrors.As(err, &unauthorized) {
					t.Fatalf("expected Unauthorized, got %T: %v", err, err)
				}
			},
		},
		{
			name:       "500 is a service fault",
			statusCode: http.StatusInternalServerError,
			body:       `{"error":"server_error"}`,
			assert: func(t *testing.T, err error) {
				var unexpected errors.Unexpected
				if !stderrors.As(err, &unexpected) {
					t.Fatalf("expected Unexpected, got %T: %v", err, err)
				}
			},
		},
		{
			name:       "200 validates successfully",
			statusCode: http.StatusOK,
			body:       `{"access_token":"tok"}`,
			assert: func(t *testing.T, err error) {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &userReaderWriter{
				config: Config{
					Domain:                 "auth.example.com",
					LFXProfileClientID:     "client-id",
					LFXProfileClientSecret: "client-secret",
				},
				httpClient: httpclient.NewClient(httpclient.Config{
					Transport: &stubTransport{statusCode: tt.statusCode, body: tt.body},
				}),
			}

			tt.assert(t, u.validateCurrentPassword(context.Background(), "john.doe", "hunter2"))
		})
	}
}

func TestSanitizeProviderMessage(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		leaks  []string
		expect string
	}{
		{
			name:  "email echoed in provider message",
			body:  `{"message":"victim@example.com was not found"}`,
			leaks: []string{"victim@example.com"},
		},
		{
			name:  "user id echoed in provider message",
			body:  `{"message":"user auth0|secret_user_123 does not exist"}`,
			leaks: []string{"secret_user_123"},
		},
		{
			name:  "google-oauth2 id echoed in provider message",
			body:  `{"message":"user google-oauth2|108secretsubject was rejected"}`,
			leaks: []string{"108secretsubject"},
		},
		{
			name:  "email connection id echoed in provider message",
			body:  `{"message":"identity email|stub_secret_123 already linked"}`,
			leaks: []string{"stub_secret_123"},
		},
		{
			name:   "message without identifiers is preserved",
			body:   `{"message":"The user does not exist."}`,
			expect: "The user does not exist.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewErrorResponse().ErrorMessage(tt.body)
			for _, leak := range tt.leaks {
				if strings.Contains(got, leak) {
					t.Errorf("ErrorMessage leaked %q in %q", leak, got)
				}
			}
			if tt.expect != "" && got != tt.expect {
				t.Errorf("ErrorMessage() = %q, want %q", got, tt.expect)
			}
		})
	}
}
