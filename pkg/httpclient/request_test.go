// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package httpclient

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSanitizeURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "plain url without query params",
			input:    "https://auth.example.com/api/v2/users",
			expected: "https://auth.example.com/api/v2/users",
		},
		{
			name:     "url with non-email query param",
			input:    "https://auth.example.com/api/v2/users?page=1&per_page=50",
			expected: "https://auth.example.com/api/v2/users?page=1&per_page=50",
		},
		{
			name:     "url with email query param",
			input:    "https://auth.example.com/api/v2/users-by-email?email=john.doe@example.com",
			expected: "https://auth.example.com/api/v2/users-by-email?email=joh%2A%2A%2A%2A%40example.com",
		},
		{
			name:     "url with path user id",
			input:    "https://auth.example.com/api/v2/users/auth0%7C64f123456789",
			expected: "https://auth.example.com/api/v2/users/auth0%7C64f%2A%2A%2A%2A",
		},
		{
			name:     "url with lucene search for email",
			input:    "https://auth.example.com/api/v2/users?q=identities.profileData.email:john.doe@example.com&search_engine=v3",
			expected: "https://auth.example.com/api/v2/users?q=identities.profileData.email%3Ajoh%2A%2A%2A%2A%40example.com&search_engine=v3",
		},
		{
			name:     "url with lucene search for username",
			input:    "https://auth.example.com/api/v2/users?q=identities.user_id:john_doe&search_engine=v3",
			expected: "https://auth.example.com/api/v2/users?q=identities.user_id%3Ajoh%2A%2A%2A%2A&search_engine=v3",
		},
		{
			name:     "url with unlink secondary identity user id",
			input:    "https://auth.example.com/api/v2/users/auth0%7Cprimary123/identities/google-oauth2/secondary_user_456",
			expected: "https://auth.example.com/api/v2/users/auth0%7Cpri%2A%2A%2A%2A/identities/google-oauth2/sec%2A%2A%2A%2A",
		},
		{
			name:     "url with grouped lucene query",
			input:    "https://auth.example.com/api/v2/users?q=email:(first@example.com OR second@example.com)",
			expected: "https://auth.example.com/api/v2/users?q=%5BREDACTED%5D",
		},
		{
			name:     "url with quoted lucene query",
			input:    `https://auth.example.com/api/v2/users?q=identities.user_id:"John Doe"`,
			expected: "https://auth.example.com/api/v2/users?q=%5BREDACTED%5D",
		},
		{
			name:     "invalid url with sensitive data",
			input:    "://bad-url?email=victim@example.com",
			expected: "[REDACTED_URL]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeURL(tt.input)
			if got != tt.expected {
				t.Errorf("sanitizeURL(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestSanitizeError(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains []string
		omits    []string
	}{
		{
			name:     "error with url containing email",
			input:    `parse "https://auth.example.com/api/v2/users?email=victim@example.com": invalid escape`,
			omits:    []string{"victim@example.com"},
			contains: []string{"vic%2A%2A%2A%2A%40example.com", "invalid escape"},
		},
		{
			name:     "error with malformed url escape containing email",
			input:    `parse "https://auth.example.com/api/v2/users?email=secret%xx@example.com": invalid URL escape "%xx"`,
			omits:    []string{"secret%xx@example.com", "secret"},
			contains: []string{"[REDACTED_URL]"},
		},
		{
			name:     "error with user id in path",
			input:    `Get "https://auth.example.com/api/v2/users/auth0|secret_user_id_123": dial tcp: connection refused`,
			omits:    []string{"secret_user_id_123"},
			contains: []string{"connection refused"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := errors.New(tt.input)
			sanitized := sanitizeError(err)
			for _, omit := range tt.omits {
				if strings.Contains(sanitized, omit) {
					t.Errorf("sanitizeError leaked %q in %q", omit, sanitized)
				}
			}
			for _, contain := range tt.contains {
				if !strings.Contains(sanitized, contain) {
					t.Errorf("sanitizeError missing expected token %q in %q", contain, sanitized)
				}
			}
		})
	}
}

func TestClient_Do_SanitizesErrorLog(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	client := NewClient(Config{MaxRetries: 0})
	// Provide malformed URL that fails NewRequestWithContext
	_, err := client.Do(context.Background(), Request{
		Method: http.MethodGet,
		URL:    "https://auth.example.com/users?email=leak_me%xx@example.com",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	logOutput := buf.String()
	if strings.Contains(logOutput, "leak_me") {
		t.Errorf("Client.Do error log leaked sensitive query: %s", logOutput)
	}
}

func TestAPIRequest_Call_SanitizesErrorLog(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	client := NewClient(Config{MaxRetries: 0})
	req := NewAPIRequest(
		client,
		WithMethod(http.MethodGet),
		WithURL("https://auth.example.com/users?email=api_leak%xx@example.com"),
		WithDescription("failing call"),
	)

	var result map[string]any
	_, err := req.Call(context.Background(), &result)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	logOutput := buf.String()
	if strings.Contains(logOutput, "api_leak") {
		t.Errorf("apiRequest.Call error log leaked sensitive query: %s", logOutput)
	}
}

func TestAPIRequest_Call_ClientErrorLogLevel(t *testing.T) {
	// Create test server returning 404
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"user not found"}`))
	}))
	defer server.Close()

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	client := NewClient(DefaultConfig())
	req := NewAPIRequest(
		client,
		WithMethod(http.MethodGet),
		WithURL(server.URL+"/api/v2/users/auth0|12345"),
		WithDescription("get user"),
	)

	var result map[string]any
	status, err := req.Call(context.Background(), &result)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if status != http.StatusNotFound {
		t.Errorf("got status %d, want %d", status, http.StatusNotFound)
	}

	logOutput := buf.String()
	// Should NOT log at ERROR level for 404 client errors
	if strings.Contains(logOutput, `"level":"ERROR"`) {
		t.Errorf("404 should not produce ERROR logs: %s", logOutput)
	}
	// Raw body with PII should not be leaked in ERROR logs
	if strings.Contains(logOutput, "auth0|12345") {
		t.Errorf("URL user ID leaked in log output: %s", logOutput)
	}
}
