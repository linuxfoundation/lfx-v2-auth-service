// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package redaction

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "very short string (1 char)",
			input:    "a",
			expected: "**",
		},
		{
			name:     "very short string (2 chars)",
			input:    "ab",
			expected: "**",
		},
		{
			name:     "short string (3 chars)",
			input:    "abc",
			expected: "a****",
		},
		{
			name:     "short string (5 chars)",
			input:    "abcde",
			expected: "a****",
		},
		{
			name:     "longer string (6 chars)",
			input:    "abcdef",
			expected: "abc****",
		},
		{
			name:     "long username",
			input:    "johndoe123",
			expected: "joh****",
		},
		{
			name:     "long sensitive data",
			input:    "verylongsensitivedata",
			expected: "ver****",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Redact(tt.input)
			if result != tt.expected {
				t.Errorf("Redact(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestRedactEmail(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty email",
			input:    "",
			expected: "",
		},
		{
			name:     "invalid email format",
			input:    "notanemail",
			expected: "not****",
		},
		{
			name:     "short local part",
			input:    "a@example.com",
			expected: "**@example.com",
		},
		{
			name:     "medium local part",
			input:    "john@example.com",
			expected: "j****@example.com",
		},
		{
			name:     "long local part",
			input:    "johndoe@example.com",
			expected: "joh****@example.com",
		},
		{
			name:     "complex email",
			input:    "john.doe+test@company.co.uk",
			expected: "joh****@company.co.uk",
		},
		{
			name:     "very long local part",
			input:    "verylongusername@domain.org",
			expected: "ver****@domain.org",
		},
		{
			name:  "multiple at signs (invalid email)",
			input: "a@b@c.com",
			// fallback to Redact of the whole string
			expected: "a@b****",
		},
		{
			name:  "unicode local part",
			input: "jóse@example.com",
			// 4 runes -> first rune + ****
			expected: "j****@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RedactEmail(tt.input)
			if result != tt.expected {
				t.Errorf("RedactEmail(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestRedactJWTs(t *testing.T) {
	// JWT-shaped strings built from repeated chars to avoid triggering secret scanners.
	// Pattern: three base64url segments separated by dots, each ≥10 chars.
	jwt1 := strings.Repeat("a", 16) + "." + strings.Repeat("b", 24) + "." + strings.Repeat("c", 32)
	jwt2 := strings.Repeat("x", 20) + "." + strings.Repeat("y", 18) + "." + strings.Repeat("z", 28)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "no JWT present",
			input:    `{"provider":"linkedin","user_id":"QhNK44iR6W"}`,
			expected: `{"provider":"linkedin","user_id":"QhNK44iR6W"}`,
		},
		{
			name:     "single JWT in JSON body",
			input:    `{"link_with":"` + jwt1 + `"}`,
			expected: `{"link_with":"[REDACTED]"}`,
		},
		{
			name:     "multiple JWTs in body",
			input:    `{"auth_token":"` + jwt1 + `","identity_token":"` + jwt2 + `"}`,
			expected: `{"auth_token":"[REDACTED]","identity_token":"[REDACTED]"}`,
		},
		{
			name:     "JWT as plain string",
			input:    jwt1,
			expected: "[REDACTED]",
		},
		{
			name:     "non-JWT dot-separated string (segments too short)",
			input:    "foo.bar.baz",
			expected: "foo.bar.baz",
		},
		{
			name:     "mixed content with JWT",
			input:    `calling API url=https://example.auth0.com token=` + jwt1,
			expected: `calling API url=https://example.auth0.com token=[REDACTED]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RedactJWTs(tt.input)
			if result != tt.expected {
				t.Errorf("RedactJWTs(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// Benchmarks to ensure redaction performance is acceptable
func BenchmarkRedact(b *testing.B) {
	testString := "johndoe123@example.com"
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		Redact(testString)
	}
}

func BenchmarkRedactEmail(b *testing.B) {
	testEmail := "john.doe+test@company.co.uk"
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		RedactEmail(testEmail)
	}
}
