// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package httpclient

import (
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
			name:     "invalid url",
			input:    "://bad-url",
			expected: "://bad-url",
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
