// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package model

import "testing"

func TestEmail_IsValidEmail(t *testing.T) {
	tests := []struct {
		name     string
		email    *Email
		expected bool
	}{
		{
			name: "valid simple email",
			email: &Email{
				Email: "user@example.com",
			},
			expected: true,
		},
		{
			name: "valid email with subdomain",
			email: &Email{
				Email: "user@mail.example.com",
			},
			expected: true,
		},
		{
			name: "valid email with plus sign",
			email: &Email{
				Email: "user+test@example.com",
			},
			expected: true,
		},
		{
			name: "valid email with dots in local part",
			email: &Email{
				Email: "first.last@example.com",
			},
			expected: true,
		},
		{
			name: "valid email with numbers",
			email: &Email{
				Email: "user123@example456.com",
			},
			expected: true,
		},
		{
			name: "valid email with hyphen in domain",
			email: &Email{
				Email: "user@my-domain.com",
			},
			expected: true,
		},
		{
			name: "valid email with underscore in local part",
			email: &Email{
				Email: "user_name@example.com",
			},
			expected: true,
		},
		{
			name: "valid email with multiple subdomains",
			email: &Email{
				Email: "user@mail.corp.example.com",
			},
			expected: true,
		},
		{
			name: "valid email with display name",
			email: &Email{
				Email: "John Doe <john@example.com>",
			},
			expected: true,
		},
		{
			name: "valid email with quoted display name",
			email: &Email{
				Email:         "\"John Doe\" <john@example.com>",
				EmailVerified: true,
				OTP:           "",
			},
			expected: true,
		},
		{
			name: "empty email",
			email: &Email{
				Email:         "",
				EmailVerified: false,
				OTP:           "",
			},
			expected: false,
		},
		{
			name: "email with only spaces",
			email: &Email{
				Email:         "   ",
				EmailVerified: false,
				OTP:           "",
			},
			expected: false,
		},
		{
			name: "email missing @",
			email: &Email{
				Email:         "userexample.com",
				EmailVerified: false,
				OTP:           "",
			},
			expected: false,
		},
		{
			name: "email missing domain",
			email: &Email{
				Email:         "user@",
				EmailVerified: false,
				OTP:           "",
			},
			expected: false,
		},
		{
			name: "email missing local part",
			email: &Email{
				Email:         "@example.com",
				EmailVerified: false,
				OTP:           "",
			},
			expected: false,
		},
		{
			name: "email with double @",
			email: &Email{
				Email:         "user@@example.com",
				EmailVerified: false,
				OTP:           "",
			},
			expected: false,
		},
		{
			name: "email with spaces in the middle",
			email: &Email{
				Email:         "user name@example.com",
				EmailVerified: false,
				OTP:           "",
			},
			expected: false,
		},
		{
			name: "email with invalid characters",
			email: &Email{
				Email:         "user<>@example.com",
				EmailVerified: false,
				OTP:           "",
			},
			expected: false,
		},
		{
			name: "email with missing TLD",
			email: &Email{
				Email:         "user@example",
				EmailVerified: false,
				OTP:           "",
			},
			expected: true, // RFC 5322 allows this
		},
		{
			name: "email with consecutive dots in local part",
			email: &Email{
				Email:         "user..name@example.com",
				EmailVerified: false,
				OTP:           "",
			},
			expected: false,
		},
		{
			name: "email starting with dot",
			email: &Email{
				Email:         ".user@example.com",
				EmailVerified: false,
				OTP:           "",
			},
			expected: false,
		},
		{
			name: "email ending with dot",
			email: &Email{
				Email:         "user.@example.com",
				EmailVerified: false,
				OTP:           "",
			},
			expected: false,
		},
		{
			name: "email with unicode characters",
			email: &Email{
				Email: "用户@example.com",
			},
			expected: true,
		},
		{
			name: "just @ symbol",
			email: &Email{
				Email: "@",
			},
			expected: false,
		},
		{
			name: "multiple @ symbols",
			email: &Email{
				Email: "user@domain@example.com",
			},
			expected: false,
		},
		{
			name: "email with parentheses (valid RFC 5322)",
			email: &Email{
				Email: "user(comment)@example.com",
			},
			expected: false, // Not valid in simple format
		},
		{
			name: "very long local part",
			email: &Email{
				Email: "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789@example.com",
			},
			expected: true,
		},
		{
			name: "very long domain",
			email: &Email{
				Email: "user@abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789.com",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.email.IsValidEmail()
			if result != tt.expected {
				t.Errorf("IsValidEmail() = %v, expected %v for email %q", result, tt.expected, tt.email.Email)
			}
		})
	}
}
