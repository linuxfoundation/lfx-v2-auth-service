// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package converters

import (
	"testing"
)

func TestStringPtr(t *testing.T) {
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
			name:     "simple string",
			input:    "hello",
			expected: "hello",
		},
		{
			name:     "string with spaces",
			input:    "hello world",
			expected: "hello world",
		},
		{
			name:     "string with special characters",
			input:    "hello@example.com",
			expected: "hello@example.com",
		},
		{
			name:     "unicode string",
			input:    "こんにちは",
			expected: "こんにちは",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StringPtr(tt.input)

			// Verify it returns a pointer
			if result == nil {
				t.Error("StringPtr() returned nil pointer")
				return
			}

			// Verify the value is correct
			if *result != tt.expected {
				t.Errorf("StringPtr(%q) = %q, want %q", tt.input, *result, tt.expected)
			}

			// Verify it's actually a different address than the input
			if &tt.input == result {
				t.Error("StringPtr() returned pointer to input variable instead of creating new pointer")
			}
		})
	}
}

func TestStringPtrModification(t *testing.T) {
	t.Run("modifying returned pointer doesn't affect original", func(t *testing.T) {
		original := "original"
		ptr := StringPtr(original)

		// Modify the value through the pointer
		*ptr = "modified"

		// Verify original is unchanged
		if original != "original" {
			t.Errorf("Original string was modified: %q", original)
		}

		// Verify pointer has the new value
		if *ptr != "modified" {
			t.Errorf("Pointer value was not modified: %q", *ptr)
		}
	})
}
