// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package collections

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
)

type RemoveFromSliceSuite struct {
	suite.Suite
}

func TestRemoveFromSlice(t *testing.T) {
	suite.Run(t, new(RemoveFromSliceSuite))
}

func (s *RemoveFromSliceSuite) TestIntegers() {
	tests := []struct {
		name      string
		input     []int
		condition func(int) bool
		expected  []int
	}{
		{
			name:      "removes matching elements",
			input:     []int{1, 2, 3, 4, 5},
			condition: func(n int) bool { return n%2 == 0 },
			expected:  []int{1, 3, 5},
		},
		{
			name:      "removes all elements when all match",
			input:     []int{2, 4, 6},
			condition: func(n int) bool { return n%2 == 0 },
			expected:  []int{},
		},
		{
			name:      "removes nothing when none match",
			input:     []int{1, 3, 5},
			condition: func(n int) bool { return n%2 == 0 },
			expected:  []int{1, 3, 5},
		},
		{
			name:      "empty slice returns empty slice",
			input:     []int{},
			condition: func(n int) bool { return true },
			expected:  []int{},
		},
		{
			name:      "nil slice returns nil",
			input:     nil,
			condition: func(n int) bool { return true },
			expected:  nil,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			result := RemoveFromSlice(tt.input, tt.condition)
			s.Equal(tt.expected, result)
		})
	}
}

func (s *RemoveFromSliceSuite) TestStrings() {
	tests := []struct {
		name      string
		input     []string
		condition func(string) bool
		expected  []string
	}{
		{
			name:      "removes case-insensitive match",
			input:     []string{"alice@example.com", "bob@example.com", "ALICE@EXAMPLE.COM"},
			condition: func(e string) bool { return strings.EqualFold(e, "alice@example.com") },
			expected:  []string{"bob@example.com"},
		},
		{
			name:      "removes single element from single-element slice",
			input:     []string{"only"},
			condition: func(e string) bool { return e == "only" },
			expected:  []string{},
		},
		{
			name:      "preserves order of remaining elements",
			input:     []string{"a", "b", "c", "d"},
			condition: func(e string) bool { return e == "b" || e == "d" },
			expected:  []string{"a", "c"},
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			result := RemoveFromSlice(tt.input, tt.condition)
			s.Equal(tt.expected, result)
		})
	}
}

type item struct {
	ID    string
	Value string
}

func (s *RemoveFromSliceSuite) TestStructs() {
	tests := []struct {
		name      string
		input     []item
		condition func(item) bool
		expected  []item
	}{
		{
			name: "removes by field match",
			input: []item{
				{ID: "a", Value: "keep"},
				{ID: "b", Value: "remove"},
				{ID: "c", Value: "keep"},
			},
			condition: func(it item) bool { return it.Value == "remove" },
			expected: []item{
				{ID: "a", Value: "keep"},
				{ID: "c", Value: "keep"},
			},
		},
		{
			name: "removes by compound field condition",
			input: []item{
				{ID: "google", Value: "abc123"},
				{ID: "linkedin", Value: "xyz456"},
				{ID: "google", Value: "other"},
			},
			condition: func(it item) bool { return it.ID == "google" && it.Value == "abc123" },
			expected: []item{
				{ID: "linkedin", Value: "xyz456"},
				{ID: "google", Value: "other"},
			},
		},
		{
			name:      "no-op when no element matches",
			input:     []item{{ID: "a", Value: "v"}},
			condition: func(it item) bool { return it.ID == "z" },
			expected:  []item{{ID: "a", Value: "v"}},
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			result := RemoveFromSlice(tt.input, tt.condition)
			s.Equal(tt.expected, result)
		})
	}
}
