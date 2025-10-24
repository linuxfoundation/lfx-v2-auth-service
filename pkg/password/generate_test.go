// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package password

import (
	"regexp"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestAlphaNum(t *testing.T) {
	tests := []struct {
		name        string
		length      int
		expectError bool
	}{
		{
			name:        "valid length 10",
			length:      10,
			expectError: false,
		},
		{
			name:        "valid length 1",
			length:      1,
			expectError: false,
		},
		{
			name:        "valid length 100",
			length:      100,
			expectError: false,
		},
		{
			name:        "invalid length 0",
			length:      0,
			expectError: true,
		},
		{
			name:        "invalid negative length",
			length:      -5,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := AlphaNum(tt.length)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				if result != "" {
					t.Errorf("expected empty string on error, got: %s", result)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Check length
			if len(result) != tt.length {
				t.Errorf("expected length %d, got %d", tt.length, len(result))
			}

			// Check that string only contains alphanumeric characters
			matched, _ := regexp.MatchString("^[a-zA-Z0-9]+$", result)
			if !matched {
				t.Errorf("result contains non-alphanumeric characters: %s", result)
			}
		})
	}
}

func TestAlphaNum_Randomness(t *testing.T) {
	// Generate multiple strings and ensure they're different
	const iterations = 10
	const length = 20
	results := make(map[string]bool)

	for i := 0; i < iterations; i++ {
		result, err := AlphaNum(length)
		if err != nil {
			t.Fatalf("unexpected error on iteration %d: %v", i, err)
		}
		results[result] = true
	}

	// With a length of 20 and 62 possible characters (26 lowercase + 26 uppercase + 10 digits),
	// it's extremely unlikely to get duplicates in 10 iterations
	if len(results) < iterations {
		t.Errorf("expected %d unique results, got %d (possible collision or weak randomness)", iterations, len(results))
	}
}

func TestOnlyNumbers(t *testing.T) {
	tests := []struct {
		name        string
		length      int
		expectError bool
	}{
		{
			name:        "valid length 6",
			length:      6,
			expectError: false,
		},
		{
			name:        "valid length 1",
			length:      1,
			expectError: false,
		},
		{
			name:        "valid length 50",
			length:      50,
			expectError: false,
		},
		{
			name:        "invalid length 0",
			length:      0,
			expectError: true,
		},
		{
			name:        "invalid negative length",
			length:      -10,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := OnlyNumbers(tt.length)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				if result != "" {
					t.Errorf("expected empty string on error, got: %s", result)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Check length
			if len(result) != tt.length {
				t.Errorf("expected length %d, got %d", tt.length, len(result))
			}

			// Check that string only contains digits
			matched, _ := regexp.MatchString("^[0-9]+$", result)
			if !matched {
				t.Errorf("result contains non-numeric characters: %s", result)
			}
		})
	}
}

func TestOnlyNumbers_Randomness(t *testing.T) {
	// Generate multiple strings and ensure they're different
	const iterations = 10
	const length = 10
	results := make(map[string]bool)

	for i := 0; i < iterations; i++ {
		result, err := OnlyNumbers(length)
		if err != nil {
			t.Fatalf("unexpected error on iteration %d: %v", i, err)
		}
		results[result] = true
	}

	// With a length of 10 and 10 possible digits, we should get mostly unique results
	// Allow for some collisions but ensure we have reasonable uniqueness
	if len(results) < iterations-2 {
		t.Errorf("expected at least %d unique results, got %d (possible weak randomness)", iterations-2, len(results))
	}
}

func TestGeneratePasswordPair(t *testing.T) {
	tests := []struct {
		name        string
		length      int
		expectError bool
	}{
		{
			name:        "valid length 12",
			length:      12,
			expectError: false,
		},
		{
			name:        "valid length 8",
			length:      8,
			expectError: false,
		},
		{
			name:        "valid length 20",
			length:      20,
			expectError: false,
		},
		{
			name:        "invalid length 0",
			length:      0,
			expectError: true,
		},
		{
			name:        "invalid negative length",
			length:      -1,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plainPassword, bcryptHash, err := GeneratePasswordPair(tt.length)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				if plainPassword != "" || bcryptHash != "" {
					t.Errorf("expected empty strings on error, got plainPassword: %s, bcryptHash: %s", plainPassword, bcryptHash)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Check plain password length
			if len(plainPassword) != tt.length {
				t.Errorf("expected plain password length %d, got %d", tt.length, len(plainPassword))
			}

			// Check that plain password only contains alphanumeric characters
			matched, _ := regexp.MatchString("^[a-zA-Z0-9]+$", plainPassword)
			if !matched {
				t.Errorf("plain password contains non-alphanumeric characters: %s", plainPassword)
			}

			// Check that bcrypt hash is not empty
			if bcryptHash == "" {
				t.Error("bcrypt hash is empty")
			}

			// Verify that the hash matches the plain password
			err = bcrypt.CompareHashAndPassword([]byte(bcryptHash), []byte(plainPassword))
			if err != nil {
				t.Errorf("bcrypt hash does not match plain password: %v", err)
			}

			// Check that the hash starts with bcrypt prefix
			if len(bcryptHash) < 7 || bcryptHash[:4] != "$2a$" && bcryptHash[:4] != "$2b$" {
				t.Errorf("bcrypt hash doesn't have expected format: %s", bcryptHash)
			}
		})
	}
}

func TestGeneratePasswordPair_Uniqueness(t *testing.T) {
	// Generate multiple password pairs and ensure they're unique
	const iterations = 5
	const length = 16

	plainPasswords := make(map[string]bool)
	bcryptHashes := make(map[string]bool)

	for i := 0; i < iterations; i++ {
		plainPassword, bcryptHash, err := GeneratePasswordPair(length)
		if err != nil {
			t.Fatalf("unexpected error on iteration %d: %v", i, err)
		}

		plainPasswords[plainPassword] = true
		bcryptHashes[bcryptHash] = true
	}

	// Plain passwords should all be unique
	if len(plainPasswords) != iterations {
		t.Errorf("expected %d unique plain passwords, got %d", iterations, len(plainPasswords))
	}

	// Bcrypt hashes should all be unique (even for the same password, bcrypt generates different hashes)
	if len(bcryptHashes) != iterations {
		t.Errorf("expected %d unique bcrypt hashes, got %d", iterations, len(bcryptHashes))
	}
}

func TestGeneratePasswordPair_VerifyBcryptCost(t *testing.T) {
	_, bcryptHash, err := GeneratePasswordPair(10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that bcrypt cost is DefaultCost (10)
	cost, err := bcrypt.Cost([]byte(bcryptHash))
	if err != nil {
		t.Fatalf("failed to get bcrypt cost: %v", err)
	}

	if cost != bcrypt.DefaultCost {
		t.Errorf("expected bcrypt cost %d, got %d", bcrypt.DefaultCost, cost)
	}
}
