// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package model

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/converters"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
)

func TestUser_Validate(t *testing.T) {
	tests := []struct {
		name    string
		user    *User
		wantErr bool
		errType string
	}{
		{
			name: "valid user with all required fields",
			user: &User{
				Token:        "valid-token",
				UserID:       "user-123",
				PrimaryEmail: "user@example.com",
				UserMetadata: &UserMetadata{
					Name: converters.StringPtr("John Doe"),
				},
			},
			wantErr: false,
		},
		{
			name: "missing token",
			user: &User{
				UserID:       "user-123",
				PrimaryEmail: "user@example.com",
				UserMetadata: &UserMetadata{
					Name: converters.StringPtr("John Doe"),
				},
			},
			wantErr: true,
			errType: "validation",
		},
		{
			name: "empty token",
			user: &User{
				Token:        "",
				UserID:       "user-123",
				PrimaryEmail: "user@example.com",
				UserMetadata: &UserMetadata{
					Name: converters.StringPtr("John Doe"),
				},
			},
			wantErr: true,
			errType: "validation",
		},
		{
			name: "token with only spaces",
			user: &User{
				Token:        "   ",
				UserID:       "user-123",
				PrimaryEmail: "user@example.com",
				UserMetadata: &UserMetadata{
					Name: converters.StringPtr("John Doe"),
				},
			},
			wantErr: true,
			errType: "validation",
		},
		{
			name: "missing user_metadata",
			user: &User{
				Token:        "valid-token",
				UserID:       "user-123",
				PrimaryEmail: "user@example.com",
				UserMetadata: nil,
			},
			wantErr: true,
			errType: "validation",
		},
		{
			name: "valid user with metadata",
			user: &User{
				Token:        "valid-token",
				UserID:       "user-123",
				PrimaryEmail: "user@example.com",
				UserMetadata: &UserMetadata{
					Name:     converters.StringPtr("John Doe"),
					JobTitle: converters.StringPtr("Software Engineer"),
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.user.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("User.Validate() expected error, got nil")
					return
				}
				if tt.errType == "validation" {
					if _, ok := err.(errors.Validation); !ok {
						t.Errorf("User.Validate() expected Validation error, got %T", err)
					}
				}
			} else if err != nil {
				t.Errorf("User.Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestUser_UserSanitize(t *testing.T) {
	tests := []struct {
		name     string
		user     *User
		expected *User
	}{
		{
			name: "sanitize basic user fields - no metadata",
			user: &User{
				Token:        "  token-with-spaces  ",
				Username:     "  username  ",
				UserID:       "  user-123  ",
				PrimaryEmail: "  user@example.com  ",
			},
			expected: &User{
				Token:        "token-with-spaces",
				Username:     "username",
				UserID:       "user-123",
				PrimaryEmail: "user@example.com",
			},
		},
		{
			name: "sanitize user with metadata",
			user: &User{
				Token:        "  token  ",
				Username:     "  username  ",
				UserID:       "  user-123  ",
				PrimaryEmail: "  user@example.com  ",
				UserMetadata: &UserMetadata{
					Name:          converters.StringPtr("  John Doe  "),
					GivenName:     converters.StringPtr("  John  "),
					FamilyName:    converters.StringPtr("  Doe  "),
					JobTitle:      converters.StringPtr("  Software Engineer  "),
					Organization:  converters.StringPtr("  ACME Corp  "),
					Country:       converters.StringPtr("  USA  "),
					StateProvince: converters.StringPtr("  California  "),
					City:          converters.StringPtr("  San Francisco  "),
					Address:       converters.StringPtr("  123 Main St  "),
					PostalCode:    converters.StringPtr("  94102  "),
					PhoneNumber:   converters.StringPtr("  +1-555-123-4567  "),
					TShirtSize:    converters.StringPtr("  M  "),
					Picture:       converters.StringPtr("  https://example.com/pic.jpg  "),
					Zoneinfo:      converters.StringPtr("  America/Los_Angeles  "),
				},
			},
			expected: &User{
				Token:        "token",
				Username:     "username",
				UserID:       "user-123",
				PrimaryEmail: "user@example.com",
				UserMetadata: &UserMetadata{
					Name:          converters.StringPtr("John Doe"),
					GivenName:     converters.StringPtr("John"),
					FamilyName:    converters.StringPtr("Doe"),
					JobTitle:      converters.StringPtr("Software Engineer"),
					Organization:  converters.StringPtr("ACME Corp"),
					Country:       converters.StringPtr("USA"),
					StateProvince: converters.StringPtr("California"),
					City:          converters.StringPtr("San Francisco"),
					Address:       converters.StringPtr("123 Main St"),
					PostalCode:    converters.StringPtr("94102"),
					PhoneNumber:   converters.StringPtr("+1-555-123-4567"),
					TShirtSize:    converters.StringPtr("M"),
					Picture:       converters.StringPtr("https://example.com/pic.jpg"),
					Zoneinfo:      converters.StringPtr("America/Los_Angeles"),
				},
			},
		},
		{
			name: "sanitize user with nil metadata",
			user: &User{
				Token:        "  token  ",
				Username:     "  username  ",
				UserID:       "  user-123  ",
				PrimaryEmail: "  user@example.com  ",
				UserMetadata: nil,
			},
			expected: &User{
				Token:        "token",
				Username:     "username",
				UserID:       "user-123",
				PrimaryEmail: "user@example.com",
				UserMetadata: nil,
			},
		},
		{
			name: "sanitize user with metadata containing nil fields",
			user: &User{
				Token:        "  token  ",
				Username:     "  username  ",
				UserID:       "  user-123  ",
				PrimaryEmail: "  user@example.com  ",
				UserMetadata: &UserMetadata{
					Name:         converters.StringPtr("  John Doe  "),
					GivenName:    nil,
					FamilyName:   converters.StringPtr("  Doe  "),
					JobTitle:     nil,
					Organization: converters.StringPtr("  ACME Corp  "),
				},
			},
			expected: &User{
				Token:        "token",
				Username:     "username",
				UserID:       "user-123",
				PrimaryEmail: "user@example.com",
				UserMetadata: &UserMetadata{
					Name:         converters.StringPtr("John Doe"),
					GivenName:    nil,
					FamilyName:   converters.StringPtr("Doe"),
					JobTitle:     nil,
					Organization: converters.StringPtr("ACME Corp"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make a copy to avoid modifying the original
			userCopy := *tt.user
			if tt.user.UserMetadata != nil {
				metadataCopy := *tt.user.UserMetadata
				userCopy.UserMetadata = &metadataCopy
			}

			userCopy.UserSanitize()

			// Check basic fields
			if userCopy.Token != tt.expected.Token {
				t.Errorf("Token = %q, want %q", userCopy.Token, tt.expected.Token)
			}
			if userCopy.Username != tt.expected.Username {
				t.Errorf("Username = %q, want %q", userCopy.Username, tt.expected.Username)
			}
			if userCopy.UserID != tt.expected.UserID {
				t.Errorf("UserID = %q, want %q", userCopy.UserID, tt.expected.UserID)
			}
			if userCopy.PrimaryEmail != tt.expected.PrimaryEmail {
				t.Errorf("PrimaryEmail = %q, want %q", userCopy.PrimaryEmail, tt.expected.PrimaryEmail)
			}

			// Check metadata
			if tt.expected.UserMetadata == nil {
				if userCopy.UserMetadata != nil {
					t.Errorf("UserMetadata = %v, want nil", userCopy.UserMetadata)
				}
				return
			}

			if userCopy.UserMetadata == nil {
				t.Errorf("UserMetadata = nil, want %v", tt.expected.UserMetadata)
				return
			}

			// Check metadata fields
			checkStringPtr := func(fieldName string, got, want *string) {
				if (got == nil) != (want == nil) {
					t.Errorf("%s pointer mismatch: got nil=%v, want nil=%v", fieldName, got == nil, want == nil)
					return
				}
				if got != nil && want != nil && *got != *want {
					t.Errorf("%s = %q, want %q", fieldName, *got, *want)
				}
			}

			checkStringPtr("Name", userCopy.UserMetadata.Name, tt.expected.UserMetadata.Name)
			checkStringPtr("GivenName", userCopy.UserMetadata.GivenName, tt.expected.UserMetadata.GivenName)
			checkStringPtr("FamilyName", userCopy.UserMetadata.FamilyName, tt.expected.UserMetadata.FamilyName)
			checkStringPtr("JobTitle", userCopy.UserMetadata.JobTitle, tt.expected.UserMetadata.JobTitle)
			checkStringPtr("Organization", userCopy.UserMetadata.Organization, tt.expected.UserMetadata.Organization)
			checkStringPtr("Country", userCopy.UserMetadata.Country, tt.expected.UserMetadata.Country)
			checkStringPtr("StateProvince", userCopy.UserMetadata.StateProvince, tt.expected.UserMetadata.StateProvince)
			checkStringPtr("City", userCopy.UserMetadata.City, tt.expected.UserMetadata.City)
			checkStringPtr("Address", userCopy.UserMetadata.Address, tt.expected.UserMetadata.Address)
			checkStringPtr("PostalCode", userCopy.UserMetadata.PostalCode, tt.expected.UserMetadata.PostalCode)
			checkStringPtr("PhoneNumber", userCopy.UserMetadata.PhoneNumber, tt.expected.UserMetadata.PhoneNumber)
			checkStringPtr("TShirtSize", userCopy.UserMetadata.TShirtSize, tt.expected.UserMetadata.TShirtSize)
			checkStringPtr("Picture", userCopy.UserMetadata.Picture, tt.expected.UserMetadata.Picture)
			checkStringPtr("Zoneinfo", userCopy.UserMetadata.Zoneinfo, tt.expected.UserMetadata.Zoneinfo)
		})
	}
}

func TestUserMetadata_userMetadataSanitize(t *testing.T) {
	t.Run("sanitize all fields", func(t *testing.T) {
		metadata := &UserMetadata{
			Name:          converters.StringPtr("  John Doe  "),
			GivenName:     converters.StringPtr("  John  "),
			FamilyName:    converters.StringPtr("  Doe  "),
			JobTitle:      converters.StringPtr("  Software Engineer  "),
			Organization:  converters.StringPtr("  ACME Corp  "),
			Country:       converters.StringPtr("  USA  "),
			StateProvince: converters.StringPtr("  California  "),
			City:          converters.StringPtr("  San Francisco  "),
			Address:       converters.StringPtr("  123 Main St  "),
			PostalCode:    converters.StringPtr("  94102  "),
			PhoneNumber:   converters.StringPtr("  +1-555-123-4567  "),
			TShirtSize:    converters.StringPtr("  M  "),
			Picture:       converters.StringPtr("  https://example.com/pic.jpg  "),
			Zoneinfo:      converters.StringPtr("  America/Los_Angeles  "),
		}

		metadata.userMetadataSanitize()

		expected := map[string]string{
			"Name":          "John Doe",
			"GivenName":     "John",
			"FamilyName":    "Doe",
			"JobTitle":      "Software Engineer",
			"Organization":  "ACME Corp",
			"Country":       "USA",
			"StateProvince": "California",
			"City":          "San Francisco",
			"Address":       "123 Main St",
			"PostalCode":    "94102",
			"PhoneNumber":   "+1-555-123-4567",
			"TShirtSize":    "M",
			"Picture":       "https://example.com/pic.jpg",
			"Zoneinfo":      "America/Los_Angeles",
		}

		checks := map[string]*string{
			"Name":          metadata.Name,
			"GivenName":     metadata.GivenName,
			"FamilyName":    metadata.FamilyName,
			"JobTitle":      metadata.JobTitle,
			"Organization":  metadata.Organization,
			"Country":       metadata.Country,
			"StateProvince": metadata.StateProvince,
			"City":          metadata.City,
			"Address":       metadata.Address,
			"PostalCode":    metadata.PostalCode,
			"PhoneNumber":   metadata.PhoneNumber,
			"TShirtSize":    metadata.TShirtSize,
			"Picture":       metadata.Picture,
			"Zoneinfo":      metadata.Zoneinfo,
		}

		for fieldName, got := range checks {
			want := expected[fieldName]
			if got == nil {
				t.Errorf("%s = nil, want %q", fieldName, want)
			} else if *got != want {
				t.Errorf("%s = %q, want %q", fieldName, *got, want)
			}
		}
	})

	t.Run("handle nil fields", func(t *testing.T) {
		metadata := &UserMetadata{
			Name:         converters.StringPtr("  John Doe  "),
			GivenName:    nil,
			FamilyName:   converters.StringPtr("  Doe  "),
			JobTitle:     nil,
			Organization: converters.StringPtr("  ACME Corp  "),
		}

		metadata.userMetadataSanitize()

		if metadata.Name == nil || *metadata.Name != "John Doe" {
			t.Errorf("Name not sanitized correctly")
		}
		if metadata.GivenName != nil {
			t.Errorf("GivenName should remain nil")
		}
		if metadata.FamilyName == nil || *metadata.FamilyName != "Doe" {
			t.Errorf("FamilyName not sanitized correctly")
		}
		if metadata.JobTitle != nil {
			t.Errorf("JobTitle should remain nil")
		}
		if metadata.Organization == nil || *metadata.Organization != "ACME Corp" {
			t.Errorf("Organization not sanitized correctly")
		}
	})
}

func TestUser_PrepareForMetadataLookup(t *testing.T) {
	tests := []struct {
		name              string
		input             string
		expectedCanonical bool
		expectedSub       string
		expectedUserID    string
		expectedUsername  string
	}{
		{
			name:              "canonical lookup with auth0 connection",
			input:             "auth0|123456789",
			expectedCanonical: true,
			expectedSub:       "auth0|123456789",
			expectedUserID:    "auth0|123456789",
			expectedUsername:  "",
		},
		{
			name:              "canonical lookup with google oauth2",
			input:             "google-oauth2|987654321",
			expectedCanonical: true,
			expectedSub:       "google-oauth2|987654321",
			expectedUserID:    "google-oauth2|987654321",
			expectedUsername:  "",
		},
		{
			name:              "canonical lookup with github connection",
			input:             "github|456789123",
			expectedCanonical: true,
			expectedSub:       "github|456789123",
			expectedUserID:    "github|456789123",
			expectedUsername:  "",
		},
		{
			name:              "canonical lookup with samlp enterprise",
			input:             "samlp|enterprise|user123",
			expectedCanonical: true,
			expectedSub:       "samlp|enterprise|user123",
			expectedUserID:    "samlp|enterprise|user123",
			expectedUsername:  "",
		},
		{
			name:              "canonical lookup with linkedin",
			input:             "linkedin|789123456",
			expectedCanonical: true,
			expectedSub:       "linkedin|789123456",
			expectedUserID:    "linkedin|789123456",
			expectedUsername:  "",
		},
		{
			name:              "search lookup with simple username",
			input:             "john.doe",
			expectedCanonical: false,
			expectedSub:       "",
			expectedUserID:    "",
			expectedUsername:  "john.doe",
		},
		{
			name:              "search lookup with complex username",
			input:             "jane.smith123",
			expectedCanonical: false,
			expectedSub:       "",
			expectedUserID:    "",
			expectedUsername:  "jane.smith123",
		},
		{
			name:              "search lookup with developer username",
			input:             "developer123",
			expectedCanonical: false,
			expectedSub:       "",
			expectedUserID:    "",
			expectedUsername:  "developer123",
		},
		{
			name:              "canonical lookup with spaces (trimmed)",
			input:             "  auth0|123456789  ",
			expectedCanonical: true,
			expectedSub:       "auth0|123456789",
			expectedUserID:    "auth0|123456789",
			expectedUsername:  "",
		},
		{
			name:              "search lookup with spaces (trimmed)",
			input:             "  john.doe  ",
			expectedCanonical: false,
			expectedSub:       "",
			expectedUserID:    "",
			expectedUsername:  "john.doe",
		},
		{
			name:              "canonical lookup with pipe at start",
			input:             "|startpipe",
			expectedCanonical: true,
			expectedSub:       "|startpipe",
			expectedUserID:    "|startpipe",
			expectedUsername:  "",
		},
		{
			name:              "canonical lookup with pipe at end",
			input:             "endpipe|",
			expectedCanonical: true,
			expectedSub:       "endpipe|",
			expectedUserID:    "endpipe|",
			expectedUsername:  "",
		},
		{
			name:              "empty input (search strategy)",
			input:             "",
			expectedCanonical: false,
			expectedSub:       "",
			expectedUserID:    "",
			expectedUsername:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &User{}
			result := user.PrepareForMetadataLookup(tt.input)

			// Check strategy result
			if result != tt.expectedCanonical {
				t.Errorf("PrepareForMetadataLookup() returned %v, expected %v", result, tt.expectedCanonical)
			}

			// Check Sub field
			if user.Sub != tt.expectedSub {
				t.Errorf("Sub = %q, expected %q", user.Sub, tt.expectedSub)
			}

			// Check UserID field
			if user.UserID != tt.expectedUserID {
				t.Errorf("UserID = %q, expected %q", user.UserID, tt.expectedUserID)
			}

			// Check Username field
			if user.Username != tt.expectedUsername {
				t.Errorf("Username = %q, expected %q", user.Username, tt.expectedUsername)
			}
		})
	}
}

func TestUser_PrepareForMetadataLookup_Idempotency(t *testing.T) {
	// Test that calling PrepareForMetadataLookup multiple times with the same input
	// produces the same result
	user := &User{}

	// First call
	result1 := user.PrepareForMetadataLookup("auth0|123456789")
	sub1, userID1, username1 := user.Sub, user.UserID, user.Username

	// Second call with same input
	result2 := user.PrepareForMetadataLookup("auth0|123456789")
	sub2, userID2, username2 := user.Sub, user.UserID, user.Username

	// Results should be identical
	if result1 != result2 {
		t.Errorf("PrepareForMetadataLookup() not idempotent: first=%v, second=%v", result1, result2)
	}
	if sub1 != sub2 {
		t.Errorf("Sub not idempotent: first=%q, second=%q", sub1, sub2)
	}
	if userID1 != userID2 {
		t.Errorf("UserID not idempotent: first=%q, second=%q", userID1, userID2)
	}
	if username1 != username2 {
		t.Errorf("Username not idempotent: first=%q, second=%q", username1, username2)
	}
}

func TestUser_PrepareForMetadataLookup_StrategySwitch(t *testing.T) {
	// Test that switching between strategies properly clears the other fields
	user := &User{}

	// Start with canonical lookup
	canonical := user.PrepareForMetadataLookup("auth0|123456789")
	if !canonical {
		t.Fatal("Expected canonical strategy")
	}
	if user.Sub == "" || user.UserID == "" || user.Username != "" {
		t.Errorf("Canonical strategy fields not set correctly: Sub=%q, UserID=%q, Username=%q",
			user.Sub, user.UserID, user.Username)
	}

	// Switch to search lookup
	search := user.PrepareForMetadataLookup("john.doe")
	if search {
		t.Fatal("Expected search strategy")
	}
	if user.Sub != "" || user.UserID != "" || user.Username == "" {
		t.Errorf("Search strategy fields not set correctly: Sub=%q, UserID=%q, Username=%q",
			user.Sub, user.UserID, user.Username)
	}
}

func TestUser_PrepareForMetadataLookup_PreservesOtherFields(t *testing.T) {
	// Test that PrepareForMetadataLookup doesn't modify other user fields
	user := &User{
		Token:        "test-token",
		PrimaryEmail: "test@example.com",
		UserMetadata: &UserMetadata{
			Name: converters.StringPtr("Test User"),
		},
	}

	originalToken := user.Token
	originalEmail := user.PrimaryEmail
	originalMetadata := user.UserMetadata

	user.PrepareForMetadataLookup("auth0|123456789")

	if user.Token != originalToken {
		t.Errorf("Token was modified: got %q, expected %q", user.Token, originalToken)
	}
	if user.PrimaryEmail != originalEmail {
		t.Errorf("PrimaryEmail was modified: got %q, expected %q", user.PrimaryEmail, originalEmail)
	}
	if user.UserMetadata != originalMetadata {
		t.Errorf("UserMetadata was modified")
	}
}

func TestUser_buildIndexKey(t *testing.T) {
	tests := []struct {
		name         string
		kind         string
		data         string
		expectedHash string
	}{
		{
			name:         "simple email data",
			kind:         "email",
			data:         "user@example.com",
			expectedHash: "b4c9a289323b21a01c3e940f150eb9b8c542587f1abfd8f0e1cc1ffc5e475514", // SHA256 of "user@example.com"
		},
		{
			name:         "empty data",
			kind:         "email",
			data:         "",
			expectedHash: "",
		},
		{
			name:         "data with special characters",
			kind:         "email",
			data:         "user+test@example.com",
			expectedHash: "", // Will be calculated in test
		},
		{
			name:         "unicode data",
			kind:         "email",
			data:         "用户@example.com",
			expectedHash: "", // Will be calculated in test
		},
		{
			name:         "long data string",
			kind:         "email",
			data:         strings.Repeat("a", 1000),
			expectedHash: "", // Will be calculated in test
		},
		{
			name:         "different kind same data",
			kind:         "username",
			data:         "user@example.com",
			expectedHash: "b4c9a289323b21a01c3e940f150eb9b8c542587f1abfd8f0e1cc1ffc5e475514", // Same hash as kind doesn't affect hash
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := User{}
			ctx := context.Background()

			result := user.buildIndexKey(ctx, tt.kind, tt.data)

			// Calculate expected hash if not provided
			expectedHash := tt.expectedHash
			if expectedHash == "" {
				hash := sha256.Sum256([]byte(tt.data))
				expectedHash = hex.EncodeToString(hash[:])
			}

			// Verify the result matches expected hash
			if result != expectedHash {
				t.Errorf("buildIndexKey() = %q, want %q", result, expectedHash)
			}

			// Verify the result is a valid hex string of correct length (64 chars for SHA256)
			if len(result) != 64 {
				t.Errorf("buildIndexKey() result length = %d, want 64", len(result))
			}

			// Verify it's valid hex
			if _, err := hex.DecodeString(result); err != nil {
				t.Errorf("buildIndexKey() result is not valid hex: %v", err)
			}
		})
	}
}

func TestUser_buildIndexKey_Consistency(t *testing.T) {
	// Test that the same input always produces the same output
	user := User{}
	ctx := context.Background()
	data := "test@example.com"
	kind := "email"

	result1 := user.buildIndexKey(ctx, kind, data)
	result2 := user.buildIndexKey(ctx, kind, data)

	if result1 != result2 {
		t.Errorf("buildIndexKey() not consistent: first=%q, second=%q", result1, result2)
	}
}

func TestUser_BuildEmailIndexKey(t *testing.T) {
	tests := []struct {
		name         string
		primaryEmail string
		expected     string
	}{
		{
			name:         "simple email",
			primaryEmail: "user@example.com",
			expected:     "", // Will be calculated
		},
		{
			name:         "email with uppercase",
			primaryEmail: "USER@EXAMPLE.COM",
			expected:     "", // Should be same as lowercase version
		},
		{
			name:         "email with mixed case",
			primaryEmail: "User@Example.Com",
			expected:     "", // Should be same as lowercase version
		},
		{
			name:         "email with leading/trailing spaces",
			primaryEmail: "  user@example.com  ",
			expected:     "", // Should be same as trimmed version
		},
		{
			name:         "email with leading/trailing spaces and mixed case",
			primaryEmail: "  USER@EXAMPLE.COM  ",
			expected:     "", // Should be same as trimmed lowercase version
		},
		{
			name:         "empty email",
			primaryEmail: "",
			expected:     "",
		},
		{
			name:         "email with only spaces",
			primaryEmail: "   ",
			expected:     "",
		},
		{
			name:         "email with plus sign",
			primaryEmail: "user+test@example.com",
			expected:     "", // Will be calculated
		},
		{
			name:         "email with dots in local part",
			primaryEmail: "user.name@example.com",
			expected:     "", // Will be calculated
		},
		{
			name:         "email with subdomain",
			primaryEmail: "user@mail.example.com",
			expected:     "", // Will be calculated
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := User{PrimaryEmail: tt.primaryEmail}
			ctx := context.Background()

			result := user.BuildEmailIndexKey(ctx)

			// Calculate expected hash
			var expectedHash string
			if tt.expected != "" {
				expectedHash = tt.expected
			} else {
				// Check if this is a case where we expect empty string explicitly
				normalizedEmail := strings.TrimSpace(strings.ToLower(tt.primaryEmail))
				if normalizedEmail == "" {
					expectedHash = "" // Empty emails should return empty string
				} else {
					hash := sha256.Sum256([]byte(normalizedEmail))
					expectedHash = hex.EncodeToString(hash[:])
				}
			}

			if result != expectedHash {
				t.Errorf("BuildEmailIndexKey() = %q, want %q", result, expectedHash)
			}
			// Verify it's valid hex
			if result == "" {
				if _, err := hex.DecodeString(result); err != nil {
					t.Errorf("BuildEmailIndexKey() result is not valid hex: %v", err)
				}
			}
		})
	}
}

func TestUser_BuildEmailIndexKey_Normalization(t *testing.T) {
	// Test that different representations of the same email produce the same hash
	ctx := context.Background()

	testCases := []struct {
		name   string
		emails []string // All should produce the same hash
	}{
		{
			name: "case normalization",
			emails: []string{
				"user@example.com",
				"USER@EXAMPLE.COM",
				"User@Example.Com",
				"uSeR@eXaMpLe.CoM",
			},
		},
		{
			name: "whitespace normalization",
			emails: []string{
				"user@example.com",
				"  user@example.com",
				"user@example.com  ",
				"  user@example.com  ",
				"\t user@example.com \n",
			},
		},
		{
			name: "combined normalization",
			emails: []string{
				"user@example.com",
				"  USER@EXAMPLE.COM  ",
				"\t User@Example.Com \n",
				"uSeR@eXaMpLe.CoM",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var hashes []string

			for _, email := range tc.emails {
				user := User{PrimaryEmail: email}
				hash := user.BuildEmailIndexKey(ctx)
				hashes = append(hashes, hash)
			}

			// All hashes should be identical
			firstHash := hashes[0]
			for i, hash := range hashes {
				if hash != firstHash {
					t.Errorf("Email %q (index %d) produced hash %q, expected %q",
						tc.emails[i], i, hash, firstHash)
				}
			}
		})
	}
}

func TestUser_BuildEmailIndexKey_Consistency(t *testing.T) {
	// Test that multiple calls with the same user produce the same result
	user := User{PrimaryEmail: "test@example.com"}
	ctx := context.Background()

	result1 := user.BuildEmailIndexKey(ctx)
	result2 := user.BuildEmailIndexKey(ctx)

	if result1 != result2 {
		t.Errorf("BuildEmailIndexKey() not consistent: first=%q, second=%q", result1, result2)
	}
}

func TestUserMetadata_Patch(t *testing.T) {
	tests := []struct {
		name           string
		original       *UserMetadata
		update         *UserMetadata
		expectedResult bool
		expectedFinal  *UserMetadata
	}{
		{
			name:           "nil update returns false",
			original:       &UserMetadata{Name: converters.StringPtr("John")},
			update:         nil,
			expectedResult: false,
			expectedFinal:  &UserMetadata{Name: converters.StringPtr("John")},
		},
		{
			name:           "update single field",
			original:       &UserMetadata{Name: converters.StringPtr("John")},
			update:         &UserMetadata{GivenName: converters.StringPtr("Johnny")},
			expectedResult: true,
			expectedFinal: &UserMetadata{
				Name:      converters.StringPtr("John"),
				GivenName: converters.StringPtr("Johnny"),
			},
		},
		{
			name: "update multiple fields",
			original: &UserMetadata{
				Name:      converters.StringPtr("John"),
				GivenName: converters.StringPtr("Johnny"),
			},
			update: &UserMetadata{
				FamilyName:   converters.StringPtr("Doe"),
				JobTitle:     converters.StringPtr("Engineer"),
				Organization: converters.StringPtr("ACME"),
			},
			expectedResult: true,
			expectedFinal: &UserMetadata{
				Name:         converters.StringPtr("John"),
				GivenName:    converters.StringPtr("Johnny"),
				FamilyName:   converters.StringPtr("Doe"),
				JobTitle:     converters.StringPtr("Engineer"),
				Organization: converters.StringPtr("ACME"),
			},
		},
		{
			name: "overwrite existing fields",
			original: &UserMetadata{
				Name:      converters.StringPtr("John"),
				GivenName: converters.StringPtr("Johnny"),
				JobTitle:  converters.StringPtr("Developer"),
			},
			update: &UserMetadata{
				GivenName: converters.StringPtr("Jon"),
				JobTitle:  converters.StringPtr("Senior Engineer"),
			},
			expectedResult: true,
			expectedFinal: &UserMetadata{
				Name:      converters.StringPtr("John"),
				GivenName: converters.StringPtr("Jon"),
				JobTitle:  converters.StringPtr("Senior Engineer"),
			},
		},
		{
			name:     "update all fields",
			original: &UserMetadata{},
			update: &UserMetadata{
				Picture:       converters.StringPtr("pic.jpg"),
				Zoneinfo:      converters.StringPtr("UTC"),
				Name:          converters.StringPtr("John Doe"),
				GivenName:     converters.StringPtr("John"),
				FamilyName:    converters.StringPtr("Doe"),
				JobTitle:      converters.StringPtr("Engineer"),
				Organization:  converters.StringPtr("ACME Corp"),
				Country:       converters.StringPtr("USA"),
				StateProvince: converters.StringPtr("CA"),
				City:          converters.StringPtr("SF"),
				Address:       converters.StringPtr("123 Main St"),
				PostalCode:    converters.StringPtr("94102"),
				PhoneNumber:   converters.StringPtr("+1-555-1234"),
				TShirtSize:    converters.StringPtr("L"),
			},
			expectedResult: true,
			expectedFinal: &UserMetadata{
				Picture:       converters.StringPtr("pic.jpg"),
				Zoneinfo:      converters.StringPtr("UTC"),
				Name:          converters.StringPtr("John Doe"),
				GivenName:     converters.StringPtr("John"),
				FamilyName:    converters.StringPtr("Doe"),
				JobTitle:      converters.StringPtr("Engineer"),
				Organization:  converters.StringPtr("ACME Corp"),
				Country:       converters.StringPtr("USA"),
				StateProvince: converters.StringPtr("CA"),
				City:          converters.StringPtr("SF"),
				Address:       converters.StringPtr("123 Main St"),
				PostalCode:    converters.StringPtr("94102"),
				PhoneNumber:   converters.StringPtr("+1-555-1234"),
				TShirtSize:    converters.StringPtr("L"),
			},
		},
		{
			name: "update with nil fields (no change)",
			original: &UserMetadata{
				Name:      converters.StringPtr("John"),
				GivenName: converters.StringPtr("Johnny"),
			},
			update: &UserMetadata{
				Name:      nil,
				GivenName: nil,
				JobTitle:  nil,
			},
			expectedResult: false,
			expectedFinal: &UserMetadata{
				Name:      converters.StringPtr("John"),
				GivenName: converters.StringPtr("Johnny"),
			},
		},
		{
			name: "mixed nil and non-nil updates",
			original: &UserMetadata{
				Name:     converters.StringPtr("John"),
				JobTitle: converters.StringPtr("Developer"),
			},
			update: &UserMetadata{
				Name:         nil,                            // Should not update
				GivenName:    converters.StringPtr("Johnny"), // Should update
				JobTitle:     nil,                            // Should not update
				Organization: converters.StringPtr("ACME"),   // Should update
			},
			expectedResult: true,
			expectedFinal: &UserMetadata{
				Name:         converters.StringPtr("John"),
				GivenName:    converters.StringPtr("Johnny"),
				JobTitle:     converters.StringPtr("Developer"),
				Organization: converters.StringPtr("ACME"),
			},
		},
		{
			name:           "empty update object",
			original:       &UserMetadata{Name: converters.StringPtr("John")},
			update:         &UserMetadata{},
			expectedResult: false,
			expectedFinal:  &UserMetadata{Name: converters.StringPtr("John")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make a deep copy of original to avoid modifying test data
			originalCopy := &UserMetadata{}
			if tt.original != nil {
				*originalCopy = *tt.original
				// Copy pointer fields
				if tt.original.Picture != nil {
					originalCopy.Picture = converters.StringPtr(*tt.original.Picture)
				}
				if tt.original.Zoneinfo != nil {
					originalCopy.Zoneinfo = converters.StringPtr(*tt.original.Zoneinfo)
				}
				if tt.original.Name != nil {
					originalCopy.Name = converters.StringPtr(*tt.original.Name)
				}
				if tt.original.GivenName != nil {
					originalCopy.GivenName = converters.StringPtr(*tt.original.GivenName)
				}
				if tt.original.FamilyName != nil {
					originalCopy.FamilyName = converters.StringPtr(*tt.original.FamilyName)
				}
				if tt.original.JobTitle != nil {
					originalCopy.JobTitle = converters.StringPtr(*tt.original.JobTitle)
				}
				if tt.original.Organization != nil {
					originalCopy.Organization = converters.StringPtr(*tt.original.Organization)
				}
				if tt.original.Country != nil {
					originalCopy.Country = converters.StringPtr(*tt.original.Country)
				}
				if tt.original.StateProvince != nil {
					originalCopy.StateProvince = converters.StringPtr(*tt.original.StateProvince)
				}
				if tt.original.City != nil {
					originalCopy.City = converters.StringPtr(*tt.original.City)
				}
				if tt.original.Address != nil {
					originalCopy.Address = converters.StringPtr(*tt.original.Address)
				}
				if tt.original.PostalCode != nil {
					originalCopy.PostalCode = converters.StringPtr(*tt.original.PostalCode)
				}
				if tt.original.PhoneNumber != nil {
					originalCopy.PhoneNumber = converters.StringPtr(*tt.original.PhoneNumber)
				}
				if tt.original.TShirtSize != nil {
					originalCopy.TShirtSize = converters.StringPtr(*tt.original.TShirtSize)
				}
			}

			result := originalCopy.Patch(tt.update)

			// Check return value
			if result != tt.expectedResult {
				t.Errorf("Patch() returned %v, expected %v", result, tt.expectedResult)
			}

			// Check final state
			checkStringPtr := func(fieldName string, got, want *string) {
				if (got == nil) != (want == nil) {
					t.Errorf("%s pointer mismatch: got nil=%v, want nil=%v", fieldName, got == nil, want == nil)
					return
				}
				if got != nil && want != nil && *got != *want {
					t.Errorf("%s = %q, want %q", fieldName, *got, *want)
				}
			}

			checkStringPtr("Picture", originalCopy.Picture, tt.expectedFinal.Picture)
			checkStringPtr("Zoneinfo", originalCopy.Zoneinfo, tt.expectedFinal.Zoneinfo)
			checkStringPtr("Name", originalCopy.Name, tt.expectedFinal.Name)
			checkStringPtr("GivenName", originalCopy.GivenName, tt.expectedFinal.GivenName)
			checkStringPtr("FamilyName", originalCopy.FamilyName, tt.expectedFinal.FamilyName)
			checkStringPtr("JobTitle", originalCopy.JobTitle, tt.expectedFinal.JobTitle)
			checkStringPtr("Organization", originalCopy.Organization, tt.expectedFinal.Organization)
			checkStringPtr("Country", originalCopy.Country, tt.expectedFinal.Country)
			checkStringPtr("StateProvince", originalCopy.StateProvince, tt.expectedFinal.StateProvince)
			checkStringPtr("City", originalCopy.City, tt.expectedFinal.City)
			checkStringPtr("Address", originalCopy.Address, tt.expectedFinal.Address)
			checkStringPtr("PostalCode", originalCopy.PostalCode, tt.expectedFinal.PostalCode)
			checkStringPtr("PhoneNumber", originalCopy.PhoneNumber, tt.expectedFinal.PhoneNumber)
			checkStringPtr("TShirtSize", originalCopy.TShirtSize, tt.expectedFinal.TShirtSize)
		})
	}
}

func TestUserMetadata_Patch_Idempotency(t *testing.T) {
	// Test that applying the same patch multiple times produces the same result
	update := &UserMetadata{
		GivenName:    converters.StringPtr("Johnny"),
		Organization: converters.StringPtr("ACME"),
	}

	// Make copies for multiple patch operations
	copy1 := &UserMetadata{
		Name:     converters.StringPtr("John"),
		JobTitle: converters.StringPtr("Developer"),
	}
	copy2 := &UserMetadata{
		Name:     converters.StringPtr("John"),
		JobTitle: converters.StringPtr("Developer"),
	}

	// Apply patch once
	result1 := copy1.Patch(update)

	// Apply patch again to the already patched object
	result2 := copy1.Patch(update)

	// Apply patch to fresh copy
	result3 := copy2.Patch(update)

	// First application should return true (changes made)
	if !result1 {
		t.Errorf("First patch application should return true")
	}

	// Second application should return true (still overwrites even with same values)
	if !result2 {
		t.Errorf("Second patch application should return true")
	}

	// Third application should return true
	if !result3 {
		t.Errorf("Third patch application should return true")
	}

	// Final states should be identical
	if copy1.Name == nil || copy2.Name == nil || *copy1.Name != *copy2.Name {
		t.Errorf("Name fields don't match after multiple patches")
	}
	if copy1.GivenName == nil || copy2.GivenName == nil || *copy1.GivenName != *copy2.GivenName {
		t.Errorf("GivenName fields don't match after multiple patches")
	}
	if copy1.JobTitle == nil || copy2.JobTitle == nil || *copy1.JobTitle != *copy2.JobTitle {
		t.Errorf("JobTitle fields don't match after multiple patches")
	}
	if copy1.Organization == nil || copy2.Organization == nil || *copy1.Organization != *copy2.Organization {
		t.Errorf("Organization fields don't match after multiple patches")
	}
}
