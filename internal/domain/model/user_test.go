// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package model

import (
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
