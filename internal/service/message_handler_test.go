// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/converters"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
)

// mockTransportMessenger is a mock implementation of port.TransportMessenger for testing
type mockTransportMessenger struct {
	data []byte
}

func (m *mockTransportMessenger) Subject() string {
	return "test-subject"
}

func (m *mockTransportMessenger) Data() []byte {
	return m.data
}

func (m *mockTransportMessenger) Respond(data []byte) error {
	// Mock implementation - just return nil
	return nil
}

// mockIdentityLinker is a mock implementation of port.IdentityLinker for testing
type mockIdentityLinker struct {
	validateLinkRequestFunc func(ctx context.Context, request *model.LinkIdentity) error
	linkIdentityFunc        func(ctx context.Context, request *model.LinkIdentity) error
	unlinkIdentityFunc      func(ctx context.Context, request *model.UnlinkIdentity) error
}

func (m *mockIdentityLinker) ValidateLinkRequest(ctx context.Context, request *model.LinkIdentity) error {
	if m.validateLinkRequestFunc != nil {
		return m.validateLinkRequestFunc(ctx, request)
	}
	return nil
}

func (m *mockIdentityLinker) LinkIdentity(ctx context.Context, request *model.LinkIdentity) error {
	if m.linkIdentityFunc != nil {
		return m.linkIdentityFunc(ctx, request)
	}
	return nil
}

func (m *mockIdentityLinker) UnlinkIdentity(ctx context.Context, request *model.UnlinkIdentity) error {
	if m.unlinkIdentityFunc != nil {
		return m.unlinkIdentityFunc(ctx, request)
	}
	return nil
}

// mockUserServiceWriter is a mock implementation of UserServiceWriter for testing
type mockUserServiceWriter struct {
	updateUserFunc      func(ctx context.Context, user *model.User) (*model.User, error)
	setPrimaryEmailFunc func(ctx context.Context, userID string, email string) error
}

func (m *mockUserServiceWriter) UpdateUser(ctx context.Context, user *model.User) (*model.User, error) {
	if m.updateUserFunc != nil {
		return m.updateUserFunc(ctx, user)
	}
	return user, nil
}

func (m *mockUserServiceWriter) SetPrimaryEmail(ctx context.Context, userID string, email string) error {
	if m.setPrimaryEmailFunc != nil {
		return m.setPrimaryEmailFunc(ctx, userID, email)
	}
	return nil
}

// mockPasswordHandler is a mock implementation of port.PasswordHandler for testing
type mockPasswordHandler struct {
	changePasswordFunc        func(ctx context.Context, user *model.User, currentPassword, newPassword string) error
	sendResetPasswordLinkFunc func(ctx context.Context, user *model.User) error
}

func (m *mockPasswordHandler) ChangePassword(ctx context.Context, user *model.User, currentPassword, newPassword string) error {
	if m.changePasswordFunc != nil {
		return m.changePasswordFunc(ctx, user, currentPassword, newPassword)
	}
	return nil
}

func (m *mockPasswordHandler) SendResetPasswordLink(ctx context.Context, user *model.User) error {
	if m.sendResetPasswordLinkFunc != nil {
		return m.sendResetPasswordLinkFunc(ctx, user)
	}
	return nil
}

// mockUserServiceReader is a mock implementation of UserServiceReader for testing
type mockUserServiceReader struct {
	getUserFunc        func(ctx context.Context, user *model.User) (*model.User, error)
	searchUserFunc     func(ctx context.Context, user *model.User, criteria string) (*model.User, error)
	metadataLookupFunc func(ctx context.Context, input string) (*model.User, error)
}

func (m *mockUserServiceReader) GetUser(ctx context.Context, user *model.User) (*model.User, error) {
	if m.getUserFunc != nil {
		return m.getUserFunc(ctx, user)
	}
	return user, nil
}

func (m *mockUserServiceReader) SearchUser(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
	if m.searchUserFunc != nil {
		return m.searchUserFunc(ctx, user, criteria)
	}
	return user, nil
}

func (m *mockUserServiceReader) MetadataLookup(ctx context.Context, input string, requiredScopes ...string) (*model.User, error) {
	if m.metadataLookupFunc != nil {
		return m.metadataLookupFunc(ctx, input)
	}

	// Default implementation: follow the same logic as the real implementations
	input = strings.TrimSpace(input)
	user := &model.User{}

	if strings.Contains(input, "|") {
		// Input contains "|", use as sub for canonical lookup
		user.Sub = input
		user.UserID = input
		user.Username = ""
	} else {
		// Input doesn't contain "|", use for search query
		user.Username = input
		user.Sub = ""
		user.UserID = ""
	}

	return user, nil
}

func TestMessageHandlerOrchestrator_UpdateUser(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		messageData    []byte
		mockFunc       func(ctx context.Context, user *model.User) (*model.User, error)
		expectError    bool
		errorType      string
		validateResult func(t *testing.T, result []byte)
	}{
		{
			name: "successful user update",
			messageData: func() []byte {
				user := &model.User{
					Token:        "test-token",
					Username:     "test-user",
					UserID:       "user-123",
					PrimaryEmail: "test@example.com",
					UserMetadata: &model.UserMetadata{
						Name:     converters.StringPtr("John Doe"),
						JobTitle: converters.StringPtr("Engineer"),
					},
				}
				data, _ := json.Marshal(user)
				return data
			}(),
			mockFunc: func(ctx context.Context, user *model.User) (*model.User, error) {
				// Simulate successful update with modifications
				updatedUser := *user
				updatedUser.Token = "updated-" + user.Token
				return &updatedUser, nil
			},
			expectError: false,
			validateResult: func(t *testing.T, result []byte) {
				var response struct {
					Success bool        `json:"success"`
					Data    interface{} `json:"data"`
					Error   string      `json:"error"`
				}
				if err := json.Unmarshal(result, &response); err != nil {
					t.Fatalf("Failed to unmarshal result: %v", err)
				}
				if !response.Success {
					t.Errorf("Expected success=true, got success=%v, error=%s", response.Success, response.Error)
				}
				if response.Data == nil {
					t.Fatal("Expected data, got nil")
				}
				// Since we're only returning metadata, we can't validate token/username anymore
				// The test should validate the metadata content instead
				if metadata, ok := response.Data.(map[string]interface{}); ok {
					if name, exists := metadata["name"]; exists && name != "John Doe" {
						t.Errorf("Expected name 'John Doe', got %v", name)
					}
				}
			},
		},
		{
			name:        "invalid JSON in message",
			messageData: []byte(`{invalid json`),
			expectError: true,
			errorType:   "unexpected",
		},
		{
			name: "empty message data",
			messageData: func() []byte {
				return []byte(`{}`)
			}(),
			mockFunc: func(ctx context.Context, user *model.User) (*model.User, error) {
				// This should fail validation due to missing required fields
				return nil, errors.NewValidation("username is required")
			},
			expectError: true,
			errorType:   "unexpected",
		},
		{
			name: "user service writer error",
			messageData: func() []byte {
				user := &model.User{
					Token:        "test-token",
					Username:     "test-user",
					UserID:       "user-123",
					PrimaryEmail: "test@example.com",
					UserMetadata: &model.UserMetadata{
						Name: converters.StringPtr("Test User"),
					},
				}
				data, _ := json.Marshal(user)
				return data
			}(),
			mockFunc: func(ctx context.Context, user *model.User) (*model.User, error) {
				return nil, errors.NewUnexpected("database connection failed", nil)
			},
			expectError: true,
			errorType:   "unexpected",
		},
		{
			name: "user with minimal data - validation error",
			messageData: func() []byte {
				user := &model.User{
					Token:    "minimal-token",
					Username: "minimal-user",
				}
				data, _ := json.Marshal(user)
				return data
			}(),
			mockFunc: func(ctx context.Context, user *model.User) (*model.User, error) {
				t.Error("Mock should not be called due to validation failure")
				return user, nil
			},
			expectError: true,
			errorType:   "validation",
			validateResult: func(t *testing.T, result []byte) {
				var response struct {
					Success bool   `json:"success"`
					Error   string `json:"error"`
				}
				if err := json.Unmarshal(result, &response); err != nil {
					t.Fatalf("Failed to unmarshal result: %v", err)
				}
				if response.Success {
					t.Error("Expected success=false for validation error")
				}
				if response.Error != "user_metadata is required" {
					t.Errorf("Expected error 'user_metadata is required', got %s", response.Error)
				}
			},
		},
		{
			name: "user with complete metadata",
			messageData: func() []byte {
				user := &model.User{
					Token:        "complete-token",
					Username:     "complete-user",
					UserID:       "user-456",
					PrimaryEmail: "complete@example.com",
					UserMetadata: &model.UserMetadata{
						Name:          converters.StringPtr("Jane Smith"),
						GivenName:     converters.StringPtr("Jane"),
						FamilyName:    converters.StringPtr("Smith"),
						JobTitle:      converters.StringPtr("Senior Engineer"),
						Organization:  converters.StringPtr("Tech Corp"),
						Country:       converters.StringPtr("USA"),
						StateProvince: converters.StringPtr("California"),
						City:          converters.StringPtr("San Francisco"),
						Address:       converters.StringPtr("123 Tech St"),
						PostalCode:    converters.StringPtr("94105"),
						PhoneNumber:   converters.StringPtr("+1-555-123-4567"),
						TShirtSize:    converters.StringPtr("M"),
						Picture:       converters.StringPtr("https://example.com/pic.jpg"),
						Zoneinfo:      converters.StringPtr("America/Los_Angeles"),
					},
				}
				data, _ := json.Marshal(user)
				return data
			}(),
			mockFunc: func(ctx context.Context, user *model.User) (*model.User, error) {
				return user, nil
			},
			expectError: false,
			validateResult: func(t *testing.T, result []byte) {
				var response struct {
					Success bool        `json:"success"`
					Data    interface{} `json:"data"`
					Error   string      `json:"error"`
				}
				if err := json.Unmarshal(result, &response); err != nil {
					t.Fatalf("Failed to unmarshal result: %v", err)
				}
				if !response.Success {
					t.Errorf("Expected success=true, got success=%v, error=%s", response.Success, response.Error)
				}
				if response.Data == nil {
					t.Fatal("Expected data, got nil")
				}

				// Verify metadata fields by casting to map
				if metadata, ok := response.Data.(map[string]interface{}); ok {
					if name, exists := metadata["name"]; exists && name != "Jane Smith" {
						t.Errorf("Result metadata name incorrect: got %v, want Jane Smith", name)
					}
					if jobTitle, exists := metadata["job_title"]; exists && jobTitle != "Senior Engineer" {
						t.Errorf("Result metadata job title incorrect: got %v, want Senior Engineer", jobTitle)
					}
					if organization, exists := metadata["organization"]; exists && organization != "Tech Corp" {
						t.Errorf("Result metadata organization incorrect: got %v, want Tech Corp", organization)
					}
				} else {
					t.Errorf("Data is not a map[string]interface{}, got %T", response.Data)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock transport messenger
			mockMsg := &mockTransportMessenger{
				data: tt.messageData,
			}

			// Create mock user service writer
			mockWriter := &mockUserServiceWriter{
				updateUserFunc: tt.mockFunc,
			}

			// Create orchestrator with mock
			orchestrator := NewMessageHandlerOrchestrator(
				WithUserWriterForMessageHandler(mockWriter),
			)

			// Execute the test
			result, err := orchestrator.UpdateUser(ctx, mockMsg)

			// Since we now return structured responses, we should never get Go errors
			if err != nil {
				t.Errorf("UpdateUser() unexpected error: %v", err)
				return
			}

			if result == nil {
				t.Errorf("UpdateUser() returned nil result")
				return
			}

			// Run custom validation if provided
			if tt.validateResult != nil {
				tt.validateResult(t, result)
			}
		})
	}
}

func TestMessageHandlerOrchestrator_EmailToUsername(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		messageData    []byte
		userReader     *mockUserServiceReader
		expectError    bool
		expectedResult string
		validateResult func(t *testing.T, result []byte)
	}{
		{
			name:        "successful email to username lookup",
			messageData: []byte("zephyr.stormwind@mythicaltech.io"),
			userReader: &mockUserServiceReader{
				searchUserFunc: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
					// Verify the search is called with correct parameters
					if criteria != constants.CriteriaTypeEmail {
						t.Errorf("Expected criteria %s, got %s", constants.CriteriaTypeEmail, criteria)
					}
					if user.PrimaryEmail != "zephyr.stormwind@mythicaltech.io" {
						t.Errorf("Expected email zephyr.stormwind@mythicaltech.io, got %s", user.PrimaryEmail)
					}
					// Return a user with username
					return &model.User{
						UserID:       "auth0|zephyr001",
						Username:     "zephyr.stormwind",
						PrimaryEmail: "zephyr.stormwind@mythicaltech.io",
					}, nil
				},
			},
			expectError:    false,
			expectedResult: "zephyr.stormwind",
		},
		{
			name:        "email with whitespace is trimmed",
			messageData: []byte("  mauriciozanetti86@gmail.com  "),
			userReader: &mockUserServiceReader{
				searchUserFunc: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
					// Verify the email was trimmed
					if user.PrimaryEmail != "mauriciozanetti86@gmail.com" {
						t.Errorf("Expected trimmed email mauriciozanetti86@gmail.com, got %s", user.PrimaryEmail)
					}
					return &model.User{
						UserID:       "auth0|mauricio001",
						Username:     "mauriciozanetti",
						PrimaryEmail: "mauriciozanetti86@gmail.com",
					}, nil
				},
			},
			expectError:    false,
			expectedResult: "mauriciozanetti",
		},
		{
			name:        "email is converted to lowercase",
			messageData: []byte("UPPERCASE@EXAMPLE.COM"),
			userReader: &mockUserServiceReader{
				searchUserFunc: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
					// Verify the email was lowercased
					if user.PrimaryEmail != "uppercase@example.com" {
						t.Errorf("Expected lowercased email uppercase@example.com, got %s", user.PrimaryEmail)
					}
					return &model.User{
						UserID:       "auth0|upper001",
						Username:     "uppercase.user",
						PrimaryEmail: "uppercase@example.com",
					}, nil
				},
			},
			expectError:    false,
			expectedResult: "uppercase.user",
		},
		{
			name:        "empty email returns error",
			messageData: []byte(""),
			userReader: &mockUserServiceReader{
				searchUserFunc: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
					t.Error("SearchUser should not be called for empty email")
					return nil, errors.NewValidation("should not be called")
				},
			},
			expectError: true,
			validateResult: func(t *testing.T, result []byte) {
				var response struct {
					Success bool   `json:"success"`
					Error   string `json:"error"`
				}
				if err := json.Unmarshal(result, &response); err != nil {
					t.Fatalf("Failed to unmarshal error response: %v", err)
				}
				if response.Success {
					t.Error("Expected success=false for empty email")
				}
				if response.Error != "email is required" {
					t.Errorf("Expected error 'email is required', got %s", response.Error)
				}
			},
		},
		{
			name:        "whitespace-only email returns error",
			messageData: []byte("   \t\n   "),
			userReader: &mockUserServiceReader{
				searchUserFunc: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
					t.Error("SearchUser should not be called for whitespace-only email")
					return nil, errors.NewValidation("should not be called")
				},
			},
			expectError: true,
			validateResult: func(t *testing.T, result []byte) {
				var response struct {
					Success bool   `json:"success"`
					Error   string `json:"error"`
				}
				if err := json.Unmarshal(result, &response); err != nil {
					t.Fatalf("Failed to unmarshal error response: %v", err)
				}
				if response.Success {
					t.Error("Expected success=false for whitespace-only email")
				}
				if response.Error != "email is required" {
					t.Errorf("Expected error 'email is required', got %s", response.Error)
				}
			},
		},
		{
			name:        "user not found error",
			messageData: []byte("notfound@example.com"),
			userReader: &mockUserServiceReader{
				searchUserFunc: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
					return nil, errors.NewNotFound("user not found")
				},
			},
			expectError: true,
			validateResult: func(t *testing.T, result []byte) {
				var response struct {
					Success bool   `json:"success"`
					Error   string `json:"error"`
				}
				if err := json.Unmarshal(result, &response); err != nil {
					t.Fatalf("Failed to unmarshal error response: %v", err)
				}
				if response.Success {
					t.Error("Expected success=false for user not found")
				}
				if response.Error != "user not found" {
					t.Errorf("Expected error 'user not found', got %s", response.Error)
				}
			},
		},
		{
			name:        "search service error",
			messageData: []byte("service.error@example.com"),
			userReader: &mockUserServiceReader{
				searchUserFunc: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
					return nil, errors.NewUnexpected("database connection failed", nil)
				},
			},
			expectError: true,
			validateResult: func(t *testing.T, result []byte) {
				var response struct {
					Success bool   `json:"success"`
					Error   string `json:"error"`
				}
				if err := json.Unmarshal(result, &response); err != nil {
					t.Fatalf("Failed to unmarshal error response: %v", err)
				}
				if response.Success {
					t.Error("Expected success=false for service error")
				}
				if response.Error != "database connection failed" {
					t.Errorf("Expected error 'database connection failed', got %s", response.Error)
				}
			},
		},
		{
			name:        "user with empty username",
			messageData: []byte("empty.username@example.com"),
			userReader: &mockUserServiceReader{
				searchUserFunc: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
					// Return user with empty username
					return &model.User{
						UserID:       "auth0|empty001",
						Username:     "",
						PrimaryEmail: "empty.username@example.com",
					}, nil
				},
			},
			expectError:    false,
			expectedResult: "", // Empty string is a valid response
		},
		{
			name:        "complex email address",
			messageData: []byte("test.user+tag@sub.example.co.uk"),
			userReader: &mockUserServiceReader{
				searchUserFunc: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
					if user.PrimaryEmail != "test.user+tag@sub.example.co.uk" {
						t.Errorf("Expected email test.user+tag@sub.example.co.uk, got %s", user.PrimaryEmail)
					}
					return &model.User{
						UserID:       "auth0|complex001",
						Username:     "test.user.complex",
						PrimaryEmail: "test.user+tag@sub.example.co.uk",
					}, nil
				},
			},
			expectError:    false,
			expectedResult: "test.user.complex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock transport messenger
			mockMsg := &mockTransportMessenger{
				data: tt.messageData,
			}

			// Create orchestrator with mock user reader
			orchestrator := NewMessageHandlerOrchestrator(
				WithUserReaderForMessageHandler(tt.userReader),
			)

			// Execute the test
			result, err := orchestrator.EmailToUsername(ctx, mockMsg)

			// The method should never return Go errors, only structured responses
			if err != nil {
				t.Errorf("EmailToUsername() unexpected error: %v", err)
				return
			}

			if result == nil {
				t.Errorf("EmailToUsername() returned nil result")
				return
			}

			if tt.expectError {
				// Run custom validation for error cases
				if tt.validateResult != nil {
					tt.validateResult(t, result)
				}
			} else {
				// For success cases, result should be plain text username
				actualResult := string(result)
				if actualResult != tt.expectedResult {
					t.Errorf("EmailToUsername() = %q, want %q", actualResult, tt.expectedResult)
				}
			}
		})
	}
}

func TestMessageHandlerOrchestrator_EmailToUsername_NoUserReader(t *testing.T) {
	ctx := context.Background()

	// Create orchestrator without user reader
	orchestrator := NewMessageHandlerOrchestrator()

	mockMsg := &mockTransportMessenger{
		data: []byte("test@example.com"),
	}

	result, err := orchestrator.EmailToUsername(ctx, mockMsg)

	if err != nil {
		t.Errorf("EmailToUsername() unexpected error: %v", err)
		return
	}

	if result == nil {
		t.Fatal("EmailToUsername() returned nil result")
	}

	// Should return structured error response
	var response struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(result, &response); err != nil {
		t.Fatalf("Failed to unmarshal error response: %v", err)
	}

	if response.Success {
		t.Error("Expected success=false when user reader is nil")
	}

	if response.Error != "auth service unavailable" {
		t.Errorf("Expected error 'auth service unavailable', got %s", response.Error)
	}
}

func TestMessageHandlerOrchestrator_EmailToSub(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		messageData    []byte
		userReader     *mockUserServiceReader
		expectError    bool
		expectedResult string
		validateResult func(t *testing.T, result []byte)
	}{
		{
			name:        "successful email to sub lookup",
			messageData: []byte("zephyr.stormwind@mythicaltech.io"),
			userReader: &mockUserServiceReader{
				searchUserFunc: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
					if criteria != constants.CriteriaTypeEmail {
						t.Errorf("Expected criteria %s, got %s", constants.CriteriaTypeEmail, criteria)
					}
					if user.PrimaryEmail != "zephyr.stormwind@mythicaltech.io" {
						t.Errorf("Expected email zephyr.stormwind@mythicaltech.io, got %s", user.PrimaryEmail)
					}
					return &model.User{
						UserID:       "auth0|zephyr001",
						Username:     "zephyr.stormwind",
						PrimaryEmail: "zephyr.stormwind@mythicaltech.io",
					}, nil
				},
			},
			expectError:    false,
			expectedResult: "auth0|zephyr001",
		},
		{
			name:        "email with whitespace is trimmed",
			messageData: []byte("  mauriciozanetti86@gmail.com  "),
			userReader: &mockUserServiceReader{
				searchUserFunc: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
					if user.PrimaryEmail != "mauriciozanetti86@gmail.com" {
						t.Errorf("Expected trimmed email mauriciozanetti86@gmail.com, got %s", user.PrimaryEmail)
					}
					return &model.User{
						UserID:       "auth0|mauricio001",
						Username:     "mauriciozanetti",
						PrimaryEmail: "mauriciozanetti86@gmail.com",
					}, nil
				},
			},
			expectError:    false,
			expectedResult: "auth0|mauricio001",
		},
		{
			name:        "email is converted to lowercase",
			messageData: []byte("UPPERCASE@EXAMPLE.COM"),
			userReader: &mockUserServiceReader{
				searchUserFunc: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
					if user.PrimaryEmail != "uppercase@example.com" {
						t.Errorf("Expected lowercased email uppercase@example.com, got %s", user.PrimaryEmail)
					}
					return &model.User{
						UserID:       "auth0|upper001",
						Username:     "uppercase.user",
						PrimaryEmail: "uppercase@example.com",
					}, nil
				},
			},
			expectError:    false,
			expectedResult: "auth0|upper001",
		},
		{
			name:        "empty email returns error",
			messageData: []byte(""),
			userReader: &mockUserServiceReader{
				searchUserFunc: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
					t.Error("SearchUser should not be called for empty email")
					return nil, errors.NewValidation("should not be called")
				},
			},
			expectError: true,
			validateResult: func(t *testing.T, result []byte) {
				var response struct {
					Success bool   `json:"success"`
					Error   string `json:"error"`
				}
				if err := json.Unmarshal(result, &response); err != nil {
					t.Fatalf("Failed to unmarshal error response: %v", err)
				}
				if response.Success {
					t.Error("Expected success=false for empty email")
				}
				if response.Error != "email is required" {
					t.Errorf("Expected error 'email is required', got %s", response.Error)
				}
			},
		},
		{
			name:        "whitespace-only email returns error",
			messageData: []byte("   \t\n   "),
			userReader: &mockUserServiceReader{
				searchUserFunc: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
					t.Error("SearchUser should not be called for whitespace-only email")
					return nil, errors.NewValidation("should not be called")
				},
			},
			expectError: true,
			validateResult: func(t *testing.T, result []byte) {
				var response struct {
					Success bool   `json:"success"`
					Error   string `json:"error"`
				}
				if err := json.Unmarshal(result, &response); err != nil {
					t.Fatalf("Failed to unmarshal error response: %v", err)
				}
				if response.Success {
					t.Error("Expected success=false for whitespace-only email")
				}
				if response.Error != "email is required" {
					t.Errorf("Expected error 'email is required', got %s", response.Error)
				}
			},
		},
		{
			name:        "user not found error",
			messageData: []byte("notfound@example.com"),
			userReader: &mockUserServiceReader{
				searchUserFunc: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
					return nil, errors.NewNotFound("user not found")
				},
			},
			expectError: true,
			validateResult: func(t *testing.T, result []byte) {
				var response struct {
					Success bool   `json:"success"`
					Error   string `json:"error"`
				}
				if err := json.Unmarshal(result, &response); err != nil {
					t.Fatalf("Failed to unmarshal error response: %v", err)
				}
				if response.Success {
					t.Error("Expected success=false for user not found")
				}
				if response.Error != "user not found" {
					t.Errorf("Expected error 'user not found', got %s", response.Error)
				}
			},
		},
		{
			name:        "search service error",
			messageData: []byte("service.error@example.com"),
			userReader: &mockUserServiceReader{
				searchUserFunc: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
					return nil, errors.NewUnexpected("database connection failed", nil)
				},
			},
			expectError: true,
			validateResult: func(t *testing.T, result []byte) {
				var response struct {
					Success bool   `json:"success"`
					Error   string `json:"error"`
				}
				if err := json.Unmarshal(result, &response); err != nil {
					t.Fatalf("Failed to unmarshal error response: %v", err)
				}
				if response.Success {
					t.Error("Expected success=false for service error")
				}
				if response.Error != "database connection failed" {
					t.Errorf("Expected error 'database connection failed', got %s", response.Error)
				}
			},
		},
		{
			name:        "user with empty sub",
			messageData: []byte("empty.sub@example.com"),
			userReader: &mockUserServiceReader{
				searchUserFunc: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
					return &model.User{
						UserID:       "",
						Username:     "empty.sub.user",
						PrimaryEmail: "empty.sub@example.com",
					}, nil
				},
			},
			expectError:    false,
			expectedResult: "", // Empty string is a valid response
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMsg := &mockTransportMessenger{
				data: tt.messageData,
			}

			orchestrator := NewMessageHandlerOrchestrator(
				WithUserReaderForMessageHandler(tt.userReader),
			)

			result, err := orchestrator.EmailToSub(ctx, mockMsg)

			if err != nil {
				t.Errorf("EmailToSub() unexpected error: %v", err)
				return
			}

			if result == nil {
				t.Errorf("EmailToSub() returned nil result")
				return
			}

			if tt.expectError {
				if tt.validateResult != nil {
					tt.validateResult(t, result)
				}
			} else {
				actualResult := string(result)
				if actualResult != tt.expectedResult {
					t.Errorf("EmailToSub() = %q, want %q", actualResult, tt.expectedResult)
				}
			}
		})
	}
}

func TestMessageHandlerOrchestrator_EmailToSub_NoUserReader(t *testing.T) {
	ctx := context.Background()

	orchestrator := NewMessageHandlerOrchestrator()

	mockMsg := &mockTransportMessenger{
		data: []byte("test@example.com"),
	}

	result, err := orchestrator.EmailToSub(ctx, mockMsg)

	if err != nil {
		t.Errorf("EmailToSub() unexpected error: %v", err)
		return
	}

	if result == nil {
		t.Fatal("EmailToSub() returned nil result")
	}

	var response struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(result, &response); err != nil {
		t.Fatalf("Failed to unmarshal error response: %v", err)
	}

	if response.Success {
		t.Error("Expected success=false when user reader is nil")
	}

	if response.Error != "auth service unavailable" {
		t.Errorf("Expected error 'auth service unavailable', got %s", response.Error)
	}
}

func TestMessageHandlerOrchestrator_UsernameToSub(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		messageData    []byte
		userReader     *mockUserServiceReader
		expectError    bool
		expectedResult string
		validateResult func(t *testing.T, result []byte)
	}{
		{
			name:        "successful username to sub lookup",
			messageData: []byte("zephyr.stormwind"),
			userReader: &mockUserServiceReader{
				searchUserFunc: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
					if criteria != constants.CriteriaTypeUsername {
						t.Errorf("Expected criteria %s, got %s", constants.CriteriaTypeUsername, criteria)
					}
					if user.Username != "zephyr.stormwind" {
						t.Errorf("Expected username zephyr.stormwind, got %s", user.Username)
					}
					return &model.User{
						UserID:   "auth0|zephyr001",
						Username: "zephyr.stormwind",
					}, nil
				},
			},
			expectError:    false,
			expectedResult: "auth0|zephyr001",
		},
		{
			name:        "username with whitespace is trimmed",
			messageData: []byte("  mauriciozanetti  "),
			userReader: &mockUserServiceReader{
				searchUserFunc: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
					if user.Username != "mauriciozanetti" {
						t.Errorf("Expected trimmed username mauriciozanetti, got %s", user.Username)
					}
					return &model.User{
						UserID:   "auth0|mauricio001",
						Username: "mauriciozanetti",
					}, nil
				},
			},
			expectError:    false,
			expectedResult: "auth0|mauricio001",
		},
		{
			name:        "empty username returns error",
			messageData: []byte(""),
			userReader: &mockUserServiceReader{
				searchUserFunc: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
					t.Error("SearchUser should not be called for empty username")
					return nil, errors.NewValidation("should not be called")
				},
			},
			expectError: true,
			validateResult: func(t *testing.T, result []byte) {
				var response struct {
					Success bool   `json:"success"`
					Error   string `json:"error"`
				}
				if err := json.Unmarshal(result, &response); err != nil {
					t.Fatalf("Failed to unmarshal error response: %v", err)
				}
				if response.Success {
					t.Error("Expected success=false for empty username")
				}
				if response.Error != "username is required" {
					t.Errorf("Expected error 'username is required', got %s", response.Error)
				}
			},
		},
		{
			name:        "whitespace-only username returns error",
			messageData: []byte("   "),
			userReader: &mockUserServiceReader{
				searchUserFunc: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
					t.Error("SearchUser should not be called for whitespace-only username")
					return nil, errors.NewValidation("should not be called")
				},
			},
			expectError: true,
			validateResult: func(t *testing.T, result []byte) {
				var response struct {
					Success bool   `json:"success"`
					Error   string `json:"error"`
				}
				if err := json.Unmarshal(result, &response); err != nil {
					t.Fatalf("Failed to unmarshal error response: %v", err)
				}
				if response.Success {
					t.Error("Expected success=false for whitespace-only username")
				}
				if response.Error != "username is required" {
					t.Errorf("Expected error 'username is required', got %s", response.Error)
				}
			},
		},
		{
			name:        "user not found error",
			messageData: []byte("nonexistent.user"),
			userReader: &mockUserServiceReader{
				searchUserFunc: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
					return nil, errors.NewNotFound("user not found")
				},
			},
			expectError: true,
			validateResult: func(t *testing.T, result []byte) {
				var response struct {
					Success bool   `json:"success"`
					Error   string `json:"error"`
				}
				if err := json.Unmarshal(result, &response); err != nil {
					t.Fatalf("Failed to unmarshal error response: %v", err)
				}
				if response.Success {
					t.Error("Expected success=false for user not found")
				}
				if response.Error != "user not found" {
					t.Errorf("Expected error 'user not found', got %s", response.Error)
				}
			},
		},
		{
			name:        "search service error",
			messageData: []byte("service.error.user"),
			userReader: &mockUserServiceReader{
				searchUserFunc: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
					return nil, errors.NewUnexpected("database connection failed", nil)
				},
			},
			expectError: true,
			validateResult: func(t *testing.T, result []byte) {
				var response struct {
					Success bool   `json:"success"`
					Error   string `json:"error"`
				}
				if err := json.Unmarshal(result, &response); err != nil {
					t.Fatalf("Failed to unmarshal error response: %v", err)
				}
				if response.Success {
					t.Error("Expected success=false for service error")
				}
				if response.Error != "database connection failed" {
					t.Errorf("Expected error 'database connection failed', got %s", response.Error)
				}
			},
		},
		{
			name:        "user with empty sub",
			messageData: []byte("empty.sub.user"),
			userReader: &mockUserServiceReader{
				searchUserFunc: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
					return &model.User{
						UserID:   "",
						Username: "empty.sub.user",
					}, nil
				},
			},
			expectError:    false,
			expectedResult: "", // Empty string is a valid response
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMsg := &mockTransportMessenger{
				data: tt.messageData,
			}

			orchestrator := NewMessageHandlerOrchestrator(
				WithUserReaderForMessageHandler(tt.userReader),
			)

			result, err := orchestrator.UsernameToSub(ctx, mockMsg)

			if err != nil {
				t.Errorf("UsernameToSub() unexpected error: %v", err)
				return
			}

			if result == nil {
				t.Errorf("UsernameToSub() returned nil result")
				return
			}

			if tt.expectError {
				if tt.validateResult != nil {
					tt.validateResult(t, result)
				}
			} else {
				actualResult := string(result)
				if actualResult != tt.expectedResult {
					t.Errorf("UsernameToSub() = %q, want %q", actualResult, tt.expectedResult)
				}
			}
		})
	}
}

func TestMessageHandlerOrchestrator_UsernameToSub_NoUserReader(t *testing.T) {
	ctx := context.Background()

	orchestrator := NewMessageHandlerOrchestrator()

	mockMsg := &mockTransportMessenger{
		data: []byte("someuser"),
	}

	result, err := orchestrator.UsernameToSub(ctx, mockMsg)

	if err != nil {
		t.Errorf("UsernameToSub() unexpected error: %v", err)
		return
	}

	if result == nil {
		t.Fatal("UsernameToSub() returned nil result")
	}

	var response struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(result, &response); err != nil {
		t.Fatalf("Failed to unmarshal error response: %v", err)
	}

	if response.Success {
		t.Error("Expected success=false when user reader is nil")
	}

	if response.Error != "auth service unavailable" {
		t.Errorf("Expected error 'auth service unavailable', got %s", response.Error)
	}
}

func TestNewMessageHandlerOrchestrator(t *testing.T) {
	t.Run("create orchestrator with options", func(t *testing.T) {
		mockWriter := &mockUserServiceWriter{}
		orchestrator := NewMessageHandlerOrchestrator(
			WithUserWriterForMessageHandler(mockWriter),
		)

		if orchestrator == nil {
			t.Error("NewMessageHandlerOrchestrator() returned nil")
		}
	})

	t.Run("create orchestrator without options", func(t *testing.T) {
		orchestrator := NewMessageHandlerOrchestrator()

		if orchestrator == nil {
			t.Error("NewMessageHandlerOrchestrator() returned nil")
		}
	})
}

func TestWithUserWriterForMessageHandler(t *testing.T) {
	t.Run("option sets user writer", func(t *testing.T) {
		mockWriter := &mockUserServiceWriter{
			updateUserFunc: func(ctx context.Context, user *model.User) (*model.User, error) {
				// Mark that this was called
				user.Token = "writer-called"
				return user, nil
			},
		}

		// Create orchestrator with option
		orchestrator := NewMessageHandlerOrchestrator(
			WithUserWriterForMessageHandler(mockWriter),
		)

		// Test that the writer was set by using it
		ctx := context.Background()
		user := &model.User{
			Token:        "test-token",
			Username:     "test-user",
			UserID:       "user-123",
			PrimaryEmail: "test@example.com",
			UserMetadata: &model.UserMetadata{
				Name: converters.StringPtr("Test User"),
			},
		}
		userData, _ := json.Marshal(user)
		mockMsg := &mockTransportMessenger{data: userData}

		result, err := orchestrator.UpdateUser(ctx, mockMsg)
		if err != nil {
			t.Errorf("UpdateUser() failed: %v", err)
			return
		}

		// Verify we get a structured response with success=true
		var response struct {
			Success bool        `json:"success"`
			Data    interface{} `json:"data"`
			Error   string      `json:"error"`
		}
		if err := json.Unmarshal(result, &response); err != nil {
			t.Fatalf("Failed to unmarshal result: %v", err)
		}

		if !response.Success {
			t.Errorf("Expected success=true, got success=%v, error=%s", response.Success, response.Error)
		}

		// The result should have the metadata we provided
		if response.Data == nil {
			t.Error("Expected user_metadata, got nil")
		} else if metadata, ok := response.Data.(map[string]interface{}); ok {
			if name, exists := metadata["name"]; !exists || name != "Test User" {
				t.Errorf("Expected name 'Test User', got %v", name)
			}
		}
	})
}

func TestWithUserReaderForMessageHandler(t *testing.T) {
	t.Run("option sets user reader", func(t *testing.T) {
		mockReader := &mockUserServiceReader{
			searchUserFunc: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
				// Mark that this was called by modifying the user
				user.Username = "reader-called"
				return user, nil
			},
		}

		// Create orchestrator with option
		orchestrator := NewMessageHandlerOrchestrator(
			WithUserReaderForMessageHandler(mockReader),
		)

		// Test that the reader was set by using it
		ctx := context.Background()
		mockMsg := &mockTransportMessenger{
			data: []byte("test@example.com"),
		}

		result, err := orchestrator.EmailToUsername(ctx, mockMsg)
		if err != nil {
			t.Errorf("EmailToUsername() failed: %v", err)
			return
		}

		// Verify we get the expected username back
		actualResult := string(result)
		expectedResult := "reader-called"
		if actualResult != expectedResult {
			t.Errorf("EmailToUsername() = %q, want %q", actualResult, expectedResult)
		}
	})
}

// Integration test for the full message handling flow
func TestMessageHandlerOrchestrator_Integration(t *testing.T) {
	ctx := context.Background()

	t.Run("full message handling flow", func(t *testing.T) {
		// Track what the mock receives and processes
		var receivedUser *model.User
		mockWriter := &mockUserServiceWriter{
			updateUserFunc: func(ctx context.Context, user *model.User) (*model.User, error) {
				receivedUser = user
				// Simulate processing by the user writer (including validation/sanitization)
				processedUser := *user
				processedUser.Token = "processed-" + user.Token

				// Add some metadata to simulate enrichment
				if processedUser.UserMetadata == nil {
					processedUser.UserMetadata = &model.UserMetadata{}
				}
				processedUser.UserMetadata.Organization = converters.StringPtr("Processed Corp")

				return &processedUser, nil
			},
		}

		orchestrator := NewMessageHandlerOrchestrator(
			WithUserWriterForMessageHandler(mockWriter),
		)

		// Create input message
		inputUser := &model.User{
			Token:        "original-token",
			Username:     "integration-user",
			UserID:       "user-integration",
			PrimaryEmail: "integration@example.com",
			UserMetadata: &model.UserMetadata{
				Name:     converters.StringPtr("Integration Test"),
				JobTitle: converters.StringPtr("Tester"),
			},
		}
		messageData, err := json.Marshal(inputUser)
		if err != nil {
			t.Fatalf("Failed to marshal input user: %v", err)
		}

		mockMsg := &mockTransportMessenger{data: messageData}

		// Execute the integration test
		result, err := orchestrator.UpdateUser(ctx, mockMsg)
		if err != nil {
			t.Fatalf("Integration test failed: %v", err)
		}

		// Verify the mock received the correct data
		if receivedUser == nil {
			t.Fatal("Mock writer did not receive user data")
		}
		if receivedUser.Token != "original-token" {
			t.Errorf("Mock received incorrect token: %q", receivedUser.Token)
		}
		if receivedUser.Username != "integration-user" {
			t.Errorf("Mock received incorrect username: %q", receivedUser.Username)
		}

		// Verify the final result is a structured response with success=true
		var response struct {
			Success bool        `json:"success"`
			Data    interface{} `json:"data"`
			Error   string      `json:"error"`
		}
		if err := json.Unmarshal(result, &response); err != nil {
			t.Fatalf("Failed to unmarshal final result: %v", err)
		}

		if !response.Success {
			t.Errorf("Expected success=true, got success=%v, error=%s", response.Success, response.Error)
		}

		if response.Data == nil {
			t.Fatal("Expected data, got nil")
		}

		// Verify enrichment occurred by casting to map
		if metadata, ok := response.Data.(map[string]interface{}); ok {
			if organization, exists := metadata["organization"]; !exists || organization != "Processed Corp" {
				t.Errorf("User metadata was not enriched correctly, got organization: %v", organization)
			}

			// Verify original metadata was preserved
			if name, exists := metadata["name"]; !exists || name != "Integration Test" {
				t.Errorf("Original metadata was not preserved, got name: %v", name)
			}
		} else {
			t.Errorf("Data is not a map[string]interface{}, got %T", response.Data)
		}
	})

	t.Run("error handling in integration", func(t *testing.T) {
		// Mock that returns an error
		mockWriter := &mockUserServiceWriter{
			updateUserFunc: func(ctx context.Context, user *model.User) (*model.User, error) {
				return nil, errors.NewValidation("integration test error")
			},
		}

		orchestrator := NewMessageHandlerOrchestrator(
			WithUserWriterForMessageHandler(mockWriter),
		)

		inputUser := &model.User{
			Token:        "error-token",
			Username:     "error-user",
			UserID:       "user-error",
			PrimaryEmail: "error@example.com",
			UserMetadata: &model.UserMetadata{
				Name: converters.StringPtr("Error Test User"),
			},
		}
		messageData, _ := json.Marshal(inputUser)
		mockMsg := &mockTransportMessenger{data: messageData}

		// Execute and expect structured error response
		result, err := orchestrator.UpdateUser(ctx, mockMsg)

		if err != nil {
			t.Errorf("Expected no error from orchestrator, got %v", err)
		}
		if result == nil {
			t.Fatal("Expected structured error response, got nil")
		}

		// Verify it's a structured error response
		var response struct {
			Success bool   `json:"success"`
			Error   string `json:"error"`
		}
		if err := json.Unmarshal(result, &response); err != nil {
			t.Fatalf("Failed to unmarshal error response: %v", err)
		}

		if response.Success {
			t.Error("Expected success=false for error case")
		}

		if response.Error != "integration test error" {
			t.Errorf("Expected 'integration test error', got %s", response.Error)
		}
	})
}

func TestMessageHandlerOrchestrator_GetUserMetadata(t *testing.T) {
	tests := []struct {
		name               string
		input              string
		mockMetadataLookup func(ctx context.Context, input string) (*model.User, error)
		mockGetUser        func(ctx context.Context, user *model.User) (*model.User, error)
		mockSearchUser     func(ctx context.Context, user *model.User, criteria string) (*model.User, error)
		expectedError      bool
		expectedData       *model.UserMetadata
		description        string
	}{
		{
			name:  "canonical lookup success",
			input: "auth0|123456789",
			mockMetadataLookup: func(ctx context.Context, input string) (*model.User, error) {
				// Verify input is correct
				if input != "auth0|123456789" {
					t.Errorf("Expected input 'auth0|123456789', got %q", input)
				}
				// Return user prepared for canonical lookup
				return &model.User{
					Sub:    "auth0|123456789",
					UserID: "auth0|123456789",
				}, nil
			},
			mockGetUser: func(ctx context.Context, user *model.User) (*model.User, error) {
				// Verify the user was prepared correctly for canonical lookup
				if user.Sub != "auth0|123456789" || user.UserID != "auth0|123456789" {
					t.Errorf("User not prepared correctly for canonical lookup: Sub=%q, UserID=%q", user.Sub, user.UserID)
				}
				return &model.User{
					UserID:   "auth0|123456789",
					Username: "john.doe",
					UserMetadata: &model.UserMetadata{
						Name:     converters.StringPtr("John Doe"),
						JobTitle: converters.StringPtr("Software Engineer"),
					},
				}, nil
			},
			expectedError: false,
			expectedData: &model.UserMetadata{
				Name:     converters.StringPtr("John Doe"),
				JobTitle: converters.StringPtr("Software Engineer"),
			},
			description: "Should use GetUser for canonical lookup and return user metadata",
		},
		{
			name:  "search lookup success",
			input: "john.doe",
			mockMetadataLookup: func(ctx context.Context, input string) (*model.User, error) {
				// Verify input is correct
				if input != "john.doe" {
					t.Errorf("Expected input 'john.doe', got %q", input)
				}
				// Return user prepared for search lookup (no | in input)
				return &model.User{
					Username: "john.doe",
				}, nil
			},
			mockSearchUser: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
				// Verify the user was prepared correctly for search lookup
				if user.Username != "john.doe" {
					t.Errorf("User not prepared correctly for search lookup: Username=%q", user.Username)
				}
				if criteria != constants.CriteriaTypeUsername {
					t.Errorf("Expected criteria %s, got %s", constants.CriteriaTypeUsername, criteria)
				}
				return &model.User{
					UserID:   "auth0|987654321",
					Username: "john.doe",
					UserMetadata: &model.UserMetadata{
						Name:         converters.StringPtr("John Doe"),
						Organization: converters.StringPtr("Example Corp"),
					},
				}, nil
			},
			expectedError: false,
			expectedData: &model.UserMetadata{
				Name:         converters.StringPtr("John Doe"),
				Organization: converters.StringPtr("Example Corp"),
			},
			description: "Should use SearchUser for search lookup and return user metadata",
		},
		{
			name:  "canonical lookup user not found",
			input: "auth0|nonexistent",
			mockMetadataLookup: func(ctx context.Context, input string) (*model.User, error) {
				return &model.User{
					Sub:    "auth0|nonexistent",
					UserID: "auth0|nonexistent",
				}, nil
			},
			mockGetUser: func(ctx context.Context, user *model.User) (*model.User, error) {
				return nil, errors.NewNotFound("user not found")
			},
			expectedError: true,
			expectedData:  nil,
			description:   "Should return error when canonical lookup fails",
		},
		{
			name:  "search lookup user not found",
			input: "nonexistent.user",
			mockMetadataLookup: func(ctx context.Context, input string) (*model.User, error) {
				return &model.User{
					Username: "nonexistent.user",
				}, nil
			},
			mockSearchUser: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
				return nil, errors.NewNotFound("user not found by criteria")
			},
			expectedError: true,
			expectedData:  nil,
			description:   "Should return error when search lookup fails",
		},
		{
			name:          "empty input",
			input:         "",
			expectedError: true,
			expectedData:  nil,
			description:   "Should return error for empty input",
		},
		{
			name:          "whitespace only input",
			input:         "   ",
			expectedError: true,
			expectedData:  nil,
			description:   "Should return error for whitespace-only input",
		},
		{
			name:  "canonical lookup with nil metadata",
			input: "auth0|123456789",
			mockMetadataLookup: func(ctx context.Context, input string) (*model.User, error) {
				return &model.User{
					Sub:    "auth0|123456789",
					UserID: "auth0|123456789",
				}, nil
			},
			mockGetUser: func(ctx context.Context, user *model.User) (*model.User, error) {
				return &model.User{
					UserID:       "auth0|123456789",
					Username:     "john.doe",
					UserMetadata: nil, // No metadata
				}, nil
			},
			expectedError: false,
			expectedData:  nil,
			description:   "Should handle users with no metadata gracefully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock user reader
			mockReader := &mockUserServiceReader{
				getUserFunc:        tt.mockGetUser,
				searchUserFunc:     tt.mockSearchUser,
				metadataLookupFunc: tt.mockMetadataLookup,
			}

			// Create message handler orchestrator
			orchestrator := &messageHandlerOrchestrator{
				userReader: mockReader,
			}

			// Create mock transport messenger
			msg := &mockTransportMessenger{
				data: []byte(tt.input),
			}

			// Call GetUserMetadata
			ctx := context.Background()
			response, err := orchestrator.GetUserMetadata(ctx, msg)

			// Check for unexpected errors
			if err != nil {
				t.Fatalf("GetUserMetadata returned unexpected error: %v", err)
			}

			// Parse response
			var userResponse UserDataResponse
			if err := json.Unmarshal(response, &userResponse); err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}

			// Check error expectation
			if tt.expectedError {
				if userResponse.Success {
					t.Errorf("Expected error but got success response")
				}
				if userResponse.Error == "" {
					t.Errorf("Expected error message but got empty string")
				}
			} else {
				if !userResponse.Success {
					t.Errorf("Expected success but got error: %s", userResponse.Error)
				}
				if userResponse.Error != "" {
					t.Errorf("Expected no error but got: %s", userResponse.Error)
				}

				// Check data
				if tt.expectedData == nil {
					if userResponse.Data != nil {
						t.Errorf("Expected nil data but got: %+v", userResponse.Data)
					}
				} else {
					// Convert interface{} back to UserMetadata for comparison
					dataBytes, err := json.Marshal(userResponse.Data)
					if err != nil {
						t.Fatalf("Failed to marshal response data: %v", err)
					}
					var actualMetadata model.UserMetadata
					if err := json.Unmarshal(dataBytes, &actualMetadata); err != nil {
						t.Fatalf("Failed to unmarshal response data: %v", err)
					}

					// Compare metadata fields
					if !compareUserMetadata(&actualMetadata, tt.expectedData) {
						t.Errorf("Metadata mismatch:\nActual: %+v\nExpected: %+v", actualMetadata, *tt.expectedData)
					}
				}
			}
		})
	}
}

func TestMessageHandlerOrchestrator_GetUserMetadata_NoUserReader(t *testing.T) {
	// Test when userReader is nil
	orchestrator := &messageHandlerOrchestrator{
		userReader: nil,
	}

	msg := &mockTransportMessenger{
		data: []byte("auth0|123456789"),
	}

	ctx := context.Background()
	response, err := orchestrator.GetUserMetadata(ctx, msg)

	if err != nil {
		t.Fatalf("GetUserMetadata returned unexpected error: %v", err)
	}

	var userResponse UserDataResponse
	if err := json.Unmarshal(response, &userResponse); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if userResponse.Success {
		t.Errorf("Expected error but got success")
	}
	if userResponse.Error != "auth service unavailable" {
		t.Errorf("Expected 'auth service unavailable' error, got: %s", userResponse.Error)
	}
}

func TestMessageHandlerOrchestrator_UnlinkIdentity(t *testing.T) {
	ctx := context.Background()

	validPayload := func(provider, identityID string) []byte {
		req := &model.UnlinkIdentity{}
		req.User.AuthToken = "auth0|testuser"
		req.Unlink.Provider = provider
		req.Unlink.IdentityID = identityID
		data, _ := json.Marshal(req)
		return data
	}

	tests := []struct {
		name             string
		messageData      []byte
		userReader       *mockUserServiceReader
		identityUnlinker *mockIdentityLinker
		validateResult   func(t *testing.T, result []byte)
	}{
		{
			name:        "nil identityUnlinker returns service unavailable",
			messageData: validPayload("linkedin", "QhNK44iR6W"),
			userReader:  &mockUserServiceReader{},
			validateResult: func(t *testing.T, result []byte) {
				assertErrorResponse(t, result, "auth service unavailable")
			},
		},
		{
			name:             "nil userReader returns service unavailable",
			messageData:      validPayload("linkedin", "QhNK44iR6W"),
			identityUnlinker: &mockIdentityLinker{},
			validateResult: func(t *testing.T, result []byte) {
				assertErrorResponse(t, result, "auth service unavailable")
			},
		},
		{
			name:             "invalid JSON returns error",
			messageData:      []byte(`{invalid json`),
			userReader:       &mockUserServiceReader{},
			identityUnlinker: &mockIdentityLinker{},
			validateResult: func(t *testing.T, result []byte) {
				assertFailureResponse(t, result)
			},
		},
		{
			name:        "MetadataLookup failure returns error",
			messageData: validPayload("linkedin", "QhNK44iR6W"),
			userReader: &mockUserServiceReader{
				metadataLookupFunc: func(ctx context.Context, input string) (*model.User, error) {
					return nil, errors.NewUnauthorized("invalid token")
				},
			},
			identityUnlinker: &mockIdentityLinker{},
			validateResult: func(t *testing.T, result []byte) {
				assertErrorResponse(t, result, "invalid token")
			},
		},
		{
			name:        "unlinker error returns error",
			messageData: validPayload("linkedin", "QhNK44iR6W"),
			userReader: &mockUserServiceReader{
				metadataLookupFunc: func(ctx context.Context, input string) (*model.User, error) {
					return &model.User{UserID: "auth0|testuser"}, nil
				},
			},
			identityUnlinker: &mockIdentityLinker{
				unlinkIdentityFunc: func(ctx context.Context, request *model.UnlinkIdentity) error {
					return errors.NewUnexpected("failed to unlink identity from user")
				},
			},
			validateResult: func(t *testing.T, result []byte) {
				assertErrorResponse(t, result, "failed to unlink identity from user")
			},
		},
		{
			name:        "successful unlink passes correct fields to unlinker",
			messageData: validPayload("linkedin", "QhNK44iR6W"),
			userReader: &mockUserServiceReader{
				metadataLookupFunc: func(ctx context.Context, input string) (*model.User, error) {
					return &model.User{UserID: "auth0|testuser"}, nil
				},
			},
			identityUnlinker: &mockIdentityLinker{
				unlinkIdentityFunc: func(ctx context.Context, request *model.UnlinkIdentity) error {
					if request.User.UserID != "auth0|testuser" {
						t.Errorf("expected user_id auth0|testuser, got %s", request.User.UserID)
					}
					if request.Unlink.Provider != "linkedin" {
						t.Errorf("expected provider linkedin, got %s", request.Unlink.Provider)
					}
					if request.Unlink.IdentityID != "QhNK44iR6W" {
						t.Errorf("expected identity_id QhNK44iR6W, got %s", request.Unlink.IdentityID)
					}
					return nil
				},
			},
			validateResult: func(t *testing.T, result []byte) {
				var resp UserDataResponse
				if err := json.Unmarshal(result, &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if !resp.Success {
					t.Errorf("expected success=true, got error: %s", resp.Error)
				}
				if resp.Message != "identity unlinked successfully" {
					t.Errorf("expected message 'identity unlinked successfully', got %q", resp.Message)
				}
			},
		},
		{
			name:        "user_id is populated from MetadataLookup not from payload",
			messageData: validPayload("google-oauth2", "110851128638631517648"),
			userReader: &mockUserServiceReader{
				metadataLookupFunc: func(ctx context.Context, input string) (*model.User, error) {
					return &model.User{UserID: "auth0|resolveduser"}, nil
				},
			},
			identityUnlinker: &mockIdentityLinker{
				unlinkIdentityFunc: func(ctx context.Context, request *model.UnlinkIdentity) error {
					if request.User.UserID != "auth0|resolveduser" {
						t.Errorf("user_id should come from MetadataLookup, got %s", request.User.UserID)
					}
					return nil
				},
			},
			validateResult: func(t *testing.T, result []byte) {
				assertSuccessResponse(t, result)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := []MessageHandlerOrchestratorOption{}
			if tt.userReader != nil {
				opts = append(opts, WithUserReaderForMessageHandler(tt.userReader))
			}
			if tt.identityUnlinker != nil {
				opts = append(opts, WithIdentityUnlinkerForMessageHandler(tt.identityUnlinker))
			}

			orchestrator := NewMessageHandlerOrchestrator(opts...)
			result, err := orchestrator.UnlinkIdentity(ctx, &mockTransportMessenger{data: tt.messageData})

			if err != nil {
				t.Fatalf("UnlinkIdentity() unexpected Go error: %v", err)
			}
			if result == nil {
				t.Fatal("UnlinkIdentity() returned nil result")
			}
			tt.validateResult(t, result)
		})
	}
}

func assertErrorResponse(t *testing.T, result []byte, wantErr string) {
	t.Helper()
	var resp UserDataResponse
	if err := json.Unmarshal(result, &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.Success {
		t.Errorf("expected success=false, got success=true")
	}
	if resp.Error != wantErr {
		t.Errorf("expected error %q, got %q", wantErr, resp.Error)
	}
}

func assertFailureResponse(t *testing.T, result []byte) {
	t.Helper()
	var resp UserDataResponse
	if err := json.Unmarshal(result, &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.Success {
		t.Errorf("expected success=false")
	}
}

func assertSuccessResponse(t *testing.T, result []byte) {
	t.Helper()
	var resp UserDataResponse
	if err := json.Unmarshal(result, &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if !resp.Success {
		t.Errorf("expected success=true, got error: %s", resp.Error)
	}
}

// Helper function to compare UserMetadata structs
func compareUserMetadata(actual, expected *model.UserMetadata) bool {
	if actual == nil && expected == nil {
		return true
	}
	if actual == nil || expected == nil {
		return false
	}

	return compareStringPtr(actual.Name, expected.Name) &&
		compareStringPtr(actual.JobTitle, expected.JobTitle) &&
		compareStringPtr(actual.Organization, expected.Organization) &&
		compareStringPtr(actual.Picture, expected.Picture) &&
		compareStringPtr(actual.GivenName, expected.GivenName) &&
		compareStringPtr(actual.FamilyName, expected.FamilyName) &&
		compareStringPtr(actual.Country, expected.Country) &&
		compareStringPtr(actual.StateProvince, expected.StateProvince) &&
		compareStringPtr(actual.City, expected.City) &&
		compareStringPtr(actual.Address, expected.Address) &&
		compareStringPtr(actual.PostalCode, expected.PostalCode) &&
		compareStringPtr(actual.PhoneNumber, expected.PhoneNumber) &&
		compareStringPtr(actual.TShirtSize, expected.TShirtSize) &&
		compareStringPtr(actual.Zoneinfo, expected.Zoneinfo)
}

// Helper function to compare string pointers
func compareStringPtr(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func TestMessageHandlerOrchestrator_LinkIdentity(t *testing.T) {
	ctx := context.Background()

	validRequest := func() []byte {
		r := &model.LinkIdentity{}
		r.User.AuthToken = "some-auth-token"
		r.LinkWith.IdentityToken = "some-identity-token"
		data, _ := json.Marshal(r)
		return data
	}()

	tests := []struct {
		name          string
		messageData   []byte
		linker        *mockIdentityLinker
		reader        *mockUserServiceReader
		expectSuccess bool
		expectError   string
	}{
		{
			name:        "validate guard blocks database user token",
			messageData: validRequest,
			linker: &mockIdentityLinker{
				validateLinkRequestFunc: func(_ context.Context, _ *model.LinkIdentity) error {
					return errors.NewValidation("the provided identity token belongs to an existing LFID account and cannot be linked")
				},
				linkIdentityFunc: func(_ context.Context, _ *model.LinkIdentity) error {
					t.Error("LinkIdentity should not be called when validation fails")
					return nil
				},
			},
			reader:        &mockUserServiceReader{},
			expectSuccess: false,
			expectError:   "the provided identity token belongs to an existing LFID account and cannot be linked",
		},
		{
			name:        "validate guard passes for social token",
			messageData: validRequest,
			linker: &mockIdentityLinker{
				validateLinkRequestFunc: func(_ context.Context, _ *model.LinkIdentity) error { return nil },
				linkIdentityFunc:        func(_ context.Context, _ *model.LinkIdentity) error { return nil },
			},
			reader: &mockUserServiceReader{
				metadataLookupFunc: func(_ context.Context, _ string) (*model.User, error) {
					return &model.User{UserID: "auth0|user123"}, nil
				},
			},
			expectSuccess: true,
		},
		{
			name:          "invalid json returns error",
			messageData:   []byte(`{bad json`),
			linker:        &mockIdentityLinker{},
			reader:        &mockUserServiceReader{},
			expectSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orchestrator := NewMessageHandlerOrchestrator(
				WithIdentityLinkerForMessageHandler(tt.linker),
				WithUserReaderForMessageHandler(tt.reader),
			)

			result, err := orchestrator.LinkIdentity(ctx, &mockTransportMessenger{data: tt.messageData})
			if err != nil {
				t.Fatalf("unexpected Go error: %v", err)
			}

			var response UserDataResponse
			if err := json.Unmarshal(result, &response); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			if response.Success != tt.expectSuccess {
				t.Errorf("success = %v, want %v (error: %s)", response.Success, tt.expectSuccess, response.Error)
			}
			if tt.expectError != "" && response.Error != tt.expectError {
				t.Errorf("error = %q, want %q", response.Error, tt.expectError)
			}
		})
	}
}

func TestMessageHandlerOrchestrator_GetUserEmails(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		messageData    []byte
		mockReader     *mockUserServiceReader
		expectSuccess  bool
		expectError    string
		validateResult func(t *testing.T, result []byte)
	}{
		{
			name:        "returns primary and alternate emails",
			messageData: []byte(`{"user":{"auth_token":"valid-token"}}`),
			mockReader: &mockUserServiceReader{
				metadataLookupFunc: func(ctx context.Context, input string) (*model.User, error) {
					return &model.User{UserID: "auth0|123"}, nil
				},
				getUserFunc: func(ctx context.Context, user *model.User) (*model.User, error) {
					return &model.User{
						UserID:       "auth0|123",
						PrimaryEmail: "primary@example.com",
						Identities: []model.Identity{
							{Connection: constants.EmailConnection, Email: "alt1@example.com", EmailVerified: true},
							{Connection: constants.EmailConnection, Email: "alt2@example.com", EmailVerified: false},
							{Connection: "google-oauth2", Email: "social@example.com", EmailVerified: true},
						},
					}, nil
				},
			},
			expectSuccess: true,
			validateResult: func(t *testing.T, result []byte) {
				var response struct {
					Success bool `json:"success"`
					Data    struct {
						PrimaryEmail    string       `json:"primary_email"`
						AlternateEmails []model.Email `json:"alternate_emails"`
					} `json:"data"`
				}
				if err := json.Unmarshal(result, &response); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if response.Data.PrimaryEmail != "primary@example.com" {
					t.Errorf("primary_email = %q, want %q", response.Data.PrimaryEmail, "primary@example.com")
				}
				if len(response.Data.AlternateEmails) != 2 {
					t.Fatalf("expected 2 alternate emails, got %d", len(response.Data.AlternateEmails))
				}
				if response.Data.AlternateEmails[0].Email != "alt1@example.com" {
					t.Errorf("alternate_emails[0].email = %q, want %q", response.Data.AlternateEmails[0].Email, "alt1@example.com")
				}
				if !response.Data.AlternateEmails[0].Verified {
					t.Error("expected alternate_emails[0].verified = true")
				}
			},
		},
		{
			name:        "includes primary email in alternate_emails for identification",
			messageData: []byte(`{"user":{"auth_token":"valid-token"}}`),
			mockReader: &mockUserServiceReader{
				metadataLookupFunc: func(ctx context.Context, input string) (*model.User, error) {
					return &model.User{UserID: "auth0|123"}, nil
				},
				getUserFunc: func(ctx context.Context, user *model.User) (*model.User, error) {
					return &model.User{
						UserID:       "auth0|123",
						PrimaryEmail: "primary@example.com",
						Identities: []model.Identity{
							{Connection: constants.EmailConnection, Email: "primary@example.com", EmailVerified: true},
							{Connection: constants.EmailConnection, Email: "alt@example.com", EmailVerified: true},
						},
					}, nil
				},
			},
			expectSuccess: true,
			validateResult: func(t *testing.T, result []byte) {
				var response struct {
					Success bool `json:"success"`
					Data    struct {
						PrimaryEmail    string        `json:"primary_email"`
						AlternateEmails []model.Email `json:"alternate_emails"`
					} `json:"data"`
				}
				if err := json.Unmarshal(result, &response); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if response.Data.PrimaryEmail != "primary@example.com" {
					t.Errorf("primary_email = %q, want %q", response.Data.PrimaryEmail, "primary@example.com")
				}
				if len(response.Data.AlternateEmails) != 2 {
					t.Fatalf("expected 2 alternate emails (primary included), got %d", len(response.Data.AlternateEmails))
				}
				foundPrimary := false
				for _, e := range response.Data.AlternateEmails {
					if e.Email == response.Data.PrimaryEmail {
						foundPrimary = true
					}
				}
				if !foundPrimary {
					t.Error("expected primary email to appear in alternate_emails")
				}
			},
		},
		{
			name:        "returns empty alternate_emails array when no email identities",
			messageData: []byte(`{"user":{"auth_token":"valid-token"}}`),
			mockReader: &mockUserServiceReader{
				metadataLookupFunc: func(ctx context.Context, input string) (*model.User, error) {
					return &model.User{UserID: "auth0|123"}, nil
				},
				getUserFunc: func(ctx context.Context, user *model.User) (*model.User, error) {
					return &model.User{
						UserID:       "auth0|123",
						PrimaryEmail: "primary@example.com",
						Identities: []model.Identity{
							{Connection: "google-oauth2", Email: "social@example.com"},
						},
					}, nil
				},
			},
			expectSuccess: true,
			validateResult: func(t *testing.T, result []byte) {
				var response struct {
					Success bool `json:"success"`
					Data    struct {
						AlternateEmails []model.Email `json:"alternate_emails"`
					} `json:"data"`
				}
				if err := json.Unmarshal(result, &response); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if len(response.Data.AlternateEmails) != 0 {
					t.Errorf("expected 0 alternate emails, got %d", len(response.Data.AlternateEmails))
				}
			},
		},
		{
			name:          "missing auth_token",
			messageData:   []byte(`{"user":{"auth_token":""}}`),
			mockReader:    &mockUserServiceReader{},
			expectSuccess: false,
			expectError:   "auth_token is required",
		},
		{
			name:          "invalid json payload",
			messageData:   []byte(`not-json`),
			mockReader:    &mockUserServiceReader{},
			expectSuccess: false,
			expectError:   "failed to unmarshal request",
		},
		{
			name:          "reader unavailable",
			messageData:   []byte(`{"user":{"auth_token":"token"}}`),
			mockReader:    nil,
			expectSuccess: false,
			expectError:   "auth service unavailable",
		},
		{
			name:        "metadata lookup failure",
			messageData: []byte(`{"user":{"auth_token":"bad-token"}}`),
			mockReader: &mockUserServiceReader{
				metadataLookupFunc: func(ctx context.Context, input string) (*model.User, error) {
					return nil, errors.NewValidation("invalid token")
				},
			},
			expectSuccess: false,
			expectError:   "invalid token",
		},
		{
			name:        "get user failure",
			messageData: []byte(`{"user":{"auth_token":"valid-token"}}`),
			mockReader: &mockUserServiceReader{
				metadataLookupFunc: func(ctx context.Context, input string) (*model.User, error) {
					return &model.User{UserID: "auth0|123"}, nil
				},
				getUserFunc: func(ctx context.Context, user *model.User) (*model.User, error) {
					return nil, errors.NewNotFound("user not found")
				},
			},
			expectSuccess: false,
			expectError:   "user not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &mockTransportMessenger{data: tt.messageData}

			var opts []MessageHandlerOrchestratorOption
			if tt.mockReader != nil {
				opts = append(opts, WithUserReaderForMessageHandler(tt.mockReader))
			}
			handler := NewMessageHandlerOrchestrator(opts...)

			result, err := handler.GetUserEmails(ctx, msg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var response UserDataResponse
			if err := json.Unmarshal(result, &response); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			if response.Success != tt.expectSuccess {
				t.Errorf("success = %v, want %v (error: %s)", response.Success, tt.expectSuccess, response.Error)
			}
			if tt.expectError != "" && response.Error != tt.expectError {
				t.Errorf("error = %q, want %q", response.Error, tt.expectError)
			}
			if tt.validateResult != nil {
				tt.validateResult(t, result)
			}
		})
	}
}

func TestMessageHandlerOrchestrator_ListIdentities(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name               string
		messageData        []byte
		mockReader         *mockUserServiceReader
		expectSuccess      bool
		expectError        string
		validateIdentities func(t *testing.T, result []byte)
	}{
		{
			name:        "successful list with identities",
			messageData: []byte(`{"user":{"auth_token":"valid-token"}}`),
			mockReader: &mockUserServiceReader{
				metadataLookupFunc: func(ctx context.Context, input string) (*model.User, error) {
					return &model.User{UserID: "auth0|123", Token: input}, nil
				},
				getUserFunc: func(ctx context.Context, user *model.User) (*model.User, error) {
					return &model.User{
						UserID: "auth0|123",
						Identities: []model.Identity{
							{Provider: "google-oauth2", IdentityID: "google123", Email: "user@gmail.com", IsSocial: true},
							{Provider: "github", IdentityID: "gh456", Nickname: "octocat", IsSocial: true},
						},
					}, nil
				},
			},
			expectSuccess: true,
			validateIdentities: func(t *testing.T, result []byte) {
				var response struct {
					Success bool               `json:"success"`
					Data    []identityResponse `json:"data"`
				}
				if err := json.Unmarshal(result, &response); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if len(response.Data) != 2 {
					t.Fatalf("expected 2 identities, got %d", len(response.Data))
				}
				if response.Data[0].Provider != "google-oauth2" {
					t.Errorf("expected provider google-oauth2, got %s", response.Data[0].Provider)
				}
				if response.Data[0].UserID != "google123" {
					t.Errorf("expected user_id google123, got %s", response.Data[0].UserID)
				}
				if !response.Data[0].IsSocial {
					t.Error("expected isSocial true")
				}
				if response.Data[0].ProfileData == nil || response.Data[0].ProfileData.Email != "user@gmail.com" {
					t.Error("expected profileData with email")
				}
				if response.Data[1].ProfileData == nil || response.Data[1].ProfileData.Nickname != "octocat" {
					t.Error("expected profileData with nickname for GitHub identity")
				}
			},
		},
		{
			name:        "successful list with no identities",
			messageData: []byte(`{"user":{"auth_token":"valid-token"}}`),
			mockReader: &mockUserServiceReader{
				metadataLookupFunc: func(ctx context.Context, input string) (*model.User, error) {
					return &model.User{UserID: "auth0|123", Token: input}, nil
				},
				getUserFunc: func(ctx context.Context, user *model.User) (*model.User, error) {
					return &model.User{UserID: "auth0|123", Identities: nil}, nil
				},
			},
			expectSuccess: true,
			validateIdentities: func(t *testing.T, result []byte) {
				var response struct {
					Success bool               `json:"success"`
					Data    []identityResponse `json:"data"`
				}
				if err := json.Unmarshal(result, &response); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if len(response.Data) != 0 {
					t.Errorf("expected 0 identities, got %d", len(response.Data))
				}
			},
		},
		{
			name:          "missing auth_token",
			messageData:   []byte(`{"user":{"auth_token":""}}`),
			mockReader:    &mockUserServiceReader{},
			expectSuccess: false,
			expectError:   "auth_token is required",
		},
		{
			name:          "invalid json payload",
			messageData:   []byte(`not-json`),
			mockReader:    &mockUserServiceReader{},
			expectSuccess: false,
			expectError:   "failed to unmarshal request",
		},
		{
			name:          "reader unavailable",
			messageData:   []byte(`{"user":{"auth_token":"token"}}`),
			mockReader:    nil, // handler created without WithUserReaderForMessageHandler
			expectSuccess: false,
			expectError:   "auth service unavailable",
		},
		{
			name:        "metadata lookup failure",
			messageData: []byte(`{"user":{"auth_token":"bad-token"}}`),
			mockReader: &mockUserServiceReader{
				metadataLookupFunc: func(ctx context.Context, input string) (*model.User, error) {
					return nil, errors.NewValidation("invalid token")
				},
			},
			expectSuccess: false,
			expectError:   "invalid token",
		},
		{
			name:        "get user failure",
			messageData: []byte(`{"user":{"auth_token":"valid-token"}}`),
			mockReader: &mockUserServiceReader{
				metadataLookupFunc: func(ctx context.Context, input string) (*model.User, error) {
					return &model.User{UserID: "auth0|123", Token: input}, nil
				},
				getUserFunc: func(ctx context.Context, user *model.User) (*model.User, error) {
					return nil, errors.NewNotFound("user not found")
				},
			},
			expectSuccess: false,
			expectError:   "user not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &mockTransportMessenger{data: tt.messageData}

			var opts []MessageHandlerOrchestratorOption
			if tt.mockReader != nil {
				opts = append(opts, WithUserReaderForMessageHandler(tt.mockReader))
			}
			handler := NewMessageHandlerOrchestrator(opts...)

			result, err := handler.ListIdentities(ctx, msg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var response UserDataResponse
			if err := json.Unmarshal(result, &response); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			if response.Success != tt.expectSuccess {
				t.Errorf("success = %v, want %v (error: %s)", response.Success, tt.expectSuccess, response.Error)
			}
			if tt.expectError != "" && response.Error != tt.expectError {
				t.Errorf("error = %q, want %q", response.Error, tt.expectError)
			}
			if tt.validateIdentities != nil {
				tt.validateIdentities(t, result)
			}
		})
	}
}

func TestMessageHandlerOrchestrator_ChangePassword(t *testing.T) {
	ctx := context.Background()

	validPayload := func() []byte {
		data, _ := json.Marshal(model.ChangePasswordRequest{
			Token:           "valid-token",
			CurrentPassword: "oldpass123",
			NewPassword:     "newpass456",
		})
		return data
	}

	tests := []struct {
		name            string
		messageData     []byte
		passwordHandler *mockPasswordHandler
		userReader      *mockUserServiceReader
		validateResult  func(t *testing.T, result []byte)
	}{
		{
			name:        "nil passwordHandler returns service unavailable",
			messageData: validPayload(),
			userReader:  &mockUserServiceReader{},
			validateResult: func(t *testing.T, result []byte) {
				assertErrorResponse(t, result, "password service unavailable")
			},
		},
		{
			name:            "nil userReader returns service unavailable",
			messageData:     validPayload(),
			passwordHandler: &mockPasswordHandler{},
			validateResult: func(t *testing.T, result []byte) {
				assertErrorResponse(t, result, "password service unavailable")
			},
		},
		{
			name:            "invalid JSON returns error",
			messageData:     []byte(`{invalid json`),
			userReader:      &mockUserServiceReader{},
			passwordHandler: &mockPasswordHandler{},
			validateResult: func(t *testing.T, result []byte) {
				assertFailureResponse(t, result)
			},
		},
		{
			name: "missing token returns error",
			messageData: func() []byte {
				data, _ := json.Marshal(model.ChangePasswordRequest{
					CurrentPassword: "oldpass123",
					NewPassword:     "newpass456",
				})
				return data
			}(),
			userReader:      &mockUserServiceReader{},
			passwordHandler: &mockPasswordHandler{},
			validateResult: func(t *testing.T, result []byte) {
				assertErrorResponse(t, result, "token is required")
			},
		},
		{
			name: "missing current_password returns error",
			messageData: func() []byte {
				data, _ := json.Marshal(model.ChangePasswordRequest{
					Token:       "valid-token",
					NewPassword: "newpass456",
				})
				return data
			}(),
			userReader:      &mockUserServiceReader{},
			passwordHandler: &mockPasswordHandler{},
			validateResult: func(t *testing.T, result []byte) {
				assertErrorResponse(t, result, "current_password is required")
			},
		},
		{
			name: "missing new_password returns error",
			messageData: func() []byte {
				data, _ := json.Marshal(model.ChangePasswordRequest{
					Token:           "valid-token",
					CurrentPassword: "oldpass123",
				})
				return data
			}(),
			userReader:      &mockUserServiceReader{},
			passwordHandler: &mockPasswordHandler{},
			validateResult: func(t *testing.T, result []byte) {
				assertErrorResponse(t, result, "new_password is required")
			},
		},
		{
			name:        "MetadataLookup failure returns error",
			messageData: validPayload(),
			userReader: &mockUserServiceReader{
				metadataLookupFunc: func(ctx context.Context, input string) (*model.User, error) {
					return nil, errors.NewUnauthorized("invalid token")
				},
			},
			passwordHandler: &mockPasswordHandler{},
			validateResult: func(t *testing.T, result []byte) {
				assertErrorResponse(t, result, "invalid token")
			},
		},
		{
			name:        "password handler error returns error",
			messageData: validPayload(),
			userReader: &mockUserServiceReader{
				metadataLookupFunc: func(ctx context.Context, input string) (*model.User, error) {
					return &model.User{UserID: "auth0|123"}, nil
				},
			},
			passwordHandler: &mockPasswordHandler{
				changePasswordFunc: func(ctx context.Context, user *model.User, currentPassword, newPassword string) error {
					return errors.NewUnauthorized("current password is incorrect")
				},
			},
			validateResult: func(t *testing.T, result []byte) {
				assertErrorResponse(t, result, "current password is incorrect")
			},
		},
		{
			name:        "successful password change",
			messageData: validPayload(),
			userReader: &mockUserServiceReader{
				metadataLookupFunc: func(ctx context.Context, input string) (*model.User, error) {
					return &model.User{UserID: "auth0|123"}, nil
				},
			},
			passwordHandler: &mockPasswordHandler{
				changePasswordFunc: func(ctx context.Context, user *model.User, currentPassword, newPassword string) error {
					if user.UserID != "auth0|123" {
						t.Errorf("expected user_id auth0|123, got %s", user.UserID)
					}
					if currentPassword != "oldpass123" {
						t.Errorf("expected currentPassword oldpass123, got %s", currentPassword)
					}
					if newPassword != "newpass456" {
						t.Errorf("expected newPassword newpass456, got %s", newPassword)
					}
					return nil
				},
			},
			validateResult: func(t *testing.T, result []byte) {
				assertSuccessResponse(t, result)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &mockTransportMessenger{data: tt.messageData}

			var opts []MessageHandlerOrchestratorOption
			if tt.userReader != nil {
				opts = append(opts, WithUserReaderForMessageHandler(tt.userReader))
			}
			if tt.passwordHandler != nil {
				opts = append(opts, WithPasswordHandlerForMessageHandler(tt.passwordHandler))
			}
			handler := NewMessageHandlerOrchestrator(opts...)

			result, err := handler.ChangePassword(ctx, msg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			tt.validateResult(t, result)
		})
	}
}

func TestMessageHandlerOrchestrator_SendResetPasswordLink(t *testing.T) {
	ctx := context.Background()

	validPayload := func() []byte {
		data, _ := json.Marshal(model.ResetPasswordLinkRequest{
			Token: "valid-token",
		})
		return data
	}

	tests := []struct {
		name            string
		messageData     []byte
		passwordHandler *mockPasswordHandler
		userReader      *mockUserServiceReader
		validateResult  func(t *testing.T, result []byte)
	}{
		{
			name:        "nil passwordHandler returns service unavailable",
			messageData: validPayload(),
			userReader:  &mockUserServiceReader{},
			validateResult: func(t *testing.T, result []byte) {
				assertErrorResponse(t, result, "password service unavailable")
			},
		},
		{
			name:            "nil userReader returns service unavailable",
			messageData:     validPayload(),
			passwordHandler: &mockPasswordHandler{},
			validateResult: func(t *testing.T, result []byte) {
				assertErrorResponse(t, result, "password service unavailable")
			},
		},
		{
			name:            "invalid JSON returns error",
			messageData:     []byte(`{invalid json`),
			userReader:      &mockUserServiceReader{},
			passwordHandler: &mockPasswordHandler{},
			validateResult: func(t *testing.T, result []byte) {
				assertFailureResponse(t, result)
			},
		},
		{
			name: "missing token returns error",
			messageData: func() []byte {
				data, _ := json.Marshal(model.ResetPasswordLinkRequest{})
				return data
			}(),
			userReader:      &mockUserServiceReader{},
			passwordHandler: &mockPasswordHandler{},
			validateResult: func(t *testing.T, result []byte) {
				assertErrorResponse(t, result, "token is required")
			},
		},
		{
			name:        "MetadataLookup failure returns error",
			messageData: validPayload(),
			userReader: &mockUserServiceReader{
				metadataLookupFunc: func(ctx context.Context, input string) (*model.User, error) {
					return nil, errors.NewUnauthorized("invalid token")
				},
			},
			passwordHandler: &mockPasswordHandler{},
			validateResult: func(t *testing.T, result []byte) {
				assertErrorResponse(t, result, "invalid token")
			},
		},
		{
			name:        "password handler error returns error",
			messageData: validPayload(),
			userReader: &mockUserServiceReader{
				metadataLookupFunc: func(ctx context.Context, input string) (*model.User, error) {
					return &model.User{UserID: "auth0|123"}, nil
				},
			},
			passwordHandler: &mockPasswordHandler{
				sendResetPasswordLinkFunc: func(ctx context.Context, user *model.User) error {
					return errors.NewUnexpected("failed to send reset password link")
				},
			},
			validateResult: func(t *testing.T, result []byte) {
				assertErrorResponse(t, result, "failed to send reset password link")
			},
		},
		{
			name:        "successful reset password link",
			messageData: validPayload(),
			userReader: &mockUserServiceReader{
				metadataLookupFunc: func(ctx context.Context, input string) (*model.User, error) {
					return &model.User{UserID: "auth0|123"}, nil
				},
			},
			passwordHandler: &mockPasswordHandler{
				sendResetPasswordLinkFunc: func(ctx context.Context, user *model.User) error {
					if user.UserID != "auth0|123" {
						t.Errorf("expected user_id auth0|123, got %s", user.UserID)
					}
					return nil
				},
			},
			validateResult: func(t *testing.T, result []byte) {
				assertSuccessResponse(t, result)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &mockTransportMessenger{data: tt.messageData}

			var opts []MessageHandlerOrchestratorOption
			if tt.userReader != nil {
				opts = append(opts, WithUserReaderForMessageHandler(tt.userReader))
			}
			if tt.passwordHandler != nil {
				opts = append(opts, WithPasswordHandlerForMessageHandler(tt.passwordHandler))
			}
			handler := NewMessageHandlerOrchestrator(opts...)

			result, err := handler.SendResetPasswordLink(ctx, msg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			tt.validateResult(t, result)
		})
	}
}

func TestMessageHandlerOrchestrator_SetPrimaryEmail(t *testing.T) {
	ctx := context.Background()

	validPayload := func() []byte {
		data, _ := json.Marshal(setPrimaryEmailRequest{
			User: struct {
				AuthToken string `json:"auth_token"`
			}{AuthToken: "valid-token"},
			Email: "new-primary@example.com",
		})
		return data
	}

	tests := []struct {
		name           string
		messageData    []byte
		userWriter     *mockUserServiceWriter
		userReader     *mockUserServiceReader
		validateResult func(t *testing.T, result []byte)
	}{
		{
			name:        "nil userWriter returns service unavailable",
			messageData: validPayload(),
			userReader:  &mockUserServiceReader{},
			validateResult: func(t *testing.T, result []byte) {
				assertErrorResponse(t, result, "auth service unavailable")
			},
		},
		{
			name:        "nil userReader returns service unavailable",
			messageData: validPayload(),
			userWriter:  &mockUserServiceWriter{},
			validateResult: func(t *testing.T, result []byte) {
				assertErrorResponse(t, result, "auth service unavailable")
			},
		},
		{
			name:        "invalid JSON returns error",
			messageData: []byte(`{invalid json`),
			userReader:  &mockUserServiceReader{},
			userWriter:  &mockUserServiceWriter{},
			validateResult: func(t *testing.T, result []byte) {
				assertFailureResponse(t, result)
			},
		},
		{
			name: "missing auth_token returns error",
			messageData: func() []byte {
				data, _ := json.Marshal(setPrimaryEmailRequest{
					Email: "new-primary@example.com",
				})
				return data
			}(),
			userReader: &mockUserServiceReader{},
			userWriter: &mockUserServiceWriter{},
			validateResult: func(t *testing.T, result []byte) {
				assertErrorResponse(t, result, "auth_token is required")
			},
		},
		{
			name: "missing email returns error",
			messageData: func() []byte {
				data, _ := json.Marshal(setPrimaryEmailRequest{
					User: struct {
						AuthToken string `json:"auth_token"`
					}{AuthToken: "valid-token"},
				})
				return data
			}(),
			userReader: &mockUserServiceReader{},
			userWriter: &mockUserServiceWriter{},
			validateResult: func(t *testing.T, result []byte) {
				assertErrorResponse(t, result, "email is required")
			},
		},
		{
			name:        "MetadataLookup failure returns error",
			messageData: validPayload(),
			userReader: &mockUserServiceReader{
				metadataLookupFunc: func(ctx context.Context, input string) (*model.User, error) {
					return nil, errors.NewUnauthorized("invalid token")
				},
			},
			userWriter: &mockUserServiceWriter{},
			validateResult: func(t *testing.T, result []byte) {
				assertErrorResponse(t, result, "invalid token")
			},
		},
		{
			name:        "SetPrimaryEmail handler error returns error",
			messageData: validPayload(),
			userReader: &mockUserServiceReader{
				metadataLookupFunc: func(ctx context.Context, input string) (*model.User, error) {
					return &model.User{UserID: "auth0|123"}, nil
				},
			},
			userWriter: &mockUserServiceWriter{
				setPrimaryEmailFunc: func(ctx context.Context, userID string, email string) error {
					return errors.NewValidation("email not found in alternate emails")
				},
			},
			validateResult: func(t *testing.T, result []byte) {
				assertErrorResponse(t, result, "email not found in alternate emails")
			},
		},
		{
			name:        "successful set primary email",
			messageData: validPayload(),
			userReader: &mockUserServiceReader{
				metadataLookupFunc: func(ctx context.Context, input string) (*model.User, error) {
					return &model.User{UserID: "auth0|123"}, nil
				},
			},
			userWriter: &mockUserServiceWriter{
				setPrimaryEmailFunc: func(ctx context.Context, userID string, email string) error {
					if userID != "auth0|123" {
						t.Errorf("expected user_id auth0|123, got %s", userID)
					}
					if email != "new-primary@example.com" {
						t.Errorf("expected email new-primary@example.com, got %s", email)
					}
					return nil
				},
			},
			validateResult: func(t *testing.T, result []byte) {
				assertSuccessResponse(t, result)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &mockTransportMessenger{data: tt.messageData}

			var opts []MessageHandlerOrchestratorOption
			if tt.userReader != nil {
				opts = append(opts, WithUserReaderForMessageHandler(tt.userReader))
			}
			if tt.userWriter != nil {
				opts = append(opts, WithUserWriterForMessageHandler(tt.userWriter))
			}
			handler := NewMessageHandlerOrchestrator(opts...)

			result, err := handler.SetPrimaryEmail(ctx, msg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			tt.validateResult(t, result)
		})
	}
}
