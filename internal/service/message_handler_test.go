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

// mockUserServiceWriter is a mock implementation of UserServiceWriter for testing
type mockUserServiceWriter struct {
	updateUserFunc func(ctx context.Context, user *model.User) (*model.User, error)
}

func (m *mockUserServiceWriter) UpdateUser(ctx context.Context, user *model.User) (*model.User, error) {
	if m.updateUserFunc != nil {
		return m.updateUserFunc(ctx, user)
	}
	return user, nil
}

// mockUserServiceReader is a mock implementation of UserServiceReader for testing
type mockUserServiceReader struct {
	getUserFunc        func(ctx context.Context, user *model.User) (*model.User, error)
	searchUserFunc     func(ctx context.Context, user *model.User, criteria string) (*model.User, error)
	metadataLookupFunc func(ctx context.Context, input string, user *model.User) bool
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

func (m *mockUserServiceReader) MetadataLookup(ctx context.Context, input string, user *model.User) bool {
	if m.metadataLookupFunc != nil {
		return m.metadataLookupFunc(ctx, input, user)
	}

	// Default implementation: follow the same logic as the real implementations
	input = strings.TrimSpace(input)

	if strings.Contains(input, "|") {
		// Input contains "|", use as sub for canonical lookup
		user.Sub = input
		user.UserID = input
		user.Username = ""
		return true
	}

	// Input doesn't contain "|", use for search query
	user.Username = input
	user.Sub = ""
	user.UserID = ""
	return false
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

	if response.Error != "user service unavailable" {
		t.Errorf("Expected error 'user service unavailable', got %s", response.Error)
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
		name           string
		input          string
		mockGetUser    func(ctx context.Context, user *model.User) (*model.User, error)
		mockSearchUser func(ctx context.Context, user *model.User, criteria string) (*model.User, error)
		expectedError  bool
		expectedData   *model.UserMetadata
		description    string
	}{
		{
			name:  "canonical lookup success",
			input: "auth0|123456789",
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
			mockSearchUser: func(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
				// Verify the user was prepared correctly for search lookup
				if user.Username != "john.doe" {
					t.Errorf("User not prepared correctly for search lookup: Username=%q", user.Username)
				}
				// Verify the criteria is correct
				if criteria != constants.CriteriaTypeUsername {
					t.Errorf("Wrong criteria passed: got %q, expected %q", criteria, constants.CriteriaTypeUsername)
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
				getUserFunc:    tt.mockGetUser,
				searchUserFunc: tt.mockSearchUser,
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
	if userResponse.Error != "user service unavailable" {
		t.Errorf("Expected 'user service unavailable' error, got: %s", userResponse.Error)
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
