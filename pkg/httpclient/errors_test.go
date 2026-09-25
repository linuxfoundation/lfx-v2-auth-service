// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package httpclient

import (
	"net/http"
	"testing"

	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
)

func TestErrorFromStatusCode(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		message       string
		expectedType  string
		expectedError string
	}{
		{
			name:          "BadRequest returns Validation error",
			statusCode:    http.StatusBadRequest,
			message:       "invalid request",
			expectedType:  "*errors.Validation",
			expectedError: "invalid request",
		},
		{
			name:          "Unauthorized returns Unauthorized error",
			statusCode:    http.StatusUnauthorized,
			message:       "authentication required",
			expectedType:  "*errors.Unauthorized",
			expectedError: "authentication required",
		},
		{
			name:          "Forbidden returns Forbidden error",
			statusCode:    http.StatusForbidden,
			message:       "access denied",
			expectedType:  "*errors.Forbidden",
			expectedError: "access denied",
		},
		{
			name:          "NotFound returns NotFound error",
			statusCode:    http.StatusNotFound,
			message:       "resource not found",
			expectedType:  "*errors.NotFound",
			expectedError: "resource not found",
		},
		{
			name:          "InternalServerError returns Unexpected error",
			statusCode:    http.StatusInternalServerError,
			message:       "server error",
			expectedType:  "*errors.Unexpected",
			expectedError: "server error",
		},
		{
			name:          "Unknown status code returns Unexpected error",
			statusCode:    http.StatusTeapot, // 418
			message:       "unknown error",
			expectedType:  "*errors.Unexpected",
			expectedError: "unknown error",
		},
		{
			name:          "ServiceUnavailable returns Unexpected error",
			statusCode:    http.StatusServiceUnavailable,
			message:       "service unavailable",
			expectedType:  "*errors.Unexpected",
			expectedError: "service unavailable",
		},
		{
			name:          "Empty message",
			statusCode:    http.StatusBadRequest,
			message:       "",
			expectedType:  "*errors.Validation",
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrorFromStatusCode(tt.statusCode, tt.message)

			// Check that error is not nil
			if err == nil {
				t.Fatal("expected error to be non-nil")
			}

			// Check error message
			if err.Error() != tt.expectedError {
				t.Errorf("expected error message %q, got %q", tt.expectedError, err.Error())
			}

			// Check error type using type assertions
			switch tt.expectedType {
			case "*errors.Validation":
				if _, ok := err.(errors.Validation); !ok {
					t.Errorf("expected error type %s, got %T", tt.expectedType, err)
				}
			case "*errors.Unauthorized":
				if _, ok := err.(errors.Unauthorized); !ok {
					t.Errorf("expected error type %s, got %T", tt.expectedType, err)
				}
			case "*errors.Forbidden":
				if _, ok := err.(errors.Forbidden); !ok {
					t.Errorf("expected error type %s, got %T", tt.expectedType, err)
				}
			case "*errors.NotFound":
				if _, ok := err.(errors.NotFound); !ok {
					t.Errorf("expected error type %s, got %T", tt.expectedType, err)
				}
			case "*errors.Unexpected":
				if _, ok := err.(errors.Unexpected); !ok {
					t.Errorf("expected error type %s, got %T", tt.expectedType, err)
				}
			default:
				t.Errorf("unknown expected type: %s", tt.expectedType)
			}
		})
	}
}

func TestErrorFromStatusCode_AllHTTPStatusCodes(t *testing.T) {
	// Test a broader range of status codes to ensure they all return some error
	statusCodes := []int{
		100, 200, 201, 204, 300, 301, 302, 400, 401, 403, 404, 405, 409, 422, 429, 500, 501, 502, 503, 504,
	}

	for _, code := range statusCodes {
		t.Run(http.StatusText(code), func(t *testing.T) {
			err := ErrorFromStatusCode(code, "test message")
			if err == nil {
				t.Errorf("expected error for status code %d, got nil", code)
			}
			if err.Error() != "test message" {
				t.Errorf("expected error message 'test message', got %q", err.Error())
			}
		})
	}
}

func TestErrorFromStatusCode_SpecificMappings(t *testing.T) {
	// Test specific mappings to ensure correct error types
	mappings := map[int]interface{}{
		http.StatusBadRequest:          errors.Validation{},
		http.StatusUnauthorized:        errors.Unauthorized{},
		http.StatusForbidden:           errors.Forbidden{},
		http.StatusNotFound:            errors.NotFound{},
		http.StatusInternalServerError: errors.Unexpected{},
	}

	for statusCode, expectedErrorType := range mappings {
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			err := ErrorFromStatusCode(statusCode, "test")

			switch expectedErrorType.(type) {
			case errors.Validation:
				if _, ok := err.(errors.Validation); !ok {
					t.Errorf("expected Validation error for status %d, got %T", statusCode, err)
				}
			case errors.Unauthorized:
				if _, ok := err.(errors.Unauthorized); !ok {
					t.Errorf("expected Unauthorized error for status %d, got %T", statusCode, err)
				}
			case errors.Forbidden:
				if _, ok := err.(errors.Forbidden); !ok {
					t.Errorf("expected Forbidden error for status %d, got %T", statusCode, err)
				}
			case errors.NotFound:
				if _, ok := err.(errors.NotFound); !ok {
					t.Errorf("expected NotFound error for status %d, got %T", statusCode, err)
				}
			case errors.Unexpected:
				if _, ok := err.(errors.Unexpected); !ok {
					t.Errorf("expected Unexpected error for status %d, got %T", statusCode, err)
				}
			}
		})
	}
}
