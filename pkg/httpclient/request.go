// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package httpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
)

// Caller defines the behavior of a request caller
type Caller interface {
	Call(ctx context.Context, resp any) (int, error)
}

// RequestOption defines a functional option for configuring APIRequest
type RequestOption func(*apiRequest)

type apiRequest struct {
	httpClient  *Client
	Method      string
	URL         string // Full URL for non-user-specific endpoints (overrides Endpoint if provided)
	Body        any
	Token       string
	Description string
}

// WithMethod sets the HTTP method for the request
func WithMethod(method string) RequestOption {
	return func(req *apiRequest) {
		req.Method = method
	}
}

// WithURL sets the full URL for the request (overrides endpoint)
func WithURL(url string) RequestOption {
	return func(req *apiRequest) {
		req.URL = url
	}
}

// WithBody sets the request body
func WithBody(body any) RequestOption {
	return func(req *apiRequest) {
		req.Body = body
	}
}

// WithToken sets the authentication token
func WithToken(token string) RequestOption {
	return func(req *apiRequest) {
		req.Token = token
	}
}

// WithDescription sets a description for the request (used in logging)
func WithDescription(description string) RequestOption {
	return func(req *apiRequest) {
		req.Description = description
	}
}

// Call makes an HTTP call with a configured data
func (a *apiRequest) Call(ctx context.Context, resp any) (int, error) {
	if a.Token == "" {
		return -1, errors.NewValidation("no authentication token available (neither user token nor M2M token)")
	}

	if a.URL == "" {
		return -1, errors.NewValidation("URL is required")
	}

	if strings.TrimSpace(a.Method) == "" {
		return -1, errors.NewValidation("HTTP method is required")
	}

	var (
		requestBody []byte
		err         error
	)

	// Prepare the request body if provided
	if a.Body != nil {
		requestBody, err = json.Marshal(a.Body)
		if err != nil {
			return -1, fmt.Errorf("failed to marshal request body: %w", err)
		}
	}

	slog.DebugContext(ctx, "calling API",
		"method", a.Method,
		"url", a.URL,
		"request_body", string(requestBody))

	// Prepare headers (normalize Authorization token)
	authHeader := strings.TrimSpace(a.Token)
	lower := strings.ToLower(authHeader)
	if !strings.HasPrefix(lower, "bearer ") {
		authHeader = "Bearer " + authHeader
	}
	headers := map[string]string{
		"Authorization": authHeader,
		"Accept":        "application/json",
	}

	// Add Content-Type for requests with body
	if a.Body != nil {
		headers["Content-Type"] = "application/json"
	}

	var bodyReader io.Reader
	if requestBody != nil {
		bodyReader = bytes.NewReader(requestBody)
	}

	// Make the HTTP request
	response, err := a.httpClient.Request(ctx, a.Method, a.URL, bodyReader, headers)
	if err != nil {
		slog.ErrorContext(ctx, "API request failed",
			"error", err,
			"method", a.Method,
			"description", a.Description)
		if re, ok := err.(*RetryableError); ok {
			return re.StatusCode, err
		}
		return -1, errors.NewUnexpected("API request failed", err)
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		slog.ErrorContext(ctx, "API returned error",
			"status_code", response.StatusCode,
			"response_body", string(response.Body),
			"method", a.Method,
			"description", a.Description)
		return response.StatusCode, errors.NewUnexpected("API returned error", fmt.Errorf("status code: %d", response.StatusCode))
	}

	// If caller doesn't need the body or there's no content, skip JSON decoding.
	if resp == nil || len(response.Body) == 0 {
		slog.DebugContext(ctx, "API call successful",
			"method", a.Method,
			"status_code", response.StatusCode,
			"description", a.Description,
			"empty_body", len(response.Body) == 0)
		return response.StatusCode, nil
	}

	if err := json.Unmarshal(response.Body, resp); err != nil {
		slog.ErrorContext(ctx, "failed to parse API response", "error", err)
		return -1, errors.NewUnexpected("failed to parse API response", err)
	}

	slog.DebugContext(ctx, "API call successful",
		"method", a.Method,
		"status_code", response.StatusCode,
		"description", a.Description)

	return response.StatusCode, nil
}

// NewAPIRequest creates a new APIRequest with the provided options
func NewAPIRequest(httpClient *Client, options ...RequestOption) Caller {
	req := &apiRequest{
		httpClient: httpClient,
	}

	for _, option := range options {
		option(req)
	}

	return req
}
