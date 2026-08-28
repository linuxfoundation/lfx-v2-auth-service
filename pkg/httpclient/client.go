// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package httpclient

import (
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// Client represents a generic HTTP client with retry logic
type Client struct {
	config     Config
	httpClient *http.Client
}

// Request represents an HTTP request configuration
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    io.Reader
}

// Response represents an HTTP response
type Response struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

// RetryableError represents an error that can be retried
type RetryableError struct {
	StatusCode int
	// RawBody is the unsanitized upstream response body. It can echo submitted
	// field values or identifiers, so it is deliberately kept out of Error() and
	// must never be logged directly — parse it, or log StatusCode instead.
	RawBody string
	// Headers are the upstream response headers. Unlike RawBody they carry no
	// submitted values, and a 429 answer is only actionable with the
	// Retry-After among them.
	Headers http.Header
}

func (e *RetryableError) Error() string {
	return fmt.Sprintf("upstream returned status %d", e.StatusCode)
}

// ResponseBody returns the unsanitized upstream response body carried by err, or
// "" if err is not a *RetryableError. It exists so callers can PARSE a provider
// error payload (e.g. Auth0's "message"/"error" fields); the result is
// unsanitized and must never be logged or returned to a caller verbatim.
func ResponseBody(err error) string {
	var retryable *RetryableError
	if !stderrors.As(err, &retryable) {
		return ""
	}
	return retryable.RawBody
}

// RetryAfter returns the wait an upstream asked for in the response that
// produced err, or 0 when err carries no response or no usable hint.
func RetryAfter(err error) time.Duration {
	var retryable *RetryableError
	if !stderrors.As(err, &retryable) {
		return 0
	}
	return ParseRetryAfter(retryable.Headers)
}

// ParseRetryAfter reads Retry-After, which is either delta-seconds or an
// HTTP-date. It returns 0 when the header is absent, unparseable, or already in
// the past, so a caller can treat 0 as "the server named no wait" and fall back
// to its own backoff rather than retrying at once.
func ParseRetryAfter(header http.Header) time.Duration {
	raw := strings.TrimSpace(header.Get("Retry-After"))
	if raw == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(raw); err == nil {
		if seconds <= 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	if deadline, err := http.ParseTime(raw); err == nil {
		if wait := time.Until(deadline); wait > 0 {
			return wait
		}
	}
	return 0
}

// Do executes an HTTP request with retry logic
func (c *Client) Do(ctx context.Context, req Request) (*Response, error) {
	var lastErr error

	for attempt := 0; attempt <= c.config.MaxRetries; attempt++ {
		if attempt > 0 {
			// Calculate delay with optional exponential backoff
			delay := c.config.RetryDelay
			if c.config.RetryBackoff {
				delay = time.Duration(int64(delay) * int64(1<<(attempt-1)))
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		response, err := c.doRequest(ctx, req)
		if err == nil {
			return response, nil
		}

		lastErr = err

		// Don't retry on certain errors
		if !c.shouldRetry(err) {
			break
		}
	}

	if lastErr != nil {
		if re, ok := lastErr.(*RetryableError); ok {
			if re.StatusCode < http.StatusInternalServerError {
				slog.DebugContext(ctx, "HTTP request completed with client status",
					"status_code", re.StatusCode,
					"method", req.Method,
				)
			} else {
				slog.ErrorContext(ctx, "HTTP request failed with server error",
					"status_code", re.StatusCode,
					"method", req.Method,
				)
			}
		} else {
			slog.ErrorContext(ctx, "HTTP request failed",
				"error", SanitizeError(lastErr),
				"method", req.Method,
			)
		}
	}

	return nil, lastErr
}

// doRequest performs a single HTTP request
func (c *Client) doRequest(ctx context.Context, reqConfig Request) (*Response, error) {
	httpReq, err := http.NewRequestWithContext(ctx, reqConfig.Method, reqConfig.URL, reqConfig.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set default headers
	httpReq.Header.Set("Accept", "application/json")

	// Set custom headers
	for key, value := range reqConfig.Headers {
		httpReq.Header.Set(key, value)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	response := &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
	}

	// Check for HTTP errors
	if resp.StatusCode >= http.StatusBadRequest {
		err := &RetryableError{
			StatusCode: resp.StatusCode,
			RawBody:    string(body),
			Headers:    resp.Header,
		}
		return response, err
	}

	return response, nil
}

// shouldRetry determines if a request should be retried based on the error
func (c *Client) shouldRetry(err error) bool {
	if err == nil {
		return false
	}

	// Check if it's a retryable error
	if retryableErr, ok := err.(*RetryableError); ok {
		// Retry on server errors and rate limiting
		return retryableErr.StatusCode >= http.StatusInternalServerError || retryableErr.StatusCode == http.StatusTooManyRequests
	}

	// Retry on network-related errors
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "connection") ||
		strings.Contains(errStr, "network")
}

// Request performs an HTTP request with the specified verb
func (c *Client) Request(ctx context.Context, verb, url string, body io.Reader, headers map[string]string) (*Response, error) {
	req := Request{
		Method:  verb,
		URL:     url,
		Headers: headers,
		Body:    body,
	}
	return c.Do(ctx, req)
}

// NewClient creates a new HTTP client with the given configuration.
// The client is instrumented with OpenTelemetry for distributed tracing.
func NewClient(config Config) *Client {
	base := config.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	return &Client{
		config: config,
		httpClient: &http.Client{
			Timeout:   config.Timeout,
			Transport: otelhttp.NewTransport(base),
		},
	}
}
