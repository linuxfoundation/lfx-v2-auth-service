// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package httpclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
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

	// SensitiveResponse keeps an error response body out of the error and out
	// of the logs. Some providers echo the submitted identity back in their
	// error bodies, and this client would otherwise print it in full.
	SensitiveResponse bool
}

// redactedBody stands in for a body that must not reach the logs.
const redactedBody = "[REDACTED]"

// Response represents an HTTP response
type Response struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

// RetryableError represents an error that can be retried
type RetryableError struct {
	StatusCode int
	Message    string

	// Body is the raw response body, kept separate from Message so a caller
	// can parse a structured error while Message stays redacted for logging.
	// Never log this directly.
	Body []byte
}

func (e *RetryableError) Error() string {
	return e.Message
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

	slog.ErrorContext(ctx, "request failed", "error", lastErr)

	return nil, lastErr
}

// scrubURLError strips the path and query from a *url.Error.
//
// url.Error.Error() renders the whole URL, and net/http only removes userinfo
// from it. Our paths carry an Auth0 sub or a CDP member id, so the rendered
// error is a PII sink — one that fires on any transport failure, at ERROR
// level, and then travels up the stack into every caller that logs it. Scheme
// and host are kept because they identify the provider without identifying a
// person.
func scrubURLError(err error) error {
	var urlErr *url.Error
	if !errors.As(err, &urlErr) {
		return err
	}

	scrubbed := *urlErr
	if parsed, parseErr := url.Parse(urlErr.URL); parseErr == nil {
		scrubbed.URL = parsed.Scheme + "://" + parsed.Host
	} else {
		scrubbed.URL = "[REDACTED]"
	}
	return &scrubbed
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
		return nil, fmt.Errorf("HTTP request failed: %w", scrubURLError(err))
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
		message := string(body)
		if reqConfig.SensitiveResponse {
			message = redactedBody
		}
		err := &RetryableError{
			StatusCode: resp.StatusCode,
			Message:    message,
			Body:       body,
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
