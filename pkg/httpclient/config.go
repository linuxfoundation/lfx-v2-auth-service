// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package httpclient

import (
	"net/http"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// Config holds the configuration for the HTTP client
type Config struct {
	// Timeout is the HTTP client timeout for requests
	Timeout time.Duration

	// MaxRetries is the maximum number of retry attempts for failed requests
	MaxRetries int

	// RetryDelay is the delay between retry attempts
	RetryDelay time.Duration

	// RetryBackoff enables exponential backoff for retries
	RetryBackoff bool

	// Transport overrides the base http.RoundTripper used by the client.
	// When nil, http.DefaultTransport is used. This is primarily a test seam:
	// it lets callers intercept requests without a live network or matching
	// the request scheme/host.
	Transport http.RoundTripper

	// OTelOptions are passed to the otelhttp transport that instruments the
	// client. Leave empty for the default instrumentation. A caller whose
	// request URLs carry personal data can add otelhttp.WithFilter to keep
	// those requests out of traces: client spans record the full URL.
	OTelOptions []otelhttp.Option
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() Config {
	return Config{
		Timeout:      30 * time.Second,
		MaxRetries:   2,
		RetryDelay:   1 * time.Second,
		RetryBackoff: true,
	}
}
