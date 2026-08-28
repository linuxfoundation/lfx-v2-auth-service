// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package httpclient

import (
	"bytes"
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

// Caller defines the behavior of a request caller
type Caller interface {
	Call(ctx context.Context, resp any) (int, error)
}

// RequestOption defines a functional option for configuring APIRequest
type RequestOption func(*apiRequest)

type apiRequest struct {
	httpClient    *Client
	Method        string
	URL           string // Full URL for non-user-specific endpoints (overrides Endpoint if provided)
	Body          any
	Token         string
	Description   string
	sensitiveBody bool // when true, the request body is replaced with [REDACTED] in logs
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

// WithSensitiveBody marks the request body as sensitive so it is replaced
// with [REDACTED] in debug logs instead of being printed in full.
// Use this for endpoints that carry passwords, client secrets, or other credentials.
func WithSensitiveBody() RequestOption {
	return func(req *apiRequest) {
		req.sensitiveBody = true
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

	// Gated: sanitizeURL and RedactJWTs both parse/rewrite their input, and slog
	// evaluates arguments eagerly, so this would run on every call with Debug off.
	if slog.Default().Enabled(ctx, slog.LevelDebug) {
		loggedBody := redaction.RedactJWTs(string(requestBody))
		if a.sensitiveBody {
			loggedBody = "[REDACTED]"
		}
		slog.DebugContext(ctx, "calling API",
			"method", a.Method,
			"url", sanitizeURL(a.URL),
			"request_body", loggedBody)
	}

	// Prepare headers; only add Authorization when a token is provided
	headers := map[string]string{
		"Accept": "application/json",
	}
	if authHeader := strings.TrimSpace(a.Token); authHeader != "" {
		if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			authHeader = "Bearer " + authHeader
		}
		headers["Authorization"] = authHeader
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
		if re, ok := err.(*RetryableError); ok {
			if re.StatusCode < http.StatusInternalServerError {
				slog.DebugContext(ctx, "API returned client status",
					"status_code", re.StatusCode,
					"method", a.Method,
					"description", a.Description)
			} else {
				slog.ErrorContext(ctx, "API returned server error",
					"status_code", re.StatusCode,
					"method", a.Method,
					"description", a.Description)
			}
			return re.StatusCode, err
		}
		slog.ErrorContext(ctx, "API request failed",
			"error", SanitizeError(err),
			"method", a.Method,
			"description", a.Description)
		return -1, errors.NewUnexpected("API request failed", SanitizedError(err))
	}

	// doRequest only converts statuses >= 400 into errors, so a 1xx/3xx response
	// would otherwise be reported as a successful call.
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		slog.ErrorContext(ctx, "API returned unexpected status",
			"status_code", response.StatusCode,
			"method", a.Method,
			"description", a.Description)
		return response.StatusCode, errors.NewUnexpected("API returned unexpected status",
			fmt.Errorf("status code: %d", response.StatusCode))
	}

	// If caller doesn't need the body or there's no content, skip JSON decoding.
	if resp == nil || len(response.Body) == 0 {
		slog.DebugContext(ctx, "API call successful",
			"method", a.Method,
			"status_code", response.StatusCode,
			"description", a.Description)
		return response.StatusCode, nil
	}

	if err := json.Unmarshal(response.Body, resp); err != nil {
		slog.ErrorContext(ctx, "failed to parse API response", "error", SanitizeError(err))
		return -1, errors.NewUnexpected("failed to parse API response", SanitizedError(err))
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

// sanitizeURL redacts sensitive path segments and query parameters from outbound request URLs
func sanitizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "[REDACTED_URL]"
	}

	// Opaque URLs (e.g. "https:victim@example.com") carry their payload outside
	// Path/Query/User, so none of the passes below would touch it.
	if u.Opaque != "" {
		return "[REDACTED_URL]"
	}

	// Userinfo credentials and fragments are never useful in a log line and can
	// carry secrets (credentials before the "@" host separator, tokens after "#").
	u.User = nil
	u.Fragment = ""
	u.RawFragment = ""

	// Sanitize path segments (e.g. /api/v2/users/{user_id}, /api/v2/users/{id}/identities/{provider}/{secondary_user_id}, or embedded emails)
	// Split on the escaped path so an encoded separator (%2F) stays inside its
	// own logical segment and is redacted as one identifier.
	if escapedPath := u.EscapedPath(); escapedPath != "" {
		escaped := strings.Split(escapedPath, "/")
		segments := make([]string, len(escaped))
		for i, seg := range escaped {
			decoded, errUnescape := url.PathUnescape(seg)
			if errUnescape != nil {
				decoded = seg
			}
			segments[i] = decoded
		}
		for i, seg := range segments {
			if seg == "" {
				continue
			}
			switch {
			case i > 0 && segments[i-1] == "users" && !strings.HasPrefix(seg, "by-"):
				segments[i] = redaction.Redact(seg)
			case i >= 2 && segments[i-2] == "identities":
				segments[i] = redaction.Redact(seg)
			case strings.Contains(seg, "@"):
				segments[i] = redaction.RedactEmail(seg)
			}
		}
		// Clear RawPath so String() re-escapes the redacted path from scratch.
		u.RawPath = ""
		u.Path = strings.Join(segments, "/")
	}

	// Sanitize query parameters
	if u.RawQuery != "" {
		q, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return "[REDACTED_URL]"
		}
		for k, vals := range q {
			lowerK := strings.ToLower(k)
			for i, v := range vals {
				switch {
				case isSensitiveQueryKey(lowerK):
					vals[i] = "[REDACTED]"
				case strings.Contains(lowerK, "email"):
					vals[i] = redaction.RedactEmail(v)
				case lowerK == "q":
					vals[i] = sanitizeLuceneQuery(v)
				case strings.Contains(lowerK, "user") || strings.Contains(lowerK, "sub") || lowerK == "id":
					vals[i] = redaction.Redact(v)
				}
			}
			q[k] = vals
		}
		u.RawQuery = q.Encode()
	}

	return u.String()
}

// sensitiveQueryKeySubstrings are credential-bearing query parameter names whose
// values are replaced wholesale, since no partial form of a secret is safe to log.
var sensitiveQueryKeySubstrings = []string{
	"token", "secret", "password", "passwd", "credential", "assertion", "code_verifier", "signature", "api_key", "apikey", "auth",
}

// isSensitiveQueryKey reports whether a lowercased query key names a credential.
func isSensitiveQueryKey(lowerKey string) bool {
	for _, needle := range sensitiveQueryKeySubstrings {
		if strings.Contains(lowerKey, needle) {
			return true
		}
	}
	return false
}

// sanitizeLuceneQuery redacts field values in search expressions (e.g. identities.user_id:123 or email:foo@example.com)
func sanitizeLuceneQuery(query string) string {
	if strings.ContainsAny(query, `()\"`) {
		return "[REDACTED]"
	}

	parts := strings.Split(query, " ")
	for i, part := range parts {
		colonIdx := strings.Index(part, ":")
		if colonIdx == -1 {
			if strings.Contains(part, "@") {
				parts[i] = redaction.RedactEmail(part)
			}
			continue
		}
		field := part[:colonIdx]
		val := strings.Trim(part[colonIdx+1:], `"`)
		if strings.Contains(strings.ToLower(field), "email") {
			parts[i] = field + ":" + redaction.RedactEmail(val)
		} else {
			parts[i] = field + ":" + redaction.Redact(val)
		}
	}
	return strings.Join(parts, " ")
}

// SanitizeError redacts raw URLs, email addresses, and sensitive tokens from error
// representations before logging. Use it on any upstream error before logging it or
// wrapping it into an error that callers may log.
func SanitizeError(err error) string {
	if err == nil {
		return ""
	}
	errStr := err.Error()

	// Strip JWTs first: a bearer token in the message would otherwise survive the
	// URL and email passes, neither of which recognizes token shapes.
	errStr = redaction.RedactJWTs(errStr)

	// Sanitize a wrapped *url.Error through its URL field. The passes below key off
	// an "http(s)://" prefix or an "@", so a malformed URL such as
	// "://bad/api/v2/users/auth0|123" would otherwise survive with its identifier intact.
	var urlErr *url.Error
	if stderrors.As(err, &urlErr) && urlErr.URL != "" {
		errStr = strings.ReplaceAll(errStr, urlErr.URL, sanitizeURL(urlErr.URL))
	}

	// Redact embedded URLs in error messages
	for _, scheme := range []string{"http://", "https://"} {
		for searchStart := 0; ; {
			offset := strings.Index(errStr[searchStart:], scheme)
			if offset == -1 {
				break
			}
			start := searchStart + offset
			// Find end of URL (delimiters: space, quote, backslash, newline)
			end := len(errStr)
			for i := start; i < len(errStr); i++ {
				if errStr[i] == '"' || errStr[i] == '\'' || errStr[i] == ' ' || errStr[i] == '\\' || errStr[i] == '\n' {
					end = i
					break
				}
			}
			rawURL := errStr[start:end]
			sanitized := sanitizeURL(rawURL)
			errStr = errStr[:start] + sanitized + errStr[end:]
			searchStart = start + len(sanitized)
		}
	}

	// Redact standalone email tokens in the error message
	parts := strings.Split(errStr, " ")
	for i, part := range parts {
		if strings.Contains(part, "@") {
			parts[i] = redaction.RedactEmail(part)
		}
	}
	return strings.Join(parts, " ")
}

// sanitizedError carries only the sanitized text in Error(), while still
// unwrapping to the original cause so errors.Is/As can identify it (e.g.
// context.Canceled) without any caller being able to log the raw message.
type sanitizedError struct {
	sanitized string
	cause     error
}

func (e *sanitizedError) Error() string { return e.sanitized }
func (e *sanitizedError) Unwrap() error { return e.cause }

// SanitizedError returns an error carrying only the sanitized representation of err,
// so wrapping it cannot re-expose the raw content to callers that log the wrapper.
func SanitizedError(err error) error {
	if err == nil {
		return nil
	}
	return &sanitizedError{sanitized: SanitizeError(err), cause: err}
}
