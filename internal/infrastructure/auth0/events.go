// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	errs "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// ErrOffsetExpired reports a 410: the offset is no longer in the stream and
// the caller must restart from a timestamp.
var ErrOffsetExpired = errors.New("auth0 events offset has expired")

// Stream-level event types, alongside the Auth0 event types such as
// "user.created" that a subscription actually asks for.
const (
	// EventTypeOffsetOnly is a position marker carrying no event payload. The
	// offset still advances, so the caller must record it like any other.
	EventTypeOffsetOnly = "offset-only"

	// EventTypeError is terminal: Auth0 closes the stream after sending it.
	EventTypeError = "error"

	// eventTypeDefault is the SSE spec's type for a frame with no `event:`
	// field. Auth0 names every frame it sends, so a message arriving under this
	// type means the stream carried something undocumented and the caller
	// should ignore it rather than guess.
	eventTypeDefault = "message"
)

// defaultConnectTimeout bounds establishing the stream, never the stream itself.
const defaultConnectTimeout = 10 * time.Second

// maxEventLineBytes caps one SSE line. bufio.Scanner defaults to 64KiB, which a
// user event carrying a large `app_metadata` can exceed; a bufio.Reader would
// grow without any ceiling at all, so the limit is raised and kept explicit.
const maxEventLineBytes = 1 << 20

// EventMessage is one message read from the Auth0 events stream.
type EventMessage struct {
	// Offset is the SSE `id`, an opaque cursor. The SSE spec keeps the last id
	// across frames, so a frame that omits one reports the most recent id seen
	// — the cursor has not moved.
	Offset string
	// Type is the SSE `event` name: an event type such as "user.created",
	// or "offset-only", or "error".
	Type string
	// Data is the raw `data:` payload, undecoded. It carries the Auth0 user
	// record, so it is never logged here and must not be logged by the caller.
	Data []byte
}

// SubscribeOptions selects where the stream starts and what it carries.
//
// Leaving both From and FromTimestamp unset starts the stream at the *latest*
// events, not the earliest, so a caller resuming after downtime must supply one
// or it will silently skip everything it missed.
type SubscribeOptions struct {
	// From resumes after this offset. Takes precedence over FromTimestamp.
	From string
	// FromTimestamp starts the stream at a point in time. Used when From is empty.
	FromTimestamp time.Time
	// EventTypes filters the stream. Empty means every type.
	EventTypes []string
}

// EventsClient reads the Auth0 events stream.
//
// One Subscribe call is one connection. This client does not reconnect, does
// not persist offsets and does not back off: it opens the stream, calls handle
// for every message in order, and returns when the context is cancelled, the
// server closes the connection, handle fails, or a terminal error event
// arrives. Reconnection, offset persistence and backoff belong to the caller
// and live elsewhere — do not add them here.
type EventsClient interface {
	Subscribe(ctx context.Context, opts SubscribeOptions, handle func(context.Context, EventMessage) error) error
}

// RateLimitedError reports a 429 along with the server's Retry-After hint.
// The caller owns reconnection, so the wait is reported rather than taken here.
type RateLimitedError struct {
	// RetryAfter is the server's hint, or zero when the header was absent,
	// unparseable, or already in the past.
	RetryAfter time.Duration
}

// Error returns the error message for RateLimitedError.
func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("auth0 events stream is rate limited, retry after %s", e.RetryAfter)
}

// EventsConfig tunes the stream connection. It stands in for httpclient.Config,
// which does not fit: the shared client buffers the whole response body into
// memory before returning and retries on its own, neither of which a response
// that stays open for minutes survives.
type EventsConfig struct {
	// ConnectTimeout bounds dialling, the TLS handshake and the wait for
	// response headers. It deliberately does not bound the stream itself.
	ConnectTimeout time.Duration

	// Transport is a test seam. Nil builds a transport tuned for a long-lived
	// stream.
	Transport http.RoundTripper
}

// eventsClient reads one Auth0 events stream connection at a time.
type eventsClient struct {
	httpClient *http.Client
	config     Config
}

// NewEventsClient creates the reader for the Auth0 events stream.
//
// Auth0 caps concurrent event-stream connections per tenant by plan tier —
// documented as Free 1 / Self-service 4 / Enterprise 8 — and answers 403 once
// the cap is reached. Our tier is UNCONFIRMED, so the service runs exactly one
// reader. REVIEWER: please confirm the tenant's tier before a second is added.
func NewEventsClient(streamConfig EventsConfig, auth0Config Config) (EventsClient, error) {
	if auth0Config.M2MTokenManager == nil {
		return nil, errs.NewUnexpected("M2M token manager is required")
	}
	if strings.TrimSpace(auth0Config.Domain) == "" {
		return nil, errs.NewUnexpected("Auth0 domain is required")
	}

	connectTimeout := streamConfig.ConnectTimeout
	if connectTimeout == 0 {
		connectTimeout = defaultConnectTimeout
	}

	transport := streamConfig.Transport
	if transport == nil {
		transport = &http.Transport{
			DialContext:           (&net.Dialer{Timeout: connectTimeout}).DialContext,
			TLSHandshakeTimeout:   connectTimeout,
			ResponseHeaderTimeout: connectTimeout,
		}
	}

	return &eventsClient{
		// http.Client.Timeout is deliberately absent. It bounds reading the
		// entire body, so on a stream Auth0 holds open for minutes it would
		// sever healthy connections on a fixed schedule. Getting connected is
		// bounded on the transport above; the stream itself is bounded by the
		// caller's context. Do not add a Timeout here.
		httpClient: &http.Client{Transport: otelhttp.NewTransport(transport)},
		config:     auth0Config,
	}, nil
}

// Subscribe opens the events stream and delivers every message to handle.
func (c *eventsClient) Subscribe(ctx context.Context, opts SubscribeOptions, handle func(context.Context, EventMessage) error) error {
	if handle == nil {
		return errs.NewValidation("a message handler is required to subscribe to the events stream")
	}

	token, err := c.config.M2MTokenManager.GetToken(ctx)
	if err != nil {
		return errs.NewUnexpected("failed to get M2M token to read the events stream", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.streamURL(opts), nil)
	if err != nil {
		return errs.NewUnexpected("failed to build the events stream request", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "text/event-stream")

	response, err := c.httpClient.Do(request)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return errs.NewUnexpected("failed to open the events stream", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return statusError(response)
	}

	slog.InfoContext(ctx, "auth0 events stream established",
		"from", opts.From,
		"from_timestamp", formatFromTimestamp(opts.FromTimestamp),
		"event_types", opts.EventTypes,
	)

	return readStream(ctx, response.Body, handle)
}

// streamURL builds the events endpoint for the requested starting point.
//
// The offset travels as the `from` query parameter and never as a
// Last-Event-ID header. Auth0 accepts both and lets the header win, so using
// one keeps that precedence rule out of play, and the query parameter is the
// one that sits next to the `from_timestamp` it is mutually exclusive with.
func (c *eventsClient) streamURL(opts SubscribeOptions) string {
	query := url.Values{}
	switch {
	case strings.TrimSpace(opts.From) != "":
		query.Set("from", opts.From)
	case !opts.FromTimestamp.IsZero():
		query.Set("from_timestamp", formatFromTimestamp(opts.FromTimestamp))
	}
	for _, eventType := range opts.EventTypes {
		if trimmed := strings.TrimSpace(eventType); trimmed != "" {
			query.Add("event_type", trimmed)
		}
	}

	endpoint := fmt.Sprintf("https://%s/api/v2/events", c.config.Domain)
	if encoded := query.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	return endpoint
}

// formatFromTimestamp renders a starting timestamp, or an empty string when
// none was requested.
func formatFromTimestamp(from time.Time) string {
	if from.IsZero() {
		return ""
	}
	return from.UTC().Format(time.RFC3339)
}

// statusError maps a non-200 response onto an error the caller can branch on.
//
// The response body is left unread: Auth0 does not contract its error bodies to
// be free of user data, and nothing in this package puts a payload in an error.
func statusError(response *http.Response) error {
	switch response.StatusCode {
	case http.StatusBadRequest:
		return errs.NewValidation("auth0 rejected the events subscription: malformed offset or unsupported event type")
	case http.StatusUnauthorized:
		return errs.NewUnauthorized("auth0 rejected the events stream token")
	case http.StatusForbidden:
		// Auth0 answers 403 for two unrelated causes and the body does not
		// separate them reliably, so both are named for whoever reads the log.
		return errs.NewForbidden("auth0 refused the events stream: the token is missing the read:events scope, " +
			"or the maximum concurrent event stream connections for the tenant has been reached")
	case http.StatusGone:
		return ErrOffsetExpired
	case http.StatusTooManyRequests:
		return &RateLimitedError{RetryAfter: retryAfter(response.Header)}
	}
	return errs.NewUnexpected(fmt.Sprintf("auth0 events stream failed with status code: %d", response.StatusCode))
}

// retryAfter reads Retry-After, which is either delta-seconds or an HTTP-date.
func retryAfter(header http.Header) time.Duration {
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

// readStream parses SSE frames off the open connection until it ends.
func readStream(ctx context.Context, body io.Reader, handle func(context.Context, EventMessage) error) error {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, bufio.MaxScanTokenSize), maxEventLineBytes)

	var (
		eventType  string
		data       []byte
		hasData    bool
		lastOffset string
	)

	for scanner.Scan() {
		line := scanner.Text()

		// `:connected` and `: heartbeat` are comments. They keep the connection
		// warm and are not frame boundaries, so they neither dispatch nor
		// discard whatever the current frame has accumulated.
		if strings.HasPrefix(line, ":") {
			continue
		}

		if line != "" {
			field, value := splitSSEField(line)
			switch field {
			case "event":
				eventType = value
			case "data":
				if hasData {
					data = append(data, '\n')
				}
				data = append(data, value...)
				hasData = true
			case "id":
				lastOffset = value
			case "retry":
				// Reconnection is the caller's job, so the server's hint is
				// recorded rather than acted on.
				slog.DebugContext(ctx, "auth0 events stream sent a reconnection hint", "retry_ms", value)
			}
			continue
		}

		// A blank line ends the frame. One carrying no `data:` at all is not an
		// event under the SSE spec, even when it moved the offset.
		if !hasData {
			eventType = ""
			continue
		}

		message := EventMessage{Offset: lastOffset, Type: eventType, Data: data}
		if message.Type == "" {
			message.Type = eventTypeDefault
		}
		eventType, data, hasData = "", nil, false

		if err := handle(ctx, message); err != nil {
			return err
		}

		if message.Type == EventTypeError {
			slog.ErrorContext(ctx, "auth0 ended the events stream with a terminal error event",
				"offset", message.Offset,
			)
			return errs.NewUnexpected("auth0 events stream ended with a terminal error event")
		}
	}

	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err := scanner.Err(); err != nil {
		return errs.NewUnexpected("failed to read the events stream", err)
	}

	// Auth0 recycles stream connections every few minutes to rebalance load, so
	// a clean close is the ordinary end of a healthy subscription.
	slog.InfoContext(ctx, "auth0 closed the events stream", "last_offset", lastOffset)
	return nil
}

// splitSSEField splits an SSE line into its field name and value, dropping the
// single optional space after the colon. A line with no colon is a field name
// with an empty value.
func splitSSEField(line string) (string, string) {
	field, value, found := strings.Cut(line, ":")
	if !found {
		return field, ""
	}
	return field, strings.TrimPrefix(value, " ")
}
