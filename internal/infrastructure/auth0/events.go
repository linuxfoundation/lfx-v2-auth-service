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
	"strings"
	"sync"
	"time"

	errs "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// Sentinels the caller branches on.
//
// These are returned BARE, never through errs.New*. The types in pkg/errors
// hold a wrapped error for their message but implement no Unwrap, so
// errs.NewUnexpected("...", ErrOffsetExpired) renders as
// "...: auth0 events offset has expired" while errors.Is against it is false.
// Routing one of these through a wrapper is therefore a silent break of the
// branch that depends on it.
var (
	// ErrOffsetExpired reports a 410: the offset is no longer in the stream
	// and the caller must restart from a timestamp.
	ErrOffsetExpired = errors.New("auth0 events offset has expired")

	// ErrStreamTerminated reports an in-band `event: error` frame. Auth0
	// documents it as terminal — an expired offset or a server-side problem —
	// and closes the stream after sending it. Only the frame's documented
	// `event:` name is read; its payload shape is not documented, so nothing
	// here parses it and no cause can be told apart from another.
	ErrStreamTerminated = errors.New("auth0 ended the events stream with a terminal error event")

	// ErrStreamIdle reports that an established stream delivered nothing for
	// longer than the configured idle timeout.
	ErrStreamIdle = errors.New("auth0 events stream went idle")
)

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

// defaultReadIdleTimeout bounds the gap between two reads on an established
// stream.
//
// Deliberately generous. Auth0 does not document its heartbeat interval, and
// this deadline resets on every byte — heartbeat comments and offset-only
// markers included — so for it to fire on a healthy stream Auth0 would have to
// go completely silent for ten minutes. Cutting a healthy stream is the exact
// mistake the absent http.Client.Timeout exists to avoid, so the bias is
// towards waiting too long rather than too little. Tighten it once the real
// heartbeat interval has been observed.
const defaultReadIdleTimeout = 10 * time.Minute

// maxEventLineBytes caps one SSE line. bufio.Scanner defaults to 64KiB, which a
// user event carrying a large `app_metadata` can exceed; a bufio.Reader would
// grow without any ceiling at all, so the limit is raised and kept explicit.
const maxEventLineBytes = 1 << 20

// maxEventFrameBytes caps the `data:` a single frame may accumulate. The
// per-line cap does not bound a frame, because a frame may carry any number of
// legal `data:` lines and is only flushed on a blank line.
const maxEventFrameBytes = 4 << 20

// maxDrainBytes bounds discarding one oversized line before the connection is
// given up on. A line with no terminator would otherwise be read forever.
const maxDrainBytes = 8 << 20

// linePrefixBytes is how much of a dropped line is kept, purely so the caller
// can still tell a comment from a field.
const linePrefixBytes = 64

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

// EventsConfig tunes the stream connection. It stands in for httpclient.Config,
// which does not fit: the shared client buffers the whole response body into
// memory before returning and retries on its own, neither of which a response
// that stays open for minutes survives.
type EventsConfig struct {
	// ConnectTimeout bounds dialling, the TLS handshake and the wait for
	// response headers. It deliberately does not bound the stream itself.
	ConnectTimeout time.Duration

	// ReadIdleTimeout bounds the wait for the NEXT byte on a stream that is
	// already established, and is reset by every byte that arrives.
	//
	// This is not the same thing as http.Client.Timeout and must not be
	// collapsed into one: that bounds reading the entire body, so on a
	// response held open for minutes it severs healthy streams on a fixed
	// schedule. A deadline between reads only fires when the stream has
	// actually stopped delivering, which the transport's timeouts cannot
	// detect — they are all spent by the time the first byte arrives.
	//
	// Zero uses defaultReadIdleTimeout.
	ReadIdleTimeout time.Duration

	// Transport is a test seam. Nil builds a transport tuned for a long-lived
	// stream.
	Transport http.RoundTripper
}

// eventsClient reads one Auth0 events stream connection at a time.
type eventsClient struct {
	httpClient      *http.Client
	config          Config
	readIdleTimeout time.Duration
}

// NewEventsClient creates the reader for the Auth0 events stream.
//
// Auth0 caps concurrent event-stream connections per tenant by plan tier and
// answers 403 once the cap is reached. The tenant is on Enterprise, so the cap
// is 8 (confirmed 2026-08-27). The service still runs one reader, because the
// stream fans out and a second would duplicate work rather than share it — but
// the cap is no longer the reason, and the two connections a lease handover
// briefly holds are comfortably within it.
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

	readIdleTimeout := streamConfig.ReadIdleTimeout
	if readIdleTimeout == 0 {
		readIdleTimeout = defaultReadIdleTimeout
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
		// caller's context and by readIdleTimeout, which is a deadline between
		// reads rather than over the whole body. Do not add a Timeout here.
		httpClient:      &http.Client{Transport: otelhttp.NewTransport(transport)},
		config:          auth0Config,
		readIdleTimeout: readIdleTimeout,
	}, nil
}

// Subscribe opens the events stream and delivers every message to handle.
func (c *eventsClient) Subscribe(ctx context.Context, opts SubscribeOptions, handle func(context.Context, EventMessage) error) error {
	if handle == nil {
		return errs.NewValidation("a message handler is required to subscribe to the events stream")
	}

	// Bounded by the token manager's own HTTP client, not from here:
	// oauth2.TokenSource.Token() takes no context, so wrapping this call in a
	// context.WithTimeout would look like a deadline while enforcing nothing.
	// See tokenFetchTimeout in token.go.
	token, err := c.config.M2MTokenManager.GetToken(ctx)
	if err != nil {
		return errs.NewUnexpected("failed to get M2M token to read the events stream", err)
	}

	// The stream runs on a context of its own so the idle deadline can tear
	// the connection down without touching the caller's.
	streamCtx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()

	request, err := http.NewRequestWithContext(streamCtx, http.MethodGet, c.streamURL(opts), nil)
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
		"read_idle_timeout", c.readIdleTimeout,
	)

	// Nothing below the transport bounds the wait for the next byte. A
	// half-open connection — no FIN, no RST, which is what a NAT or load
	// balancer idle timeout usually leaves behind — would otherwise park the
	// reader here forever while it holds the lease, so the stream would be
	// dead with no peer taking over and nothing saying so.
	reader := newIdleReader(response.Body, c.readIdleTimeout, cancelStream)
	defer reader.stop()

	err = readStream(ctx, reader, handle)

	// Disarmed before the check, so a timer firing in the gap cannot report a
	// stream that already finished as idle.
	reader.stop()

	// The idle deadline works by cancelling the stream context, so the error
	// that surfaces is a cancellation. Only this knows what it really was.
	if reader.wentIdle() && ctx.Err() == nil {
		slog.ErrorContext(ctx, "auth0 events stream delivered nothing within the idle timeout, reconnecting",
			"read_idle_timeout", c.readIdleTimeout,
		)
		return ErrStreamIdle
	}
	return err
}

// idleReader fails the stream when no byte arrives within timeout.
//
// The deadline is between reads and is reset by every one that returns data,
// so a heartbeat comment or an offset-only marker keeps it open indefinitely.
// A blocked Read cannot be interrupted directly, so expiry cancels the request
// context, which closes the connection and unblocks it.
type idleReader struct {
	reader  io.Reader
	timeout time.Duration

	mu      sync.Mutex
	timer   *time.Timer
	expired bool
}

func newIdleReader(reader io.Reader, timeout time.Duration, cancel context.CancelFunc) *idleReader {
	r := &idleReader{reader: reader, timeout: timeout}
	r.timer = time.AfterFunc(timeout, func() {
		r.mu.Lock()
		r.expired = true
		r.mu.Unlock()
		cancel()
	})
	return r
}

func (r *idleReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.mu.Lock()
		if !r.expired {
			r.timer.Reset(r.timeout)
		}
		r.mu.Unlock()
	}
	return n, err
}

// wentIdle reports whether the deadline fired.
func (r *idleReader) wentIdle() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.expired
}

func (r *idleReader) stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.timer.Stop()
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
		// Bare, like the sentinels above: the consumer tells a rate limit
		// apart from an ordinary failure with errors.As, which a wrapper
		// would defeat.
		return errs.NewRateLimited("auth0 events stream is rate limited",
			httpclient.ParseRetryAfter(response.Header))
	}
	return errs.NewUnexpected(fmt.Sprintf("auth0 events stream failed with status code: %d", response.StatusCode))
}

// readStream parses SSE frames off the open connection until it ends.
func readStream(ctx context.Context, body io.Reader, handle func(context.Context, EventMessage) error) error {
	reader := bufio.NewReader(body)

	var (
		eventType  string
		data       []byte
		hasData    bool
		hasID      bool
		lastOffset string
		oversized  bool
	)

	for {
		line, tooLong, err := readSSELine(reader, maxEventLineBytes)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			if err != io.EOF {
				return errs.NewUnexpected("failed to read the events stream", err)
			}
			// Auth0 recycles stream connections every few minutes to rebalance
			// load, so a clean close is the ordinary end of a healthy
			// subscription.
			slog.InfoContext(ctx, "auth0 closed the events stream", "last_offset", lastOffset)
			return nil
		}

		// A comment is ignored entirely under the SSE spec, so an oversized one
		// must not disturb the frame being assembled around it. `:connected`
		// and `: heartbeat` keep the connection warm and are not frame
		// boundaries — they neither dispatch nor discard what has accumulated.
		if strings.HasPrefix(line, ":") {
			continue
		}

		// An oversized field is dropped rather than failing the connection. It
		// was never delivered, so no retry can turn it into a success, and
		// killing the stream here would wedge every later event behind it with
		// no ceiling — the per-event attempt limit lives in the handler, which
		// this frame never reaches. Dropping it lets the offset move on.
		if tooLong {
			oversized = true
			slog.ErrorContext(ctx, "dropping an oversized frame from the events stream",
				"limit_bytes", maxEventLineBytes,
				"last_offset", lastOffset,
			)
			continue
		}

		if line != "" {
			field, value := splitSSEField(line)
			switch field {
			case "event":
				eventType = value
			case "data":
				// A frame is capped as well as a line: any number of legal
				// lines can otherwise accumulate into one unbounded frame.
				if len(data)+len(value) > maxEventFrameBytes {
					oversized = true
					data, hasData = nil, false
					slog.ErrorContext(ctx, "dropping an oversized frame from the events stream",
						"limit_bytes", maxEventFrameBytes,
						"last_offset", lastOffset,
					)
					continue
				}
				if hasData {
					data = append(data, '\n')
				}
				data = append(data, value...)
				hasData = true
			case "id":
				// An empty `id:` clears the last event ID under the SSE spec.
				// Auth0 offsets are opaque and there is no way to ask for the
				// position held before one, so honouring that would discard the
				// position with no way back. It is ignored instead.
				if value != "" {
					lastOffset = value
					hasID = true
				}
			case "retry":
				// Reconnection is the caller's job, so the server's hint is
				// recorded rather than acted on.
				slog.DebugContext(ctx, "auth0 events stream sent a reconnection hint", "retry_ms", value)
			}
			continue
		}

		// A frame that lost a line to a size cap is incomplete, so it is
		// discarded whole rather than dispatched with a hole in it. Its `id`
		// still counts: the offset advances past it so the next connection
		// does not replay straight back into it.
		if oversized {
			// The event name survived even though the payload did not, and a
			// terminal error stays terminal whatever its size.
			if eventType == EventTypeError {
				slog.ErrorContext(ctx, "auth0 ended the events stream with a terminal error event",
					"offset", lastOffset,
				)
				return ErrStreamTerminated
			}
			eventType, data, hasData, hasID, oversized = "", nil, false, false, false

			// Dropping the frame is only half the job: the position has to be
			// persisted too. Nothing else here reaches the offset store, so if
			// Auth0 closed the connection now, the next one would resume from
			// the last saved offset and meet the same frame again, forever.
			// An offset-only marker is exactly the "moved, no event" signal.
			if err := handle(ctx, EventMessage{Offset: lastOffset, Type: EventTypeOffsetOnly}); err != nil {
				return err
			}
			continue
		}

		// A blank line ends the frame. One carrying no `data:` is not an event
		// under the SSE spec, but two kinds of payload-less frame still matter:
		// Auth0's bare position markers, which move the offset, and a terminal
		// error, which is terminal whether or not it carried a body.
		if !hasData {
			frameType, moved := eventType, hasID
			eventType, hasID = "", false

			if frameType == EventTypeError {
				slog.ErrorContext(ctx, "auth0 ended the events stream with a terminal error event",
					"offset", lastOffset,
				)
				return ErrStreamTerminated
			}
			if !moved {
				continue
			}

			// The position advanced with no event on it. Dropping the frame
			// here would strand the offset: nothing else in this loop reaches
			// the offset store, so a quiet stream would replay its whole window
			// on every reconnect and its recorded position would never age out
			// of the stall signal.
			if err := handle(ctx, EventMessage{Offset: lastOffset, Type: EventTypeOffsetOnly}); err != nil {
				return err
			}
			continue
		}

		message := EventMessage{Offset: lastOffset, Type: eventType, Data: data}
		if message.Type == "" {
			message.Type = eventTypeDefault
		}
		eventType, data, hasData, hasID = "", nil, false, false

		if err := handle(ctx, message); err != nil {
			return err
		}

		if message.Type == EventTypeError {
			// Auth0 documents this as terminal — an expired offset or a
			// server-side problem — but does not document the payload that
			// says which. Returning a distinct sentinel lets the caller treat
			// the offset as suspect without anything here guessing at a shape
			// it cannot verify. Bare, because errs.* wrappers defeat
			// errors.Is.
			slog.ErrorContext(ctx, "auth0 ended the events stream with a terminal error event",
				"offset", message.Offset,
			)
			return ErrStreamTerminated
		}
	}
}

// readSSELine reads one newline-terminated line, reporting whether it exceeded
// max. An oversized line is drained to its terminator and discarded, so the
// connection stays usable instead of dying on one outsized frame.
//
// A dropped line still returns its first linePrefixBytes. Without them an
// oversized comment would be indistinguishable from an oversized field, and the
// caller has to tell those apart: a comment must not disturb the frame around
// it. Draining is itself bounded — a line that never terminates would otherwise
// spin here forever, resetting the idle deadline on every read.
func readSSELine(reader *bufio.Reader, max int) (string, bool, error) {
	var (
		buf     []byte
		prefix  []byte
		content int
		tooLong bool
	)

	finish := func() (string, bool, error) {
		out := buf
		if tooLong {
			out = prefix
		}
		return strings.TrimSuffix(string(out), "\r"), tooLong, nil
	}

	for {
		chunk, err := reader.ReadSlice('\n')

		// ReadSlice keeps the delimiter; the cap is about the line's content.
		line := chunk
		if err == nil {
			line = chunk[:len(chunk)-1]
		}
		content += len(line)

		if len(prefix) < linePrefixBytes {
			prefix = append(prefix, line[:min(len(line), linePrefixBytes-len(prefix))]...)
		}

		if !tooLong && content > max {
			tooLong = true
			buf = nil
		}
		if !tooLong {
			buf = append(buf, line...)
		}

		if content > maxDrainBytes {
			return "", true, errs.NewUnexpected("the events stream sent a line that never terminated")
		}

		switch {
		case err == bufio.ErrBufferFull:
			continue
		case err != nil:
			// A trailing line without a terminator still counts as read.
			if err == io.EOF && content > 0 {
				return finish()
			}
			return "", tooLong, err
		}

		return finish()
	}
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
