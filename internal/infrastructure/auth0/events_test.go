// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	errs "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// eventsTokenSource returns a fixed valid token so a TokenManager can be built
// without contacting Auth0.
type eventsTokenSource struct{ token string }

func (s eventsTokenSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{
		AccessToken: s.token,
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}, nil
}

// eventsRewriteTransport points the https://<domain> URL the client builds at
// the test server, keeping the path and query intact so assertions run against
// the wire format the client actually produced.
type eventsRewriteTransport struct{ target *url.URL }

func (t eventsRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	routed := req.Clone(req.Context())
	routed.URL.Scheme = t.target.Scheme
	routed.URL.Host = t.target.Host
	routed.Host = ""
	return http.DefaultTransport.RoundTrip(routed)
}

// recordedEventsRequest is what the test server saw.
type recordedEventsRequest struct {
	query  url.Values
	header http.Header
}

// eventsServer answers the subscription and hands the request back over a
// channel, so assertions never race the handler goroutine.
type eventsServer struct {
	*httptest.Server
	requests chan recordedEventsRequest
}

func newEventsServer(t *testing.T, respond http.HandlerFunc) *eventsServer {
	t.Helper()

	server := &eventsServer{requests: make(chan recordedEventsRequest, 4)}
	server.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.requests <- recordedEventsRequest{query: r.URL.Query(), header: r.Header.Clone()}
		respond(w, r)
	}))
	t.Cleanup(server.Close)

	return server
}

func (s *eventsServer) request(t *testing.T) recordedEventsRequest {
	t.Helper()

	select {
	case recorded := <-s.requests:
		return recorded
	default:
		t.Fatal("the client never called the events endpoint")
		return recordedEventsRequest{}
	}
}

// writeSSE writes each chunk verbatim and flushes, so the client sees frames as
// they are produced rather than in one blob at close.
func writeSSE(w http.ResponseWriter, chunks ...string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}
	for _, chunk := range chunks {
		_, _ = io.WriteString(w, chunk)
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// respondStatus answers the subscription with a status and no stream.
func respondStatus(status int, headers map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		for key, value := range headers {
			w.Header().Set(key, value)
		}
		w.WriteHeader(status)
	}
}

func newTestEventsClient(t *testing.T, server *eventsServer) EventsClient {
	t.Helper()

	target, err := url.Parse(server.URL)
	require.NoError(t, err)

	client, err := NewEventsClient(
		EventsConfig{Transport: eventsRewriteTransport{target: target}},
		Config{
			Domain:          "test-tenant.auth0.com",
			M2MTokenManager: &TokenManager{tokenSource: eventsTokenSource{token: "test-m2m-token"}},
		},
	)
	require.NoError(t, err)

	return client
}

// collect subscribes and returns every message handed to the handler.
func collect(t *testing.T, server *eventsServer, opts SubscribeOptions) ([]EventMessage, error) {
	t.Helper()

	var messages []EventMessage
	err := newTestEventsClient(t, server).Subscribe(context.Background(), opts, func(_ context.Context, message EventMessage) error {
		messages = append(messages, message)
		return nil
	})

	return messages, err
}

func TestNewEventsClientValidation(t *testing.T) {
	t.Run("a missing token manager is refused at construction", func(t *testing.T) {
		_, err := NewEventsClient(EventsConfig{}, Config{Domain: "test.auth0.com"})
		require.Error(t, err, "misconfiguration must surface here, not as a panic on the first subscription")
	})

	t.Run("a missing domain is refused at construction", func(t *testing.T) {
		_, err := NewEventsClient(EventsConfig{}, Config{
			M2MTokenManager: &TokenManager{tokenSource: eventsTokenSource{token: "t"}},
		})
		require.Error(t, err)
	})

	t.Run("a nil handler is refused before opening a connection", func(t *testing.T) {
		server := newEventsServer(t, func(w http.ResponseWriter, _ *http.Request) { writeSSE(w) })

		err := newTestEventsClient(t, server).Subscribe(context.Background(), SubscribeOptions{}, nil)
		require.Error(t, err)
		assert.Empty(t, server.requests, "a connection slot must not be spent on a caller defect")
	})
}

func TestSubscribeStream(t *testing.T) {
	t.Run("real events reach the handler in order", func(t *testing.T) {
		server := newEventsServer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeSSE(w,
				":connected\n\n",
				"event: user.created\nid: off-1\ndata: {\"offset\":\"off-1\"}\n\n",
				"event: user.updated\nid: off-2\ndata: {\"offset\":\"off-2\"}\n\n",
			)
		})

		messages, err := collect(t, server, SubscribeOptions{})

		require.NoError(t, err, "a clean close is how a healthy subscription ends")
		require.Len(t, messages, 2)
		assert.Equal(t, "user.created", messages[0].Type)
		assert.Equal(t, "off-1", messages[0].Offset)
		assert.JSONEq(t, `{"offset":"off-1"}`, string(messages[0].Data))
		assert.Equal(t, "user.updated", messages[1].Type)
		assert.Equal(t, "off-2", messages[1].Offset)

		recorded := server.request(t)
		assert.Equal(t, "Bearer test-m2m-token", recorded.header.Get("Authorization"))
		assert.Equal(t, "text/event-stream", recorded.header.Get("Accept"))
	})

	t.Run("an offset-only marker is delivered so the caller can record it", func(t *testing.T) {
		server := newEventsServer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeSSE(w,
				"event: user.created\nid: off-1\ndata: {\"offset\":\"off-1\"}\n\n",
				"event: offset-only\nid: off-2\ndata: {\"offset\":\"off-2\"}\n\n",
			)
		})

		messages, err := collect(t, server, SubscribeOptions{})

		require.NoError(t, err)
		require.Len(t, messages, 2)
		assert.Equal(t, EventTypeOffsetOnly, messages[1].Type)
		assert.Equal(t, "off-2", messages[1].Offset, "the offset advances even with no event payload")
	})

	t.Run("comments and heartbeats are skipped without ending a frame", func(t *testing.T) {
		server := newEventsServer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeSSE(w,
				":connected\n\n",
				": heartbeat\n\n",
				"event: user.created\n",
				": heartbeat\n",
				"id: off-1\ndata: {\"offset\":\"off-1\"}\n\n",
				": heartbeat\n\n",
			)
		})

		messages, err := collect(t, server, SubscribeOptions{})

		require.NoError(t, err)
		require.Len(t, messages, 1, "only the real event dispatches")
		assert.Equal(t, "user.created", messages[0].Type, "a comment mid-frame must not discard the event name")
		assert.Equal(t, "off-1", messages[0].Offset)
	})

	t.Run("an oversized frame is dropped and the stream keeps going", func(t *testing.T) {
		huge := strings.Repeat("x", maxEventLineBytes+1024)
		server := newEventsServer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeSSE(w,
				"event: user.created\nid: off-1\ndata: {\"offset\":\"off-1\"}\n\n",
				"event: user.updated\nid: off-2\ndata: "+huge+"\n\n",
				"event: user.created\nid: off-3\ndata: {\"offset\":\"off-3\"}\n\n",
			)
		})

		messages, err := collect(t, server, SubscribeOptions{})

		require.NoError(t, err, "one outsized frame must not fail the connection")
		require.Len(t, messages, 3)
		assert.Equal(t, "off-1", messages[0].Offset)

		// The dropped frame still has to move the stored position, or a close
		// right here would replay straight back into it on the next connection.
		assert.Equal(t, EventTypeOffsetOnly, messages[1].Type,
			"the drop is reported as a position marker, not as an event")
		assert.Equal(t, "off-2", messages[1].Offset)
		assert.Empty(t, messages[1].Data, "a dropped frame carries no payload")

		assert.Equal(t, "user.created", messages[2].Type)
		assert.Equal(t, "off-3", messages[2].Offset)
	})

	t.Run("an oversized comment does not disturb the frames around it", func(t *testing.T) {
		// A padding comment is a real anti-buffering trick on proxied streams.
		// Classifying it as a dropped field would take an unrelated event with
		// it, because the drop is only cleared on the next frame boundary.
		huge := strings.Repeat("x", maxEventLineBytes+1024)
		server := newEventsServer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeSSE(w,
				"event: user.created\nid: off-1\ndata: {\"offset\":\"off-1\"}\n\n",
				":"+huge+"\n\n",
				"event: user.created\nid: off-2\ndata: {\"offset\":\"off-2\"}\n\n",
			)
		})

		messages, err := collect(t, server, SubscribeOptions{})

		require.NoError(t, err)
		require.Len(t, messages, 2, "a comment, however large, is not an event and eats no event")
		assert.Equal(t, "off-1", messages[0].Offset)
		assert.Equal(t, "off-2", messages[1].Offset)
	})

	t.Run("a terminal error event stays terminal even when oversized", func(t *testing.T) {
		huge := strings.Repeat("x", maxEventLineBytes+1024)
		server := newEventsServer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeSSE(w,
				"event: error\nid: off-1\ndata: "+huge+"\n\n",
				"event: user.created\nid: off-2\ndata: {\"offset\":\"off-2\"}\n\n",
			)
		})

		_, err := collect(t, server, SubscribeOptions{})

		require.ErrorIs(t, err, ErrStreamTerminated,
			"discarding the payload must not discard the signal that the stream ended")
	})

	t.Run("one frame cannot accumulate unbounded data", func(t *testing.T) {
		// Every line here is legal on its own; only the frame is not.
		line := strings.Repeat("y", 512*1024)
		var frame strings.Builder
		frame.WriteString("event: user.created\nid: off-1\n")
		for range 16 {
			frame.WriteString("data: " + line + "\n")
		}
		frame.WriteString("\n")

		server := newEventsServer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeSSE(w,
				frame.String(),
				"event: user.created\nid: off-2\ndata: {\"offset\":\"off-2\"}\n\n",
			)
		})

		messages, err := collect(t, server, SubscribeOptions{})

		require.NoError(t, err)
		require.Len(t, messages, 2)
		assert.Equal(t, EventTypeOffsetOnly, messages[0].Type, "the unbounded frame is dropped")
		assert.Equal(t, "off-1", messages[0].Offset)
		assert.Equal(t, "user.created", messages[1].Type, "the healthy frame still arrives")
		assert.Equal(t, "off-2", messages[1].Offset)
	})

	t.Run("a close right after a dropped frame still moves the position", func(t *testing.T) {
		// The replay-loop case: if the drop does not reach the offset store
		// before the connection ends, the next one resumes from the previous
		// offset and meets the same frame again, forever.
		huge := strings.Repeat("x", maxEventLineBytes+1024)
		server := newEventsServer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeSSE(w,
				"event: user.created\nid: off-1\ndata: {\"offset\":\"off-1\"}\n\n",
				"event: user.updated\nid: off-2\ndata: "+huge+"\n\n",
			)
		})

		messages, err := collect(t, server, SubscribeOptions{})

		require.NoError(t, err)
		require.Len(t, messages, 2)
		assert.Equal(t, EventTypeOffsetOnly, messages[1].Type)
		assert.Equal(t, "off-2", messages[1].Offset,
			"the last thing the caller sees must be the dropped frame's position")
	})

	t.Run("a retry hint does not dispatch a message", func(t *testing.T) {
		server := newEventsServer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeSSE(w,
				"retry: 5000\n\n",
				"event: user.created\nid: off-1\ndata: {}\n\n",
			)
		})

		messages, err := collect(t, server, SubscribeOptions{})

		require.NoError(t, err)
		require.Len(t, messages, 1)
	})

	t.Run("multiple data lines in one frame are joined with a newline", func(t *testing.T) {
		server := newEventsServer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeSSE(w, "event: user.created\nid: off-1\ndata: line-one\ndata: line-two\ndata: line-three\n\n")
		})

		messages, err := collect(t, server, SubscribeOptions{})

		require.NoError(t, err)
		require.Len(t, messages, 1)
		assert.Equal(t, "line-one\nline-two\nline-three", string(messages[0].Data))
	})

	t.Run("a frame larger than the default scanner buffer survives", func(t *testing.T) {
		// bufio.Scanner tops out at 64KiB by default, which a user event with a
		// large app_metadata exceeds.
		payload := strings.Repeat("m", 200*1024)
		server := newEventsServer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeSSE(w, "event: user.updated\nid: off-1\ndata: "+payload+"\n\n")
		})

		messages, err := collect(t, server, SubscribeOptions{})

		require.NoError(t, err)
		require.Len(t, messages, 1)
		assert.Equal(t, payload, string(messages[0].Data))
	})

	t.Run("a frame with no event name surfaces as the SSE default type", func(t *testing.T) {
		server := newEventsServer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeSSE(w, "id: off-1\ndata: {}\n\n")
		})

		messages, err := collect(t, server, SubscribeOptions{})

		require.NoError(t, err)
		require.Len(t, messages, 1)
		assert.Equal(t, "message", messages[0].Type)
	})

	t.Run("a frame carrying no data is not an event", func(t *testing.T) {
		server := newEventsServer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeSSE(w,
				"id: off-1\n\n",
				"event: user.created\nid: off-2\ndata: {}\n\n",
			)
		})

		messages, err := collect(t, server, SubscribeOptions{})

		require.NoError(t, err)
		require.Len(t, messages, 1)
		assert.Equal(t, "off-2", messages[0].Offset)
	})

	t.Run("a terminal error event is delivered and then ends the stream", func(t *testing.T) {
		server := newEventsServer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeSSE(w,
				"event: user.created\nid: off-1\ndata: {}\n\n",
				"event: error\nid: off-2\ndata: {\"code\":\"stream_error\"}\n\n",
				"event: user.updated\nid: off-3\ndata: {}\n\n",
			)
		})

		messages, err := collect(t, server, SubscribeOptions{})

		require.Error(t, err, "a terminal error is not a clean close")
		require.ErrorIs(t, err, ErrStreamTerminated,
			"the caller branches on this to suspect its offset, so it must survive errors.Is")
		require.Len(t, messages, 2, "nothing after the error event may be delivered")
		assert.Equal(t, EventTypeError, messages[1].Type)
		assert.JSONEq(t, `{"code":"stream_error"}`, string(messages[1].Data),
			"the caller only sees the failure payload if it is handed over")
	})

	t.Run("a terminal error is recognised whatever its payload says", func(t *testing.T) {
		// The frame's `event:` name is documented; its payload shape is not.
		// Nothing may depend on the latter.
		for _, payload := range []string{`{}`, `{"unexpected":"shape"}`, `not json at all`} {
			server := newEventsServer(t, func(w http.ResponseWriter, _ *http.Request) {
				writeSSE(w, "event: error\nid: off-1\ndata: "+payload+"\n\n")
			})

			_, err := collect(t, server, SubscribeOptions{})

			assert.ErrorIs(t, err, ErrStreamTerminated, "payload %q must not change the outcome", payload)
		}
	})

	t.Run("a handler error stops the stream and is returned unchanged", func(t *testing.T) {
		server := newEventsServer(t, func(w http.ResponseWriter, _ *http.Request) {
			writeSSE(w,
				"event: user.created\nid: off-1\ndata: {}\n\n",
				"event: user.updated\nid: off-2\ndata: {}\n\n",
				"event: user.deleted\nid: off-3\ndata: {}\n\n",
			)
		})

		var seen int
		err := newTestEventsClient(t, server).Subscribe(context.Background(), SubscribeOptions{},
			func(_ context.Context, _ EventMessage) error {
				seen++
				if seen == 2 {
					return assert.AnError
				}
				return nil
			})

		require.ErrorIs(t, err, assert.AnError)
		assert.Equal(t, 2, seen)
	})

	t.Run("cancelling the context returns promptly", func(t *testing.T) {
		server := newEventsServer(t, func(w http.ResponseWriter, r *http.Request) {
			writeSSE(w, "event: user.created\nid: off-1\ndata: {}\n\n")
			<-r.Context().Done()
		})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		done := make(chan error, 1)
		go func() {
			done <- newTestEventsClient(t, server).Subscribe(ctx, SubscribeOptions{},
				func(_ context.Context, _ EventMessage) error {
					cancel()
					return nil
				})
		}()

		select {
		case err := <-done:
			require.ErrorIs(t, err, context.Canceled)
		case <-time.After(5 * time.Second):
			t.Fatal("the read loop did not unblock on cancellation")
		}
	})
}

// newIdleTestEventsClient builds a client with a short read idle timeout.
func newIdleTestEventsClient(t *testing.T, server *eventsServer, idle time.Duration) EventsClient {
	t.Helper()

	target, err := url.Parse(server.URL)
	require.NoError(t, err)

	client, err := NewEventsClient(
		EventsConfig{Transport: eventsRewriteTransport{target: target}, ReadIdleTimeout: idle},
		Config{
			Domain:          "test-tenant.auth0.com",
			M2MTokenManager: &TokenManager{tokenSource: eventsTokenSource{token: "test-m2m-token"}},
		},
	)
	require.NoError(t, err)

	return client
}

func TestSubscribeReadIdleTimeout(t *testing.T) {
	t.Run("a stream that stops delivering fails instead of blocking", func(t *testing.T) {
		// No FIN and no RST, which is what a NAT or load balancer idle
		// timeout leaves behind. Without a read deadline Scan parks here for
		// as long as the peer keeps the socket open.
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })

		server := newEventsServer(t, func(w http.ResponseWriter, r *http.Request) {
			writeSSE(w, "event: user.created\nid: off-1\ndata: {}\n\n")
			select {
			case <-release:
			case <-r.Context().Done():
			}
		})

		var messages []EventMessage
		done := make(chan error, 1)
		go func() {
			done <- newIdleTestEventsClient(t, server, 150*time.Millisecond).
				Subscribe(context.Background(), SubscribeOptions{}, func(_ context.Context, m EventMessage) error {
					messages = append(messages, m)
					return nil
				})
		}()

		select {
		case err := <-done:
			require.ErrorIs(t, err, ErrStreamIdle)
			assert.Len(t, messages, 1, "what arrived before the silence is still delivered")
		case <-time.After(10 * time.Second):
			t.Fatal("Subscribe never returned: the read deadline did not fire")
		}
	})

	t.Run("traffic keeps the deadline open", func(t *testing.T) {
		// Every byte resets it, so a stream that keeps heartbeating outlives
		// an idle timeout many times shorter than its total life.
		server := newEventsServer(t, func(w http.ResponseWriter, _ *http.Request) {
			chunks := make([]string, 0, 12)
			for i := 0; i < 12; i++ {
				chunks = append(chunks, ": heartbeat\n\n")
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			flusher, _ := w.(http.Flusher)
			for _, chunk := range chunks {
				_, _ = io.WriteString(w, chunk)
				if flusher != nil {
					flusher.Flush()
				}
				time.Sleep(20 * time.Millisecond)
			}
		})

		err := newIdleTestEventsClient(t, server, 150*time.Millisecond).
			Subscribe(context.Background(), SubscribeOptions{}, func(context.Context, EventMessage) error { return nil })

		assert.NoError(t, err, "240ms of heartbeats must survive a 150ms idle deadline")
	})

	t.Run("the caller cancelling is not reported as idle", func(t *testing.T) {
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })

		server := newEventsServer(t, func(w http.ResponseWriter, r *http.Request) {
			writeSSE(w, ": connected\n\n")
			select {
			case <-release:
			case <-r.Context().Done():
			}
		})

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		err := newIdleTestEventsClient(t, server, time.Hour).
			Subscribe(ctx, SubscribeOptions{}, func(context.Context, EventMessage) error { return nil })

		assert.NotErrorIs(t, err, ErrStreamIdle)
		assert.ErrorIs(t, err, context.Canceled)
	})
}

func TestSubscribeStatusHandling(t *testing.T) {
	t.Run("410 reports an expired offset so the caller can fall back to a timestamp", func(t *testing.T) {
		server := newEventsServer(t, respondStatus(http.StatusGone, nil))

		_, err := collect(t, server, SubscribeOptions{From: "stale-offset"})

		require.ErrorIs(t, err, ErrOffsetExpired)
	})

	t.Run("401 is an authorization failure", func(t *testing.T) {
		server := newEventsServer(t, respondStatus(http.StatusUnauthorized, nil))

		_, err := collect(t, server, SubscribeOptions{})

		require.Error(t, err)
		var unauthorized errs.Unauthorized
		require.ErrorAs(t, err, &unauthorized, "a bad token must be distinguishable from a refused stream")
	})

	t.Run("403 names both of the causes Auth0 collapses into it", func(t *testing.T) {
		server := newEventsServer(t, respondStatus(http.StatusForbidden, nil))

		_, err := collect(t, server, SubscribeOptions{})

		require.Error(t, err)
		var forbidden errs.Forbidden
		require.ErrorAs(t, err, &forbidden)

		var unauthorized errs.Unauthorized
		assert.False(t, errors.As(err, &unauthorized), "403 must not read as 401")
		assert.Contains(t, err.Error(), "read:events")
		assert.Contains(t, err.Error(), "concurrent event stream connections")
	})

	t.Run("400 is a validation failure", func(t *testing.T) {
		server := newEventsServer(t, respondStatus(http.StatusBadRequest, nil))

		_, err := collect(t, server, SubscribeOptions{From: "not-an-offset"})

		require.Error(t, err)
		var validation errs.Validation
		require.ErrorAs(t, err, &validation)
	})

	t.Run("429 hands Retry-After to the caller", func(t *testing.T) {
		server := newEventsServer(t, respondStatus(http.StatusTooManyRequests, map[string]string{"Retry-After": "30"}))

		_, err := collect(t, server, SubscribeOptions{})

		var rateLimited *RateLimitedError
		require.ErrorAs(t, err, &rateLimited)
		assert.Equal(t, 30*time.Second, rateLimited.RetryAfter)
	})

	t.Run("429 without a Retry-After reports no wait rather than guessing one", func(t *testing.T) {
		server := newEventsServer(t, respondStatus(http.StatusTooManyRequests, nil))

		_, err := collect(t, server, SubscribeOptions{})

		var rateLimited *RateLimitedError
		require.ErrorAs(t, err, &rateLimited)
		assert.Zero(t, rateLimited.RetryAfter)
	})

	t.Run("429 accepts an HTTP-date Retry-After", func(t *testing.T) {
		deadline := time.Now().Add(45 * time.Second).UTC().Format(http.TimeFormat)
		server := newEventsServer(t, respondStatus(http.StatusTooManyRequests, map[string]string{"Retry-After": deadline}))

		_, err := collect(t, server, SubscribeOptions{})

		var rateLimited *RateLimitedError
		require.ErrorAs(t, err, &rateLimited)
		assert.Positive(t, rateLimited.RetryAfter)
	})

	t.Run("an unmapped status is an unexpected error", func(t *testing.T) {
		server := newEventsServer(t, respondStatus(http.StatusInternalServerError, nil))

		_, err := collect(t, server, SubscribeOptions{})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "500")
	})
}

func TestSubscribeQueryParameters(t *testing.T) {
	stream := func(w http.ResponseWriter, _ *http.Request) { writeSSE(w) }

	t.Run("an offset travels as from", func(t *testing.T) {
		server := newEventsServer(t, stream)

		_, err := collect(t, server, SubscribeOptions{From: "off-1"})
		require.NoError(t, err)

		query := server.request(t).query
		assert.Equal(t, "off-1", query.Get("from"))
		assert.Empty(t, query["from_timestamp"], "from and from_timestamp are mutually exclusive")
	})

	t.Run("a timestamp is used only when no offset is given", func(t *testing.T) {
		server := newEventsServer(t, stream)

		_, err := collect(t, server, SubscribeOptions{FromTimestamp: time.Date(2026, 8, 14, 10, 30, 0, 0, time.UTC)})
		require.NoError(t, err)

		query := server.request(t).query
		assert.Equal(t, "2026-08-14T10:30:00Z", query.Get("from_timestamp"))
		assert.Empty(t, query["from"])
	})

	t.Run("an offset wins over a timestamp", func(t *testing.T) {
		server := newEventsServer(t, stream)

		_, err := collect(t, server, SubscribeOptions{
			From:          "off-1",
			FromTimestamp: time.Date(2026, 8, 14, 10, 30, 0, 0, time.UTC),
		})
		require.NoError(t, err)

		query := server.request(t).query
		assert.Equal(t, "off-1", query.Get("from"))
		assert.Empty(t, query["from_timestamp"])
	})

	t.Run("each event type is a repeated parameter", func(t *testing.T) {
		server := newEventsServer(t, stream)

		_, err := collect(t, server, SubscribeOptions{
			EventTypes: []string{"user.created", "user.updated", "user.deleted"},
		})
		require.NoError(t, err)

		assert.Equal(t,
			[]string{"user.created", "user.updated", "user.deleted"},
			server.request(t).query["event_type"],
		)
	})

	t.Run("no starting point sends neither parameter", func(t *testing.T) {
		server := newEventsServer(t, stream)

		_, err := collect(t, server, SubscribeOptions{})
		require.NoError(t, err)

		query := server.request(t).query
		assert.Empty(t, query["from"])
		assert.Empty(t, query["from_timestamp"])
	})

	t.Run("the offset is never sent as a Last-Event-ID header", func(t *testing.T) {
		// Auth0 lets the header override `from`, so sending both would put the
		// precedence rule between the caller's intent and the stream.
		server := newEventsServer(t, stream)

		_, err := collect(t, server, SubscribeOptions{From: "off-1"})
		require.NoError(t, err)

		assert.Empty(t, server.request(t).header.Get("Last-Event-ID"))
	})
}
