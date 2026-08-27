// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package provisioning

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/auth0"
	errs "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
)

// mockEventsClient replays a fixed set of messages, recording the options it
// was subscribed with so a test can assert where the stream resumed from.
//
// Consumer.Run drives Subscribe from its own goroutine while a test watches
// the recorded calls, so the recording is guarded.
type mockEventsClient struct {
	messages [][]auth0.EventMessage
	errs     []error

	// Used by every connection once the scripted scripts above run out, for
	// tests of a fault that does not go away by itself.
	alwaysMessages []auth0.EventMessage
	alwaysErr      error

	mu    sync.Mutex
	calls []auth0.SubscribeOptions
}

func (m *mockEventsClient) Subscribe(ctx context.Context, opts auth0.SubscribeOptions, handle func(context.Context, auth0.EventMessage) error) error {
	m.mu.Lock()
	call := len(m.calls)
	m.calls = append(m.calls, opts)
	m.mu.Unlock()

	deliver := m.alwaysMessages
	if call < len(m.messages) {
		deliver = m.messages[call]
	}
	for _, message := range deliver {
		if err := handle(ctx, message); err != nil {
			return err
		}
	}

	if call < len(m.errs) {
		return m.errs[call]
	}
	return m.alwaysErr
}

// subscribeCalls returns a snapshot of the options each connection used.
func (m *mockEventsClient) subscribeCalls() []auth0.SubscribeOptions {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.calls)
}

// mockOffsetStore keeps the offset in memory and counts writes.
//
// Save drops an empty offset exactly as the KV store does. Mirroring that
// matters: a mock that let an empty Save clear the offset would report the
// expired-offset recovery as working when the real store silently keeps the
// dead value.
type mockOffsetStore struct {
	offset   string
	loadErr  error
	saveErr  error
	clearErr error
	saves    []string
	clears   int
	loadCall int
}

func (m *mockOffsetStore) Load(context.Context) (string, error) {
	m.loadCall++
	if m.loadErr != nil {
		return "", m.loadErr
	}
	return m.offset, nil
}

func (m *mockOffsetStore) Save(_ context.Context, offset string) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	if offset == "" {
		return nil
	}
	m.saves = append(m.saves, offset)
	m.offset = offset
	return nil
}

func (m *mockOffsetStore) Clear(context.Context) error {
	if m.clearErr != nil {
		return m.clearErr
	}
	m.clears++
	m.offset = ""
	return nil
}

// mockProvisioner records requests and returns a scripted outcome.
type mockProvisioner struct {
	err   error
	calls int
}

func (m *mockProvisioner) Provision(context.Context, Request) (Result, error) {
	m.calls++
	if m.err != nil {
		return Result{}, m.err
	}
	return Result{Outcome: OutcomeProvisioned, MemberID: "member-1"}, nil
}

// userEvent builds a stream message wrapping a verified database user.
func userEvent(offset, userID string) auth0.EventMessage {
	return auth0.EventMessage{
		Offset: offset,
		Type:   EventTypeUserUpdated,
		Data: []byte(`{"offset":"` + offset + `","event":{` +
			`"id":"evt_1","type":"user.updated","time":"2026-08-26T00:00:00Z",` +
			`"data":{"object":{"user_id":"` + userID + `","username":"psmith",` +
			`"email":"p@example.com","email_verified":true,` +
			`"identities":[{"connection":"Username-Password-Authentication"}]}}}}`),
	}
}

func newTestConsumer(t *testing.T, events auth0.EventsClient, provisioner Orchestrator, offsets OffsetStore) *Consumer {
	t.Helper()

	consumer, err := NewConsumer(
		WithEventsClient(events),
		WithProvisioner(provisioner),
		WithOffsetStore(offsets),
		WithReplayWindow(24*time.Hour),
	)
	require.NoError(t, err)

	consumer.now = func() time.Time { return time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC) }
	// The reconnect paths are what these tests exercise; the production
	// backoff would make them sleep for seconds to see three attempts.
	consumer.minBackoff = time.Millisecond
	consumer.maxBackoff = 2 * time.Millisecond
	return consumer
}

func TestNewConsumerValidation(t *testing.T) {
	t.Run("every dependency is required", func(t *testing.T) {
		_, err := NewConsumer()
		require.Error(t, err)

		_, err = NewConsumer(WithEventsClient(&mockEventsClient{}))
		require.Error(t, err)

		_, err = NewConsumer(
			WithEventsClient(&mockEventsClient{}),
			WithProvisioner(&mockProvisioner{}),
		)
		require.Error(t, err)
	})

	t.Run("defaults to the two user event types", func(t *testing.T) {
		consumer, err := NewConsumer(
			WithEventsClient(&mockEventsClient{}),
			WithProvisioner(&mockProvisioner{}),
			WithOffsetStore(&mockOffsetStore{}),
		)
		require.NoError(t, err)
		assert.Equal(t, []string{EventTypeUserCreated, EventTypeUserUpdated}, consumer.eventTypes)
	})
}

func TestConsumerHandle(t *testing.T) {
	ctx := context.Background()

	t.Run("a position marker advances the offset without provisioning", func(t *testing.T) {
		provisioner := &mockProvisioner{}
		offsets := &mockOffsetStore{}
		consumer := newTestConsumer(t, &mockEventsClient{}, provisioner, offsets)

		err := consumer.handle(ctx, auth0.EventMessage{Offset: "o1", Type: auth0.EventTypeOffsetOnly})

		require.NoError(t, err)
		assert.Equal(t, []string{"o1"}, offsets.saves)
		assert.Zero(t, provisioner.calls, "a marker carries no event")
	})

	t.Run("a user event is provisioned and its offset recorded", func(t *testing.T) {
		provisioner := &mockProvisioner{}
		offsets := &mockOffsetStore{}
		consumer := newTestConsumer(t, &mockEventsClient{}, provisioner, offsets)

		err := consumer.handle(ctx, userEvent("o2", "auth0|1"))

		require.NoError(t, err)
		assert.Equal(t, 1, provisioner.calls)
		assert.Equal(t, []string{"o2"}, offsets.saves)
	})

	t.Run("an unparseable event is skipped rather than retried forever", func(t *testing.T) {
		provisioner := &mockProvisioner{}
		offsets := &mockOffsetStore{}
		consumer := newTestConsumer(t, &mockEventsClient{}, provisioner, offsets)

		err := consumer.handle(ctx, auth0.EventMessage{
			Offset: "o3",
			Type:   EventTypeUserUpdated,
			Data:   []byte(`{"event":{"id":"evt_1","type":"user.updated","data":{}}}`),
		})

		require.NoError(t, err)
		assert.Zero(t, provisioner.calls)
		assert.Equal(t, []string{"o3"}, offsets.saves, "the stream must move past it")
	})

	t.Run("a validation failure is permanent and skipped", func(t *testing.T) {
		provisioner := &mockProvisioner{err: errs.NewValidation("user_id is required")}
		offsets := &mockOffsetStore{}
		consumer := newTestConsumer(t, &mockEventsClient{}, provisioner, offsets)

		err := consumer.handle(ctx, userEvent("o4", "auth0|1"))

		require.NoError(t, err)
		assert.Equal(t, []string{"o4"}, offsets.saves)
	})

	t.Run("a transient failure holds the offset back so the event is retried", func(t *testing.T) {
		provisioner := &mockProvisioner{err: errors.New("CDP unavailable")}
		offsets := &mockOffsetStore{}
		consumer := newTestConsumer(t, &mockEventsClient{}, provisioner, offsets)

		err := consumer.handle(ctx, userEvent("o5", "auth0|1"))

		require.Error(t, err)
		assert.Empty(t, offsets.saves, "not advancing is what makes the reconnect replay it")
	})

	t.Run("one event cannot wedge the stream forever", func(t *testing.T) {
		provisioner := &mockProvisioner{err: errors.New("CDP unavailable")}
		offsets := &mockOffsetStore{}
		consumer := newTestConsumer(t, &mockEventsClient{}, provisioner, offsets)

		var lastErr error
		for i := 0; i < maxEventAttempts; i++ {
			lastErr = consumer.handle(ctx, userEvent("o6", "auth0|1"))
		}

		require.NoError(t, lastErr, "the final attempt gives up and moves on")
		assert.Equal(t, []string{"o6"}, offsets.saves)
		assert.Equal(t, maxEventAttempts, provisioner.calls)
	})

	t.Run("a different event resets the failure count", func(t *testing.T) {
		provisioner := &mockProvisioner{err: errors.New("CDP unavailable")}
		offsets := &mockOffsetStore{}
		consumer := newTestConsumer(t, &mockEventsClient{}, provisioner, offsets)

		for i := 0; i < maxEventAttempts-1; i++ {
			require.Error(t, consumer.handle(ctx, userEvent("o7", "auth0|1")))
		}
		require.Error(t, consumer.handle(ctx, userEvent("o8", "auth0|2")))

		assert.Empty(t, offsets.saves, "neither event has been abandoned yet")
	})
}

func TestConsumerSubscribeOptions(t *testing.T) {
	ctx := context.Background()

	t.Run("a cold start reaches back by the replay window", func(t *testing.T) {
		consumer := newTestConsumer(t, &mockEventsClient{}, &mockProvisioner{}, &mockOffsetStore{})

		opts, err := consumer.subscribeOptions(ctx)

		require.NoError(t, err)
		assert.Empty(t, opts.From)
		assert.Equal(t, time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC), opts.FromTimestamp,
			"leaving both unset would silently start at the latest events")
	})

	t.Run("a stored offset resumes from it", func(t *testing.T) {
		consumer := newTestConsumer(t, &mockEventsClient{}, &mockProvisioner{}, &mockOffsetStore{offset: "o9"})

		opts, err := consumer.subscribeOptions(ctx)

		require.NoError(t, err)
		assert.Equal(t, "o9", opts.From)
		assert.True(t, opts.FromTimestamp.IsZero())
	})
}

func TestConsumerOffsetAge(t *testing.T) {
	ctx := context.Background()

	// Age is what separates a connected-but-stalled reader from a quiet one:
	// leadership and connection state look healthy in both.
	newAgingConsumer := func(t *testing.T, clock *time.Time) *Consumer {
		t.Helper()
		consumer := newTestConsumer(t, &mockEventsClient{}, &mockProvisioner{}, &mockOffsetStore{})
		consumer.now = func() time.Time { return *clock }
		consumer.recordAdvance()
		return consumer
	}

	t.Run("age climbs while the offset stands still", func(t *testing.T) {
		clock := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
		consumer := newAgingConsumer(t, &clock)

		assert.Zero(t, consumer.offsetAge())
		clock = clock.Add(90 * time.Second)
		assert.Equal(t, 90*time.Second, consumer.offsetAge())
	})

	t.Run("an offset-only marker resets it, so a quiet stream does not alarm", func(t *testing.T) {
		// These markers are exactly the heartbeat that keeps a quiet stream's
		// position fresh, so they must count as the offset advancing.
		clock := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
		consumer := newAgingConsumer(t, &clock)

		clock = clock.Add(10 * time.Minute)
		require.NoError(t, consumer.handle(ctx, auth0.EventMessage{Offset: "o1", Type: auth0.EventTypeOffsetOnly}))

		assert.Zero(t, consumer.offsetAge())
	})

	t.Run("a terminal error frame does not reset it", func(t *testing.T) {
		// It moves nothing, and treating it as freshness would hide the exact
		// stall this signal exists to expose.
		clock := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
		consumer := newAgingConsumer(t, &clock)

		clock = clock.Add(10 * time.Minute)
		require.NoError(t, consumer.handle(ctx, auth0.EventMessage{Offset: "o1", Type: auth0.EventTypeError}))

		assert.Equal(t, 10*time.Minute, consumer.offsetAge())
	})

	t.Run("a failed save does not count as an advance", func(t *testing.T) {
		clock := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
		consumer := newAgingConsumer(t, &clock)
		consumer.offsets = &mockOffsetStore{saveErr: errors.New("bucket unavailable")}

		clock = clock.Add(5 * time.Minute)
		require.Error(t, consumer.handle(ctx, auth0.EventMessage{Offset: "o1", Type: auth0.EventTypeOffsetOnly}))

		assert.Equal(t, 5*time.Minute, consumer.offsetAge(), "the position did not actually move")
	})
}

func TestConsumerRun(t *testing.T) {
	t.Run("an expired offset restarts from the replay window", func(t *testing.T) {
		events := &mockEventsClient{errs: []error{auth0.ErrOffsetExpired}}
		offsets := &mockOffsetStore{offset: "stale"}
		consumer := newTestConsumer(t, events, &mockProvisioner{}, offsets)

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			// Two connections is enough to see the recovery: the first is
			// rejected, the second must not reuse the dead offset.
			for len(events.subscribeCalls()) < 2 {
				time.Sleep(time.Millisecond)
			}
			cancel()
		}()
		consumer.Run(ctx)

		calls := events.subscribeCalls()
		require.GreaterOrEqual(t, len(calls), 2)
		assert.Equal(t, "stale", calls[0].From)
		assert.Empty(t, calls[1].From, "the dead offset must be dropped")
		assert.False(t, calls[1].FromTimestamp.IsZero())
		assert.Positive(t, offsets.clears, "the stored offset must be cleared, not overwritten with an empty save")
	})

	t.Run("a clean close reconnects without backing off", func(t *testing.T) {
		events := &mockEventsClient{
			messages: [][]auth0.EventMessage{{userEvent("o10", "auth0|1")}},
		}
		offsets := &mockOffsetStore{}
		consumer := newTestConsumer(t, events, &mockProvisioner{}, offsets)

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		consumer.Run(ctx)

		assert.Greater(t, len(events.subscribeCalls()), 1, "Auth0 cycles connections; idling for a second each time would stall the consumer")
		assert.Equal(t, "o10", offsets.offset)
	})

	t.Run("a clear that fails backs off instead of spinning on the dead offset", func(t *testing.T) {
		events := &mockEventsClient{alwaysErr: auth0.ErrOffsetExpired}
		offsets := &mockOffsetStore{offset: "stale", clearErr: errors.New("bucket unavailable")}
		consumer := newTestConsumer(t, events, &mockProvisioner{}, offsets)
		// This one is about the wait itself, so it needs a backoff long
		// enough that spinning and backing off produce different counts.
		consumer.minBackoff = 50 * time.Millisecond
		consumer.maxBackoff = 50 * time.Millisecond

		ctx, cancel := context.WithTimeout(context.Background(), 220*time.Millisecond)
		defer cancel()
		consumer.Run(ctx)

		assert.LessOrEqual(t, len(events.subscribeCalls()), 6,
			"a still-stored dead offset earns the same rejection, so reconnecting must wait")
	})

	// An offset can also expire mid-stream, after the HTTP 200, and Auth0 only
	// says so with an in-band `event: error` whose payload shape is not
	// documented. The consumer therefore watches its own progress instead of
	// reading that payload, which also covers any other way a cursor can go
	// permanently bad.
	t.Run("an offset that only ever fails is abandoned for the replay window", func(t *testing.T) {
		events := &mockEventsClient{alwaysErr: auth0.ErrStreamTerminated}
		offsets := &mockOffsetStore{offset: "poisoned"}
		consumer := newTestConsumer(t, events, &mockProvisioner{}, offsets)

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			for len(events.subscribeCalls()) < maxBarrenReconnects+1 {
				time.Sleep(time.Millisecond)
			}
			cancel()
		}()
		consumer.Run(ctx)

		calls := events.subscribeCalls()
		require.Greater(t, len(calls), maxBarrenReconnects)
		for i := 0; i < maxBarrenReconnects; i++ {
			assert.Equal(t, "poisoned", calls[i].From, "attempt %d should still be trying the stored offset", i)
		}
		assert.Positive(t, offsets.clears, "the offset must be cleared, not retried forever")
		assert.Empty(t, calls[maxBarrenReconnects].From, "the next attempt must not reuse it")
		assert.False(t, calls[maxBarrenReconnects].FromTimestamp.IsZero(), "it must fall back to the replay window")
	})

	t.Run("a terminal error frame does not count as progress", func(t *testing.T) {
		// The poisoned connection delivers exactly one error frame. Counting
		// it as a message read would convince the guard the offset is fine and
		// switch off the only defence there is.
		events := &mockEventsClient{
			alwaysMessages: []auth0.EventMessage{{Offset: "poisoned", Type: auth0.EventTypeError, Data: []byte(`{}`)}},
			alwaysErr:      auth0.ErrStreamTerminated,
		}
		offsets := &mockOffsetStore{offset: "poisoned"}
		consumer := newTestConsumer(t, events, &mockProvisioner{}, offsets)

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			for len(events.subscribeCalls()) < maxBarrenReconnects+1 {
				time.Sleep(time.Millisecond)
			}
			cancel()
		}()
		consumer.Run(ctx)

		assert.Positive(t, offsets.clears, "an error frame is the failure, not evidence the offset works")
	})

	t.Run("a quiet stream closing cleanly is never mistaken for a bad offset", func(t *testing.T) {
		// Auth0 recycles connections on purpose and a quiet one carries no
		// messages. That must not look like a poisoned cursor.
		events := &mockEventsClient{}
		offsets := &mockOffsetStore{offset: "healthy"}
		consumer := newTestConsumer(t, events, &mockProvisioner{}, offsets)

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		consumer.Run(ctx)

		require.Greater(t, len(events.subscribeCalls()), maxBarrenReconnects,
			"the point of this test is many clean reconnects")
		assert.Zero(t, offsets.clears, "a clean close says nothing about the offset")
		assert.Equal(t, "healthy", offsets.offset)
	})

	t.Run("a delivered message clears the suspicion", func(t *testing.T) {
		events := &mockEventsClient{
			messages: [][]auth0.EventMessage{
				nil,
				nil,
				{{Offset: "o1", Type: auth0.EventTypeOffsetOnly}},
			},
			errs:      []error{auth0.ErrStreamTerminated, auth0.ErrStreamTerminated, auth0.ErrStreamTerminated},
			alwaysErr: auth0.ErrStreamTerminated,
		}
		offsets := &mockOffsetStore{offset: "suspect"}
		consumer := newTestConsumer(t, events, &mockProvisioner{}, offsets)

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			for len(events.subscribeCalls()) < 4 {
				time.Sleep(time.Millisecond)
			}
			cancel()
		}()
		consumer.Run(ctx)

		assert.Zero(t, offsets.clears,
			"two failures then a message means the count restarts, so three total must not trip it")
	})

	t.Run("returns promptly when the context is already done", func(t *testing.T) {
		events := &mockEventsClient{}
		consumer := newTestConsumer(t, events, &mockProvisioner{}, &mockOffsetStore{})

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		consumer.Run(ctx)

		assert.Empty(t, events.subscribeCalls())
	})
}
