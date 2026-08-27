// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package provisioning

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sort"
	"strconv"
	"time"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/auth0"
	errs "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

// Reconnection backoff. Auth0 closes the stream every few minutes on purpose,
// so a clean close reconnects immediately and only failures back off.
const (
	minReconnectBackoff = 1 * time.Second
	maxReconnectBackoff = 30 * time.Second
)

// maxEventAttempts bounds how many times one message may break the connection
// before the consumer gives up on it and moves past.
//
// Without a ceiling a single user whose provisioning keeps failing would wedge
// the stream for everyone behind them. Skipping loses that user from this
// trigger only — the login self-heal and the population sweep still reach
// them, which is the same guarantee that covered a webhook delivery Auth0 gave
// up redelivering.
const maxEventAttempts = 5

// Consumer reads the Auth0 events stream and provisions the users it names.
//
// Exactly one replica may run it. The stream has no competing-consumer
// semantics: every connection receives every event, so a second reader
// duplicates work rather than sharing it.
type Consumer struct {
	events       auth0.EventsClient
	provisioner  Orchestrator
	offsets      OffsetStore
	eventTypes   []string
	replayWindow time.Duration
	now          func() time.Time

	// Failure bookkeeping for the message currently being retried.
	failedOffset string
	failedCount  int
}

// ConsumerOption configures the consumer.
type ConsumerOption func(*Consumer)

// WithEventsClient sets the Auth0 events stream reader.
func WithEventsClient(client auth0.EventsClient) ConsumerOption {
	return func(c *Consumer) { c.events = client }
}

// WithProvisioner sets the orchestrator each event is handed to.
func WithProvisioner(orchestrator Orchestrator) ConsumerOption {
	return func(c *Consumer) { c.provisioner = orchestrator }
}

// WithOffsetStore sets where the stream position is persisted.
func WithOffsetStore(store OffsetStore) ConsumerOption {
	return func(c *Consumer) { c.offsets = store }
}

// WithEventTypes narrows the subscription.
func WithEventTypes(types ...string) ConsumerOption {
	return func(c *Consumer) { c.eventTypes = types }
}

// WithReplayWindow sets how far back the consumer starts with no usable offset.
func WithReplayWindow(window time.Duration) ConsumerOption {
	return func(c *Consumer) { c.replayWindow = window }
}

// NewConsumer creates the events consumer.
func NewConsumer(options ...ConsumerOption) (*Consumer, error) {
	consumer := &Consumer{
		eventTypes:   []string{EventTypeUserCreated, EventTypeUserUpdated},
		replayWindow: 24 * time.Hour,
		now:          time.Now,
	}
	for _, option := range options {
		option(consumer)
	}

	switch {
	case consumer.events == nil:
		return nil, errs.NewValidation("an events client is required")
	case consumer.provisioner == nil:
		return nil, errs.NewValidation("a provisioning orchestrator is required")
	case consumer.offsets == nil:
		return nil, errs.NewValidation("an offset store is required")
	}

	return consumer, nil
}

// Run reads the stream until ctx is cancelled, reconnecting as needed.
func (c *Consumer) Run(ctx context.Context) {
	backoff := minReconnectBackoff

	for ctx.Err() == nil {
		opts, err := c.subscribeOptions(ctx)
		if err != nil {
			slog.ErrorContext(ctx, "could not read the stored events offset", "error", err)
			if !sleep(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}

		slog.InfoContext(ctx, "connecting to the Auth0 events stream",
			"resuming", opts.From != "",
			"from_timestamp", opts.FromTimestamp,
			"event_types", opts.EventTypes,
		)

		err = c.events.Subscribe(ctx, opts, c.handle)
		switch {
		case ctx.Err() != nil:
			return

		case err == nil:
			// Auth0 cycles connections for load balancing. Reconnecting at
			// once is expected; backing off here would idle the consumer for
			// no reason every few minutes.
			backoff = minReconnectBackoff
			continue

		case errors.Is(err, auth0.ErrOffsetExpired):
			// Auth0 has aged our position out of the stream. Restarting from
			// the replay window re-reads more than needed, which the gate
			// absorbs, rather than skipping whatever fell in the gap.
			slog.WarnContext(ctx, "stored events offset has expired, restarting from the replay window",
				"replay_window", c.replayWindow,
			)
			c.forgetFailedEvent()
			if errClear := c.offsets.Clear(ctx); errClear != nil {
				// The dead offset is still stored, so reconnecting now would
				// present it again and earn the same rejection.
				slog.ErrorContext(ctx, "could not clear the expired events offset", "error", errClear)
				if !sleep(ctx, backoff) {
					return
				}
				backoff = nextBackoff(backoff)
				continue
			}
			backoff = minReconnectBackoff
			continue
		}

		wait := backoff
		var rateLimited *auth0.RateLimitedError
		if errors.As(err, &rateLimited) && rateLimited.RetryAfter > 0 {
			wait = rateLimited.RetryAfter
		}

		slog.ErrorContext(ctx, "Auth0 events stream ended, reconnecting",
			"error", err,
			"retry_in", wait,
		)
		if !sleep(ctx, wait) {
			return
		}
		backoff = nextBackoff(backoff)
	}
}

// subscribeOptions decides where the next connection resumes from.
func (c *Consumer) subscribeOptions(ctx context.Context) (auth0.SubscribeOptions, error) {
	offset, err := c.offsets.Load(ctx)
	if err != nil {
		return auth0.SubscribeOptions{}, err
	}

	opts := auth0.SubscribeOptions{
		From:       offset,
		EventTypes: c.eventTypes,
	}
	if offset == "" {
		// Without one of these the stream starts at the latest events and
		// silently skips everything that happened while we were away.
		opts.FromTimestamp = c.now().Add(-c.replayWindow)
	}
	return opts, nil
}

// handle processes one message from the stream.
//
// Returning an error ends the connection without advancing the offset, so the
// next connection replays from the last message that was fully processed.
func (c *Consumer) handle(ctx context.Context, message auth0.EventMessage) error {
	switch message.Type {
	case auth0.EventTypeOffsetOnly:
		// Carries no event, but it does move the position. Recording it is
		// what keeps a quiet stream from replaying the whole window on the
		// next reconnect.
		return c.offsets.Save(ctx, message.Offset)

	case auth0.EventTypeError:
		// The client surfaces this as a terminal error from Subscribe. Not
		// advancing means the message is seen again, which is correct: it says
		// nothing about the event that follows it.
		return nil
	}

	// The shape is logged, not the contents: an Auth0 user event carries
	// email, username and user id in cleartext. Keys are enough to tell a
	// wrong field path from a genuinely absent field.
	slog.DebugContext(ctx, "received Auth0 event",
		"event_type", message.Type,
		"data_bytes", len(message.Data),
		"data_keys", topLevelKeys(message.Data),
	)

	event, user, err := provisionRequest(message)
	if err != nil {
		// Re-reading the same bytes cannot help, so move past it rather than
		// reconnecting onto the same failure.
		slog.WarnContext(ctx, "skipping unparseable Auth0 event",
			"error", err,
			"event_type", message.Type,
		)
		c.count(ctx, event, "", "rejected")
		return c.offsets.Save(ctx, message.Offset)
	}

	request := user.ToRequest()

	slog.InfoContext(ctx, "processing Auth0 event",
		"event_id", event.ID,
		"event_type", event.Type,
		"user_id", redaction.Redact(request.UserID),
		"email_verified", payloadFlag(request.EmailVerified),
		"has_cdp_uuid", request.StoredCDPUUID != "",
		"has_database_identity", request.HasDatabaseIdentity,
	)

	result, err := c.provisioner.Provision(ctx, request)
	if err != nil {
		var validation errs.Validation
		if errors.As(err, &validation) {
			slog.WarnContext(ctx, "skipping invalid Auth0 event",
				"error", err,
				"event_id", event.ID,
			)
			c.count(ctx, event, request.UserID, "rejected")
			return c.offsets.Save(ctx, message.Offset)
		}

		if c.exhausted(message.Offset) {
			slog.ErrorContext(ctx, "giving up on an event after repeated failures, moving past it",
				"error", err,
				"event_id", event.ID,
				"user_id", redaction.Redact(request.UserID),
				"attempts", maxEventAttempts,
			)
			c.count(ctx, event, request.UserID, "abandoned")
			c.forgetFailedEvent()
			return c.offsets.Save(ctx, message.Offset)
		}

		slog.ErrorContext(ctx, "provisioning failed, reconnecting to retry the event",
			"error", err,
			"event_id", event.ID,
			"user_id", redaction.Redact(request.UserID),
			"attempt", c.failedCount,
		)
		c.count(ctx, event, request.UserID, "failed")
		return err
	}

	c.forgetFailedEvent()

	slog.InfoContext(ctx, "completed Auth0 event",
		"event_id", event.ID,
		"event_type", event.Type,
		"user_id", redaction.Redact(request.UserID),
		"outcome", string(result.Outcome),
		"reason", result.Reason,
	)
	c.count(ctx, event, request.UserID, string(result.Outcome))

	return c.offsets.Save(ctx, message.Offset)
}

// exhausted reports whether this offset has failed too many times to keep
// blocking the stream on it.
func (c *Consumer) exhausted(offset string) bool {
	if c.failedOffset != offset {
		c.failedOffset = offset
		c.failedCount = 0
	}
	c.failedCount++
	return c.failedCount >= maxEventAttempts
}

// forgetFailedEvent resets the retry bookkeeping. It does not touch the stored
// offset — clearing that is OffsetStore.Clear.
func (c *Consumer) forgetFailedEvent() {
	c.failedOffset = ""
	c.failedCount = 0
}

// count emits the delivery trace.
//
// A stream that has stopped delivering is otherwise indistinguishable from a
// quiet one, so received and processed counts are what make silence readable.
func (c *Consumer) count(ctx context.Context, event Event, userID, outcome string) {
	slog.InfoContext(ctx, "provisioning event delivery",
		"metric", "provisioning_event",
		"event_id", event.ID,
		"event_type", event.Type,
		"user_id", redaction.Redact(userID),
		"outcome", outcome,
	)
}

func provisionRequest(message auth0.EventMessage) (Event, EventUser, error) {
	return ParseStreamMessage(message.Data)
}

// topLevelKeys returns the top-level keys of a JSON object, or nil when the
// payload is not one. It makes a field-path mismatch visible without logging
// any of the user data the payload carries.
func topLevelKeys(body []byte) []string {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err != nil {
		return nil
	}

	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	return keys
}

// payloadFlag renders a nullable payload flag so an absent field reads as
// absent rather than as false. Telling those two apart is what says whether
// the assumed field path is the right one.
func payloadFlag(value *bool) string {
	if value == nil {
		return "absent"
	}
	return strconv.FormatBool(*value)
}

func nextBackoff(current time.Duration) time.Duration {
	doubled := current * 2
	if doubled > maxReconnectBackoff {
		return maxReconnectBackoff
	}
	return doubled
}

// sleep waits for d, reporting false when the context ended first.
func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
