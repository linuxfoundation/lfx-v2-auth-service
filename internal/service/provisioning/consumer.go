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
	"sync"
	"sync/atomic"
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
// them.
const maxEventAttempts = 5

// maxBarrenReconnects bounds how many times the consumer will reconnect from
// the same offset, each time failing without reading a single message, before
// it treats that offset as poisoned and falls back to the replay window.
//
// This is the shape-independent half of the expired-offset defence. A 410
// arrives before the stream opens and is unambiguous, but Auth0 also ends an
// established stream with an in-band `event: error` that it documents as
// covering "an expired offset or a server-side problem" without documenting
// how to tell those apart. Rather than guess at a payload shape that cannot be
// verified, the consumer watches its own progress: an offset that produces
// nothing but failed connections is unusable whatever the reason, so this also
// catches any other way a cursor can become permanently poisoned.
//
// Only failures count. A clean close is Auth0's ordinary load-balancing
// recycle and says nothing about the offset, so a quiet stream cannot trip
// this. A genuine outage can, and the cost of that false positive is one
// bounded replay — which the design already calls cheap, because the gate
// drops anyone already provisioned before any CDP call is made.
const maxBarrenReconnects = 3

// offsetAgeInterval is how often the offset-age gauge is emitted.
const offsetAgeInterval = 1 * time.Minute

// minHealthyConnection is the shortest a clean, empty connection may last
// before it is treated as a fault rather than as Auth0's ordinary recycle.
//
// It is a floor, not an estimate of the rotation interval, and does not need
// to be accurate to be safe: Auth0 holds a stream open for minutes, so no
// genuine rotation comes near a second and nothing on the healthy path is
// delayed by this. What it stops is a peer answering 200 and closing at once,
// which on the immediate-reconnect path spins the reader as fast as the
// network allows.
const minHealthyConnection = 1 * time.Second

// forbiddenRetryInterval is the wait after a 403.
//
// The contract says to surface a 403 for a human rather than retry blindly.
// Auth0 answers it either because the read:events grant is missing, which no
// amount of retrying fixes, or because the tenant's concurrent-connection
// allowance is used up. The second is now unlikely — the tenant is Enterprise,
// so the cap is 8 and this service runs one reader — which makes the grant the
// first thing to check. The stream is not abandoned, because a revoked grant
// can be restored without a redeploy, but it is retried slowly and logged
// loudly enough to be noticed.
const forbiddenRetryInterval = 5 * time.Minute

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

	// Reconnection backoff bounds. Fields rather than constants so tests can
	// exercise the reconnect paths without sleeping through them.
	minBackoff     time.Duration
	maxBackoff     time.Duration
	refusalBackoff time.Duration

	// Failure bookkeeping for the message currently being retried.
	failedOffset string
	failedCount  int

	// Progress bookkeeping for the offset the current connection resumed
	// from. Touched only by Run's goroutine.
	barrenOffset string
	barrenRuns   int
	processed    int

	// lastAdvance is the local-clock time the offset last moved, as UnixNano.
	// The age reporter reads it from another goroutine.
	lastAdvance atomic.Int64
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
		eventTypes:     []string{EventTypeUserCreated, EventTypeUserUpdated},
		replayWindow:   24 * time.Hour,
		now:            time.Now,
		minBackoff:     minReconnectBackoff,
		maxBackoff:     maxReconnectBackoff,
		refusalBackoff: forbiddenRetryInterval,
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

	consumer.lastAdvance.Store(consumer.now().UnixNano())

	return consumer, nil
}

// Run reads the stream until ctx is cancelled, reconnecting as needed.
func (c *Consumer) Run(ctx context.Context) {
	var reporter sync.WaitGroup
	reporter.Add(1)
	go func() {
		defer reporter.Done()
		c.reportOffsetAge(ctx)
	}()
	defer reporter.Wait()

	backoff := c.minBackoff

	for ctx.Err() == nil {
		opts, err := c.subscribeOptions(ctx)
		if err != nil {
			slog.ErrorContext(ctx, "could not read the stored events offset", "error", err)
			if !sleep(ctx, backoff) {
				return
			}
			backoff = c.nextBackoff(backoff)
			continue
		}

		slog.InfoContext(ctx, "connecting to the Auth0 events stream",
			"resuming", opts.From != "",
			"from_timestamp", opts.FromTimestamp,
			"event_types", opts.EventTypes,
			"offset_age_seconds", int64(c.offsetAge().Seconds()),
		)

		processedBefore := c.processed
		openedAt := c.now()
		err = c.events.Subscribe(ctx, opts, c.handle)
		madeProgress := c.processed > processedBefore
		lasted := c.now().Sub(openedAt)

		switch {
		case ctx.Err() != nil:
			return

		case err == nil:
			// Auth0 cycles connections for load balancing. Reconnecting at
			// once is expected; backing off here would idle the consumer for
			// no reason every few minutes. A clean close says nothing about
			// the offset even when it carried no messages, so the barren
			// count starts over.
			c.forgetBarrenOffset()

			if !madeProgress && lasted < minHealthyConnection {
				// A 200 answered and closed immediately is not a rotation. On
				// the immediate-reconnect path it becomes a hot loop that
				// mints a token and opens a connection as fast as the network
				// allows, against an API whose rate limit is shared with other
				// services. The backoff is left to escalate instead.
				slog.WarnContext(ctx, "Auth0 events stream closed immediately without delivering, backing off",
					"lasted", lasted,
					"retry_in", backoff,
				)
				if !sleep(ctx, backoff) {
					return
				}
				backoff = c.nextBackoff(backoff)
				continue
			}

			backoff = c.minBackoff
			continue

		case errors.Is(err, auth0.ErrOffsetExpired):
			// Auth0 has aged our position out of the stream. Restarting from
			// the replay window re-reads more than needed, which the gate
			// absorbs, rather than skipping whatever fell in the gap.
			slog.WarnContext(ctx, "stored events offset has expired, restarting from the replay window",
				"replay_window", c.replayWindow,
			)
			if !c.restartFromReplayWindow(ctx) {
				// The dead offset is still stored, so reconnecting now would
				// present it again and earn the same rejection.
				if !sleep(ctx, backoff) {
					return
				}
				backoff = c.nextBackoff(backoff)
				continue
			}
			backoff = c.minBackoff
			continue
		}

		// The connection failed. If it also read nothing, and the one before
		// it did the same from this offset, the offset itself is the common
		// factor — which is the only signal available when Auth0 ends an
		// established stream in-band without documenting how to read why.
		//
		// Refusals and rate limits are excluded. A 401, 403 or 429 is answered
		// before the offset is ever looked at, so counting them would throw
		// away a perfectly good position over a missing grant or a busy
		// minute, and buy a needless replay once it clears.
		limited, isRateLimited := rateLimit(err)
		if !refused(err) && !isRateLimited && c.barren(opts.From, madeProgress) {
			slog.ErrorContext(ctx, "events offset has produced only failed connections, restarting from the replay window",
				"error", err,
				"attempts", maxBarrenReconnects,
				"replay_window", c.replayWindow,
			)
			if c.restartFromReplayWindow(ctx) {
				backoff = c.minBackoff
				continue
			}
		}

		wait := backoff
		switch {
		case isRateLimited:
			// Either end can rate limit: Auth0 refusing the stream connection,
			// or CDP refusing a call while an event was being provisioned.
			// Both mean wait rather than press on, and neither is the current
			// event's fault, so handle counted no attempt against it.
			if limited.RetryAfter > 0 {
				wait = limited.RetryAfter
			}
			slog.WarnContext(ctx, "rate limited, pausing before reconnecting",
				"error", err,
				"retry_after", limited.RetryAfter,
				"retry_in", wait,
			)
			if !sleep(ctx, wait) {
				return
			}
			// With no Retry-After to honour the backoff still has to grow, or
			// a limit that outlasts one wait is met at the same interval
			// forever.
			backoff = c.nextBackoff(backoff)
			continue

		case refused(err):
			// Named rather than left to the generic line, because the two
			// causes need different people and the ordinary reconnect message
			// would bury both under a stream that looks merely flaky.
			wait = c.refusalBackoff
			slog.ErrorContext(ctx, "Auth0 refused the events stream, needs a human",
				"error", err,
				"causes", "the read:events grant is missing or was revoked, or the tenant's concurrent connection allowance is used up (Enterprise: 8, this service uses 1)",
				"retry_in", wait,
			)
			if !sleep(ctx, wait) {
				return
			}
			continue
		}

		slog.ErrorContext(ctx, "Auth0 events stream ended, reconnecting",
			"error", err,
			"retry_in", wait,
		)
		if !sleep(ctx, wait) {
			return
		}
		backoff = c.nextBackoff(backoff)
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
	if message.Type == auth0.EventTypeError {
		// The client surfaces this as a terminal error from Subscribe. Not
		// advancing means the message is seen again, which is correct: it says
		// nothing about the event that follows it.
		//
		// Deliberately not counted as progress. It is the failure itself, and
		// a poisoned offset delivers exactly one of these per connection —
		// counting it would tell the barren guard the offset is fine and
		// disable the very defence it exists to provide.
		return nil
	}

	c.processed++

	if message.Type == auth0.EventTypeOffsetOnly {
		// Carries no event, but it does move the position. Recording it is
		// what keeps a quiet stream from replaying the whole window on the
		// next reconnect.
		return c.advance(ctx, message.Offset)
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
		return c.advance(ctx, message.Offset)
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
			return c.advance(ctx, message.Offset)
		}

		// A rate limit is the shared CDP budget being spent elsewhere, not a
		// defect in this event, so it must not consume one of the event's
		// bounded attempts — a window outlasting the ceiling would otherwise
		// abandon every user in front of the reader for as long as it held.
		// Returning ends the connection and hands the wait to Run, which
		// honours Retry-After before resuming from this same offset.
		var rateLimited errs.RateLimited
		if errors.As(err, &rateLimited) {
			slog.WarnContext(ctx, "provisioning is rate limited, this event will be retried after the wait",
				"event_id", event.ID,
				"user_id", redaction.Redact(request.UserID),
				"retry_after", rateLimited.RetryAfter,
			)
			c.count(ctx, event, request.UserID, "rate_limited")
			return err
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
			return c.advance(ctx, message.Offset)
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

	// Only the event that was failing clears the count. Delivery is
	// at-least-once, so a reconnect replays events that already succeeded
	// ahead of the one that did not; clearing on any of those would hold the
	// poison event at attempt one forever and the ceiling would never arrive.
	if message.Offset == c.failedOffset {
		c.forgetFailedEvent()
	}

	slog.InfoContext(ctx, "completed Auth0 event",
		"event_id", event.ID,
		"event_type", event.Type,
		"user_id", redaction.Redact(request.UserID),
		"outcome", string(result.Outcome),
		"reason", result.Reason,
	)
	c.count(ctx, event, request.UserID, string(result.Outcome))

	return c.advance(ctx, message.Offset)
}

// restartFromReplayWindow drops the stored offset so the next connection falls
// back to the replay window. It reports whether the offset is actually gone —
// a caller that gets false must back off rather than reconnect onto it again.
func (c *Consumer) restartFromReplayWindow(ctx context.Context) bool {
	if err := c.offsets.Clear(ctx); err != nil {
		// The bookkeeping is left standing on purpose. It is what makes the
		// next failed connection ask for the clear again, instead of waiting
		// out another full count with the dead offset still stored.
		slog.ErrorContext(ctx, "could not clear the unusable events offset", "error", err)
		return false
	}

	c.forgetFailedEvent()
	c.forgetBarrenOffset()
	return true
}

// barren records a connection that failed, and reports whether this offset has
// now failed that way often enough to be treated as unusable.
func (c *Consumer) barren(from string, madeProgress bool) bool {
	if from == "" || madeProgress {
		// Nothing to hold against the offset: either the consumer is already
		// on the replay window, or the stream did deliver from it.
		c.forgetBarrenOffset()
		return false
	}

	if c.barrenOffset != from {
		c.barrenOffset = from
		c.barrenRuns = 0
	}
	c.barrenRuns++

	return c.barrenRuns >= maxBarrenReconnects
}

func (c *Consumer) forgetBarrenOffset() {
	c.barrenOffset = ""
	c.barrenRuns = 0
}

// rateLimit returns the rate-limit error carried by err, if it carries one.
func rateLimit(err error) (errs.RateLimited, bool) {
	var limited errs.RateLimited
	return limited, errors.As(err, &limited)
}

// refused reports whether Auth0 turned the subscription away before it read
// the offset, which is a grant or capacity problem rather than a stream one.
func refused(err error) bool {
	var (
		forbidden    errs.Forbidden
		unauthorized errs.Unauthorized
	)
	return errors.As(err, &forbidden) || errors.As(err, &unauthorized)
}

// recordAdvance marks the position as having moved.
func (c *Consumer) recordAdvance() {
	c.lastAdvance.Store(c.now().UnixNano())
}

// offsetAge is the time since the offset last moved.
//
// Measured on the local clock and updated by every message, offset-only
// markers included, rather than from an event's own `time` field: those
// markers carry no event and are precisely what keeps a quiet stream's
// position fresh, so an event-time derivation would climb on a perfectly
// healthy idle consumer and spike again through an ordinary replay.
func (c *Consumer) offsetAge() time.Duration {
	return c.now().Sub(time.Unix(0, c.lastAdvance.Load()))
}

// reportOffsetAge emits the stall signal until ctx ends.
//
// Leadership and connection state already show a consumer that has fallen
// over. This is the one that separates a connected-but-stalled reader from a
// quiet stream, which look identical on every other signal.
func (c *Consumer) reportOffsetAge(ctx context.Context) {
	ticker := time.NewTicker(offsetAgeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			slog.InfoContext(ctx, "provisioning offset age",
				"metric", "provisioning_offset_age",
				"age_seconds", int64(c.offsetAge().Seconds()),
			)
		}
	}
}

// advance persists the offset and records that the position moved.
func (c *Consumer) advance(ctx context.Context, offset string) error {
	if err := c.offsets.Save(ctx, offset); err != nil {
		return err
	}
	c.recordAdvance()
	return nil
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

func (c *Consumer) nextBackoff(current time.Duration) time.Duration {
	doubled := current * 2
	if doubled > c.maxBackoff {
		return c.maxBackoff
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
