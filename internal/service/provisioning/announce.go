// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package provisioning

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	errs "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

// UserEmailVerifiedEvent is published on constants.UserEmailVerifiedSubject the
// first time a user is seen with a verified primary email.
//
// It is a notification, not a credential: it travels over an unauthenticated
// bus, so a consumer that acts on it should re-resolve the email through this
// service before trusting the username.
type UserEmailVerifiedEvent struct {
	// Username is the user's LFID.
	Username string `json:"username"`

	// Email is the user's verified primary email.
	Email string `json:"email"`

	// Timestamp is when the event was published.
	Timestamp time.Time `json:"timestamp"`
}

// Announcer publishes the user_email_verified event for a user.
type Announcer interface {
	// Announce publishes the event when the user qualifies and has not been
	// announced before. It is best-effort: a failure is logged and the next
	// stream event for the user tries again, so it never returns an error.
	Announce(ctx context.Context, req Request)
}

type announcer struct {
	store     port.UserAnnouncementStore
	publisher port.ConfirmedEventPublisher
	now       func() time.Time
}

// NewAnnouncer creates the announcer.
func NewAnnouncer(store port.UserAnnouncementStore, publisher port.ConfirmedEventPublisher) (Announcer, error) {
	if store == nil {
		return nil, errs.NewValidation("an announcement store is required")
	}
	if publisher == nil {
		return nil, errs.NewValidation("an event publisher is required")
	}
	return &announcer{store: store, publisher: publisher, now: time.Now}, nil
}

// Announce runs the cheap payload pre-filter, re-reads the user from Auth0, then
// publishes and records the marker.
//
// The marker is written only after the server confirms the publish, so a failed publish
// is retried on the user's next stream event. The reverse failure, a publish
// that succeeded followed by a marker write that failed, can announce a user
// twice, which consumers must tolerate: the stream itself is at-least-once.
func (a *announcer) Announce(ctx context.Context, req Request) {
	// Only an explicit false is skipped here. The stream fires on every user
	// mutation, and a payload that omits the flag is unknown rather than
	// unverified, so it goes on to the Auth0 re-check below.
	if req.EmailVerified != nil && !*req.EmailVerified {
		return
	}
	if strings.TrimSpace(req.UserID) == "" || strings.TrimSpace(req.AnnouncedAt) != "" {
		return
	}

	state, err := a.store.ReadAnnouncementState(ctx, req.UserID)
	if err != nil {
		slog.WarnContext(ctx, "could not read user to announce verified email",
			"error", err,
			"user_id", redaction.Redact(req.UserID),
		)
		return
	}

	// The payload is a snapshot, so every field that decides whether to
	// announce is checked again against the record.
	if !state.EmailVerified || strings.TrimSpace(state.AnnouncedAt) != "" {
		return
	}
	username := strings.TrimSpace(state.Username)
	email := strings.TrimSpace(state.Email)
	if username == "" || email == "" {
		// Not a database-connection user, so there is no LFID to announce.
		slog.DebugContext(ctx, "user has no LFID username or email, not announcing",
			"user_id", redaction.Redact(req.UserID),
		)
		return
	}

	now := a.now().UTC()
	data, err := json.Marshal(UserEmailVerifiedEvent{Username: username, Email: email, Timestamp: now})
	if err != nil {
		slog.WarnContext(ctx, "failed to marshal user email verified event",
			"error", err,
			"user_id", redaction.Redact(req.UserID),
		)
		return
	}

	if err := a.publisher.PublishConfirmed(ctx, constants.UserEmailVerifiedSubject, data); err != nil {
		slog.WarnContext(ctx, "failed to publish user email verified event",
			"error", err,
			"user_id", redaction.Redact(req.UserID),
		)
		return
	}

	if err := a.store.MarkAnnounced(ctx, req.UserID, now.Format(time.RFC3339)); err != nil {
		slog.WarnContext(ctx, "published user email verified event but could not record it, it may be sent again",
			"error", err,
			"user_id", redaction.Redact(req.UserID),
		)
	}
}
