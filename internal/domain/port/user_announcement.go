// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package port

import "context"

// UserAnnouncementState is the authoritative view of a user needed to decide
// whether to announce their verified email, read from Auth0 rather than taken
// from an event payload that may be stale or replayed.
type UserAnnouncementState struct {
	// EmailVerified is the user's current verification state.
	EmailVerified bool

	// Email is the user's current primary email.
	Email string

	// Username is the LFID. It is populated only when the user's primary
	// identity is the database connection, since another connection's
	// username is not an LFID.
	Username string

	// AnnouncedAt is the RFC3339 time the user was last announced, empty when
	// they never have been.
	AnnouncedAt string
}

// UserAnnouncementStore reads and records whether a user's verified email has
// been announced.
type UserAnnouncementStore interface {
	// ReadAnnouncementState returns the user's current announcement state.
	ReadAnnouncementState(ctx context.Context, userID string) (UserAnnouncementState, error)

	// MarkAnnounced records that the user has been announced at the given
	// RFC3339 time. Only that key is written.
	MarkAnnounced(ctx context.Context, userID, announcedAt string) error
}
