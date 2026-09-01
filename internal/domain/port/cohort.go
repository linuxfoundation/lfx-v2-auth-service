// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package port

import (
	"context"
	"time"
)

// CohortUser is the subset of an Auth0 user the out-of-band CDP jobs read.
//
// It carries the stored enrichment record alongside the identifiers a resolve
// needs, so selecting a population and deciding what to send are one read
// rather than two.
type CohortUser struct {
	CDPMetadata

	// UserID is the Auth0 user id, used to write back.
	UserID string

	// Username is the LFID. `/v1/members/resolve` requires at least one, so a
	// user without one cannot be resolved and is skipped rather than sent.
	Username string

	// Email is the user's primary email.
	Email string

	// EmailVerified reports whether Email may be sent as a secondary resolve
	// identifier (FR-003a).
	EmailVerified bool

	// UpdatedAt is when Auth0 last changed the record. The sweep sorts and
	// keysets on it; it is the sole input to the cursor.
	UpdatedAt time.Time
}

// UserSearch describes one page of an Auth0 Management user search.
type UserSearch struct {
	// Query is the Lucene expression, sent verbatim.
	Query string

	// Page is the zero-based page index.
	//
	// Auth0 caps offset paging at 1000 results and truncates silently past it,
	// so a caller walking a large population MUST move a keyset lower bound
	// inside Query rather than increment this. It exists for the bounded probe
	// the sweep uses to step over a search index that has not caught up yet.
	Page int

	// PerPage is the page size.
	PerPage int
}

// UserSearcher runs an Auth0 Management user search.
//
// Separate from CDPMetadataReader because it selects a population rather than
// reading one known user: the jobs search to find whom to call, then read each
// user by id before writing.
type UserSearcher interface {
	SearchUsers(ctx context.Context, search UserSearch) ([]CohortUser, error)
}
