// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package holderwalk enumerates every Auth0 user carrying a stored cdp_uuid.
// Both CDP repair commands (the Release Gate sampler and the scheduled
// merge-repair job) walk through this one implementation, so the keyset
// pagination past Auth0's 1,000-result offset cap and the tie-block drain
// exist exactly once.
package holderwalk

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

// TokenProvider supplies a bearer token for the Auth0 Management API.
type TokenProvider interface {
	GetToken(ctx context.Context) (string, error)
}

// Holder is one enumerated user carrying a stored cdp_uuid.
type Holder struct {
	UserID        string
	Username      string // blank when no database-connection identity (primary or linked) carries an LFID
	Email         string
	EmailVerified bool
	StoredUUID    string // lowercased, as the writers store it
}

// MgmtUser is the slice of an Auth0 Management user the walk reads. Exported
// because command tests serve fixture rows over httptest.
type MgmtUser struct {
	UserID        string         `json:"user_id"`
	Username      string         `json:"username"`
	Email         string         `json:"email"`
	EmailVerified bool           `json:"email_verified"`
	UpdatedAt     string         `json:"updated_at"`
	AppMetadata   map[string]any `json:"app_metadata"`
	Identities    []MgmtIdentity `json:"identities,omitempty"`
}

// MgmtIdentity is the slice of an Auth0 identity the walk reads: only the
// connection and the user id, which is what derives an LFID from a linked
// database identity on a social- or enterprise-primary user.
type MgmtIdentity struct {
	Connection string `json:"connection"`
	UserID     any    `json:"user_id"`
}

// Walker enumerates every user carrying a stored cdp_uuid.
type Walker struct {
	HTTPClient *httpclient.Client
	Domain     string
	Tokens     TokenProvider

	// RetryBackoff overrides the initial retry backoff; zero means the
	// production default. Tests shrink it to keep retry paths fast.
	RetryBackoff time.Duration

	// now supplies the walk's start time; nil means time.Now. Tests pin it so
	// the number of windows to the open-ended last one is fixed.
	now func() time.Time
}

// errSearchUnavailable marks a 503 from a walk page returned without
// retrying, so the walk can narrow its window instead of re-sending a search
// too heavy for Auth0 to finish.
var errSearchUnavailable = errors.New("user search unavailable")

const (
	walkPageSize = 100

	// walkOffsetLimit is Auth0's hard window: user search rejects reading
	// past the 1,000th result of one query.
	walkOffsetLimit = 1000

	// walkInitialBound predates every Auth0 user, so the first page starts at
	// the beginning of the population.
	walkInitialBound = "1970-01-01T00:00:00.000Z"

	// Auth0 user search runs under a short query time limit and answers a
	// search too heavy for it with a 503 (an HTML error page, so the cause is
	// not readable from the body). On the production tenant the unbounded
	// first search from walkInitialBound is that heavy
	// (linuxfoundation/lfx-self-serve-ops#2007), so the walk bounds searches
	// above by a window once one is rejected: a 503 halves the window and
	// re-issues at once. A window walked to its end doubles the next one —
	// without limit while windows come back empty, so the years before any
	// holder are crossed in a few searches, and up to walkMaxWindow once they
	// hold rows. At walkMinWindow a 503 is no longer taken for the query's
	// weight and gets the ordinary backoff retries instead.
	walkMaxWindow = 30 * 24 * time.Hour
	walkMinWindow = time.Minute

	// updatedAtLayout is the millisecond UTC form Auth0 returns updated_at
	// in, used for the window bounds the walk computes itself.
	updatedAtLayout = "2006-01-02T15:04:05.000Z"

	// holderQuery selects every user carrying the stored key. Wildcard
	// searches are not supported on app_metadata fields; `_exists_` is the
	// documented existence operator.
	holderQuery = "_exists_:app_metadata.cdp_uuid"

	// drainPasses bounds re-reads of one tie block whose collected rows keep
	// falling short of the server's total.
	drainPasses = 3

	// mgmtMaxAttempts bounds retries of one page against Management 429s and
	// transient failures.
	mgmtMaxAttempts = 8

	// databaseUserIDPrefix marks a user whose primary identity is the database
	// connection — the case where the root `username` is an LFID outright.
	// Otherwise the LFID is derived from a linked database identity. That is
	// deliberately wider than ReadProvisioningState's primary-only guard
	// (internal/infrastructure/auth0/cdp_metadata.go), which leaves those
	// users username-less: provisioning never provisions them, while the
	// repair job still checks their stored UUIDs (writing only CAS-guarded
	// own-only repairs).
	databaseUserIDPrefix = "auth0|"
)

// linkedDatabaseUsername returns the LFID of a linked database identity, or
// "" when there is none. Mirrors the login username filter
// (internal/infrastructure/auth0/filter.go): only the database connection
// carries an LFID user id.
func linkedDatabaseUsername(identities []MgmtIdentity) string {
	for _, id := range identities {
		if id.Connection != constants.Auth0UsernamePasswordConnection {
			continue
		}
		if uid, ok := id.UserID.(string); ok {
			return strings.TrimSpace(uid)
		}
	}
	return ""
}

// ListCDPUUIDHolders walks the whole population of users with a stored
// cdp_uuid, also returning the user IDs of records that matched the query but
// carry no usable string value — the caller must report those as
// inconclusive, not silently shrink the population.
//
// Auth0's user search rejects reading past the 1,000th result of a query, so
// plain page-walking cannot reach the population. This walks page 0 of an
// ascending `updated_at` lower bound instead: bound advanced to the last row
// seen, boundary kept inclusive so a timestamp shared across a page edge is
// not skipped, and a seen-set to drop the overlap that inclusivity
// re-presents. A block of users sharing one timestamp that fills a whole page
// cannot advance the bound — and deeper offset pages of one query cannot be
// trusted for completeness, because Auth0 gives ties no guaranteed sub-order
// and separate page requests can reshuffle them. Such a block is drained by
// drainTieBlock, which verifies its row count against the server's own total,
// and the walk resumes with an exclusive bound strictly past the drained
// timestamp.
//
// The first search is the unbounded one. Once Auth0 rejects a search as too
// heavy, searches are bounded above by an adaptive window (see
// walkMaxWindow). A short page ends its window; the window that reaches the
// walk's start time is open-ended, and a short page there ends the walk.
//
// `updated_at` moves when a user logs in, so a user active during the walk can
// migrate across the bound and be missed. Acceptable for drawing a sample;
// a census run should quiesce or re-run.
func (w *Walker) ListCDPUUIDHolders(ctx context.Context) ([]Holder, []string, error) {
	var population []Holder
	var malformed []string
	seen := make(map[string]struct{})

	absorb := func(rows []MgmtUser) {
		for _, row := range rows {
			if _, dup := seen[row.UserID]; dup {
				continue
			}
			seen[row.UserID] = struct{}{}

			stored, _ := row.AppMetadata["cdp_uuid"].(string)
			stored = strings.TrimSpace(stored)
			if stored == "" {
				// The query selects on key existence, so this is a shape
				// surprise that makes the enumeration inconclusive.
				slog.WarnContext(ctx, "user matched _exists_:app_metadata.cdp_uuid but carries no string value",
					"user_id", redaction.Redact(row.UserID))
				malformed = append(malformed, row.UserID)
				continue
			}
			// Trimmed like provisioning trims its resolve inputs — an
			// untrimmed legacy value must not resolve differently here than
			// it would for the writer.
			username := strings.TrimSpace(row.Username)
			if !strings.HasPrefix(row.UserID, databaseUserIDPrefix) {
				// The root username belongs to the primary identity; for a
				// social- or enterprise-primary user it is not an LFID. Fall
				// back to a linked database identity, and blank it only when
				// there is none, so the user counts as skipped_no_lfid instead
				// of being resolved as someone else.
				username = linkedDatabaseUsername(row.Identities)
			}
			population = append(population, Holder{
				UserID:        row.UserID,
				Username:      username,
				Email:         strings.TrimSpace(row.Email),
				EmailVerified: row.EmailVerified,
				StoredUUID:    strings.ToLower(stored),
			})
		}
	}

	walkStart := time.Now
	if w.now != nil {
		walkStart = w.now
	}
	start := walkStart().UTC()

	bound := walkInitialBound
	boundAt, err := time.Parse(time.RFC3339Nano, bound)
	if err != nil {
		return nil, nil, fmt.Errorf("population walk initial bound %s: %w", bound, err)
	}
	exclusive := false
	window := start.Sub(boundAt)
	windowEnd := start
	windowHadRows := false
	for fetches := 1; ; fetches++ {
		// The window reaching the walk's start is left open so users updated
		// during the walk stay reachable, as with an unbounded walk.
		openEnded := !windowEnd.Before(start)
		upper := "*"
		remaining := start.Sub(boundAt)
		if !openEnded {
			upper = windowEnd.Format(updatedAtLayout)
			remaining = windowEnd.Sub(boundAt)
		}

		rows, err := w.fetchWalkPage(ctx, bound, exclusive, upper, remaining > walkMinWindow)
		if errors.Is(err, errSearchUnavailable) {
			window = remaining / 2
			windowEnd = boundAt.Add(window)
			slog.WarnContext(ctx, "user search unavailable, narrowing the walk window",
				"bound", bound, "window", window.String())
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("population walk failed at bound %s: %w", bound, err)
		}
		absorb(rows)
		if len(rows) > 0 {
			windowHadRows = true
		}

		if len(rows) < walkPageSize {
			// Page 0 came back short: nothing else matches up to the window's
			// end.
			if openEnded {
				break
			}
			// The window's exclusive upper bound becomes the next inclusive
			// lower bound, so no timestamp falls between windows.
			bound, boundAt, exclusive = upper, windowEnd, false
			window *= 2
			if windowHadRows {
				window = min(window, walkMaxWindow)
			}
			windowHadRows = false
			windowEnd = boundAt.Add(window)
			continue
		}

		nextBound := rows[len(rows)-1].UpdatedAt
		if nextBound == bound {
			if exclusive {
				// An exclusive lower bound must move strictly past itself; a
				// server ignoring it would loop this walk forever.
				return nil, nil, fmt.Errorf("population walk stalled: exclusive bound %s not honored", bound)
			}
			tieRows, errDrain := w.drainTieBlock(ctx, bound)
			if errDrain != nil {
				return nil, nil, errDrain
			}
			absorb(tieRows)
			exclusive = true
			continue
		}
		nextAt, err := time.Parse(time.RFC3339Nano, nextBound)
		if err != nil {
			return nil, nil, fmt.Errorf("population walk cannot advance past updated_at %q: %w", nextBound, err)
		}
		exclusive = false
		bound, boundAt = nextBound, nextAt

		if fetches%10 == 0 {
			slog.InfoContext(ctx, "population walk progress", "pages", fetches, "users", len(population))
		}
	}

	return population, malformed, nil
}

// drainTieBlock enumerates every holder sharing one exact updated_at. Deeper
// offset pages of one query are the only way in, and Auth0 gives ties no
// stable sub-order across requests, so separate page reads can reshuffle rows
// and silently omit some. The server's own total makes that detectable:
// passes repeat until the distinct rows collected reach it, and a block this
// walk cannot prove complete fails the enumeration instead of passing as an
// incomplete sampling frame. Rows come back sorted by user ID so the drain's
// contribution to the population order is deterministic.
func (w *Walker) drainTieBlock(ctx context.Context, ts string) ([]MgmtUser, error) {
	collected := make(map[string]MgmtUser)
	total := 0
	for pass := 1; pass <= drainPasses; pass++ {
		for page := 0; ; page++ {
			rows, pageTotal, err := w.fetchTiePage(ctx, ts, page)
			if err != nil {
				return nil, fmt.Errorf("tie-block drain failed at updated_at %s: %w", ts, err)
			}
			total = pageTotal
			if total >= walkOffsetLimit {
				// Auth0 caps the reported total at the same 1,000-result
				// window, so a block at the cap cannot be told apart from a
				// larger one; fail closed instead of passing a possibly
				// incomplete frame.
				return nil, fmt.Errorf("population walk cannot enumerate %d users sharing updated_at %s: at or past Auth0's %d-result window", total, ts, walkOffsetLimit)
			}
			for _, row := range rows {
				collected[row.UserID] = row
			}
			if len(rows) < walkPageSize || (page+1)*walkPageSize >= total {
				break
			}
		}
		if len(collected) >= total {
			rows := make([]MgmtUser, 0, len(collected))
			for _, row := range collected {
				rows = append(rows, row)
			}
			sort.Slice(rows, func(i, j int) bool { return rows[i].UserID < rows[j].UserID })
			return rows, nil
		}
		slog.WarnContext(ctx, "tie-block drain came up short, re-reading",
			"updated_at", ts, "collected", len(collected), "total", total, "pass", pass)
	}
	return nil, fmt.Errorf("tie-block drain at updated_at %s incomplete after %d passes: %d of %d users seen", ts, drainPasses, len(collected), total)
}

// fetchWalkPage reads page 0 above bound, up to upper ("*" for none). With
// narrowable set, a 503 returns errSearchUnavailable at once so the walk can
// shrink the window instead of retrying the same search.
func (w *Walker) fetchWalkPage(ctx context.Context, bound string, exclusive bool, upper string, narrowable bool) ([]MgmtUser, error) {
	// The exclusive open bracket steps strictly past a fully drained tie
	// block; everywhere else the bound stays inclusive so a timestamp shared
	// across a page edge is not skipped.
	open := "["
	if exclusive {
		open = "{"
	}
	// A window's upper bound is exclusive: a row stamped exactly at it
	// belongs to the next window, which starts there inclusively.
	closing := "]"
	if upper != "*" {
		closing = "}"
	}
	q := fmt.Sprintf("%s AND updated_at:%s%s TO %s%s", holderQuery, open, bound, upper, closing)
	var rows []MgmtUser
	if err := w.searchUsers(ctx, q, 0, false, narrowable, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

// mgmtUserPage is the include_totals=true response envelope.
type mgmtUserPage struct {
	Total int        `json:"total"`
	Users []MgmtUser `json:"users"`
}

func (w *Walker) fetchTiePage(ctx context.Context, ts string, page int) ([]MgmtUser, int, error) {
	q := fmt.Sprintf("%s AND updated_at:[%s TO %s]", holderQuery, ts, ts)
	var envelope mgmtUserPage
	if err := w.searchUsers(ctx, q, page, true, false, &envelope); err != nil {
		return nil, 0, err
	}
	return envelope.Users, envelope.Total, nil
}

func (w *Walker) searchUsers(ctx context.Context, q string, page int, includeTotals, narrowable bool, out any) error {
	params := url.Values{}
	params.Set("q", q)
	params.Set("sort", "updated_at:1")
	params.Set("page", fmt.Sprintf("%d", page))
	params.Set("per_page", fmt.Sprintf("%d", walkPageSize))
	params.Set("include_totals", fmt.Sprintf("%t", includeTotals))
	params.Set("search_engine", "v3")
	params.Set("fields", "user_id,username,email,email_verified,updated_at,app_metadata,identities")
	params.Set("include_fields", "true")

	backoff := w.RetryBackoff
	if backoff == 0 {
		backoff = 2 * time.Second
	}
	for attempt := 1; ; attempt++ {
		token, err := w.Tokens.GetToken(ctx)
		if err != nil {
			return fmt.Errorf("failed to get Management API token: %w", err)
		}

		request := httpclient.NewAPIRequest(
			w.HTTPClient,
			httpclient.WithMethod(http.MethodGet),
			httpclient.WithURL(fmt.Sprintf("https://%s/api/v2/users?%s", w.Domain, params.Encode())),
			httpclient.WithToken(token),
			httpclient.WithDescription("list cdp_uuid holders"),
		)

		statusCode, errCall := request.Call(ctx, out)
		if errCall == nil {
			return nil
		}
		if narrowable && statusCode == http.StatusServiceUnavailable {
			return fmt.Errorf("%w: status code: %d", errSearchUnavailable, statusCode)
		}
		if attempt >= mgmtMaxAttempts {
			return fmt.Errorf("status code: %d after %d attempts: %w", statusCode, attempt, errCall)
		}
		// Call reports a negative status when no usable response arrived
		// (transport failure, decode failure); retry those like a 5xx.
		if statusCode >= 0 && statusCode != http.StatusTooManyRequests && statusCode < 500 {
			return fmt.Errorf("status code: %d: %w", statusCode, errCall)
		}

		slog.WarnContext(ctx, "Management API page retry",
			"status_code", statusCode, "attempt", attempt, "backoff", backoff.String())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}
