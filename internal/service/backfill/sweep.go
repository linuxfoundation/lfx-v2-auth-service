// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package backfill

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/cdp"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	errs "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

// CohortQueryTemplate is a VERBATIM marked copy of the canonical population
// query.
//
// SOURCE OF TRUTH:
// specs/001-cdp-uuid-to-segment/decisions/2026-07-cdp-no-match-representation.md §5
//
// Do not paraphrase it, reorder its clauses, or "fix" the leading connection
// filter. Excluding social and enterprise-only users is deliberate and
// measured: 2,272 users, 3.2% of the cohort, ZERO of whom hold an LFID
// username — so `/v1/members/resolve`, which requires one, could never answer
// for them anyway. They are covered by the login path and by provisioning.
//
// `NOT app_metadata.cdp_uuid_source=*` is what excludes already-processed
// users, and it is field-existence rather than a timestamp range because
// nested `app_metadata` range queries are unverified against Auth0.
const CohortQueryTemplate = `identities.connection:"Username-Password-Authentication" AND email_verified:true AND NOT app_metadata.cdp_uuid_source=* AND updated_at:[%s TO *]`

// maxIndexLagProbePages bounds how far the sweep steps forward when a page
// returns nothing it has not already handled this run.
//
// Auth0's user search reads a lag-behind index, so a user written moments ago
// can still be returned by a query that excludes them. Without a bound the run
// would re-request the same page forever.
const maxIndexLagProbePages = 3

// DefaultStartOffset is how far back a cold-start cursor begins.
//
// This is the sweep's real scope knob: the canonical query carries no upper
// bound and no rolling window, so "active in the last 30 days" is expressed
// entirely by where the cursor starts. Once it has advanced, the sweep only
// ever looks forward.
const DefaultStartOffset = 30 * 24 * time.Hour

// Pacer bounds how fast a job calls CDP.
//
// CDP enforces 200 req/min per M2M client. The out-of-band jobs authenticate as
// the auth-service, which is a different client from the login Action, so they
// cannot starve login — but they DO share that one client with US3
// provisioning, so they share a single allocation rather than holding separate
// budgets.
type Pacer interface {
	Wait(ctx context.Context) error
}

// RunStats are the per-run counts both out-of-band jobs emit.
type RunStats struct {
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`
	Scanned       int       `json:"scanned"`
	Found         int       `json:"found"`
	NoMatch       int       `json:"no_match"`
	Conflicted    int       `json:"conflicted"`
	Written       int       `json:"written"`
	SkippedNoLFID int       `json:"skipped_no_lfid"`
	WouldResolve  int       `json:"would_resolve"`
	Errors        int       `json:"errors"`
	StoppedReason string    `json:"stopped_reason"`
}

// Options configures a sweep run.
type Options struct {
	// DryRun selects and reports without calling CDP or writing anything.
	DryRun bool

	// Limit caps how many users a run processes. Zero means no cap.
	Limit int

	// PageSize is the Auth0 search page size.
	PageSize int

	// StartOffset is how far back a cold-start cursor begins.
	StartOffset time.Duration

	// MaxRateLimitRetries bounds how many times one user is retried after a
	// 429 before the run stops. Stopping is safe: the user keeps no marker, so
	// the cursor has not advanced past them.
	MaxRateLimitRetries int
}

// Sweep walks the target cohort and pre-fills CDP UUIDs against live CDP.
type Sweep struct {
	search   port.UserSearcher
	resolver cdp.Client
	metadata port.CDPMetadataWriter
	cursor   CursorStore
	pacer    Pacer
	now      func() time.Time
	sleep    func(context.Context, time.Duration) error
	opts     Options
}

// NewSweep creates the full-cohort population sweep.
func NewSweep(
	search port.UserSearcher,
	resolver cdp.Client,
	metadata port.CDPMetadataWriter,
	cursor CursorStore,
	pacer Pacer,
	opts Options,
) (*Sweep, error) {
	switch {
	case search == nil:
		return nil, errs.NewValidation("a user searcher is required")
	case resolver == nil:
		return nil, errs.NewValidation("a CDP client is required")
	case metadata == nil:
		return nil, errs.NewValidation("a metadata writer is required")
	case cursor == nil:
		return nil, errs.NewValidation("a cursor store is required")
	}

	if opts.PageSize <= 0 {
		opts.PageSize = 20
	}
	if opts.StartOffset <= 0 {
		opts.StartOffset = DefaultStartOffset
	}
	if pacer == nil {
		pacer = noopPacer{}
	}

	return &Sweep{
		search:   search,
		resolver: resolver,
		metadata: metadata,
		cursor:   cursor,
		pacer:    pacer,
		now:      time.Now,
		sleep:    sleepContext,
		opts:     opts,
	}, nil
}

// CohortQuery renders the canonical query for a cursor position.
func CohortQuery(cursor time.Time) string {
	return fmt.Sprintf(CohortQueryTemplate, cursor.UTC().Format(time.RFC3339))
}

// Run walks forward from the stored cursor until the cohort is exhausted, the
// limit is reached, or a call fails.
//
// Paging is keyset, never offset: the sweep writes `cdp_uuid_source`, which is
// the query's own exclusion predicate, so a processed user leaves the result
// set and an offset would step over live users. Every request therefore asks
// for page 0 at the current cursor. The one exception is the bounded probe that
// steps over a search index which has not caught up yet.
func (s *Sweep) Run(ctx context.Context) (RunStats, error) {
	cursor, err := s.cursor.Load(ctx)
	if err != nil {
		return RunStats{}, err
	}
	if cursor.LastUpdatedAt.IsZero() {
		cursor.LastUpdatedAt = s.now().Add(-s.opts.StartOffset).UTC()
		slog.InfoContext(ctx, "population sweep starting from a cold cursor",
			"start_from", cursor.LastUpdatedAt.Format(time.RFC3339),
		)
	}

	stats := RunStats{StartedAt: s.now().UTC()}
	seen := make(map[string]struct{})
	page := 0

	for {
		if s.opts.Limit > 0 && stats.Scanned >= s.opts.Limit {
			stats.StoppedReason = "limit reached"
			break
		}

		users, errSearch := s.search.SearchUsers(ctx, port.UserSearch{
			Query:   CohortQuery(cursor.LastUpdatedAt),
			Page:    page,
			PerPage: s.opts.PageSize,
		})
		if errSearch != nil {
			stats.Errors++
			stats.StoppedReason = "search failed"
			return s.finish(ctx, cursor, stats, errSearch)
		}

		if len(users) == 0 {
			stats.StoppedReason = "cohort exhausted"
			break
		}

		fresh := make([]port.CohortUser, 0, len(users))
		for _, user := range users {
			if _, handled := seen[user.UserID]; !handled {
				fresh = append(fresh, user)
			}
		}

		if len(fresh) == 0 {
			// Every user on this page was already handled this run, which
			// means the search index still lists them. Step forward rather
			// than re-request the same page.
			page++
			if page > maxIndexLagProbePages {
				stats.StoppedReason = "search index lag"
				slog.InfoContext(ctx, "population sweep stopping on search index lag",
					"probe_pages", maxIndexLagProbePages,
					"cursor", cursor.LastUpdatedAt.Format(time.RFC3339),
				)
				break
			}
			continue
		}
		page = 0

		for _, user := range fresh {
			if s.opts.Limit > 0 && stats.Scanned >= s.opts.Limit {
				break
			}
			seen[user.UserID] = struct{}{}
			stats.Scanned++

			if errProcess := s.processUser(ctx, user, &stats); errProcess != nil {
				stats.Errors++
				stats.StoppedReason = "user failed"
				// The cursor is NOT advanced past this user. They keep no
				// marker, so the next run selects them again.
				return s.finish(ctx, cursor, stats, errProcess)
			}

			// Advance INCLUSIVELY and forward-only. Never `+1ms`: anyone
			// sharing this timestamp who was not on the page must stay
			// selectable.
			if !user.UpdatedAt.IsZero() && !user.UpdatedAt.Before(cursor.LastUpdatedAt) {
				cursor.LastUpdatedAt = user.UpdatedAt
				cursor.LastProcessedUserID = user.UserID
			}
		}

		if errSave := s.saveCursor(ctx, cursor, stats); errSave != nil {
			stats.Errors++
			stats.StoppedReason = "cursor save failed"
			return stats, errSave
		}
	}

	return s.finish(ctx, cursor, stats, nil)
}

// saveCursor persists progress, except on a dry run.
//
// A dry run still advances the cursor in memory — that is how it pages forward
// and reports what a real run would cover — but persisting it would leave the
// cohort permanently skipped by a run that called nothing.
func (s *Sweep) saveCursor(ctx context.Context, cursor Cursor, stats RunStats) error {
	if s.opts.DryRun {
		return nil
	}
	return s.cursor.Save(ctx, withStats(cursor, stats))
}

// processUser resolves one user against live CDP and writes the result.
func (s *Sweep) processUser(ctx context.Context, user port.CohortUser, stats *RunStats) error {
	// `/v1/members/resolve` requires at least one LFID. The cohort query's
	// connection filter should guarantee one, but a database identity with no
	// username is possible, so this asserts rather than assumes.
	if strings.TrimSpace(user.Username) == "" {
		stats.SkippedNoLFID++
		slog.WarnContext(ctx, "skipping a swept user with no LFID username",
			"user_id", redaction.Redact(user.UserID),
		)
		return nil
	}

	// FR-003a: the email only ever widens an already-valid LFID match, and only
	// when verified. The cohort query filters on `email_verified:true`, so this
	// should always hold — assert it rather than trust it.
	verifiedEmail := ""
	if user.EmailVerified {
		verifiedEmail = user.Email
	} else {
		slog.WarnContext(ctx, "swept user is not email-verified despite the cohort filter",
			"user_id", redaction.Redact(user.UserID),
		)
	}

	if s.opts.DryRun {
		stats.WouldResolve++
		return nil
	}

	result, err := s.resolve(ctx, user.Username, verifiedEmail)
	if err != nil {
		return err
	}

	record := port.CDPMetadata{
		Source:    constants.CDPUUIDSourceBackfill,
		CheckedAt: s.now().UTC().Format(time.RFC3339),
	}

	switch result.Outcome {
	case cdp.OutcomeFound:
		record.UUID = result.MemberID
		stats.Found++
	case cdp.OutcomeNoMatch:
		stats.NoMatch++
	case cdp.OutcomeConflict:
		// The user is called and NO uuid is written — never guess which of
		// several members is theirs. The marker itself IS written, because a
		// conflicted user is stored identically to a genuine no-match: leaving
		// them unmarked would drop them out of this sweep once the cursor
		// passes them AND out of the no-match re-check, which selects on
		// marker presence. The re-check picks them up once CDP merges them.
		stats.Conflicted++
	default:
		return errs.NewUnexpected(fmt.Sprintf("unknown CDP resolve outcome %q", result.Outcome))
	}

	if errWrite := s.metadata.WriteCDPMetadata(ctx, user.UserID, record); errWrite != nil {
		return errWrite
	}
	stats.Written++
	return nil
}

// resolve calls CDP, waiting out a 429 rather than counting it against the user.
func (s *Sweep) resolve(ctx context.Context, lfid, verifiedEmail string) (cdp.ResolveResult, error) {
	for attempt := 0; ; attempt++ {
		if err := s.pacer.Wait(ctx); err != nil {
			return cdp.ResolveResult{}, err
		}

		result, err := s.resolver.Resolve(ctx, lfid, verifiedEmail)
		if err == nil {
			return result, nil
		}

		// The CDP client never retries a 429 itself — backing off is
		// deliberately the caller's job, so a wait is spent by whoever can
		// decide it is worth spending.
		var rateLimited errs.RateLimited
		if !errors.As(err, &rateLimited) || attempt >= s.opts.MaxRateLimitRetries {
			return cdp.ResolveResult{}, err
		}

		wait := rateLimited.RetryAfter
		if wait <= 0 {
			wait = time.Second
		}
		slog.WarnContext(ctx, "CDP rate limited the sweep; waiting out Retry-After",
			"retry_after", wait.String(),
			"attempt", attempt+1,
		)
		if errSleep := s.sleep(ctx, wait); errSleep != nil {
			return cdp.ResolveResult{}, errSleep
		}
	}
}

// finish records the run's outcome and persists the final cursor position.
func (s *Sweep) finish(ctx context.Context, cursor Cursor, stats RunStats, runErr error) (RunStats, error) {
	stats.FinishedAt = s.now().UTC()
	if stats.StoppedReason == "" {
		stats.StoppedReason = "completed"
	}

	if errSave := s.saveCursor(ctx, cursor, stats); errSave != nil {
		slog.ErrorContext(ctx, "failed to save the sweep cursor",
			"error", errSave,
		)
		if runErr == nil {
			return stats, errSave
		}
	}

	// The Management API query string is redacted in transport logs, so the
	// cursor is only recoverable from a field emitted here.
	slog.InfoContext(ctx, "completed population sweep run",
		"dry_run", s.opts.DryRun,
		"cursor", cursor.LastUpdatedAt.Format(time.RFC3339),
		"scanned", stats.Scanned,
		"found", stats.Found,
		"no_match", stats.NoMatch,
		"conflicted", stats.Conflicted,
		"written", stats.Written,
		"skipped_no_lfid", stats.SkippedNoLFID,
		"would_resolve", stats.WouldResolve,
		"errors", stats.Errors,
		"stopped_reason", stats.StoppedReason,
	)
	return stats, runErr
}

func withStats(cursor Cursor, stats RunStats) Cursor {
	cursor.RunStats = stats
	return cursor
}

type noopPacer struct{}

func (noopPacer) Wait(context.Context) error { return nil }

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
