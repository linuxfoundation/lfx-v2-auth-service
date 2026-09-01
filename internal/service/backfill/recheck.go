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

// RecheckQueryTemplate selects users carrying a no-match marker.
//
// Both clauses are field-existence, which is the only form proven against the
// tenant. A staleness filter on the marker timestamp is NOT possible: measured
// 2026-09-01, `app_metadata.cdp_uuid_checked_at:[* TO <date>]` answers
// `400 invalid query: operator 'less or equal' is not supported`. The whole
// no-match population is taken every run and paced by the rate limit instead.
//
// The `%s` is the run-local walk bound, never a persisted cursor. See walk().
const RecheckQueryTemplate = `app_metadata.cdp_uuid_source:* AND NOT app_metadata.cdp_uuid:* AND updated_at:[%s TO *]`

// RecheckQueryUnbounded is the same population with no lower bound, used for
// the first page of a run.
const RecheckQueryUnbounded = `app_metadata.cdp_uuid_source:* AND NOT app_metadata.cdp_uuid:*`

const (
	// maxRecheckClusterProbePages bounds the offset step used when a page
	// yields nothing new and the walk bound has not moved.
	//
	// That means more users share one `updated_at` than fit on a page, so the
	// bound alone cannot get past them. Stepping the offset can, and the bound
	// keeps this far away from Auth0's offset ceiling of 1000: at page size 20
	// this reaches offset 100.
	maxRecheckClusterProbePages = 5

	// maxRecheckEmptyStreak bounds how many consecutive already-seen pages the
	// walk tolerates while its bound IS advancing.
	//
	// That is the tail of users this same run already re-wrote: writing bumps
	// `updated_at`, so they collect at the top of the ascending order and the
	// walk meets them again on its way out. Seeing a few in a row means the
	// population is done.
	maxRecheckEmptyStreak = 3
)

// RecheckStats are the per-run counts the no-match re-check emits.
//
// Promoted, Conflicted and CompletedFullPass are the health signals: a re-check
// that silently stops working is how the dormant-user gap reopens.
type RecheckStats struct {
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`

	// Scanned is how many users this run actually examined. It is NOT the
	// population size: Auth0 caps a reported total at 1000, so the population
	// is only knowable by walking it.
	Scanned int `json:"scanned"`

	// Promoted is users whose marker was replaced by a real UUID.
	Promoted int `json:"promoted"`

	// StillNoMatch is users CDP still has no member for. Their marker
	// timestamp is refreshed so the login path's TTL stays honest.
	StillNoMatch int `json:"still_no_match"`

	// Conflicted is this run's own tally of live 409s — the FR-010b figure.
	// A direct observation rather than an estimate from a warehouse table.
	Conflicted int `json:"conflicted"`

	SkippedNoLFID int `json:"skipped_no_lfid"`
	WouldResolve  int `json:"would_resolve"`
	Errors        int `json:"errors"`

	// CompletedFullPass reports whether the run reached the end of the
	// population.
	//
	// Load-bearing, because this job keeps no cursor. A run cut short by its
	// deadline or limit always covers the same prefix, so the tail is never
	// reached and the coverage gap reopens with no other symptom. A run that
	// keeps reporting false needs a longer window, not a retry.
	CompletedFullPass bool `json:"completed_full_pass"`

	StoppedReason string `json:"stopped_reason"`
}

// Recheck re-resolves users carrying a no-match marker against live CDP.
//
// It is deliberately cursorless: the population is re-derived from marker
// presence on every run, which is what makes a user whose CDP duplicates were
// merged reappear on the next run with nothing having to remember them.
type Recheck struct {
	search   port.UserSearcher
	resolver cdp.Client
	metadata port.CDPMetadataWriter
	pacer    Pacer
	now      func() time.Time
	sleep    func(context.Context, time.Duration) error
	opts     Options
}

// NewRecheck creates the dormant no-match re-check.
func NewRecheck(
	search port.UserSearcher,
	resolver cdp.Client,
	metadata port.CDPMetadataWriter,
	pacer Pacer,
	opts Options,
) (*Recheck, error) {
	switch {
	case search == nil:
		return nil, errs.NewValidation("a user searcher is required")
	case resolver == nil:
		return nil, errs.NewValidation("a CDP client is required")
	case metadata == nil:
		return nil, errs.NewValidation("a metadata writer is required")
	}

	if opts.PageSize <= 0 {
		opts.PageSize = 20
	}
	if pacer == nil {
		pacer = noopPacer{}
	}

	return &Recheck{
		search:   search,
		resolver: resolver,
		metadata: metadata,
		pacer:    pacer,
		now:      time.Now,
		sleep:    sleepContext,
		opts:     opts,
	}, nil
}

// RecheckQuery renders the population query for a walk bound.
//
// A zero bound renders the unbounded form rather than a query anchored at year
// one, so the first page does not depend on how Auth0 parses an extreme date.
func RecheckQuery(bound time.Time) string {
	if bound.IsZero() {
		return RecheckQueryUnbounded
	}
	return fmt.Sprintf(RecheckQueryTemplate, bound.UTC().Format(auth0TimeFormat))
}

// Run walks the whole no-match population and re-resolves each user.
//
// **Why the walk looks like this.** Auth0 refuses any search whose offset
// reaches 1000 — `400 errorCode: invalid_paging`, measured — and this
// population does not shrink as the job works: a still-404 keeps its marker and
// a 409 writes nothing at all. Offset paging would therefore reach 1000 of
// ~16,200 users and then fail the run outright.
//
// So the walk carries a RUN-LOCAL ascending `updated_at` bound and always asks
// for page 0. Nothing is persisted — every run starts at the beginning of the
// population, which is what keeps this a walk rather than a second cursor — and
// the bound is on top-level `updated_at`, the proven form, never on the nested
// marker timestamp.
func (r *Recheck) Run(ctx context.Context) (RecheckStats, error) {
	stats := RecheckStats{StartedAt: r.now().UTC()}
	seen := make(map[string]struct{})

	var bound time.Time
	clusterProbe := 0
	emptyStreak := 0

	for {
		if r.opts.Limit > 0 && stats.Scanned >= r.opts.Limit {
			stats.StoppedReason = "limit reached"
			break
		}
		if err := ctx.Err(); err != nil {
			// Out of time. The population is unchanged, so the next run covers
			// it again from the start — but it covers the same PREFIX again,
			// which is why CompletedFullPass matters.
			stats.StoppedReason = "deadline reached"
			return r.finish(ctx, stats, nil)
		}

		users, errSearch := r.search.SearchUsers(ctx, port.UserSearch{
			Query:   RecheckQuery(bound),
			Page:    clusterProbe,
			PerPage: r.opts.PageSize,
		})
		if errSearch != nil {
			stats.Errors++
			stats.StoppedReason = "search failed"
			return r.finish(ctx, stats, errSearch)
		}

		if len(users) == 0 {
			stats.CompletedFullPass = true
			stats.StoppedReason = "population exhausted"
			break
		}

		fresh := make([]port.CohortUser, 0, len(users))
		for _, user := range users {
			if _, handled := seen[user.UserID]; !handled {
				fresh = append(fresh, user)
			}
		}

		previous := bound
		if last := users[len(users)-1].UpdatedAt; !last.IsZero() {
			bound = last
		}

		// A short page is the last page at this bound: Auth0 had nothing more
		// to give behind it.
		pageWasFull := len(users) == r.opts.PageSize

		if len(fresh) == 0 {
			if !pageWasFull {
				// Nothing new, and nothing behind it either. The commonest
				// shape of this is the very last page holding only the
				// inclusive-boundary user, already handled one page ago.
				stats.CompletedFullPass = true
				stats.StoppedReason = "population exhausted"
				break
			}
			if bound.Equal(previous) {
				// The bound cannot move: more users share this timestamp than
				// fit on a page. Step the offset to reach the rest of them.
				clusterProbe++
				if clusterProbe > maxRecheckClusterProbePages {
					stats.StoppedReason = "same-timestamp cluster exceeded the probe bound"
					slog.WarnContext(ctx, "no-match re-check stopped inside a same-timestamp cluster",
						"probe_pages", maxRecheckClusterProbePages,
						"bound", bound.Format(time.RFC3339),
					)
					break
				}
				continue
			}

			// The bound moved but nothing here is new: this is the tail of
			// users this run already re-wrote, which collect at the top of the
			// ordering. A few in a row means the population is done.
			emptyStreak++
			clusterProbe = 0
			if emptyStreak >= maxRecheckEmptyStreak {
				stats.CompletedFullPass = true
				stats.StoppedReason = "population exhausted"
				break
			}
			continue
		}

		clusterProbe = 0
		emptyStreak = 0

		for _, user := range fresh {
			if r.opts.Limit > 0 && stats.Scanned >= r.opts.Limit {
				break
			}
			if err := ctx.Err(); err != nil {
				stats.StoppedReason = "deadline reached"
				return r.finish(ctx, stats, nil)
			}

			seen[user.UserID] = struct{}{}
			stats.Scanned++

			if errProcess := r.processUser(ctx, user, &stats); errProcess != nil {
				stats.Errors++
				stats.StoppedReason = "user failed"
				return r.finish(ctx, stats, errProcess)
			}
		}
	}

	return r.finish(ctx, stats, nil)
}

// processUser re-resolves one marked user against live CDP.
func (r *Recheck) processUser(ctx context.Context, user port.CohortUser, stats *RecheckStats) error {
	// A user already holding a UUID has nothing to re-check. The query
	// excludes them, but Auth0's search index lags its writes, so one can
	// still arrive here — and calling CDP for them would spend budget on an
	// answer that cannot be written anyway (cdp_uuid is write-once).
	if strings.TrimSpace(user.UUID) != "" {
		return nil
	}

	// `/v1/members/resolve` requires at least one LFID, and refuses an empty
	// list before calling. Sending one anyway would return a validation error
	// that a careless caller could mistake for a no-match.
	if strings.TrimSpace(user.Username) == "" {
		stats.SkippedNoLFID++
		slog.WarnContext(ctx, "skipping a marked user with no LFID username",
			"user_id", redaction.Redact(user.UserID),
		)
		return nil
	}

	// FR-003a: the email widens an already-valid LFID match, and only when it
	// is verified. Unlike the sweep's cohort, this population is not filtered
	// on `email_verified`, so an unverified address here is ordinary rather
	// than a surprise.
	verifiedEmail := ""
	if user.EmailVerified {
		verifiedEmail = user.Email
	}

	if r.opts.DryRun {
		stats.WouldResolve++
		return nil
	}

	result, err := r.resolve(ctx, user.Username, verifiedEmail)
	if err != nil {
		return err
	}

	switch result.Outcome {
	case cdp.OutcomeFound:
		stats.Promoted++
		return r.write(ctx, user.UserID, port.CDPMetadata{
			UUID:      result.MemberID,
			Source:    constants.CDPUUIDSourceBackfill,
			CheckedAt: r.now().UTC().Format(time.RFC3339),
		})

	case cdp.OutcomeNoMatch:
		// Still no member. The marker is rewritten to refresh `checked_at`,
		// which keeps the login path's 24h TTL honest for somebody CDP was
		// just asked about. `cdp_uuid` stays absent.
		stats.StillNoMatch++
		return r.write(ctx, user.UserID, port.CDPMetadata{
			Source:    constants.CDPUUIDSourceBackfill,
			CheckedAt: r.now().UTC().Format(time.RFC3339),
		})

	case cdp.OutcomeConflict:
		// Two or more members match. NOTHING is written — never guess which
		// one is theirs (FR-021). They keep the marker they already have, so
		// they stay in this population and are picked up on the first run
		// after CDP merges the duplicates, with no warehouse sync in between.
		//
		// This is the churn the withdrawn `= 1` warehouse predicate existed to
		// avoid. It is affordable because these jobs hold their own per-client
		// CDP budget and nothing waits on the run.
		stats.Conflicted++
		return nil

	default:
		return errs.NewUnexpected(fmt.Sprintf("unknown CDP resolve outcome %q", result.Outcome))
	}
}

// write records the outcome through the shared write-once writer.
func (r *Recheck) write(ctx context.Context, userID string, record port.CDPMetadata) error {
	return r.metadata.WriteCDPMetadata(ctx, userID, record)
}

// resolve calls CDP, waiting out a 429 rather than counting it against the user.
func (r *Recheck) resolve(ctx context.Context, lfid, verifiedEmail string) (cdp.ResolveResult, error) {
	for attempt := 0; ; attempt++ {
		if err := r.pacer.Wait(ctx); err != nil {
			return cdp.ResolveResult{}, err
		}

		result, err := r.resolver.Resolve(ctx, lfid, verifiedEmail)
		if err == nil {
			return result, nil
		}

		var rateLimited errs.RateLimited
		if !errors.As(err, &rateLimited) || attempt >= r.opts.MaxRateLimitRetries {
			return cdp.ResolveResult{}, err
		}

		wait := rateLimited.RetryAfter
		if wait <= 0 {
			wait = time.Second
		}
		slog.WarnContext(ctx, "CDP rate limited the no-match re-check; waiting out Retry-After",
			"retry_after", wait.String(),
			"attempt", attempt+1,
		)
		if errSleep := r.sleep(ctx, wait); errSleep != nil {
			return cdp.ResolveResult{}, errSleep
		}
	}
}

// finish reports the run.
//
// These counts are the only health signal this job has — it holds no cursor, so
// there is no lag to measure. A re-check that stops working is otherwise
// invisible, which is exactly how the dormant-user gap reopened before.
func (r *Recheck) finish(ctx context.Context, stats RecheckStats, runErr error) (RecheckStats, error) {
	stats.FinishedAt = r.now().UTC()
	if stats.StoppedReason == "" {
		stats.StoppedReason = "completed"
	}

	level := slog.LevelInfo
	if !stats.CompletedFullPass {
		// Not an error, but not routine either: the tail of the population went
		// unvisited, and because the walk always restarts from the beginning it
		// will go unvisited again next run.
		level = slog.LevelWarn
	}

	slog.Log(ctx, level, "completed no-match re-check run",
		"dry_run", r.opts.DryRun,
		"scanned", stats.Scanned,
		"promoted", stats.Promoted,
		"still_no_match", stats.StillNoMatch,
		"conflicted", stats.Conflicted,
		"skipped_no_lfid", stats.SkippedNoLFID,
		"would_resolve", stats.WouldResolve,
		"errors", stats.Errors,
		"completed_full_pass", stats.CompletedFullPass,
		"stopped_reason", stats.StoppedReason,
		"duration_seconds", int(stats.FinishedAt.Sub(stats.StartedAt).Seconds()),
	)
	return stats, runErr
}
