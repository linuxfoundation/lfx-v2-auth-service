// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Command cdp-merge-repair is the scheduled counterpart to the Release Gate's
// live-sample tool (cmd/cdp-reconcile-sample): instead of sampling, it walks
// every Auth0 user carrying a stored `cdp_uuid`, re-derives each against live
// CDP, and repairs the superseded ones whose resolve target provably belongs
// to the same person (linuxfoundation/segment-web-scripts#43).
//
// Only a resolve to a different member whose identities hold exactly the
// holder's own LFID is a repair, written with `cdp_uuid_source =
// "merge-repair"` through the writer's compare-and-swap. Every other outcome
// is a reasoned no-write — including a multi-LFID blob member (tallied as
// foreign) and holders whose identifiers no longer resolve.
//
// Dry-run by default: live writes require --dry-run=false together with
// --live. Every CDP call takes one limiter slot (default 50/min); the JSON
// tally goes to stdout or --out.
//
// Environment — the same keys the service uses: AUTH0_DOMAIN (or AUTH0_TENANT),
// AUTH0_AUDIENCE, the Auth0 M2M client credentials (AUTH0_M2M_CLIENT_ID,
// AUTH0_M2M_PRIVATE_BASE64_KEY), CDP_BASE_URL, and CDP_AUDIENCE. The CDP token
// comes from the service M2M app audience-switched; there is no dedicated
// merge-repair client.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/auth0"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/auth0/holderwalk"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/cdp"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/service/cdpidentity"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/service/mergerepair"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	lferrors "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

// holderUser is one enumerated user: the shared holder shape, aliased so the
// repair verdicts keep their names.
type holderUser = holderwalk.Holder

// repairRecord is one applied (live) or would-apply (dry-run) repair, carried
// into the tally verbatim — the follow-up needs actionable identifiers, so
// these are not redacted.
type repairRecord struct {
	UserID string `json:"user_id"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// checkError is one inconclusive user or enumeration warning.
type checkError struct {
	UserID  string `json:"user_id"`
	Message string `json:"message"`
}

// repairFlags carries the effective run mode. Live is already resolved:
// --live counts only together with --dry-run=false, anything else stays a
// dry run.
type repairFlags struct {
	dryRun      bool
	live        bool
	noPrefilter bool
}

// prefilter reports whether the stored-member read gates the resolve.
func (f repairFlags) prefilter() bool {
	return !f.noPrefilter
}

// tallyReport is the JSON artifact of one run. Unknown fields MUST be ignored
// by readers.
type tallyReport struct {
	Run struct {
		Mode          string    `json:"mode"`
		RatePerMinute int       `json:"rate_per_min"`
		Limit         int       `json:"limit"`
		Prefilter     bool      `json:"prefilter"`
		StartedAt     time.Time `json:"started_at"`
		FinishedAt    time.Time `json:"finished_at"`
		WalkComplete  bool      `json:"walk_complete"`
	} `json:"run"`
	Counters mergerepair.Tally `json:"counters"`
	Totals   struct {
		Touched int `json:"touched"`
		NoWrite int `json:"no_write"`
	} `json:"totals"`
	Repairs               []repairRecord `json:"repairs"`
	RepairsTruncated      bool           `json:"repairs_truncated"`
	ErrorSamples          []checkError   `json:"error_samples"`
	ErrorSamplesTruncated bool           `json:"error_samples_truncated"`
	EnumerationWarnings   []checkError   `json:"enumeration_warnings"`
	Unchecked             int            `json:"unchecked"`
	DurationSeconds       float64        `json:"duration_seconds"`
}

// processUser classifies one holder and, in live mode only, CAS-writes a
// repair. The returned member id is set only for a repair. A writer error —
// including a CAS mismatch, which means the stored value moved mid-run — is
// an error verdict, never a skip.
func processUser(ctx context.Context, client cdp.Client, writer port.CDPMetadataRepairer, pace *holderwalk.Limiter, flags repairFlags, u holderUser) (mergerepair.Verdict, string, error) {
	if strings.TrimSpace(u.Username) == "" {
		return mergerepair.VerdictSkippedNoLFID, "", nil
	}

	stored := mergerepair.StoredCheck{}
	if flags.prefilter() {
		held, err := holderwalk.CallWithRateLimitRetry(ctx, pace, func(callCtx context.Context) ([]cdp.MemberIdentity, error) {
			return client.ListIdentities(callCtx, u.StoredUUID)
		})
		if err != nil {
			if errors.Is(err, cdp.ErrMemberNotFound) {
				stored = mergerepair.StoredCheck{Found: false}
			} else {
				return mergerepair.VerdictError, "", err
			}
		} else {
			_, foreign := cdpidentity.ForeignLFID(held, u.Username)
			stored = mergerepair.StoredCheck{
				Found: true,
				// Own agreement needs a verified carry: resolve ignores
				// unverified identities, so an unverified own LFID must
				// not short-circuit before resolve. The foreign arm
				// keeps the full set, mirroring the target guard.
				HoldsOwnLFID:     cdpidentity.HoldsLFID(mergerepair.VerifiedOnly(held), u.Username),
				HoldsForeignLFID: foreign,
			}
			if stored.HoldsOwnLFID {
				return mergerepair.VerdictUnchangedAgrees, "", nil
			}
			// A stored member holding somebody else's LFID still goes to
			// resolve: the user's own member may live elsewhere, and
			// replacing the wrong-person UUID beats any clear policy.
		}
	}

	email := ""
	if u.EmailVerified {
		email = u.Email
	}
	resolved, err := holderwalk.CallWithRateLimitRetry(ctx, pace, func(callCtx context.Context) (cdp.ResolveResult, error) {
		return client.Resolve(callCtx, u.Username, email)
	})
	if err != nil {
		return mergerepair.VerdictError, "", err
	}

	var target []cdp.MemberIdentity
	if resolved.Outcome == cdp.OutcomeFound && !strings.EqualFold(strings.TrimSpace(resolved.MemberID), strings.TrimSpace(u.StoredUUID)) {
		held, err := holderwalk.CallWithRateLimitRetry(ctx, pace, func(callCtx context.Context) ([]cdp.MemberIdentity, error) {
			return client.ListIdentities(callCtx, resolved.MemberID)
		})
		if err != nil {
			// The target vanished between resolve and read, or the read
			// failed: either way nothing may be stored off this answer.
			return mergerepair.VerdictError, "", err
		}
		target = held
	}

	verdict, to := mergerepair.Classify(
		mergerepair.Holder{UserID: u.UserID, Username: u.Username, StoredUUID: u.StoredUUID},
		stored,
		mergerepair.ResolveCheck{Outcome: resolved.Outcome, MemberID: resolved.MemberID, ConflictReason: resolved.ConflictReason},
		target,
	)
	if verdict == mergerepair.VerdictError {
		// Classify's fail-loud row for inputs it does not recognise; carry a
		// message so the tally records it instead of run dereferencing nil.
		return verdict, "", fmt.Errorf("unclassifiable holder: resolve %q member %q stored %q",
			resolved.Outcome, resolved.MemberID, u.StoredUUID)
	}
	if verdict != mergerepair.VerdictRepaired || !flags.live {
		return verdict, to, nil
	}
	if writer == nil {
		return mergerepair.VerdictError, "", errors.New("live repair needs a metadata writer")
	}
	if err := writeRepairWithRetry(ctx, writer, u.UserID, u.StoredUUID, to); err != nil {
		return mergerepair.VerdictError, "", err
	}
	return verdict, to, nil
}

// auth0WriteMaxAttempts bounds waits on a throttled Management write: the
// repair is one PATCH per qualifying holder, so a limit that outlasts five
// bounded waits is an outage the next day's run retries, not this row's.
const auth0WriteMaxAttempts = 5

// writeRepairWithRetry waits out a bare RateLimited from the repair writer
// instead of erroring the row on transient Auth0 throttling. Any other error
// — including a CAS Conflict, which means the stored value moved mid-run —
// returns immediately: refusing to clobber is the point, not a retry case.
func writeRepairWithRetry(ctx context.Context, writer port.CDPMetadataRepairer, userID, from, to string) error {
	for attempt := 1; ; attempt++ {
		err := writer.WriteCDPMetadataRepair(ctx, userID, from, port.CDPMetadata{
			UUID:   to,
			Source: constants.CDPUUIDSourceMergeRepair,
		})
		var limited lferrors.RateLimited
		if !errors.As(err, &limited) || attempt >= auth0WriteMaxAttempts {
			return err
		}
		waitFor := holderwalk.BoundedRetryAfter(limited.RetryAfter)
		slog.WarnContext(ctx, "Auth0 throttled the repair write, waiting",
			"retry_after", waitFor.String(), "attempt", attempt)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitFor):
		}
	}
}

// repairDeps carries the seams run needs; tests substitute stubs for all three.
type repairDeps struct {
	client cdp.Client
	writer port.CDPMetadataRepairer
	list   func(context.Context) ([]holderUser, []string, error)
}

// repairOptions mirrors the CLI flags.
type repairOptions struct {
	ratePerMinute int
	limit         int
	dryRun        bool
	live          bool
	noPrefilter   bool
	outPath       string
}

// maxRepairRecords caps the per-repair listing in the tally; the counters
// stay authoritative past it.
const maxRepairRecords = 1000

// maxErrorSamples caps the per-error listing the same way: an outage mid-walk
// must not turn every remaining holder into an identifier in the tally.
const maxErrorSamples = 1000

// defaultRatePerMinute is the agreed CDP ceiling for this job.
const defaultRatePerMinute = 50

// run executes the whole repair pass over the enumerated population.
func run(ctx context.Context, deps repairDeps, opts repairOptions) (int, error) {
	if opts.ratePerMinute <= 0 {
		return 2, fmt.Errorf("-rate must be positive, got %d", opts.ratePerMinute)
	}
	if opts.ratePerMinute > defaultRatePerMinute {
		slog.WarnContext(ctx, "CDP rate above the agreed ceiling; the budget is shared with login and provisioning",
			"rate", opts.ratePerMinute, "ceiling", defaultRatePerMinute)
	}
	if opts.limit < 0 {
		return 2, fmt.Errorf("-limit must be zero or positive, got %d", opts.limit)
	}
	live := opts.live && !opts.dryRun
	if opts.live && opts.dryRun {
		slog.WarnContext(ctx, "--live without --dry-run=false stays a dry run")
	}
	mode := "dry-run"
	if live {
		mode = "live"
	}

	started := time.Now()
	population, malformed, err := deps.list(ctx)
	if err != nil {
		return 1, err
	}
	if opts.limit > 0 && len(population) > opts.limit {
		population = population[:opts.limit]
	}

	out := tallyReport{
		Repairs:             []repairRecord{},
		ErrorSamples:        []checkError{},
		EnumerationWarnings: []checkError{},
	}
	out.Run.Mode = mode
	out.Run.RatePerMinute = opts.ratePerMinute
	out.Run.Limit = opts.limit
	out.Run.Prefilter = !opts.noPrefilter
	out.Run.StartedAt = started.UTC()

	for _, userID := range malformed {
		// A user whose stored value cannot even be read is never assumed to
		// agree — malformed records force a nonzero exit.
		out.EnumerationWarnings = append(out.EnumerationWarnings, checkError{UserID: userID, Message: "matched _exists_:app_metadata.cdp_uuid but carries no usable string value"})
	}

	flags := repairFlags{dryRun: opts.dryRun, live: live, noPrefilter: opts.noPrefilter}
	pace := holderwalk.NewLimiter(opts.ratePerMinute)
	for i, user := range population {
		if ctx.Err() != nil {
			out.Unchecked = len(population) - i
			break
		}

		verdict, to, checkErr := processUser(ctx, deps.client, deps.writer, pace, flags, user)
		out.Counters.Add(verdict)
		switch verdict {
		case mergerepair.VerdictRepaired:
			if len(out.Repairs) < maxRepairRecords {
				out.Repairs = append(out.Repairs, repairRecord{UserID: user.UserID, Before: user.StoredUUID, After: to})
			} else {
				out.RepairsTruncated = true
			}
			slog.InfoContext(ctx, "merge-repair verdict",
				"verdict", string(verdict), "user_id", redaction.Redact(user.UserID), "live", live)
		case mergerepair.VerdictError:
			if len(out.ErrorSamples) < maxErrorSamples {
				out.ErrorSamples = append(out.ErrorSamples, checkError{UserID: user.UserID, Message: errMessage(checkErr)})
			} else {
				out.ErrorSamplesTruncated = true
			}
		}

		if (i+1)%100 == 0 {
			slog.InfoContext(ctx, "merge-repair progress", "checked", i+1, "of", len(population))
		}
	}
	out.Run.FinishedAt = time.Now().UTC()
	out.Run.WalkComplete = ctx.Err() == nil
	out.DurationSeconds = time.Since(started).Seconds()

	if live {
		out.Totals.Touched = out.Counters.Repaired
	}
	out.Totals.NoWrite = out.Counters.Examined - out.Totals.Touched

	if err := writeTally(out, opts.outPath); err != nil {
		return 1, err
	}

	slog.InfoContext(ctx, "merge-repair finished",
		"mode", mode,
		"examined", out.Counters.Examined,
		"repaired", out.Counters.Repaired,
		"touched", out.Totals.Touched,
		"unchecked", out.Unchecked,
	)

	return exitCode(out), nil
}

// exitCode maps a finished tally to the CLI contract: 0 is conclusive (a
// dry run that would repair is still conclusive — the tally carries the
// count); 1 covers errors, warnings, interrupts and empty runs. It reads
// the counters, never the sample slices, so the tally alone decides.
func exitCode(out tallyReport) int {
	checked := out.Counters.Examined - out.Counters.SkippedNoLFID
	switch {
	case out.Counters.Errors > 0 || len(out.EnumerationWarnings) > 0 || out.Unchecked > 0 || !out.Run.WalkComplete:
		return 1
	case checked == 0:
		return 1
	default:
		return 0
	}
}

// errMessage renders an error for the tally; a nil error means the verdict
// came from classification, not a call, and must not panic the run.
func errMessage(err error) string {
	if err == nil {
		return "classification error"
	}
	return err.Error()
}

func buildRepairDeps(ctx context.Context) (repairDeps, error) {
	cdpBaseURL := os.Getenv(constants.CDPBaseURLEnvKey)
	cdpAudience := os.Getenv(constants.CDPAudienceEnvKey)
	if cdpBaseURL == "" || cdpAudience == "" {
		return repairDeps{}, fmt.Errorf("%s and %s must be set", constants.CDPBaseURLEnvKey, constants.CDPAudienceEnvKey)
	}

	auth0Tenant := os.Getenv(constants.Auth0TenantEnvKey)
	auth0Domain := os.Getenv(constants.Auth0DomainEnvKey)
	if auth0Domain == "" {
		if auth0Tenant == "" {
			return repairDeps{}, fmt.Errorf("%s or %s must be set", constants.Auth0DomainEnvKey, constants.Auth0TenantEnvKey)
		}
		auth0Domain = fmt.Sprintf("%s.auth0.com", auth0Tenant)
	}

	auth0Config := auth0.Config{Tenant: auth0Tenant, Domain: auth0Domain}
	managementTokens, err := auth0.NewM2MTokenManager(ctx, auth0Config)
	if err != nil {
		return repairDeps{}, fmt.Errorf("failed to create the Management API token manager: %w", err)
	}
	// The service M2M identity, audience-switched; the job has no client of
	// its own, so it shares the per-client CDP budget and must stay capped.
	cdpTokens, err := auth0.NewM2MTokenManagerForAudience(ctx, auth0Config, cdpAudience)
	if err != nil {
		return repairDeps{}, fmt.Errorf("failed to create the CDP token manager: %w", err)
	}
	writer, err := auth0.NewCDPMetadataRepairWriter(
		httpclient.Config{Timeout: 30 * time.Second, MaxRetries: 0},
		auth0.Config{Domain: auth0Domain, M2MTokenManager: managementTokens},
	)
	if err != nil {
		return repairDeps{}, fmt.Errorf("failed to create the metadata writer: %w", err)
	}

	walker := &holderwalk.Walker{
		HTTPClient: httpclient.NewClient(httpclient.Config{
			Timeout:    30 * time.Second,
			MaxRetries: 0,
		}),
		Domain: auth0Domain,
		Tokens: managementTokens,
	}
	return repairDeps{
		client: cdp.NewClient(cdp.Config{
			BaseURL:      strings.TrimSuffix(cdpBaseURL, "/"),
			TokenManager: cdpTokens,
		}),
		writer: writer,
		list: func(ctx context.Context) ([]holderUser, []string, error) {
			return walker.ListCDPUUIDHolders(ctx)
		},
	}, nil
}

func writeTally(out tallyReport, outPath string) error {
	encoded, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode the tally: %w", err)
	}
	encoded = append(encoded, '\n')
	if outPath == "" {
		_, err = os.Stdout.Write(encoded)
		return err
	}
	// The tally carries unredacted identifiers. OpenFile's mode applies only
	// to a newly created file, so force 0600 on a reused path too.
	f, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to write the tally: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to restrict the tally permissions: %w", err)
	}
	if _, err := f.Write(encoded); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to write the tally: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to write the tally: %w", err)
	}
	return nil
}

func main() {
	os.Exit(realMain())
}

// realMain carries the deferred signal cleanup; os.Exit in main would skip it.
func realMain() int {
	dryRun := flag.Bool("dry-run", true, "classify and tally only; zero writes")
	live := flag.Bool("live", false, "authorize live CAS writes (requires --dry-run=false)")
	ratePerMinute := flag.Int("rate", defaultRatePerMinute, "CDP calls per minute ceiling; every resolve and identity read takes one slot")
	limit := flag.Int("limit", 0, "examine at most N holders (0 = all; canary path)")
	noPrefilter := flag.Bool("no-prefilter", false, "resolve every holder; skip the stored-member pre-filter (audit mode)")
	outPath := flag.String("out", "", "write the JSON tally here (default stdout)")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	deps, err := buildRepairDeps(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "merge-repair setup failed", "error", err)
		return 2
	}
	code, err := run(ctx, deps, repairOptions{
		ratePerMinute: *ratePerMinute,
		limit:         *limit,
		dryRun:        *dryRun,
		live:          *live,
		noPrefilter:   *noPrefilter,
		outPath:       *outPath,
	})
	if err != nil {
		slog.ErrorContext(ctx, "merge-repair failed", "error", err)
	}
	return code
}
