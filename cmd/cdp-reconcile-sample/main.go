// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Command cdp-reconcile-sample is the Release Gate's live-sample half (SC-004).
//
// It draws a random sample of Auth0 users carrying a stored `cdp_uuid`,
// re-resolves each against live CDP, and reports whether every stored UUID is
// still among the members the user's identifiers match. It answers what the
// warehouse parity query provably cannot: live conflict behaviour and
// post-write drift, measured against CDP as it stands now.
//
// Disagreement uses the member-set rule: a user who matches several members
// still agrees when the stored UUID is one of them. A resolve 409 therefore is
// not a failure — the tool confirms membership by reading the stored member's
// own identities. Two failure modes are reported separately because they carry
// different risk:
//
//   - disagree_other_member / disagree_member_gone: the user's identifiers
//     match members and the stored UUID is not among them, or the stored
//     member no longer exists. The Segment user_id would be wrong.
//   - unresolvable_no_match: the identifiers match nothing now. The stored
//     UUID is not contradicted, only no longer re-derivable — typically an
//     email change after the write.
//
// With zero failures observed, a sample of n gives `confidence` that the true
// disagreement rate is below `ceiling`: n = ln(1-confidence)/ln(1-ceiling)
// (default 99% / 0.1% -> 4,603). When the population is smaller than n the
// whole population is checked instead.
//
// One-shot by design (it runs a handful of times before enablement, never on a
// schedule) and read-only everywhere: it writes nothing to Auth0 and nothing
// to CDP. Keep the JSON report as gate evidence (T024c).
//
// Environment — the same keys the service uses: AUTH0_DOMAIN (or AUTH0_TENANT)
// plus the Auth0 M2M client credentials, CDP_BASE_URL, and CDP_AUDIENCE.
//
// Exit codes: 0 every sampled user agrees; 1 at least one disagreement or
// unresolvable user (the gate's literal rule blocks on both; the sign-off
// artifact records any accepted exception); 2 the run is inconclusive —
// errors, rate-limit exhaustion, an interrupt left users unchecked, or no
// user was actually checked (dry run, empty population, every user skipped).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/auth0"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/cdp"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	lferrors "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

// verdict classifies one sampled user under the member-set rule.
type verdict string

const (
	// verdictAgreeSingle: the identifiers resolved to exactly the stored member.
	verdictAgreeSingle verdict = "agree_single"

	// verdictAgreeMulti: the identifiers match several members (live 409) and
	// the stored member is one of them — an agreement, not an error. Blocking
	// on these is exactly the naive single-match rule SC-004 forbids.
	verdictAgreeMulti verdict = "agree_multi_match"

	// verdictDisagreeOther: the identifiers resolved to a member that is not
	// the stored one. The Segment user_id would be wrong.
	verdictDisagreeOther verdict = "disagree_other_member"

	// verdictDisagreeGone: the identifiers match members but the stored member
	// itself no longer exists.
	verdictDisagreeGone verdict = "disagree_member_gone"

	// verdictUnresolvable: the identifiers match nothing now. Reported apart
	// from the disagreements: the stored UUID is not contradicted, only no
	// longer re-derivable.
	verdictUnresolvable verdict = "unresolvable_no_match"

	// verdictSkippedNoLFID: the user holds no username, and `lfids` is
	// mandatory on /v1/members/resolve, so there is no valid call to make.
	verdictSkippedNoLFID verdict = "skipped_no_lfid"

	// verdictError: the check itself failed for this user; re-run to settle.
	verdictError verdict = "error"
)

// gateUser is one member of the sampled population.
type gateUser struct {
	UserID        string
	Username      string
	Email         string
	EmailVerified bool
	StoredUUID    string // lowercased, as the writers store it
}

// disagreement is one hard failure, carried into the report verbatim — the
// gate evidence needs actionable identifiers, so these are not redacted.
type disagreement struct {
	UserID     string `json:"user_id"`
	StoredUUID string `json:"stored_uuid"`
	ResolvedID string `json:"resolved_member_id,omitempty"`
	Kind       string `json:"kind"`
}

// checkError is one inconclusive user.
type checkError struct {
	UserID  string `json:"user_id"`
	Message string `json:"message"`
}

// report is the JSON artifact the sign-off records.
type report struct {
	GeneratedAt     time.Time      `json:"generated_at"`
	Population      int            `json:"population"`
	SampleSize      int            `json:"sample_size"`
	Census          bool           `json:"census"`
	Confidence      float64        `json:"confidence"`
	Ceiling         float64        `json:"ceiling"`
	Seed            int64          `json:"seed"`
	DryRun          bool           `json:"dry_run"`
	Counts          map[string]int `json:"counts"`
	Disagreements   []disagreement `json:"disagreements"`
	Unresolvable    []string       `json:"unresolvable_no_match"`
	Errors          []checkError   `json:"errors"`
	Unchecked       int            `json:"unchecked"`
	DurationSeconds float64        `json:"duration_seconds"`
}

// requiredSampleSize returns the smallest n such that observing zero failures
// gives `confidence` that the true failure rate is below `ceiling`:
// (1-ceiling)^n <= 1-confidence.
func requiredSampleSize(confidence, ceiling float64) (int, error) {
	if confidence <= 0 || confidence >= 1 {
		return 0, fmt.Errorf("confidence must be in (0,1), got %v", confidence)
	}
	if ceiling <= 0 || ceiling >= 1 {
		return 0, fmt.Errorf("ceiling must be in (0,1), got %v", ceiling)
	}
	// Log1p sidesteps the 1-x rounding hole: for a tiny ceiling, 1-ceiling
	// rounds to 1 and the plain-Log denominator collapses to zero.
	n := math.Ceil(math.Log1p(-confidence) / math.Log1p(-ceiling))
	if n > math.MaxInt32 {
		return 0, fmt.Errorf("required sample size %g is impractically large; relax -confidence or -ceiling", n)
	}
	return int(n), nil
}

// sampleUsers draws n users without replacement, deterministically for a given
// seed. n >= len(population) returns the whole population (a census).
func sampleUsers(population []gateUser, n int, seed int64) []gateUser {
	if n >= len(population) {
		return population
	}
	rng := rand.New(rand.NewPCG(uint64(seed), uint64(seed>>32)))
	sampled := make([]gateUser, 0, n)
	for _, idx := range rng.Perm(len(population))[:n] {
		sampled = append(sampled, population[idx])
	}
	return sampled
}

// identityMatchesUser reports whether any of a member's identities matches the
// user's identifiers under the resolver's own predicate: values compared
// case-insensitively, `verified` required on both arms, the LFID arm
// platform-qualified, and the email arm deliberately platform-free — and only
// consulted when the user's email is verified (FR-003a).
func identityMatchesUser(u gateUser, identities []cdp.MemberIdentity) bool {
	for _, id := range identities {
		if !id.Verified {
			continue
		}
		if id.Platform == "lfid" && id.Type == "username" && strings.EqualFold(id.Value, u.Username) {
			return true
		}
		if u.EmailVerified && u.Email != "" && id.Type == "email" && strings.EqualFold(id.Value, u.Email) {
			return true
		}
	}
	return false
}

// limiter paces CDP calls to a fixed per-minute rate. Every CDP call — resolve
// and identity read alike — takes one slot: the budget is per client, not per
// endpoint.
type limiter struct {
	interval time.Duration
	next     time.Time
}

func newLimiter(perMinute int) *limiter {
	return &limiter{interval: time.Minute / time.Duration(perMinute)}
}

func (l *limiter) wait(ctx context.Context) error {
	now := time.Now()
	if now.Before(l.next) {
		timer := time.NewTimer(l.next.Sub(now))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	l.next = time.Now().Add(l.interval)
	return nil
}

// mgmtUser is the slice of an Auth0 Management user this tool reads.
type mgmtUser struct {
	UserID        string         `json:"user_id"`
	Username      string         `json:"username"`
	Email         string         `json:"email"`
	EmailVerified bool           `json:"email_verified"`
	UpdatedAt     string         `json:"updated_at"`
	AppMetadata   map[string]any `json:"app_metadata"`
}

// populationWalker enumerates every user carrying a stored cdp_uuid.
type populationWalker struct {
	httpClient *httpclient.Client
	domain     string
	tokens     cdp.TokenProvider
}

const (
	walkPageSize = 100

	// walkInitialBound predates every Auth0 user, so the first page starts at
	// the beginning of the population.
	walkInitialBound = "1970-01-01T00:00:00.000Z"

	// mgmtMaxAttempts bounds retries of one page against Management 429s and
	// transient failures.
	mgmtMaxAttempts = 8

	// databaseUserIDPrefix marks a user whose primary identity is the database
	// connection — the only case where the root `username` is an LFID (the
	// same guard internal/infrastructure/auth0/cdp_metadata.go applies).
	databaseUserIDPrefix = "auth0|"
)

// listCDPUUIDHolders walks the whole population of users with a stored
// cdp_uuid, also returning the user IDs of records that matched the query but
// carry no usable string value — the caller must report those as
// inconclusive, not silently shrink the population.
//
// Auth0's user search rejects offsets past 1,000, so plain page-walking cannot
// reach a ~43k population. This walks with an ascending `updated_at` lower
// bound instead: always page 0, bound advanced to the last row seen, boundary
// kept inclusive so a timestamp shared across a page edge is not skipped, and
// a seen-set to drop the one-row overlap that inclusivity re-presents.
//
// `updated_at` moves when a user logs in, so a user active during the walk can
// migrate across the bound and be missed. Acceptable for drawing a sample;
// a census run should quiesce or re-run.
func (w *populationWalker) listCDPUUIDHolders(ctx context.Context) ([]gateUser, []string, error) {
	var population []gateUser
	var malformed []string
	seen := make(map[string]struct{})
	bound := walkInitialBound

	for page := 0; ; page++ {
		rows, err := w.fetchPage(ctx, bound)
		if err != nil {
			return nil, nil, fmt.Errorf("population walk failed at bound %s: %w", bound, err)
		}

		newRows := 0
		for _, row := range rows {
			if _, dup := seen[row.UserID]; dup {
				continue
			}
			seen[row.UserID] = struct{}{}
			newRows++

			stored, _ := row.AppMetadata["cdp_uuid"].(string)
			if strings.TrimSpace(stored) == "" {
				// The query selects on key existence, so this is a shape
				// surprise that makes the enumeration inconclusive.
				slog.WarnContext(ctx, "user matched cdp_uuid=* but carries no string value",
					"user_id", redaction.Redact(row.UserID))
				malformed = append(malformed, row.UserID)
				continue
			}
			username := row.Username
			if !strings.HasPrefix(row.UserID, databaseUserIDPrefix) {
				// The root username belongs to the primary identity; for a
				// social- or enterprise-primary user it is not an LFID.
				// Blank it so the user counts as skipped_no_lfid instead of
				// being resolved as someone else.
				username = ""
			}
			population = append(population, gateUser{
				UserID:        row.UserID,
				Username:      username,
				Email:         row.Email,
				EmailVerified: row.EmailVerified,
				StoredUUID:    strings.ToLower(stored),
			})
		}

		if len(rows) < walkPageSize && newRows == 0 {
			break // a short page of only already-seen rows is the end
		}
		if len(rows) == 0 {
			break
		}

		nextBound := rows[len(rows)-1].UpdatedAt
		if newRows == 0 && nextBound == bound {
			return nil, nil, fmt.Errorf("population walk stalled: >%d users share updated_at %s", walkPageSize, bound)
		}
		bound = nextBound

		if page%10 == 9 {
			slog.InfoContext(ctx, "population walk progress", "pages", page+1, "users", len(population))
		}
	}

	return population, malformed, nil
}

func (w *populationWalker) fetchPage(ctx context.Context, bound string) ([]mgmtUser, error) {
	token, err := w.tokens.GetToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Management API token: %w", err)
	}

	params := url.Values{}
	params.Set("q", fmt.Sprintf("app_metadata.cdp_uuid=* AND updated_at:[%s TO *]", bound))
	params.Set("sort", "updated_at:1")
	params.Set("page", "0")
	params.Set("per_page", fmt.Sprintf("%d", walkPageSize))
	params.Set("include_totals", "false")
	params.Set("search_engine", "v3")
	params.Set("fields", "user_id,username,email,email_verified,updated_at,app_metadata")
	params.Set("include_fields", "true")

	backoff := 2 * time.Second
	for attempt := 1; ; attempt++ {
		request := httpclient.NewAPIRequest(
			w.httpClient,
			httpclient.WithMethod(http.MethodGet),
			httpclient.WithURL(fmt.Sprintf("https://%s/api/v2/users?%s", w.domain, params.Encode())),
			httpclient.WithToken(token),
			httpclient.WithDescription("list cdp_uuid holders"),
		)

		var rows []mgmtUser
		statusCode, errCall := request.Call(ctx, &rows)
		if errCall == nil {
			return rows, nil
		}
		if attempt >= mgmtMaxAttempts {
			return nil, fmt.Errorf("status code: %d after %d attempts: %w", statusCode, attempt, errCall)
		}
		// Call reports a negative status when no usable response arrived
		// (transport failure, decode failure); retry those like a 5xx.
		if statusCode >= 0 && statusCode != http.StatusTooManyRequests && statusCode < 500 {
			return nil, fmt.Errorf("status code: %d: %w", statusCode, errCall)
		}

		slog.WarnContext(ctx, "Management API page retry",
			"status_code", statusCode, "attempt", attempt, "backoff", backoff.String())
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}

const cdpCallMaxAttempts = 5
const defaultRateLimitWait = time.Minute

func checkUser(ctx context.Context, client cdp.Client, pace *limiter, u gateUser) (verdict, string, error) {
	if strings.TrimSpace(u.Username) == "" {
		return verdictSkippedNoLFID, "", nil
	}

	email := ""
	if u.EmailVerified {
		email = u.Email
	}

	result, err := callWithRateLimitRetry(ctx, pace, func(callCtx context.Context) (cdp.ResolveResult, error) {
		return client.Resolve(callCtx, u.Username, email)
	})
	if err != nil {
		return verdictError, "", err
	}

	switch result.Outcome {
	case cdp.OutcomeFound:
		if strings.EqualFold(result.MemberID, u.StoredUUID) {
			return verdictAgreeSingle, result.MemberID, nil
		}
		return verdictDisagreeOther, result.MemberID, nil
	case cdp.OutcomeNoMatch:
		return verdictUnresolvable, "", nil
	case cdp.OutcomeConflict:
		identities, listErr := callWithRateLimitRetry(ctx, pace, func(callCtx context.Context) ([]cdp.MemberIdentity, error) {
			return client.ListIdentities(callCtx, u.StoredUUID)
		})
		if listErr != nil {
			if errors.Is(listErr, cdp.ErrMemberNotFound) {
				return verdictDisagreeGone, "", nil
			}
			return verdictError, "", listErr
		}
		if identityMatchesUser(u, identities) {
			return verdictAgreeMulti, u.StoredUUID, nil
		}
		return verdictDisagreeOther, "", nil
	}

	return verdictError, "", fmt.Errorf("unexpected resolve outcome %q", result.Outcome)
}

func callWithRateLimitRetry[T any](ctx context.Context, pace *limiter, call func(context.Context) (T, error)) (T, error) {
	var zero T
	for attempt := 1; ; attempt++ {
		if err := pace.wait(ctx); err != nil {
			return zero, err
		}

		result, err := call(ctx)
		if err == nil {
			return result, nil
		}

		var rateLimited lferrors.RateLimited
		if !errors.As(err, &rateLimited) || attempt >= cdpCallMaxAttempts {
			return zero, err
		}

		waitFor := rateLimited.RetryAfter
		if waitFor <= 0 {
			waitFor = defaultRateLimitWait
		}
		slog.WarnContext(ctx, "CDP rate limited, waiting", "retry_after", waitFor.String(), "attempt", attempt)
		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case <-time.After(waitFor):
		}
	}
}

func main() {
	os.Exit(realMain())
}

// realMain carries the deferred signal cleanup; os.Exit in main would skip it.
func realMain() int {
	confidence := flag.Float64("confidence", 0.99, "confidence that the disagreement rate is below -ceiling, in (0,1)")
	ceiling := flag.Float64("ceiling", 0.001, "disagreement-rate ceiling the sample must support, in (0,1)")
	sampleSize := flag.Int("sample-size", 0, "override the derived sample size (0 = derive from -confidence/-ceiling)")
	ratePerMinute := flag.Int("rate", 100, "CDP calls per minute (shared client budget; leave headroom for provisioning)")
	dryRun := flag.Bool("dry-run", false, "enumerate and sample only; no CDP calls")
	seed := flag.Int64("seed", 0, "sampling seed for reproducibility (0 = time-based)")
	outPath := flag.String("out", "", "write the JSON report here (default stdout)")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	code, err := run(ctx, *confidence, *ceiling, *sampleSize, *ratePerMinute, *dryRun, *seed, *outPath)
	if err != nil {
		slog.ErrorContext(ctx, "reconcile sample failed", "error", err)
	}
	return code
}

func run(ctx context.Context, confidence, ceiling float64, sampleOverride, ratePerMinute int, dryRun bool, seed int64, outPath string) (int, error) {
	if ratePerMinute <= 0 {
		return 2, fmt.Errorf("-rate must be positive, got %d", ratePerMinute)
	}
	derivedN, err := requiredSampleSize(confidence, ceiling)
	if err != nil {
		return 2, err
	}
	n := derivedN
	if sampleOverride > 0 {
		n = sampleOverride
	}
	if seed == 0 {
		seed = time.Now().UnixNano()
	}

	cdpClient, walker, err := buildClients(ctx)
	if err != nil {
		return 2, err
	}

	started := time.Now()
	population, malformed, err := walker.listCDPUUIDHolders(ctx)
	if err != nil {
		return 2, err
	}
	slog.InfoContext(ctx, "population enumerated", "population", len(population), "sample_size", n, "seed", seed)

	sampled := sampleUsers(population, n, seed)
	census := len(sampled) == len(population)
	achievedConfidence := confidence
	if !census && len(sampled) < derivedN {
		// An undersized override supports a weaker claim than requested;
		// record what the sample actually proves, not what was asked for.
		achievedConfidence = -math.Expm1(float64(len(sampled)) * math.Log1p(-ceiling))
		slog.WarnContext(ctx, "sample smaller than the derived size; reporting the achieved confidence",
			"sample_size", len(sampled), "derived_n", derivedN, "achieved_confidence", achievedConfidence)
	}
	out := report{
		GeneratedAt:   time.Now().UTC(),
		Population:    len(population),
		SampleSize:    len(sampled),
		Census:        census,
		Confidence:    achievedConfidence,
		Ceiling:       ceiling,
		Seed:          seed,
		DryRun:        dryRun,
		Counts:        make(map[string]int),
		Disagreements: []disagreement{},
		Unresolvable:  []string{},
		Errors:        []checkError{},
	}
	for _, userID := range malformed {
		out.Errors = append(out.Errors, checkError{UserID: userID, Message: "matched cdp_uuid=* but carries no usable string value"})
	}

	if !dryRun {
		pace := newLimiter(ratePerMinute)
		for i, user := range sampled {
			if ctx.Err() != nil {
				out.Unchecked = len(sampled) - i
				break
			}

			result, resolvedID, checkErr := checkUser(ctx, cdpClient, pace, user)
			out.Counts[string(result)]++
			switch result {
			case verdictDisagreeOther, verdictDisagreeGone:
				out.Disagreements = append(out.Disagreements, disagreement{
					UserID:     user.UserID,
					StoredUUID: user.StoredUUID,
					ResolvedID: resolvedID,
					Kind:       string(result),
				})
				slog.WarnContext(ctx, "DISAGREEMENT", "kind", result, "user_id", redaction.Redact(user.UserID))
			case verdictUnresolvable:
				out.Unresolvable = append(out.Unresolvable, user.UserID)
			case verdictError:
				out.Errors = append(out.Errors, checkError{UserID: user.UserID, Message: checkErr.Error()})
			}

			if (i+1)%500 == 0 {
				slog.InfoContext(ctx, "sample progress", "checked", i+1, "of", len(sampled))
			}
		}
	}
	out.DurationSeconds = time.Since(started).Seconds()

	if err := writeReport(out, outPath); err != nil {
		return 2, err
	}

	slog.InfoContext(ctx, "reconcile sample finished",
		"population", out.Population,
		"sampled", out.SampleSize,
		"counts", out.Counts,
		"unchecked", out.Unchecked,
	)

	return reportExitCode(out), nil
}

func reportExitCode(out report) int {
	agreed := out.Counts[string(verdictAgreeSingle)] + out.Counts[string(verdictAgreeMulti)]
	switch {
	case len(out.Errors) > 0 || out.Unchecked > 0:
		return 2
	case len(out.Disagreements) > 0 || len(out.Unresolvable) > 0:
		return 1
	case agreed == 0:
		// Dry runs, empty populations, and all-skipped samples check nobody;
		// exit 0 would fabricate gate evidence.
		return 2
	default:
		return 0
	}
}

func buildClients(ctx context.Context) (cdp.Client, *populationWalker, error) {
	cdpBaseURL := os.Getenv(constants.CDPBaseURLEnvKey)
	cdpAudience := os.Getenv(constants.CDPAudienceEnvKey)
	if cdpBaseURL == "" || cdpAudience == "" {
		return nil, nil, fmt.Errorf("%s and %s must be set", constants.CDPBaseURLEnvKey, constants.CDPAudienceEnvKey)
	}

	auth0Tenant := os.Getenv(constants.Auth0TenantEnvKey)
	auth0Domain := os.Getenv(constants.Auth0DomainEnvKey)
	if auth0Domain == "" {
		if auth0Tenant == "" {
			return nil, nil, fmt.Errorf("%s or %s must be set", constants.Auth0DomainEnvKey, constants.Auth0TenantEnvKey)
		}
		auth0Domain = fmt.Sprintf("%s.auth0.com", auth0Tenant)
	}

	auth0Config := auth0.Config{Tenant: auth0Tenant, Domain: auth0Domain}
	managementTokens, err := auth0.NewM2MTokenManager(ctx, auth0Config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create the Management API token manager: %w", err)
	}
	cdpTokens, err := auth0.NewM2MTokenManagerForAudience(ctx, auth0Config, cdpAudience)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create the CDP token manager: %w", err)
	}

	cdpClient := cdp.NewClient(cdp.Config{
		BaseURL:      strings.TrimSuffix(cdpBaseURL, "/"),
		TokenManager: cdpTokens,
	})
	walker := &populationWalker{
		httpClient: httpclient.NewClient(httpclient.Config{
			Timeout:    30 * time.Second,
			MaxRetries: 0,
		}),
		domain: auth0Domain,
		tokens: managementTokens,
	}
	return cdpClient, walker, nil
}

func writeReport(out report, outPath string) error {
	encoded, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode the report: %w", err)
	}
	encoded = append(encoded, '\n')
	if outPath == "" {
		_, err = os.Stdout.Write(encoded)
		return err
	}
	// The report carries unredacted identifiers. OpenFile's mode applies only
	// to a newly created file, so force 0600 on a reused path too.
	f, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to write the report: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to restrict the report permissions: %w", err)
	}
	if _, err := f.Write(encoded); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to write the report: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to write the report: %w", err)
	}
	return nil
}
