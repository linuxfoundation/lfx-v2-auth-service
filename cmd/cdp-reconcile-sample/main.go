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
// (default 99% / 0.1% -> 4,603). The sampling frame is the *checkable*
// population: users with no LFID username have no valid resolve call to make
// (`lfids` is mandatory), so they are reported as a separate count rather than
// spent as sample slots that prove nothing. When the checkable population is
// smaller than n the whole of it is checked instead.
//
// One-shot by design (it runs a handful of times before enablement, never on a
// schedule) and read-only everywhere: it writes nothing to Auth0 and nothing
// to CDP. Keep the JSON report as gate evidence (T024c).
//
// Environment — the same keys the service uses: AUTH0_DOMAIN (or AUTH0_TENANT),
// AUTH0_AUDIENCE, the Auth0 M2M client credentials (AUTH0_M2M_CLIENT_ID,
// AUTH0_M2M_PRIVATE_BASE64_KEY), CDP_BASE_URL, and CDP_AUDIENCE.
//
// Exit codes: 0 every sampled user agrees; 1 at least one disagreement or
// unresolvable user (the gate's literal rule blocks on both; the sign-off
// artifact records any accepted exception) — reported even when errors are
// also present, because a hard failure outranks an inconclusive run; 2 the
// run is inconclusive — errors, enumeration warnings, rate-limit exhaustion,
// an interrupt left users unchecked, or no user was actually checked (dry
// run, empty population, every user skipped).
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
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/auth0"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/auth0/holderwalk"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/cdp"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
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

// gateUser is one member of the sampled population: the shared holder shape,
// aliased so the gate verdicts keep their names.
type gateUser = holderwalk.Holder

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
	GeneratedAt         time.Time      `json:"generated_at"`
	Population          int            `json:"population"`
	SkippedNoLFID       int            `json:"skipped_no_lfid_population"`
	SampleSize          int            `json:"sample_size"`
	Census              bool           `json:"census"`
	Confidence          float64        `json:"confidence"`
	Ceiling             float64        `json:"ceiling"`
	Seed                int64          `json:"seed"`
	DryRun              bool           `json:"dry_run"`
	Counts              map[string]int `json:"counts"`
	Disagreements       []disagreement `json:"disagreements"`
	Unresolvable        []string       `json:"unresolvable_no_match"`
	EnumerationWarnings []checkError   `json:"enumeration_warnings"`
	Errors              []checkError   `json:"errors"`
	Unchecked           int            `json:"unchecked"`
	DurationSeconds     float64        `json:"duration_seconds"`
}

// requiredSampleSize returns the smallest n such that observing zero failures
// gives `confidence` that the true failure rate is below `ceiling`:
// (1-ceiling)^n <= 1-confidence.
func requiredSampleSize(confidence, ceiling float64) (int, error) {
	// NaN passes plain range checks (every comparison is false) and would
	// convert to a negative n downstream.
	if math.IsNaN(confidence) || confidence <= 0 || confidence >= 1 {
		return 0, fmt.Errorf("confidence must be in (0,1), got %v", confidence)
	}
	if math.IsNaN(ceiling) || ceiling <= 0 || ceiling >= 1 {
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

// splitCheckable removes the users this tool can never check — `lfids` is
// mandatory on /v1/members/resolve, so a user without an LFID username has no
// valid call to make. Sampling them would dilute the confidence claim: a
// sample slot spent on a guaranteed skip proves nothing about the rest.
func splitCheckable(population []gateUser) (checkable []gateUser, skipped int) {
	checkable = make([]gateUser, 0, len(population))
	for _, u := range population {
		if strings.TrimSpace(u.Username) == "" {
			skipped++
			continue
		}
		checkable = append(checkable, u)
	}
	return checkable, skipped
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
// user's identifiers under the same predicate CDP's /v1/members/resolve applies
// (crowd.dev resolveMember.ts): only `verified` identities are consulted —
// resolve filters verified=true on both arms, so an unverified identity can
// never have produced the 409 and must not count as membership here (a false
// pass otherwise). `verifiedBy` is not consulted because resolve ignores it.
// Values are trimmed and compared case-insensitively. The LFID arm is
// platform-qualified; the email arm is deliberately platform-free and only
// consulted when the user's email is verified (FR-003a).
func identityMatchesUser(u gateUser, identities []cdp.MemberIdentity) bool {
	for _, id := range identities {
		if !id.Verified {
			continue
		}
		value := strings.TrimSpace(id.Value)
		if id.Platform == constants.LFIDPlatform && id.Type == constants.CDPIdentityTypeUsername && strings.EqualFold(value, u.Username) {
			return true
		}
		if u.EmailVerified && u.Email != "" && id.Type == constants.CDPIdentityTypeEmail && strings.EqualFold(value, u.Email) {
			return true
		}
	}
	return false
}

func checkUser(ctx context.Context, client cdp.Client, pace *holderwalk.Limiter, u gateUser) (verdict, string, error) {
	if strings.TrimSpace(u.Username) == "" {
		return verdictSkippedNoLFID, "", nil
	}

	email := ""
	if u.EmailVerified {
		email = u.Email
	}

	result, err := holderwalk.CallWithRateLimitRetry(ctx, pace, func(callCtx context.Context) (cdp.ResolveResult, error) {
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
		// No match alone cannot tell "identifiers changed" from "stored
		// member deleted" — the latter is a hard failure, not merely a
		// non-re-derivable UUID. Reading the stored member splits the two.
		_, listErr := holderwalk.CallWithRateLimitRetry(ctx, pace, func(callCtx context.Context) ([]cdp.MemberIdentity, error) {
			return client.ListIdentities(callCtx, u.StoredUUID)
		})
		if listErr != nil {
			if errors.Is(listErr, cdp.ErrMemberNotFound) {
				return verdictDisagreeGone, "", nil
			}
			return verdictError, "", listErr
		}
		return verdictUnresolvable, "", nil
	case cdp.OutcomeConflict:
		identities, listErr := holderwalk.CallWithRateLimitRetry(ctx, pace, func(callCtx context.Context) ([]cdp.MemberIdentity, error) {
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

	code, err := run(ctx, buildClients, *confidence, *ceiling, *sampleSize, *ratePerMinute, *dryRun, *seed, *outPath)
	if err != nil {
		slog.ErrorContext(ctx, "reconcile sample failed", "error", err)
	}
	return code
}

// run executes the whole gate check. The clients factory is injected so tests
// can substitute a stub CDP client and an httptest-backed walker.
func run(ctx context.Context, clients func(context.Context) (cdp.Client, *holderwalk.Walker, error), confidence, ceiling float64, sampleOverride, ratePerMinute int, dryRun bool, seed int64, outPath string) (int, error) {
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

	cdpClient, walker, err := clients(ctx)
	if err != nil {
		return 2, err
	}

	started := time.Now()
	population, malformed, err := walker.ListCDPUUIDHolders(ctx)
	if err != nil {
		return 2, err
	}
	checkable, skippedNoLFID := splitCheckable(population)
	slog.InfoContext(ctx, "population enumerated",
		"population", len(population), "checkable", len(checkable),
		"skipped_no_lfid", skippedNoLFID, "sample_size", n, "seed", seed)

	// The walk's order is only as stable as Auth0's updated_at sort, which
	// gives ties no sub-order; sorting the frame by user ID is what actually
	// makes a (population, seed) pair reproduce the same sample.
	sort.Slice(checkable, func(i, j int) bool { return checkable[i].UserID < checkable[j].UserID })
	sampled := sampleUsers(checkable, n, seed)
	census := len(sampled) == len(checkable)
	achievedConfidence := confidence
	if !census && len(sampled) < derivedN {
		// An undersized override supports a weaker claim than requested;
		// record what the sample actually proves, not what was asked for.
		achievedConfidence = -math.Expm1(float64(len(sampled)) * math.Log1p(-ceiling))
		slog.WarnContext(ctx, "sample smaller than the derived size; reporting the achieved confidence",
			"sample_size", len(sampled), "derived_n", derivedN, "achieved_confidence", achievedConfidence)
	}
	out := report{
		GeneratedAt:         time.Now().UTC(),
		Population:          len(population),
		SkippedNoLFID:       skippedNoLFID,
		SampleSize:          len(sampled),
		Census:              census,
		Confidence:          achievedConfidence,
		Ceiling:             ceiling,
		Seed:                seed,
		DryRun:              dryRun,
		Counts:              make(map[string]int),
		Disagreements:       []disagreement{},
		Unresolvable:        []string{},
		EnumerationWarnings: []checkError{},
		Errors:              []checkError{},
	}
	for _, userID := range malformed {
		// Kept apart from the per-user check errors: one junk record must be
		// tellable from a failed CDP check, but it still forces a nonzero
		// exit — a user whose stored value cannot even be read is never
		// assumed to agree.
		out.EnumerationWarnings = append(out.EnumerationWarnings, checkError{UserID: userID, Message: "matched _exists_:app_metadata.cdp_uuid but carries no usable string value"})
	}

	if !dryRun {
		pace := holderwalk.NewLimiter(ratePerMinute)
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
	case len(out.Disagreements) > 0 || len(out.Unresolvable) > 0:
		// A hard failure outranks an inconclusive run: a disagreement found
		// beside an error must surface as the gate's blocking signal, not be
		// masked by the weaker "re-run to settle" code.
		return 1
	case len(out.Errors) > 0 || len(out.EnumerationWarnings) > 0 || out.Unchecked > 0:
		return 2
	case agreed == 0:
		// Dry runs, empty populations, and all-skipped samples check nobody;
		// exit 0 would fabricate gate evidence.
		return 2
	default:
		return 0
	}
}

func buildClients(ctx context.Context) (cdp.Client, *holderwalk.Walker, error) {
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
	walker := &holderwalk.Walker{
		HTTPClient: httpclient.NewClient(httpclient.Config{
			Timeout:    30 * time.Second,
			MaxRetries: 0,
		}),
		Domain: auth0Domain,
		Tokens: managementTokens,
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
