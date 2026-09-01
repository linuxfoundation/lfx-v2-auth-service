// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package backfill

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/cdp"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	errs "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
)

// --- a fake tenant that enforces the constraints the real one does ----------

// auth0OffsetCap is the offset at which the real tenant answers
// `400 invalid_paging`. Measured against production 2026-09-01: offset 980
// succeeds, offset 1000 fails, at any page size.
const auth0OffsetCap = 1000

var boundPattern = regexp.MustCompile(`updated_at:\[([^ ]+) TO \*\]`)

// fakeTenant models the slice of Auth0 search behaviour this walk depends on:
// ascending sort, offset paging, and the hard offset cap. Writes mutate
// updated_at exactly as the real tenant does, which is what makes the
// termination tests meaningful.
type fakeTenant struct {
	users     map[string]*port.CohortUser
	queries   []string
	pagesSeen []int
	capHits   int
	now       time.Time
}

func newFakeTenant(users []port.CohortUser) *fakeTenant {
	m := make(map[string]*port.CohortUser, len(users))
	for i := range users {
		u := users[i]
		m[u.UserID] = &u
	}
	return &fakeTenant{users: m, now: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
}

// SearchUsers applies the marker predicate, the walk bound, ascending order and
// the offset cap.
func (f *fakeTenant) SearchUsers(_ context.Context, s port.UserSearch) ([]port.CohortUser, error) {
	f.queries = append(f.queries, s.Query)
	f.pagesSeen = append(f.pagesSeen, s.Page)

	offset := s.Page * s.PerPage
	if offset >= auth0OffsetCap {
		f.capHits++
		return nil, errs.NewUnexpected(
			"400 invalid_paging: You can only page through the first 1000 records")
	}

	var bound time.Time
	if m := boundPattern.FindStringSubmatch(s.Query); m != nil {
		parsed, err := time.Parse(time.RFC3339, m[1])
		if err != nil {
			return nil, errs.NewValidation("unparseable bound in query")
		}
		bound = parsed
	}

	var matched []port.CohortUser
	for _, u := range f.users {
		// The query's own predicate: marker present, uuid absent.
		if u.Source == "" || u.UUID != "" {
			continue
		}
		if !bound.IsZero() && u.UpdatedAt.Before(bound) {
			continue
		}
		matched = append(matched, *u)
	}

	sort.Slice(matched, func(i, j int) bool {
		if matched[i].UpdatedAt.Equal(matched[j].UpdatedAt) {
			return matched[i].UserID < matched[j].UserID
		}
		return matched[i].UpdatedAt.Before(matched[j].UpdatedAt)
	})

	if offset >= len(matched) {
		return nil, nil
	}
	end := offset + s.PerPage
	if end > len(matched) {
		end = len(matched)
	}
	return matched[offset:end], nil
}

// WriteCDPMetadata applies the write and bumps updated_at, as Auth0 does.
func (f *fakeTenant) WriteCDPMetadata(_ context.Context, userID string, rec port.CDPMetadata) error {
	u, ok := f.users[userID]
	if !ok {
		return errs.NewNotFound("no such user")
	}
	if rec.UUID != "" {
		u.UUID = rec.UUID
	}
	u.Source = rec.Source
	u.CheckedAt = rec.CheckedAt
	f.now = f.now.Add(time.Millisecond)
	u.UpdatedAt = f.now
	return nil
}

func (f *fakeTenant) maxPage() int {
	m := 0
	for _, p := range f.pagesSeen {
		if p > m {
			m = p
		}
	}
	return m
}

// scriptedResolver answers per LFID so a test can place a specific user in a
// specific branch.
type scriptedResolver struct {
	byLFID  map[string]cdp.ResolveResult
	errs    map[string]error
	fallive cdp.Outcome
	calls   []string
}

func (s *scriptedResolver) Resolve(_ context.Context, lfid, _ string) (cdp.ResolveResult, error) {
	s.calls = append(s.calls, lfid)
	if err, ok := s.errs[lfid]; ok {
		return cdp.ResolveResult{}, err
	}
	if r, ok := s.byLFID[lfid]; ok {
		return r, nil
	}
	out := s.fallive
	if out == "" {
		out = cdp.OutcomeNoMatch
	}
	return cdp.ResolveResult{Outcome: out}, nil
}

func (s *scriptedResolver) ListIdentities(context.Context, string) ([]cdp.MemberIdentity, error) {
	return nil, nil
}

func (s *scriptedResolver) CreateMember(context.Context, string, cdp.Identity) (cdp.CreateResult, error) {
	return cdp.CreateResult{}, nil
}

func (s *scriptedResolver) AttachIdentity(context.Context, string, cdp.Identity) (cdp.AttachResult, error) {
	return cdp.AttachResult{}, nil
}

// markedUser is a user carrying a no-match marker: source set, uuid absent.
func markedUser(id string, updatedAt time.Time) port.CohortUser {
	return port.CohortUser{
		CDPMetadata: port.CDPMetadata{
			Source:    constants.CDPUUIDSourceLoginResolve,
			CheckedAt: "2026-08-01T00:00:00Z",
		},
		UserID:        id,
		Username:      "lfid-" + id,
		Email:         id + "@example.org",
		EmailVerified: true,
		UpdatedAt:     updatedAt,
	}
}

func markedPopulation(n int) []port.CohortUser {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	users := make([]port.CohortUser, 0, n)
	for i := 0; i < n; i++ {
		users = append(users, markedUser(fmt.Sprintf("u%04d", i), base.Add(time.Duration(i)*time.Minute)))
	}
	return users
}

func newTestRecheck(t *testing.T, tenant *fakeTenant, resolver cdp.Client, opts Options) *Recheck {
	t.Helper()
	if opts.PageSize == 0 {
		opts.PageSize = 20
	}
	rc, err := NewRecheck(tenant, resolver, tenant, nil, opts)
	require.NoError(t, err)
	rc.now = func() time.Time { return time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC) }
	rc.sleep = func(context.Context, time.Duration) error { return nil }
	return rc
}

// --- the population query --------------------------------------------------

func TestRecheckQueryUsesFieldExistenceOnly(t *testing.T) {
	// Both forms are proven against the tenant. A staleness clause on the
	// nested marker timestamp is not merely unverified, it is rejected:
	// measured 400 "operator 'less or equal' is not supported".
	q := RecheckQuery(time.Time{})
	assert.Equal(t, "app_metadata."+constants.CDPUUIDSourceKey+":* AND NOT app_metadata."+constants.CDPUUIDKey+":*", q)
	assert.NotContains(t, q, constants.CDPUUIDCheckedAtKey,
		"a staleness filter cannot execute against Auth0 and must never be added")
}

func TestRecheckQueryNeverFiltersOnTheMarkerTimestamp(t *testing.T) {
	bounded := RecheckQuery(time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC))
	assert.Contains(t, bounded, "updated_at:[2026-08-20T10:00:00.000Z TO *]",
		"the walk bound is on top-level updated_at, the proven form")
	assert.NotContains(t, bounded, constants.CDPUUIDCheckedAtKey)
}

func TestQueryBoundsCarryMillisecondPrecision(t *testing.T) {
	// time.RFC3339 truncates to whole seconds, and Auth0 stores milliseconds
	// (`2026-08-17T20:25:34.048Z`, observed live). A truncated lower bound
	// re-selects up to a second of already-handled users on every page.
	//
	// The sweep survives that — its processed-marker exclusion removes them —
	// but the re-check has no exclusion, so it re-reads the same second
	// forever and the walk stalls. See the stall regression test below.
	at := time.Date(2026, 8, 17, 20, 25, 34, 48_000_000, time.UTC)

	assert.Contains(t, RecheckQuery(at), "2026-08-17T20:25:34.048Z",
		"the re-check bound must keep milliseconds or its walk stalls")
	assert.Contains(t, CohortQuery(at), "2026-08-17T20:25:34.048Z",
		"the sweep cursor keeps them too, so the two jobs render bounds alike")
}

func TestRecheckDoesNotStallOnAPopulationPackedIntoOneSecond(t *testing.T) {
	// The regression this precision bug actually caused. 200 users inside a
	// single second: under second-truncated bounds every page re-selects the
	// same head of the population, the walk stops early, and the tail is never
	// re-checked — silently, because the run still reports success.
	base := time.Date(2026, 8, 15, 9, 0, 0, 0, time.UTC)
	var users []port.CohortUser
	for i := 0; i < 200; i++ {
		users = append(users, markedUser(
			fmt.Sprintf("d%03d", i), base.Add(time.Duration(i)*time.Millisecond)))
	}
	tenant := newFakeTenant(users)
	resolver := &scriptedResolver{fallive: cdp.OutcomeConflict} // writes nothing; nothing moves
	rc := newTestRecheck(t, tenant, resolver, Options{PageSize: 20})

	stats, err := rc.Run(context.Background())
	require.NoError(t, err)

	assert.Equal(t, 200, stats.Scanned, "every user in the second must be reached")
	assert.True(t, stats.CompletedFullPass)
	assert.Zero(t, tenant.capHits)
}

func TestRecheckFirstPageIsUnbounded(t *testing.T) {
	// Anchoring the first page at year one would depend on how Auth0 parses an
	// extreme date. Omitting the clause avoids the question entirely.
	assert.NotContains(t, RecheckQuery(time.Time{}), "updated_at:")
}

// --- the walk, against the offset cap --------------------------------------

func TestRecheckWalksAPopulationFarLargerThanTheOffsetCap(t *testing.T) {
	// The whole reason this walk exists. 1,500 users at page size 20 is 75
	// pages; plain offset paging would 400 at page 50.
	tenant := newFakeTenant(markedPopulation(1500))
	resolver := &scriptedResolver{fallive: cdp.OutcomeNoMatch}
	rc := newTestRecheck(t, tenant, resolver, Options{})

	stats, err := rc.Run(context.Background())
	require.NoError(t, err)

	assert.Equal(t, 1500, stats.Scanned, "every user must be reached")
	assert.Equal(t, 1500, stats.StillNoMatch)
	assert.True(t, stats.CompletedFullPass)
	assert.Zero(t, tenant.capHits, "the walk must never trip the offset cap")
	assert.Zero(t, tenant.maxPage(), "a healthy walk only ever asks for page 0")
}

func TestRecheckWouldTripTheCapIfItPagedByOffset(t *testing.T) {
	// Guards the fake itself: if it did not enforce the cap, the test above
	// would pass for the wrong reason.
	tenant := newFakeTenant(markedPopulation(1500))
	_, err := tenant.SearchUsers(context.Background(), port.UserSearch{
		Query: RecheckQueryUnbounded, Page: 50, PerPage: 20,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_paging")
	assert.Equal(t, 1, tenant.capHits)
}

func TestRecheckTerminatesOnANonShrinkingPopulation(t *testing.T) {
	// Nothing here leaves the population: a still-404 keeps its marker and a
	// 409 writes nothing. The walk must still end.
	users := markedPopulation(60)
	tenant := newFakeTenant(users)
	resolver := &scriptedResolver{fallive: cdp.OutcomeConflict}
	rc := newTestRecheck(t, tenant, resolver, Options{})

	stats, err := rc.Run(context.Background())
	require.NoError(t, err)

	assert.Equal(t, 60, stats.Scanned)
	assert.Equal(t, 60, stats.Conflicted)
	assert.True(t, stats.CompletedFullPass)
	// Population is untouched, so a second run sees exactly the same work.
	stats2, err := rc.Run(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 60, stats2.Scanned, "a cursorless job re-derives the same population")
}

func TestRecheckReachesPastASameTimestampCluster(t *testing.T) {
	// More users share one updated_at than fit on a page, so the bound alone
	// cannot get past them. Stepping the offset can.
	at := time.Date(2026, 8, 15, 9, 0, 0, 0, time.UTC)
	var users []port.CohortUser
	for i := 0; i < 45; i++ {
		users = append(users, markedUser(fmt.Sprintf("c%03d", i), at))
	}
	tenant := newFakeTenant(users)
	resolver := &scriptedResolver{fallive: cdp.OutcomeConflict} // writes nothing, so nothing moves
	rc := newTestRecheck(t, tenant, resolver, Options{PageSize: 20})

	stats, err := rc.Run(context.Background())
	require.NoError(t, err)

	assert.Equal(t, 45, stats.Scanned, "the whole cluster must be reached")
	assert.Positive(t, tenant.maxPage(), "reaching it requires stepping the offset")
	assert.LessOrEqual(t, tenant.maxPage(), maxRecheckClusterProbePages)
	assert.Zero(t, tenant.capHits)
}

// --- outcome branches ------------------------------------------------------

func TestRecheckPromotesAUserWhoNowResolves(t *testing.T) {
	tenant := newFakeTenant([]port.CohortUser{
		markedUser("a", time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)),
	})
	resolver := &scriptedResolver{byLFID: map[string]cdp.ResolveResult{
		"lfid-a": {Outcome: cdp.OutcomeFound, MemberID: "11111111-2222-3333-4444-555555555555"},
	}}
	rc := newTestRecheck(t, tenant, resolver, Options{})

	stats, err := rc.Run(context.Background())
	require.NoError(t, err)

	assert.Equal(t, 1, stats.Promoted)
	assert.Equal(t, "11111111-2222-3333-4444-555555555555", tenant.users["a"].UUID)
	assert.Equal(t, constants.CDPUUIDSourceBackfill, tenant.users["a"].Source)
}

func TestRecheckRefreshesCheckedAtOnAStillNoMatch(t *testing.T) {
	// Keeps the login path's 24h TTL honest for somebody CDP was just asked
	// about, and cdp_uuid stays absent.
	tenant := newFakeTenant([]port.CohortUser{
		markedUser("a", time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)),
	})
	before := tenant.users["a"].CheckedAt
	resolver := &scriptedResolver{fallive: cdp.OutcomeNoMatch}
	rc := newTestRecheck(t, tenant, resolver, Options{})

	stats, err := rc.Run(context.Background())
	require.NoError(t, err)

	assert.Equal(t, 1, stats.StillNoMatch)
	assert.Empty(t, tenant.users["a"].UUID, "cdp_uuid must stay absent")
	assert.NotEqual(t, before, tenant.users["a"].CheckedAt, "checked_at must be refreshed")
}

func TestRecheckCallsAConflictedUserAndWritesNothing(t *testing.T) {
	// FR-021: never guess which of several members is theirs. They keep the
	// marker they already have, so they stay in this population and are
	// promoted on the first run after CDP merges the duplicates.
	original := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	tenant := newFakeTenant([]port.CohortUser{markedUser("a", original)})
	beforeChecked := tenant.users["a"].CheckedAt
	resolver := &scriptedResolver{fallive: cdp.OutcomeConflict}
	rc := newTestRecheck(t, tenant, resolver, Options{})

	stats, err := rc.Run(context.Background())
	require.NoError(t, err)

	assert.Len(t, resolver.calls, 1, "a conflicted user IS called, not excluded")
	assert.Equal(t, 1, stats.Conflicted, "and counted - this is the FR-010b figure")
	assert.Empty(t, tenant.users["a"].UUID)
	assert.Equal(t, beforeChecked, tenant.users["a"].CheckedAt, "nothing may be written")
	assert.True(t, tenant.users["a"].UpdatedAt.Equal(original), "not even a timestamp bump")
}

func TestRecheckPromotesAConflictedUserOnceCDPMerges(t *testing.T) {
	// The property the standalone design buys over the withdrawn warehouse
	// worklist: no sync has to happen in between.
	tenant := newFakeTenant([]port.CohortUser{
		markedUser("a", time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)),
	})
	resolver := &scriptedResolver{fallive: cdp.OutcomeConflict}
	rc := newTestRecheck(t, tenant, resolver, Options{})

	first, err := rc.Run(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, first.Conflicted)

	// CDP merges the duplicates.
	resolver.byLFID = map[string]cdp.ResolveResult{
		"lfid-a": {Outcome: cdp.OutcomeFound, MemberID: "merged-uuid"},
	}

	second, err := rc.Run(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, second.Promoted, "the very next run picks them up")
	assert.Equal(t, "merged-uuid", tenant.users["a"].UUID)
}

func TestRecheckStopsOnAValidationErrorRatherThanWriting(t *testing.T) {
	// A rejected request is not a no-match. Recording one would refresh the
	// timestamp off our own bug and suppress the login re-check for 24h.
	tenant := newFakeTenant([]port.CohortUser{
		markedUser("a", time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)),
	})
	before := tenant.users["a"].CheckedAt
	resolver := &scriptedResolver{errs: map[string]error{
		"lfid-a": errs.NewValidation("lfid is required"),
	}}
	rc := newTestRecheck(t, tenant, resolver, Options{})

	_, err := rc.Run(context.Background())
	require.Error(t, err)
	assert.Equal(t, before, tenant.users["a"].CheckedAt)
}

func TestRecheckSkipsAUserWithNoLFIDWithoutCallingCDP(t *testing.T) {
	u := markedUser("a", time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC))
	u.Username = ""
	tenant := newFakeTenant([]port.CohortUser{u})
	resolver := &scriptedResolver{}
	rc := newTestRecheck(t, tenant, resolver, Options{})

	stats, err := rc.Run(context.Background())
	require.NoError(t, err)
	assert.Empty(t, resolver.calls, "resolve refuses an empty lfid; do not send one")
	assert.Equal(t, 1, stats.SkippedNoLFID)
}

func TestRecheckSkipsAUserWhoAlreadyHasAUUID(t *testing.T) {
	// Auth0's search index lags its writes, so a user the query excludes can
	// still arrive. Calling CDP for them spends budget on an answer that is
	// unwritable anyway, since cdp_uuid is write-once.
	u := markedUser("a", time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC))
	u.UUID = "already-set"
	tenant := newFakeTenant([]port.CohortUser{u})
	// Force it past the tenant's own predicate to simulate the lag.
	tenant.users["a"].UUID = ""
	resolver := &scriptedResolver{fallive: cdp.OutcomeNoMatch}
	rc := newTestRecheck(t, tenant, resolver, Options{})
	rc.search = staleIndex{inner: tenant, uuid: "already-set"}

	stats, err := rc.Run(context.Background())
	require.NoError(t, err)
	assert.Empty(t, resolver.calls, "a user already holding a UUID must not be called")
	assert.Zero(t, stats.Promoted)
}

// staleIndex hands back a user carrying a UUID, which the live query would
// have excluded — the shape of Auth0's lagging search index.
type staleIndex struct {
	inner *fakeTenant
	uuid  string
	done  bool
}

func (s staleIndex) SearchUsers(ctx context.Context, q port.UserSearch) ([]port.CohortUser, error) {
	if s.done {
		return nil, nil
	}
	users, err := s.inner.SearchUsers(ctx, q)
	if err != nil {
		return nil, err
	}
	for i := range users {
		users[i].UUID = s.uuid
	}
	return users, nil
}

// --- dry run and partial passes --------------------------------------------

func TestRecheckDryRunCallsNothingAndWritesNothing(t *testing.T) {
	tenant := newFakeTenant(markedPopulation(30))
	resolver := &scriptedResolver{}
	rc := newTestRecheck(t, tenant, resolver, Options{DryRun: true})

	stats, err := rc.Run(context.Background())
	require.NoError(t, err)

	assert.Empty(t, resolver.calls, "a dry run must not spend CDP budget")
	assert.Equal(t, 30, stats.WouldResolve)
	assert.Zero(t, stats.Promoted)
	for _, u := range tenant.users {
		assert.Equal(t, "2026-08-01T00:00:00Z", u.CheckedAt, "nothing may be written")
	}
}

func TestRecheckReportsAPartialPassWhenTheLimitCutsItShort(t *testing.T) {
	// The signal that matters most for this job. It keeps no cursor, so a
	// truncated run always covers the same prefix and the tail is never
	// reached — a coverage gap with no other symptom.
	tenant := newFakeTenant(markedPopulation(200))
	resolver := &scriptedResolver{fallive: cdp.OutcomeNoMatch}
	rc := newTestRecheck(t, tenant, resolver, Options{Limit: 50})

	stats, err := rc.Run(context.Background())
	require.NoError(t, err)

	assert.Equal(t, 50, stats.Scanned)
	assert.False(t, stats.CompletedFullPass, "a truncated run must say so")
	assert.Equal(t, "limit reached", stats.StoppedReason)
}

func TestRecheckReportsAPartialPassWhenTheDeadlinePasses(t *testing.T) {
	tenant := newFakeTenant(markedPopulation(200))
	resolver := &scriptedResolver{fallive: cdp.OutcomeNoMatch}
	rc := newTestRecheck(t, tenant, resolver, Options{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	stats, err := rc.Run(ctx)
	require.NoError(t, err, "running out of time is not a failure")
	assert.False(t, stats.CompletedFullPass)
	assert.Equal(t, "deadline reached", stats.StoppedReason)
}

func TestRecheckReportsAFullPassOnACompleteRun(t *testing.T) {
	tenant := newFakeTenant(markedPopulation(40))
	resolver := &scriptedResolver{fallive: cdp.OutcomeNoMatch}
	rc := newTestRecheck(t, tenant, resolver, Options{})

	stats, err := rc.Run(context.Background())
	require.NoError(t, err)
	assert.True(t, stats.CompletedFullPass)
	assert.Equal(t, 40, stats.Scanned)
}

// --- rate limiting ---------------------------------------------------------

func TestRecheckWaitsOutARateLimitAndRetriesTheSameUser(t *testing.T) {
	tenant := newFakeTenant([]port.CohortUser{
		markedUser("a", time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)),
	})
	resolver := &rateLimitedOnce{
		inner: &scriptedResolver{byLFID: map[string]cdp.ResolveResult{
			"lfid-a": {Outcome: cdp.OutcomeFound, MemberID: "uuid-1"},
		}},
	}
	rc := newTestRecheck(t, tenant, resolver, Options{MaxRateLimitRetries: 2})

	stats, err := rc.Run(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, stats.Promoted)
	assert.Equal(t, 2, resolver.attempts, "the same user is retried, not skipped")
}

type rateLimitedOnce struct {
	inner    *scriptedResolver
	attempts int
}

func (r *rateLimitedOnce) Resolve(ctx context.Context, lfid, email string) (cdp.ResolveResult, error) {
	r.attempts++
	if r.attempts == 1 {
		return cdp.ResolveResult{}, errs.NewRateLimited("slow down", 2*time.Second)
	}
	return r.inner.Resolve(ctx, lfid, email)
}

func (r *rateLimitedOnce) ListIdentities(context.Context, string) ([]cdp.MemberIdentity, error) {
	return nil, nil
}

func (r *rateLimitedOnce) CreateMember(context.Context, string, cdp.Identity) (cdp.CreateResult, error) {
	return cdp.CreateResult{}, nil
}

func (r *rateLimitedOnce) AttachIdentity(context.Context, string, cdp.Identity) (cdp.AttachResult, error) {
	return cdp.AttachResult{}, nil
}

// --- construction ----------------------------------------------------------

func TestNewRecheckValidatesItsDependencies(t *testing.T) {
	tenant := newFakeTenant(nil)
	resolver := &scriptedResolver{}

	_, err := NewRecheck(nil, resolver, tenant, nil, Options{})
	require.Error(t, err, "a missing searcher must fail at construction")

	_, err = NewRecheck(tenant, nil, tenant, nil, Options{})
	require.Error(t, err, "a missing CDP client must fail at construction")

	_, err = NewRecheck(tenant, resolver, nil, nil, Options{})
	require.Error(t, err, "a missing writer must fail at construction")
}

func TestRecheckTakesNoCursorStore(t *testing.T) {
	// Structural: there is exactly one cursor in this feature and it belongs
	// to the sweep. If a CursorStore parameter ever appears here, this stops
	// compiling, which is the point.
	tenant := newFakeTenant(nil)
	_, err := NewRecheck(tenant, &scriptedResolver{}, tenant, nil, Options{})
	require.NoError(t, err)
	assert.NotContains(t, strings.ToLower(fmt.Sprintf("%T", &Recheck{})), "cursor")
}
