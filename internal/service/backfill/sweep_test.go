// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package backfill

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/cdp"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	errs "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
)

// --- fakes -----------------------------------------------------------------

type fakeSearcher struct {
	pages [][]port.CohortUser
	calls []port.UserSearch
	err   error
}

func (f *fakeSearcher) SearchUsers(_ context.Context, search port.UserSearch) ([]port.CohortUser, error) {
	f.calls = append(f.calls, search)
	if f.err != nil {
		return nil, f.err
	}
	if len(f.pages) == 0 {
		return nil, nil
	}
	page := f.pages[0]
	f.pages = f.pages[1:]
	return page, nil
}

type resolveCall struct {
	lfid  string
	email string
}

type fakeResolver struct {
	results []cdp.ResolveResult
	errs    []error
	calls   []resolveCall
}

func (f *fakeResolver) Resolve(_ context.Context, lfid, verifiedEmail string) (cdp.ResolveResult, error) {
	index := len(f.calls)
	f.calls = append(f.calls, resolveCall{lfid: lfid, email: verifiedEmail})
	if index < len(f.errs) && f.errs[index] != nil {
		return cdp.ResolveResult{}, f.errs[index]
	}
	if index < len(f.results) {
		return f.results[index], nil
	}
	return cdp.ResolveResult{Outcome: cdp.OutcomeNoMatch}, nil
}

func (f *fakeResolver) ListIdentities(context.Context, string) ([]cdp.MemberIdentity, error) {
	return nil, nil
}

func (f *fakeResolver) CreateMember(context.Context, string, cdp.Identity) (cdp.CreateResult, error) {
	return cdp.CreateResult{}, nil
}

func (f *fakeResolver) AttachIdentity(context.Context, string, cdp.Identity) (cdp.AttachResult, error) {
	return cdp.AttachResult{}, nil
}

type write struct {
	userID string
	record port.CDPMetadata
}

type fakeWriter struct {
	writes  []write
	failOn  string
	failErr error
}

func (f *fakeWriter) WriteCDPMetadata(_ context.Context, userID string, record port.CDPMetadata) error {
	if f.failOn != "" && userID == f.failOn {
		return f.failErr
	}
	f.writes = append(f.writes, write{userID: userID, record: record})
	return nil
}

type fakeCursorStore struct {
	cursor Cursor
	saves  int
}

func (f *fakeCursorStore) Load(context.Context) (Cursor, error) { return f.cursor, nil }

func (f *fakeCursorStore) Save(_ context.Context, cursor Cursor) error {
	f.cursor = cursor
	f.saves++
	return nil
}

func testUser(id string, updatedAt time.Time) port.CohortUser {
	return port.CohortUser{
		UserID:        id,
		Username:      "lfid-" + id,
		Email:         id + "@example.org",
		EmailVerified: true,
		UpdatedAt:     updatedAt,
	}
}

func newTestSweep(
	t *testing.T,
	searcher *fakeSearcher,
	resolver *fakeResolver,
	writer *fakeWriter,
	store *fakeCursorStore,
	opts Options,
) *Sweep {
	t.Helper()
	sweep, err := NewSweep(searcher, resolver, writer, store, nil, opts)
	require.NoError(t, err)
	sweep.now = func() time.Time { return time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC) }
	sweep.sleep = func(context.Context, time.Duration) error { return nil }
	return sweep
}

// --- the canonical query ---------------------------------------------------

func TestCohortQueryIsTheCanonicalStringVerbatim(t *testing.T) {
	// Byte-for-byte against the SoT block in
	// decisions/2026-07-cdp-no-match-representation.md §5. A reordered clause
	// or a "tidied" connection filter selects a different cohort in silence,
	// which is why this asserts equality rather than a shape.
	const expected = `identities.connection:"Username-Password-Authentication" AND ` +
		`email_verified:true AND NOT app_metadata.cdp_uuid_source=* AND ` +
		`updated_at:[2026-08-02T00:00:00Z TO *]`

	got := CohortQuery(time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC))
	assert.Equal(t, expected, got)
}

func TestCohortQueryUsesTheSharedConnectionConstant(t *testing.T) {
	// The template hard-codes the connection name to stay verbatim. This is
	// what catches a rename of the constant the rest of the service uses.
	assert.Contains(t, CohortQueryTemplate, `"`+constants.DatabaseConnection+`"`)
}

func TestCohortQueryExcludesProcessedUsersByFieldExistence(t *testing.T) {
	// Not a timestamp range: nested app_metadata range queries are unverified
	// against Auth0 and would silently match nothing.
	assert.Contains(t, CohortQueryTemplate, "NOT app_metadata."+constants.CDPUUIDSourceKey+"=*")
	assert.NotContains(t, CohortQueryTemplate, constants.CDPUUIDCheckedAtKey)
}

// --- cursor behaviour ------------------------------------------------------

func TestSweepAdvancesTheCursorInclusively(t *testing.T) {
	// Advancing even a millisecond past the boundary would permanently skip
	// anyone sharing that timestamp who was not on the page.
	boundary := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)

	searcher := &fakeSearcher{pages: [][]port.CohortUser{{testUser("a", boundary)}}}
	store := &fakeCursorStore{}
	sweep := newTestSweep(t, searcher, &fakeResolver{}, &fakeWriter{}, store, Options{})

	_, err := sweep.Run(context.Background())
	require.NoError(t, err)

	assert.Equal(t, boundary, store.cursor.LastUpdatedAt,
		"the cursor must land exactly on the last timestamp seen")
}

func TestSweepDoesNotAdvancePastAFailedUser(t *testing.T) {
	first := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	second := time.Date(2026, 8, 20, 11, 0, 0, 0, time.UTC)

	searcher := &fakeSearcher{pages: [][]port.CohortUser{{
		testUser("ok", first),
		testUser("boom", second),
	}}}
	writer := &fakeWriter{failOn: "boom", failErr: errs.NewUnexpected("auth0 unavailable")}
	store := &fakeCursorStore{}
	sweep := newTestSweep(t, searcher, &fakeResolver{}, writer, store, Options{})

	stats, err := sweep.Run(context.Background())
	require.Error(t, err, "a transient failure must surface, not be swallowed")

	assert.Equal(t, first, store.cursor.LastUpdatedAt,
		"the cursor must stop at the last user that actually succeeded")
	assert.Equal(t, 1, stats.Errors)
	assert.Equal(t, "user failed", stats.StoppedReason)
}

func TestSweepColdStartsFromTheConfiguredOffset(t *testing.T) {
	searcher := &fakeSearcher{}
	store := &fakeCursorStore{}
	sweep := newTestSweep(t, searcher, &fakeResolver{}, &fakeWriter{}, store,
		Options{StartOffset: 30 * 24 * time.Hour})

	_, err := sweep.Run(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, searcher.calls)

	assert.Contains(t, searcher.calls[0].Query, "updated_at:[2026-08-02T12:00:00Z TO *]",
		"a cold cursor starts one offset back from now")
}

func TestSweepNeverMovesTheCursorBackwards(t *testing.T) {
	start := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	earlier := start.Add(-time.Hour)

	searcher := &fakeSearcher{pages: [][]port.CohortUser{{testUser("late", earlier)}}}
	store := &fakeCursorStore{cursor: Cursor{LastUpdatedAt: start}}
	sweep := newTestSweep(t, searcher, &fakeResolver{}, &fakeWriter{}, store, Options{})

	_, err := sweep.Run(context.Background())
	require.NoError(t, err)
	assert.Equal(t, start, store.cursor.LastUpdatedAt)
}

// --- resolve outcome branches ----------------------------------------------

func TestSweepWritesTheUUIDOnAMatch(t *testing.T) {
	searcher := &fakeSearcher{pages: [][]port.CohortUser{{
		testUser("a", time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)),
	}}}
	resolver := &fakeResolver{results: []cdp.ResolveResult{
		{Outcome: cdp.OutcomeFound, MemberID: "11111111-2222-3333-4444-555555555555"},
	}}
	writer := &fakeWriter{}
	sweep := newTestSweep(t, searcher, resolver, writer, &fakeCursorStore{}, Options{})

	stats, err := sweep.Run(context.Background())
	require.NoError(t, err)

	require.Len(t, writer.writes, 1)
	assert.Equal(t, "11111111-2222-3333-4444-555555555555", writer.writes[0].record.UUID)
	assert.Equal(t, constants.CDPUUIDSourceBackfill, writer.writes[0].record.Source)
	assert.NotEmpty(t, writer.writes[0].record.CheckedAt)
	assert.Equal(t, 1, stats.Found)
}

func TestSweepWritesTheMarkerWithNoUUIDOnANoMatch(t *testing.T) {
	searcher := &fakeSearcher{pages: [][]port.CohortUser{{
		testUser("a", time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)),
	}}}
	resolver := &fakeResolver{results: []cdp.ResolveResult{{Outcome: cdp.OutcomeNoMatch}}}
	writer := &fakeWriter{}
	sweep := newTestSweep(t, searcher, resolver, writer, &fakeCursorStore{}, Options{})

	stats, err := sweep.Run(context.Background())
	require.NoError(t, err)

	require.Len(t, writer.writes, 1)
	assert.Empty(t, writer.writes[0].record.UUID,
		"cdp_uuid stays absent so it can never leak a sentinel into Segment")
	assert.Equal(t, constants.CDPUUIDSourceBackfill, writer.writes[0].record.Source)
	assert.Equal(t, 1, stats.NoMatch)
}

func TestSweepCallsAConflictedUserAndWritesNoUUID(t *testing.T) {
	// A multi-match user is called like anyone else and gets no uuid — never
	// guess which member is theirs. The marker IS written: leaving them
	// unmarked would drop them out of this sweep once the cursor passes them
	// and out of the re-check, which selects on marker presence.
	searcher := &fakeSearcher{pages: [][]port.CohortUser{{
		testUser("a", time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)),
	}}}
	resolver := &fakeResolver{results: []cdp.ResolveResult{{Outcome: cdp.OutcomeConflict}}}
	writer := &fakeWriter{}
	sweep := newTestSweep(t, searcher, resolver, writer, &fakeCursorStore{}, Options{})

	stats, err := sweep.Run(context.Background())
	require.NoError(t, err)

	assert.Len(t, resolver.calls, 1, "a conflicted user is still called")
	require.Len(t, writer.writes, 1)
	assert.Empty(t, writer.writes[0].record.UUID)
	assert.Equal(t, 1, stats.Conflicted)
}

func TestSweepStopsOnAValidationErrorRatherThanCachingANoMatch(t *testing.T) {
	// A rejected request is not a no-match. Writing a marker here would
	// permanently drop a person off both out-of-band populations.
	searcher := &fakeSearcher{pages: [][]port.CohortUser{{
		testUser("a", time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)),
	}}}
	resolver := &fakeResolver{errs: []error{errs.NewValidation("lfid is required")}}
	writer := &fakeWriter{}
	sweep := newTestSweep(t, searcher, resolver, writer, &fakeCursorStore{}, Options{})

	_, err := sweep.Run(context.Background())
	require.Error(t, err)
	assert.Empty(t, writer.writes, "a 4xx must never be recorded as a no-match")
}

func TestSweepSkipsAUserWithNoLFIDWithoutCallingCDP(t *testing.T) {
	user := testUser("a", time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC))
	user.Username = ""

	searcher := &fakeSearcher{pages: [][]port.CohortUser{{user}}}
	resolver := &fakeResolver{}
	writer := &fakeWriter{}
	sweep := newTestSweep(t, searcher, resolver, writer, &fakeCursorStore{}, Options{})

	stats, err := sweep.Run(context.Background())
	require.NoError(t, err)

	assert.Empty(t, resolver.calls, "resolve refuses an empty lfid; do not send one")
	assert.Empty(t, writer.writes)
	assert.Equal(t, 1, stats.SkippedNoLFID)
}

func TestSweepSendsTheEmailOnlyWhenVerified(t *testing.T) {
	verified := testUser("v", time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC))
	unverified := testUser("u", time.Date(2026, 8, 20, 11, 0, 0, 0, time.UTC))
	unverified.EmailVerified = false

	searcher := &fakeSearcher{pages: [][]port.CohortUser{{verified, unverified}}}
	resolver := &fakeResolver{}
	sweep := newTestSweep(t, searcher, resolver, &fakeWriter{}, &fakeCursorStore{}, Options{})

	_, err := sweep.Run(context.Background())
	require.NoError(t, err)

	require.Len(t, resolver.calls, 2)
	assert.Equal(t, "v@example.org", resolver.calls[0].email)
	assert.Empty(t, resolver.calls[1].email, "FR-003a: an unverified email is never sent")
}

// --- dry run ---------------------------------------------------------------

func TestSweepDryRunCallsNothingAndPersistsNothing(t *testing.T) {
	searcher := &fakeSearcher{pages: [][]port.CohortUser{{
		testUser("a", time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)),
	}}}
	resolver := &fakeResolver{}
	writer := &fakeWriter{}
	store := &fakeCursorStore{}
	sweep := newTestSweep(t, searcher, resolver, writer, store, Options{DryRun: true})

	stats, err := sweep.Run(context.Background())
	require.NoError(t, err)

	assert.Empty(t, resolver.calls, "a dry run must not spend CDP budget")
	assert.Empty(t, writer.writes)
	assert.Zero(t, store.saves, "a dry run must not move the cursor for the next real run")
	assert.Equal(t, 1, stats.WouldResolve)
}

// --- paging ----------------------------------------------------------------

func TestSweepAlwaysRequestsPageZeroWhileMakingProgress(t *testing.T) {
	// The sweep writes the very key its query excludes on, so a processed user
	// leaves the result set. Incrementing an offset would step over live users.
	first := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	second := time.Date(2026, 8, 20, 11, 0, 0, 0, time.UTC)

	searcher := &fakeSearcher{pages: [][]port.CohortUser{
		{testUser("a", first)},
		{testUser("b", second)},
	}}
	sweep := newTestSweep(t, searcher, &fakeResolver{}, &fakeWriter{}, &fakeCursorStore{}, Options{})

	_, err := sweep.Run(context.Background())
	require.NoError(t, err)

	require.GreaterOrEqual(t, len(searcher.calls), 2)
	for i, call := range searcher.calls {
		assert.Zero(t, call.Page, "call %d used an offset instead of moving the cursor", i)
	}
}

func TestSweepTerminatesWhenTheSearchIndexKeepsReturningHandledUsers(t *testing.T) {
	// Auth0's search index lags, so a just-written user can be served again.
	// Without a bound the run would re-request the same page forever.
	at := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	stale := []port.CohortUser{testUser("a", at)}

	searcher := &fakeSearcher{pages: [][]port.CohortUser{
		stale, stale, stale, stale, stale, stale, stale, stale,
	}}
	sweep := newTestSweep(t, searcher, &fakeResolver{}, &fakeWriter{}, &fakeCursorStore{}, Options{})

	stats, err := sweep.Run(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "search index lag", stats.StoppedReason)
	assert.Equal(t, 1, stats.Scanned, "the repeated user is processed exactly once")
	assert.LessOrEqual(t, len(searcher.calls), maxIndexLagProbePages+2)
}

func TestSweepDrainsASameTimestampClusterAcrossRuns(t *testing.T) {
	// Every user in the cluster shares one timestamp, so the cursor cannot
	// move past them. The processed-marker exclusion is what shrinks the
	// cluster run over run — not the cursor.
	at := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	store := &fakeCursorStore{}

	remaining := []port.CohortUser{
		testUser("a", at), testUser("b", at), testUser("c", at),
	}
	for run := 0; run < 3; run++ {
		searcher := &fakeSearcher{pages: [][]port.CohortUser{{remaining[0]}}}
		sweep := newTestSweep(t, searcher, &fakeResolver{}, &fakeWriter{}, store, Options{})
		stats, err := sweep.Run(context.Background())
		require.NoError(t, err)
		assert.Equal(t, 1, stats.Scanned)
		assert.Equal(t, at, store.cursor.LastUpdatedAt,
			"the cursor stays on the boundary until the cluster is drained")
		remaining = remaining[1:]
	}
}

func TestSweepHonoursTheLimit(t *testing.T) {
	at := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	searcher := &fakeSearcher{pages: [][]port.CohortUser{{
		testUser("a", at), testUser("b", at.Add(time.Minute)), testUser("c", at.Add(2*time.Minute)),
	}}}
	resolver := &fakeResolver{}
	sweep := newTestSweep(t, searcher, resolver, &fakeWriter{}, &fakeCursorStore{}, Options{Limit: 2})

	stats, err := sweep.Run(context.Background())
	require.NoError(t, err)

	assert.Equal(t, 2, stats.Scanned)
	assert.Len(t, resolver.calls, 2)
	assert.Equal(t, "limit reached", stats.StoppedReason)
}

func TestSweepStopsWhenTheSearchFails(t *testing.T) {
	// An error is not an empty cohort: treating it as one would advance the
	// cursor across a range that was never read.
	searcher := &fakeSearcher{err: errs.NewUnexpected("auth0 unavailable")}
	store := &fakeCursorStore{cursor: Cursor{LastUpdatedAt: time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)}}
	before := store.cursor.LastUpdatedAt
	sweep := newTestSweep(t, searcher, &fakeResolver{}, &fakeWriter{}, store, Options{})

	_, err := sweep.Run(context.Background())
	require.Error(t, err)
	assert.Equal(t, before, store.cursor.LastUpdatedAt)
}

// --- rate limiting ---------------------------------------------------------

func TestSweepWaitsOutARateLimitAndRetriesTheSameUser(t *testing.T) {
	at := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	searcher := &fakeSearcher{pages: [][]port.CohortUser{{testUser("a", at)}}}
	resolver := &fakeResolver{
		errs:    []error{errs.NewRateLimited("slow down", 2*time.Second)},
		results: []cdp.ResolveResult{{}, {Outcome: cdp.OutcomeFound, MemberID: "uuid-1"}},
	}
	writer := &fakeWriter{}
	sweep := newTestSweep(t, searcher, resolver, writer, &fakeCursorStore{},
		Options{MaxRateLimitRetries: 3})

	stats, err := sweep.Run(context.Background())
	require.NoError(t, err)

	assert.Len(t, resolver.calls, 2, "the same user is retried, not skipped")
	require.Len(t, writer.writes, 1)
	assert.Equal(t, "uuid-1", writer.writes[0].record.UUID)
	assert.Equal(t, 1, stats.Found)
}

func TestSweepStopsWhenRateLimitRetriesAreExhausted(t *testing.T) {
	at := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	searcher := &fakeSearcher{pages: [][]port.CohortUser{{testUser("a", at)}}}
	resolver := &fakeResolver{errs: []error{
		errs.NewRateLimited("slow down", time.Second),
		errs.NewRateLimited("slow down", time.Second),
	}}
	store := &fakeCursorStore{}
	sweep := newTestSweep(t, searcher, resolver, &fakeWriter{}, store,
		Options{MaxRateLimitRetries: 1})

	_, err := sweep.Run(context.Background())
	require.Error(t, err)
	assert.True(t, store.cursor.LastUpdatedAt.Before(at) || store.cursor.LastUpdatedAt.IsZero(),
		"an exhausted budget must not advance past the user it could not call")
}
