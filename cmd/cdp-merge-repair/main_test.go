// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/auth0/holderwalk"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/cdp"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/service/mergerepair"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errCASConflict = errors.New("stored cdp_uuid changed since classification")

type stubCDPClient struct {
	resolveCalls int
	listCalls    int
	resolveFn    func(ctx context.Context, lfid, email string) (cdp.ResolveResult, error)
	listFn       func(ctx context.Context, memberID string) ([]cdp.MemberIdentity, error)
}

func (s *stubCDPClient) Resolve(ctx context.Context, lfid, email string) (cdp.ResolveResult, error) {
	s.resolveCalls++
	if s.resolveFn != nil {
		return s.resolveFn(ctx, lfid, email)
	}
	return cdp.ResolveResult{}, errors.New("no resolve stub")
}

func (s *stubCDPClient) ListIdentities(ctx context.Context, memberID string) ([]cdp.MemberIdentity, error) {
	s.listCalls++
	if s.listFn != nil {
		return s.listFn(ctx, memberID)
	}
	return nil, errors.New("no list stub")
}

func (s *stubCDPClient) CreateMember(_ context.Context, _ string, _ cdp.Identity) (cdp.CreateResult, error) {
	panic("merge-repair never creates members")
}

func (s *stubCDPClient) AttachIdentity(_ context.Context, _ string, _ cdp.Identity) (cdp.AttachResult, error) {
	panic("merge-repair never attaches identities")
}

type stubWriter struct {
	calls   int
	userIDs []string
	froms   []string
	records []port.CDPMetadata
	err     error
}

func (s *stubWriter) WriteCDPMetadataRepair(_ context.Context, userID, from string, record port.CDPMetadata) error {
	s.calls++
	s.userIDs = append(s.userIDs, userID)
	s.froms = append(s.froms, from)
	s.records = append(s.records, record)
	return s.err
}

func lfid(username string) cdp.MemberIdentity {
	return cdp.MemberIdentity{Platform: "lfid", Type: "username", Value: username}
}

func repairUser() holderUser {
	return holderUser{
		UserID:        "auth0|1",
		Username:      "psmith",
		Email:         "p@example.org",
		EmailVerified: true,
		StoredUUID:    "uuid-stale",
	}
}

func TestProcessUser(t *testing.T) {
	ctx := context.Background()
	pace := holderwalk.NewLimiter(6000)

	t.Run("dry-run repair classifies without writing", func(t *testing.T) {
		client := &stubCDPClient{
			listFn: func(_ context.Context, memberID string) ([]cdp.MemberIdentity, error) {
				if memberID == "uuid-stale" {
					return nil, cdp.ErrMemberNotFound
				}
				return []cdp.MemberIdentity{lfid("psmith")}, nil
			},
			resolveFn: func(_ context.Context, lfid, email string) (cdp.ResolveResult, error) {
				assert.Equal(t, "p@example.org", email)
				return cdp.ResolveResult{Outcome: cdp.OutcomeFound, MemberID: "uuid-fresh"}, nil
			},
		}
		writer := &stubWriter{}
		verdict, to, err := processUser(ctx, client, writer, pace, repairFlags{dryRun: true}, repairUser())
		require.NoError(t, err)
		assert.Equal(t, mergerepair.VerdictRepaired, verdict)
		assert.Equal(t, "uuid-fresh", to)
		assert.Zero(t, writer.calls, "dry-run never writes")
	})

	t.Run("live repair CAS-writes from the stored UUID", func(t *testing.T) {
		client := &stubCDPClient{
			listFn: func(_ context.Context, memberID string) ([]cdp.MemberIdentity, error) {
				if memberID == "uuid-stale" {
					return nil, cdp.ErrMemberNotFound
				}
				return []cdp.MemberIdentity{lfid("psmith")}, nil
			},
			resolveFn: func(_ context.Context, _, _ string) (cdp.ResolveResult, error) {
				return cdp.ResolveResult{Outcome: cdp.OutcomeFound, MemberID: "uuid-fresh"}, nil
			},
		}
		writer := &stubWriter{}
		verdict, _, err := processUser(ctx, client, writer, pace, repairFlags{dryRun: false, live: true}, repairUser())
		require.NoError(t, err)
		assert.Equal(t, mergerepair.VerdictRepaired, verdict)
		require.Len(t, writer.records, 1)
		assert.Equal(t, "uuid-stale", writer.froms[0])
		assert.Equal(t, "uuid-fresh", writer.records[0].UUID)
		assert.Equal(t, "merge-repair", writer.records[0].Source)
	})

	t.Run("writer CAS conflict is an error, not a skip", func(t *testing.T) {
		client := &stubCDPClient{
			listFn: func(_ context.Context, memberID string) ([]cdp.MemberIdentity, error) {
				if memberID == "uuid-stale" {
					return nil, cdp.ErrMemberNotFound
				}
				return []cdp.MemberIdentity{lfid("psmith")}, nil
			},
			resolveFn: func(_ context.Context, _, _ string) (cdp.ResolveResult, error) {
				return cdp.ResolveResult{Outcome: cdp.OutcomeFound, MemberID: "uuid-fresh"}, nil
			},
		}
		writer := &stubWriter{err: errCASConflict}
		verdict, _, err := processUser(ctx, client, writer, pace, repairFlags{dryRun: false, live: true}, repairUser())
		require.Error(t, err)
		assert.Equal(t, mergerepair.VerdictError, verdict)
		assert.Equal(t, 1, writer.calls, "the verdict must come from the writer refusing, not from a stubbed transport error")
	})

	t.Run("live refusal writes nothing", func(t *testing.T) {
		client := &stubCDPClient{
			listFn: func(_ context.Context, _ string) ([]cdp.MemberIdentity, error) {
				return nil, cdp.ErrMemberNotFound
			},
			resolveFn: func(_ context.Context, _, _ string) (cdp.ResolveResult, error) {
				return cdp.ResolveResult{Outcome: cdp.OutcomeFound, MemberID: "uuid-fresh"}, nil
			},
		}
		writer := &stubWriter{}
		alias := repairUser()
		alias.Username = "kmaida"
		verdict, _, err := processUser(ctx, &aliasTargetClient{stubCDPClient: client}, writer, pace,
			repairFlags{dryRun: false, live: true}, alias)
		require.NoError(t, err)
		assert.Equal(t, mergerepair.VerdictTargetHoldsAlias, verdict)
		assert.Zero(t, writer.calls)
	})

	t.Run("agreed stored member short-circuits before resolve", func(t *testing.T) {
		client := &stubCDPClient{
			listFn: func(_ context.Context, _ string) ([]cdp.MemberIdentity, error) {
				return []cdp.MemberIdentity{lfid("psmith")}, nil
			},
		}
		verdict, _, err := processUser(ctx, client, &stubWriter{}, pace, repairFlags{dryRun: true}, repairUser())
		require.NoError(t, err)
		assert.Equal(t, mergerepair.VerdictUnchangedAgrees, verdict)
		assert.Zero(t, client.resolveCalls, "no resolve call spent on an agreeing holder")
	})

	t.Run("unverified email is not sent to resolve", func(t *testing.T) {
		user := repairUser()
		user.EmailVerified = false
		client := &stubCDPClient{
			listFn: func(_ context.Context, _ string) ([]cdp.MemberIdentity, error) {
				return nil, cdp.ErrMemberNotFound
			},
			resolveFn: func(_ context.Context, _, email string) (cdp.ResolveResult, error) {
				assert.Empty(t, email)
				return cdp.ResolveResult{Outcome: cdp.OutcomeNoMatch}, nil
			},
		}
		verdict, _, err := processUser(ctx, client, &stubWriter{}, pace, repairFlags{dryRun: true}, user)
		require.NoError(t, err)
		assert.Equal(t, mergerepair.VerdictResolve404, verdict)
	})
}

// aliasTargetClient answers the target-identities read with own-plus-one.
type aliasTargetClient struct {
	*stubCDPClient
}

func (s *aliasTargetClient) ListIdentities(ctx context.Context, memberID string) ([]cdp.MemberIdentity, error) {
	s.listCalls++
	if memberID == "uuid-fresh" {
		return []cdp.MemberIdentity{lfid("kmaida"), lfid("kimmaida")}, nil
	}
	return nil, cdp.ErrMemberNotFound
}

func TestExitCode(t *testing.T) {
	t.Run("clean run exits 0, including dry-run would-repairs", func(t *testing.T) {
		out := tallyReport{}
		out.Run.WalkComplete = true
		out.Counters.Add(mergerepair.VerdictRepaired)
		out.Counters.Add(mergerepair.VerdictUnchangedAgrees)
		assert.Equal(t, 0, exitCode(out))
	})

	t.Run("errors exit 1", func(t *testing.T) {
		out := tallyReport{}
		out.Run.WalkComplete = true
		out.Counters.Add(mergerepair.VerdictError)
		assert.Equal(t, 1, exitCode(out))
	})

	t.Run("enumeration warnings exit 1", func(t *testing.T) {
		out := tallyReport{EnumerationWarnings: []checkError{{UserID: "auth0|x"}}}
		out.Run.WalkComplete = true
		assert.Equal(t, 1, exitCode(out))
	})

	t.Run("interrupted runs exit 1", func(t *testing.T) {
		out := tallyReport{Unchecked: 3}
		assert.Equal(t, 1, exitCode(out))
	})

	t.Run("empty runs exit 1", func(t *testing.T) {
		out := tallyReport{}
		out.Run.WalkComplete = true
		assert.Equal(t, 1, exitCode(out))
	})

	t.Run("a truncated walk exits 1 even when every examined holder was clean", func(t *testing.T) {
		out := tallyReport{}
		out.Counters.Add(mergerepair.VerdictUnchangedAgrees)
		out.Run.WalkComplete = false
		assert.Equal(t, 1, exitCode(out), "a deterministic walk cut short blinds the same tail every run; it must be loud")
	})

	t.Run("a --limit canary is operator intent, not truncation: walk_complete stays true and exit follows the verdicts", func(t *testing.T) {
		out := tallyReport{}
		out.Run.Limit = 25
		out.Run.WalkComplete = true
		out.Counters.Add(mergerepair.VerdictUnchangedAgrees)
		assert.Equal(t, 0, exitCode(out))
	})
}

func TestProcessUserClassificationError(t *testing.T) {
	ctx := context.Background()
	pace := holderwalk.NewLimiter(6000)

	t.Run("an unrecognised resolve outcome is an error row with a message, not a nil dereference", func(t *testing.T) {
		client := &stubCDPClient{
			listFn: func(_ context.Context, _ string) ([]cdp.MemberIdentity, error) {
				return nil, cdp.ErrMemberNotFound
			},
			resolveFn: func(_ context.Context, _, _ string) (cdp.ResolveResult, error) {
				return cdp.ResolveResult{Outcome: cdp.Outcome("something-cdp-added-later")}, nil
			},
		}
		verdict, _, err := processUser(ctx, client, &stubWriter{}, pace, repairFlags{dryRun: true}, repairUser())
		assert.Equal(t, mergerepair.VerdictError, verdict)
		require.Error(t, err, "run records checkErr.Error(); a nil here would panic and lose the whole tally")
		assert.Contains(t, err.Error(), "something-cdp-added-later")
	})
}

func TestRunWritesNothingWhenNothingQualifies(t *testing.T) {
	ctx := context.Background()
	population := []holderUser{
		{UserID: "auth0|agree", Username: "alice", EmailVerified: true, StoredUUID: "uuid-a"},
		{UserID: "auth0|same", Username: "bob", EmailVerified: true, StoredUUID: "uuid-b"},
		{UserID: "auth0|gone", Username: "carol", EmailVerified: true, StoredUUID: "uuid-c"},
	}
	client := &stubCDPClient{
		listFn: func(_ context.Context, memberID string) ([]cdp.MemberIdentity, error) {
			if memberID == "uuid-a" {
				return []cdp.MemberIdentity{lfid("alice")}, nil
			}
			return nil, cdp.ErrMemberNotFound
		},
		resolveFn: func(_ context.Context, lfid, _ string) (cdp.ResolveResult, error) {
			if lfid == "bob" {
				return cdp.ResolveResult{Outcome: cdp.OutcomeFound, MemberID: "uuid-b"}, nil
			}
			return cdp.ResolveResult{Outcome: cdp.OutcomeNoMatch}, nil
		},
	}
	writer := &stubWriter{}
	deps := repairDeps{
		client: client,
		writer: writer,
		list: func(context.Context) ([]holderUser, []string, error) {
			return population, nil, nil
		},
	}
	code, err := run(ctx, deps, repairOptions{ratePerMinute: 6000, dryRun: false, live: true})
	require.NoError(t, err)
	assert.Equal(t, 0, code)
	assert.Zero(t, writer.calls, "no qualifying repair means zero PATCH calls")
	assert.Equal(t, 2, client.resolveCalls, "agree short-circuits; same-member and no-match resolve once each")
}

func TestRunLimitIsIntentNotTruncation(t *testing.T) {
	// Guards the coupling a unit test on exitCode cannot: run itself must
	// leave walk_complete true under --limit, or every canary would exit 1.
	ctx := context.Background()
	population := []holderUser{
		{UserID: "auth0|1", Username: "alice", EmailVerified: true, StoredUUID: "uuid-a"},
		{UserID: "auth0|2", Username: "bob", EmailVerified: true, StoredUUID: "uuid-b"},
	}
	client := &stubCDPClient{
		listFn: func(_ context.Context, memberID string) ([]cdp.MemberIdentity, error) {
			return []cdp.MemberIdentity{lfid(map[string]string{"uuid-a": "alice", "uuid-b": "bob"}[memberID])}, nil
		},
	}
	deps := repairDeps{
		client: client,
		writer: &stubWriter{},
		list: func(context.Context) ([]holderUser, []string, error) {
			return population, nil, nil
		},
	}
	outPath := filepath.Join(t.TempDir(), "tally.json")
	code, err := run(ctx, deps, repairOptions{ratePerMinute: 6000, dryRun: true, limit: 1, outPath: outPath})
	require.NoError(t, err)
	assert.Equal(t, 0, code)

	raw, err := os.ReadFile(outPath)
	require.NoError(t, err)
	var out tallyReport
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.True(t, out.Run.WalkComplete, "--limit is operator intent; only deadline/interrupt truncation flips this")
	assert.Equal(t, 1, out.Run.Limit)
	assert.Equal(t, 1, out.Counters.Examined)
}

func TestTallyJSONKeys(t *testing.T) {
	var tally mergerepair.Tally
	tally.Add(mergerepair.VerdictUnchangedAgrees)
	tally.Add(mergerepair.VerdictTargetHoldsAlias)
	encoded, err := json.Marshal(tally)
	require.NoError(t, err)
	assert.Contains(t, string(encoded), `"unchanged_agrees":1`)
	assert.Contains(t, string(encoded), `"target_holds_alias":1`)
	assert.NotContains(t, string(encoded), "blob")
}

func TestProcessUserMixedCaseStoredUUID(t *testing.T) {
	ctx := context.Background()
	pace := holderwalk.NewLimiter(6000)

	t.Run("legacy uppercase stored value still repairs", func(t *testing.T) {
		user := repairUser()
		user.StoredUUID = "UUID-STALE"
		client := &stubCDPClient{
			listFn: func(_ context.Context, memberID string) ([]cdp.MemberIdentity, error) {
				if memberID == "UUID-STALE" {
					return nil, cdp.ErrMemberNotFound
				}
				return []cdp.MemberIdentity{lfid("psmith")}, nil
			},
			resolveFn: func(_ context.Context, _, _ string) (cdp.ResolveResult, error) {
				return cdp.ResolveResult{Outcome: cdp.OutcomeFound, MemberID: "uuid-fresh"}, nil
			},
		}
		verdict, to, err := processUser(ctx, client, &stubWriter{}, pace, repairFlags{dryRun: true}, user)
		require.NoError(t, err)
		assert.Equal(t, mergerepair.VerdictRepaired, verdict)
		assert.Equal(t, "uuid-fresh", to)
	})
}

func TestProcessUserForeignHolder(t *testing.T) {
	ctx := context.Background()
	pace := holderwalk.NewLimiter(6000)

	t.Run("alive stored member holding someone else's LFID still resolves; a 404 parks it as the foreign-holder class", func(t *testing.T) {
		// Wrong-person holder with no verified email: resolve is LFID-only
		// and returns a plain 404, so only the stored evidence can name the
		// row. Nothing is written in live mode while the clear-vs-leave
		// policy is pending.
		client := &stubCDPClient{
			listFn: func(_ context.Context, memberID string) ([]cdp.MemberIdentity, error) {
				assert.Equal(t, "uuid-stale", memberID)
				return []cdp.MemberIdentity{lfid("someone-else")}, nil
			},
			resolveFn: func(_ context.Context, _, email string) (cdp.ResolveResult, error) {
				assert.Empty(t, email)
				return cdp.ResolveResult{Outcome: cdp.OutcomeNoMatch}, nil
			},
		}
		writer := &stubWriter{}
		unverified := repairUser()
		unverified.EmailVerified = false
		verdict, to, err := processUser(ctx, client, writer, pace, repairFlags{dryRun: false, live: true}, unverified)
		require.NoError(t, err)
		assert.Equal(t, mergerepair.VerdictStoredForeignHolder, verdict)
		assert.Empty(t, to)
		assert.Equal(t, 1, client.resolveCalls, "the stored evidence never skips resolve: the own member may live elsewhere")
		assert.Zero(t, writer.calls)
	})

	t.Run("alive stored member holding someone else's LFID is repaired when resolve finds the own member elsewhere", func(t *testing.T) {
		client := &stubCDPClient{
			listFn: func(_ context.Context, memberID string) ([]cdp.MemberIdentity, error) {
				if memberID == "uuid-stale" {
					return []cdp.MemberIdentity{lfid("someone-else")}, nil
				}
				return []cdp.MemberIdentity{lfid("psmith")}, nil
			},
			resolveFn: func(_ context.Context, _, _ string) (cdp.ResolveResult, error) {
				return cdp.ResolveResult{Outcome: cdp.OutcomeFound, MemberID: "uuid-fresh"}, nil
			},
		}
		writer := &stubWriter{}
		verdict, to, err := processUser(ctx, client, writer, pace, repairFlags{dryRun: false, live: true}, repairUser())
		require.NoError(t, err)
		assert.Equal(t, mergerepair.VerdictRepaired, verdict, "replacing a wrong-person UUID beats parking it")
		assert.Equal(t, "uuid-fresh", to)
		require.Len(t, writer.froms, 1)
		assert.Equal(t, "uuid-stale", writer.froms[0])
	})

	t.Run("without the pre-filter the 409 foreign reason still lands in the same bucket", func(t *testing.T) {
		client := &stubCDPClient{
			resolveFn: func(_ context.Context, _, _ string) (cdp.ResolveResult, error) {
				return cdp.ResolveResult{Outcome: cdp.OutcomeConflict, ConflictReason: cdp.ConflictReasonForeignLFID}, nil
			},
		}
		verdict, _, err := processUser(ctx, client, &stubWriter{}, pace, repairFlags{dryRun: true, noPrefilter: true}, repairUser())
		require.NoError(t, err)
		assert.Equal(t, mergerepair.VerdictStoredForeignHolder, verdict)
		assert.Zero(t, client.listCalls, "audit mode skips the stored read by design")
	})
}
