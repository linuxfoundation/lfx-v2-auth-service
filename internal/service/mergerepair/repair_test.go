// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package mergerepair_test

import (
	"fmt"
	"testing"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/cdp"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/service/mergerepair"
	"github.com/stretchr/testify/assert"
)

func lfidIdentities(values ...string) []cdp.MemberIdentity {
	out := make([]cdp.MemberIdentity, 0, len(values))
	for _, v := range values {
		out = append(out, cdp.MemberIdentity{Platform: "lfid", Type: "username", Value: v})
	}
	return out
}

// blobIdentities builds a 25-LFID blob member (linuxfoundation/segment-web-scripts#46),
// including the two absorbed holders.
func blobIdentities() []cdp.MemberIdentity {
	values := []string{"absol", "decodableminion", "mengjinyan"}
	for i := 0; i < 22; i++ {
		values = append(values, fmt.Sprintf("absorbed-%02d", i))
	}
	return lfidIdentities(values...)
}

func TestClassify(t *testing.T) {
	holder := mergerepair.Holder{UserID: "auth0|1", Username: "psmith", StoredUUID: "uuid-stale"}
	aliveAgrees := mergerepair.StoredCheck{Found: true, HoldsOwnLFID: true}
	gone := mergerepair.StoredCheck{Found: false}

	t.Run("stored alive and agrees is a no-op", func(t *testing.T) {
		v, to := mergerepair.Classify(holder, aliveAgrees,
			mergerepair.ResolveCheck{Outcome: cdp.OutcomeFound, MemberID: "uuid-stale"},
			lfidIdentities("psmith"))
		assert.Equal(t, mergerepair.VerdictUnchangedAgrees, v)
		assert.Empty(t, to)
	})

	t.Run("re-resolve to the same member is a no-op", func(t *testing.T) {
		v, to := mergerepair.Classify(holder, gone,
			mergerepair.ResolveCheck{Outcome: cdp.OutcomeFound, MemberID: "uuid-stale"},
			lfidIdentities("psmith"))
		assert.Equal(t, mergerepair.VerdictUnchangedSameMember, v)
		assert.Empty(t, to)
	})

	t.Run("resolve no-match is refused", func(t *testing.T) {
		v, to := mergerepair.Classify(holder, gone,
			mergerepair.ResolveCheck{Outcome: cdp.OutcomeNoMatch}, nil)
		assert.Equal(t, mergerepair.VerdictResolve404, v)
		assert.Empty(t, to)
	})

	t.Run("resolve multi-match conflict is refused", func(t *testing.T) {
		v, to := mergerepair.Classify(holder, gone,
			mergerepair.ResolveCheck{Outcome: cdp.OutcomeConflict, ConflictReason: cdp.ConflictReasonMultipleMatches}, nil)
		assert.Equal(t, mergerepair.VerdictResolve409, v)
		assert.Empty(t, to)
	})

	t.Run("a 409 with no recognised reason stays the generic refusal", func(t *testing.T) {
		v, _ := mergerepair.Classify(holder, gone,
			mergerepair.ResolveCheck{Outcome: cdp.OutcomeConflict}, nil)
		assert.Equal(t, mergerepair.VerdictResolve409, v, "an unknown reason must never be promoted to the foreign-holder row")
	})

	t.Run("a stored member holding someone else's LFID is the foreign-holder class when resolve cannot repair", func(t *testing.T) {
		// Defined by the stored member's identities, not the 409: CDP only
		// says "different LFID" when a verified email was sent, so a holder
		// with no verified email would otherwise vanish into resolve_404.
		foreignHolder := mergerepair.StoredCheck{Found: true, HoldsOwnLFID: false, HoldsForeignLFID: true}
		for name, res := range map[string]mergerepair.ResolveCheck{
			"resolve 404 (no verified email)":  {Outcome: cdp.OutcomeNoMatch},
			"resolve 409 foreign (email sent)": {Outcome: cdp.OutcomeConflict, ConflictReason: cdp.ConflictReasonForeignLFID},
			"resolve 409 multi-match":          {Outcome: cdp.OutcomeConflict, ConflictReason: cdp.ConflictReasonMultipleMatches},
			"resolve 200 same wrong member":    {Outcome: cdp.OutcomeFound, MemberID: "uuid-stale"},
		} {
			v, to := mergerepair.Classify(holder, foreignHolder, res, nil)
			assert.Equal(t, mergerepair.VerdictStoredForeignHolder, v, name)
			assert.Empty(t, to, name+": no write in either mode while the clear-vs-leave policy is open")
		}
	})

	t.Run("a stored foreign holder whose own member lives elsewhere is repaired, not parked", func(t *testing.T) {
		// The best outcome for the wrong-person class: replacing the UUID
		// beats any clear-vs-leave policy, so resolve wins over the stored
		// evidence whenever it can repair.
		foreignHolder := mergerepair.StoredCheck{Found: true, HoldsOwnLFID: false, HoldsForeignLFID: true}
		v, to := mergerepair.Classify(holder, foreignHolder,
			mergerepair.ResolveCheck{Outcome: cdp.OutcomeFound, MemberID: "uuid-fresh"},
			lfidIdentities("psmith"))
		assert.Equal(t, mergerepair.VerdictRepaired, v)
		assert.Equal(t, "uuid-fresh", to)
	})

	t.Run("a stored foreign holder resolving to another foreign member is refused as target-foreign", func(t *testing.T) {
		foreignHolder := mergerepair.StoredCheck{Found: true, HoldsOwnLFID: false, HoldsForeignLFID: true}
		v, to := mergerepair.Classify(holder, foreignHolder,
			mergerepair.ResolveCheck{Outcome: cdp.OutcomeFound, MemberID: "uuid-fresh"},
			lfidIdentities("stranger"))
		assert.Equal(t, mergerepair.VerdictTargetHoldsForeignLFID, v, "the target guard, not the stored evidence, names this refusal")
		assert.Empty(t, to)
	})

	t.Run("the 409 foreign reason alone lands in the same bucket when the stored read is skipped", func(t *testing.T) {
		unknownStored := mergerepair.StoredCheck{} // --no-prefilter: nothing read
		v, to := mergerepair.Classify(holder, unknownStored,
			mergerepair.ResolveCheck{Outcome: cdp.OutcomeConflict, ConflictReason: cdp.ConflictReasonForeignLFID}, nil)
		assert.Equal(t, mergerepair.VerdictStoredForeignHolder, v)
		assert.Empty(t, to)
	})

	t.Run("stored alive with no LFID identities at all is not an agreement", func(t *testing.T) {
		// Alive, holds neither the own nor a foreign LFID (e.g. email-only
		// member): resolve decides, exactly as for a gone member.
		aliveNoLFID := mergerepair.StoredCheck{Found: true}
		v, to := mergerepair.Classify(holder, aliveNoLFID,
			mergerepair.ResolveCheck{Outcome: cdp.OutcomeFound, MemberID: "uuid-fresh"},
			lfidIdentities("psmith"))
		assert.Equal(t, mergerepair.VerdictRepaired, v, "liveness alone never no-ops")
		assert.Equal(t, "uuid-fresh", to)
	})

	t.Run("own-only target repairs", func(t *testing.T) {
		v, to := mergerepair.Classify(holder, gone,
			mergerepair.ResolveCheck{Outcome: cdp.OutcomeFound, MemberID: "uuid-fresh"},
			lfidIdentities("psmith"))
		assert.Equal(t, mergerepair.VerdictRepaired, v)
		assert.Equal(t, "uuid-fresh", to)
	})

	t.Run("own plus exactly one other is an alias refusal", func(t *testing.T) {
		h := mergerepair.Holder{UserID: "auth0|2", Username: "kmaida", StoredUUID: "uuid-stale"}
		v, to := mergerepair.Classify(h, gone,
			mergerepair.ResolveCheck{Outcome: cdp.OutcomeFound, MemberID: "uuid-fresh"},
			lfidIdentities("kmaida", "kimmaida"))
		assert.Equal(t, mergerepair.VerdictTargetHoldsAlias, v)
		assert.Empty(t, to)
	})

	t.Run("own absent is a foreign refusal", func(t *testing.T) {
		v, to := mergerepair.Classify(holder, gone,
			mergerepair.ResolveCheck{Outcome: cdp.OutcomeFound, MemberID: "uuid-fresh"},
			lfidIdentities("stranger"))
		assert.Equal(t, mergerepair.VerdictTargetHoldsForeignLFID, v)
		assert.Empty(t, to)
	})

	t.Run("own plus two others is a foreign refusal", func(t *testing.T) {
		v, to := mergerepair.Classify(holder, gone,
			mergerepair.ResolveCheck{Outcome: cdp.OutcomeFound, MemberID: "uuid-fresh"},
			lfidIdentities("psmith", "kimmaida", "zuzoci2"))
		assert.Equal(t, mergerepair.VerdictTargetHoldsForeignLFID, v)
		assert.Empty(t, to)
	})

	t.Run("a 25-LFID blob is a foreign refusal with no separate counter", func(t *testing.T) {
		for _, username := range []string{"decodableminion", "mengjinyan"} {
			h := mergerepair.Holder{UserID: "auth0|" + username, Username: username, StoredUUID: "uuid-stale"}
			v, to := mergerepair.Classify(h, gone,
				mergerepair.ResolveCheck{Outcome: cdp.OutcomeFound, MemberID: "d6f4a060-f818-4fab-bf36-73032634fe7c"},
				blobIdentities())
			assert.Equal(t, mergerepair.VerdictTargetHoldsForeignLFID, v, username)
			assert.Empty(t, to, username)
		}
	})

	t.Run("empty target is unresolvable and never written", func(t *testing.T) {
		v, to := mergerepair.Classify(holder, gone,
			mergerepair.ResolveCheck{Outcome: cdp.OutcomeFound, MemberID: "uuid-fresh"},
			nil)
		assert.Equal(t, mergerepair.VerdictUnresolvableSkipped, v)
		assert.Empty(t, to)
	})

	t.Run("holder without an LFID is skipped", func(t *testing.T) {
		h := mergerepair.Holder{UserID: "auth0|3", StoredUUID: "uuid-stale"}
		v, to := mergerepair.Classify(h, gone,
			mergerepair.ResolveCheck{Outcome: cdp.OutcomeFound, MemberID: "uuid-fresh"},
			lfidIdentities("psmith"))
		assert.Equal(t, mergerepair.VerdictSkippedNoLFID, v)
		assert.Empty(t, to)
	})

	t.Run("empty stored UUID is an error, never a silent bucket", func(t *testing.T) {
		h := mergerepair.Holder{UserID: "auth0|4", Username: "psmith"}
		v, _ := mergerepair.Classify(h, gone,
			mergerepair.ResolveCheck{Outcome: cdp.OutcomeFound, MemberID: "uuid-fresh"},
			lfidIdentities("psmith"))
		assert.Equal(t, mergerepair.VerdictError, v)
	})

	t.Run("duplicate foreign values count as one other username", func(t *testing.T) {
		h := mergerepair.Holder{UserID: "auth0|2", Username: "kmaida", StoredUUID: "uuid-stale"}
		v, _ := mergerepair.Classify(h, gone,
			mergerepair.ResolveCheck{Outcome: cdp.OutcomeFound, MemberID: "uuid-fresh"},
			lfidIdentities("kmaida", "KIMMAIDA", " kimmaida "))
		assert.Equal(t, mergerepair.VerdictTargetHoldsAlias, v)
	})

	t.Run("non-lfid identities never decide", func(t *testing.T) {
		v, to := mergerepair.Classify(holder, gone,
			mergerepair.ResolveCheck{Outcome: cdp.OutcomeFound, MemberID: "uuid-fresh"},
			[]cdp.MemberIdentity{
				{Platform: "lfid", Type: "username", Value: "psmith"},
				{Platform: "email", Type: "email", Value: "someone-else@example.com"},
			})
		assert.Equal(t, mergerepair.VerdictRepaired, v)
		assert.Equal(t, "uuid-fresh", to)
	})
}

func TestTally(t *testing.T) {
	var tally mergerepair.Tally
	tally.Add(mergerepair.VerdictRepaired)
	tally.Add(mergerepair.VerdictUnchangedAgrees)
	tally.Add(mergerepair.VerdictTargetHoldsForeignLFID)
	tally.Add(mergerepair.VerdictError)

	assert.Equal(t, 4, tally.Examined)
	assert.Equal(t, 1, tally.Repaired)
	assert.Equal(t, 1, tally.UnchangedAgrees)
	assert.Equal(t, 1, tally.TargetHoldsForeignLFID)
	assert.Equal(t, 1, tally.Errors)
}
