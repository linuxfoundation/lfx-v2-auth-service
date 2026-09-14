// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package mergerepair classifies stored cdp_uuid holders against live CDP
// state for the scheduled merge-repair job (linuxfoundation/segment-web-scripts#43).
//
// Classify is pure: every remote read (stored-member identities, resolve,
// target identities) happens in the caller, so the full decision table is
// unit-testable without Auth0 or CDP. Only VerdictRepaired authorizes a
// write, issued through the writer's compare-and-swap with the observed
// stale UUID.
package mergerepair

import (
	"strings"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/cdp"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/service/cdpidentity"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
)

// Verdict is one decision-table row. String values are the tally's JSON keys.
type Verdict string

// Only VerdictRepaired authorizes a write.
const (
	VerdictRepaired               Verdict = "repaired"
	VerdictUnchangedAgrees        Verdict = "unchanged_agrees"
	VerdictUnchangedSameMember    Verdict = "unchanged_same_member"
	VerdictResolve404             Verdict = "resolve_404"
	VerdictResolve409             Verdict = "resolve_409"
	VerdictStoredForeignHolder    Verdict = "stored_foreign_holder"
	VerdictTargetHoldsAlias       Verdict = "target_holds_alias"
	VerdictTargetHoldsForeignLFID Verdict = "target_holds_foreign_lfid"
	VerdictUnresolvableSkipped    Verdict = "unresolvable_skipped"
	VerdictSkippedNoLFID          Verdict = "skipped_no_lfid"
	VerdictError                  Verdict = "errors"
)

// Holder is one enumerated user carrying a stored cdp_uuid.
type Holder struct {
	// UserID is the Auth0 user id.
	UserID string
	// Username is the LFID. Empty when the holder has no usable resolve input.
	Username string
	// StoredUUID is the cdp_uuid under test. Empty is a walker bug, reported
	// as VerdictError rather than filed into a silent bucket.
	StoredUUID string
}

// StoredCheck is what the stored-member identities read proved.
type StoredCheck struct {
	// Found is false when the read hit cdp.ErrMemberNotFound (merged away).
	Found bool
	// HoldsOwnLFID reports the stored member still carries the holder's
	// LFID, verified: resolve ignores unverified identities, so an
	// unverified carry is not agreement (producers filter first).
	HoldsOwnLFID bool
	// HoldsForeignLFID reports the stored member carries somebody else's
	// LFID. With HoldsOwnLFID false this is the wrong-person holder class
	// (linuxfoundation/crowd.dev#4574): the stored value was never this user's.
	HoldsForeignLFID bool
}

// ResolveCheck mirrors cdp.ResolveResult for the holder's identifiers.
type ResolveCheck struct {
	Outcome        cdp.Outcome
	MemberID       string
	ConflictReason cdp.ConflictReason
}

// Classify maps fetched state to a verdict. The returned member id is set
// only for VerdictRepaired and is the resolve target to CAS-write.
//
// A warehouse unresolvable_no_match row is never an input here (the job has
// no verdict feed by design); operationally it arrives as resolve-no-match
// or an empty target, both of which skip without writing.
func Classify(h Holder, stored StoredCheck, res ResolveCheck, target []cdp.MemberIdentity) (Verdict, string) {
	if strings.TrimSpace(h.Username) == "" {
		return VerdictSkippedNoLFID, ""
	}
	if strings.TrimSpace(h.StoredUUID) == "" {
		return VerdictError, ""
	}
	if stored.Found && stored.HoldsOwnLFID {
		return VerdictUnchangedAgrees, ""
	}
	// The stored member holding somebody else's LFID (linuxfoundation/crowd.dev#4574)
	// is decided by the stored member's own identities, not by the resolve
	// answer — CDP only says "Member holds a different LFID" when the job sent
	// a verified email, so a holder with no verified email would otherwise
	// vanish into resolve_404. But a resolve that finds this user's own
	// member elsewhere still wins: replacing a wrong-person UUID beats any
	// clear-vs-leave policy, so the foreign-holder bucket is only the
	// fallback for the outcomes that cannot repair (404 / 409 / unknown).
	storedForeign := stored.Found && stored.HoldsForeignLFID
	switch res.Outcome {
	case cdp.OutcomeNoMatch:
		if storedForeign {
			return VerdictStoredForeignHolder, ""
		}
		return VerdictResolve404, ""
	case cdp.OutcomeConflict:
		if storedForeign || res.ConflictReason == cdp.ConflictReasonForeignLFID {
			// The reason alone carries the row when the stored read was
			// skipped (--no-prefilter) or the member vanished between calls.
			// A foreign-LFID conflict names the unique candidate, which holds
			// no verified LFID of this holder — so the stored UUID is
			// wrong-person or gone, and either way unrepairable here.
			// Whether these are cleared or left is still an open policy
			// question, so no mode writes here.
			return VerdictStoredForeignHolder, ""
		}
		return VerdictResolve409, ""
	case cdp.OutcomeFound:
		// Anything else is a caller bug; fail loud, not silent.
		if strings.TrimSpace(res.MemberID) == "" {
			return VerdictError, ""
		}
	default:
		return VerdictError, ""
	}
	if strings.EqualFold(strings.TrimSpace(res.MemberID), strings.TrimSpace(h.StoredUUID)) {
		if storedForeign {
			// Resolve re-found the same wrong-person member: nothing to
			// repair towards, so this is the foreign-holder class too.
			return VerdictStoredForeignHolder, ""
		}
		return VerdictUnchangedSameMember, ""
	}
	return gateTarget(h.Username, target, res.MemberID)
}

// VerifiedOnly returns the member's verified identities. Resolve consults
// verified identities only, so these are the only ones that can authorize an
// own-LFID decision; the foreign count deliberately sees the full set.
func VerifiedOnly(ids []cdp.MemberIdentity) []cdp.MemberIdentity {
	out := make([]cdp.MemberIdentity, 0, len(ids))
	for _, id := range ids {
		if id.Verified {
			out = append(out, id)
		}
	}
	return out
}

// gateTarget applies the target guard to a resolve-to-other member. The rule
// is asymmetric by design: only a verified own LFID authorizes a repair
// (resolve filters verified=true, so an unverified match can never have
// produced it), while the foreign count sees every LFID value — an
// unverified other username still makes the target shared, never own-only.
func gateTarget(username string, target []cdp.MemberIdentity, memberID string) (Verdict, string) {
	own := cdpidentity.HoldsLFID(VerifiedOnly(target), username)
	others := distinctForeignLFIDs(target, username)
	switch {
	case own && len(others) == 0:
		return VerdictRepaired, memberID
	case len(others) == 0:
		// No usable LFID identities at all: nothing proves ownership.
		return VerdictUnresolvableSkipped, ""
	case own && len(others) == 1:
		return VerdictTargetHoldsAlias, ""
	default:
		// Own absent, or own plus two or more others — the blob is this
		// extreme, with no separate counter by design.
		return VerdictTargetHoldsForeignLFID, ""
	}
}

// distinctForeignLFIDs counts distinct LFID usernames that are not the
// holder's, case-insensitively: the discriminator counts usernames, not
// identity rows, so a repeated alias stays an alias.
func distinctForeignLFIDs(target []cdp.MemberIdentity, username string) map[string]struct{} {
	others := map[string]struct{}{}
	for _, identity := range target {
		if identity.Platform != constants.LFIDPlatform || identity.Type != constants.CDPIdentityTypeUsername {
			continue
		}
		value := strings.ToLower(strings.TrimSpace(identity.Value))
		if value == "" || strings.EqualFold(value, username) {
			continue
		}
		others[value] = struct{}{}
	}
	return others
}

// Tally counts verdicts for one run. JSON keys match the tally contract.
type Tally struct {
	Examined               int `json:"examined"`
	Repaired               int `json:"repaired"`
	UnchangedAgrees        int `json:"unchanged_agrees"`
	UnchangedSameMember    int `json:"unchanged_same_member"`
	Resolve404             int `json:"resolve_404"`
	Resolve409             int `json:"resolve_409"`
	StoredForeignHolder    int `json:"stored_foreign_holder"`
	TargetHoldsAlias       int `json:"target_holds_alias"`
	TargetHoldsForeignLFID int `json:"target_holds_foreign_lfid"`
	UnresolvableSkipped    int `json:"unresolvable_skipped"`
	SkippedNoLFID          int `json:"skipped_no_lfid"`
	Errors                 int `json:"errors"`
}

// Add records one holder's verdict.
func (t *Tally) Add(v Verdict) {
	t.Examined++
	switch v {
	case VerdictRepaired:
		t.Repaired++
	case VerdictUnchangedAgrees:
		t.UnchangedAgrees++
	case VerdictUnchangedSameMember:
		t.UnchangedSameMember++
	case VerdictResolve404:
		t.Resolve404++
	case VerdictResolve409:
		t.Resolve409++
	case VerdictStoredForeignHolder:
		t.StoredForeignHolder++
	case VerdictTargetHoldsAlias:
		t.TargetHoldsAlias++
	case VerdictTargetHoldsForeignLFID:
		t.TargetHoldsForeignLFID++
	case VerdictUnresolvableSkipped:
		t.UnresolvableSkipped++
	case VerdictSkippedNoLFID:
		t.SkippedNoLFID++
	default:
		t.Errors++
	}
}
