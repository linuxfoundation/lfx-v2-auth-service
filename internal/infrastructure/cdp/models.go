// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package cdp

// resolveRequest is the body for POST /v1/members/resolve.
//
// `lfids` is required with at least one entry; the provider rejects an
// email-only body as a schema validation failure rather than a 404, so
// callers must skip the call entirely when they hold no LFID username.
type resolveRequest struct {
	LFIDs  []string `json:"lfids"`
	Emails []string `json:"emails,omitempty"`
}

// resolveResponse is the 200 body for POST /v1/members/resolve.
type resolveResponse struct {
	MemberID string `json:"memberId"`
}

// Identity is one CDP member identity, used when creating a member or
// attaching an identity to an existing one.
type Identity struct {
	Value      string `json:"value"`
	Platform   string `json:"platform"`
	Type       string `json:"type"`
	Source     string `json:"source"`
	Verified   bool   `json:"verified"`
	VerifiedBy string `json:"verifiedBy,omitempty"`
}

// createMemberRequest is the body for POST /v1/members.
type createMemberRequest struct {
	DisplayName string     `json:"displayName"`
	Identities  []Identity `json:"identities"`
}

// createMemberResponse is the 201 body for POST /v1/members.
type createMemberResponse struct {
	MemberID string `json:"memberId"`
}

// Outcome classifies a CDP call result that is not an error.
//
// A 404 and a 409 are both legitimate answers rather than failures, and they
// mean different things to the caller, so they are modeled explicitly instead
// of being folded into an error.
type Outcome string

const (
	// OutcomeFound means the identifiers matched exactly one member.
	OutcomeFound Outcome = "found"

	// OutcomeNoMatch means no member matched (404).
	OutcomeNoMatch Outcome = "no-match"

	// OutcomeConflict means the identifiers matched more than one member, or
	// the identity already belongs to a member (409).
	//
	// The create-409 body carries no member id, so this outcome is terminal
	// for a caller that cannot re-resolve.
	OutcomeConflict Outcome = "conflict"
)

// ResolveResult is the outcome of a resolve call. MemberID is set only when
// Outcome is OutcomeFound.
type ResolveResult struct {
	Outcome  Outcome
	MemberID string
}

// CreateResult is the outcome of a create call. MemberID is set only when
// Outcome is OutcomeFound (i.e. the member was created).
//
// On OutcomeConflict the member id is deliberately absent: the provider maps
// the identity conflict to a body carrying `{platform, value, type}` only, so
// recovery requires a re-resolve and is impossible without an LFID username.
type CreateResult struct {
	Outcome  Outcome
	MemberID string
}
