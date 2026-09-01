// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package provisioning gives a newly verified user a CDP identity and writes
// the resulting member id back to Auth0.
//
// It is driven by an Auth0 Event Stream, whose delivery is at-least-once and
// unordered, so every path here is idempotent: the gate skips users who already
// carry a UUID, and the CDP client reports an already-attached identity as
// success.
package provisioning

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/cdp"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	errs "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

// Request is one provisioning attempt, built by the consumer from an Auth0
// event payload.
type Request struct {
	// UserID is the Auth0 user id.
	UserID string

	// Username is the LFID. It MUST come from the database-connection
	// identity; another connection's username is not an LFID.
	Username string

	// Email is a secondary resolve identifier, used only when verified.
	Email string

	// EmailVerified is the payload's verification flag, kept nullable because
	// the field has a real third state and absence must not read as false.
	// The authoritative value comes from Auth0, not from here.
	EmailVerified *bool

	// StoredCDPUUID is the `cdp_uuid` carried on the event payload. Its
	// presence is the second half of the gate.
	StoredCDPUUID string

	// HasDatabaseIdentity reports whether the user holds an identity on the
	// Auth0 database connection.
	HasDatabaseIdentity bool

	// DisplayName seeds a newly created CDP member.
	DisplayName string
}

// Outcome classifies the result of a provisioning attempt.
type Outcome string

const (
	// OutcomeProvisioned means a member id was resolved or created and written
	// back to Auth0.
	OutcomeProvisioned Outcome = "provisioned"

	// OutcomeSkipped means the request was deliberately not acted on. It is a
	// success from the trigger's point of view — the event must not be
	// replayed.
	OutcomeSkipped Outcome = "skipped"
)

// Result reports what happened, so the caller can log it and decide whether
// to advance the offset. Reason is always set on a skip.
type Result struct {
	Outcome  Outcome
	Reason   string
	MemberID string
}

// Skip reasons, recorded on the trace so a quiet endpoint can be told apart
// from a broken one.
const (
	reasonEmailNotVerified   = "email-not-verified"
	reasonAlreadyProvisioned = "already-has-cdp-uuid"
	reasonNoDatabaseIdentity = "no-database-identity"
	reasonNoLFIDUsername     = "missing-lfid-username"
	reasonUserNotFound       = "user-not-found"
	reasonConflict           = "cdp-identity-conflict"

	// reasonMemberHoldsForeignLFID marks a member that already belongs to a
	// different person. Counting these is how a rise in cross-person merges
	// becomes visible.
	reasonMemberHoldsForeignLFID = "cdp-member-holds-foreign-lfid"

	// reasonLFIDOnAnotherMember marks the write-side twin: the attach was
	// refused because this LFID is verified on a different member. Kept
	// separate from the read-side reason so the two are countable apart.
	reasonLFIDOnAnotherMember = "cdp-lfid-on-another-member"

	// reasonOutOfBandNoMatch marks a user an out-of-band job has already
	// resolved to no CDP member. Counted separately from the other skips
	// because its rate is how a sweep pass becomes visible from here.
	reasonOutOfBandNoMatch = "out-of-band-no-match"
)

// Orchestrator provisions a CDP identity for a verified user.
type Orchestrator interface {
	Provision(ctx context.Context, req Request) (Result, error)
}

type orchestrator struct {
	cdpClient cdp.Client
	metadata  port.CDPMetadataReaderWriter
}

// Option configures the orchestrator.
type Option func(*orchestrator)

// WithCDPClient sets the CDP client.
func WithCDPClient(client cdp.Client) Option {
	return func(o *orchestrator) {
		o.cdpClient = client
	}
}

// WithMetadataStore sets the Auth0 `app_metadata` reader/writer.
func WithMetadataStore(store port.CDPMetadataReaderWriter) Option {
	return func(o *orchestrator) {
		o.metadata = store
	}
}

// NewOrchestrator creates the provisioning orchestrator.
func NewOrchestrator(options ...Option) Orchestrator {
	o := &orchestrator{}
	for _, option := range options {
		option(o)
	}
	return o
}

// Provision runs resolve, then attach or create, then writes the member id
// back to Auth0.
//
// A returned error means the attempt is worth retrying: the consumer leaves the
// offset unadvanced and replays the event on reconnect. A skip is a final
// answer and must not be replayed.
func (o *orchestrator) Provision(ctx context.Context, req Request) (Result, error) {
	if o.cdpClient == nil || o.metadata == nil {
		return Result{}, errs.NewUnexpected("provisioning orchestrator is not fully configured")
	}
	if strings.TrimSpace(req.UserID) == "" {
		return Result{}, errs.NewValidation("user_id is required")
	}

	// Cheap pre-filter on the event payload. Most deliveries are ordinary user
	// updates that fail this, and skipping them here keeps the authoritative
	// read below off the common path.
	//
	// Only an explicit false rules a delivery out. A missing email_verified is
	// not a "no", and the live payload shape is still unconfirmed — collapsing
	// absent to false here would skip every user permanently, and the skip
	// would look like an ordinary unverified account rather than a bad field
	// path.
	if req.EmailVerified != nil && !*req.EmailVerified {
		return skip(reasonEmailNotVerified), nil
	}
	if strings.TrimSpace(req.StoredCDPUUID) != "" {
		return skip(reasonAlreadyProvisioned), nil
	}

	// Re-read from Auth0 before deciding anything. The payload is a snapshot
	// taken when the event was produced, and replay can present it hours
	// later — these fields decide whether this service writes to CDP on a
	// user's behalf, so they are read from the record rather than from a
	// snapshot that may since have gone stale or arrived malformed.
	state, err := o.metadata.ReadProvisioningState(ctx, req.UserID)
	if err != nil {
		// A deleted user is a permanent answer. Surfacing it as a failure
		// would have the consumer replay the event until the attempt ceiling
		// gives up.
		var notFound errs.NotFound
		if errors.As(err, &notFound) {
			return skip(reasonUserNotFound), nil
		}
		return Result{}, err
	}

	// The gate. Both halves are required: `user.updated` fires on every user
	// record mutation, including this flow's own write-back, so gating on
	// verification alone would make provisioning re-trigger on itself.
	if !state.EmailVerified {
		return skip(reasonEmailNotVerified), nil
	}
	if strings.TrimSpace(state.UUID) != "" {
		return skip(reasonAlreadyProvisioned), nil
	}

	// The uuid is absent by here, so a `backfill` source means an out-of-band
	// job already asked CDP for this user and CDP had no member.
	//
	// Acting on that would create one. The marker write bumps Auth0
	// `updated_at`, which emits `user.updated`, which arrives here describing a
	// verified user holding no uuid — exactly what the gate above admits. The
	// trigger would then be an administrative pass rather than anything the
	// user did: a full sweep of the 30-day cohort would create a CDP member for
	// roughly 12,200 people who never logged in, and those records are
	// permanent once the feature is enabled.
	//
	// Keyed on the source rather than on marker presence. The login path writes
	// the same marker for the same answer, and those users stay eligible: they
	// are here because they logged in, which is the activity this flow exists
	// to serve. Nobody is dropped either way — a swept user who later logs in
	// gets a live re-resolve once the Action's 24h TTL lapses, and its write
	// moves the source to `login-resolve`, which reopens this gate.
	if strings.TrimSpace(state.Source) == constants.CDPUUIDSourceBackfill {
		return skip(reasonOutOfBandNoMatch), nil
	}

	// Only database-connection users hold an LFID, and resolve requires one.
	if !state.HasDatabaseIdentity {
		return skip(reasonNoDatabaseIdentity), nil
	}
	username := strings.TrimSpace(state.Username)
	if username == "" {
		// Unexpected for a database user, and not recoverable: an email-only
		// create would 409 without returning the conflicting member id, so the
		// recovery re-resolve is impossible and the call would loop.
		slog.ErrorContext(ctx, "database user has no LFID username, skipping provisioning",
			"user_id", redaction.Redact(req.UserID),
		)
		return skip(reasonNoLFIDUsername), nil
	}

	// The email is a secondary identifier that only widens the match, so it
	// also comes from Auth0 rather than the payload — a forged one could widen
	// the match onto somebody else's member.
	memberID, result, err := o.findOrCreateMember(ctx, req, state, username)
	if err != nil {
		return Result{}, err
	}
	if memberID == "" {
		return result, nil
	}

	if err := o.metadata.WriteCDPMetadata(ctx, req.UserID, port.CDPMetadata{
		UUID:      strings.ToLower(memberID),
		Source:    constants.CDPUUIDSourceProvisioning,
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		// A write-once rejection means another writer got there first with a
		// value of its own. The end state is correct, so the event is done.
		var conflict errs.Conflict
		if errors.As(err, &conflict) {
			slog.WarnContext(ctx, "CDP uuid already written by another path",
				"user_id", redaction.Redact(req.UserID),
			)
			return Result{Outcome: OutcomeSkipped, Reason: reasonAlreadyProvisioned, MemberID: memberID}, nil
		}
		return Result{}, err
	}

	return Result{Outcome: OutcomeProvisioned, MemberID: memberID}, nil
}

// findOrCreateMember resolves the user to a CDP member, attaching the LFID
// identity when one already exists and creating a member when none does.
//
// An empty member id with a nil error means the attempt ended in a skip, which
// the returned Result describes.
func (o *orchestrator) findOrCreateMember(ctx context.Context, req Request, state port.UserProvisioningState, username string) (string, Result, error) {
	email := strings.TrimSpace(state.Email)

	resolved, err := o.cdpClient.Resolve(ctx, username, email)
	if err != nil {
		return "", Result{}, err
	}

	switch resolved.Outcome {
	case cdp.OutcomeFound:
		held, errIdentities := o.cdpClient.ListIdentities(ctx, resolved.MemberID)
		if errIdentities != nil {
			return "", Result{}, errIdentities
		}
		if other, occupied := foreignLFID(held, username); occupied {
			// The member already carries somebody else's LFID, so it holds
			// more than one person. Attaching would add a third and make the
			// eventual split harder. A resolve conflict is CDP telling us it
			// is unsure; this is the same ambiguity with CDP unaware of it.
			slog.WarnContext(ctx, "CDP member already holds another LFID, skipping provisioning",
				"user_id", redaction.Redact(req.UserID),
				"member_id", redaction.Redact(resolved.MemberID),
				"existing_lfid", redaction.Redact(other),
			)
			return "", skip(reasonMemberHoldsForeignLFID), nil
		}

		attached, errAttach := o.cdpClient.AttachIdentity(ctx, resolved.MemberID, lfidIdentity(username))
		if errAttach != nil {
			return "", Result{}, errAttach
		}
		if attached.Outcome == cdp.OutcomeConflict {
			// The LFID is verified on a different member than the one resolve
			// returned, so CDP disagrees with itself. The read-side guard above
			// cannot see this: the foreign identity is on the other member, not
			// this one.
			//
			// The 409 body names the winner, looked up on the primary while the
			// error was built — so unlike a re-resolve it is neither subject to
			// replica lag nor liable to come back as a multi-match. It is still
			// verified before use rather than trusted: storing a member id is
			// permanent, and the reason for skipping here in the first place is
			// that CDP has contradicted itself.
			return o.adoptConflictMember(ctx, req, resolved.MemberID, attached.ConflictMemberID, username)
		}
		return resolved.MemberID, Result{}, nil

	case cdp.OutcomeConflict:
		// The identifiers match more than one member. Picking one would store
		// an arbitrary identity permanently, so this waits for CDP to merge.
		slog.WarnContext(ctx, "CDP resolve conflicted, skipping provisioning",
			"user_id", redaction.Redact(req.UserID),
		)
		return "", skip(reasonConflict), nil
	}

	// No member: create one seeded with the LFID identity.
	created, err := o.cdpClient.CreateMember(ctx, displayName(state, username), lfidIdentity(username))
	if err != nil {
		return "", Result{}, err
	}

	if created.Outcome == cdp.OutcomeConflict {
		// Somebody claimed the identity between the resolve and the create.
		// The 409 body carries no member id, so recover by re-resolving — which
		// works here because this path always holds an LFID username.
		reResolved, errResolve := o.cdpClient.Resolve(ctx, username, email)
		if errResolve != nil {
			return "", Result{}, errResolve
		}
		switch reResolved.Outcome {
		case cdp.OutcomeFound:
			// Verified below before any id is stored.
		case cdp.OutcomeConflict:
			// Several members matched. Only CDP can merge them, so a replay
			// asks the same question and gets the same answer.
			slog.WarnContext(ctx, "CDP create conflicted and re-resolve matched several members, skipping provisioning",
				"user_id", redaction.Redact(req.UserID),
			)
			return "", skip(reasonConflict), nil
		default:
			// The 409 proves the LFID is claimed, so a no-match is the read
			// replica trailing the primary rather than an answer. Replaying
			// the event asks again; the attempt ceiling bounds it. An outcome
			// this code does not know is retried for the same reason: nothing
			// is stored, so asking again is cheaper than assuming.
			slog.WarnContext(ctx, "CDP create conflicted but the claimed LFID does not resolve yet, retrying",
				"user_id", redaction.Redact(req.UserID),
				"resolve_outcome", string(reResolved.Outcome),
			)
			return "", Result{}, errs.NewUnexpected("CDP create conflicted but the claimed LFID does not resolve yet")
		}
		// Nothing is attached on this path — the 409 means the identity is
		// already attached — so this read is also what proves the member still
		// exists. It fails rather than reading empty when the member has gone,
		// which matters because the id below is stored write-once and becomes
		// a Segment user_id that cannot be corrected afterwards.
		held, errIdentities := o.cdpClient.ListIdentities(ctx, reResolved.MemberID)
		if errIdentities != nil {
			return "", Result{}, errIdentities
		}
		if other, occupied := foreignLFID(held, username); occupied {
			slog.WarnContext(ctx, "CDP member already holds another LFID, skipping provisioning",
				"user_id", redaction.Redact(req.UserID),
				"member_id", redaction.Redact(reResolved.MemberID),
				"existing_lfid", redaction.Redact(other),
			)
			return "", skip(reasonMemberHoldsForeignLFID), nil
		}
		if !holdsLFID(held, username) {
			// Should not happen: the 409 says the identity is attached
			// somewhere, and a single-member re-resolve should be the member
			// holding it. Logged rather than enforced because CDP's
			// read-after-write behaviour is undocumented, so this may simply
			// be the attach not yet visible — and refusing on an unmeasured
			// assumption would drop users this trigger provisions correctly
			// today. Measure it here first; gate on it once it is known.
			slog.WarnContext(ctx, "CDP create conflicted but the resolved member does not yet show the LFID",
				"user_id", redaction.Redact(req.UserID),
				"member_id", redaction.Redact(reResolved.MemberID),
				"identities_held", len(held),
			)
		}
		return reResolved.MemberID, Result{}, nil
	}

	return created.MemberID, Result{}, nil
}

// adoptConflictMember decides what to store after an attach-409.
//
// The member CDP named is only adopted once its identities confirm it: it must
// actually hold this user's LFID and no one else's. A contradictory answer is
// a skip, since only CDP can resolve it. A failed lookup is returned instead,
// so the event is retried: nothing has been stored yet, and the answer may
// differ on the next attempt.
func (o *orchestrator) adoptConflictMember(
	ctx context.Context,
	req Request,
	resolvedMemberID string,
	conflictMemberID string,
	username string,
) (string, Result, error) {
	if conflictMemberID == "" {
		slog.WarnContext(ctx, "CDP LFID belongs to another member, skipping provisioning",
			"user_id", redaction.Redact(req.UserID),
			"member_id", redaction.Redact(resolvedMemberID),
			"reason", "the conflict response named no member",
		)
		return "", skip(reasonLFIDOnAnotherMember), nil
	}

	held, err := o.cdpClient.ListIdentities(ctx, conflictMemberID)
	if err != nil {
		// Nothing is stored yet, so a replay is free and a transient CDP
		// failure should not cost this user their trigger. The re-resolve
		// path above propagates the identical error for the same reason.
		return "", Result{}, err
	}

	if other, occupied := foreignLFID(held, username); occupied {
		slog.WarnContext(ctx, "the conflicting CDP member holds another LFID, skipping provisioning",
			"user_id", redaction.Redact(req.UserID),
			"conflict_member_id", redaction.Redact(conflictMemberID),
			"existing_lfid", redaction.Redact(other),
		)
		return "", skip(reasonLFIDOnAnotherMember), nil
	}

	if !holdsLFID(held, username) {
		// It was named as the holder of this LFID and does not hold it, so the
		// two answers disagree and neither is worth making permanent.
		slog.WarnContext(ctx, "the conflicting CDP member does not hold this LFID, skipping provisioning",
			"user_id", redaction.Redact(req.UserID),
			"conflict_member_id", redaction.Redact(conflictMemberID),
		)
		return "", skip(reasonLFIDOnAnotherMember), nil
	}

	slog.InfoContext(ctx, "adopting the CDP member that holds this LFID",
		"user_id", redaction.Redact(req.UserID),
		"resolved_member_id", redaction.Redact(resolvedMemberID),
		"conflict_member_id", redaction.Redact(conflictMemberID),
	)
	return conflictMemberID, Result{}, nil
}

// foreignLFID reports the first LFID username on the member that is not this
// user's, if there is one.
//
// LFID usernames are one per person, so a member carrying two of them holds
// two people. Comparison is case-insensitive because CDP stores identity
// values as they arrive from each source.
func foreignLFID(held []cdp.MemberIdentity, username string) (string, bool) {
	for _, identity := range held {
		if identity.Platform != constants.LFIDPlatform || identity.Type != constants.CDPIdentityTypeUsername {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(identity.Value), username) {
			return identity.Value, true
		}
	}
	return "", false
}

// holdsLFID reports whether the member already carries this user's own LFID.
//
// The mirror of foreignLFID, and case-insensitive for the same reason: CDP
// stores identity values as each source supplies them.
func holdsLFID(held []cdp.MemberIdentity, username string) bool {
	for _, identity := range held {
		if identity.Platform != constants.LFIDPlatform || identity.Type != constants.CDPIdentityTypeUsername {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(identity.Value), username) {
			return true
		}
	}
	return false
}

// lfidIdentity builds the CDP identity for an LFID username.
func lfidIdentity(username string) cdp.Identity {
	return cdp.Identity{
		Value:      username,
		Platform:   constants.LFIDPlatform,
		Type:       constants.CDPIdentityTypeUsername,
		Source:     constants.CDPIdentitySource,
		Verified:   true,
		VerifiedBy: username,
	}
}

// displayName falls back to the username when Auth0 holds no name.
//
// Taken from the Auth0 record rather than the event: a forged payload could
// otherwise put an attacker-chosen name on a real person's new CDP member.
func displayName(state port.UserProvisioningState, username string) string {
	if name := strings.TrimSpace(state.Name); name != "" {
		return name
	}
	return username
}

// skip builds a skip result.
func skip(reason string) Result {
	return Result{Outcome: OutcomeSkipped, Reason: reason}
}
