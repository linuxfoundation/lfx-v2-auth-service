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

// Request is one provisioning attempt, built by the webhook handler from an
// Auth0 event payload.
type Request struct {
	// UserID is the Auth0 user id.
	UserID string

	// Username is the LFID. It MUST come from the database-connection
	// identity; another connection's username is not an LFID.
	Username string

	// Email is a secondary resolve identifier, used only when verified.
	Email string

	// EmailVerified gates the whole flow and is checked strictly against
	// true, since the field has a real third state.
	EmailVerified bool

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
	// redelivered.
	OutcomeSkipped Outcome = "skipped"
)

// Result reports what happened, so the caller can log it and choose a status
// code. Reason is always set on a skip.
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
// A returned error means the attempt is worth retrying and the caller should
// answer with a 5xx; a skip is a final answer and must not be redelivered.
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
	if !req.EmailVerified || strings.TrimSpace(req.StoredCDPUUID) != "" {
		if !req.EmailVerified {
			return skip(reasonEmailNotVerified), nil
		}
		return skip(reasonAlreadyProvisioned), nil
	}

	// Re-read from Auth0 before deciding anything. The payload arrives behind
	// a shared static secret, which proves who sent the request but not that
	// the fields are true — and these fields decide whether this service
	// writes to CDP on a user's behalf. The stored record is also more
	// current than a snapshot taken when the event was queued.
	state, err := o.metadata.ReadProvisioningState(ctx, req.UserID)
	if err != nil {
		// A deleted user is a permanent answer. Surfacing it as a failure
		// would have Auth0 redeliver the event until the stream gives up.
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

		if err := o.cdpClient.AttachIdentity(ctx, resolved.MemberID, lfidIdentity(username)); err != nil {
			return "", Result{}, err
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
		if reResolved.Outcome != cdp.OutcomeFound {
			slog.WarnContext(ctx, "CDP create conflicted but re-resolve found no single member",
				"user_id", redaction.Redact(req.UserID),
				"resolve_outcome", string(reResolved.Outcome),
			)
			return "", skip(reasonConflict), nil
		}
		return reResolved.MemberID, Result{}, nil
	}

	return created.MemberID, Result{}, nil
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
