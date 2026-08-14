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
	reasonConflict           = "cdp-identity-conflict"
)

// Orchestrator provisions a CDP identity for a verified user.
type Orchestrator interface {
	Provision(ctx context.Context, req Request) (Result, error)
}

type orchestrator struct {
	cdpClient      cdp.Client
	metadataWriter port.CDPMetadataWriter
}

// Option configures the orchestrator.
type Option func(*orchestrator)

// WithCDPClient sets the CDP client.
func WithCDPClient(client cdp.Client) Option {
	return func(o *orchestrator) {
		o.cdpClient = client
	}
}

// WithMetadataWriter sets the Auth0 `app_metadata` writer.
func WithMetadataWriter(writer port.CDPMetadataWriter) Option {
	return func(o *orchestrator) {
		o.metadataWriter = writer
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
	if o.cdpClient == nil || o.metadataWriter == nil {
		return Result{}, errs.NewUnexpected("provisioning orchestrator is not fully configured")
	}
	if strings.TrimSpace(req.UserID) == "" {
		return Result{}, errs.NewValidation("user_id is required")
	}

	// The gate. Both halves are required: `user.updated` fires on every user
	// record mutation, including this flow's own write-back, so gating on
	// verification alone would make provisioning re-trigger on itself.
	if !req.EmailVerified {
		return skip(reasonEmailNotVerified), nil
	}
	if strings.TrimSpace(req.StoredCDPUUID) != "" {
		return skip(reasonAlreadyProvisioned), nil
	}

	// Only database-connection users hold an LFID, and resolve requires one.
	if !req.HasDatabaseIdentity {
		return skip(reasonNoDatabaseIdentity), nil
	}
	username := strings.TrimSpace(req.Username)
	if username == "" {
		// Unexpected for a database user, and not recoverable: an email-only
		// create would 409 without returning the conflicting member id, so the
		// recovery re-resolve is impossible and the call would loop.
		slog.ErrorContext(ctx, "database user has no LFID username, skipping provisioning",
			"user_id", redaction.Redact(req.UserID),
		)
		return skip(reasonNoLFIDUsername), nil
	}

	memberID, result, err := o.findOrCreateMember(ctx, req, username)
	if err != nil {
		return Result{}, err
	}
	if memberID == "" {
		return result, nil
	}

	if err := o.metadataWriter.WriteCDPMetadata(ctx, req.UserID, port.CDPMetadata{
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
func (o *orchestrator) findOrCreateMember(ctx context.Context, req Request, username string) (string, Result, error) {
	// Email only ever widens the match, and only when verified.
	email := ""
	if req.EmailVerified {
		email = strings.TrimSpace(req.Email)
	}

	resolved, err := o.cdpClient.Resolve(ctx, username, email)
	if err != nil {
		return "", Result{}, err
	}

	switch resolved.Outcome {
	case cdp.OutcomeFound:
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
	created, err := o.cdpClient.CreateMember(ctx, displayName(req, username), lfidIdentity(username))
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

// displayName falls back to the username when the event carries no name.
func displayName(req Request, username string) string {
	if name := strings.TrimSpace(req.DisplayName); name != "" {
		return name
	}
	return username
}

// skip builds a skip result.
func skip(reason string) Result {
	return Result{Outcome: OutcomeSkipped, Reason: reason}
}
