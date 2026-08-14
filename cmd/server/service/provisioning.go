// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package service

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"strings"

	authservice "github.com/linuxfoundation/lfx-v2-auth-service/gen/auth_service"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/service/provisioning"
	errs "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

// ProvisionCdpUUID handles an Auth0 Event Stream delivery.
//
// This is the one place in the feature where the edge does not carry the
// authorization decision: the webhook destination can present only a static
// secret, so there is no caller identity for Heimdall to pin and the check
// lives here.
func (s *authService) ProvisionCdpUUID(ctx context.Context, payload *authservice.ProvisionCdpUUIDPayload) error {
	if payload == nil {
		return authservice.BadRequest("empty request")
	}

	if !s.authorizeWebhook(ctx, payload.Authorization) {
		return authservice.Unauthorized("invalid or missing bearer secret")
	}

	// Logged before any field is read, so a field path that does not match the
	// real payload shows up as data rather than as a silently empty struct.
	slog.DebugContext(ctx, "received Auth0 provisioning event",
		"raw_body", redaction.RedactJWTs(string(payload.Body)),
	)

	event, user, err := provisioning.ParseEvent(payload.Body)
	if err != nil {
		// Redelivering the same bytes cannot help, so suppress the retry.
		slog.WarnContext(ctx, "rejected unparseable Auth0 provisioning event",
			"error", err,
			"event_id", event.ID,
		)
		s.countProvisioningEvent(ctx, event, "", "rejected")
		return authservice.BadRequest("unparseable event payload")
	}

	request := user.ToRequest()

	slog.InfoContext(ctx, "processing Auth0 provisioning event",
		"event_id", event.ID,
		"event_type", event.Type,
		"user_id", redaction.Redact(request.UserID),
		"email_verified", request.EmailVerified,
		"has_cdp_uuid", request.StoredCDPUUID != "",
		"has_database_identity", request.HasDatabaseIdentity,
	)

	if s.provisioner == nil {
		slog.ErrorContext(ctx, "provisioning orchestrator is not configured")
		s.countProvisioningEvent(ctx, event, request.UserID, "failed")
		return authservice.InternalServerError("provisioning is not available")
	}

	result, errProvision := s.provisioner.Provision(ctx, request)
	if errProvision != nil {
		// A validation failure is the caller's fault and permanent; anything
		// else is transient and must surface as a 5xx or the event is lost.
		var validation errs.Validation
		if errors.As(errProvision, &validation) {
			slog.WarnContext(ctx, "rejected invalid Auth0 provisioning event",
				"error", errProvision,
				"event_id", event.ID,
			)
			s.countProvisioningEvent(ctx, event, request.UserID, "rejected")
			return authservice.BadRequest(validation.Error())
		}

		slog.ErrorContext(ctx, "provisioning failed, expecting redelivery",
			"error", errProvision,
			"event_id", event.ID,
			"user_id", redaction.Redact(request.UserID),
		)
		s.countProvisioningEvent(ctx, event, request.UserID, "failed")
		return authservice.InternalServerError("provisioning failed")
	}

	slog.InfoContext(ctx, "completed Auth0 provisioning event",
		"event_id", event.ID,
		"event_type", event.Type,
		"user_id", redaction.Redact(request.UserID),
		"outcome", string(result.Outcome),
		"reason", result.Reason,
	)
	s.countProvisioningEvent(ctx, event, request.UserID, string(result.Outcome))

	return nil
}

// authorizeWebhook compares the presented bearer secret against the configured
// one in constant time.
func (s *authService) authorizeWebhook(ctx context.Context, header *string) bool {
	if s.provisioningSecret == "" {
		// Refusing every request is the safe failure here: a missing secret
		// must not silently turn the endpoint into an open one.
		slog.ErrorContext(ctx, "provisioning webhook secret is not configured, rejecting request")
		return false
	}
	if header == nil {
		return false
	}

	presented := strings.TrimSpace(*header)
	presented = strings.TrimSpace(strings.TrimPrefix(presented, "Bearer "))
	if presented == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(presented), []byte(s.provisioningSecret)) == 1
}

// countProvisioningEvent emits the delivery counter trace.
//
// A stream that stops delivering is otherwise invisible — it auto-disables
// after a run of failures with no other signal — so received/processed counts
// are what make silence distinguishable from health.
func (s *authService) countProvisioningEvent(ctx context.Context, event provisioning.Event, userID, outcome string) {
	slog.InfoContext(ctx, "provisioning event delivery",
		"metric", "provisioning_webhook_event",
		"event_id", event.ID,
		"event_type", event.Type,
		"user_id", redaction.Redact(userID),
		"outcome", outcome,
	)
}
