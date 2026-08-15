// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package service

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"sort"
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

	// An unconfigured secret is our fault, not the caller's. Answering 401
	// would tell Auth0 to stop retrying and the events would be lost for the
	// duration of the misconfiguration.
	if s.provisioningSecret == "" {
		slog.ErrorContext(ctx, "provisioning webhook secret is not configured, rejecting request")
		return authservice.InternalServerError("provisioning is not available")
	}
	if !s.authorizeWebhook(ctx, payload.Authorization) {
		return authservice.Unauthorized("invalid or missing bearer secret")
	}

	// The shape is logged, not the contents: an Auth0 user event carries email,
	// username and user id in cleartext, and redaction only masks
	// token-shaped substrings. Keys are enough to tell a field-path mismatch
	// from a genuinely absent field, which is what this trace is for.
	slog.DebugContext(ctx, "received Auth0 provisioning event",
		"body_bytes", len(payload.Body),
		"body_keys", topLevelKeys(payload.Body),
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
		// Checked by the caller, which answers 5xx rather than 4xx. Repeated
		// here so this can never authorize against an empty secret.
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

// topLevelKeys returns the top-level keys of a JSON object body, or nil when
// it is not one. Used to make a field-path mismatch visible without logging
// any of the user data the body carries.
func topLevelKeys(body []byte) []string {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err != nil {
		return nil
	}

	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	return keys
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
