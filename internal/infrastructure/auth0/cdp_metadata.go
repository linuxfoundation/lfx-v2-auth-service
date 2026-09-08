// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

// managementRateLimited reports a Management API 429 as the shared typed error,
// carrying the server's Retry-After when it gave one.
//
// Returned BARE. pkg/errors has no Unwrap, so a wrapped one is invisible to the
// errors.As the events consumer uses to tell a rate limit apart from a failure
// worth counting against the event being provisioned.
func managementRateLimited(ctx context.Context, operation string, err error) errors.RateLimited {
	wait := httpclient.RetryAfter(err)
	slog.WarnContext(ctx, "Auth0 Management API rate limited the request",
		"operation", operation,
		"retry_after", wait,
	)
	return errors.NewRateLimited("Auth0 "+operation+" was rate limited", wait)
}

// databaseUserIDPrefix is the Auth0 user-id prefix for a user whose primary
// identity is the database connection.
const databaseUserIDPrefix = "auth0|"

// cdpMetadataPatch is the body for PATCH /api/v2/users/{id} when writing the
// CDP enrichment keys.
//
// Auth0 merges top-level `app_metadata` keys natively, so sending only the
// changed keys is a partial update. Building the patch from a struct populated
// by a prior read would reintroduce the lost-update race this deliberately
// avoids, so the struct is always constructed fresh from the record.
type cdpMetadataPatch struct {
	AppMetadata *Auth0AppMetadata `json:"app_metadata"`
}

// cdpMetadataWriter writes the CDP enrichment keys to Auth0 `app_metadata`.
type cdpMetadataWriter struct {
	httpClient *httpclient.Client
	config     Config
}

// newCDPMetadataWriter validates and builds the shared concrete writer.
func newCDPMetadataWriter(httpConfig httpclient.Config, auth0Config Config) (*cdpMetadataWriter, error) {
	if auth0Config.M2MTokenManager == nil {
		return nil, errors.NewUnexpected("M2M token manager is required")
	}
	if strings.TrimSpace(auth0Config.Domain) == "" {
		return nil, errors.NewUnexpected("Auth0 domain is required")
	}

	return &cdpMetadataWriter{
		httpClient: httpclient.NewClient(httpConfig),
		config:     auth0Config,
	}, nil
}

// NewCDPMetadataWriter creates the Auth0 `app_metadata` writer for the CDP
// enrichment keys.
func NewCDPMetadataWriter(httpConfig httpclient.Config, auth0Config Config) (port.CDPMetadataReaderWriter, error) {
	return newCDPMetadataWriter(httpConfig, auth0Config)
}

// NewCDPMetadataRepairWriter creates the scoped repair writer for the
// merge-repair job's compare-and-swap. It shares the concrete writer — and
// its token-before-read ordering — with NewCDPMetadataWriter; only the
// reachable interface is narrower.
func NewCDPMetadataRepairWriter(httpConfig httpclient.Config, auth0Config Config) (port.CDPMetadataRepairer, error) {
	return newCDPMetadataWriter(httpConfig, auth0Config)
}

// ReadCDPMetadata returns the user's current CDP enrichment record.
func (w *cdpMetadataWriter) ReadCDPMetadata(ctx context.Context, userID string) (port.CDPMetadata, error) {
	if strings.TrimSpace(userID) == "" {
		return port.CDPMetadata{}, errors.NewValidation("user_id is required")
	}

	user, err := w.getUser(ctx, userID, "app_metadata")
	if err != nil {
		return port.CDPMetadata{}, err
	}

	if user.AppMetadata == nil {
		return port.CDPMetadata{}, nil
	}

	return port.CDPMetadata{
		UUID:      user.AppMetadata.CDPUUID,
		Source:    user.AppMetadata.CDPUUIDSource,
		CheckedAt: user.AppMetadata.CDPUUIDCheckedAt,
	}, nil
}

// ReadProvisioningState returns the authoritative fields the provisioning gate
// depends on, in a single Management API call.
func (w *cdpMetadataWriter) ReadProvisioningState(ctx context.Context, userID string) (port.UserProvisioningState, error) {
	if strings.TrimSpace(userID) == "" {
		return port.UserProvisioningState{}, errors.NewValidation("user_id is required")
	}

	user, err := w.getUser(ctx, userID, "user_id,app_metadata,email,email_verified,username,name,identities")
	if err != nil {
		return port.UserProvisioningState{}, err
	}

	state := port.UserProvisioningState{
		EmailVerified: user.EmailVerified,
		Email:         user.Email,
		Name:          user.Name,
	}

	// The root `username` belongs to the user's *primary* identity. Reading it
	// for a user whose primary is social or enterprise would hand CDP another
	// connection's username as though it were an LFID, and the resulting id is
	// permanent. Auth0 gives database-connection users an `auth0|` id, so that
	// prefix is what makes the root username safe to read.
	//
	// A social-primary user with a linked database identity is therefore left
	// without a username here rather than given a wrong one: Auth0 does not
	// expose a secondary identity's username on this record. Those users are
	// skipped, and a later login heals them.
	primaryIsDatabase := strings.HasPrefix(user.UserID, databaseUserIDPrefix)
	if primaryIsDatabase {
		state.Username = user.Username
	}
	if user.AppMetadata != nil {
		state.CDPMetadata = port.CDPMetadata{
			UUID:      user.AppMetadata.CDPUUID,
			Source:    user.AppMetadata.CDPUUIDSource,
			CheckedAt: user.AppMetadata.CDPUUIDCheckedAt,
		}
	}
	for _, identity := range user.Identities {
		if identity.Connection == constants.DatabaseConnection {
			state.HasDatabaseIdentity = true
			break
		}
	}

	return state, nil
}

// getUser fetches the requested fields of an Auth0 user.
func (w *cdpMetadataWriter) getUser(ctx context.Context, userID, fields string) (Auth0User, error) {
	token, err := w.config.M2MTokenManager.GetToken(ctx)
	if err != nil {
		return Auth0User{}, errors.NewUnexpected("failed to get M2M token to read user", err)
	}

	request := httpclient.NewAPIRequest(
		w.httpClient,
		httpclient.WithMethod(http.MethodGet),
		httpclient.WithURL(fmt.Sprintf("https://%s/api/v2/users/%s?fields=%s&include_fields=true",
			w.config.Domain, url.PathEscape(userID), url.QueryEscape(fields))),
		httpclient.WithToken(token),
		httpclient.WithDescription("read user for CDP provisioning"),
	)

	var user Auth0User
	statusCode, errCall := request.Call(ctx, &user)
	if errCall != nil {
		if statusCode == http.StatusNotFound {
			return Auth0User{}, errors.NewNotFound("user not found")
		}
		if statusCode == http.StatusTooManyRequests {
			return Auth0User{}, managementRateLimited(ctx, "user read", errCall)
		}
		slog.ErrorContext(ctx, "failed to read user for CDP provisioning",
			"error", errCall,
			"status_code", statusCode,
			"user_id", redaction.Redact(userID),
		)
		return Auth0User{}, errors.NewUnexpected("failed to read user", errCall)
	}

	return user, nil
}

// WriteCDPMetadata writes the CDP enrichment keys, rejecting a change to a
// stored `cdp_uuid`.
//
// Absent to present is the only legal transition for the UUID itself: changing
// one to a different value, or clearing one, is rejected. `source` and
// `checked_at` stay freely updatable, which is what lets a re-check refresh the
// timestamp without touching the identity. Rejections are logged and counted —
// they mean a caller's own guard is wrong, not that the data is.
//
// **Best-effort, not atomic.** The read below and the patch are two Management
// API calls, and the login Action writes the same keys directly, so two writers
// can both observe an absent UUID and both proceed. Auth0 offers no
// compare-and-set on `app_metadata`, so this cannot be closed here.
//
// What it does instead is keep the gap as short as the API allows: the token is
// obtained before the read, so nothing but the patch itself sits between
// checking and writing. That shrinks the window to one round trip rather than
// removing it. The guard still catches every ordering where one writer's patch
// lands before the other's read, which is the common case; two patches issued
// from reads taken in the same instant remain possible, and both writers derive
// the value from the same CDP lookup, so such a write is normally identical
// rather than conflicting.
func (w *cdpMetadataWriter) WriteCDPMetadata(ctx context.Context, userID string, record port.CDPMetadata) error {
	if strings.TrimSpace(userID) == "" {
		return errors.NewValidation("user_id is required")
	}
	if strings.TrimSpace(record.Source) == "" {
		return errors.NewValidation("cdp_uuid_source is required")
	}
	if !isValidCDPSource(record.Source) {
		return errors.NewValidation("invalid cdp_uuid_source: " + record.Source)
	}

	// Fetched before the read so a cold token cache cannot stretch the gap
	// between the write-once check and the patch it guards.
	token, errToken := w.config.M2MTokenManager.GetToken(ctx)
	if errToken != nil {
		return errors.NewUnexpected("failed to get M2M token to write CDP metadata", errToken)
	}

	existing, err := w.ReadCDPMetadata(ctx, userID)
	if err != nil {
		return err
	}

	if existing.UUID != "" {
		switch {
		case record.UUID == "":
			slog.ErrorContext(ctx, "rejected attempt to clear a stored cdp_uuid",
				"user_id", redaction.Redact(userID),
				"cdp_uuid_write_rejected", true,
				"reason", "clear",
			)
			return errors.NewConflict("cdp_uuid is write-once and cannot be cleared")
		case record.UUID != existing.UUID:
			slog.ErrorContext(ctx, "rejected attempt to overwrite a stored cdp_uuid",
				"user_id", redaction.Redact(userID),
				"cdp_uuid_write_rejected", true,
				"reason", "overwrite",
			)
			return errors.NewConflict("cdp_uuid is write-once and cannot be changed")
		}
	}

	return w.patchCDPMetadata(ctx, token, userID, record, "write", "wrote")
}

// isValidCDPSource reports whether source is one of the values the write-once
// path may stamp. merge-repair is deliberately absent: only the repair path
// writes it, and it enforces that itself.
func isValidCDPSource(source string) bool {
	switch source {
	case constants.CDPUUIDSourceBackfill,
		constants.CDPUUIDSourceLoginResolve,
		constants.CDPUUIDSourceProvisioning:
		return true
	}
	return false
}

// WriteCDPMetadataRepair overwrites a stored `cdp_uuid` if and only if the
// stored value still matches from — the merge-repair job's compare-and-swap.
//
// Unlike WriteCDPMetadata it requires a stored value to replace (there is
// nothing to repair on an empty record). Both sides are case-folded to
// lowercase UUIDs per repo convention (provisioning and the login Action both
// store lowercase; the walker lowercases at ingestion), so a legacy
// mixed-case value still CAS-matches instead of failing into `errors` on
// every run. A from that matches nothing — e.g. a mid-run login write —
// fails loud here rather than being clobbered. A record UUID identical to
// from, or any source but merge-repair, is a validation error.
// Token-before-read ordering matches WriteCDPMetadata so the race window
// stays one round trip.
func (w *cdpMetadataWriter) WriteCDPMetadataRepair(ctx context.Context, userID, from string, record port.CDPMetadata) error {
	if strings.TrimSpace(userID) == "" {
		return errors.NewValidation("user_id is required")
	}
	from = strings.ToLower(strings.TrimSpace(from))
	if from == "" {
		return errors.NewValidation("expected stored cdp_uuid (from) is required")
	}
	if record.Source != constants.CDPUUIDSourceMergeRepair {
		return errors.NewValidation("repair writes carry cdp_uuid_source merge-repair only")
	}
	record.UUID = strings.ToLower(strings.TrimSpace(record.UUID))
	if record.UUID == "" {
		return errors.NewValidation("repair record UUID is required")
	}
	if record.UUID == from {
		return errors.NewValidation("repair must change the stored cdp_uuid")
	}

	// Fetched before the read so a cold token cache cannot stretch the gap
	// between the compare and the patch it guards.
	token, errToken := w.config.M2MTokenManager.GetToken(ctx)
	if errToken != nil {
		return errors.NewUnexpected("failed to get M2M token to write CDP metadata", errToken)
	}

	existing, err := w.ReadCDPMetadata(ctx, userID)
	if err != nil {
		return err
	}

	if !strings.EqualFold(strings.TrimSpace(existing.UUID), from) {
		slog.ErrorContext(ctx, "rejected stale merge-repair overwrite",
			"user_id", redaction.Redact(userID),
			"cdp_uuid_write_rejected", true,
			"reason", "cas-mismatch",
		)
		return errors.NewConflict("stored cdp_uuid changed since classification; repair refused")
	}

	return w.patchCDPMetadata(ctx, token, userID, record, "repair", "repaired")
}

// patchCDPMetadata PATCHes exactly the record's keys: a partial update built
// fresh, never merged from a prior read. op/opPast name the operation for
// logs and the Management client description ("write"/"wrote",
// "repair"/"repaired"). A 429 is reported bare for the caller to wait out.
func (w *cdpMetadataWriter) patchCDPMetadata(ctx context.Context, token, userID string, record port.CDPMetadata, op, opPast string) error {
	checkedAt := record.CheckedAt
	if strings.TrimSpace(checkedAt) == "" {
		checkedAt = time.Now().UTC().Format(time.RFC3339)
	}

	// Built fresh, holding only the keys being changed — never from the value
	// read above.
	patch := cdpMetadataPatch{
		AppMetadata: &Auth0AppMetadata{
			CDPUUID:          record.UUID,
			CDPUUIDSource:    record.Source,
			CDPUUIDCheckedAt: checkedAt,
		},
	}

	request := httpclient.NewAPIRequest(
		w.httpClient,
		httpclient.WithMethod(http.MethodPatch),
		httpclient.WithURL(fmt.Sprintf("https://%s/api/v2/users/%s", w.config.Domain, url.PathEscape(userID))),
		httpclient.WithToken(token),
		httpclient.WithDescription(op+" CDP app_metadata"),
		httpclient.WithBody(patch),
		httpclient.WithSensitiveBody(),
	)

	var patchResponse map[string]any
	statusCode, errCall := request.Call(ctx, &patchResponse)
	if errCall != nil {
		if statusCode == http.StatusTooManyRequests {
			return managementRateLimited(ctx, "app_metadata "+op, errCall)
		}
		slog.ErrorContext(ctx, "failed to "+op+" CDP app_metadata",
			"error", errCall,
			"status_code", statusCode,
			"user_id", redaction.Redact(userID),
		)
		return errors.NewUnexpected("failed to "+op+" CDP app_metadata", errCall)
	}

	slog.InfoContext(ctx, opPast+" CDP app_metadata",
		"user_id", redaction.Redact(userID),
		"cdp_uuid_source", record.Source,
		"has_uuid", record.UUID != "",
	)

	return nil
}
