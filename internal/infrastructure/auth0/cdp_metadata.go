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

// NewCDPMetadataWriter creates the Auth0 `app_metadata` writer for the CDP
// enrichment keys.
func NewCDPMetadataWriter(httpConfig httpclient.Config, auth0Config Config) port.CDPMetadataReaderWriter {
	return &cdpMetadataWriter{
		httpClient: httpclient.NewClient(httpConfig),
		config:     auth0Config,
	}
}

// ReadCDPMetadata returns the user's current CDP enrichment record.
func (w *cdpMetadataWriter) ReadCDPMetadata(ctx context.Context, userID string) (port.CDPMetadata, error) {
	if strings.TrimSpace(userID) == "" {
		return port.CDPMetadata{}, errors.NewValidation("user_id is required")
	}

	token, err := w.config.M2MTokenManager.GetToken(ctx)
	if err != nil {
		return port.CDPMetadata{}, errors.NewUnexpected("failed to get M2M token to read CDP metadata", err)
	}

	request := httpclient.NewAPIRequest(
		w.httpClient,
		httpclient.WithMethod(http.MethodGet),
		httpclient.WithURL(fmt.Sprintf("https://%s/api/v2/users/%s?fields=app_metadata&include_fields=true",
			w.config.Domain, url.PathEscape(userID))),
		httpclient.WithToken(token),
		httpclient.WithDescription("read CDP app_metadata"),
	)

	var user Auth0User
	statusCode, errCall := request.Call(ctx, &user)
	if errCall != nil {
		if statusCode == http.StatusNotFound {
			return port.CDPMetadata{}, errors.NewNotFound("user not found")
		}
		slog.ErrorContext(ctx, "failed to read CDP app_metadata",
			"error", errCall,
			"status_code", statusCode,
			"user_id", redaction.Redact(userID),
		)
		return port.CDPMetadata{}, errors.NewUnexpected("failed to read CDP app_metadata", errCall)
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

// WriteCDPMetadata writes the CDP enrichment keys, enforcing that a stored
// `cdp_uuid` is write-once.
//
// Absent to present is the only legal transition for the UUID itself: changing
// one to a different value, or clearing one, is rejected. `source` and
// `checked_at` stay freely updatable, which is what lets a re-check refresh the
// timestamp without touching the identity. Rejections are logged and counted —
// they mean a caller's own guard is wrong, not that the data is.
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

	checkedAt := record.CheckedAt
	if strings.TrimSpace(checkedAt) == "" {
		checkedAt = time.Now().UTC().Format(time.RFC3339)
	}

	token, errToken := w.config.M2MTokenManager.GetToken(ctx)
	if errToken != nil {
		return errors.NewUnexpected("failed to get M2M token to write CDP metadata", errToken)
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
		httpclient.WithDescription("write CDP app_metadata"),
		httpclient.WithBody(patch),
	)

	var patchResponse map[string]any
	statusCode, errCall := request.Call(ctx, &patchResponse)
	if errCall != nil {
		slog.ErrorContext(ctx, "failed to write CDP app_metadata",
			"error", errCall,
			"status_code", statusCode,
			"user_id", redaction.Redact(userID),
		)
		return errors.NewUnexpected("failed to write CDP app_metadata", errCall)
	}

	slog.InfoContext(ctx, "wrote CDP app_metadata",
		"user_id", redaction.Redact(userID),
		"cdp_uuid_source", record.Source,
		"has_uuid", record.UUID != "",
	)

	return nil
}

// isValidCDPSource reports whether source is one of the three allowed values.
func isValidCDPSource(source string) bool {
	switch source {
	case constants.CDPUUIDSourceBackfill,
		constants.CDPUUIDSourceLoginResolve,
		constants.CDPUUIDSourceProvisioning:
		return true
	}
	return false
}
