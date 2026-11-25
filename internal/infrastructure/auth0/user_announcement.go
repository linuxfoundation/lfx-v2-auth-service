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

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

// userAnnouncementStore reads and writes the announcement marker on Auth0
// `app_metadata`. It shares the Management API plumbing, and the token-handling
// and error conventions, of the CDP metadata writer.
type userAnnouncementStore struct {
	writer *cdpMetadataWriter
}

// NewUserAnnouncementStore creates the Auth0-backed announcement store.
func NewUserAnnouncementStore(httpConfig httpclient.Config, auth0Config Config) (port.UserAnnouncementStore, error) {
	writer, err := newCDPMetadataWriter(httpConfig, auth0Config)
	if err != nil {
		return nil, err
	}
	return &userAnnouncementStore{writer: writer}, nil
}

// ReadAnnouncementState returns the fields the announcement gate depends on, in
// one Management API call.
func (s *userAnnouncementStore) ReadAnnouncementState(ctx context.Context, userID string) (port.UserAnnouncementState, error) {
	if strings.TrimSpace(userID) == "" {
		return port.UserAnnouncementState{}, errors.NewValidation("user_id is required")
	}

	user, err := s.writer.getUser(ctx, userID, "user_id,app_metadata,email,email_verified,username")
	if err != nil {
		return port.UserAnnouncementState{}, err
	}

	state := port.UserAnnouncementState{
		EmailVerified: user.EmailVerified,
		Email:         user.Email,
	}
	// The root `username` belongs to the primary identity, and is an LFID only
	// for a database-connection user (see ReadProvisioningState).
	if strings.HasPrefix(user.UserID, databaseUserIDPrefix) {
		state.Username = user.Username
	}
	if user.AppMetadata != nil {
		state.AnnouncedAt = user.AppMetadata.EmailVerifiedAnnouncedAt
	}

	return state, nil
}

// MarkAnnounced PATCHes only the announcement key. Auth0 merges top-level
// `app_metadata` keys, so the CDP keys and others are left untouched.
func (s *userAnnouncementStore) MarkAnnounced(ctx context.Context, userID, announcedAt string) error {
	if strings.TrimSpace(userID) == "" {
		return errors.NewValidation("user_id is required")
	}
	if strings.TrimSpace(announcedAt) == "" {
		return errors.NewValidation("announced_at is required")
	}

	w := s.writer
	token, err := w.config.M2MTokenManager.GetToken(ctx)
	if err != nil {
		return errors.NewUnexpected("failed to get M2M token to mark user announced", err)
	}

	request := httpclient.NewAPIRequest(
		w.httpClient,
		httpclient.WithMethod(http.MethodPatch),
		httpclient.WithURL(fmt.Sprintf("https://%s/api/v2/users/%s", w.config.Domain, url.PathEscape(userID))),
		httpclient.WithToken(token),
		httpclient.WithDescription("mark user email verified announced"),
		httpclient.WithBody(cdpMetadataPatch{
			AppMetadata: &Auth0AppMetadata{EmailVerifiedAnnouncedAt: announcedAt},
		}),
		httpclient.WithSensitiveBody(),
	)

	var response map[string]any
	statusCode, errCall := request.Call(ctx, &response)
	if errCall != nil {
		if statusCode == http.StatusTooManyRequests {
			return managementRateLimited(ctx, "announcement marker write", errCall)
		}
		slog.ErrorContext(ctx, "failed to mark user email verified announced",
			"error", errCall,
			"status_code", statusCode,
			"user_id", redaction.Redact(userID),
		)
		return errors.NewUnexpected("failed to mark user announced", errCall)
	}

	return nil
}
