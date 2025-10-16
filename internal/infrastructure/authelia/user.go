// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package authelia

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/nats"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

// userReaderWriter implements UserReaderWriter with pluggable storage and ConfigMap sync
type userReaderWriter struct {
	oidcUserInfoURL string
	sync            *sync
	storage         internalStorageReaderWriter
	orchestrator    internalOrchestrator
	httpClient      *httpclient.Client
}

// fetchOIDCUserInfo fetches user information from the OIDC userinfo endpoint
func (a *userReaderWriter) fetchOIDCUserInfo(ctx context.Context, token string) (*OIDCUserInfo, error) {
	if strings.TrimSpace(token) == "" {
		return nil, errors.NewValidation("token is required")
	}

	if strings.TrimSpace(a.oidcUserInfoURL) == "" {
		return nil, errors.NewValidation("OIDC userinfo URL is not configured")
	}

	// Create API request using the standard pattern
	apiRequest := httpclient.NewAPIRequest(
		a.httpClient,
		httpclient.WithMethod(http.MethodGet),
		httpclient.WithURL(a.oidcUserInfoURL),
		httpclient.WithToken(token),
		httpclient.WithDescription("fetch OIDC userinfo"),
	)

	var userInfo OIDCUserInfo
	statusCode, err := apiRequest.Call(ctx, &userInfo)
	if err != nil {
		slog.ErrorContext(ctx, "failed to fetch OIDC userinfo",
			"error", err,
			"status_code", statusCode,
			"url", a.oidcUserInfoURL,
		)
		return nil, httpclient.ErrorFromStatusCode(statusCode, fmt.Sprintf("failed to fetch OIDC userinfo: %v", err))
	}

	return &userInfo, nil
}

// SearchUser searches for a user in storage
func (a *userReaderWriter) SearchUser(ctx context.Context, user *model.User, criteria string) (*model.User, error) {

	if user == nil {
		return nil, errors.NewValidation("user is required")
	}

	param := func(criteriaType string) string {
		switch criteriaType {
		case constants.CriteriaTypeEmail:
			slog.DebugContext(ctx, "searching user",
				"criteria", criteria,
				"email", redaction.RedactEmail(user.PrimaryEmail),
			)
			if strings.TrimSpace(user.PrimaryEmail) == "" {
				return ""
			}
			return a.storage.BuildLookupKey(ctx, "email", user.BuildEmailIndexKey(ctx))
		case constants.CriteriaTypeUsername:
			slog.DebugContext(ctx, "searching user",
				"criteria", criteria,
				"username", redaction.Redact(user.Username),
			)
			return user.Username
		}
		return ""
	}

	key := param(criteria)
	if key == "" {
		return nil, errors.NewValidation("invalid criteria type")
	}

	existingUser, err := a.storage.GetUser(ctx, key)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get existing user from storage",
			"error", err,
			"key", key,
		)
		return nil, err
	}
	return existingUser.User, nil

}

// GetUser retrieves a user from storage
func (a *userReaderWriter) GetUser(ctx context.Context, user *model.User) (*model.User, error) {

	if user == nil {
		return nil, errors.NewValidation("user is required")
	}

	key := ""
	if user.Username != "" {
		key = user.Username
	}

	if key == "" && user.Sub != "" {
		key = a.storage.BuildLookupKey(ctx, "sub", user.BuildSubIndexKey(ctx))
	}

	existingUser, err := a.storage.GetUser(ctx, key)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get existing user from storage",
			"error", err,
			"key", key,
		)
		return nil, err
	}
	return existingUser.User, nil
}

// MetadataLookup prepares the user for metadata lookup based on the input
// Accepts Authelia token, username, or sub
func (u *userReaderWriter) MetadataLookup(ctx context.Context, input string) (*model.User, error) {

	if input == "" {
		return nil, errors.NewValidation("input is required")
	}

	slog.DebugContext(ctx, "metadata lookup", "input", redaction.Redact(input))

	user := &model.User{}

	// First, try to parse as Authelia token (starts with 'authelia')
	if strings.HasPrefix(input, "authelia") {
		// Handle Authelia token
		userInfo, err := u.fetchOIDCUserInfo(ctx, input)
		if err != nil {
			slog.ErrorContext(ctx, "failed to fetch OIDC userinfo",
				"error", err,
			)
			return nil, err
		}
		user.Token = input
		user.UserID = userInfo.Sub
		user.Sub = userInfo.Sub
		user.Username = userInfo.PreferredUsername
		return user, nil
	}

	sub, errParseUUID := uuid.Parse(input)
	if errParseUUID == nil {
		user.UserID = sub.String()
		user.Sub = user.UserID
		slog.DebugContext(ctx, "canonical lookup strategy", "sub", redaction.Redact(input))
		return user, nil
	}

	// username search
	user.Username = input
	user.Sub = input
	slog.DebugContext(ctx, "username search strategy", "username", redaction.Redact(input))

	return user, nil
}

// UpdateUser updates a user only in storage with patch-like behavior, updating only changed fields
func (a *userReaderWriter) UpdateUser(ctx context.Context, user *model.User) (*model.User, error) {
	if user == nil {
		return nil, errors.NewValidation("user is required")
	}

	if user.Token != "" {
		// Fetch user information from OIDC userinfo endpoint
		userInfo, err := a.fetchOIDCUserInfo(ctx, user.Token)
		if err != nil {
			slog.WarnContext(ctx, "failed to fetch OIDC userinfo, skipping sub update",
				"username", user.Username,
				"error", err,
			)
		}
		if userInfo != nil && userInfo.Sub != "" {
			user.Sub = userInfo.Sub
			slog.DebugContext(ctx, "updated user sub from OIDC userinfo",
				"username", user.Username,
				"preferred_username", userInfo.PreferredUsername,
				"sub", userInfo.Sub,
			)
			if user.Username == "" {
				user.Username = userInfo.PreferredUsername
			}
		}
	}

	if user.Sub == "" && user.Username == "" {
		return nil, errors.NewValidation("username or sub is required")
	}

	// First, get the existing user from storage to preserve Authelia-specific fields
	existingAutheliaUser := &AutheliaUser{}
	existingAutheliaUser.SetUsername(user.Username)

	existingUser, err := a.storage.GetUser(ctx, existingAutheliaUser.Username)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get existing user from storage",
			"username", user.Username,
			"error", err,
			"key", existingAutheliaUser.Username,
		)
		return nil, errors.NewUnexpected("failed to get existing user from storage", err)
	}

	// Update Sub field if provided from OIDC userinfo
	subUpdated := false
	if user.Sub != "" && existingUser.Sub != user.Sub {
		existingUser.Sub = user.Sub
		subUpdated = true
		slog.InfoContext(ctx, "updated user sub field in storage",
			"username", user.Username,
			"sub", redaction.Redact(user.Sub),
		)
	}

	// Update UserMetadata if provided - patch individual metadata fields
	metadataUpdated := false
	if user.UserMetadata != nil {
		if existingUser.UserMetadata == nil {
			existingUser.UserMetadata = &model.UserMetadata{}
		}
		metadataUpdated = existingUser.UserMetadata.Patch(user.UserMetadata)
	}

	// Save to storage if any updates were made
	if subUpdated || metadataUpdated {
		_, err = a.storage.SetUser(ctx, existingUser)
		if err != nil {
			slog.ErrorContext(ctx, "failed to update user in storage",
				"username", user.Username,
				"error", err,
			)
			return nil, errors.NewUnexpected("failed to update user in storage", err)
		}
	}

	slog.InfoContext(ctx, "user updated successfully in storage",
		"username", user.Username)

	return existingUser.User, nil
}

func (a *userReaderWriter) SendVerificationAlternateEmail(ctx context.Context, alternateEmail string) error {
	slog.DebugContext(ctx, "sending alternate email verification", "alternate_email", redaction.Redact(alternateEmail))
	return errors.NewValidation("send verification alternate email is not supported for Authelia yet")
}

func (a *userReaderWriter) VerifyAlternateEmail(ctx context.Context, email *model.Email) (*model.User, error) {
	slog.DebugContext(ctx, "verifying alternate email", "email", redaction.Redact(email.Email))
	return nil, errors.NewValidation("alternate email verification is not supported for Authelia yet")
}

// NewUserReaderWriter creates a new Authelia User repository
func NewUserReaderWriter(ctx context.Context, config map[string]string, natsClient *nats.NATSClient) (port.UserReaderWriter, error) {
	// Set defaults in case of not set

	u := &userReaderWriter{
		sync:            &sync{},
		oidcUserInfoURL: config["oidc-userinfo-url"],
		httpClient:      httpclient.NewClient(httpclient.DefaultConfig()),
	}

	// Initialize storage using NATS KV store
	if u.storage == nil {
		storage, errNATSUserStorage := newNATSUserStorage(ctx, natsClient)
		if errNATSUserStorage != nil {
			slog.ErrorContext(ctx, "failed to create storage", "error", errNATSUserStorage)
			return nil, errNATSUserStorage
		}
		u.storage = storage
	}

	// Initialize orchestrator using K8S to update the ConfigMap, Secrets and DaemonSet
	if u.orchestrator == nil {
		orchestrator, errK8sOrchestrator := newK8sUserOrchestrator(ctx, config)
		if errK8sOrchestrator != nil {
			slog.ErrorContext(ctx, "failed to create orchestrator", "error", errK8sOrchestrator)
			return nil, errK8sOrchestrator
		}
		u.orchestrator = orchestrator
	}

	errSyncUsers := u.sync.syncUsers(ctx, u.storage, u.orchestrator)
	if errSyncUsers != nil {
		slog.Warn("failed to sync from storage to orchestrator", "error", errSyncUsers)
	}

	return u, nil
}
