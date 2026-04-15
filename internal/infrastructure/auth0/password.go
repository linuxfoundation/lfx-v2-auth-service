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

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

// passwordCheckRequest represents the request body for validating a user's current password
// via Auth0's Resource Owner Password Grant with realm extension
type passwordCheckRequest struct {
	GrantType    string `json:"grant_type"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Realm        string `json:"realm"`
}

// passwordUpdateRequest represents the request body for updating a user's password in Auth0
type passwordUpdateRequest struct {
	Password   string `json:"password"`
	Connection string `json:"connection"`
}

// resetPasswordRequest represents the request body for Auth0's change password endpoint
type resetPasswordRequest struct {
	ClientID   string `json:"client_id"`
	Email      string `json:"email"`
	Connection string `json:"connection"`
}

// ChangePassword validates the user's current password and sets a new one.
// The caller is expected to have already verified the JWT and set user.UserID.
// Flow:
// 1. Look up the user to get their username
// 2. Validate current password via Auth0 oauth/token (Resource Owner Password Grant)
// 3. Update the password via Auth0 Management API using M2M token
func (u *userReaderWriter) ChangePassword(ctx context.Context, user *model.User, currentPassword, newPassword string) error {

	slog.DebugContext(ctx, "changing password for user",
		"user_id", redaction.Redact(user.UserID),
	)

	// Look up the user to get their username (nickname)
	fullUser, errGetUser := u.GetUser(ctx, user)
	if errGetUser != nil {
		slog.ErrorContext(ctx, "failed to get user for password change",
			"error", errGetUser,
			"user_id", redaction.Redact(user.UserID),
		)
		return errGetUser
	}

	if !strings.HasPrefix(user.UserID, "auth0|") || fullUser.Username == "" {
		return errors.NewValidation("password change requires an Auth0 user with a username")
	}

	// Validate current password via Auth0 Resource Owner Password Grant
	errValidate := u.validateCurrentPassword(ctx, fullUser.Username, currentPassword)
	if errValidate != nil {
		return errValidate
	}

	// Update password via Auth0 Management API using M2M token
	m2mToken, errGetToken := u.config.M2MTokenManager.GetToken(ctx)
	if errGetToken != nil {
		return errors.NewUnexpected("failed to get M2M token for password update", errGetToken)
	}

	updatePayload := passwordUpdateRequest{
		Password:   newPassword,
		Connection: constants.Auth0UsernamePasswordConnection,
	}

	apiRequest := httpclient.NewAPIRequest(
		u.httpClient,
		httpclient.WithMethod(http.MethodPatch),
		httpclient.WithURL(fmt.Sprintf("https://%s/api/v2/users/%s", u.config.Domain, url.PathEscape(user.UserID))),
		httpclient.WithToken(m2mToken),
		httpclient.WithDescription("update user password"),
		httpclient.WithBody(updatePayload),
		httpclient.WithSensitiveBody(),
	)

	var patchResponse map[string]any
	statusCode, errCall := apiRequest.Call(ctx, &patchResponse)
	if errCall != nil {
		slog.ErrorContext(ctx, "failed to update password in Auth0",
			"error", errCall,
			"status_code", statusCode,
			"user_id", redaction.Redact(user.UserID),
		)
		return errors.NewUnexpected("failed to update password", errCall)
	}

	slog.DebugContext(ctx, "password updated successfully",
		"user_id", redaction.Redact(user.UserID),
	)

	return nil
}

// validateCurrentPassword validates the user's current password by attempting
// a Resource Owner Password Grant against Auth0's oauth/token endpoint.
func (u *userReaderWriter) validateCurrentPassword(ctx context.Context, username, password string) error {

	clientID := u.config.LFXProfileClientID
	clientSecret := u.config.LFXProfileClientSecret

	if clientID == "" || clientSecret == "" {
		return errors.NewUnexpected("Auth0 profile client credentials not configured for password validation")
	}

	payload := passwordCheckRequest{
		GrantType:    "http://auth0.com/oauth/grant-type/password-realm",
		Username:     username,
		Password:     password,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Realm:        constants.Auth0UsernamePasswordConnection,
	}

	url := fmt.Sprintf("https://%s/oauth/token", u.config.Domain)

	apiRequest := httpclient.NewAPIRequest(
		u.httpClient,
		httpclient.WithMethod(http.MethodPost),
		httpclient.WithURL(url),
		httpclient.WithDescription("validate current password"),
		httpclient.WithBody(payload),
		httpclient.WithSensitiveBody(),
	)

	var tokenResponse map[string]any
	statusCode, errCall := apiRequest.Call(ctx, &tokenResponse)
	if errCall != nil {
		slog.ErrorContext(ctx, "current password validation failed",
			"error", errCall,
			"status_code", statusCode,
			"username", redaction.Redact(username),
		)

		if statusCode == http.StatusForbidden || statusCode == http.StatusUnauthorized {
			return errors.NewUnauthorized("current password is incorrect")
		}

		return errors.NewUnexpected("failed to validate current password", errCall)
	}

	slog.DebugContext(ctx, "current password validated successfully",
		"username", redaction.Redact(username),
	)

	return nil
}

// SendResetPasswordLink sends a password reset email to the user via Auth0's
// Authentication API POST /dbconnections/change_password endpoint.
// The caller is expected to have already verified the JWT and set user.UserID.
func (u *userReaderWriter) SendResetPasswordLink(ctx context.Context, user *model.User) error {

	slog.DebugContext(ctx, "sending reset password link for user",
		"user_id", redaction.Redact(user.UserID),
	)

	// Look up the user to get their email
	fullUser, errGetUser := u.GetUser(ctx, user)
	if errGetUser != nil {
		slog.ErrorContext(ctx, "failed to get user for reset password link",
			"error", errGetUser,
			"user_id", redaction.Redact(user.UserID),
		)
		return errGetUser
	}

	if strings.TrimSpace(fullUser.PrimaryEmail) == "" {
		return errors.NewValidation("user does not have an email address")
	}

	clientID := u.config.LFXOneClientID
	if clientID == "" {
		return errors.NewUnexpected("Auth0 LFX One client ID not configured for reset password link")
	}

	payload := resetPasswordRequest{
		ClientID:   clientID,
		Email:      fullUser.PrimaryEmail,
		Connection: constants.Auth0UsernamePasswordConnection,
	}

	url := fmt.Sprintf("https://%s/dbconnections/change_password", u.config.Domain)

	apiRequest := httpclient.NewAPIRequest(
		u.httpClient,
		httpclient.WithMethod(http.MethodPost),
		httpclient.WithURL(url),
		httpclient.WithDescription("send reset password link"),
		httpclient.WithBody(payload),
	)

	// Auth0 returns plain text (not JSON) for this endpoint; pass nil since we only need the status code.
	statusCode, errCall := apiRequest.Call(ctx, nil)
	if errCall != nil {
		slog.ErrorContext(ctx, "failed to send reset password link",
			"error", errCall,
			"status_code", statusCode,
			"user_id", redaction.Redact(user.UserID),
		)
		return errors.NewUnexpected("failed to send reset password link", errCall)
	}

	slog.DebugContext(ctx, "reset password link sent successfully",
		"user_id", redaction.Redact(user.UserID),
		"email", redaction.RedactEmail(fullUser.PrimaryEmail),
	)

	return nil
}
