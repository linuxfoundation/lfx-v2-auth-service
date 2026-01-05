// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package authelia

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/nats"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	errs "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/jwt"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

// userReaderWriter implements UserReaderWriter with pluggable storage and ConfigMap sync
type userReaderWriter struct {
	oidcUserInfoURL  string
	sync             *sync
	storage          internalStorageReaderWriter
	orchestrator     internalOrchestrator
	emailLinkingFlow passwordlessFlow
	httpClient       *httpclient.Client
}

// fetchOIDCUserInfo fetches user information from the OIDC userinfo endpoint
func (a *userReaderWriter) fetchOIDCUserInfo(ctx context.Context, token string) (*OIDCUserInfo, error) {
	if strings.TrimSpace(token) == "" {
		return nil, errs.NewValidation("token is required")
	}

	if strings.TrimSpace(a.oidcUserInfoURL) == "" {
		return nil, errs.NewValidation("OIDC userinfo URL is not configured")
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
		return nil, errs.NewValidation("user is required")
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
		case constants.CriteriaTypeAlternateEmail:
			// only the first alternate email is supported
			for _, alternateEmail := range user.AlternateEmails {
				slog.DebugContext(ctx, "searching user",
					"criteria", criteria,
					"alternate_email", redaction.RedactEmail(alternateEmail.Email),
				)
				return a.storage.BuildLookupKey(ctx, "email", user.BuildAlternateEmailIndexKey(ctx, alternateEmail.Email))
			}
			return ""
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
		return nil, errs.NewValidation("invalid criteria type")
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
		return nil, errs.NewValidation("user is required")
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
func (u *userReaderWriter) MetadataLookup(ctx context.Context, input string, requiredScopes ...string) (*model.User, error) {

	if input == "" {
		return nil, errs.NewValidation("input is required")
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
		return nil, errs.NewValidation("user is required")
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
		return nil, errs.NewValidation("username or sub is required")
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
		return nil, errs.NewUnexpected("failed to get existing user from storage", err)
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
			return nil, errs.NewUnexpected("failed to update user in storage", err)
		}
	}

	slog.InfoContext(ctx, "user updated successfully in storage",
		"username", user.Username)

	return existingUser.User, nil
}

func (a *userReaderWriter) SendVerificationAlternateEmail(ctx context.Context, alternateEmail string) error {
	slog.DebugContext(ctx, "sending alternate email verification",
		"alternate_email", redaction.RedactEmail(alternateEmail),
	)

	if alternateEmail == "" {
		return errs.NewValidation("alternate email is required")
	}

	otp, errSendEmail := a.emailLinkingFlow.SendEmail(ctx, alternateEmail)
	if errSendEmail != nil {
		slog.ErrorContext(ctx, "failed to send email", "error", errSendEmail)
		return errs.NewUnexpected("failed to send email", errSendEmail)
	}

	user := &model.User{}
	key := user.BuildAlternateEmailIndexKey(ctx, alternateEmail)
	errCreateVerificationCode := a.storage.CreateVerificationCode(ctx, key, otp)
	if errCreateVerificationCode != nil {
		slog.ErrorContext(ctx, "failed to create verification code", "error", errCreateVerificationCode)
		return errs.NewUnexpected("failed to create verification code", errCreateVerificationCode)
	}

	slog.DebugContext(ctx, "alternate email verification initiated successfully",
		"email", redaction.RedactEmail(alternateEmail),
	)

	return nil
}

func (a *userReaderWriter) VerifyAlternateEmail(ctx context.Context, email *model.Email) (*model.AuthResponse, error) {

	if email.Email == "" || email.OTP == "" {
		return nil, errs.NewValidation("email and OTP are required")
	}

	user := &model.User{}

	key := user.BuildAlternateEmailIndexKey(ctx, email.Email)
	otp, errGetVerificationCode := a.storage.GetVerificationCode(ctx, key)
	if errGetVerificationCode != nil {
		return nil, errGetVerificationCode
	}

	if otp != email.OTP {
		return nil, errs.NewValidation("invalid verification code")
	}

	expiresIn := 60 * time.Minute

	// Generate identity token with custom sub claim in format "email|provider"
	idToken, errGenerateIDToken := jwt.GenerateSimpleTestIdentityTokenWithSubject(
		email.Email,
		fmt.Sprintf("email|%s", email.Email),
		expiresIn,
	)
	if errGenerateIDToken != nil {
		return nil, errs.NewUnexpected("failed to generate ID token", errGenerateIDToken)
	}

	accessToken, errGenerateAccessToken := jwt.GenerateSimpleTestAccessToken(email.Email, expiresIn)
	if errGenerateAccessToken != nil {
		return nil, errs.NewUnexpected("failed to generate access token", errGenerateAccessToken)
	}

	return &model.AuthResponse{
		IDToken:     idToken,
		AccessToken: accessToken,
		ExpiresIn:   int(expiresIn.Seconds()),
		TokenType:   "Bearer",
	}, nil
}

func (a *userReaderWriter) LinkIdentity(ctx context.Context, request *model.LinkIdentity) error {
	if request == nil {
		return errs.NewValidation("request is required")
	}

	if request.User.UserID == "" {
		return errs.NewValidation("user ID is required")
	}

	if request.LinkWith.IdentityToken == "" {
		return errs.NewValidation("identity token is required")
	}

	// Parse the identity token to extract the email (from sub claim)
	opts := &jwt.ParseOptions{
		RequireExpiration: false, // The token might be expired but we still want the email
		AllowBearerPrefix: true,
		RequireSubject:    true,
	}

	claims, err := jwt.ParseUnverified(ctx, request.LinkWith.IdentityToken, opts)
	if err != nil {
		slog.ErrorContext(ctx, "failed to parse identity token",
			"error", err,
		)
		return errs.NewValidation("invalid identity token")
	}

	// Extract email
	email := claims.Email
	if email == "" {
		return errs.NewValidation("identity token does not contain an email")
	}

	slog.DebugContext(ctx, "linking identity",
		"user_id", redaction.Redact(request.User.UserID),
		"email", redaction.RedactEmail(email),
	)

	// Converting the sub to use the lookup key
	user := &model.User{
		Sub: request.User.UserID,
	}
	key := a.storage.BuildLookupKey(ctx, "sub", user.BuildSubIndexKey(ctx))

	// Get the user with revision for optimistic locking
	existingUser, revision, err := a.storage.GetUserWithRevision(ctx, key)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get user for linking identity",
			"user_id", redaction.Redact(request.User.UserID),
			"error", err,
		)
		return err
	}

	// Check if the email already exists in the alternate email list
	emailExists := false
	for _, altEmail := range existingUser.AlternateEmails {
		if strings.EqualFold(altEmail.Email, email) {
			emailExists = true
			slog.InfoContext(ctx, "email already exists in alternate email list",
				"user_id", redaction.Redact(request.User.UserID),
				"email", redaction.RedactEmail(email),
			)
			break
		}
	}

	// If email doesn't exist, add it to the list
	if !emailExists {
		if existingUser.AlternateEmails == nil {
			existingUser.AlternateEmails = []model.Email{}
		}
		existingUser.AlternateEmails = append(existingUser.AlternateEmails, model.Email{
			Email:    email,
			Verified: true, // The email is verified because it came from a verified identity token
		})

		// Update the user with optimistic locking
		err = a.storage.UpdateUserWithRevision(ctx, existingUser, revision)
		if err != nil {
			slog.ErrorContext(ctx, "failed to update user with alternate email",
				"user_id", redaction.Redact(request.User.UserID),
				"error", err,
			)
			return err
		}

		slog.InfoContext(ctx, "successfully linked alternate email to user",
			"user_id", redaction.Redact(request.User.UserID),
			"email", redaction.RedactEmail(email),
		)
	}

	return nil
}

// NewUserReaderWriter creates a new Authelia User repository
func NewUserReaderWriter(ctx context.Context, config map[string]string, natsClient *nats.NATSClient) (port.UserReaderWriter, error) {
	// Set defaults in case of not set

	u := &userReaderWriter{
		sync:             &sync{},
		oidcUserInfoURL:  config["oidc-userinfo-url"],
		emailLinkingFlow: newEmailLinkingFlow(),
		httpClient:       httpclient.NewClient(httpclient.DefaultConfig()),
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
