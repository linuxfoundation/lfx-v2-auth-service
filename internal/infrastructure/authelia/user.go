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
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/collections"
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
			"key", redaction.Redact(key),
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
			"key", redaction.Redact(key),
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
	if isAutheliaToken(input) {
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

	// The token is the caller's only proof of identity: verify it against the
	// OIDC userinfo endpoint and take the account to update exclusively from the
	// verified response, never from caller-supplied fields.
	userInfo, err := a.fetchOIDCUserInfo(ctx, user.Token)
	if err != nil {
		slog.WarnContext(ctx, "failed to verify token via OIDC userinfo", "error", err)
		return nil, errs.NewUnauthorized("a valid token is required", err)
	}
	if userInfo == nil || strings.TrimSpace(userInfo.Sub) == "" || strings.TrimSpace(userInfo.PreferredUsername) == "" {
		return nil, errs.NewUnauthorized("a valid token is required")
	}
	user.UserID = userInfo.Sub
	user.Sub = userInfo.Sub
	user.Username = userInfo.PreferredUsername
	slog.DebugContext(ctx, "resolved user from OIDC userinfo",
		"username", redaction.Redact(user.Username),
		"sub", redaction.Redact(user.Sub),
	)

	if user.Sub == "" && user.Username == "" {
		return nil, errs.NewValidation("username or sub is required")
	}

	// First, get the existing user from storage to preserve Authelia-specific fields
	existingAutheliaUser := &AutheliaUser{}
	existingAutheliaUser.SetUsername(user.Username)

	existingUser, err := a.storage.GetUser(ctx, existingAutheliaUser.Username)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get existing user from storage",
			"username", redaction.Redact(user.Username),
			"error", err,
			"key", redaction.Redact(existingAutheliaUser.Username),
		)
		return nil, errs.NewUnexpected("failed to get existing user from storage", err)
	}

	// Update Sub field if provided from OIDC userinfo
	subUpdated := false
	if user.Sub != "" && existingUser.Sub != user.Sub {
		existingUser.Sub = user.Sub
		subUpdated = true
		slog.InfoContext(ctx, "updated user sub field in storage",
			"username", redaction.Redact(user.Username),
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
				"username", redaction.Redact(user.Username),
				"error", err,
			)
			return nil, errs.NewUnexpected("failed to update user in storage", err)
		}
	}

	slog.InfoContext(ctx, "user updated successfully in storage",
		"username", redaction.Redact(user.Username))

	return existingUser.User, nil
}

// SendVerificationAlternateEmail triggers an email verification link via the Authelia backend.
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

// VerifyAlternateEmail completes verification of an alternate email for an Authelia-backed user.
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

// ValidateLinkRequest is a no-op for Authelia; link requests are validated implicitly by LinkIdentity.
func (a *userReaderWriter) ValidateLinkRequest(ctx context.Context, _ *model.LinkIdentity) error {
	slog.DebugContext(ctx, "no validations for authelia request")
	return nil
}

// LinkIdentity links a secondary identity onto an Authelia-backed primary user.
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

	if !isAutheliaToken(request.User.AuthToken) {
		return errs.NewValidation("an Authelia auth token is required")
	}

	// The identity token submitted with link_with.identity_token is the
	// short-lived ID token this service mints in VerifyAlternateEmail, signed
	// with the service's own RSA key. We must verify the signature; otherwise
	// any caller holding a valid auth_token can forge an unsigned (alg=none)
	// JWT with arbitrary sub/email and link any identity to their account.
	publicKey, err := jwt.GetDefaultTestPublicKey()
	if err != nil {
		slog.ErrorContext(ctx, "failed to load identity-token verification key", "error", err)
		return errs.NewUnexpected("failed to load identity-token verification key", err)
	}
	opts := &jwt.ParseOptions{
		VerifySignature:   true,
		SigningKey:        publicKey,
		RequireExpiration: true,
		AllowBearerPrefix: true,
		RequireSubject:    true,
	}
	claims, err := jwt.ParseVerified(ctx, request.LinkWith.IdentityToken, opts)
	if err != nil {
		slog.ErrorContext(ctx, "failed to verify identity token", "error", err)
		return errs.NewValidation("invalid identity token")
	}

	// This service only mints email identity tokens ("email|<address>"), and the
	// same key also signs access tokens, so anything else is rejected.
	address, isEmailIdentity := strings.CutPrefix(claims.Subject, "email|")
	if !isEmailIdentity || claims.Email == "" || !strings.EqualFold(address, claims.Email) {
		slog.WarnContext(ctx, "identity token is not an email identity token")
		return errs.NewValidation("invalid identity token")
	}

	return a.linkEmailIdentity(ctx, request, claims.Email)
}

func (a *userReaderWriter) linkEmailIdentity(ctx context.Context, request *model.LinkIdentity, email string) error {
	if email == "" {
		return errs.NewValidation("identity token does not contain an email")
	}

	slog.DebugContext(ctx, "linking email identity",
		"user_id", redaction.Redact(request.User.UserID),
		"email", redaction.RedactEmail(email),
	)

	user := &model.User{Sub: request.User.UserID}
	key := a.storage.BuildLookupKey(ctx, "sub", user.BuildSubIndexKey(ctx))

	existingUser, revision, err := a.storage.GetUserWithRevision(ctx, key)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get user for linking email identity",
			"user_id", redaction.Redact(request.User.UserID),
			"error", err,
		)
		return err
	}

	for _, altEmail := range existingUser.AlternateEmails {
		if strings.EqualFold(altEmail.Email, email) {
			slog.InfoContext(ctx, "email already exists in alternate email list",
				"user_id", redaction.Redact(request.User.UserID),
				"email", redaction.RedactEmail(email),
			)
			return nil
		}
	}

	existingUser.AlternateEmails = append(existingUser.AlternateEmails, model.Email{
		Email:    email,
		Verified: true,
	})

	err = a.storage.UpdateUserWithRevision(ctx, existingUser, revision)
	if err != nil {
		slog.ErrorContext(ctx, "failed to update user with alternate email",
			"user_id", redaction.Redact(request.User.UserID),
			"error", err,
		)
		return err
	}

	slog.InfoContext(ctx, "successfully linked email identity",
		"user_id", redaction.Redact(request.User.UserID),
		"email", redaction.RedactEmail(email),
	)
	return nil
}

// UnlinkIdentity unlinks an identity from an Authelia-backed primary user.
func (a *userReaderWriter) UnlinkIdentity(ctx context.Context, request *model.UnlinkIdentity) error {
	if request == nil {
		return errs.NewValidation("request is required")
	}
	if request.User.UserID == "" {
		return errs.NewValidation("user ID is required")
	}
	if request.Unlink.Provider == "" || request.Unlink.IdentityID == "" {
		return errs.NewValidation("provider and identity_id are required")
	}
	if !isAutheliaToken(request.User.AuthToken) {
		return errs.NewValidation("an Authelia auth token is required")
	}

	user := &model.User{Sub: request.User.UserID}
	key := a.storage.BuildLookupKey(ctx, "sub", user.BuildSubIndexKey(ctx))

	existingUser, revision, err := a.storage.GetUserWithRevision(ctx, key)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get user for unlinking identity",
			"user_id", redaction.Redact(request.User.UserID),
			"error", err,
		)
		return err
	}

	switch request.Unlink.Provider {
	case "email":
		existingUser.AlternateEmails = collections.RemoveFromSlice(existingUser.AlternateEmails, func(e model.Email) bool {
			return strings.EqualFold(e.Email, request.Unlink.IdentityID)
		})
	default:
		existingUser.Identities = collections.RemoveFromSlice(existingUser.Identities, func(id model.Identity) bool {
			return id.Provider == request.Unlink.Provider && id.IdentityID == request.Unlink.IdentityID
		})
	}

	err = a.storage.UpdateUserWithRevision(ctx, existingUser, revision)
	if err != nil {
		slog.ErrorContext(ctx, "failed to update user after unlinking identity",
			"user_id", redaction.Redact(request.User.UserID),
			"provider", request.Unlink.Provider,
			"error", err,
		)
		return err
	}

	slog.InfoContext(ctx, "successfully unlinked identity",
		"user_id", redaction.Redact(request.User.UserID),
		"provider", request.Unlink.Provider,
	)
	return nil
}

// isAutheliaToken reports whether the input is an Authelia opaque token. Only
// these are authenticated against the OIDC userinfo endpoint in MetadataLookup;
// a UUID or username input is resolved to a user without any authentication.
func isAutheliaToken(input string) bool {
	return strings.HasPrefix(input, "authelia")
}

// ChangePassword is not supported for Authelia users.
func (a *userReaderWriter) ChangePassword(_ context.Context, _ *model.User, _, _ string) error {
	return errs.NewValidation("password change is not supported for Authelia users")
}

// SendResetPasswordLink is not supported for Authelia users.
func (a *userReaderWriter) SendResetPasswordLink(_ context.Context, _ *model.User) error {
	return errs.NewValidation("password reset link is not supported for Authelia users")
}

// SetPrimaryEmail is not supported for Authelia users.
func (a *userReaderWriter) SetPrimaryEmail(_ context.Context, _ string, _ string) error {
	return errs.NewValidation("set primary email is not supported for Authelia users")
}

// AddSystemManagedEmail is not supported for Authelia users; system-managed
// aliases require the Auth0 Management API backend.
func (a *userReaderWriter) AddSystemManagedEmail(_ context.Context, _, _ string) (string, error) {
	return "", errs.NewValidation("add system managed email is not supported for Authelia users")
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
		slog.WarnContext(ctx, "failed to sync from storage to orchestrator", "error", errSyncUsers)
	}

	return u, nil
}
