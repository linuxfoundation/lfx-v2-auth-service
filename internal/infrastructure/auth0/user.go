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
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/jwt"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

const auth0SubPrefix = "auth0|"

// Config holds the configuration for Auth0 Management API
type Config struct {
	Tenant string
	Domain string
	// M2MTokenManager for machine-to-machine authentication
	M2MTokenManager *TokenManager
	// JWTVerificationConfig for JWT signature verification
	JWTVerificationConfig *JWTVerificationConfig
	// LFXProfileClientID is the Auth0 client ID for the LFX Profile app,
	// used to validate current passwords via Resource Owner Password Grant.
	LFXProfileClientID string
	// LFXProfileClientSecret is the Auth0 client secret for the LFX Profile app.
	LFXProfileClientSecret string
	// LFXOneClientID is the Auth0 client ID for the LFX One app,
	// used as the audience when sending password reset links.
	LFXOneClientID string
}

// userUpdateRequest represents the request body for updating a user in Auth0
type userUpdateRequest struct {
	UserMetadata *model.UserMetadata `json:"user_metadata,omitempty"`
}

type userReaderWriter struct {
	config              Config
	identityLinkingFlow *identityLinkingFlow
	emailLinkingFlow    *emailLinkingFlow
	httpClient          *httpclient.Client
	errorResponse       *ErrorResponse
}

// SearchUser searches Auth0 for a user matching the given criteria (email, username, or user_id).
func (u *userReaderWriter) SearchUser(ctx context.Context, user *model.User, criteria string) (*model.User, error) {

	filterer := newUserFilterer(criteria, user)
	if filterer == nil {
		return nil, errors.NewValidation(fmt.Sprintf("invalid criteria type: %s", criteria))
	}

	endpoint := filterer.Endpoint(ctx)
	args := filterer.Args(ctx)

	if user.Token == "" {
		slog.DebugContext(ctx, "getting M2M token",
			"criteria", criteria,
		)

		m2mToken, errGetToken := u.config.M2MTokenManager.GetToken(ctx)
		if errGetToken != nil {
			return nil, errors.NewUnexpected("failed to get M2M token", errGetToken)
		}
		user.Token = m2mToken
	}

	endpointWithParam := fmt.Sprintf(endpoint, args...)
	url := fmt.Sprintf("https://%s/api/v2/%s", u.config.Domain, endpointWithParam)

	apiRequest := httpclient.NewAPIRequest(
		u.httpClient,
		httpclient.WithMethod(http.MethodGet),
		httpclient.WithURL(url),
		httpclient.WithToken(user.Token),
		httpclient.WithDescription("search user"),
	)

	var users []Auth0User

	statusCode, errCall := apiRequest.Call(ctx, &users)
	if errCall != nil {
		slog.ErrorContext(ctx, "failed to search user",
			"error", errCall,
			"status_code", statusCode,
		)
		return nil, errors.NewUnexpected("failed to search user", errCall)
	}

	if len(users) == 0 {
		return nil, errors.NewNotFound("user not found")
	}

	slog.DebugContext(ctx, "users found, checking if the user is the one with the correct identity",
		"criteria", criteria,
	)

	for _, userResult := range users {
		// identities.user_id:{{username}} AND identities.connection:Username-Password-Authentication (and other connections)
		// It doesn't work like an AND, it works like an IN clause
		// (check if it contains the username and the connection, but they might not be in  the same identity)
		// So it's necessary to check if the identity is the one we are looking for
		found, err := filterer.Filter(ctx, &userResult)
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		return userResult.ToUser(), nil
	}
	return nil, errors.NewNotFound("user not found")
}

// GetUser fetches the full Auth0 user record by user_id.
func (u *userReaderWriter) GetUser(ctx context.Context, user *model.User) (*model.User, error) {

	slog.DebugContext(ctx, "getting user", "user_id", user.UserID)

	if user.Token == "" {
		slog.DebugContext(ctx, "getting M2M token",
			"user_id", redaction.Redact(user.UserID),
		)

		m2mToken, errGetToken := u.config.M2MTokenManager.GetToken(ctx)
		if errGetToken != nil {
			return nil, errors.NewUnexpected("failed to get M2M token", errGetToken)
		}
		user.Token = m2mToken
	}

	// If we don't have a user ID, we can't fetch the user
	if user.UserID == "" {
		return nil, errors.NewValidation("user_id is required to get user")
	}

	// Validate configuration before making HTTP requests
	if strings.TrimSpace(u.config.Domain) == "" {
		return nil, errors.NewValidation("Auth0 domain configuration is missing")
	}

	apiRequest := httpclient.NewAPIRequest(
		u.httpClient,
		httpclient.WithMethod(http.MethodGet),
		httpclient.WithURL(fmt.Sprintf("https://%s/api/v2/users/%s", u.config.Domain, user.UserID)),
		httpclient.WithToken(user.Token),
		httpclient.WithDescription("get user details"),
	)

	// Parse the response to update the user object
	var auth0User *Auth0User
	statusCode, errCall := apiRequest.Call(ctx, &auth0User)
	if errCall != nil {
		slog.ErrorContext(ctx, "failed to get user from Auth0",
			"error", errCall,
			"status_code", statusCode,
			"user_id", user.UserID,
		)
		msg := u.errorResponse.ErrorMessage(errCall.Error())
		return nil, httpclient.ErrorFromStatusCode(statusCode, msg)
	}

	if auth0User == nil {
		slog.ErrorContext(ctx, "failed to get user from Auth0",
			"status_code", statusCode,
			"user_id", user.UserID,
		)
		return nil, errors.NewNotFound("user not found")
	}

	slog.DebugContext(ctx, "user retrieved successfully", "user_id", user.UserID)

	return auth0User.ToUser(), nil
}

// MetadataLookup prepares the user for metadata lookup based on the input
// Accepts JWT token, username, or sub
func (u *userReaderWriter) MetadataLookup(ctx context.Context, input string, requiredScopes ...string) (*model.User, error) {
	// Validate input
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, errors.NewValidation("input is required")
	}

	slog.DebugContext(ctx, "metadata lookup", "input", redaction.Redact(input))

	user := &model.User{}

	// First, try to parse as JWT token to extract the sub
	if cleanToken, isJWT := jwt.LooksLikeJWT(input); isJWT {

		slog.DebugContext(ctx, "jwt strategy", "input", redaction.Redact(input))

		// Verify JWT token with read scope
		if u.config.JWTVerificationConfig == nil {
			return nil, errors.NewValidation("JWT verification configuration is required")
		}

		claims, err := u.config.JWTVerificationConfig.JWTVerify(ctx, cleanToken, requiredScopes...)
		if err != nil {
			slog.ErrorContext(ctx, "JWT signature verification failed",
				"error", err,
			)
			return nil, err
		}

		// Successfully verified JWT token
		user.Token = cleanToken
		user.UserID = claims.Subject
		user.Sub = claims.Subject

		slog.DebugContext(ctx, "JWT signature verification successful for metadata lookup",
			"sub", user.Sub,
		)
		return user, nil

	}

	// Determine lookup strategy based on input format
	switch {
	case strings.Contains(input, "|"):
		// Input contains "|", use as sub for canonical lookup
		user.UserID = input
		slog.DebugContext(ctx, "canonical lookup strategy", "sub", redaction.Redact(input))

	default:
		// username search
		user.Username = input
		user.UserID = ""
		slog.DebugContext(ctx, "username search strategy", "username", redaction.Redact(input))
	}

	return user, nil
}

// UpdateUser applies the provided changes to the Auth0 user via PATCH.
func (u *userReaderWriter) UpdateUser(ctx context.Context, user *model.User) (*model.User, error) {

	if u.config.JWTVerificationConfig == nil {
		return nil, errors.NewValidation("JWT verification configuration is required")
	}

	claims, errJwtVerify := u.config.JWTVerificationConfig.JWTVerify(ctx, user.Token, constants.UserUpdateMetadataRequiredScope)
	if errJwtVerify != nil {
		slog.ErrorContext(ctx, "jwt verify failed", "error", errJwtVerify)
		return nil, errJwtVerify
	}
	// Extract the user_id from the 'sub' claim
	user.UserID = claims.Subject

	// Validate configuration before making HTTP requests
	if strings.TrimSpace(u.config.Domain) == "" {
		return nil, errors.NewValidation("Auth0 domain configuration is missing")
	}

	// Prepare the request body for updating user metadata
	if user.UserMetadata == nil {
		return nil, errors.NewValidation("user_metadata is required for update")
	}
	updateRequest := userUpdateRequest{UserMetadata: user.UserMetadata}

	// Call Auth0 Management API to update the user
	apiRequest := httpclient.NewAPIRequest(
		u.httpClient,
		httpclient.WithMethod(http.MethodPatch),
		httpclient.WithURL(fmt.Sprintf("https://%s/api/v2/users/%s", u.config.Domain, user.UserID)),
		httpclient.WithToken(user.Token),
		httpclient.WithDescription("update user metadata"),
		httpclient.WithBody(updateRequest),
	)

	var auth0Response struct {
		UserMetadata *model.UserMetadata `json:"user_metadata,omitempty"`
	}

	statusCode, errCall := apiRequest.Call(ctx, &auth0Response)
	if errCall != nil {
		slog.ErrorContext(ctx, "failed to update user in Auth0",
			"error", errCall,
			"status_code", statusCode,
			"user_id", user.UserID,
		)
		return nil, errors.NewUnexpected("failed to update user in Auth0", errCall)
	}

	// Create a new user object with only the user_metadata populated
	updatedUser := &model.User{
		UserMetadata: auth0Response.UserMetadata,
	}

	slog.DebugContext(ctx, "user updated successfully",
		"user_id", user.UserID,
	)
	return updatedUser, nil
}

// SendVerificationAlternateEmail triggers Auth0 to send a verification link for an alternate email.
func (u *userReaderWriter) SendVerificationAlternateEmail(ctx context.Context, alternateEmail string) error {

	if u.emailLinkingFlow == nil {
		return errors.NewUnexpected("email linking flow not configured")
	}

	errStartPasswordlessFlow := u.emailLinkingFlow.StartPasswordlessFlow(ctx, alternateEmail)
	if errStartPasswordlessFlow != nil {
		return errStartPasswordlessFlow
	}

	slog.DebugContext(ctx, "send verification alternate email successfully")

	return nil
}

// VerifyAlternateEmail completes verification of an alternate email using the provided code/token.
func (u *userReaderWriter) VerifyAlternateEmail(ctx context.Context, email *model.Email) (*model.AuthResponse, error) {

	if u.emailLinkingFlow == nil {
		return nil, errors.NewUnexpected("email linking flow not configured")
	}

	if email.Email == "" || email.OTP == "" {
		return nil, errors.NewValidation("email and OTP are required")
	}

	tokenResp, errExchangeOTPForToken := u.emailLinkingFlow.ExchangeOTPForToken(ctx, email.Email, email.OTP)
	if errExchangeOTPForToken != nil {
		return nil, errExchangeOTPForToken
	}

	authResponse := &model.AuthResponse{
		AccessToken: tokenResp.AccessToken,
		IDToken:     tokenResp.IDToken,
		Scope:       tokenResp.Scope,
		ExpiresIn:   int(tokenResp.ExpiresIn),
		TokenType:   tokenResp.TokenType,
	}

	slog.DebugContext(ctx, "alternate email verified successfully",
		"email", redaction.Redact(email.Email),
	)

	return authResponse, nil
}

// ValidateLinkRequest performs backend-specific validation on a link-identity request before linking.
func (u *userReaderWriter) ValidateLinkRequest(ctx context.Context, request *model.LinkIdentity) error {
	if request == nil {
		return errors.NewValidation("link identity request is required")
	}

	if request.LinkWith.IdentityToken == "" {
		return errors.NewValidation("link_with identity token is required")
	}

	sub, err := jwt.ExtractSubject(ctx, request.LinkWith.IdentityToken)
	if err != nil {
		return errors.NewValidation("invalid identity token: unable to extract subject")
	}

	if strings.HasPrefix(sub, auth0SubPrefix) {
		slog.WarnContext(ctx, "identity token belongs to a database (LFID) user; rejecting link request")
		return errors.NewValidation("the provided identity token belongs to an existing LFID account and cannot be linked")
	}

	return nil
}

// LinkIdentity links the secondary identity in the request onto the primary Auth0 user.
func (u *userReaderWriter) LinkIdentity(ctx context.Context, request *model.LinkIdentity) error {

	if u.identityLinkingFlow == nil {
		return errors.NewUnexpected("email linking flow not configured")
	}

	if request == nil {
		return errors.NewValidation("link identity request is required")
	}

	if request.User.UserID == "" {
		return errors.NewValidation("user_id is required")
	}

	if request.User.AuthToken == "" {
		return errors.NewValidation("user_token is required")
	}

	if request.LinkWith.IdentityToken == "" {
		return errors.NewValidation("link_with is required")
	}

	slog.DebugContext(ctx, "linking identity to user",
		"user_id", redaction.Redact(request.User.UserID),
	)

	errLinkIdentity := u.identityLinkingFlow.LinkIdentityToUser(
		ctx,
		request.User.UserID,
		request.User.AuthToken,
		request.LinkWith.IdentityToken,
	)
	if errLinkIdentity != nil {
		return errLinkIdentity
	}

	slog.DebugContext(ctx, "identity linked successfully via user reader writer",
		"user_id", redaction.Redact(request.User.UserID),
	)

	return nil
}

// UnlinkIdentity unlinks the identity in the request from the primary Auth0 user, refusing system-managed identities.
func (u *userReaderWriter) UnlinkIdentity(ctx context.Context, request *model.UnlinkIdentity) error {

	if u.identityLinkingFlow == nil {
		return errors.NewUnexpected("identity linking flow not configured")
	}

	if request == nil {
		return errors.NewValidation("unlink identity request is required")
	}

	if request.User.UserID == "" {
		return errors.NewValidation("user_id is required")
	}

	if request.User.AuthToken == "" {
		return errors.NewValidation("user_token is required")
	}

	if request.Unlink.Provider == "" {
		return errors.NewValidation("provider is required")
	}

	if request.Unlink.IdentityID == "" {
		return errors.NewValidation("identity_id is required")
	}

	slog.DebugContext(ctx, "unlinking identity from user",
		"user_id", redaction.Redact(request.User.UserID),
		"provider", request.Unlink.Provider,
	)

	// Guard: refuse to unlink system-managed identities (e.g. aliases).
	// Only the passwordless email connection can hold system-managed identities,
	// so skip the guard entirely for other providers (google, github, etc.) to
	// avoid making every social-identity unlink depend on the Management API.
	// For email-connection unlinks, fetch the stub via M2M to read its
	// app_metadata. The check fails closed: any error other than 404 (which
	// means the stub never existed and there is nothing to protect) blocks the
	// unlink so a transient Auth0 failure cannot be used to bypass immutability.
	if request.Unlink.Provider != constants.EmailConnection {
		return u.identityLinkingFlow.UnlinkIdentityFromUser(
			ctx,
			request.User.UserID,
			request.User.AuthToken,
			request.Unlink.Provider,
			request.Unlink.IdentityID,
		)
	}

	stubUserID := fmt.Sprintf("%s|%s", request.Unlink.Provider, request.Unlink.IdentityID)
	m2mToken, errToken := u.config.M2MTokenManager.GetToken(ctx)
	if errToken != nil {
		return errors.NewUnexpected("failed to get M2M token for unlink guard", errToken)
	}
	apiRequest := httpclient.NewAPIRequest(
		u.httpClient,
		httpclient.WithMethod(http.MethodGet),
		httpclient.WithURL(fmt.Sprintf("https://%s/api/v2/users/%s", u.config.Domain, url.PathEscape(stubUserID))),
		httpclient.WithToken(m2mToken),
		httpclient.WithDescription("get stub user for unlink guard"),
	)
	var rawStub Auth0User
	if statusCode, callErr := apiRequest.Call(ctx, &rawStub); callErr != nil {
		if statusCode != http.StatusNotFound {
			slog.ErrorContext(ctx, "failed to evaluate system-managed unlink guard",
				"stub_user_id", redaction.Redact(stubUserID),
				"status_code", statusCode,
				"error", callErr,
			)
			return errors.NewUnexpected("failed to evaluate system-managed unlink guard", callErr)
		}
	} else if rawStub.AppMetadata != nil && rawStub.AppMetadata.SystemManaged {
		return errors.NewForbidden("system_managed_identity")
	}

	errUnlinkIdentity := u.identityLinkingFlow.UnlinkIdentityFromUser(
		ctx,
		request.User.UserID,
		request.User.AuthToken,
		request.Unlink.Provider,
		request.Unlink.IdentityID,
	)
	if errUnlinkIdentity != nil {
		return errUnlinkIdentity
	}

	slog.DebugContext(ctx, "identity unlinked successfully via user reader writer",
		"user_id", redaction.Redact(request.User.UserID),
	)

	return nil
}

// AddSystemManagedEmail creates a stub Auth0 passwordless user for email,
// links it to primaryUserID via the Management API (M2M, no user-facing
// magic-link), and marks it system_managed so it cannot be user-unlinked.
// Returns the stub user_id. On link failure a best-effort cleanup of the stub
// is attempted before the error is returned.
func (u *userReaderWriter) AddSystemManagedEmail(ctx context.Context, primaryUserID, email string) (string, error) {
	if strings.TrimSpace(primaryUserID) == "" {
		return "", errors.NewValidation("primary_user_id is required")
	}
	if strings.TrimSpace(email) == "" {
		return "", errors.NewValidation("email is required")
	}

	return u.createAndLinkEmailIdentity(ctx, primaryUserID, email, &Auth0AppMetadata{SystemManaged: true})
}

// createAndLinkEmailIdentity creates a stub Auth0 passwordless email-connection
// user for email and links it to primaryUserID via the Management API (M2M
// direct-link, no user-facing magic-link). It returns the stub user_id.
//
// appMetadata controls how the resulting identity is governed:
//   - nil: a normal, user-removable email identity (no app_metadata is sent).
//   - non-nil: attached as-is (e.g. {SystemManaged:true} for a system alias that
//     must not be user-unlinked).
//
// EmailVerified is always set: callers guarantee the address is already verified
// (a system alias on an LF-controlled domain, or the user's current verified
// primary email being preserved before a switch).
//
// On link failure the just-created stub is rolled back on a best-effort basis:
// system-managed stubs via deleteSystemManagedUser, otherwise via
// deleteEmailConnectionStub.
func (u *userReaderWriter) createAndLinkEmailIdentity(ctx context.Context, primaryUserID, email string, appMetadata *Auth0AppMetadata) (string, error) {
	m2mToken, errToken := u.config.M2MTokenManager.GetToken(ctx)
	if errToken != nil {
		return "", errors.NewUnexpected("failed to get M2M token for add email identity", errToken)
	}

	// Step 1: create the stub passwordless user.
	createPayload := systemManagedUserPayload{
		Connection:    constants.EmailConnection,
		Email:         email,
		EmailVerified: true,
		AppMetadata:   appMetadata,
	}

	apiCreate := httpclient.NewAPIRequest(
		u.httpClient,
		httpclient.WithMethod(http.MethodPost),
		httpclient.WithURL(fmt.Sprintf("https://%s/api/v2/users", u.config.Domain)),
		httpclient.WithToken(m2mToken),
		httpclient.WithDescription("create email stub user"),
		httpclient.WithBody(createPayload),
	)

	var stubUser Auth0User
	statusCode, errCreate := apiCreate.Call(ctx, &stubUser)
	if errCreate != nil {
		slog.ErrorContext(ctx, "failed to create email stub user",
			"error", errCreate,
			"status_code", statusCode,
			"email", redaction.RedactEmail(email),
		)
		// Auth0 returns 409 when the email is already registered on the
		// connection. Surface this as a validation error so the handler can
		// map it to alias_not_available instead of a generic infra failure.
		if statusCode == http.StatusConflict {
			return "", errors.NewValidation("email already linked")
		}
		return "", errors.NewUnexpected("failed to create email stub user", errCreate)
	}

	if stubUser.UserID == "" {
		return "", errors.NewUnexpected("Auth0 returned empty user_id for created stub user")
	}

	slog.DebugContext(ctx, "email stub user created",
		"stub_user_id", redaction.Redact(stubUser.UserID),
	)

	// Step 2: link the stub to the primary user.
	// Auth0's direct-link endpoint expects the provider-local part only (without the "email|" prefix).
	localID := stubUser.UserID
	if idx := strings.Index(localID, "|"); idx >= 0 {
		localID = localID[idx+1:]
	}

	linkPayload := linkSubIdentityPayload{
		Provider: constants.EmailConnection,
		UserID:   localID,
	}

	apiLink := httpclient.NewAPIRequest(
		u.httpClient,
		httpclient.WithMethod(http.MethodPost),
		httpclient.WithURL(fmt.Sprintf("https://%s/api/v2/users/%s/identities", u.config.Domain, url.PathEscape(primaryUserID))),
		httpclient.WithToken(m2mToken),
		httpclient.WithDescription("link email stub to primary user"),
		httpclient.WithBody(linkPayload),
	)

	var linkedIdentities []any
	statusCode, errLink := apiLink.Call(ctx, &linkedIdentities)
	if errLink != nil {
		slog.ErrorContext(ctx, "failed to link email stub to primary user; attempting rollback",
			"error", errLink,
			"status_code", statusCode,
			"stub_user_id", redaction.Redact(stubUser.UserID),
			"primary_user_id", redaction.Redact(primaryUserID),
		)
		// Best-effort rollback: delete the orphaned stub user. System-managed
		// stubs use the system_managed-guarded delete; user-removable stubs use
		// the connection-guarded delete (the system_managed guard would refuse).
		errDel := u.rollbackEmailStub(ctx, stubUser.UserID, m2mToken, appMetadata)
		if errDel != nil {
			slog.WarnContext(ctx, "rollback failed: could not delete orphaned stub user",
				"error", errDel,
				"stub_user_id", redaction.Redact(stubUser.UserID),
			)
		}
		return "", errors.NewUnexpected("failed to link email identity", errLink)
	}

	slog.DebugContext(ctx, "email identity linked successfully",
		"primary_user_id", redaction.Redact(primaryUserID),
		"stub_user_id", redaction.Redact(stubUser.UserID),
		"email", redaction.RedactEmail(email),
	)

	return stubUser.UserID, nil
}

// rollbackEmailStub deletes a just-created stub on link failure, selecting the
// delete guard that matches how the stub was created.
func (u *userReaderWriter) rollbackEmailStub(ctx context.Context, userID, m2mToken string, appMetadata *Auth0AppMetadata) error {
	if appMetadata != nil && appMetadata.SystemManaged {
		return u.deleteSystemManagedUser(ctx, userID, m2mToken)
	}
	return u.deleteEmailConnectionStub(ctx, userID, m2mToken)
}

// NewUserReaderWriter  creates a new UserReaderWriter with the provided configuration
func NewUserReaderWriter(ctx context.Context, httpConfig httpclient.Config, auth0Config Config) (port.UserReaderWriter, error) {

	// Add M2M token manager to config
	m2mTokenManager, err := NewM2MTokenManager(ctx, auth0Config)
	if err != nil {
		return nil, fmt.Errorf("failed to create M2M token manager: %w", err)
	}

	auth0Config.M2MTokenManager = m2mTokenManager

	// Create httpClient first
	httpClient := httpclient.NewClient(httpConfig)

	// JWT verification config is required
	if auth0Config.JWTVerificationConfig == nil {
		jwtConfig, errNewJWTVerificationConfig := NewJWTVerificationConfig(ctx, auth0Config.Domain, httpClient)
		if errNewJWTVerificationConfig != nil {
			return nil, errors.NewUnexpected("failed to create JWT verification config", errNewJWTVerificationConfig)
		}
		if jwtConfig == nil {
			return nil, errors.NewUnexpected("JWT verification configuration is required but could not be created")
		}
		auth0Config.JWTVerificationConfig = jwtConfig
	}

	// Create profile client auth config for email linking flow (passwordless)
	profileClientAuthConfig, err := NewProfileClientAuthConfig(ctx, auth0Config.Domain)
	if err != nil {
		return nil, fmt.Errorf("failed to create profile client auth config: %w", err)
	}

	// linking flow for email linking (passwordless)
	emailLinkingFlow := newEmailLinkingFlow(profileClientAuthConfig)

	// linking flow for identity linking (passwordless)
	identityLinkingFlow := newIdentityLinkingFlow(auth0Config.Domain, httpClient)

	return &userReaderWriter{
		config:              auth0Config,
		identityLinkingFlow: identityLinkingFlow,
		emailLinkingFlow:    emailLinkingFlow,
		httpClient:          httpClient,
		errorResponse:       NewErrorResponse(),
	}, nil
}

// setPrimaryEmailRequest represents the request body for updating a user's primary email in Auth0
type setPrimaryEmailRequest struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

// hasSufficientPrimaryEmailIdentity reports whether email is already backed by an
// identity that keeps it reachable as a verified login after it stops being the
// root primary, so no new email identity needs to be materialized:
//
//   - constants.EmailConnection (any): a passwordless email/OTP identity. It is
//     OTP-reachable regardless of its current email_verified flag (Auth0 marks it
//     verified on the next successful OTP login), and a duplicate cannot be
//     created — so an existing email identity is always sufficient.
//
// Every other case is NOT sufficient. Social and enterprise connections (Google,
// GitHub, LinkedIn, etc.) are login *methods*, not alternate emails — the auth
// service only ever offers email-connection identities as primary-email
// candidates, so a social identity does not keep the address reachable as a
// selectable verified email. When the only backing is social, or there is no
// backing at all, the old primary must be preserved as a verified email identity
// before it is replaced. Matching is case-insensitive on the identity's email.
func hasSufficientPrimaryEmailIdentity(user *model.User, email string) bool {
	for _, id := range user.Identities {
		if !strings.EqualFold(id.Email, email) {
			continue
		}
		// Any passwordless email identity is OTP-reachable and self-verifies on
		// the next login; a duplicate cannot be created — so it is sufficient.
		if id.Connection == constants.EmailConnection {
			return true
		}
	}
	return false
}

// SetPrimaryEmail updates the user's primary email address via the Auth0 Management API.
// The email must already be a verified linked identity on the user's account.
func (u *userReaderWriter) SetPrimaryEmail(ctx context.Context, userID string, email string) error {

	if strings.TrimSpace(userID) == "" {
		return errors.NewValidation("user ID is required")
	}
	if strings.TrimSpace(email) == "" {
		return errors.NewValidation("email is required")
	}

	// Fetch the user to validate the requested email is a verified linked identity
	fullUser, errGetUser := u.GetUser(ctx, &model.User{UserID: userID})
	if errGetUser != nil {
		slog.ErrorContext(ctx, "failed to get user for set primary email",
			"error", errGetUser,
			"user_id", redaction.Redact(userID),
		)
		return errors.NewUnexpected("failed to get user for set primary email", errGetUser)
	}

	// Verify the email is one of the user's verified linked email identities
	found := false
	for _, id := range fullUser.Identities {
		if id.Connection != constants.EmailConnection {
			continue
		}
		if strings.EqualFold(id.Email, email) {
			if !id.EmailVerified {
				return errors.NewValidation("email is not verified and cannot be set as primary")
			}
			found = true
			break
		}
	}
	if !found {
		return errors.NewValidation("email is not a linked identity on this account")
	}

	// Preserve the current primary before switching. The root email PATCH below
	// overwrites the primary, which would leave the old primary unreachable as a
	// selectable verified email unless it is already backed by an email-connection
	// identity (see hasSufficientPrimaryEmailIdentity). Otherwise — backed only by a
	// social/enterprise identity (Google, GitHub, LinkedIn, etc.), which is a login
	// method and not a primary-email candidate, or no backing identity at all —
	// create+link it as a normal, user-removable verified email identity first.
	// Done first so that any failure leaves the account unchanged rather than
	// silently dropping the old primary.
	oldPrimary := fullUser.PrimaryEmail
	if oldPrimary != "" && !strings.EqualFold(oldPrimary, email) && !hasSufficientPrimaryEmailIdentity(fullUser, oldPrimary) {
		if _, errPreserve := u.createAndLinkEmailIdentity(ctx, userID, oldPrimary, nil); errPreserve != nil {
			slog.ErrorContext(ctx, "failed to preserve old primary email before switching",
				"error", errPreserve,
				"user_id", redaction.Redact(userID),
			)
			return errPreserve
		}
	}

	m2mToken, errGetToken := u.config.M2MTokenManager.GetToken(ctx)
	if errGetToken != nil {
		return errors.NewUnexpected("failed to get M2M token for set primary email", errGetToken)
	}

	payload := setPrimaryEmailRequest{
		Email:         email,
		EmailVerified: true,
	}

	apiRequest := httpclient.NewAPIRequest(
		u.httpClient,
		httpclient.WithMethod(http.MethodPatch),
		httpclient.WithURL(fmt.Sprintf("https://%s/api/v2/users/%s", u.config.Domain, url.PathEscape(userID))),
		httpclient.WithToken(m2mToken),
		httpclient.WithDescription("set primary email"),
		httpclient.WithBody(payload),
	)

	var patchResponse map[string]any
	statusCode, errCall := apiRequest.Call(ctx, &patchResponse)
	if errCall != nil {
		slog.ErrorContext(ctx, "failed to set primary email in Auth0",
			"error", errCall,
			"status_code", statusCode,
			"user_id", redaction.Redact(userID),
		)
		return errors.NewUnexpected("failed to set primary email", errCall)
	}

	slog.DebugContext(ctx, "primary email updated successfully",
		"user_id", redaction.Redact(userID),
	)

	return nil
}

// deleteSystemManagedUser deletes an Auth0 user but only if its
// app_metadata.system_managed is true. The pre-flight GET is defense-in-depth:
// it ensures this helper can never be used to delete a real human account even
// if a future caller passes the wrong user_id. A non-404 fetch failure or a
// missing/false system_managed flag aborts the delete.
func (u *userReaderWriter) deleteSystemManagedUser(ctx context.Context, userID, m2mToken string) error {
	if strings.TrimSpace(userID) == "" {
		return errors.NewValidation("user_id is required")
	}

	apiGet := httpclient.NewAPIRequest(
		u.httpClient,
		httpclient.WithMethod(http.MethodGet),
		httpclient.WithURL(fmt.Sprintf("https://%s/api/v2/users/%s", u.config.Domain, url.PathEscape(userID))),
		httpclient.WithToken(m2mToken),
		httpclient.WithDescription("verify system-managed before delete"),
	)
	var target Auth0User
	if statusCode, errGet := apiGet.Call(ctx, &target); errGet != nil {
		if statusCode == http.StatusNotFound {
			// Already gone — nothing to clean up.
			return nil
		}
		slog.ErrorContext(ctx, "failed to verify system-managed before delete",
			"user_id", redaction.Redact(userID),
			"status_code", statusCode,
			"error", errGet,
		)
		return errors.NewUnexpected("failed to verify system_managed before delete", errGet)
	}
	if target.AppMetadata == nil || !target.AppMetadata.SystemManaged {
		return errors.NewForbidden("refusing to delete user without app_metadata.system_managed=true")
	}

	apiDelete := httpclient.NewAPIRequest(
		u.httpClient,
		httpclient.WithMethod(http.MethodDelete),
		httpclient.WithURL(fmt.Sprintf("https://%s/api/v2/users/%s", u.config.Domain, url.PathEscape(userID))),
		httpclient.WithToken(m2mToken),
		httpclient.WithDescription("delete system-managed user"),
	)
	if _, errDel := apiDelete.Call(ctx, nil); errDel != nil {
		return errors.NewUnexpected("failed to delete system-managed user", errDel)
	}
	return nil
}

// deleteEmailConnectionStub deletes a just-created email-connection stub user on
// rollback when the stub is NOT system-managed (so deleteSystemManagedUser would
// refuse it). The pre-flight GET is defense-in-depth: it refuses to delete unless
// every identity on the user is an email-connection identity, ensuring this helper
// can never remove a real account that also carries social/DB identities. A 404
// fetch is treated as already-gone; any other fetch failure or a non-email identity
// aborts the delete.
func (u *userReaderWriter) deleteEmailConnectionStub(ctx context.Context, userID, m2mToken string) error {
	if strings.TrimSpace(userID) == "" {
		return errors.NewValidation("user_id is required")
	}

	apiGet := httpclient.NewAPIRequest(
		u.httpClient,
		httpclient.WithMethod(http.MethodGet),
		httpclient.WithURL(fmt.Sprintf("https://%s/api/v2/users/%s", u.config.Domain, url.PathEscape(userID))),
		httpclient.WithToken(m2mToken),
		httpclient.WithDescription("verify email-connection stub before delete"),
	)
	var target Auth0User
	if statusCode, errGet := apiGet.Call(ctx, &target); errGet != nil {
		if statusCode == http.StatusNotFound {
			// Already gone — nothing to clean up.
			return nil
		}
		slog.ErrorContext(ctx, "failed to verify email-connection stub before delete",
			"user_id", redaction.Redact(userID),
			"status_code", statusCode,
			"error", errGet,
		)
		return errors.NewUnexpected("failed to verify email-connection stub before delete", errGet)
	}
	if len(target.Identities) == 0 {
		return errors.NewForbidden("refusing to delete user with no identities")
	}
	for _, id := range target.Identities {
		if id.Connection != constants.EmailConnection {
			return errors.NewForbidden("refusing to delete user with a non-email-connection identity")
		}
	}

	apiDelete := httpclient.NewAPIRequest(
		u.httpClient,
		httpclient.WithMethod(http.MethodDelete),
		httpclient.WithURL(fmt.Sprintf("https://%s/api/v2/users/%s", u.config.Domain, url.PathEscape(userID))),
		httpclient.WithToken(m2mToken),
		httpclient.WithDescription("delete email-connection stub user"),
	)
	if _, errDel := apiDelete.Call(ctx, nil); errDel != nil {
		return errors.NewUnexpected("failed to delete email-connection stub user", errDel)
	}
	return nil
}
