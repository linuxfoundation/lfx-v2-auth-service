// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/jwt"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

const (
	userUpdateRequiredScope = "update:current_user_metadata"
	userReadRequiredScope   = "read:current_user"
)

// Config holds the configuration for Auth0 Management API
type Config struct {
	Tenant string
	Domain string
	// M2MTokenManager for machine-to-machine authentication
	M2MTokenManager *TokenManager
	// JWTVerificationConfig for JWT signature verification
	JWTVerificationConfig *JWTVerificationConfig
}

// userUpdateRequest represents the request body for updating a user in Auth0
type userUpdateRequest struct {
	UserMetadata *model.UserMetadata `json:"user_metadata,omitempty"`
}

type userReaderWriter struct {
	config           Config
	emailLinkingFlow *EmailLinkingFlow
	httpClient       *httpclient.Client
	errorResponse    *ErrorResponse
}

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
func (u *userReaderWriter) MetadataLookup(ctx context.Context, input string) (*model.User, error) {
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

		claims, err := u.config.JWTVerificationConfig.JWTVerify(ctx, cleanToken, userReadRequiredScope)
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

func (u *userReaderWriter) UpdateUser(ctx context.Context, user *model.User) (*model.User, error) {

	if u.config.JWTVerificationConfig == nil {
		return nil, errors.NewValidation("JWT verification configuration is required")
	}

	claims, errJwtVerify := u.config.JWTVerificationConfig.JWTVerify(ctx, user.Token, userUpdateRequiredScope)
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

func (u *userReaderWriter) SendVerificationAlternateEmail(ctx context.Context, alternateEmail string) error {

	errStartPasswordlessFlow := u.emailLinkingFlow.StartPasswordlessFlow(ctx, alternateEmail)
	if errStartPasswordlessFlow != nil {
		return errStartPasswordlessFlow
	}

	slog.DebugContext(ctx, "send verification alternate email successfully")

	return nil
}

func (u *userReaderWriter) VerifyAlternateEmail(ctx context.Context, email *model.Email) (*model.User, error) {

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

	user := &model.User{
		Token: tokenResp.IDToken,
	}

	slog.DebugContext(ctx, "alternate email verified successfully",
		"email", redaction.Redact(email.Email),
	)

	return user, nil
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

	emailLinkingFlow := NewEmailLinkingFlow(auth0Config.M2MTokenManager.authConfig)

	return &userReaderWriter{
		config:           auth0Config,
		emailLinkingFlow: emailLinkingFlow,
		httpClient:       httpClient,
		errorResponse:    NewErrorResponse(),
	}, nil
}
