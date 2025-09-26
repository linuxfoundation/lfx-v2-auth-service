// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"

	"github.com/golang-jwt/jwt/v5"
)

const (
	userMetadataRequiredScope = "update:current_user_metadata"

	usernameFilter = "Username-Password-Authentication"
)

var (
	// criteriaEndpointMapping is a map of criteria types and their corresponding API endpoints
	criteriaEndpointMapping = map[string]string{
		constants.CriteriaTypeEmail:    "users-by-email?email=%s",
		constants.CriteriaTypeUsername: `users?q=identities.user_id:%s&search_engine=v3`,
	}
)

// Config holds the configuration for Auth0 Management API
type Config struct {
	Tenant string
	Domain string
	// M2MTokenManager for machine-to-machine authentication
	M2MTokenManager *TokenManager
}

// userUpdateRequest represents the request body for updating a user in Auth0
type userUpdateRequest struct {
	UserMetadata *model.UserMetadata `json:"user_metadata,omitempty"`
}

type userReaderWriter struct {
	config     Config
	httpClient *httpclient.Client
}

func (u *userReaderWriter) jwtVerify(ctx context.Context, user *model.User) error {
	if strings.TrimSpace(user.Token) == "" {
		return fmt.Errorf("token is required")
	}

	// Remove optional Bearer prefix (case-insensitive) and trim
	tokenString := strings.TrimSpace(user.Token)
	parts := strings.Fields(user.Token)
	if len(parts) > 1 && strings.EqualFold(parts[0], "Bearer") {
		tokenString = strings.Join(parts[1:], " ")
	}

	// Parse the token without verification for now (we'll add JWKS verification later if needed)
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return errors.NewValidation("failed to parse JWT token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return errors.NewValidation("invalid token claims")
	}

	// 1. Extract user_id from 'sub' claim
	sub, ok := claims["sub"].(string)
	if !ok || strings.TrimSpace(sub) == "" {
		return errors.NewValidation("missing or invalid 'sub' claim in token")
	}

	// Assign the user_id from sub claim
	user.UserID = sub

	slog.DebugContext(ctx, "extracted user_id from token", "user_id", user.UserID)

	// 2. Check if token is expired
	exp, okExp := claims["exp"]
	if !okExp {
		return errors.NewValidation("missing 'exp' claim in token")
	}
	var expTime time.Time
	switch expValue := exp.(type) {
	case float64:
		expTime = time.Unix(int64(expValue), 0)
	case int64:
		expTime = time.Unix(expValue, 0)
	case int:
		expTime = time.Unix(int64(expValue), 0)
	default:
		return errors.NewValidation("invalid 'exp' claim format")
	}
	if time.Now().After(expTime) {
		return errors.NewValidation(fmt.Sprintf("token has expired at %v", expTime))
	}
	slog.DebugContext(ctx, "token expiration validated", "expires_at", expTime)

	// 3. Check if scope contains 'update:current_user_metadata'
	scopeClaim, okScopeClaim := claims["scope"]
	if !okScopeClaim {
		return errors.NewValidation("missing 'scope' claim in token")
	}
	scopeString, ok := scopeClaim.(string)
	if !ok {
		return errors.NewValidation("invalid 'scope' claim format")
	}

	scopes := strings.Fields(scopeString) // Split by whitespace
	hasRequiredScope := slices.Contains(scopes, userMetadataRequiredScope)
	if !hasRequiredScope {
		return errors.NewValidation(fmt.Sprintf("wrong scope, got %s", scopeString))
	}

	slog.DebugContext(ctx, "JWT validation successful", "user_id", user.UserID)
	return nil
}

func (u *userReaderWriter) SearchUser(ctx context.Context, user *model.User, criteria string) (*model.User, error) {

	endpoint, ok := criteriaEndpointMapping[criteria]
	if !ok {
		return nil, errors.NewValidation(fmt.Sprintf("invalid criteria type: %s", criteria))
	}

	param := func(criteriaType string) []any {
		switch criteriaType {
		case constants.CriteriaTypeEmail:
			slog.DebugContext(ctx, "searching user",
				"criteria", criteria,
				"email", redaction.RedactEmail(user.PrimaryEmail),
			)
			return []any{url.QueryEscape(strings.ToLower(strings.TrimSpace(user.PrimaryEmail)))}
		case constants.CriteriaTypeUsername:
			slog.DebugContext(ctx, "searching user",
				"criteria", criteria,
				"username", redaction.Redact(user.Username),
			)
			return []any{url.QueryEscape(strings.TrimSpace(user.Username))}
		}
		return []any{}
	}

	if user.Token == "" {
		m2mToken, errGetToken := u.config.M2MTokenManager.GetToken(ctx)
		if errGetToken != nil {
			return nil, errors.NewUnexpected("failed to get M2M token", errGetToken)
		}
		user.Token = m2mToken
	}

	endpointWithParam := fmt.Sprintf(endpoint, param(criteria)...)
	url := fmt.Sprintf("https://%s/api/v2/%s", u.config.Domain, endpointWithParam)

	apiRequest := httpclient.NewAPIRequest(
		u.httpClient,
		httpclient.WithMethod(http.MethodGet),
		httpclient.WithURL(url),
		httpclient.WithToken(user.Token),
		httpclient.WithDescription("search user"),
	)

	var users []model.Auth0User

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
		// identities.user_id:{{username}} AND identities.connection:Username-Password-Authentication
		// It doesn't work like an AND, it works like an IN clause
		// (check if it contains the username and the connection, but they might not be in  the same identity)
		// So it's necessary to check if the identity is the one we are looking for
		for _, identity := range userResult.Identities {
			if identity.Connection == usernameFilter {
				// if the search is by username, we need to check if the identity is the one we are looking for
				//
				// At this point, we know that the user is found, but the validation is to
				// make sure the username is from the Username-Password-Authentication connection
				if criteria == constants.CriteriaTypeUsername && identity.UserID != user.Username {
					slog.DebugContext(ctx, "user found, but it's not the correct identity",
						"filter", usernameFilter,
						"user_id", redaction.Redact(identity.UserID),
					)
					// if the connection is Password-Authentication and the user is not the one we are looking for,
					// we need to return an error
					return nil, errors.NewNotFound("user not found")
				}
				user.Username = identity.UserID
				return userResult.ToUser(), nil
			}
		}
	}

	return nil, errors.NewNotFound("user not found")

}

func (u *userReaderWriter) GetUser(ctx context.Context, user *model.User) (*model.User, error) {

	slog.DebugContext(ctx, "getting user", "user_id", user.UserID)

	if user.Token == "" {
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
	var auth0User *model.Auth0User
	statusCode, errCall := apiRequest.Call(ctx, &auth0User)
	if errCall != nil {
		slog.ErrorContext(ctx, "failed to get user from Auth0",
			"error", errCall,
			"status_code", statusCode,
			"user_id", user.UserID,
		)
		if statusCode == http.StatusNotFound {
			return nil, errors.NewNotFound("user not found")
		}
		return nil, errors.NewUnexpected("failed to get user from Auth0", errCall)
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

func (u *userReaderWriter) UpdateUser(ctx context.Context, user *model.User) (*model.User, error) {

	if err := u.jwtVerify(ctx, user); err != nil {
		slog.ErrorContext(ctx, "jwt verify failed", "error", err)
		return nil, err
	}

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

// NewUserReaderWriter  creates a new UserReaderWriter with the provided configuration
func NewUserReaderWriter(ctx context.Context, httpConfig httpclient.Config, auth0Config Config) (port.UserReaderWriter, error) {

	// Add M2M token manager to config
	m2mTokenManager, err := NewM2MTokenManager(ctx, auth0Config)
	if err != nil {
		return nil, fmt.Errorf("failed to create M2M token manager: %w", err)
	}

	auth0Config.M2MTokenManager = m2mTokenManager

	return &userReaderWriter{
		config:     auth0Config,
		httpClient: httpclient.NewClient(httpConfig),
	}, nil
}
