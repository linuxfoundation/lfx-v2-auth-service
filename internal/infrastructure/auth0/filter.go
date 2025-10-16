// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

const (
	usernamePasswordAuthenticationFilter = "Username-Password-Authentication"
	emailAuthenticationFilter            = "email"
)

var (
	// criteriaEndpointMapping is a map of criteria types and their corresponding API endpoints
	criteriaEndpointMapping = map[string]string{
		constants.CriteriaTypeEmail:          "users-by-email?email=%s",
		constants.CriteriaTypeUsername:       `users?q=identities.user_id:%s&search_engine=v3`,
		constants.CriteriaTypeAlternateEmail: `users?q=identities.profileData.email:%s&search_engine=v3`,
	}
)

type userFilterer interface {
	Endpoint(ctx context.Context) string
	Args(ctx context.Context) []any
	Filter(ctx context.Context, auth0User *Auth0User) (bool, error)
}

type usernameFilter struct {
	user *model.User
}

func (u *usernameFilter) Endpoint(ctx context.Context) string {
	return criteriaEndpointMapping[constants.CriteriaTypeUsername]
}

func (u *usernameFilter) Args(ctx context.Context) []any {
	return []any{url.QueryEscape(u.user.Username)}
}

func (u *usernameFilter) Filter(ctx context.Context, auth0User *Auth0User) (bool, error) {
	for _, identity := range auth0User.Identities {
		if identity.Connection == usernamePasswordAuthenticationFilter {
			// if the search is by username, we need to check if the identity is the one we are looking for
			//
			// At this point, we know that the user is found, but the validation is to
			// make sure the username is from the Username-Password-Authentication connection
			userID, ok := identity.UserID.(string)
			if !ok {
				slog.DebugContext(ctx, "user found, but it's not the correct identity",
					"filter", usernamePasswordAuthenticationFilter,
					"user_id", redaction.Redact(fmt.Sprintf("%v", identity.UserID)),
				)
				return false, nil
			}

			if userID != u.user.Username {
				slog.DebugContext(ctx, "user found, but it's not the correct identity",
					"filter", usernamePasswordAuthenticationFilter,
					"user_id", redaction.Redact(userID),
				)
				// if the connection is Password-Authentication and the user is not the one we are looking for,
				// we need to return an error
				return false, errors.NewNotFound("user not found")
			}
			u.user.Username = userID
			return true, nil
		}
	}
	return false, nil
}

type emailFilter struct {
	user *model.User
}

func (e *emailFilter) Endpoint(ctx context.Context) string {
	return criteriaEndpointMapping[constants.CriteriaTypeEmail]
}

func (e *emailFilter) Args(ctx context.Context) []any {
	return []any{url.QueryEscape(e.user.PrimaryEmail)}
}

func (e *emailFilter) Filter(ctx context.Context, auth0User *Auth0User) (bool, error) {
	for _, identity := range auth0User.Identities {
		if identity.Connection == usernamePasswordAuthenticationFilter {
			// At this point, we know that the user is found, but the validation is to
			// make sure the username is from the Username-Password-Authentication connection
			userID, ok := identity.UserID.(string)
			if !ok {
				slog.DebugContext(ctx, "user found, but it's not the correct identity",
					"filter", usernamePasswordAuthenticationFilter,
					"user_id", redaction.Redact(fmt.Sprintf("%v", identity.UserID)),
				)
				return false, nil
			}
			e.user.PrimaryEmail = userID
			return true, nil
		}
	}
	return false, nil
}

type alternateEmailFilter struct {
	user *model.User
}

func (a *alternateEmailFilter) Endpoint(ctx context.Context) string {
	return criteriaEndpointMapping[constants.CriteriaTypeAlternateEmail]
}

func (a *alternateEmailFilter) Args(ctx context.Context) []any {
	if len(a.user.AlternateEmail) == 0 {
		return []any{}
	}
	return []any{url.QueryEscape(a.user.AlternateEmail[0].Email)}
}

func (a *alternateEmailFilter) Filter(ctx context.Context, auth0User *Auth0User) (bool, error) {
	for _, identity := range auth0User.Identities {
		if identity.Connection == emailAuthenticationFilter {
			for _, alternateEmail := range a.user.AlternateEmail {
				if identity.ProfileData != nil &&
					strings.EqualFold(alternateEmail.Email, identity.ProfileData.Email) {
					slog.DebugContext(ctx, "user found, and it's the correct identity",
						"filter", emailAuthenticationFilter,
						"identity_email", redaction.RedactEmail(identity.ProfileData.Email),
						"identity_email_verified", identity.ProfileData.EmailVerified,
					)
					auth0User.AlternateEmail = append(auth0User.AlternateEmail, Auth0ProfileData{
						Email:         identity.ProfileData.Email,
						EmailVerified: identity.ProfileData.EmailVerified,
					})
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// newUserFilterer creates a new user filterer based on the criteria type
// each filter might have a different way to filter the user, so we need to return the arguments and the filter function
func newUserFilterer(criteriaType string, user *model.User) userFilterer {

	switch criteriaType {

	case constants.CriteriaTypeEmail:
		return &emailFilter{user: user}
	case constants.CriteriaTypeUsername:
		return &usernameFilter{user: user}
	case constants.CriteriaTypeAlternateEmail:
		return &alternateEmailFilter{user: user}
	}
	return nil
}
