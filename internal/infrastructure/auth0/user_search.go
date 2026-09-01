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
)

// SortUpdatedAtAscending orders a user search oldest-change-first.
//
// The out-of-band jobs walk forward through time, so ascending order is what
// makes the last row of a page a usable lower bound for the next one.
const SortUpdatedAtAscending = "updated_at:1"

// DefaultSearchPageSize is the page size the out-of-band jobs request.
const DefaultSearchPageSize = 20

// cohortSearchFields limits the search response to what the jobs read.
//
// `identities` is included so an LFID username can be taken from the database
// connection rather than from the top-level field, which on a social-only user
// is not an LFID.
const cohortSearchFields = "user_id,username,email,email_verified,updated_at,identities,app_metadata"

// userSearcher runs Auth0 Management user searches.
type userSearcher struct {
	httpClient *httpclient.Client
	config     Config
}

// NewUserSearcher creates the Auth0 Management user search used to select the
// out-of-band CDP job populations.
func NewUserSearcher(httpConfig httpclient.Config, auth0Config Config) (port.UserSearcher, error) {
	if strings.TrimSpace(auth0Config.Domain) == "" {
		return nil, errors.NewValidation("auth0 domain is required")
	}
	if auth0Config.M2MTokenManager == nil {
		return nil, errors.NewValidation("auth0 M2M token manager is required")
	}
	return &userSearcher{
		httpClient: httpclient.NewClient(httpConfig),
		config:     auth0Config,
	}, nil
}

// SearchUsers returns one page of users matching the query.
//
// The query is sent verbatim. Callers own its content — for the population
// sweep it is a marked copy of a canonical string held in a decision record,
// so rewriting it here would put the two out of step silently.
func (s *userSearcher) SearchUsers(ctx context.Context, search port.UserSearch) ([]port.CohortUser, error) {
	if strings.TrimSpace(search.Query) == "" {
		return nil, errors.NewValidation("a search query is required")
	}
	if search.PerPage <= 0 {
		search.PerPage = DefaultSearchPageSize
	}
	if search.Page < 0 {
		return nil, errors.NewValidation("page must not be negative")
	}

	token, err := s.config.M2MTokenManager.GetToken(ctx)
	if err != nil {
		return nil, errors.NewUnexpected("failed to get M2M token to search users", err)
	}

	// include_totals is deliberately off: it wraps the response in an object,
	// and the count it adds is the one Auth0 caps at 1000 anyway.
	endpoint := fmt.Sprintf(
		"https://%s/api/v2/users?q=%s&search_engine=v3&sort=%s&page=%d&per_page=%d&include_totals=false&fields=%s&include_fields=true",
		s.config.Domain,
		url.QueryEscape(search.Query),
		url.QueryEscape(SortUpdatedAtAscending),
		search.Page,
		search.PerPage,
		url.QueryEscape(cohortSearchFields),
	)

	request := httpclient.NewAPIRequest(
		s.httpClient,
		httpclient.WithMethod(http.MethodGet),
		httpclient.WithURL(endpoint),
		httpclient.WithToken(token),
		httpclient.WithDescription("search users for CDP out-of-band job"),
	)

	var users []Auth0User
	statusCode, errCall := request.Call(ctx, &users)
	if errCall != nil {
		if statusCode == http.StatusTooManyRequests {
			return nil, managementRateLimited(ctx, "user search", errCall)
		}
		slog.ErrorContext(ctx, "failed to search users for CDP out-of-band job",
			"error", errCall,
			"status_code", statusCode,
			"page", search.Page,
			"per_page", search.PerPage,
		)
		return nil, errors.NewUnexpected("failed to search users", errCall)
	}

	cohort := make([]port.CohortUser, 0, len(users))
	for i := range users {
		cohort = append(cohort, toCohortUser(ctx, users[i]))
	}
	return cohort, nil
}

// toCohortUser maps an Auth0 search row onto the job-facing view.
//
// An unparseable `updated_at` yields a zero time rather than an error: the
// caller treats that as "cannot advance the cursor past this row", which stops
// a run rather than skipping a person.
func toCohortUser(ctx context.Context, user Auth0User) port.CohortUser {
	cohortUser := port.CohortUser{
		UserID:        user.UserID,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
	}

	if trimmed := strings.TrimSpace(user.UpdatedAt); trimmed != "" {
		parsed, err := time.Parse(time.RFC3339, trimmed)
		if err != nil {
			slog.WarnContext(ctx, "Auth0 user has an unparseable updated_at",
				"error", err,
			)
		} else {
			cohortUser.UpdatedAt = parsed.UTC()
		}
	}

	// Only a database-connection identity carries an LFID. Taking the
	// top-level username unconditionally would hand `resolve` a social
	// provider's nickname and cache the resulting miss as a no-match.
	for _, identity := range user.Identities {
		if identity.Connection == constants.DatabaseConnection {
			cohortUser.Username = strings.TrimSpace(user.Username)
			break
		}
	}

	if user.AppMetadata != nil {
		cohortUser.UUID = user.AppMetadata.CDPUUID
		cohortUser.Source = user.AppMetadata.CDPUUIDSource
		cohortUser.CheckedAt = user.AppMetadata.CDPUUIDCheckedAt
	}

	return cohortUser
}
