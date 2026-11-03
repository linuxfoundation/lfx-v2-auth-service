// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

const (
	// userSearchMinTermLength is the shortest term worth sending to Auth0. Shorter
	// prefixes match too much of the tenant and are slow against its ~2s query limit.
	userSearchMinTermLength = 3
	// userSearchMaxTerms bounds the query length and the cost of the AND-ed clauses.
	userSearchMaxTerms = 4
	// userSearchMaxQueryLength bounds the raw input before it is tokenized.
	userSearchMaxQueryLength = 200
	// userSearchDefaultLimit and userSearchMaxLimit bound the number of results
	// returned to the caller.
	userSearchDefaultLimit = 10
	userSearchMaxLimit     = 20
	// userSearchFetchFactor over-fetches from Auth0 because results without an
	// LFID are dropped afterwards, so a page of `limit` could otherwise come back short.
	userSearchFetchFactor = 2
	// userSearchTimeout bounds one Management API search call.
	userSearchTimeout = 10 * time.Second

	// userSearchFields limits the Auth0 response to what the filter and the
	// picker read.
	userSearchFields = "user_id,username,name,given_name,family_name,email,email_verified,identities"
)

// subjectAuthorizer verifies an impersonator's subject token and returns its subject.
type subjectAuthorizer interface {
	authorizeSubject(ctx context.Context, subjectToken string) (string, error)
}

// managementTokenSource supplies Auth0 Management API access tokens.
type managementTokenSource interface {
	GetToken(ctx context.Context) (string, error)
}

// userSearch searches Auth0 users for callers allowed to impersonate (see authorizeSubject).
type userSearch struct {
	domain     string
	authorizer subjectAuthorizer
	tokens     managementTokenSource
	httpClient *httpclient.Client
}

// NewUserSearcher creates a user searcher that authorizes callers
// with the given impersonation flow and queries the Auth0 Management API using
// the service's M2M client.
func NewUserSearcher(ctx context.Context, domain string, flow port.Impersonator) (port.UserSearcher, error) {
	authorizer, ok := flow.(subjectAuthorizer)
	if !ok {
		return nil, errors.NewUnexpected("impersonation flow cannot authorize user search")
	}

	tokens, err := NewM2MTokenManager(ctx, Config{Domain: domain})
	if err != nil {
		return nil, fmt.Errorf("failed to create M2M token manager for user search: %w", err)
	}

	return &userSearch{
		domain:     domain,
		authorizer: authorizer,
		tokens:     tokens,
		httpClient: httpclient.NewClient(httpclient.Config{Timeout: userSearchTimeout}),
	}, nil
}

// SearchUsers authorizes subjectToken as an impersonator, then returns users
// matching query. The query is never logged: it is free text that can contain
// names and emails.
func (s *userSearch) SearchUsers(ctx context.Context, subjectToken, query string, limit int) ([]model.UserSearchResult, error) {
	// Authorize before anything else so an unauthorized caller learns nothing,
	// not even whether its query was well-formed.
	sub, err := s.authorizer.authorizeSubject(ctx, subjectToken)
	if err != nil {
		return nil, err
	}

	terms, err := parseUserSearchTerms(query)
	if err != nil {
		return nil, err
	}
	limit = clampUserSearchLimit(limit)

	m2mToken, err := s.tokens.GetToken(ctx)
	if err != nil {
		return nil, errors.NewUnexpected("failed to get M2M token", err)
	}

	endpoint := fmt.Sprintf("https://%s/api/v2/users?q=%s&search_engine=v3&per_page=%d&fields=%s&include_fields=true",
		s.domain,
		url.QueryEscape(buildUserSearchQuery(terms)),
		limit*userSearchFetchFactor,
		url.QueryEscape(userSearchFields),
	)

	var users []Auth0User
	statusCode, err := httpclient.NewAPIRequest(
		s.httpClient,
		httpclient.WithMethod(http.MethodGet),
		httpclient.WithURL(endpoint),
		httpclient.WithToken(m2mToken),
		httpclient.WithDescription("user search"),
	).Call(ctx, &users)
	if err != nil {
		// Do not forward the upstream message: it can echo the query.
		slog.ErrorContext(ctx, "user search failed",
			"error", err,
			"status_code", statusCode,
		)
		return nil, errors.NewServiceUnavailable("user search is unavailable")
	}

	results := rankUserSearchResults(toUserSearchResults(users), terms)
	if len(results) > limit {
		results = results[:limit]
	}

	slog.InfoContext(ctx, "user search",
		"caller", redaction.Redact(sub),
		"terms", len(terms),
		"results", len(results),
	)
	return results, nil
}

// clampUserSearchLimit applies the default and the maximum result count.
func clampUserSearchLimit(limit int) int {
	switch {
	case limit <= 0:
		return userSearchDefaultLimit
	case limit > userSearchMaxLimit:
		return userSearchMaxLimit
	}
	return limit
}

// parseUserSearchTerms splits free-text input into lowercase search terms.
// Terms shorter than userSearchMinTermLength are dropped, since the user is
// typically still typing them; at least one longer term must remain.
func parseUserSearchTerms(input string) ([]string, error) {
	if utf8.RuneCountInString(input) > userSearchMaxQueryLength {
		return nil, errors.NewValidation("query is too long")
	}

	fields := strings.Fields(strings.ToLower(input))
	if len(fields) > userSearchMaxTerms {
		return nil, errors.NewValidation(fmt.Sprintf("query has too many terms (maximum %d)", userSearchMaxTerms))
	}

	terms := make([]string, 0, len(fields))
	for _, field := range fields {
		if utf8.RuneCountInString(field) >= userSearchMinTermLength {
			terms = append(terms, field)
		}
	}
	if len(terms) == 0 {
		return nil, errors.NewValidation(fmt.Sprintf("query needs at least one term of %d or more characters", userSearchMinTermLength))
	}
	return terms, nil
}

// luceneSpecialChars are the characters Lucene query syntax treats as operators.
// They are escaped so user input can only ever be a literal prefix.
// Whitespace never reaches here because terms come from strings.Fields.
const luceneSpecialChars = `+-&|!(){}[]^"~*?:\/`

// escapeLucene backslash-escapes every Lucene operator character in term.
func escapeLucene(term string) string {
	var b strings.Builder
	for _, r := range term {
		if strings.ContainsRune(luceneSpecialChars, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// buildUserSearchQuery builds an Auth0 v3 search query from validated terms.
// Every term is a prefix match (suffix wildcard) and the terms are AND-ed, so
// "john smith" and "smith john" both find John Smith. A term containing "@" can
// only be an email, so it only searches that field.
//
// The Username-Password-Authentication connection is part of the query so that
// the result page is not filled with accounts that have no LFID. It cannot
// replace the per-result check (see toUserSearchResults): Auth0 matches
// identities.* fields independently, not as one identity.
func buildUserSearchQuery(terms []string) string {
	clauses := make([]string, 0, len(terms)+1)
	for _, term := range terms {
		escaped := escapeLucene(term)
		if strings.Contains(term, "@") {
			clauses = append(clauses, "email:"+escaped+"*")
			continue
		}
		clauses = append(clauses, fmt.Sprintf(
			"(name:%[1]s* OR given_name:%[1]s* OR family_name:%[1]s* OR username:%[1]s* OR email:%[1]s*)",
			escaped,
		))
	}
	clauses = append(clauses, fmt.Sprintf("identities.connection:%q", constants.Auth0UsernamePasswordConnection))
	return strings.Join(clauses, " AND ")
}

// toUserSearchResults maps Auth0 users to search results, keeping only accounts
// that have an LFID: a Username-Password-Authentication identity, which is what
// impersonation resolves.
func toUserSearchResults(users []Auth0User) []model.UserSearchResult {
	results := make([]model.UserSearchResult, 0, len(users))
	for i := range users {
		user := &users[i]

		username := user.Username
		hasLFID := false
		for _, identity := range user.Identities {
			if identity.Connection != constants.Auth0UsernamePasswordConnection {
				continue
			}
			hasLFID = true
			if id, ok := identity.UserID.(string); ok && username == "" {
				username = id
			}
		}
		if !hasLFID || username == "" {
			continue
		}

		result := model.UserSearchResult{
			UserID:   user.UserID,
			Username: username,
			Name:     displayName(user),
		}
		// A root email can be set by anyone at signup, so only a verified one is shown.
		if user.EmailVerified {
			result.Email = user.Email
		}
		results = append(results, result)
	}
	return results
}

// displayName returns the user's name, falling back to given and family name.
func displayName(user *Auth0User) string {
	if name := strings.TrimSpace(user.Name); name != "" {
		return name
	}
	return strings.TrimSpace(user.GivenName + " " + user.FamilyName)
}

// rankUserSearchResults orders results best match first, since Auth0 does not
// rank: an exact username or email, then a username prefix, then an email
// prefix, then everything else, with ties broken by username for stable output.
func rankUserSearchResults(results []model.UserSearchResult, terms []string) []model.UserSearchResult {
	rank := func(r model.UserSearchResult) int {
		best := 4
		username := strings.ToLower(r.Username)
		email := strings.ToLower(r.Email)
		for _, term := range terms {
			var score int
			switch {
			case username == term:
				score = 0
			case email != "" && email == term:
				score = 1
			case strings.HasPrefix(username, term):
				score = 2
			case email != "" && strings.HasPrefix(email, term):
				score = 3
			default:
				score = 4
			}
			if score < best {
				best = score
			}
		}
		return best
	}

	sort.SliceStable(results, func(i, j int) bool {
		ri, rj := rank(results[i]), rank(results[j])
		if ri != rj {
			return ri < rj
		}
		return results[i].Username < results[j].Username
	})
	return results
}
