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
	"unicode"
	"unicode/utf8"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

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
	// userSearchMaxTerms bounds the query length and the cost of the AND-ed
	// clauses. It counts only terms long enough to be searched.
	userSearchMaxTerms = 4
	// userSearchMaxRawFields bounds the words in the input before short ones
	// are dropped.
	userSearchMaxRawFields = 10
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
	// userSearchExactFetchSize is how many users the exact lookup asks for; one
	// LFID or email is unique, the margin only covers duplicate-looking data.
	userSearchExactFetchSize = 5

	// errUserSearchUnavailable is the only failure text returned for an
	// upstream problem, so nothing from Auth0 reaches the caller.
	errUserSearchUnavailable = "user search is unavailable"

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
		httpClient: newUserSearchHTTPClient(nil),
	}, nil
}

// newUserSearchHTTPClient builds the Management API client for user search.
// Its requests carry the search terms (names and email addresses of other
// people) in the URL, and client spans record the full URL, so they are kept
// out of traces entirely. base is the transport under the instrumentation
// (nil for the default); extra options exist for tests.
func newUserSearchHTTPClient(base http.RoundTripper, extra ...otelhttp.Option) *httpclient.Client {
	options := append([]otelhttp.Option{
		otelhttp.WithFilter(func(*http.Request) bool { return false }),
	}, extra...)
	return httpclient.NewClient(httpclient.Config{
		Timeout:     userSearchTimeout,
		Transport:   base,
		OTelOptions: options,
	})
}

// SearchUsers authorizes subjectToken as an impersonator, then returns users
// matching query. The query is never logged by this service: it is free text
// that can contain names and emails.
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
		// The wrapped error can carry the token endpoint's response body, so it
		// is logged here and never returned to the caller.
		slog.ErrorContext(ctx, "failed to get M2M token for user search", "error", err)
		return nil, errors.NewServiceUnavailable(errUserSearchUnavailable)
	}

	users, err := s.fetch(ctx, m2mToken, buildUserSearchQuery(terms), limit*userSearchFetchFactor)
	if err != nil {
		return nil, err
	}

	// Auth0 returns an unranked page, so a short exact LFID or email can be
	// missing from it when many accounts share the prefix. Look the exact value
	// up directly and merge it in before ranking. Best effort: the prefix page
	// is already a usable answer.
	if exactQuery, ok := buildExactUserSearchQuery(terms); ok {
		exact, errExact := s.fetch(ctx, m2mToken, exactQuery, userSearchExactFetchSize)
		if errExact != nil {
			slog.WarnContext(ctx, "exact user lookup failed, using prefix results only")
		} else {
			users = mergeAuth0Users(exact, users)
		}
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

// fetch runs one Management API user search. A failure is reported with a fixed
// message: the upstream body can echo the query.
func (s *userSearch) fetch(ctx context.Context, m2mToken, q string, perPage int) ([]Auth0User, error) {
	endpoint := fmt.Sprintf("https://%s/api/v2/users?q=%s&search_engine=v3&per_page=%d&fields=%s&include_fields=true",
		s.domain,
		url.QueryEscape(q),
		perPage,
		url.QueryEscape(userSearchFields),
	)

	var users []Auth0User
	// The HTTP client already logs the failure (status only, no query).
	if _, err := httpclient.NewAPIRequest(
		s.httpClient,
		httpclient.WithMethod(http.MethodGet),
		httpclient.WithURL(endpoint),
		httpclient.WithToken(m2mToken),
		httpclient.WithDescription("user search"),
	).Call(ctx, &users); err != nil {
		return nil, errors.NewServiceUnavailable(errUserSearchUnavailable)
	}
	return users, nil
}

// mergeAuth0Users returns first followed by the users of rest that are not
// already in it, keyed by user_id.
func mergeAuth0Users(first, rest []Auth0User) []Auth0User {
	seen := make(map[string]struct{}, len(first)+len(rest))
	merged := make([]Auth0User, 0, len(first)+len(rest))
	for _, group := range [][]Auth0User{first, rest} {
		for _, user := range group {
			if _, dup := seen[user.UserID]; dup {
				continue
			}
			seen[user.UserID] = struct{}{}
			merged = append(merged, user)
		}
	}
	return merged
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

// isUserSearchChar reports whether r may appear in a search term. This is an
// allowlist on purpose: Auth0 search is Lucene query_string syntax, which has
// operators that cannot be backslash-escaped (such as the < and > range
// operators), so anything not known to be safe is a separator, not escaped.
func isUserSearchChar(r rune) bool {
	if unicode.IsLetter(r) || unicode.IsDigit(r) {
		return true
	}
	switch r {
	case '.', '_', '-', '+', '\'', '@':
		return true
	}
	return false
}

// parseUserSearchTerms splits free-text input into lowercase search terms.
// Characters outside isUserSearchChar separate terms, so "smith, john" is two
// terms. Terms shorter than userSearchMinTermLength are dropped, since the user
// is typically still typing them; at least one longer term must remain.
func parseUserSearchTerms(input string) ([]string, error) {
	if utf8.RuneCountInString(input) > userSearchMaxQueryLength {
		return nil, errors.NewValidation("query is too long")
	}

	fields := strings.FieldsFunc(strings.ToLower(input), func(r rune) bool { return !isUserSearchChar(r) })
	if len(fields) > userSearchMaxRawFields {
		return nil, errors.NewValidation("query has too many words")
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
	// Only the terms that are searched count towards the cap, so short name
	// particles ("de", "la", "van der") never turn a full name into an error.
	if len(terms) > userSearchMaxTerms {
		return nil, errors.NewValidation(fmt.Sprintf("query has too many terms (maximum %d)", userSearchMaxTerms))
	}
	return terms, nil
}

// luceneSpecialChars are the characters Lucene query syntax treats as operators.
// They are escaped so user input can only ever be a literal prefix.
// Terms come from the isUserSearchChar allowlist, so only - and + can reach
// the escaper today; the full set is kept as defense in depth.
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
			"(name:%[1]s* OR given_name:%[1]s* OR family_name:%[1]s* OR username:%[1]s* OR identities.user_id:%[1]s* OR email:%[1]s*)",
			escaped,
		))
	}
	clauses = append(clauses, fmt.Sprintf("identities.connection:%q", constants.Auth0UsernamePasswordConnection))
	return strings.Join(clauses, " AND ")
}

// buildExactUserSearchQuery builds the lookup for a query that is a single
// term, which is how an admin types a known LFID or email. It reports false
// for several terms, where there is no single exact value to look up.
func buildExactUserSearchQuery(terms []string) (string, bool) {
	if len(terms) != 1 {
		return "", false
	}
	escaped := escapeLucene(terms[0])
	if strings.Contains(terms[0], "@") {
		return fmt.Sprintf("email:%s AND identities.connection:%q", escaped, constants.Auth0UsernamePasswordConnection), true
	}
	// An LFID can live in a linked database identity while the root username
	// belongs to another primary account, so both fields are searched. The
	// identity id is quoted: it is matched as an exact value, so a numeric-looking
	// LFID is not read as a number.
	return fmt.Sprintf(`(username:%[1]s OR identities.user_id:"%[1]s") AND identities.connection:%[2]q`,
		escaped, constants.Auth0UsernamePasswordConnection), true
}

// toUserSearchResults maps Auth0 users to search results, keeping only accounts
// that have an LFID: a Username-Password-Authentication identity, which is what
// impersonation resolves.
func toUserSearchResults(users []Auth0User) []model.UserSearchResult {
	results := make([]model.UserSearchResult, 0, len(users))
	for i := range users {
		user := &users[i]

		// The LFID is the user_id of the database identity. The root username is
		// never used: for a linked account whose primary is another connection it
		// can be that connection's username, which does not identify the LFID
		// account. A database identity with no usable user_id leaves the account out.
		username := ""
		for _, identity := range user.Identities {
			if identity.Connection != constants.Auth0UsernamePasswordConnection {
				continue
			}
			if id := databaseIdentityUsername(identity.UserID); id != "" {
				username = id
				break
			}
		}
		if username == "" {
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

// databaseIdentityUsername returns the LFID held in a database identity's
// user_id, or "" when it is missing, blank, or neither a string nor a number.
func databaseIdentityUsername(userID any) string {
	switch userID.(type) {
	case string, float64:
		return strings.TrimSpace(identityIDString(userID))
	}
	return ""
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
