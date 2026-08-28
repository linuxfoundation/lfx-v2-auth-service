// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package cdp is the client for the CDP (crowd.dev) v1 transactional API.
//
// Four operations are consumed: resolve an identity to a member, list a
// member's identities, create a member, and attach an identity to an existing
// member. The API is shared with
// other services under a global rate limit, so callers are expected to pass a
// bounded context and to treat a 429 as a reason to back off rather than to
// retry immediately.
package cdp

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

// TokenProvider supplies a bearer token for the CDP audience.
type TokenProvider interface {
	GetToken(ctx context.Context) (string, error)
}

// Config holds the CDP client configuration.
type Config struct {
	// BaseURL is the root of the CDP public API, without a trailing slash.
	BaseURL string

	// TokenManager mints M2M tokens for the CDP audience. This is a different
	// audience from the Auth0 Management API, so it is a separate manager.
	TokenManager TokenProvider

	// Timeout bounds a single CDP call. Callers on a latency budget should
	// also pass a context deadline; whichever is shorter wins.
	Timeout time.Duration

	// Transport is a test seam. Nil uses the default transport.
	Transport http.RoundTripper
}

// defaultTimeout bounds a CDP call when the caller sets none.
const defaultTimeout = 10 * time.Second

// client is the CDP v1 API client.
type client struct {
	httpClient *httpclient.Client
	config     Config
}

// Client is the behavior the provisioning flow and the out-of-band jobs
// consume.
type Client interface {
	Resolve(ctx context.Context, lfid string, verifiedEmail string) (ResolveResult, error)
	ListIdentities(ctx context.Context, memberID string) ([]MemberIdentity, error)
	CreateMember(ctx context.Context, displayName string, identity Identity) (CreateResult, error)
	AttachIdentity(ctx context.Context, memberID string, identity Identity) (AttachResult, error)
}

// NewClient creates a CDP v1 API client.
func NewClient(config Config) Client {
	if config.Timeout == 0 {
		config.Timeout = defaultTimeout
	}
	return &client{
		httpClient: httpclient.NewClient(httpclient.Config{
			Timeout:   config.Timeout,
			Transport: config.Transport,
			// A 429 here means the shared budget is exhausted. Retrying inside
			// the client would spend a second slice of a budget somebody else
			// is waiting on, so backing off is left to the caller.
			MaxRetries: 0,
		}),
		config: config,
	}
}

// sanitize strips a provider response body out of an error before it is logged
// or wrapped.
//
// The shared client puts the raw body in RetryableError.Message, and CDP error
// bodies echo the identity back — the create-409 body is {platform, value,
// type}. Carrying that into an error chain would print the LFID in plain text
// everywhere this flow otherwise redacts it. A transport failure has no body
// and is worth keeping intact.
func sanitize(statusCode int, err error) error {
	if statusCode <= 0 {
		return err
	}
	return fmt.Errorf("status code: %d", statusCode)
}

// Resolve maps an LFID username (optionally widened by a verified email) to a
// CDP member.
//
// The email only ever widens an already-valid LFID match, so an empty lfid is
// rejected here rather than sent: the provider would answer a validation error,
// and a caller that mistook that for a 404 would cache "this person has no CDP
// member" off its own bug.
func (c *client) Resolve(ctx context.Context, lfid string, verifiedEmail string) (ResolveResult, error) {
	if strings.TrimSpace(lfid) == "" {
		return ResolveResult{}, errors.NewValidation("lfid is required to resolve a CDP member")
	}
	if c.config.TokenManager == nil {
		return ResolveResult{}, errors.NewUnexpected("CDP token manager is not configured")
	}

	token, err := c.config.TokenManager.GetToken(ctx)
	if err != nil {
		return ResolveResult{}, errors.NewUnexpected("failed to get CDP M2M token", err)
	}

	payload := resolveRequest{LFIDs: []string{lfid}}
	if trimmed := strings.TrimSpace(verifiedEmail); trimmed != "" {
		payload.Emails = []string{trimmed}
	}

	request := httpclient.NewAPIRequest(
		c.httpClient,
		httpclient.WithMethod(http.MethodPost),
		httpclient.WithURL(c.config.BaseURL+"/v1/members/resolve"),
		httpclient.WithToken(token),
		httpclient.WithDescription("resolve CDP member"),
		// CDP error bodies echo the submitted identity back.
		httpclient.WithSensitiveResponse(),
		httpclient.WithBody(payload),
		// The body carries the LFID and a verified email, and the client logs
		// request bodies verbatim at debug level.
		httpclient.WithSensitiveBody(),
	)

	var response resolveResponse
	statusCode, errCall := request.Call(ctx, &response)
	if errCall != nil {
		switch statusCode {
		case http.StatusNotFound:
			return ResolveResult{Outcome: OutcomeNoMatch}, nil
		case http.StatusConflict:
			slog.WarnContext(ctx, "CDP resolve matched multiple members",
				"lfid", redaction.Redact(lfid),
			)
			return ResolveResult{Outcome: OutcomeConflict}, nil
		}
		slog.ErrorContext(ctx, "CDP resolve failed",
			"status_code", statusCode,
			"lfid", redaction.Redact(lfid),
		)
		return ResolveResult{}, errors.NewUnexpected("CDP resolve failed", sanitize(statusCode, errCall))
	}

	if strings.TrimSpace(response.MemberID) == "" {
		return ResolveResult{}, errors.NewUnexpected("CDP resolve returned an empty member id")
	}

	return ResolveResult{Outcome: OutcomeFound, MemberID: response.MemberID}, nil
}

// ListIdentities returns the identities a CDP member already holds.
//
// Read-only, and used to decide whether attaching to a member is safe. A
// successful call is also the caller's proof that the member exists: a 404
// means it disappeared between the resolve and this read, and is reported as
// ErrMemberNotFound rather than as an empty list.
//
// Reading it as empty was wrong in a way that could not be undone. A caller
// checking "does this member hold somebody else's LFID" gets false from an
// empty list either way, so a vanished member looked exactly like a free one —
// and on the create-conflict path that answer is returned as the member id,
// written to Auth0 as a write-once cdp_uuid and later emitted as the Segment
// user_id. A dead id recorded there is permanent.
func (c *client) ListIdentities(ctx context.Context, memberID string) ([]MemberIdentity, error) {
	if strings.TrimSpace(memberID) == "" {
		return nil, errors.NewValidation("member id is required to list identities")
	}
	if c.config.TokenManager == nil {
		return nil, errors.NewUnexpected("CDP token manager is not configured")
	}

	token, err := c.config.TokenManager.GetToken(ctx)
	if err != nil {
		return nil, errors.NewUnexpected("failed to get CDP M2M token", err)
	}

	request := httpclient.NewAPIRequest(
		c.httpClient,
		httpclient.WithMethod(http.MethodGet),
		httpclient.WithURL(c.config.BaseURL+"/v1/members/"+url.PathEscape(memberID)+"/identities"),
		httpclient.WithToken(token),
		httpclient.WithDescription("list CDP member identities"),
		// CDP error bodies echo the submitted identity back.
		httpclient.WithSensitiveResponse(),
	)

	var response memberIdentitiesResponse
	statusCode, errCall := request.Call(ctx, &response)
	if errCall != nil {
		if statusCode == http.StatusNotFound {
			slog.WarnContext(ctx, "CDP member disappeared between resolve and identity read",
				"member_id", redaction.Redact(memberID),
			)
			return nil, ErrMemberNotFound
		}
		slog.ErrorContext(ctx, "CDP member identities list failed",
			"status_code", statusCode,
			"member_id", redaction.Redact(memberID),
		)
		return nil, errors.NewUnexpected("CDP member identities list failed", sanitize(statusCode, errCall))
	}

	return response.Identities, nil
}

// CreateMember creates a CDP member seeded with the given identity.
//
// A 409 means the identity already belongs to a member, but the response body
// does not say which one, so the caller must re-resolve. That is only possible
// when the caller holds an LFID username; otherwise the conflict is terminal.
func (c *client) CreateMember(ctx context.Context, displayName string, identity Identity) (CreateResult, error) {
	if strings.TrimSpace(identity.Value) == "" {
		return CreateResult{}, errors.NewValidation("identity value is required to create a CDP member")
	}
	if c.config.TokenManager == nil {
		return CreateResult{}, errors.NewUnexpected("CDP token manager is not configured")
	}

	token, err := c.config.TokenManager.GetToken(ctx)
	if err != nil {
		return CreateResult{}, errors.NewUnexpected("failed to get CDP M2M token", err)
	}

	request := httpclient.NewAPIRequest(
		c.httpClient,
		httpclient.WithMethod(http.MethodPost),
		httpclient.WithURL(c.config.BaseURL+"/v1/members"),
		httpclient.WithToken(token),
		httpclient.WithDescription("create CDP member"),
		// CDP error bodies echo the submitted identity back.
		httpclient.WithSensitiveResponse(),
		httpclient.WithBody(createMemberRequest{
			DisplayName: displayName,
			Identities:  []Identity{identity},
		}),
		// Carries the display name and the LFID.
		httpclient.WithSensitiveBody(),
	)

	var response createMemberResponse
	statusCode, errCall := request.Call(ctx, &response)
	if errCall != nil {
		if statusCode == http.StatusConflict {
			slog.InfoContext(ctx, "CDP member already exists for identity",
				"identity_value", redaction.Redact(identity.Value),
			)
			return CreateResult{Outcome: OutcomeConflict}, nil
		}
		slog.ErrorContext(ctx, "CDP member create failed",
			"status_code", statusCode,
			"identity_value", redaction.Redact(identity.Value),
		)
		return CreateResult{}, errors.NewUnexpected("CDP member create failed", sanitize(statusCode, errCall))
	}

	if strings.TrimSpace(response.MemberID) == "" {
		return CreateResult{}, errors.NewUnexpected("CDP member create returned an empty member id")
	}

	return CreateResult{Outcome: OutcomeFound, MemberID: response.MemberID}, nil
}

// AttachIdentity attaches an identity to an existing CDP member.
//
// Re-attaching the same identity to the same member is not a conflict: the
// provider finds the exact match and answers 200, which keeps the caller
// idempotent under at-least-once delivery. A 409 means the opposite — the
// identity is already verified on a *different* member — so it is reported as
// a conflict rather than swallowed, or the caller would store a member id whose
// LFID was never attached.
func (c *client) AttachIdentity(ctx context.Context, memberID string, identity Identity) (AttachResult, error) {
	if strings.TrimSpace(memberID) == "" {
		return AttachResult{}, errors.NewValidation("member id is required to attach an identity")
	}
	if strings.TrimSpace(identity.Value) == "" {
		return AttachResult{}, errors.NewValidation("identity value is required to attach an identity")
	}
	if c.config.TokenManager == nil {
		return AttachResult{}, errors.NewUnexpected("CDP token manager is not configured")
	}

	token, err := c.config.TokenManager.GetToken(ctx)
	if err != nil {
		return AttachResult{}, errors.NewUnexpected("failed to get CDP M2M token", err)
	}

	request := httpclient.NewAPIRequest(
		c.httpClient,
		httpclient.WithMethod(http.MethodPost),
		httpclient.WithURL(c.config.BaseURL+"/v1/members/"+url.PathEscape(memberID)+"/identities"),
		httpclient.WithToken(token),
		httpclient.WithDescription("attach CDP member identity"),
		// CDP error bodies echo the submitted identity back.
		httpclient.WithSensitiveResponse(),
		httpclient.WithBody(identity),
		// Carries the LFID.
		httpclient.WithSensitiveBody(),
	)

	statusCode, errCall := request.Call(ctx, nil)
	if errCall != nil {
		if statusCode == http.StatusConflict {
			conflictID := attachConflictMemberID(errCall)
			slog.WarnContext(ctx, "CDP identity belongs to another member",
				"member_id", redaction.Redact(memberID),
				"conflict_member_id", redaction.Redact(conflictID),
				"conflict_member_id_reported", conflictID != "",
			)
			return AttachResult{Outcome: OutcomeConflict, ConflictMemberID: conflictID}, nil
		}
		slog.ErrorContext(ctx, "CDP identity attach failed",
			"status_code", statusCode,
			"member_id", redaction.Redact(memberID),
		)
		return AttachResult{}, errors.NewUnexpected("CDP identity attach failed", sanitize(statusCode, errCall))
	}

	return AttachResult{Outcome: OutcomeFound}, nil
}

// attachConflictMemberID pulls the winning member out of an attach-409 body.
//
// The body is read off the error rather than the response because the shared
// client returns no response on a non-2xx. It is parsed, never logged: the same
// body echoes the submitted identity back, which is why the request is marked
// sensitive.
func attachConflictMemberID(err error) string {
	var retryable *httpclient.RetryableError
	if !stderrors.As(err, &retryable) || len(retryable.Body) == 0 {
		return ""
	}

	var body attachConflictResponse
	if jsonErr := json.Unmarshal(retryable.Body, &body); jsonErr != nil {
		return ""
	}
	return strings.TrimSpace(body.Error.Context.ConflictMemberID)
}
