// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package cdp is the client for the CDP (crowd.dev) v1 transactional API.
//
// Three operations are consumed: resolve an identity to a member, create a
// member, and attach an identity to an existing member. The API is shared with
// other services under a global rate limit, so callers are expected to pass a
// bounded context and to treat a 429 as a reason to back off rather than to
// retry immediately.
package cdp

import (
	"context"
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
	CreateMember(ctx context.Context, displayName string, identity Identity) (CreateResult, error)
	AttachIdentity(ctx context.Context, memberID string, identity Identity) error
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
		httpclient.WithBody(payload),
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
			"error", errCall,
			"status_code", statusCode,
			"lfid", redaction.Redact(lfid),
		)
		return ResolveResult{}, errors.NewUnexpected("CDP resolve failed", errCall)
	}

	if strings.TrimSpace(response.MemberID) == "" {
		return ResolveResult{}, errors.NewUnexpected("CDP resolve returned an empty member id")
	}

	return ResolveResult{Outcome: OutcomeFound, MemberID: response.MemberID}, nil
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
		httpclient.WithBody(createMemberRequest{
			DisplayName: displayName,
			Identities:  []Identity{identity},
		}),
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
			"error", errCall,
			"status_code", statusCode,
			"identity_value", redaction.Redact(identity.Value),
		)
		return CreateResult{}, errors.NewUnexpected("CDP member create failed", errCall)
	}

	if strings.TrimSpace(response.MemberID) == "" {
		return CreateResult{}, errors.NewUnexpected("CDP member create returned an empty member id")
	}

	return CreateResult{Outcome: OutcomeFound, MemberID: response.MemberID}, nil
}

// AttachIdentity attaches an identity to an existing CDP member.
//
// A 409 means the identity is already attached, which is the desired end state,
// so it is reported as success to keep the caller idempotent under the
// at-least-once delivery the provisioning trigger provides.
func (c *client) AttachIdentity(ctx context.Context, memberID string, identity Identity) error {
	if strings.TrimSpace(memberID) == "" {
		return errors.NewValidation("member id is required to attach an identity")
	}
	if strings.TrimSpace(identity.Value) == "" {
		return errors.NewValidation("identity value is required to attach an identity")
	}
	if c.config.TokenManager == nil {
		return errors.NewUnexpected("CDP token manager is not configured")
	}

	token, err := c.config.TokenManager.GetToken(ctx)
	if err != nil {
		return errors.NewUnexpected("failed to get CDP M2M token", err)
	}

	request := httpclient.NewAPIRequest(
		c.httpClient,
		httpclient.WithMethod(http.MethodPost),
		httpclient.WithURL(c.config.BaseURL+"/v1/members/"+url.PathEscape(memberID)+"/identities"),
		httpclient.WithToken(token),
		httpclient.WithDescription("attach CDP member identity"),
		httpclient.WithBody(identity),
	)

	statusCode, errCall := request.Call(ctx, nil)
	if errCall != nil {
		if statusCode == http.StatusConflict {
			slog.InfoContext(ctx, "CDP identity already attached to member",
				"member_id", memberID,
			)
			return nil
		}
		slog.ErrorContext(ctx, "CDP identity attach failed",
			"error", errCall,
			"status_code", statusCode,
			"member_id", memberID,
		)
		return errors.NewUnexpected("CDP identity attach failed", errCall)
	}

	return nil
}
