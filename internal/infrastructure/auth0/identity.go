// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

type identityLinkingFlow struct {
	domain     string
	httpClient *httpclient.Client
}

// LinkIdentityToUser links a verified email identity to an existing user account
// This uses the Auth0 Management API endpoint POST /api/v2/users/{id}/identities
// with the user's JWT token (with update:current_user_identities scope), not the service's credentials.
func (ilf *identityLinkingFlow) LinkIdentityToUser(ctx context.Context, userID, userToken, linkWith string) error {
	if ilf == nil || ilf.httpClient == nil {
		return errors.NewUnexpected("identity linking flow not configured")
	}

	if strings.TrimSpace(userID) == "" {
		return errors.NewValidation("user_id is required")
	}

	if userToken == "" {
		return errors.NewValidation("user_token is required")
	}

	if linkWith == "" {
		return errors.NewValidation("link_with is required")
	}

	slog.DebugContext(ctx, "linking identity to user",
		"user_token", redaction.Redact(userToken))

	// Prepare the payload with the ID token
	payload := LinkIdentityPayload{
		LinkWith: linkWith,
	}

	// Call Auth0 Management API to link the identity
	// IMPORTANT: Using the user's management API token (with update:current_user_identities scope)
	// NOT the service's M2M credentials
	url := fmt.Sprintf("https://%s/api/v2/users/%s/identities", ilf.domain, userID)

	apiRequest := httpclient.NewAPIRequest(
		ilf.httpClient,
		httpclient.WithMethod(http.MethodPost),
		httpclient.WithURL(url),
		httpclient.WithToken(userToken),
		httpclient.WithDescription("link identity to user"),
		httpclient.WithBody(payload),
	)

	// The response is an array of linked identities
	var linkedIdentities []any
	statusCode, errCall := apiRequest.Call(ctx, &linkedIdentities)
	if errCall != nil {
		slog.ErrorContext(ctx, "failed to link identity to user",
			"error", errCall,
			"status_code", statusCode,
			"user_id", redaction.Redact(userID),
		)
		return errors.NewUnexpected("failed to link identity to user", errCall)
	}

	slog.DebugContext(ctx, "identity linked successfully",
		"user_id", redaction.Redact(userID),
		"status_code", statusCode,
	)

	return nil
}

// newIdentityLinkingFlow creates a new IdentityLinkingFlow with the provided configuration
func newIdentityLinkingFlow(domain string, httpClient *httpclient.Client) *identityLinkingFlow {
	return &identityLinkingFlow{
		domain:     domain,
		httpClient: httpClient,
	}
}
