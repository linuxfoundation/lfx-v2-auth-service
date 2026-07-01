// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package port

import "context"

// Impersonator performs an Auth0 Custom Token Exchange that swaps the
// requesting user's LFX V2 access token for a new one representing a
// different (target) user.
//
// audience is optional: when non-empty it overrides the default LFX V2 audience,
// allowing callers to obtain a token scoped to a different API (e.g. Crowdfunding).
// An empty string means "use the service's configured default audience".
type Impersonator interface {
	ImpersonateUser(ctx context.Context, subjectToken, targetUser, audience string) (string, error)
}

// ImpersonationMessageHandler handles NATS impersonation token exchange messages.
type ImpersonationMessageHandler interface {
	ImpersonateUser(ctx context.Context, msg TransportMessenger) ([]byte, error)
}
