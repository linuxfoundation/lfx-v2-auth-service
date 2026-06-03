// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package port

import "context"

// Impersonator performs an Auth0 Custom Token Exchange that swaps the
// requesting user's LFX V2 access token for a new one representing a
// different (target) user.
type Impersonator interface {
	ImpersonateUser(ctx context.Context, subjectToken, targetUser string) (string, error)
}

// ImpersonationMessageHandler handles NATS impersonation token exchange messages.
type ImpersonationMessageHandler interface {
	ImpersonateUser(ctx context.Context, msg TransportMessenger) ([]byte, error)
}
