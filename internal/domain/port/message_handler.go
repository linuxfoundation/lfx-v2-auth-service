// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package port

import "context"

// MessageHandler defines the behavior of the all domain handlers
type MessageHandler interface {
	UserHandler
}

// UserHandler defines the behavior of the user domain handlers
type UserHandler interface {
	UserWriteHandler
	UserReaderHandler
	UserLookupHandler
	UserLinkHandler
}

// UserReadHandler defines the behavior of the user read/lookup domain handlers
type UserReaderHandler interface {
	GetUserMetadata(ctx context.Context, msg TransportMessenger) ([]byte, error)
	GetUserEmails(ctx context.Context, msg TransportMessenger) ([]byte, error)
	ListIdentities(ctx context.Context, msg TransportMessenger) ([]byte, error)
}

// UserLookupHandler defines the behavior of the user lookup domain handlers
type UserLookupHandler interface {
	EmailToUsername(ctx context.Context, msg TransportMessenger) ([]byte, error)
	EmailToSub(ctx context.Context, msg TransportMessenger) ([]byte, error)
	UsernameToSub(ctx context.Context, msg TransportMessenger) ([]byte, error)
}

// UserWriteHandler defines the behavior of the user write domain handlers
type UserWriteHandler interface {
	UpdateUser(ctx context.Context, msg TransportMessenger) ([]byte, error)
}

// UserLinkHandler defines the behavior of the user link/alternate email domain handlers
type UserLinkHandler interface {
	EmailLinkingHandler
	IdentityLinkingHandler
	// it will handle social account linking, etc
}

// IdentityLinkingHandler defines the behavior of the identity linking domain handlers
type IdentityLinkingHandler interface {
	LinkIdentity(ctx context.Context, msg TransportMessenger) ([]byte, error)
	UnlinkIdentity(ctx context.Context, msg TransportMessenger) ([]byte, error)
}

// EmailLinkingHandler defines the behavior of the email linking domain handlers
type EmailLinkingHandler interface {
	StartEmailLinking(ctx context.Context, msg TransportMessenger) ([]byte, error)
	VerifyEmailLinking(ctx context.Context, msg TransportMessenger) ([]byte, error)
}
