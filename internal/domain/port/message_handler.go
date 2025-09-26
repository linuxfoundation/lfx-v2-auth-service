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
	UpdateUser(ctx context.Context, msg TransportMessenger) ([]byte, error)
	EmailToUsername(ctx context.Context, msg TransportMessenger) ([]byte, error)
	GetUserMetadata(ctx context.Context, msg TransportMessenger) ([]byte, error)
}
