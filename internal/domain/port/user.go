// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package port

import (
	"context"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
)

// UserReaderWriter defines the behavior of the user reader writer
type UserReaderWriter interface {
	UserReader
	UserWriter
	EmailHandler
	IdentityLinker
	PasswordHandler
}

// UserReader defines the behavior of the user reader
type UserReader interface {
	GetUser(ctx context.Context, user *model.User) (*model.User, error)
	SearchUser(ctx context.Context, user *model.User, criteria string) (*model.User, error)
	MetadataLookup(ctx context.Context, input string, requiredScopes ...string) (*model.User, error)
}

// UserWriter defines the behavior of the user writer
type UserWriter interface {
	UpdateUser(ctx context.Context, user *model.User) (*model.User, error)
}

// IdentityLinker defines the behavior of the identity linker
type IdentityLinker interface {
	ValidateLinkRequest(ctx context.Context, request *model.LinkIdentity) error
	LinkIdentity(ctx context.Context, request *model.LinkIdentity) error
	UnlinkIdentity(ctx context.Context, request *model.UnlinkIdentity) error
}

// EmailHandler defines the behavior of the email handler
type EmailHandler interface {
	SendVerificationAlternateEmail(ctx context.Context, alternateEmail string) error
	VerifyAlternateEmail(ctx context.Context, email *model.Email) (*model.AuthResponse, error)
}

// PasswordHandler defines the behavior of the password handler
type PasswordHandler interface {
	ChangePassword(ctx context.Context, user *model.User, currentPassword, newPassword string) error
	SendResetPasswordLink(ctx context.Context, user *model.User) error
}
