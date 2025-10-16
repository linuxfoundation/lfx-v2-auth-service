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
}

// UserReader defines the behavior of the user reader
type UserReader interface {
	GetUser(ctx context.Context, user *model.User) (*model.User, error)
	SearchUser(ctx context.Context, user *model.User, criteria string) (*model.User, error)
	MetadataLookup(ctx context.Context, input string) (*model.User, error)
}

// UserWriter defines the behavior of the user writer
type UserWriter interface {
	UpdateUser(ctx context.Context, user *model.User) (*model.User, error)
}

// EmailHandler defines the behavior of the email handler
type EmailHandler interface {
	SendVerificationAlternateEmail(ctx context.Context, alternateEmail string) error
	VerifyAlternateEmail(ctx context.Context, email *model.Email) (*model.User, error)
}
