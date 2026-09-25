// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package port

import (
	"context"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
)

// EmailSender defines the behavior for sending emails
type EmailSender interface {
	// SendEmail sends an email message
	SendEmail(ctx context.Context, message *model.EmailMessage) error
}
