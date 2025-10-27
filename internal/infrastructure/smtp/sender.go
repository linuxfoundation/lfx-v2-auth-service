// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package smtp

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
)

// Sender is the SMTP sender that implements port.EmailSender
type Sender struct {
	client *client
}

func (s *Sender) SendEmail(ctx context.Context, message *model.EmailMessage) error {
	if message == nil {
		return errors.NewValidation("email message is required")
	}

	if !message.IsValid() {
		return errors.NewValidation("invalid email message")
	}

	// Use message's From/FromName if provided, otherwise use client config
	from := message.From
	fromName := message.FromName

	fromAddress := from
	if fromName != "" {
		fromAddress = fmt.Sprintf("%s <%s>", fromName, from)
	}

	contentType := "text/plain"
	if message.IsHTML {
		contentType = "text/html"
	}

	emailBytes := []byte(
		fmt.Sprintf("From: %s\r\n", fromAddress) +
			fmt.Sprintf("To: %s\r\n", message.To) +
			fmt.Sprintf("Subject: %s\r\n", message.Subject) +
			fmt.Sprintf("Content-Type: %s; charset=UTF-8\r\n", contentType) +
			"\r\n" +
			message.Body,
	)

	errSendEmail := s.client.sendEmail(ctx, fromAddress, message.To, emailBytes)
	if errSendEmail != nil {
		return errSendEmail
	}

	slog.DebugContext(ctx, "email sent successfully via SMTP",
		"host", s.client.Host,
		"port", s.client.Port,
		"to", message.To,
		"subject", message.Subject,
	)

	return nil
}

// NewSender creates a new SMTP sender
func NewSender() port.EmailSender {
	return &Sender{
		client: newClient(),
	}
}
