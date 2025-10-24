// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package authelia

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/smtp"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/password"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

type passwordlessFlow interface {
	SendEmail(ctx context.Context, email string) (string, error)
	LoginWithEmail(ctx context.Context) error
}

type autheliaPasswordlessFlow struct {
	emailSender port.EmailSender
}

func (a *autheliaPasswordlessFlow) SendEmail(ctx context.Context, email string) (string, error) {

	otp, err := password.OnlyNumbers(6)
	if err != nil {
		slog.ErrorContext(ctx, "failed to generate OTP", "error", err)
		return "", errors.NewUnexpected("failed to generate OTP", err)
	}

	message := &model.EmailMessage{
		From:    "noreply@lfx.dev",
		To:      email,
		Subject: "Welcome to Linux Foundation",
		Body:    fmt.Sprintf("Your verification code is: %s", otp),
	}

	errSendEmail := a.emailSender.SendEmail(ctx, message)
	if errSendEmail != nil {
		slog.ErrorContext(ctx, "failed to send email", "error", errSendEmail)
		return "", errors.NewUnexpected("failed to send email", errSendEmail)
	}

	// Note: this is not a production flow, so the otp is not sensitive
	// We're logging the otp here to help with debugging and testing
	slog.InfoContext(ctx, "passwordless flow email sent",
		"email", redaction.RedactEmail(email),
		"otp", otp,
	)

	return otp, nil
}

func (a *autheliaPasswordlessFlow) LoginWithEmail(ctx context.Context) error {
	return nil
}

func newEmailLinkingFlow() passwordlessFlow {
	return &autheliaPasswordlessFlow{
		emailSender: smtp.NewSender(),
	}
}
