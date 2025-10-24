// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package smtp

import (
	"context"
	"fmt"
	"log/slog"
	"net/smtp"
	"os"

	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
)

// config holds the configuration for the SMTP client
type config struct {
	// Host is the SMTP server host (e.g., "lfx-platform-mailpit-smtp.lfx.svc.cluster.local")
	Host string
	// Port is the SMTP server port (e.g., 1025 for Mailpit)
	Port string
	// FromEmail is the sender email address
	Username string
	// Password is the SMTP password (optional)
	Password string
}

// client is the SMTP client that implements port.EmailSender
type client struct {
	config
}

func (c *client) sendEmail(ctx context.Context, from, to string, emailBytes []byte) error {

	// Connect to SMTP server
	addr := fmt.Sprintf("%s:%s", c.config.Host, c.config.Port)

	var auth smtp.Auth
	if c.config.Username != "" && c.config.Password != "" {
		auth = smtp.PlainAuth("", c.config.Username, c.config.Password, c.config.Host)
	}

	err := smtp.SendMail(addr, auth, from, []string{to}, emailBytes)
	if err != nil {
		slog.ErrorContext(ctx, "failed to send email via SMTP",
			"error", err,
			"host", c.config.Host,
			"port", c.config.Port,
		)
		return errors.NewUnexpected("failed to send email", err)
	}
	return nil
}

// newClient creates a new SMTP client from environment variables
func newClient() *client {
	config := config{
		Host:     os.Getenv(constants.EmailSMTPHostEnvKey),
		Port:     os.Getenv(constants.EmailSMTPPortEnvKey),
		Username: os.Getenv(constants.EmailSMTPUsernameEnvKey),
		Password: os.Getenv(constants.EmailSMTPPasswordEnvKey),
	}

	if config.Host == "" {
		config.Host = "lfx-platform-mailpit-smtp.lfx.svc.cluster.local"
	}
	if config.Port == "" {
		config.Port = "25"
	}

	return &client{
		config: config,
	}
}
