// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"context"
	"log/slog"

	"github.com/auth0/go-auth0/authentication"
	"github.com/auth0/go-auth0/authentication/oauth"
	"github.com/auth0/go-auth0/authentication/passwordless"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

// EmailLinkingFlow is the flow for email linking
type EmailLinkingFlow struct {
	flow passwordlessFlow
}

type passwordlessFlow interface {
	SendEmail(ctx context.Context, request passwordless.SendEmailRequest) (*passwordless.SendEmailResponse, error)
	LoginWithEmail(ctx context.Context, request passwordless.LoginWithEmailRequest, options oauth.IDTokenValidationOptions) (*oauth.TokenSet, error)
}

type auth0PasswordlessFlow struct {
	authConfig *authentication.Authentication
}

func (a *auth0PasswordlessFlow) SendEmail(ctx context.Context, request passwordless.SendEmailRequest) (*passwordless.SendEmailResponse, error) {
	if a.authConfig == nil {
		return nil, errors.NewUnexpected("auth0 authentication client not configured")
	}
	return a.authConfig.Passwordless.SendEmail(ctx, request)
}

func (a *auth0PasswordlessFlow) LoginWithEmail(ctx context.Context, request passwordless.LoginWithEmailRequest, options oauth.IDTokenValidationOptions) (*oauth.TokenSet, error) {
	if a.authConfig == nil {
		return nil, errors.NewUnexpected("auth0 authentication client not configured")
	}
	return a.authConfig.Passwordless.LoginWithEmail(ctx, request, options)
}

// StartPasswordlessFlow initiates a passwordless authentication flow by sending an OTP to the user's email
// This is used in the alternate email linking flow to send a verification code to the alternate email address.
func (e *EmailLinkingFlow) StartPasswordlessFlow(ctx context.Context, email string) error {

	if e == nil || e.flow == nil {
		return errors.NewUnexpected("passwordless flow not configured")
	}

	// Use SDK's passwordless SendEmail method
	request := passwordless.SendEmailRequest{
		Email:      email,
		Connection: "email",
		Send:       "code",
	}

	response, err := e.flow.SendEmail(ctx, request)
	if err != nil {
		slog.ErrorContext(ctx, "failed to send passwordless email",
			"error", err,
			"email", redaction.Redact(email))
		return errors.NewUnexpected("failed to start passwordless flow", err)
	}

	slog.DebugContext(ctx, "passwordless flow started successfully",
		"email", redaction.Redact(response.Email),
		"passwordless_flow_id", response.ID,
		"email_verified", response.EmailVerified)

	return nil
}

// ExchangeOTPForToken exchanges a passwordless OTP for tokens using private key JWT authentication
// This is used for the alternate email linking flow where a user verifies their
// alternate email address by entering a one-time password (OTP) sent to their email.
func (e *EmailLinkingFlow) ExchangeOTPForToken(ctx context.Context, email, otp string) (*TokenResponse, error) {
	// Use SDK's passwordless LoginWithEmail method
	request := passwordless.LoginWithEmailRequest{
		Email: email,
		Code:  otp,
		Realm: "email",
		Scope: "openid email profile",
	}

	tokenSet, err := e.flow.LoginWithEmail(ctx, request, oauth.IDTokenValidationOptions{})
	if err != nil {
		slog.ErrorContext(ctx, "failed to exchange OTP for token",
			"error", err,
			"email", redaction.Redact(email))
		return nil, errors.NewUnexpected("failed to exchange OTP for token", err)
	}

	slog.DebugContext(ctx, "OTP exchange successful",
		"token_type", tokenSet.TokenType,
		"expires_in", tokenSet.ExpiresIn,
		"has_id_token", tokenSet.IDToken != "",
		"has_refresh_token", tokenSet.RefreshToken != "")

	return &TokenResponse{
		AccessToken:  tokenSet.AccessToken,
		IDToken:      tokenSet.IDToken,
		TokenType:    tokenSet.TokenType,
		ExpiresIn:    int64(tokenSet.ExpiresIn),
		RefreshToken: tokenSet.RefreshToken,
		Scope:        tokenSet.Scope,
	}, nil
}

// NewEmailLinkingFlow creates a new EmailLinkingFlow with the provided configuration
func NewEmailLinkingFlow(authConfig *authentication.Authentication) *EmailLinkingFlow {
	return &EmailLinkingFlow{
		flow: &auth0PasswordlessFlow{
			authConfig: authConfig,
		},
	}
}
