// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/auth0/go-auth0/authentication"
	"github.com/auth0/go-auth0/authentication/oauth"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"

	"golang.org/x/oauth2"
)

const leeway = 60 * time.Second

// TokenManager manages Auth0 M2M tokens using the Auth0 Go SDK
type TokenManager struct {
	httpClient  *http.Client
	tokenSource oauth2.TokenSource
	config      m2mConfig
	authConfig  *authentication.Authentication
}

// m2mConfig holds the configuration for Auth0 M2M authentication
type m2mConfig struct {
	ClientID     string
	PrivateKey   string // PEM format private key
	Audience     string
	Domain       string
	Organization string // Optional
}

// auth0TokenSource implements oauth2.TokenSource using Auth0 Go SDK
type auth0TokenSource struct {
	ctx             context.Context
	authConfig      *authentication.Authentication
	audience        string
	organization    string
	extraParameters map[string]string
}

// Token implements the oauth2.TokenSource interface
func (a *auth0TokenSource) Token() (*oauth2.Token, error) {
	ctx := a.ctx
	if ctx == nil {
		ctx = context.TODO()
	}

	// Build and issue a request using Auth0 SDK
	body := oauth.LoginWithClientCredentialsRequest{
		Audience:        a.audience,
		ExtraParameters: a.extraParameters,
		Organization:    a.organization,
	}

	tokenSet, err := a.authConfig.OAuth.LoginWithClientCredentials(ctx, body, oauth.IDTokenValidationOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get token from Auth0: %w", err)
	}

	// Convert Auth0 response to oauth2.Token with leeway for expiration
	token := &oauth2.Token{
		AccessToken:  tokenSet.AccessToken,
		TokenType:    tokenSet.TokenType,
		RefreshToken: tokenSet.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(tokenSet.ExpiresIn)*time.Second - leeway),
	}

	// Add extra fields
	token = token.WithExtra(map[string]any{
		"scope": tokenSet.Scope,
	})

	return token, nil
}

// GetToken returns a valid M2M access token
func (tm *TokenManager) GetToken(ctx context.Context) (string, error) {
	token, err := tm.tokenSource.Token()
	if err != nil {
		return "", fmt.Errorf("failed to get M2M token: %w", err)
	}

	if !token.Valid() {
		return "", fmt.Errorf("token is not valid")
	}

	slog.DebugContext(ctx, "M2M token retrieved successfully",
		"token_type", token.TokenType,
		"expires_at", token.Expiry,
		"has_refresh_token", token.RefreshToken != "")

	return token.AccessToken, nil
}

// IsTokenExpired checks if the current token is expired
func (tm *TokenManager) IsTokenExpired() bool {
	token, err := tm.tokenSource.Token()
	if err != nil {
		return true
	}
	return !token.Valid()
}

// TokenInfo represents token information
type TokenInfo struct {
	AccessToken string
	TokenType   string
	ExpiresAt   time.Time
	Scope       string
	Valid       bool
}

// GetTokenInfo returns information about the current token
func (tm *TokenManager) GetTokenInfo() (*TokenInfo, error) {
	token, err := tm.tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to get token info: %w", err)
	}

	scope, _ := token.Extra("scope").(string)

	return &TokenInfo{
		AccessToken: token.AccessToken,
		TokenType:   token.TokenType,
		ExpiresAt:   token.Expiry,
		Scope:       scope,
		Valid:       token.Valid(),
	}, nil
}

// loadM2MConfigFromEnv loads M2M configuration from environment variables or secrets
func loadM2MConfigFromEnv(ctx context.Context, config Config) (m2mConfig, error) {
	clientID := os.Getenv(constants.Auth0ClientIDEnvKey)
	if clientID == "" {
		return m2mConfig{}, errors.NewUnexpected("AUTH0_CLIENT_ID is required")
	}

	audience := os.Getenv(constants.Auth0AudienceEnvKey)
	if audience == "" {
		return m2mConfig{}, errors.NewUnexpected("AUTH0_AUDIENCE is required")
	}

	// private key is base64 encoded
	privateKey := os.Getenv(constants.Auth0PrivateBase64KeyEnvKey)
	if privateKey == "" {
		return m2mConfig{}, errors.NewUnexpected("AUTH0_PRIVATE_BASE64_KEY is required")
	}

	decoded, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return m2mConfig{}, errors.NewUnexpected("failed to base64-decode AUTH0_PRIVATE_BASE64_KEY", err)
	}
	privateKey = string(decoded)
	//

	// Optional organization
	organization := os.Getenv("AUTH0_ORGANIZATION")

	slog.DebugContext(ctx, "M2M configuration loaded")

	return m2mConfig{
		ClientID:     clientID,
		PrivateKey:   privateKey,
		Audience:     audience,
		Domain:       config.Domain,
		Organization: organization,
	}, nil
}

// NewM2MTokenManager creates a new M2M token manager using Auth0 SDK
func NewM2MTokenManager(ctx context.Context, config Config) (*TokenManager, error) {
	m2mConfig, err := loadM2MConfigFromEnv(ctx, config)
	if err != nil {
		return nil, errors.NewUnexpected("failed to load M2M configuration", err)
	}

	// Create Auth0 authentication client with private key assertion
	authConfig, err := authentication.New(
		ctx,
		config.Domain,
		authentication.WithClientID(m2mConfig.ClientID),
		authentication.WithClientAssertion(m2mConfig.PrivateKey, "RS256"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Auth0 client: %w", err)
	}

	// Create token source
	tokenSource := &auth0TokenSource{
		ctx:          ctx,
		authConfig:   authConfig,
		audience:     m2mConfig.Audience,
		organization: m2mConfig.Organization,
	}

	// Wrap with oauth2.ReuseTokenSource for automatic caching and renewal
	reuseTokenSource := oauth2.ReuseTokenSource(nil, tokenSource)

	// Create HTTP client that automatically handles token management
	httpClient := oauth2.NewClient(ctx, reuseTokenSource)

	return &TokenManager{
		httpClient:  httpClient,
		tokenSource: reuseTokenSource,
		config:      m2mConfig,
		authConfig:  authConfig,
	}, nil
}
