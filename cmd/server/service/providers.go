// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package service

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/auth0"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/authelia"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/mock"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/nats"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/service"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
)

var (
	// expose the NATS client for direct access in subscriptions
	natsClient *nats.NATSClient

	natsDoOnce sync.Once
)

func natsInit(ctx context.Context) {

	natsDoOnce.Do(func() {
		natsURL := os.Getenv("NATS_URL")
		if natsURL == "" {
			natsURL = "nats://localhost:4222"
		}

		natsTimeout := os.Getenv("NATS_TIMEOUT")
		if natsTimeout == "" {
			natsTimeout = "10s"
		}
		natsTimeoutDuration, err := time.ParseDuration(natsTimeout)
		if err != nil {
			log.Fatalf("invalid NATS timeout duration: %v", err)
		}

		natsMaxReconnect := os.Getenv("NATS_MAX_RECONNECT")
		if natsMaxReconnect == "" {
			natsMaxReconnect = "3"
		}
		natsMaxReconnectInt, err := strconv.Atoi(natsMaxReconnect)
		if err != nil {
			log.Fatalf("invalid NATS max reconnect value %s: %v", natsMaxReconnect, err)
		}

		natsReconnectWait := os.Getenv("NATS_RECONNECT_WAIT")
		if natsReconnectWait == "" {
			natsReconnectWait = "2s"
		}
		natsReconnectWaitDuration, err := time.ParseDuration(natsReconnectWait)
		if err != nil {
			log.Fatalf("invalid NATS reconnect wait duration %s : %v", natsReconnectWait, err)
		}

		config := nats.Config{
			URL:           natsURL,
			Timeout:       natsTimeoutDuration,
			MaxReconnect:  natsMaxReconnectInt,
			ReconnectWait: natsReconnectWaitDuration,
		}

		client, errNewClient := nats.NewClient(ctx, config)
		if errNewClient != nil {
			log.Fatalf("failed to create NATS client: %v", errNewClient)
		}
		natsClient = client
	})
}

// newUserReaderWriter creates a UserReaderWriter implementation based on the environment variable.
// Set USER_REPOSITORY_TYPE to "mock" to explicitly use mock, or "auth0" to use Auth0.
func newUserReaderWriter(ctx context.Context) port.UserReaderWriter {

	userRepositoryType := os.Getenv(constants.UserRepositoryTypeEnvKey)
	if userRepositoryType == "" {
		userRepositoryType = constants.UserRepositoryTypeMock // default to mock when not set
	}

	switch userRepositoryType {
	case constants.UserRepositoryTypeMock:
		slog.DebugContext(ctx, "using mock user repository implementation")
		return mock.NewUserReaderWriter(ctx)
	case constants.UserRepositoryTypeAuth0:

		// Load Auth0 configuration from environment variables
		auth0Tenant := os.Getenv(constants.Auth0TenantEnvKey)
		auth0Domain := os.Getenv(constants.Auth0DomainEnvKey)

		slog.DebugContext(ctx, "using Auth0 user repository implementation",
			"tenant", auth0Tenant,
			"domain", auth0Domain,
		)

		if auth0Domain == "" {
			// Default to tenant.auth0.com if domain is not explicitly set
			auth0Domain = fmt.Sprintf("%s.auth0.com", auth0Tenant)
		}

		auth0Config := auth0.Config{
			Tenant: auth0Tenant,
			Domain: auth0Domain,
		}

		slog.DebugContext(ctx, "Auth0 client initialized with M2M token support",
			"tenant", auth0Tenant,
			"domain", auth0Domain,
		)

		userReaderWriter, err := auth0.NewUserReaderWriter(ctx, httpclient.DefaultConfig(), auth0Config)
		if err != nil {
			log.Fatalf("failed to create Auth0 user reader writer: %v", err)
		}

		return userReaderWriter
	case constants.UserRepositoryTypeAuthelia:
		// Initialize NATS client first for Authelia NATS storage
		natsInit(ctx)

		// Load Authelia configuration from environment variables
		configMapName := os.Getenv(constants.AutheliaConfigMapNameEnvKey)
		if configMapName == "" {
			configMapName = "authelia-users"
		}
		configMapNamespace := os.Getenv(constants.AutheliaConfigMapNamespaceEnvKey)
		if configMapNamespace == "" {
			configMapNamespace = "lfx"
		}

		daemonSetName := os.Getenv(constants.AutheliaDaemonSetNameEnvKey)
		if daemonSetName == "" {
			daemonSetName = "lfx-platform-authelia"
		}

		secretName := os.Getenv(constants.AutheliaSecretNameEnvKey)
		if secretName == "" {
			secretName = "authelia-users"
		}

		oidcUserInfoURL := os.Getenv(constants.AutheliaOIDCUserInfoURLEnvKey)
		if oidcUserInfoURL == "" {
			oidcUserInfoURL = "https://auth.k8s.orb.local/api/oidc/userinfo"
		}

		config := map[string]string{
			"configmap-name":    configMapName,
			"namespace":         configMapNamespace,
			"daemon-set-name":   daemonSetName,
			"secret-name":       secretName,
			"oidc-userinfo-url": oidcUserInfoURL,
		}

		// Create Authelia user repository with NATS client for storage
		userWriter, err := authelia.NewUserReaderWriter(ctx, config, natsClient)
		if err != nil {
			log.Fatalf("failed to create Authelia user repository: %v", err)
		}
		return userWriter
	default:
		log.Fatalf("unsupported user repository type: %s", userRepositoryType)
		return nil // This will never be reached due to log.Fatalf, but satisfies the linter
	}
}

// QueueSubscriptions starts all NATS subscriptions with the provided dependencies
func QueueSubscriptions(ctx context.Context) error {
	slog.DebugContext(ctx, "starting NATS subscriptions")

	// Initialize NATS client first
	natsInit(ctx)

	userReaderWriter := newUserReaderWriter(ctx)

	messageHandlerService := &MessageHandlerService{
		messageHandler: service.NewMessageHandlerOrchestrator(
			service.WithUserWriterForMessageHandler(
				userReaderWriter,
			),
			service.WithUserReaderForMessageHandler(
				userReaderWriter,
			),
			service.WithEmailHandlerForMessageHandler(
				userReaderWriter,
			),
		),
	}

	// Get the NATS client - we need to access it directly
	natsClient := getNATSClient()
	if natsClient == nil {
		return fmt.Errorf("NATS client not initialized")
	}

	// Start subscriptions for each subject
	subjects := map[string]func(context.Context, port.TransportMessenger){
		constants.UserMetadataUpdateSubject:           messageHandlerService.HandleMessage,
		constants.UserEmailToUserSubject:              messageHandlerService.HandleMessage,
		constants.UserEmailToSubSubject:               messageHandlerService.HandleMessage,
		constants.UserMetadataReadSubject:             messageHandlerService.HandleMessage,
		constants.EmailLinkingSendVerificationSubject: messageHandlerService.HandleMessage,
		constants.EmailLinkingVerifySubject:           messageHandlerService.HandleMessage,
		// Add more subjects here as needed
	}

	for subject, handler := range subjects {
		slog.DebugContext(ctx, "subscribing to NATS subject", "subject", subject)
		if _, err := natsClient.SubscribeWithTransportMessenger(ctx, subject, constants.AuthServiceQueue, handler); err != nil {
			slog.ErrorContext(ctx, "failed to subscribe to NATS subject",
				"error", err,
				"subject", subject,
			)
			return fmt.Errorf("failed to subscribe to subject %s: %w", subject, err)
		}
	}

	slog.DebugContext(ctx, "NATS subscriptions started successfully")
	return nil
}

// getNATSClient returns the initialized NATS client
// This is a helper function to access the client for subscription management
func getNATSClient() *nats.NATSClient {
	return natsClient
}
