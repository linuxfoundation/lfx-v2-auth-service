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
	"strings"
	"sync"
	"time"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/auth0"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/authelia"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/cdp"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/k8s"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/mock"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/nats"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/service"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/service/provisioning"
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
			Tenant:                 auth0Tenant,
			Domain:                 auth0Domain,
			LFXProfileClientID:     os.Getenv(constants.Auth0LFXProfileClientIDEnvKey),
			LFXProfileClientSecret: os.Getenv(constants.Auth0LFXProfileClientSecretEnvKey),
			LFXOneClientID:         os.Getenv(constants.Auth0LFXOneClientIDEnvKey),
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

// newProvisioningOrchestrator wires the CDP provisioning flow.
//
// It returns nil when the CDP configuration is absent, which leaves the
// consumer unstarted rather than reading a stream it cannot act on.
func newProvisioningOrchestrator(ctx context.Context) provisioning.Orchestrator {
	cdpBaseURL := os.Getenv(constants.CDPBaseURLEnvKey)
	cdpAudience := os.Getenv(constants.CDPAudienceEnvKey)
	if cdpBaseURL == "" || cdpAudience == "" {
		slog.WarnContext(ctx, "CDP provisioning is not configured, the events consumer will not start",
			"has_base_url", cdpBaseURL != "",
			"has_audience", cdpAudience != "",
		)
		return nil
	}

	auth0Config, ok := newProvisioningAuth0Config(ctx)
	if !ok {
		return nil
	}

	cdpTokenManager, err := auth0.NewM2MTokenManagerForAudience(ctx, auth0Config, cdpAudience)
	if err != nil {
		slog.ErrorContext(ctx, "failed to create CDP M2M token manager", "error", err)
		return nil
	}

	cdpClient := cdp.NewClient(cdp.Config{
		BaseURL:      strings.TrimSuffix(cdpBaseURL, "/"),
		TokenManager: cdpTokenManager,
	})

	slog.DebugContext(ctx, "CDP provisioning initialized", "cdp_base_url", cdpBaseURL)

	metadataStore, err := auth0.NewCDPMetadataWriter(httpclient.Config{MaxRetries: 0}, auth0Config)
	if err != nil {
		slog.ErrorContext(ctx, "failed to create the CDP metadata writer", "error", err)
		return nil
	}

	return provisioning.NewOrchestrator(
		provisioning.WithCDPClient(cdpClient),
		provisioning.WithMetadataStore(metadataStore),
	)
}

// newProvisioningAuth0Config resolves the Auth0 tenant and mints the
// Management API token manager the provisioning paths share.
//
// The Management API and the CDP public API are different audiences, so each
// gets its own token manager and its own cache.
func newProvisioningAuth0Config(ctx context.Context) (auth0.Config, bool) {
	auth0Tenant := os.Getenv(constants.Auth0TenantEnvKey)
	auth0Domain := os.Getenv(constants.Auth0DomainEnvKey)
	if auth0Domain == "" {
		if auth0Tenant == "" {
			slog.ErrorContext(ctx, "CDP provisioning needs an Auth0 tenant or domain, disabling it")
			return auth0.Config{}, false
		}
		auth0Domain = fmt.Sprintf("%s.auth0.com", auth0Tenant)
	}

	config := auth0.Config{
		Tenant: auth0Tenant,
		Domain: auth0Domain,
	}

	tokenManager, err := auth0.NewM2MTokenManager(ctx, config)
	if err != nil {
		slog.ErrorContext(ctx, "failed to create Auth0 M2M token manager for provisioning", "error", err)
		return auth0.Config{}, false
	}
	config.M2MTokenManager = tokenManager

	return config, true
}

// startProvisioningConsumer reads the Auth0 events stream on one replica.
//
// The stream fans out rather than load balancing — every connection receives
// every event — so the consumer runs under a lease and the replicas that do
// not hold it stand by.
func startProvisioningConsumer(ctx context.Context) {
	if os.Getenv(constants.ProvisioningConsumerEnabledEnvKey) != "true" {
		slog.InfoContext(ctx, "Auth0 events consumer is disabled")
		return
	}

	orchestrator := newProvisioningOrchestrator(ctx)
	if orchestrator == nil {
		return
	}

	auth0Config, ok := newProvisioningAuth0Config(ctx)
	if !ok {
		return
	}
	// Production reaches Auth0 through a custom domain. The override exists
	// because it is unconfirmed whether every custom domain serves
	// /api/v2/events.
	if host := os.Getenv(constants.Auth0EventsHostEnvKey); host != "" {
		auth0Config.Domain = host
	}

	eventsClient, err := auth0.NewEventsClient(auth0.EventsConfig{}, auth0Config)
	if err != nil {
		slog.ErrorContext(ctx, "failed to create the Auth0 events client", "error", err)
		return
	}

	kv, found := getNATSClient().GetKVStore(constants.KVBucketNameProvisioningCursor)
	if !found {
		slog.ErrorContext(ctx, "the provisioning offset bucket is not available, not starting the consumer",
			"bucket", constants.KVBucketNameProvisioningCursor,
		)
		return
	}
	offsets, err := provisioning.NewKVOffsetStore(kv)
	if err != nil {
		slog.ErrorContext(ctx, "failed to create the provisioning offset store", "error", err)
		return
	}

	consumer, err := provisioning.NewConsumer(
		provisioning.WithEventsClient(eventsClient),
		provisioning.WithProvisioner(orchestrator),
		provisioning.WithOffsetStore(offsets),
		provisioning.WithReplayWindow(provisioningReplayWindow(ctx)),
	)
	if err != nil {
		slog.ErrorContext(ctx, "failed to create the Auth0 events consumer", "error", err)
		return
	}

	namespace := k8s.PodNamespace()
	if namespace == "" {
		slog.ErrorContext(ctx, "cannot determine the pod namespace, not starting the consumer")
		return
	}

	lease := k8s.LeaseConfig{
		Name:      constants.LeaseNameProvisioningConsumer,
		Namespace: namespace,
		Identity:  k8s.PodIdentity(),
	}

	go func() {
		if err := k8s.RunAsLeader(ctx, lease, consumer.Run); err != nil {
			slog.ErrorContext(ctx, "the Auth0 events consumer stopped", "error", err)
		}
	}()
}

// provisioningReplayWindow reads the configured replay window.
func provisioningReplayWindow(ctx context.Context) time.Duration {
	raw := os.Getenv(constants.ProvisioningReplayWindowEnvKey)
	if raw == "" {
		return constants.DefaultProvisioningReplayWindow
	}

	window, err := time.ParseDuration(raw)
	if err != nil || window <= 0 {
		slog.WarnContext(ctx, "invalid provisioning replay window, using the default",
			"value", raw,
			"default", constants.DefaultProvisioningReplayWindow,
		)
		return constants.DefaultProvisioningReplayWindow
	}
	return window
}

// QueueSubscriptions starts all NATS subscriptions with the provided dependencies
func QueueSubscriptions(ctx context.Context) error {
	slog.DebugContext(ctx, "starting NATS subscriptions")

	// Initialize NATS client first
	natsInit(ctx)

	userReaderWriter := newUserReaderWriter(ctx)

	opts := []service.MessageHandlerOrchestratorOption{
		service.WithUserWriterForMessageHandler(userReaderWriter),
		service.WithUserReaderForMessageHandler(userReaderWriter),
		service.WithEmailHandlerForMessageHandler(userReaderWriter),
		service.WithIdentityLinkerForMessageHandler(userReaderWriter),
		service.WithIdentityUnlinkerForMessageHandler(userReaderWriter),
		service.WithPasswordHandlerForMessageHandler(userReaderWriter),
		service.WithEventPublisherForMessageHandler(natsClient),
	}

	// Only wire the alias manager for backends that meaningfully support
	// system-managed aliases. Authelia returns a backend-specific validation
	// error; leaving it nil lets AddAlias surface the stable
	// "alias_service_unavailable" guard instead.
	userRepoType := os.Getenv(constants.UserRepositoryTypeEnvKey)
	if userRepoType == constants.UserRepositoryTypeAuth0 || userRepoType == constants.UserRepositoryTypeMock || userRepoType == "" {
		opts = append(opts, service.WithAliasManagerForMessageHandler(userReaderWriter))
	}

	if userRepoType == constants.UserRepositoryTypeAuth0 {
		auth0Domain := os.Getenv(constants.Auth0DomainEnvKey)
		if auth0Domain == "" {
			auth0Domain = fmt.Sprintf("%s.auth0.com", os.Getenv(constants.Auth0TenantEnvKey))
		}

		impersonationFlow, err := auth0.NewImpersonationFlow(ctx, auth0Domain)
		if err != nil {
			slog.WarnContext(ctx, "impersonation flow unavailable", "error", err)
		} else {
			opts = append(opts, service.WithImpersonatorForMessageHandler(impersonationFlow))
		}
	}

	messageHandlerService := NewMessageHandlerService(
		service.NewMessageHandlerOrchestrator(opts...),
	)

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
		constants.UserUsernameToSubSubject:            messageHandlerService.HandleMessage,
		constants.UserMetadataReadSubject:             messageHandlerService.HandleMessage,
		constants.UserEmailReadSubject:                messageHandlerService.HandleMessage,
		constants.UserEmailSetPrimarySubject:          messageHandlerService.HandleMessage,
		constants.EmailLinkingSendVerificationSubject: messageHandlerService.HandleMessage,
		constants.EmailLinkingVerifySubject:           messageHandlerService.HandleMessage,
		constants.UserIdentityLinkSubject:             messageHandlerService.HandleMessage,
		constants.UserIdentityUnlinkSubject:           messageHandlerService.HandleMessage,
		constants.UserIdentityListSubject:             messageHandlerService.HandleMessage,
		constants.UserAddAliasSubject:                 messageHandlerService.HandleMessage,
		constants.PasswordUpdateSubject:               messageHandlerService.HandleMessage,
		constants.PasswordResetLinkSubject:            messageHandlerService.HandleMessage,
		constants.ImpersonationTokenExchangeSubject:   messageHandlerService.HandleMessage,
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

	startProvisioningConsumer(ctx)

	slog.DebugContext(ctx, "NATS subscriptions started successfully")
	return nil
}

// getNATSClient returns the initialized NATS client
// This is a helper function to access the client for subscription management
func getNATSClient() *nats.NATSClient {
	return natsClient
}
