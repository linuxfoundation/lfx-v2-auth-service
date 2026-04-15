// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package constants

const (

	// ServiceName is the name of the auth service
	ServiceName = "lfx-v2-auth-service"

	// UserRepositoryTypeEnvKey is the environment variable key for the user repository type
	UserRepositoryTypeEnvKey = "USER_REPOSITORY_TYPE"

	// UserRepositoryTypeMock is the value for the mock user repository type
	UserRepositoryTypeMock = "mock"

	// UserRepositoryTypeAuthelia is the value for the Authelia user repository type
	UserRepositoryTypeAuthelia = "authelia"

	// UserRepositoryTypeAuth0 is the value for the Auth0 user repository type
	UserRepositoryTypeAuth0 = "auth0"
)

const (
	// Authelia configuration
	// AutheliaConfigMapNameEnvKey is the environment variable key for the ConfigMap name
	AutheliaConfigMapNameEnvKey = "AUTHELIA_CONFIGMAP_NAME"

	// AutheliaConfigMapNamespaceEnvKey is the environment variable key for the ConfigMap namespace
	AutheliaConfigMapNamespaceEnvKey = "AUTHELIA_CONFIGMAP_NAMESPACE"

	// AutheliaDaemonSetNameEnvKey is the environment variable key for the DaemonSet name
	AutheliaDaemonSetNameEnvKey = "AUTHELIA_DAEMONSET_NAME"

	// AutheliaSecretNameEnvKey is the environment variable key for the Secret name
	AutheliaSecretNameEnvKey = "AUTHELIA_SECRET_NAME"

	// AutheliaOIDCUserInfoURLEnvKey is the environment variable key for the OIDC userinfo URL
	AutheliaOIDCUserInfoURLEnvKey = "AUTHELIA_OIDC_USERINFO_URL"
)

const (
	// Auth0 Management API configuration
	// Auth0TenantEnvKey is the environment variable key for the Auth0 tenant
	Auth0TenantEnvKey = "AUTH0_TENANT"

	// Auth0DomainEnvKey is the environment variable key for the Auth0 domain
	Auth0DomainEnvKey = "AUTH0_DOMAIN"

	// Auth0 M2M Authentication configuration
	// Auth0M2MClientIDEnvKey is the environment variable key for the Auth0 M2M client ID
	Auth0M2MClientIDEnvKey = "AUTH0_M2M_CLIENT_ID"

	// Auth0M2MPrivateBase64KeyEnvKey is the environment variable key for the Auth0 M2M private key (base64-encoded or raw PEM)
	Auth0M2MPrivateBase64KeyEnvKey = "AUTH0_M2M_PRIVATE_BASE64_KEY"

	// Auth0AudienceEnvKey is the environment variable key for the Auth0 audience
	Auth0AudienceEnvKey = "AUTH0_AUDIENCE"

	// Auth0ManagementAudienceEnvKey is the environment variable key for the Auth0 Management API audience override
	Auth0ManagementAudienceEnvKey = "AUTH0_MANAGEMENT_AUDIENCE"

	// Auth0LFXv2APIAudienceEnvKey is the environment variable key for the LFX V2 API audience
	// (identifier of the LFX V2 resource server). Used as subject_token_type and audience
	// for the impersonation Custom Token Exchange.
	Auth0LFXv2APIAudienceEnvKey = "AUTH0_LFX_V2_API_AUDIENCE"

	// Auth0 LFX Profile Client configuration (Regular Web Application for passwordless flows)
	// Auth0LFXProfileClientIDEnvKey is the environment variable key for the LFX Profile Auth0 client ID
	Auth0LFXProfileClientIDEnvKey = "AUTH0_LFX_PROFILE_CLIENT_ID"

	// Auth0LFXProfileClientSecretEnvKey is the environment variable key for the LFX Profile Auth0 client secret
	Auth0LFXProfileClientSecretEnvKey = "AUTH0_LFX_PROFILE_CLIENT_SECRET"
)

const (
	// Email/SMTP configuration (generic for any SMTP provider: Mailpit, SendGrid, AWS SES, etc.)
	// EmailSMTPHostEnvKey is the environment variable key for the SMTP server host
	EmailSMTPHostEnvKey = "EMAIL_SMTP_HOST"

	// EmailSMTPPortEnvKey is the environment variable key for the SMTP server port
	EmailSMTPPortEnvKey = "EMAIL_SMTP_PORT"

	// EmailFromAddressEnvKey is the environment variable key for the sender email address
	EmailFromAddressEnvKey = "EMAIL_FROM_ADDRESS"

	// EmailFromNameEnvKey is the environment variable key for the sender name
	EmailFromNameEnvKey = "EMAIL_FROM_NAME"

	// EmailSMTPUsernameEnvKey is the environment variable key for SMTP username
	EmailSMTPUsernameEnvKey = "EMAIL_SMTP_USERNAME"

	// EmailSMTPPasswordEnvKey is the environment variable key for SMTP password
	EmailSMTPPasswordEnvKey = "EMAIL_SMTP_PASSWORD"
)
