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
	// Auth0ClientIDEnvKey is the environment variable key for the Auth0 client ID
	Auth0ClientIDEnvKey = "AUTH0_CLIENT_ID"

	// Auth0PrivateBase64KeyEnvKey is the environment variable key for the Auth0 base64 encoded private key
	Auth0PrivateBase64KeyEnvKey = "AUTH0_PRIVATE_BASE64_KEY"

	// Auth0AudienceEnvKey is the environment variable key for the Auth0 audience
	Auth0AudienceEnvKey = "AUTH0_AUDIENCE"

	// Auth0 Regular Web Client configuration (for passwordless flows)
	// Auth0RegularWebClientIDEnvKey is the environment variable key for the regular web Auth0 client ID
	Auth0RegularWebClientIDEnvKey = "AUTH0_REGULAR_WEB_CLIENT_ID"

	// Auth0RegularWebClientSecretEnvKey is the environment variable key for the regular web Auth0 client secret
	Auth0RegularWebClientSecretEnvKey = "AUTH0_REGULAR_WEB_CLIENT_SECRET"
)
