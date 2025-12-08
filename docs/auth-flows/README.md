# LFX One Authentication Flows

This directory contains sequence diagrams documenting the authentication flows used in LFX One.

## Overview

The authentication architecture uses multiple Auth0 clients and flows to support different use cases:

- **SSR Client**: Used for server-side rendering authentication with LFX v2 API access
- **LFX One Profile Client**: Used for social account linking and self-service Auth0 access (user profile updates)
- **LFX One Passwordless Client**: Used for passwordless email linking flow via Auth Service. This client supports the OTP grant type and may use different validation in the postLogin action.
- **Auth Service M2M Client**: Machine-to-machine client used by Auth Service for reading user profiles

## Authentication Flows

| Flow | Description | Client Used | Audience | Purpose |
|------|-------------|-------------|----------|---------|
| [Flow A](A-auth-service-m2m-profile-lookup.md) | Auth Service M2M | Auth Service M2M | `auth0_mgmt` | Read user profiles and check email-to-username mappings |
| [Flow B](B-lfx-one-login-ssr-oidc.md) | LFX One Login (SSR OIDC) | SSR Client | `lfxv2` | Authenticate users and obtain access tokens for LFX v2 API |
| [Flow C](C-auth-service-m2m-profile-update.md) | Self-Service Profile Updates | LFX One Profile | `auth0_mgmt` | Allow users to update their own profiles via Management API |
| [Flow D](D-spa-social-identity-linking.md) | Social Identity Linking | LFX One Profile | None | Link social identities (Google, GitHub, etc.) to user accounts |
| [Flow E](E-passwordless-email-linking.md) | Email Identity Linking | LFX One Passwordless | None | Link additional email addresses using passwordless OTP verification |

## Client Descriptions

### SSR Client
The main server-side rendering client used for user authentication. This client obtains access tokens with the `lfxv2` audience for accessing the LFX v2 API (Traefik/Heimdall).

### LFX One Profile Client
This client is used for social account linking and self-service Auth0 access. It allows users to update their own profiles through the Auth0 Management API with restricted permissions (users can only modify their own data).

### LFX One Passwordless Client
A specialized client used for the passwordless email linking flow, primarily by the Auth Service. This client supports the OTP grant type and may use different validation logic in the postLogin action compared to other clients.

### Auth Service M2M Client
A machine-to-machine client with `read:users` permissions (but **not** `update:users`) used by the Auth Service to read user profiles and check email mappings.

## Token Overview

| Token | Audience | Scope | Used For |
|-------|----------|-------|----------|
| `access_token_m2m_read` | `auth0_mgmt` | `read:users` | Auth Service reading user profiles (Flow A) |
| `access_token_lfxv2` | `lfxv2` | LFX v2 API | Calling LFX v2 API endpoints (Flow B) |
| `access_token_mgmt_self` | `auth0_mgmt` | `update:users` (self only) | User updating their own profile (Flow C, D, E) |
| `access_token_social` | `/userinfo` | N/A | Ignored - returned from social auth (Flow D) |
| `access_token_pwdless` | `/userinfo` | N/A | Ignored - returned from passwordless (Flow E) |
| `id_token_user` | N/A | N/A | User identity from main login (Flow B) |
| `id_token_mgmt` | N/A | N/A | Ignored - returned from mgmt flow (Flow C) |
| `id_token_social` | N/A | N/A | Social provider identity (Flow D) |
| `id_token_pwdless` | N/A | N/A | Passwordless email identity (Flow E) |

## Key Architecture Patterns

### NATS Pub/Sub
Auth Service uses NATS for communication with LFX One SSR, subscribing to subjects for:
- Profile lookup requests
- Profile update requests
- Email linking requests
- Social identity linking requests

### Auth Service Abstraction
All Auth0 Management API calls are abstracted through the Auth Service, which communicates with LFX One via NATS. This provides:
- Centralized token management
- Simplified client-side code
- Better security (Management API credentials stay in Auth Service)

### Token Validation
Flow C includes a critical validation step (C5) where the SSR validates that the `id_token_user` from Flow B and the `access_token_mgmt_self` from Flow C have the same subject (`sub` claim), ensuring the user requesting profile updates is the authenticated user.

## Flow Dependencies

- **Flow C, D, E** all depend on **Flow B** (user must be logged in first)
- **Flow D and E** both use `access_token_mgmt_self` from **Flow C** to perform identity linking operations
- **Flow A** is independent and used by Auth Service for background operations

## Security Considerations

1. **Principle of Least Privilege**: Auth Service M2M client only has `read:users`, not `update:users`
2. **Subject Validation**: Flow C validates token subjects match before allowing profile updates
3. **Email Verification**: Flow E validates the email in `id_token_pwdless` matches the requested email before linking
4. **Token Scoping**: Each access token is scoped to specific audiences and permissions
5. **Abstraction Layer**: Management API calls go through Auth Service, not directly from client

