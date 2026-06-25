# Auth0 Integration

This package provides Auth0 integration for the LFX v2 Auth Service, implementing user management operations through the Auth0 Management API.

## Overview

The Auth0 integration takes a JWT token and validates/retrieves user data from the Auth0 identity provider. The system parses the JWT token to extract user identification information and performs lookups through the Auth0 Management API.

## Token Support

The Auth0 integration supports JWT (JSON Web Token) parsing to extract user identification information. When a JWT token is provided as input, the system automatically extracts the `sub` (subject) claim and uses it for user lookups.

### JWT Token Processing

**Token Format:** JWT tokens issued by Auth0

**Token Structure:**
```json
{
  "iss": "https://{{tenant}}.auth0.com/",
  "sub": "auth0|user123",
  "aud": "https://{{tenant}}.auth0.com/api/v2/",
  "iat": 1759751739,
  "exp": 1759755339,
  "scope": "read:current_user",
  "azp": "O8sQ4Jbr3At8buVR3IkrTRlejPZFWenI"
}
```

### Token Processing Flow

1. **Token Validation**: Validates the JWT token signature and expiration
2. **Sub Extraction**: Extracts the `sub` claim from the token payload
3. **User Lookup**: Uses the extracted `sub` value for direct user lookup via Auth0 Management API
4. **Auth0 API Call**: Performs direct user lookup using the `sub` identifier
5. **User Data Retrieval**: Returns user metadata from Auth0

### Auth0 Management API Integration

**Canonical Lookup (Recommended):**
```http
GET /api/v2/users/{sub}
```

**Search Lookup (Convenience):**
```http
GET /api/v2/users?q=identities.user_id:{username} AND identities.connection:Username-Password-Authentication
```

### Important Notes

- **JWT Signature Validation**: Full JWT signature validation is performed using Auth0's public keys
- **Token Expiration**: JWT tokens are validated for expiration and freshness
- **Auth0 Management API**: Uses Auth0's Management API for user data retrieval

## Email Verification for Alternate Email Linking

The Auth0 integration uses Auth0's Passwordless Authentication API to verify ownership of alternate email addresses through an OTP (One-Time Password) flow.

### Auth0 Passwordless Authentication Flow

The verification and linking process consists of three Auth0 API calls:

#### 1. Send Verification Code

**Auth0 API Endpoint:** `POST https://{auth0-domain}/passwordless/start`

**Request:**
```json
{
  "client_id": "{client_id}",
  "connection": "email",
  "email": "alternate-email@example.com",
  "send": "code"
}
```

**Response:**
```json
{
  "_id": "session-id",
  "email": "alternate-email@example.com",
  "email_verified": false
}
```

**Auth0 Behavior:**
- Sends a **6-digit OTP code** via email to the specified address
- Uses the configured email template for passwordless authentication
- OTP code is typically valid for **5-10 minutes**
- Creates a passwordless session identified by `_id`

#### 2. Verify OTP and Exchange for Token

**Auth0 API Endpoint:** `POST https://{auth0-domain}/oauth/token`

**Request:**
```json
{
  "grant_type": "http://auth0.com/oauth/grant-type/passwordless/otp",
  "client_id": "{client_id}",
  "username": "alternate-email@example.com",
  "otp": "123456",
  "realm": "email",
  "scope": "openid email profile"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "id_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 86400,
  "scope": "openid email profile"
}
```

**Auth0 Behavior:**
- Validates the OTP against the passwordless session
- Returns standard OAuth 2.0 token set upon successful verification
- ID token contains claims about the verified email address
- OTP is single-use and expires after the time limit

#### 3. Link Identity to User Account

**Auth0 API Endpoint:** `POST https://{auth0-domain}/api/v2/users/{user_id}/identities`

**Request Headers:**
```
Authorization: Bearer {user_management_api_token}
Content-Type: application/json
```

**Request Body:**
```json
{
  "link_with": "eyJhbGciOiJSUzI1NiIs..."
}
```

**Response:**
```json
[
  {
    "connection": "email",
    "user_id": "alternate-email@example.com",
    "provider": "email",
    "isSocial": false,
    "profileData": {
      "email": "alternate-email@example.com",
      "email_verified": true
    }
  }
]
```

**Auth0 Behavior:**
- Links the verified email identity to the existing user account
- Uses the ID token from step 2 to identify the verified email
- Requires user's JWT token with `update:current_user_identities` scope
- Does NOT change the user's current global session
- Returns array of all linked identities for the user

**Important Notes:**
- The Auth Service uses the **user's JWT token** (not the service's M2M credentials) to authenticate the API call
- This ensures the operation is performed with user-level permissions
- The `link_with` field contains the ID token from the passwordless verification flow
- This approach prevents session hijacking by maintaining the user's current authentication state

### Set Primary Email

**Auth0 API Endpoint:** `PATCH https://{auth0-domain}/api/v2/users/{user_id}` with `{"email": "...", "email_verified": true}` (M2M token).

The target email must already be a **verified** linked `email`-connection identity on the account.

**Preserve-then-promote:** the PATCH overwrites the user's root `email`, which would leave the previous
primary unreachable as an email/OTP login if it was not already backed by a suitable identity. To avoid
this, before the PATCH the adapter preserves the previous primary:

- No preservation is needed when the previous primary is empty, equals the new email, or is already
  backed by a **sufficient** identity for that address:
  - an `email`-connection identity (any verification state) — it is OTP-reachable and self-verifies on
    the next login, and a duplicate cannot be created, so an existing email identity is always
    sufficient.
- Otherwise — backed only by a social/enterprise identity (Google, GitHub, LinkedIn, enterprise, …),
  which is a login method and never a primary-email candidate, or no backing identity at all — the
  adapter creates a stub passwordless `email` user for the previous primary and links it via
  `POST /api/v2/users/{user_id}/identities` (M2M direct-link) as a **verified, user-removable** identity
  (no `app_metadata.system_managed`), so the user can later unlink it.

Preservation runs first and is fail-loud: if it fails, the just-created stub is rolled back (best-effort)
and the PATCH is **not** performed, leaving the account unchanged rather than dropping the old primary.

This shares its create+link mechanics with the system-managed alias flow (`AddSystemManagedEmail`); the
only difference is that the preserved old primary is **not** marked `system_managed`.

### NATS Integration

The email verification and linking functionality is exposed via three NATS subjects:

- **`lfx.auth-service.email_linking.send_verification`**: Initiates the passwordless flow
- **`lfx.auth-service.email_linking.verify`**: Validates OTP and returns ID token
- **`lfx.auth-service.user_identity.link`**: Links the verified email identity to the user account

**Token Processing for Identity Linking:**
- The Auth Service parses the user's JWT token (`user_token`) to extract the `user_id` from the `sub` claim
- Validates the JWT signature using Auth0's public keys
- Verifies the token has the required `update:current_user_identities` scope
- Uses the extracted `user_id` to make the identity linking API call with the `link_with` ID token

### Security & Rate Limiting

**Auth0 Security Features:**
- OTP codes are time-limited (typically 5 minutes)
- Each OTP code is single-use

**Service-Level Validation:**
- Checks if email is already linked to another user account
- Prevents duplicate alternate email addresses
- Validates email format before initiating passwordless flow
