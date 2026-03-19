# Email Verification Flow

The auth service provides a two-step verification flow for verifying ownership of alternate email addresses. This flow validates that the user controls the email address and provides an ID token that can be used for identity linking.

## Complete Email Verification and Linking Flow

The following diagram shows the complete three-step flow for verifying an alternate email address and linking it to a user account.

> **Auth0 flow** — OTP is delivered and validated by Auth0's passwordless service.

```mermaid
sequenceDiagram
    participant User
    participant SSRApp
    participant AuthService
    participant Auth0

    Note over User,Auth0: Step 1: Start Email Verification Flow

    User->>SSRApp: Request to link alternate email
    SSRApp->>AuthService: NATS: email_linking.send_verification<br/>(alternate email)

    AuthService->>AuthService: Validate email format
    AuthService->>AuthService: Check email doesn't exist<br/>(primary or alternate)

    AuthService->>Auth0: Start Passwordless Flow<br/>(send OTP to email)
    Auth0-->>User: Email with OTP code
    Auth0-->>AuthService: Success
    AuthService-->>SSRApp: {"success": true,<br/>"message": "verification sent"}
    SSRApp-->>User: Show OTP input modal

    Note over User,Auth0: Step 2: Verify Email with OTP

    User->>SSRApp: Submit OTP code
    SSRApp->>AuthService: NATS: email_linking.verify<br/>(email + OTP)

    AuthService->>AuthService: Validate email format
    AuthService->>AuthService: Check email still doesn't exist<br/>(prevent race condition)

    AuthService->>Auth0: Exchange OTP for ID token<br/>(using service credentials)
    Auth0-->>AuthService: ID token
    AuthService-->>SSRApp: {"success": true,<br/>"data": {"token": "..."}}

    Note over User,Auth0: Step 3: Link Identity to User

    SSRApp->>AuthService: NATS: user_identity.link<br/>(user_token, link_with)
    AuthService->>AuthService: Parse JWT token<br/>(extract user_id from 'sub')
    AuthService->>Auth0: POST /users/{id}/identities<br/>(using user's token)
    Auth0-->>AuthService: Linked identities
    AuthService-->>SSRApp: {"success": true,<br/>"message": "identity linked"}
    SSRApp-->>User: Email linked successfully
```

> **Authelia flow** — OTP is generated and validated internally; no external provider call is made.

```mermaid
sequenceDiagram
    participant User
    participant SSRApp
    participant AuthService
    participant NATSKV

    Note over User,NATSKV: Step 1: Start Email Verification Flow

    User->>SSRApp: Request to link alternate email
    SSRApp->>AuthService: NATS: email_linking.send_verification<br/>(alternate email)

    AuthService->>AuthService: Validate email format
    AuthService->>AuthService: Check email doesn't exist<br/>(primary or alternate)

    AuthService->>AuthService: Generate OTP
    AuthService->>NATSKV: Store OTP (with TTL)
    AuthService->>User: Send OTP via SMTP
    AuthService-->>SSRApp: {"success": true,<br/>"message": "verification sent"}
    SSRApp-->>User: Show OTP input modal

    Note over User,NATSKV: Step 2: Verify Email with OTP

    User->>SSRApp: Submit OTP code
    SSRApp->>AuthService: NATS: email_linking.verify<br/>(email + OTP)

    AuthService->>NATSKV: Retrieve stored OTP
    AuthService->>AuthService: Compare OTP — generate internal ID token<br/>(sub: "email|<email>", signed by auth-service)
    AuthService-->>SSRApp: {"success": true,<br/>"data": {"token": "..."}}

    Note over User,NATSKV: Step 3: Link Identity to User

    SSRApp->>AuthService: NATS: user_identity.link<br/>(user_token, link_with)
    AuthService->>AuthService: Parse identity_token sub<br/>("email|..." → email flow)
    AuthService->>NATSKV: Append email to user's alternate_emails<br/>(optimistic concurrency)
    AuthService-->>SSRApp: {"success": true,<br/>"message": "identity linked"}
    SSRApp-->>User: Email linked successfully
```

**Flow Steps:**
- **Step 1-2:** Email verification process (documented below)
- **Step 3:** Identity linking - see [Identity Linking Documentation](identity_linking.md)

---

## Step 1: Send Verification Code

To initiate the email verification process, send a NATS request to start the passwordless flow:

**Subject:** `lfx.auth-service.email_linking.send_verification`  
**Pattern:** Request/Reply

### Request Payload

The request payload should be a plain text email address (no JSON wrapping required):

```
alternate-email@example.com
```

### Reply

The service sends a one-time password (OTP) to the provided email address and returns a success confirmation:

**Success Reply:**
```json
{
  "success": true,
  "message": "alternate email verification sent"
}
```

**Error Reply (Email Already Linked):**
```json
{
  "success": false,
  "error": "alternate email already linked"
}
```

**Error Reply (Invalid Email):**
```json
{
  "success": false,
  "error": "alternate email is required"
}
```

### Example using NATS CLI

```bash
# Send verification code to alternate email
nats request lfx.auth-service.email_linking.send_verification "john.personal@gmail.com"

# Expected response: {"success":true,"message":"alternate email verification sent"}
```

**Important Notes:**
- The service checks if the email is already linked to any user account before sending the verification code
- An OTP code is available to be used for a valid time period

---

## Step 2: Verify Email with OTP

After receiving the OTP code via email, verify the email address by exchanging the OTP for authentication tokens:

**Subject:** `lfx.auth-service.email_linking.verify`  
**Pattern:** Request/Reply

### Request Payload

The request payload must be a JSON object containing the email address and the OTP code:

```json
{
  "email": "john.personal@gmail.com",
  "otp": "123456"
}
```

### Required Fields

- `email`: The email address that received the verification code
- `otp`: The one-time password code sent to the email

### Reply

The service validates the OTP and returns authentication tokens if successful:

**Success Reply:**
```json
{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

The returned token is an authentication token that can be used to link the verified email to the user's account.

**Error Reply (Invalid OTP):**
```json
{
  "success": false,
  "error": "failed to exchange OTP for token"
}
```

**Error Reply (Email Already Linked):**
```json
{
  "success": false,
  "error": "alternate email already linked"
}
```

**Error Reply (Invalid Request):**
```json
{
  "success": false,
  "error": "failed to unmarshal email data"
}
```

### Example using NATS CLI

```bash
# Verify the alternate email with OTP code
nats request lfx.auth-service.email_linking.verify '{
  "email": "john.personal@gmail.com",
  "otp": "123456"
}'

# Expected response: {"success":true,"data":{"token":"eyJhbG..."}}
```

**Important Notes:**
- OTP codes are time-sensitive and available for a valid time period
- The service prevents linking an email that is already verified and linked to another user
- The returned token (ID token) can be used to link the verified email to the user account using the identity linking operation (see [Identity Linking Documentation](identity_linking.md))
- For detailed Auth0-specific implementation details and technical information about the passwordless flow, see: [`../internal/infrastructure/auth0/README.md`](../internal/infrastructure/auth0/README.md)

---

## Implementation Notes by Provider

### Auth0

The OTP is delivered via Auth0's passwordless email flow. After verification, Auth0 issues a standard ID token that is returned directly to the caller and passed to `user_identity.link`.

### Authelia

The Authelia flow is fully self-contained — no external provider is called:

1. **Send verification** (`email_linking.send_verification`): The auth-service generates a random OTP, emails it via the configured SMTP sender, and stores the OTP in the NATS KV email-OTP bucket with a TTL.
2. **Verify OTP** (`email_linking.verify`): The auth-service reads the stored OTP from NATS KV and compares it against the submitted code. On success, it generates an **internal ID token** (signed with the auth-service's own key) with:
   - `email` claim set to the verified email address
   - `sub` claim set to `email|<email-address>`
3. **Link identity** (`user_identity.link`): The `sub` prefix `email|` signals the email flow — the verified email is appended to the user's `alternate_emails` in NATS KV using optimistic concurrency.

### Mock

The Mock flow is fully self-contained — no NATS KV or SMTP is involved:

1. **Send verification** (`email_linking.send_verification`): Generates a 6-digit OTP stored in-memory with a 5-minute TTL. The OTP is logged to stdout (no email is sent).
2. **Verify OTP** (`email_linking.verify`): Compares the submitted code against the in-memory entry. On success, generates an **internal ID token** with `sub: "email|<email-address>"` — identical sub format to the Authelia flow.
3. **Link identity** (`user_identity.link`): Same `email|` dispatch — the verified email is appended to the user's `alternate_emails` in the in-memory store.

