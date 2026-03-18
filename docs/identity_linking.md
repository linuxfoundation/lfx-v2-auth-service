# User Identity Linking

This document describes the NATS subjects for linking and unlinking identities (social providers, email, etc.) to and from user accounts.

---

## Important Notes

- The `user_id` is automatically extracted from the `sub` claim of `user.auth_token` — it does not need to be provided explicitly
- The Auth Service uses the **user's token** (not the service's M2M credentials) to call the identity provider, ensuring the operation is scoped to the user's own permissions
- These subjects are **only supported for Auth0**. Authelia and mock implementations do not support this functionality yet.

---

## Link Identity

Links a verified identity to the user's account. The identity can come from any provider (e.g. Google, LinkedIn, GitHub) or from the email verification flow — in which case the `identity_token` is the ID token received after successfully verifying an email address.

**Subject:** `lfx.auth-service.user_identity.link`
**Pattern:** Request/Reply

### Request Payload

```json
{
  "user": {
    "auth_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
  },
  "link_with": {
    "identity_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

### Required Fields

- `user.auth_token`: A JWT access token with the `update:current_user_identities` scope.
- `link_with.identity_token`: The ID token representing the identity to be linked. For the email verification flow, this is the token received after completing the OTP verification step.

### Reply

**Success:**
```json
{
  "success": true,
  "message": "identity linked successfully"
}
```

**Error:**
```json
{
  "success": false,
  "error": "<error message>"
}
```

### Example using NATS CLI

```bash
nats request lfx.auth-service.user_identity.link '{
  "user": {
    "auth_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
  },
  "link_with": {
    "identity_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}'
```

---

## Unlink Identity

Removes a secondary identity (e.g. Google, LinkedIn, GitHub) from the user's account.

**Subject:** `lfx.auth-service.user_identity.unlink`
**Pattern:** Request/Reply

### Request Payload

```json
{
  "user": {
    "auth_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
  },
  "unlink": {
    "provider": "linkedin",
    "identity_id": "QhNK44iR6W"
  }
}
```

### Required Fields

- `user.auth_token`: A JWT access token with the `update:current_user_identities` scope.
- `unlink.provider`: The identity provider to unlink (e.g. `google-oauth2`, `linkedin`, `github`).
- `unlink.identity_id`: The identity's ID as returned by the identity provider. This must be retrieved directly from the identity provider since there is no dedicated subject for listing identities at this time.

### Reply

**Success:**
```json
{
  "success": true,
  "message": "identity unlinked successfully"
}
```

**Error:**
```json
{
  "success": false,
  "error": "<error message>"
}
```

### Example using NATS CLI

```bash
nats request lfx.auth-service.user_identity.unlink '{
  "user": {
    "auth_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
  },
  "unlink": {
    "provider": "linkedin",
    "identity_id": "QhNK44iR6W"
  }
}'
```

---

## Email Verification Flow

When linking an email identity, `lfx.auth-service.user_identity.link` is used as the final step after completing the OTP verification. For the complete flow see [Email Verification Documentation](email_verification.md#complete-email-verification-and-linking-flow).
