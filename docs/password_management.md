# Password Management Operations

This document describes the NATS subjects for managing user passwords: changing a password and sending a password reset link.

---

## Change Password

To change a user's password, send a NATS request to the following subject:

**Subject:** `lfx.auth-service.password.update`  
**Pattern:** Request/Reply

The caller must provide a valid JWT token along with the user's current password and the desired new password. The service validates the current password before applying the update.

### Request Payload

```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "current_password": "OldPassword123!",
  "new_password": "NewPassword456!"
}
```

### Request Fields

- `token` (string, required): A valid JWT token identifying the authenticated user
- `current_password` (string, required): The user's current password
- `new_password` (string, required): The desired new password

### Reply

**Success Reply:**
```json
{
  "success": true,
  "message": "password changed successfully"
}
```

**Error Reply (Incorrect Current Password):**
```json
{
  "success": false,
  "message": "current password is incorrect"
}
```

**Error Reply (Invalid Token):**
```json
{
  "success": false,
  "message": "invalid token"
}
```

**Error Reply (Unsupported Account Type):**
```json
{
  "success": false,
  "message": "password change requires an Auth0 user with a username"
}
```

### Example using NATS CLI

```bash
# Change password for authenticated user
nats request lfx.auth-service.password.update \
  '{"token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...", "current_password": "OldPassword123!", "new_password": "NewPassword456!"}'
```

### Important Notes

- Requires the `update:current_user_metadata` scope in the JWT
- Only supported for Auth0 username-password connection accounts (`auth0|` prefix); social login accounts (Google, GitHub, etc.) cannot use this endpoint
- The current password is validated via Auth0's Resource Owner Password Grant before the update is applied
- Password requirements (minimum length, complexity) are enforced by Auth0 and may cause the update to fail if not met
- For detailed Auth0-specific behavior, see: [`../internal/infrastructure/auth0/README.md`](../internal/infrastructure/auth0/README.md)

### Provider Support

| Provider | Support |
|----------|---------|
| Auth0    | Full    |
| Authelia | Not implemented |
| Mock     | Stub (returns success without validation) |

---

## Send Reset Password Link

To send a password reset email to a user, send a NATS request to the following subject:

**Subject:** `lfx.auth-service.password.reset_link`  
**Pattern:** Request/Reply

The caller must provide a valid JWT token. The service looks up the user's primary email address and triggers Auth0 to send a password reset email.

### Request Payload

```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### Request Fields

- `token` (string, required): A valid JWT token identifying the authenticated user

### Reply

**Success Reply:**
```json
{
  "success": true,
  "message": "reset password link sent"
}
```

**Error Reply (Invalid Token):**
```json
{
  "success": false,
  "message": "invalid token"
}
```

**Error Reply (No Email Address):**
```json
{
  "success": false,
  "message": "user does not have an email address"
}
```

### Example using NATS CLI

```bash
# Send password reset link for authenticated user
nats request lfx.auth-service.password.reset_link \
  '{"token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}'
```

### Important Notes

- Requires the `update:current_user_metadata` scope in the JWT
- The reset email is sent to the user's primary email address on file
- Email delivery is handled by Auth0 via the `/dbconnections/change_password` endpoint
- The reset link expires according to Auth0 tenant configuration (typically 24 hours)
- This operation succeeds even if the user's account uses a social login provider; Auth0 will handle the email gracefully
- For detailed Auth0-specific behavior, see: [`../internal/infrastructure/auth0/README.md`](../internal/infrastructure/auth0/README.md)

### Provider Support

| Provider | Support |
|----------|---------|
| Auth0    | Full    |
| Authelia | Not implemented |
| Mock     | Stub (returns success without sending email) |

---

## Related Subjects

- **User Emails**: [`user_emails.md`](user_emails.md)
- **User Metadata**: [`user_metadata.md`](user_metadata.md)
- **Identity Linking**: [`identity_linking.md`](identity_linking.md)
