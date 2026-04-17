# User Emails Operations

This document describes the NATS subject for retrieving user email addresses.

---

## User Emails Retrieval

To retrieve user email addresses (both primary and alternate emails), send a NATS request to the following subject:

**Subject:** `lfx.auth-service.user_emails.read`  
**Pattern:** Request/Reply

### Request Payload

```json
{
  "user": {
    "auth_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

### Request Fields

- `user.auth_token` (string, required): A valid JWT token identifying the authenticated user

### Reply

The service returns a structured reply with user email information:

**Success Reply:**
```json
{
  "success": true,
  "data": {
    "primary_email": "john.doe@example.com",
    "alternate_emails": [
      {
        "email": "john.doe@example.com",
        "verified": true
      },
      {
        "email": "john.doe@personal.com",
        "verified": true
      },
      {
        "email": "j.doe@company.com",
        "verified": false
      }
    ]
  }
}
```

The `alternate_emails` array contains every email identity linked to the user (Auth0 connection `email`), **including the primary email**. Callers identify the primary by matching an entry's `email` field to the top-level `primary_email`.

**Success Reply (No Email Identities):**
```json
{
  "success": true,
  "data": {
    "primary_email": "john.doe@example.com",
    "alternate_emails": []
  }
}
```

**Error Reply (User Not Found):**
```json
{
  "success": false,
  "error": "user not found"
}
```

**Error Reply (Invalid Token):**
```json
{
  "success": false,
  "error": "invalid token"
}
```

### Response Fields

- `primary_email` (string): The user's primary email address registered with the identity provider
- `alternate_emails` (array): Every email identity linked to the user account via the `email` connection — **including the primary**. To find the primary entry, match `email` against `primary_email`.
  - `email` (string): The email address
  - `verified` (boolean): Whether the email has been verified

### Example using NATS CLI

```bash
nats request lfx.auth-service.user_emails.read '{"user":{"auth_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}}'
```

### Example Response Processing

```bash
# Get and format the response
nats request lfx.auth-service.user_emails.read '{"user":{"auth_token":"<token>"}}' | jq '.'

# Extract only the primary email
nats request lfx.auth-service.user_emails.read '{"user":{"auth_token":"<token>"}}' | jq -r '.data.primary_email'

# List all verified alternate emails
nats request lfx.auth-service.user_emails.read '{"user":{"auth_token":"<token>"}}' | jq -r '.data.alternate_emails[] | select(.verified == true) | .email'

# Count total email identities (primary is already included in alternate_emails)
nats request lfx.auth-service.user_emails.read '{"user":{"auth_token":"<token>"}}' | jq '.data.alternate_emails | length'
```

**Important Notes:**
- The target identity provider is determined by the `USER_REPOSITORY_TYPE` environment variable
- Primary email is always present if the user exists
- Alternate emails array may be empty if the user has not linked any additional email addresses
- Only verified alternate emails should be considered as confirmed user identities
- For detailed Auth0-specific behavior and limitations, see: [`../internal/infrastructure/auth0/README.md`](../internal/infrastructure/auth0/README.md)
- For detailed Authelia-specific behavior and SUB management, see: [`../internal/infrastructure/authelia/README.md`](../internal/infrastructure/authelia/README.md)

---

## Set Primary Email

To change a user's primary email address, send a NATS request to the following subject:

**Subject:** `lfx.auth-service.user_emails.set_primary`  
**Pattern:** Request/Reply

The caller must provide a valid JWT token and the email address to promote to primary. The email must already be a verified alternate email on the user's account.

### Request Payload

```json
{
  "user": {
    "auth_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
  },
  "email": "new-primary@example.com"
}
```

### Request Fields

- `user.auth_token` (string, required): A valid JWT token identifying the authenticated user
- `email` (string, required): The email address to set as the new primary; must be a verified alternate email on the account

### Reply

**Success Reply:**
```json
{
  "success": true,
  "message": "primary email updated successfully"
}
```

**Error Reply (Email Not Linked):**
```json
{
  "success": false,
  "message": "email is not a linked identity on this account"
}
```

**Error Reply (Email Not Verified):**
```json
{
  "success": false,
  "message": "email is not verified and cannot be set as primary"
}
```

**Error Reply (Missing Token):**
```json
{
  "success": false,
  "message": "auth_token is required"
}
```

**Error Reply (Missing Email):**
```json
{
  "success": false,
  "message": "email is required"
}
```

**Error Reply (Invalid Email Format):**
```json
{
  "success": false,
  "message": "invalid email format"
}
```

### Example using NATS CLI

```bash
# Set a new primary email for the authenticated user
nats request lfx.auth-service.user_emails.set_primary \
  '{"user": {"auth_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}, "email": "new-primary@example.com"}'
```

### Important Notes

- Requires the `update:current_user_identities` scope in the JWT
- The target email must already exist as a verified alternate email on the user's account; it cannot be an arbitrary new address
- The email input is normalized to lowercase before processing; matching is case-insensitive
- After a successful update, the previous primary email becomes an alternate email on the account
- For detailed Auth0-specific behavior, see: [`../internal/infrastructure/auth0/README.md`](../internal/infrastructure/auth0/README.md)

### Provider Support

| Provider | Support |
|----------|---------|
| Auth0    | Full    |
| Authelia | Not implemented |
| Mock     | Simulated (mutates in-memory store) |

---

## Use Cases

### Identity Verification
When you need to verify if a user owns a specific email address:
```bash
# Get all user emails
nats request lfx.auth-service.user_emails.read '{"user":{"auth_token":"<token>"}}'
```

### Email Communication
When you need to send notifications to all verified user email addresses:
```bash
# Extract all verified emails (primary is already in alternate_emails)
nats request lfx.auth-service.user_emails.read '{"user":{"auth_token":"<token>"}}' | \
  jq -r '.data.alternate_emails[] | select(.verified == true) | .email'
```

### Account Recovery
When displaying email options for account recovery:
```bash
# Show all verified email addresses for recovery selection
nats request lfx.auth-service.user_emails.read '{"user":{"auth_token":"<token>"}}' | \
  jq '.data.alternate_emails[] | select(.verified == true)'
```

### Email Uniqueness Check
To check if an email is already associated with a user account, use the email lookup subjects:
- `lfx.auth-service.email_to_username` - Get username from email
- `lfx.auth-service.email_to_sub` - Get user ID from email

See [`email_lookups.md`](email_lookups.md) for more details on these subjects.

---

## Related Subjects

- **Email Lookup**: [`email_lookups.md`](email_lookups.md)
- **Email Verification**: [`email_verification.md`](email_verification.md)
- **User Metadata**: [`user_metadata.md`](user_metadata.md)
- **Identity Linking**: [`identity_linking.md`](identity_linking.md)
- **Password Management**: [`password_management.md`](password_management.md)

