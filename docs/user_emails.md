# User Emails Operations

This document describes the NATS subject for retrieving user email addresses.

---

## User Emails Retrieval

To retrieve user email addresses (both primary and alternate emails), send a NATS request to the following subject:

**Subject:** `lfx.auth-service.user_emails.read`  
**Pattern:** Request/Reply

The service supports a **hybrid approach** for user email retrieval, accepting multiple input types and automatically determining the appropriate lookup strategy based on the input format.

### Hybrid Input Support

The service intelligently handles different input types:

1. **JWT Tokens** (Auth0) or **Authelia Tokens** (Authelia)
2. **Subject Identifiers** (canonical user IDs)
3. **Usernames**

### Request Payload

The request payload can be any of the following formats (no JSON wrapping required):

**JWT Token (Auth0):**
```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Subject Identifier:**
```
auth0|123456789
```

**Username:**
```
john.doe
```

### Lookup Strategy

The service automatically determines the lookup strategy based on input format:

- **Token Strategy**: If input is a JWT/Authelia token, validates the token and extracts the subject identifier
- **Canonical Lookup**: If input contains `|` (pipe character) or is a UUID, treats as subject identifier for direct lookup
- **Username Search**: If input doesn't match above patterns, treats as username for search lookup

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

**Success Reply (No Alternate Emails):**
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
- `alternate_emails` (array): List of alternate email addresses linked to the user account
  - `email` (string): The alternate email address
  - `verified` (boolean): Whether the alternate email has been verified

### Example using NATS CLI

```bash
# Retrieve user emails using JWT token
nats request lfx.auth-service.user_emails.read "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

# Retrieve user emails using subject identifier
nats request lfx.auth-service.user_emails.read "auth0|123456789"

# Retrieve user emails using username
nats request lfx.auth-service.user_emails.read "john.doe"
```

### Example Response Processing

```bash
# Get and format the response
nats request lfx.auth-service.user_emails.read "john.doe" | jq '.'

# Extract only the primary email
nats request lfx.auth-service.user_emails.read "john.doe" | jq -r '.data.primary_email'

# List all verified alternate emails
nats request lfx.auth-service.user_emails.read "john.doe" | jq -r '.data.alternate_emails[] | select(.verified == true) | .email'

# Count total email addresses (primary + alternates)
nats request lfx.auth-service.user_emails.read "john.doe" | jq '.data.alternate_emails | length + 1'
```

**Important Notes:**
- The service automatically detects input type and applies the appropriate lookup strategy
- JWT tokens are validated for signature and expiration before extracting subject information
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
nats request lfx.auth-service.user_emails.read "john.doe"
```

### Email Communication
When you need to send notifications to all verified user email addresses:
```bash
# Extract all verified emails (primary + verified alternates)
nats request lfx.auth-service.user_emails.read "john.doe" | \
  jq -r '(.data.primary_email, (.data.alternate_emails[] | select(.verified == true) | .email))'
```

### Account Recovery
When displaying email options for account recovery:
```bash
# Show all verified email addresses for recovery selection
nats request lfx.auth-service.user_emails.read "auth0|123456789" | \
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

