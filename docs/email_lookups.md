# Email Lookup Operations

This document describes NATS subjects for looking up user information by email address.

---

## Email to Username Lookup

To look up a username by email address, send a NATS request to the following subject:

**Subject:** `lfx.auth-service.email_to_username`  
**Pattern:** Request/Reply

### Request Payload

The request payload should be a plain text email address (no JSON wrapping required):

```
user@example.com
```

### Reply

The service returns the username as plain text if the email is found:

**Success Reply:**
```
john.doe
```

**Error Reply:**
```json
{
  "success": false,
  "error": "user not found"
}
```

### Example using NATS CLI

```bash
# Look up username by email
nats request lfx.auth-service.email_to_username zephyr.stormwind@mythicaltech.io

# Expected response: zephyr.stormwind
```

**Important Notes:**
- This service searches for users by their **primary email** only
- Linked/alternate email addresses are **not** supported for lookup
- The service works with Auth0, Authelia, and mock repositories based on configuration

---

## Email to Subject Identifier Lookup

To look up a subject identifier by email address, send a NATS request to the following subject:

**Subject:** `lfx.auth-service.email_to_sub`  
**Pattern:** Request/Reply

### Request Payload

The request payload should be a plain text email address (no JSON wrapping required):

```
user@example.com
```

### Reply

The service returns the subject identifier as plain text if the email is found:

**Success Reply:**
```
auth0|123456789
```

**Error Reply:**
```json
{
  "success": false,
  "error": "user not found"
}
```

### Example using NATS CLI

```bash
# Look up subject identifier by email
nats request lfx.auth-service.email_to_sub zephyr.stormwind@mythicaltech.io

# Expected response: auth0|zephyr001
```

**Important Notes:**
- This service searches for users by their **primary email** only
- Linked/alternate email addresses are **not** supported for lookup
- The service works with Auth0, Authelia, and mock repositories based on configuration
- The returned subject identifier is the canonical user identifier used throughout the system
- For Authelia-specific SUB identifier details and how they are populated, see: [`../internal/infrastructure/authelia/README.md`](../internal/infrastructure/authelia/README.md)

