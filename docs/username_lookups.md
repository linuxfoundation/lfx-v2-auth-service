# Username Lookup Operations

This document describes NATS subjects for looking up user information by username.

---

## Username to Subject Identifier Lookup

To look up a subject identifier by username, send a NATS request to the following subject:

**Subject:** `lfx.auth-service.username_to_sub`
**Pattern:** Request/Reply

### Request Payload

The request payload should be a plain text username (no JSON wrapping required):

```
john.doe
```

### Reply

The service returns the subject identifier as plain text if the username is found:

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
# Look up subject identifier by username
nats request lfx.auth-service.username_to_sub zephyr.stormwind

# Expected response: auth0|zephyr001
```

**Important Notes:**
- Usernames are matched exactly (case-sensitive, no normalization applied)
- Leading/trailing whitespace in the request payload is trimmed automatically
- The service works with Auth0, Authelia, and mock repositories based on configuration
- The returned subject identifier is the canonical user identifier used throughout the system
- For Authelia-specific SUB identifier details and how they are populated, see: [`../internal/infrastructure/authelia/README.md`](../internal/infrastructure/authelia/README.md)
