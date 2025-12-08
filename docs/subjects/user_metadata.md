# User Metadata Operations

This document describes NATS subjects for retrieving and updating user metadata.

---

## User Metadata Retrieval

To retrieve user metadata, send a NATS request to the following subject:

**Subject:** `lfx.auth-service.user_metadata.read`  
**Pattern:** Request/Reply

The service supports a **hybrid approach** for user metadata retrieval, accepting multiple input types and automatically determining the appropriate lookup strategy based on the input format.

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

The service returns a structured reply with user metadata:

**Success Reply:**
```json
{
  "success": true,
  "data": {
    "name": "John Doe",
    "given_name": "John",
    "family_name": "Doe",
    "job_title": "Software Engineer",
    "organization": "Example Corp",
    "country": "United States",
    "state_province": "California",
    "city": "San Francisco",
    "address": "123 Main Street",
    "postal_code": "94102",
    "phone_number": "+1-555-0123",
    "t_shirt_size": "L",
    "picture": "https://example.com/avatar.jpg",
    "zoneinfo": "America/Los_Angeles"
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

### Example using NATS CLI

```bash
# Retrieve user metadata using JWT token
nats request lfx.auth-service.user_metadata.read "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

# Retrieve user metadata using subject identifier
nats request lfx.auth-service.user_metadata.read "auth0|123456789"

# Retrieve user metadata using username
nats request lfx.auth-service.user_metadata.read "john.doe"
```

**Important Notes:**
- The service automatically detects input type and applies the appropriate lookup strategy
- JWT tokens are validated for signature and expiration before extracting subject information
- The target identity provider is determined by the `USER_REPOSITORY_TYPE` environment variable
- For detailed Auth0-specific behavior and limitations, see: [`../internal/infrastructure/auth0/README.md`](../internal/infrastructure/auth0/README.md)
- For detailed Authelia-specific behavior and SUB management, see: [`../internal/infrastructure/authelia/README.md`](../internal/infrastructure/authelia/README.md)

---

## User Update Operation

To update a user profile, send a NATS request to the following subject:

**Subject:** `lfx.auth-service.user_metadata.update`  
**Pattern:** Request/Reply

### Request Payload

The request payload must be a JSON object containing the user data to update. The `token` field is **required** for authentication and authorization.

```json
{
  "token": "eyJhbG...",
  "user_id": "auth0|zephyr001",
  "username": "zephyr.stormwind",
  "primary_email": "zephyr.stormwind@mythicaltech.io",
  "user_metadata": {
    "name": "Zephyr Stormwind",
    "given_name": "Zephyr",
    "family_name": "Stormwind",
    "job_title": "Cloud Architect",
    "organization": "Mythical Tech Solutions",
    "country": "Aetheria",
    "state_province": "Skylands",
    "city": "Nimbus City",
    "address": "42 Celestial Tower, Cloud District",
    "postal_code": "90210",
    "phone_number": "+1-555-STORM-01",
    "t_shirt_size": "M",
    "picture": "https://avatars.mythicaltech.io/zephyr.jpg",
    "zoneinfo": "Aetheria/Skylands"
  }
}
```

### Required Fields

- `token`: JWT authentication token (required for all requests)
- `user_metadata`: Object containing additional user profile information

### Reply

The service returns a structured reply indicating success or failure:

**Success Reply:**
```json
{
  "success": true,
  "data": {
    "name": "Zephyr Stormwind",
    "given_name": "Zephyr",
    "family_name": "Stormwind",
    "job_title": "Cloud Architect",
    "organization": "Mythical Tech Solutions",
    "country": "Aetheria",
    "state_province": "Skylands",
    "city": "Nimbus City",
    "address": "42 Celestial Tower, Cloud District",
    "postal_code": "90210",
    "phone_number": "+1-555-STORM-01",
    "t_shirt_size": "M",
    "picture": "https://avatars.mythicaltech.io/zephyr.jpg",
    "zoneinfo": "Aetheria/Skylands"
  }
}
```

**Error Reply:**
```json
{
  "success": false,
  "error": "username is required"
}
```

### Example using NATS CLI

```bash
# Update user profile
nats request lfx.auth-service.user_metadata.update '{
  "token": "eyJhbG...",
  "user_metadata": {
    "name": "Aurora Moonbeam",
    "job_title": "Senior DevOps Enchanter"
  }
}'
```

**Important Notes:**
- The service works with Auth0, Authelia, and mock repositories based on configuration

