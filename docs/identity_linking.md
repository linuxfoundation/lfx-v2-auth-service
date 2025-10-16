# User Identity Linking

This document describes the NATS subject for linking verified identities to user accounts.

---

## Link Verified Email Identity

After successfully verifying an email address and receiving an ID token, link the verified email identity to the user's account.

**Subject:** `lfx.auth-service.user_identity.link`  
**Pattern:** Request/Reply

### Request Payload

The request payload must be a JSON object containing the user's JWT token and the ID token from the email verification step:

```json
{
  "user_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "link_with": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### Required Fields

- `user_token`: A JWT access token for the Auth0 Management API with the `update:current_user_identities` scope. The `user_id` will be automatically extracted from the `sub` claim of this token.
- `link_with`: The ID token obtained from the email verification process that contains the verified email identity

### Reply

The service links the verified email identity to the user account without changing the user's current global session:

**Success Reply:**
```json
{
  "success": true,
  "message": "identity linked successfully"
}
```

**Error Reply (Invalid Token):**
```json
{
  "success": false,
  "error": "jwt verify failed for link identity"
}
```

**Error Reply (Link Failed):**
```json
{
  "success": false,
  "error": "failed to link identity to user"
}
```

### Example using NATS CLI

```bash
# Link the verified email identity to the user account
nats request lfx.auth-service.user_identity.link '{
  "user_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "link_with": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}'

# Expected response: {"success":true,"message":"identity linked successfully"}
```

### Important Notes

- The SSR application must provide the user's JWT token (`user_token`) with the `update:current_user_identities` scope
- The Auth Service automatically extracts the `user_id` from the `sub` claim of the user's token
- The Auth Service verifies the JWT token signature and validates the required scope before processing
- The Auth Service uses the **user's token** (not the service's M2M credentials) to call the Auth0 Management API
- This ensures the operation is performed with the user's permissions and does not change their current global session
- The `link_with` field contains the ID token from the email verification process with the verified email information that will be linked to the user account
- This feature is **only supported for Auth0**. Authelia and mock implementations do not support this functionality yet.

### Complete Flow

For a complete understanding of how this operation fits into the email verification and linking flow, see the [Email Verification Documentation](email_verification.md#complete-email-verification-and-linking-flow) which includes a comprehensive flow diagram showing all three steps (Steps 1-2: Email Verification, Step 3: Identity Linking).

