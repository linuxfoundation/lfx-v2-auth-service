# Impersonation

Allows a caller to exchange their own access token for one representing a different (target) user, using Auth0's Custom Token Exchange (CTE) grant.

---

## Token Exchange

Exchanges the caller's LFX V2 access token for an access token representing a target user.

**Subject:** `lfx.auth-service.impersonation.token_exchange`
**Pattern:** Request/Reply

### Request Payload

```json
{
  "subject_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "target_user": "user@example.com"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `subject_token` | string | The caller's valid LFX V2 access token |
| `target_user` | string | Email or username of the user to impersonate |

### Reply

**Success Reply:**
```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

**Error Reply:**
```json
{
  "success": false,
  "error": "error message"
}
```

### Example using NATS CLI

```bash
nats request lfx.auth-service.impersonation.token_exchange \
  '{"subject_token":"<your-access-token>","target_user":"user@example.com"}'
```

### Important Notes

- Both `subject_token` and `target_user` are required. The request will fail with a validation error if either is missing or blank.
- The `subject_token` must be a valid, unexpired LFX V2 access token. It must carry the claim `"http://lfx.dev/claims/can_impersonate": true` — enforcement of this requirement is the responsibility of the upstream caller before sending the request.
- `target_user` can be an email address or username. The service resolves it to an Auth0 user before performing the exchange.
- This feature is only available when the Auth0 provider is active. The Authelia and mock providers do not support impersonation.
- Internally, the service uses Auth0's `urn:ietf:params:oauth:grant-type:token-exchange` grant with a signed client-assertion JWT (RS256).
