# User Search

Searches Auth0 for users by LFID (username), email, or name. It covers every user in the tenant who has an LFID, not only members of a committee. It exists to let an impersonator (see [Impersonation](impersonation.md)) find the user to act as.

**Access:** callers must present an access token carrying the `http://lfx.dev/claims/can_impersonate` claim. This is a tenant-wide user lookup, so the subject is not open to other callers; a use case with different permissions needs its own subject.

**Whose token:** the search is the searcher's own action, so `subject_token` must be the signed-in admin's **own** access token, never the token of a user they are currently impersonating. This applies when picking the first user to impersonate and again when switching to another user while impersonating. The service cannot tell the two apart (any valid token carrying `can_impersonate` is accepted), so callers must resolve the admin's real token. The caller recorded in the audit log is that token's subject.

**Subject:** `lfx.auth-service.user.search`
**Pattern:** Request/Reply

### Request Payload

```json
{
  "subject_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "query": "john smith",
  "limit": 10
}
```

| Field | Type | Description |
|-------|------|-------------|
| `subject_token` | string | The caller's valid LFX V2 access token (same requirements as the [impersonation token exchange](impersonation.md)) |
| `query` | string | Free text: part of a username, email, or name. Whitespace separates terms |
| `limit` | integer | Optional. Maximum results; defaults to 10, capped at 20 |

### Reply

**Success Reply:**
```json
{
  "success": true,
  "users": [
    { "user_id": "auth0|abc123", "username": "jsmith", "name": "John Smith", "email": "john@example.com" }
  ]
}
```

`users` is an empty array when nothing matches. `email` is omitted when the identity provider has not verified it.

**Error Reply:**
```json
{
  "success": false,
  "error": "error message"
}
```

### Example using NATS CLI

```bash
nats request lfx.auth-service.user.search \
  '{"subject_token":"<your-access-token>","query":"john smith"}'
```

### Matching

- The query is split on whitespace and lowercased. Each term of 3 or more characters is a **prefix** match on `name`, `given_name`, `family_name`, `username` or `email`; all terms must match (AND), so `john smith` and `smith john` both find John Smith.
- A term containing `@` is matched against `email` only.
- Terms shorter than 3 characters are ignored (the caller is usually still typing them). At least one term of 3 or more characters is required, and at most 4 terms are accepted; the query may be at most 200 characters.
- Lucene operator characters in the input are escaped, so input is only ever a literal prefix.
- Only accounts with an LFID (a `Username-Password-Authentication` identity) are returned. Results are ordered exact username, exact email, username prefix, email prefix, then other matches, because Auth0 does not rank results.

### Important Notes

- The `subject_token` is authorized exactly as for the token exchange (signature, issuer, expiry, LFX V2 audience, and `http://lfx.dev/claims/can_impersonate` set to boolean `true`) **before** anything is sent to Auth0. A request that fails any check gets an error reply and no search is performed; validation of `query` happens only after authorization.
- The search runs with the service's M2M client (`read:users` on the Management API), not with the caller's token, so results are not limited to what the caller could see. This lets any impersonator find any user by prefix; it is why the check above matters.
- The query text and returned emails are never logged. The log records only the caller's (redacted) subject, the number of terms and the number of results.
- Auth0 user search is eventually consistent, returns at most 1,000 matches, and times out (HTTP 503) after about 2 seconds. A search that fails or times out replies `user search is unavailable`; the upstream error is not forwarded because it can echo the query. Callers should debounce, and may retry.
- Searches share the M2M client's Management API rate limit with login and profile flows. There is currently no per-caller rate limit in this service, so callers (for example the UI backend) should rate-limit.
- Only available when the Auth0 provider is active.
