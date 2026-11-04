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
| `query` | string | Free text: part of a username, email, or name. Terms are separated by whitespace or any character outside the allowed set (see Matching) |
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

- The query is lowercased and split into terms on any character outside the allowlist below (for example whitespace or a comma). Each term of 3 or more characters is a **prefix** match on `name`, `given_name`, `family_name`, `username` or `email`; all terms must match (AND), so `john smith` and `smith john` both find John Smith.
- A term containing `@` is matched against `email` only.
- `identities.user_id` is not searched by prefix, because Auth0 rejects a wildcard on that field and the whole search would fail. An LFID that is held only in a linked database identity (and differs from the root `username`) is found by typing it exactly, through the exact lookup below.
- Terms shorter than 3 characters are ignored (the caller is usually still typing them). At least one term of 3 or more characters is required. At most 4 such terms are accepted (short words such as "de" or "la" do not count), at most 10 words overall, and the query may be at most 200 characters.
- Only letters, digits and `. _ - + ' @` are accepted in a term; any other character separates terms (so `smith, john` is two terms). This is an allowlist because Auth0 search is Lucene syntax with operators, such as the `<` and `>` range operators, that cannot be escaped. The allowed characters that are Lucene operators (`-` and `+`) are escaped, so input is only ever a literal prefix.
- Only accounts with an LFID (a `Username-Password-Authentication` identity) are returned, and the `username` in a result is that identity's `user_id`, not the root username (which for a linked account can belong to another connection). A numeric `user_id` is used as its digits, and an account whose database identity has no usable `user_id` is left out. Results are ordered exact username, exact email, username prefix, email prefix, then other matches, because Auth0 does not rank results.
- Auth0 returns an unranked page, so when many accounts share a prefix the exact one may not be in it. For a single-term query the service therefore also looks up the exact username, matched against both the root `username` and `identities.user_id` (or, for a term with `@`, the exact email) and merges it into the results before ranking. For several terms there is no single exact value, so only the prefix query runs. If the exact lookup fails, the prefix results are returned.

### Important Notes

- The `subject_token` is authorized exactly as for the token exchange (signature, issuer, expiry, LFX V2 audience, and `http://lfx.dev/claims/can_impersonate` set to boolean `true`) **before** anything is sent to Auth0. A request that fails any check gets an error reply and no search is performed; validation of `query` happens only after authorization.
- The search runs with the service's M2M client (`read:users` on the Management API), not with the caller's token, so results are not limited to what the caller could see. This lets any impersonator find any user by prefix; it is why the check above matters.
- The service never logs the query text or returned emails. Its log records only the caller's (redacted) subject, the number of terms and the number of results. The Management API requests for this subject are also kept out of traces, because client spans would record the request URL, which includes the search terms.
- Failures to obtain the M2M token or to reach Auth0 reply with the fixed message `user search is unavailable`; details stay in the server log.
- Auth0 user search is eventually consistent, returns at most 1,000 matches, and times out (HTTP 503) after about 2 seconds. A search that fails or times out replies `user search is unavailable`; the upstream error is not forwarded because it can echo the query. Callers should debounce, and may retry.
- Searches share the M2M client's Management API rate limit with login and profile flows. There is currently no per-caller rate limit in this service, so callers (for example the UI backend) should rate-limit.
- Only available when the Auth0 provider is active.
