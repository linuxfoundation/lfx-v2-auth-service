# Alias Operations

This document describes the NATS subject for claiming a system-managed alias (e.g. `@linux.com`) as a verified secondary email on a user account.

An alias is a system-managed Auth0 identity linked onto the caller's primary user. Once claimed it is **immutable** — the unlink path refuses to remove it. Each user may hold at most one alias per allowed domain.

The target domain is supplied per-request and must be present in the server-side `ALLOWED_ALIAS_DOMAINS` allow-list. This lets production run with `linux.com` while dev/staging environments use their own test domains, without any caller able to claim aliases on arbitrary domains.

---

## Add Alias

**Subject:** `lfx.auth-service.add_alias`
**Pattern:** Request/Reply

### Request Payload

```json
{
  "user": {
    "auth_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
  },
  "alias": "jane.doe",
  "domain": "linux.com"
}
```

### Request Fields

- `user.auth_token` (string, required): A valid JWT identifying the caller. Must carry the `update:current_user_identities` scope.
- `alias` (string, required): The local part of the desired address. Do not include `@` or the domain suffix.
- `domain` (string, required): The domain to claim under. Must be present (case-insensitive) in the server's `ALLOWED_ALIAS_DOMAINS` env list, otherwise the request is rejected with `domain_not_allowed`.

### Reply

**Success Reply:**
```json
{
  "success": true,
  "email": "jane.doe@linux.com"
}
```

The returned `email` is the canonical, lowercased form of the claimed alias.

**Error Reply:**
```json
{
  "success": false,
  "error": "alias_invalid"
}
```

### Error Codes

| Code | Meaning |
|------|---------|
| `domain_not_allowed` | The requested `domain` is missing, empty, or not present in `ALLOWED_ALIAS_DOMAINS` |
| `alias_invalid` | The alias is empty, too long (>64 chars), contains banned characters, or fails RFC 5322 canonicalisation |
| `alias_reserved` | The alias matches a reserved name (built-in list or `AUTH0_ALIAS_RESERVED_EXTRA`) |
| `alias_not_available` | The full `<alias>@<domain>` address is already linked to another user (also returned on a race during claim) |
| `already_claimed` | The caller already has an alias on this domain as primary, linked identity, or alternate email |
| `alias service unavailable` | The current backend does not support alias claims (e.g. Authelia) |
| `auth service unavailable` | The user reader is not wired |
| `auth_token is required` | Missing `user.auth_token` in the request |
| `failed to unmarshal request` | Request JSON is malformed |

Operational errors from the backend (Auth0 outage, M2M token failure, etc.) propagate their raw message rather than mapping to one of the codes above.

### Validation Rules

**Domain (`request.domain`):**
- Lowercased and trimmed on read
- Must be non-empty and present in `ALLOWED_ALIAS_DOMAINS` (case-insensitive)
- Empty/unset env → feature is disabled, every claim fails with `domain_not_allowed`

**Alias local part (`request.alias`):**

The alias is normalised by trimming whitespace and lower-casing, then validated as follows:

- **Length**: 1–64 characters after trimming
- **Banned characters**: `"`, `/`, `*`, `$`, `^`, `:`, `@`, space, `;`, and other characters that would break RFC 5322 local parts or allow quoted-form bypass
- **RFC 5322 round-trip**: the input is reconstructed as `<norm>@<domain>` and parsed with `net/mail.ParseAddress`; the canonical form must equal the reconstructed string. This guards against the quoted-local-part bypass (e.g. `"admin"`)
- **Reserved names** (case-insensitive, applied on every domain): `postmaster`, `abuse`, `hostmaster`, `admin`, `administrator`, `noreply`, `no-reply`, `root`, `mailer-daemon`, `linux`, `linuxfoundation`, `lf`, `security`, `support`, `info`, `webmaster`, `ops`, `devops`, `itx-system`
- **Extra reserved names**: any entry in the comma-separated `AUTH0_ALIAS_RESERVED_EXTRA` environment variable is added to the reserved list (case-insensitive)

### System-Managed Semantics

When a claim succeeds, the Auth0 adapter:

1. Creates a passwordless **stub user** on the `email` connection with `email_verified: true` and `app_metadata.system_managed: true` via `POST /api/v2/users`.
2. Links the stub onto the caller's primary user via `POST /api/v2/users/{primary}/identities`.
3. If the link step fails, performs a best-effort rollback by deleting the orphaned stub.

The `system_managed` flag lives on the **stub user record**, which continues to exist after the link (Auth0 transplants the identity entry into the primary's `identities` array but the stub record stays around at its original `user_id`).

### Why `provider: "email"`?

The linked identity reports `provider: "email"` because Auth0's `provider` field maps to a fixed set of connection **strategies** (`auth0`, `email`, `sms`, `google-oauth2`, etc.) — it is not a free-form label this service controls. The passwordless `email` strategy is the right fit for system-managed aliases (no password, pre-verified, linkable as a secondary).

To distinguish a system-managed alias from a regular email identity, callers should either:

- Check the email suffix against `ALLOWED_ALIAS_DOMAINS`, **or**
- Fetch the stub user record and check `app_metadata.system_managed == true`.

### Unlink Guard

A subsequent `lfx.auth-service.user_identity.unlink` call targeting an `email`-connection identity triggers the immutability guard in the Auth0 adapter:

1. Non-`email` providers (oauth2/social) short-circuit and proceed normally.
2. For `email` providers, the adapter fetches the stub user record via M2M (`GET /api/v2/users/email|<id>`).
3. **Fail-closed**: any non-404 fetch error returns an `Unexpected` error so a flaky Auth0 cannot silently allow the unlink.
4. If `app_metadata.system_managed == true`, the adapter returns `errors.NewForbidden("system_managed_identity")`.

The mock adapter mirrors this guard: any `email`-connection entry in `user.Identities` is by construction system-managed (only `AddSystemManagedEmail` writes there), so the mock refuses the unlink with the same error.

### Surfacing in `user_emails.read`

Once linked, the alias appears in the `alternate_emails` array returned by `lfx.auth-service.user_emails.read`, alongside any other email-connection identities on the account.

### Example using NATS CLI

```bash
# Production (ALLOWED_ALIAS_DOMAINS=linux.com)
nats request lfx.auth-service.add_alias \
  '{"user":{"auth_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."},"alias":"jane.doe","domain":"linux.com"}'

# Dev (ALLOWED_ALIAS_DOMAINS=dev.lfx.example)
nats request lfx.auth-service.add_alias \
  '{"user":{"auth_token":"..."},"alias":"jane.doe","domain":"dev.lfx.example"}'
```

### Provider Support

| Provider | Support |
|----------|---------|
| Auth0    | Full — creates a system-managed stub on the `email` connection, links it, and rolls back on link failure |
| Mock     | Simulated — appends an `email`-connection identity and enforces the same unlink guard |
| Authelia | Not supported — returns `alias service unavailable` |

### Environment Configuration

| Variable | Purpose | Default |
|---|---|---|
| `ALLOWED_ALIAS_DOMAINS` | Comma-separated list of domains permitted as alias suffix. Case-insensitive. Empty/unset disables the feature. | _(unset → disabled)_ |
| `AUTH0_ALIAS_RESERVED_EXTRA` | Comma-separated list of additional reserved local parts on top of the built-in list. Case-insensitive. | _(unset)_ |

### Required Auth0 Configuration

The `lfx_v2_auth_service` M2M application must hold the following scopes on the Management API:

- `read:users` — search for existing claims, fetch stub for the unlink guard
- `create:users` — create the stub
- `update:users` — link the stub identity onto the primary user
- `delete:users` — rollback an orphaned stub on link failure

These scopes are provisioned via the companion `auth0-terraform` repository — see `grants_auth0v2.tf` for the `lfx_v2_auth_service` grant.

### Important Notes

- Requires the `update:current_user_identities` scope in the JWT.
- The domain is caller-supplied and validated against the server-side allow-list — there is no implicit default.
- Each user may hold at most one alias **per allowed domain**. With multiple domains in the allow-list, a user could in principle claim one alias on each (e.g. `jane@linux.com` and `jane@dev.lfx.example`).
- A successful claim is immutable from the user's perspective: only an administrator with direct Auth0 access can flip `app_metadata.system_managed` and remove the alias.
- For detailed Auth0-specific behavior and limitations, see: [`../internal/infrastructure/auth0/README.md`](../internal/infrastructure/auth0/README.md)

---

## Related Subjects

- **Identity Linking** (general link/unlink/list flow): [`identity_linking.md`](identity_linking.md)
- **User Emails** (where the alias surfaces): [`user_emails.md`](user_emails.md)
- **Email Lookups**: [`email_lookups.md`](email_lookups.md)
- **User Metadata**: [`user_metadata.md`](user_metadata.md)
