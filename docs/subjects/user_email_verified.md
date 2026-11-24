# User Email Verified Event

This document describes the NATS event published when a user is first seen with a verified primary email.

---

## Overview

Services sometimes hold data keyed by email for a person who does not yet have an LFX account, such as a role granted to an email address before sign-up. This event tells those services that the email now belongs to a real account, so they can reconcile their data.

**Subject:** `lfx.auth-service.user_email_verified`
**Pattern:** Publish / Subscribe (fire-and-forget, core NATS; no reply)

## Payload

```json
{
  "username": "jane.doe",
  "email": "jane.doe@example.com",
  "timestamp": "2026-11-24T12:00:00Z"
}
```

| Field | Description |
|---|---|
| `username` | The user's LFID |
| `email` | The user's verified primary email |
| `timestamp` | When the event was published (UTC) |

## When it is published

The Auth0 events consumer (the same stream that drives CDP provisioning) publishes the event for a `user.created` or `user.updated` event when all of these hold, checked against the user's current Auth0 record rather than the stream payload:

- the primary email is verified;
- the user's primary identity is the database connection, so the username is an LFID;
- the user has not been announced before.

After a successful publish, the service records `email_verified_announced_at` on the user's Auth0 `app_metadata`. That marker keeps the event to once per user, and lets the consumer skip already-announced users from the stream payload without an extra Management API call.

## Delivery

- **Best-effort, at-least-once.** A failed publish is logged and retried on the user's next stream event. If the publish succeeds but the marker write fails, the user can be announced again, so subscribers must be idempotent.
- **Core NATS.** A subscriber that is down or reconnecting when the event is published does not receive it.
- **Requires the consumer.** The event is published only while the Auth0 events consumer runs, so `PROVISIONING_CONSUMER_ENABLED` and the CDP configuration it depends on must be set.
- **Existing users.** Users who verified before this event existed are announced the next time the stream emits an event for them. There is no separate backfill.

## Security

The event travels over an unauthenticated bus, so subscribers should treat it as a hint. Before acting on it, resolve `email` through `lfx.auth-service.email_to_username` (see [Email Lookups](email_lookups.md)) and require the result to match `username`.
