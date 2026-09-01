// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package constants

import "time"

// Auth0 `app_metadata` keys holding the CDP enrichment record.
//
// These MUST stay identical to the block at the top of
// `apps/auth0-terraform/src/actions/cdp_uuid.js`. The login Action writes the
// same three keys directly through `api.user.setAppMetadata`, so a rename on
// one side lands a value under a key the other side never reads.
const (
	// CDPUUIDKey holds the resolved CDP member id.
	CDPUUIDKey = "cdp_uuid"

	// CDPUUIDSourceKey records which path produced the record. It is present
	// even when no member was found, which is what lets the login path
	// suppress a re-check for the TTL.
	//
	// It does NOT mark a user as finished: provisioning gates on the UUID, so
	// somebody previously recorded as having no CDP member is retried once
	// they verify their email and become eligible.
	CDPUUIDSourceKey = "cdp_uuid_source"

	// CDPUUIDCheckedAtKey is the RFC3339 timestamp of the last CDP check.
	CDPUUIDCheckedAtKey = "cdp_uuid_checked_at"
)

// Allowed values for CDPUUIDSourceKey.
const (
	// CDPUUIDSourceBackfill marks a value written by the out-of-band sweep.
	CDPUUIDSourceBackfill = "backfill"

	// CDPUUIDSourceLoginResolve marks a value written by the login Action.
	CDPUUIDSourceLoginResolve = "login-resolve"

	// CDPUUIDSourceProvisioning marks a value written by the provisioning flow.
	CDPUUIDSourceProvisioning = "provisioning"
)

// CDP environment variable keys.
const (
	// CDPBaseURLEnvKey is the base URL of the CDP public API.
	CDPBaseURLEnvKey = "CDP_BASE_URL"

	// CDPAudienceEnvKey is the M2M audience for the CDP public API.
	CDPAudienceEnvKey = "CDP_AUDIENCE"

	// ProvisioningConsumerEnabledEnvKey switches on the Auth0 events consumer.
	// Off unless explicitly enabled, so a deployment that has not been
	// configured for it does not open a stream.
	ProvisioningConsumerEnabledEnvKey = "PROVISIONING_CONSUMER_ENABLED"

	// ProvisioningReplayWindowEnvKey bounds how far back the consumer restarts
	// when it has no usable offset. See DefaultProvisioningReplayWindow.
	ProvisioningReplayWindowEnvKey = "PROVISIONING_REPLAY_WINDOW"

	// Auth0EventsHostEnvKey overrides the host the events stream is read from.
	// Unset means Auth0DomainEnvKey, which in production is the tenant's
	// custom domain.
	Auth0EventsHostEnvKey = "AUTH0_EVENTS_HOST"
)

// DefaultProvisioningReplayWindow is how far back the consumer restarts with
// no usable offset — a cold start, or an offset Auth0 has aged out.
//
// Auth0 does not publish how long it retains offsets, so this is chosen for
// the asymmetry rather than fitted to a documented window: re-reading is cheap
// because the gate skips anyone already provisioned, while reading too little
// loses users outright. The login self-heal and the population sweep remain
// the floor either way.
const DefaultProvisioningReplayWindow = 24 * time.Hour

// LFIDPlatform is the CDP identity platform for a Linux Foundation ID.
const LFIDPlatform = "lfid"

// CDPIdentityTypeUsername is the CDP identity type for a username identity.
const CDPIdentityTypeUsername = "username"

// CDPIdentitySource identifies this service as the origin of an identity it
// creates in CDP.
const CDPIdentitySource = "lfxV2AuthService"

// DatabaseConnection is the Auth0 database connection name. Only users holding
// an identity on this connection carry an LFID username, which
// `/v1/members/resolve` requires (FR-012, FR-017).
const DatabaseConnection = "Username-Password-Authentication"
