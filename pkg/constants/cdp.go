// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package constants

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

	// ProvisioningWebhookSecretEnvKey is the static bearer secret the Auth0
	// Event Stream presents on the provisioning webhook. The webhook
	// destination supports static-secret auth only, so this is the whole of
	// the endpoint's authorization.
	ProvisioningWebhookSecretEnvKey = "PROVISIONING_WEBHOOK_SECRET"
)

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
