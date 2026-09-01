// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package constants

// NATS Key-Value store bucket names.
const (
	// KVBucketNameAutheliaUsers is the name of the KV bucket for authelia users.
	KVBucketNameAutheliaUsers = "authelia-users"

	// KVBucketNameAutheliaEmailOTP is the name of the KV bucket for authelia email OTPs.
	KVBucketNameAutheliaEmailOTP = "authelia-email-otp"

	// KVLookupPrefixAuthelia is the prefix for lookup keys in the KV store.
	KVLookupPrefixAuthelia = "lookup/authelia-users/%s"

	// KVBucketNameProvisioningCursor is the default name of the KV bucket
	// holding the Auth0 events stream offset. Override with
	// ProvisioningCursorBucketEnvKey when the chart renders a different name.
	KVBucketNameProvisioningCursor = "cdp-provisioning-cursor"

	// ProvisioningCursorBucketEnvKey overrides the offset bucket name so the
	// chart value and the bucket the consumer opens cannot drift apart.
	ProvisioningCursorBucketEnvKey = "PROVISIONING_CURSOR_BUCKET"

	// KVKeyProvisioningCursor is the single key in that bucket. One consumer
	// reads one stream, so there is nothing to partition on.
	KVKeyProvisioningCursor = "offset"

	// KVBucketNameSweepCursor is the default name of the KV bucket holding the
	// population sweep's cursor. Override with SweepCursorBucketEnvKey when the
	// chart renders a different name.
	KVBucketNameSweepCursor = "cdp-sweep-cursor"

	// SweepCursorBucketEnvKey overrides the sweep cursor bucket name so the
	// chart value and the bucket the sweep opens cannot drift apart.
	SweepCursorBucketEnvKey = "SWEEP_CURSOR_BUCKET"

	// KVKeySweepCursor is the single key in that bucket.
	//
	// There is exactly one cursor in this feature and it belongs to the
	// full-cohort sweep. The no-match re-check re-derives its population from
	// marker presence on every run and stores nothing, which is what lets a
	// user reappear the moment their CDP answer changes.
	KVKeySweepCursor = "cursor"
)

// LeaseNameProvisioningConsumer is the Kubernetes Lease the replicas compete
// for. Only its holder reads the Auth0 events stream.
const LeaseNameProvisioningConsumer = "lfx-v2-auth-service-provisioning"
