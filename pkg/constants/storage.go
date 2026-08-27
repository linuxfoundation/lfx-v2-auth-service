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

	// KVBucketNameProvisioningCursor is the name of the KV bucket holding the
	// Auth0 events stream offset.
	KVBucketNameProvisioningCursor = "cdp-provisioning-cursor"

	// KVKeyProvisioningCursor is the single key in that bucket. One consumer
	// reads one stream, so there is nothing to partition on.
	KVKeyProvisioningCursor = "offset"
)

// LeaseNameProvisioningConsumer is the Kubernetes Lease the replicas compete
// for. Only its holder reads the Auth0 events stream.
const LeaseNameProvisioningConsumer = "lfx-v2-auth-service-provisioning"
