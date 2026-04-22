// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package constants

// NATS Key-Value store bucket names.
const (
	// KVBucketNameAutheliaUsers is the name of the KV bucket for authelia users.
	KVBucketNameAutheliaUsers = "authelia-users"

	// KVBucketNameAutheliaEmailOTP is the name of the KV bucket for authelia email OTPs.
	KVBucketNameAutheliaEmailOTP = "authelia-email-otp"

	// KVBucketNameUsernameSubCache is the name of the KV bucket for caching username → sub lookups.
	KVBucketNameUsernameSubCache = "auth-service-username-sub-cache"

	// KVLookupPrefixAuthelia is the prefix for lookup keys in the KV store.
	KVLookupPrefixAuthelia = "lookup/authelia-users/%s"
)
