// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package port

import "context"

// CDPMetadata is the CDP enrichment record stored on an Auth0 user's
// `app_metadata`.
//
// UUID is empty when the user has been checked but no CDP member matched; the
// presence of Source is what marks the user as checked.
type CDPMetadata struct {
	UUID      string
	Source    string
	CheckedAt string
}

// UserProvisioningState is the authoritative view of a user, read from Auth0
// rather than taken from an event payload.
//
// A stream event carries a snapshot taken when it was produced, which may be
// stale by the time it is read and may be replayed after a reconnect — and the
// fields below decide whether this service writes to CDP on a user's behalf, so
// they are re-read before any write rather than believed.
type UserProvisioningState struct {
	CDPMetadata

	// EmailVerified is the user's current verification state.
	EmailVerified bool

	// Email is the user's current primary email, usable as a secondary
	// resolve identifier only when EmailVerified is true.
	Email string

	// Name is the user's display name, used to seed a new CDP member.
	Name string

	// Username is the LFID. It is populated only when the user's primary
	// identity is the database connection, since another connection's
	// username is not an LFID.
	Username string

	// HasDatabaseIdentity reports whether the user holds an identity on the
	// Auth0 database connection.
	HasDatabaseIdentity bool
}

// CDPMetadataReader reads a user's stored CDP enrichment record.
type CDPMetadataReader interface {
	ReadCDPMetadata(ctx context.Context, userID string) (CDPMetadata, error)

	// ReadProvisioningState returns the fields the provisioning gate depends
	// on, in one call.
	ReadProvisioningState(ctx context.Context, userID string) (UserProvisioningState, error)
}

// CDPMetadataWriter writes a user's CDP enrichment record.
//
// Implementations reject a change to a stored UUID: absent to present is the
// only legal transition, and a rejection is a caller-guard bug rather than a
// data problem.
//
// This is best-effort, not atomic. The check is a read followed by a write, and
// the Auth0 Management API offers no compare-and-set on `app_metadata`, so two
// writers can both observe an absent UUID and both proceed.
type CDPMetadataWriter interface {
	WriteCDPMetadata(ctx context.Context, userID string, record CDPMetadata) error
}

// CDPMetadataReaderWriter combines the CDP metadata read and write sides.
type CDPMetadataReaderWriter interface {
	CDPMetadataReader
	CDPMetadataWriter
}
