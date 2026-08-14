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

// CDPMetadataReader reads a user's stored CDP enrichment record.
type CDPMetadataReader interface {
	ReadCDPMetadata(ctx context.Context, userID string) (CDPMetadata, error)
}

// CDPMetadataWriter writes a user's CDP enrichment record.
//
// Implementations MUST enforce that a stored UUID is write-once: absent to
// present is the only legal transition, and a rejection is a caller-guard bug
// rather than a data problem.
type CDPMetadataWriter interface {
	WriteCDPMetadata(ctx context.Context, userID string, record CDPMetadata) error
}

// CDPMetadataReaderWriter combines the CDP metadata read and write sides.
type CDPMetadataReaderWriter interface {
	CDPMetadataReader
	CDPMetadataWriter
}
