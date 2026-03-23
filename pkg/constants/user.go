// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package constants

const (
	// CriteriaTypeEmail is the type of criteria for email
	CriteriaTypeEmail = "email"
	// CriteriaTypeUsername is the type of criteria for username
	CriteriaTypeUsername = "username"
	// CriteriaTypeAlternateEmail is the type of criteria for alternate email
	CriteriaTypeAlternateEmail = "alternate_email"
)

const (
	// UserUpdateMetadataRequiredScope is the Auth0 scope required to update the current user's metadata.
	UserUpdateMetadataRequiredScope = "update:current_user_metadata"
	// UserUpdateIdentityRequiredScope is the Auth0 scope required to link or unlink identities for the current user.
	UserUpdateIdentityRequiredScope = "update:current_user_identities"
)
