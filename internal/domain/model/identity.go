// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package model

// Identity represents a linked identity from an external provider.
type Identity struct {
	Provider   string `json:"provider"`        // e.g. "google-oauth2", "linkedin", "github"
	IdentityID string `json:"identity_id"`     // provider-specific user ID (part after "|" in Auth0)
	Email      string `json:"email,omitempty"` // email from the provider's profileData, if available
	IsSocial   bool   `json:"is_social"`
}

// LinkIdentity represents a request to link a verified email identity to a user account.
type LinkIdentity struct {
	// User contains the authenticated user's information needed to authorize the linking action.
	User struct {
		// UserID is the ID of the user to be linked.
		UserID string `json:"user_id"`
		// AuthToken is the JWT token with the proper scope to link an identity to a user account.
		AuthToken string `json:"auth_token"`
	} `json:"user"`

	// LinkWith contains the identity information of the user to be linked.
	LinkWith struct {
		// IdentityToken is the ID token obtained from the passwordless verification flow.
		IdentityToken string `json:"identity_token"`
	} `json:"link_with"`
}

// UnlinkIdentity represents a request to unlink a secondary identity from a user account.
type UnlinkIdentity struct {
	// User contains the authenticated user's information needed to authorize the unlinking action.
	User struct {
		// UserID is the primary user's ID, populated from the auth_token sub claim.
		UserID string `json:"user_id"`
		// AuthToken is the JWT token with the update:current_user_identities scope.
		AuthToken string `json:"auth_token"`
	} `json:"user"`

	// Unlink contains the secondary identity to be removed.
	Unlink struct {
		// Provider is the identity provider of the secondary account (e.g. "google-oauth2", "auth0").
		Provider string `json:"provider"`
		// IdentityID is the identity's user_id as returned by the identity provider (the part after the "|").
		IdentityID string `json:"identity_id"`
	} `json:"unlink"`
}
