// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package model

// LinkIdentity represents a request to link a verified email identity to a user account.
type LinkIdentity struct {
	// User contains the authenticated user's information needed to authorize the linking action.
	User struct {
		// AuthToken is the JWT token with the proper scope to link an identity to a user account.
		AuthToken string `json:"auth_token"`
	} `json:"user"`

	// LinkWith contains the identity information of the user to be linked.
	LinkWith struct {
		// IdentityToken is the ID token obtained from the passwordless verification flow.
		IdentityToken string `json:"identity_token"`
	} `json:"link_with"`
}
