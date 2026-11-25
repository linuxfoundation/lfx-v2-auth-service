// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package model

// UserSearchResult is the minimal view of a user returned by an impersonation
// user search. It carries only what a picker needs to identify an account.
type UserSearchResult struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Name     string `json:"name,omitempty"`
	// Email is set only when the identity provider has verified it, so an
	// unverified address a user typed at signup is never surfaced.
	Email string `json:"email,omitempty"`
}
