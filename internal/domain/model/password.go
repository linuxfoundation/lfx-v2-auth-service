// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package model

// ChangePasswordRequest represents the request body for changing a user's password
type ChangePasswordRequest struct {
	Token           string `json:"token"`
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// ResetPasswordLinkRequest represents the request body for sending a password reset link
type ResetPasswordLinkRequest struct {
	Token string `json:"token"`
}
