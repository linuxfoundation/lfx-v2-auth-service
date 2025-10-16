// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package model

import "net/mail"

// Email represents an email
type Email struct {
	OTP           string `json:"otp"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

// IsValidEmail checks if the email is valid according to RFC 5322
func (e *Email) IsValidEmail() bool {
	if e.Email == "" {
		return false
	}
	_, err := mail.ParseAddress(e.Email)
	return err == nil
}
