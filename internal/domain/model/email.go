// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package model

import "net/mail"

// Email represents an email
type Email struct {
	OTP      string `json:"otp,omitempty"`
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
}

// IsValidEmail checks if the email is valid according to RFC 5322
func (e *Email) IsValidEmail() bool {
	if e.Email == "" {
		return false
	}
	_, err := mail.ParseAddress(e.Email)
	return err == nil
}

// EmailMessage represents an email message to be sent
type EmailMessage struct {
	// From is the sender email address
	From string
	// FromName is the sender name (optional)
	FromName string
	// To is the recipient email address
	To string
	// Subject is the email subject
	Subject string
	// Body is the email body content
	Body string
	// IsHTML indicates if the body is HTML formatted
	IsHTML bool
}

// IsValid checks if the email message has all required fields
func (e *EmailMessage) IsValid() bool {
	if e.To == "" || e.Subject == "" || e.Body == "" {
		return false
	}
	// Validate email addresses
	if _, err := mail.ParseAddress(e.To); err != nil {
		return false
	}
	if e.From != "" {
		if _, err := mail.ParseAddress(e.From); err != nil {
			return false
		}
	}
	return true
}
