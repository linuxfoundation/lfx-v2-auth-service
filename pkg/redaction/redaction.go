// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package redaction provides utilities for redacting sensitive information
// in logs, error messages, and other outputs to protect privacy and comply
// with data protection regulations.
package redaction

import (
	"regexp"
	"strings"
)

// jwtPattern matches JWT tokens (three base64url segments separated by dots)
var jwtPattern = regexp.MustCompile(`[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)

// Redact redacts sensitive information for logging and output purposes.
// Shows the first 3 characters when the string has more than 5 characters,
// otherwise shows asterisks for shorter strings.
//
// Examples:
//   - Redact("") → ""
//   - Redact("ab") → "**"
//   - Redact("abc") → "a****"
//   - Redact("johndoe123") → "joh****"
//   - Redact("auth0|johndoe123") → "auth0|joh****"
func Redact(sensitive string) string {
	if len(sensitive) == 0 {
		return ""
	}

	runes := []rune(sensitive)
	n := len(runes)

	// For very short strings (1-2 chars), show asterisks
	if n <= 2 {
		return "**"
	}

	// For short strings (3-5 chars), show first rune + asterisks
	if n <= 5 {
		return string(runes[0]) + "****"
	}

	// Handle Auth0 user IDs
	if strings.HasPrefix(sensitive, "auth0|") {
		return "auth0|" + Redact(strings.TrimPrefix(sensitive, "auth0|"))
	}

	// For longer strings (>5 runes), show first 3 runes + asterisks
	return string(runes[:3]) + "****"
}

// RedactJWTs replaces any JWT tokens found in the input string with a redacted placeholder.
// Useful for sanitizing request/response bodies before logging.
func RedactJWTs(s string) string {
	return jwtPattern.ReplaceAllString(s, "[REDACTED]")
}

// RedactEmail redacts email addresses for logging and output purposes.
// Shows the first 3 characters of the local part and keeps the full domain
// visible for debugging purposes.
//
// Examples:
//   - RedactEmail("") → ""
//   - RedactEmail("a@example.com") → "**@example.com"
//   - RedactEmail("john@example.com") → "j****@example.com"
//   - RedactEmail("johndoe@company.com") → "joh****@company.com"
//   - RedactEmail("invalid-email") → "inv****" (falls back to Redact)
func RedactEmail(email string) string {
	if email == "" {
		return ""
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		// Invalid email format, redact the whole thing
		return Redact(email)
	}

	localPart := parts[0]
	domain := parts[1]

	// Redact the local part but keep the domain visible for debugging
	redactedLocal := Redact(localPart)

	return redactedLocal + "@" + domain
}
