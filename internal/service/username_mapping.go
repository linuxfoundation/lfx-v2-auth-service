// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package service

// Username mapping utility for converting usernames to Auth0 "sub" format.
//
// This logic is derived from lfx-v1-sync-helper (cmd/lfx-v1-sync-helper/username_mapping.go)
// and handles conversion of LDAP usernames to the "sub" claim format expected by v2 services.
//
// NOTE: This mapping is not forward-safe for a future Auth0 native-DB migration.
// When that migration occurs, this will be replaced with a call to Auth0 with a cache layer.

import (
	"crypto/sha512"
	"regexp"

	"github.com/akamensky/base58"
)

var (
	// safeNameRE detects usernames compatible with Auth0-generated user IDs.
	safeNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,58}[A-Za-z0-9]$`)
	hexUserRE  = regexp.MustCompile(`^[0-9a-f]{24,60}$`)
)

// mapUsernameToSub converts a username to the Auth0 "sub" format expected by v2 services.
//
// The mapping logic:
//   - Safe usernames (matching safeNameRE and not hexUserRE): use directly as userID
//   - Unsafe usernames: hash with SHA-512 and encode to base58 (~80 chars)
//
// Returns: "auth0|{userID}" format string, or empty string if username is empty.
func mapUsernameToSub(username string) string {
	if username == "" {
		return ""
	}

	var userID string
	if safeNameRE.MatchString(username) && !hexUserRE.MatchString(username) {
		userID = username
	} else {
		hash := sha512.Sum512([]byte(username))
		userID = base58.Encode(hash[:])
	}

	return "auth0|" + userID
}
