// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package model

import (
	"net/mail"
	"strings"
)

// lcomReservedNames is the canonical set of local parts that may not be claimed
// as @linux.com aliases. Extended at runtime via the
// AUTH0_LCOM_ALIAS_RESERVED_EXTRA environment variable.
var lcomReservedNames = map[string]struct{}{
	"postmaster":      {},
	"abuse":           {},
	"hostmaster":      {},
	"admin":           {},
	"administrator":   {},
	"noreply":         {},
	"no-reply":        {},
	"root":            {},
	"mailer-daemon":   {},
	"linux":           {},
	"linuxfoundation": {},
	"lf":              {},
	"security":        {},
	"support":         {},
	"info":            {},
	"webmaster":       {},
	"ops":             {},
	"devops":          {},
	"itx-system":      {},
}

// lcomBannedChars are characters disallowed in an @linux.com alias local part,
// ported from itx-service-forwards/forwards.go:309-327.
const lcomBannedChars = `/*$^:()<>[];@\, `

// ValidateLcomAlias normalises alias (lowercases + trims) and returns
// ("", "alias_invalid") or ("", "alias_reserved") on failure, or
// (normalised, "") on success.
func ValidateLcomAlias(alias string, extraReserved []string) (string, string) {
	alias = strings.ToLower(strings.TrimSpace(alias))

	if len(alias) == 0 || len(alias) > 64 {
		return "", "alias_invalid"
	}

	if strings.ContainsAny(alias, lcomBannedChars) {
		return "", "alias_invalid"
	}

	// RFC 5322 round-trip: ensure the full address parses cleanly.
	if _, err := mail.ParseAddress(alias + "@linux.com"); err != nil {
		return "", "alias_invalid"
	}

	if _, reserved := lcomReservedNames[alias]; reserved {
		return "", "alias_reserved"
	}
	for _, extra := range extraReserved {
		if strings.EqualFold(alias, strings.TrimSpace(extra)) {
			return "", "alias_reserved"
		}
	}

	return alias, ""
}
