// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package model

import (
	"net/mail"
	"strings"
)

// aliasReservedNames is the canonical set of local parts that may not be claimed
// as system-managed aliases on any allowed domain. Extended at runtime via the
// AUTH0_ALIAS_RESERVED_EXTRA environment variable. These names are reserved
// regardless of the requested domain because they are universally sensitive
// (RFC 2142 mailbox names, LF branding terms, etc.).
var aliasReservedNames = map[string]struct{}{
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

// aliasBannedChars are characters disallowed in an alias local part. The
// double-quote is included to prevent reserved-name bypass via RFC 5322 quoted
// local-parts (e.g. `"admin"@<domain>` would otherwise parse and canonicalize
// to `admin@<domain>`, slipping past the reserved-name check on the raw alias).
const aliasBannedChars = `/*$^:()<>[];@\, "`

// ValidateAlias normalises alias (lowercases + trims) and validates it as a
// local part that can be safely appended to "@<domain>". Returns
// ("", "alias_invalid") or ("", "alias_reserved") on failure, or
// (normalised, "") on success. The domain is used only for the RFC 5322
// round-trip canonicalisation check — callers are responsible for verifying
// the domain itself is allowed before calling this function.
func ValidateAlias(alias, domain string, extraReserved []string) (string, string) {
	alias = strings.ToLower(strings.TrimSpace(alias))
	domain = strings.ToLower(strings.TrimSpace(domain))

	if len(alias) == 0 || len(alias) > 64 {
		return "", "alias_invalid"
	}

	if strings.ContainsAny(alias, aliasBannedChars) {
		return "", "alias_invalid"
	}

	// Ensure the address parses and that net/mail's canonical form matches the
	// input verbatim. This catches any other surface (escapes, encoded forms)
	// that could let a normalised value differ from `alias`.
	full := alias + "@" + domain
	parsed, err := mail.ParseAddress(full)
	if err != nil || !strings.EqualFold(parsed.Address, full) {
		return "", "alias_invalid"
	}

	if _, reserved := aliasReservedNames[alias]; reserved {
		return "", "alias_reserved"
	}
	for _, extra := range extraReserved {
		if strings.EqualFold(alias, strings.TrimSpace(extra)) {
			return "", "alias_reserved"
		}
	}

	return alias, ""
}
