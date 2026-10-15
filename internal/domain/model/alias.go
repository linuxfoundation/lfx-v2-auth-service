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

// aliasSubaddressDelimiter separates the mailbox from an optional subaddress
// tag (e.g. `admin+tag` is delivered to `admin`). The reserved-name check is
// applied to the part before the delimiter.
const aliasSubaddressDelimiter = "+"

// aliasSeparators are stripped from the reserved-name key so that variants such
// as `no_reply`, `post.master` or `-admin` match their reserved counterparts.
var aliasSeparators = strings.NewReplacer(".", "", "-", "", "_", "")

// aliasASCIIConfusableChars and aliasASCIIConfusableSeqs fold ASCII characters
// and sequences that render alike onto a single representative, so that
// look-alikes such as `adrnin`, `adm1n` or `r00t` are matched against the
// reserved list. They are applied to both the alias and the reserved names.
// Single characters are folded first so that sequences they form (e.g. `c1` →
// `cl`) are seen by the second stage. The first stage leaves no `0`, `1` or
// `i`, and the second emits only `m`, `w` and `d`, which neither stage matches
// on, so the result is a fixed point.
var aliasASCIIConfusableChars = strings.NewReplacer(
	"0", "o",
	"1", "l",
	"i", "l",
)

var aliasASCIIConfusableSeqs = strings.NewReplacer(
	"rn", "m",
	"vv", "w",
	"cl", "d",
)

// isAllowedAliasChar reports whether c may appear in a normalised alias.
// Restricting the local part to this ASCII alphabet rejects Unicode homoglyphs
// (e.g. Cyrillic `ѕupport`) that net/mail would otherwise accept as RFC 6532
// atext and that would render identically to a reserved name.
func isAllowedAliasChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		c == '.' || c == '_' || c == '-' || c == '+'
}

// aliasReservedKey returns the canonical form of a local part used for the
// reserved-name comparison: subaddress tag and separators stripped and ASCII
// confusables folded.
func aliasReservedKey(localPart string) string {
	base, _, _ := strings.Cut(localPart, aliasSubaddressDelimiter)
	return aliasASCIIConfusableSeqs.Replace(aliasASCIIConfusableChars.Replace(aliasSeparators.Replace(base)))
}

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

	for i := 0; i < len(alias); i++ {
		if !isAllowedAliasChar(alias[i]) {
			return "", "alias_invalid"
		}
	}

	// Ensure the address parses and that net/mail's canonical form matches the
	// input verbatim. This catches any other surface (escapes, encoded forms)
	// that could let a normalised value differ from `alias`.
	full := alias + "@" + domain
	parsed, err := mail.ParseAddress(full)
	if err != nil || !strings.EqualFold(parsed.Address, full) {
		return "", "alias_invalid"
	}

	// A mailbox part made only of separators (e.g. `+tag`, `-`) is degenerate
	// and could never be matched against the reserved list.
	key := aliasReservedKey(alias)
	if key == "" {
		return "", "alias_invalid"
	}
	for name := range aliasReservedNames {
		if key == aliasReservedKey(name) {
			return "", "alias_reserved"
		}
	}
	for _, extra := range extraReserved {
		extra = strings.ToLower(strings.TrimSpace(extra))
		if extra != "" && key == aliasReservedKey(extra) {
			return "", "alias_reserved"
		}
	}

	return alias, ""
}
