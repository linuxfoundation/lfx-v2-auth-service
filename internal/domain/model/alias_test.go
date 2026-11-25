// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package model

import (
	"strings"
	"testing"
)

func TestIsAllowedAliasDomain(t *testing.T) {
	tests := []struct {
		name      string
		domain    string
		allowList string
		want      bool
	}{
		{name: "exact match", domain: "linux.com", allowList: "linux.com", want: true},
		{name: "case and whitespace insensitive", domain: " Linux.COM ", allowList: "foo.org , LINUX.com", want: true},
		{name: "not listed", domain: "example.com", allowList: "linux.com,foo.org", want: false},
		{name: "subdomain is not a match", domain: "sub.linux.com", allowList: "linux.com", want: false},
		{name: "trailing dot is not normalised", domain: "linux.com", allowList: "linux.com.", want: false},
		{name: "empty domain", domain: "  ", allowList: "linux.com", want: false},
		{name: "empty allow list", domain: "linux.com", allowList: "", want: false},
		{name: "empty entries ignored", domain: "linux.com", allowList: ",,", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAllowedAliasDomain(tt.domain, tt.allowList); got != tt.want {
				t.Errorf("IsAllowedAliasDomain(%q, %q) = %v, want %v", tt.domain, tt.allowList, got, tt.want)
			}
		})
	}
}

func TestValidateAlias(t *testing.T) {
	const testDomain = "linux.com"

	tests := []struct {
		name          string
		alias         string
		extraReserved []string
		wantNorm      string
		wantErrCode   string
	}{
		// Happy paths
		{
			name:        "simple valid alias",
			alias:       "jdoe",
			wantNorm:    "jdoe",
			wantErrCode: "",
		},
		{
			name:        "alias with hyphen",
			alias:       "jane-doe",
			wantNorm:    "jane-doe",
			wantErrCode: "",
		},
		{
			name:        "alias with dot",
			alias:       "jane.doe",
			wantNorm:    "jane.doe",
			wantErrCode: "",
		},
		{
			name:        "alias with plus",
			alias:       "jane+doe",
			wantNorm:    "jane+doe",
			wantErrCode: "",
		},
		{
			name:        "uppercase is normalised to lowercase",
			alias:       "JaneDoe",
			wantNorm:    "janedoe",
			wantErrCode: "",
		},
		{
			name:        "leading/trailing whitespace trimmed",
			alias:       "  jdoe  ",
			wantNorm:    "jdoe",
			wantErrCode: "",
		},
		{
			name:        "single character",
			alias:       "x",
			wantNorm:    "x",
			wantErrCode: "",
		},
		{
			name:        "exactly 64 characters",
			alias:       strings.Repeat("a", 64),
			wantNorm:    strings.Repeat("a", 64),
			wantErrCode: "",
		},

		// Invalid — length
		{
			name:        "empty alias",
			alias:       "",
			wantErrCode: "alias_invalid",
		},
		{
			name:        "whitespace only",
			alias:       "   ",
			wantErrCode: "alias_invalid",
		},
		{
			name:        "65 characters — too long",
			alias:       strings.Repeat("b", 65),
			wantErrCode: "alias_invalid",
		},

		// Invalid — banned chars
		{
			name:        "double-quoted alias rejected (RFC 5322 bypass guard)",
			alias:       `"jdoe"`,
			wantErrCode: "alias_invalid",
		},
		{
			name:        "double-quoted reserved alias rejected",
			alias:       `"admin"`,
			wantErrCode: "alias_invalid",
		},
		{
			name:        "slash",
			alias:       "jane/doe",
			wantErrCode: "alias_invalid",
		},
		{
			name:        "asterisk",
			alias:       "jane*doe",
			wantErrCode: "alias_invalid",
		},
		{
			name:        "dollar sign",
			alias:       "jane$doe",
			wantErrCode: "alias_invalid",
		},
		{
			name:        "caret",
			alias:       "jane^doe",
			wantErrCode: "alias_invalid",
		},
		{
			name:        "colon",
			alias:       "jane:doe",
			wantErrCode: "alias_invalid",
		},
		{
			name:        "at sign",
			alias:       "jane@doe",
			wantErrCode: "alias_invalid",
		},
		{
			name:        "space in middle",
			alias:       "jane doe",
			wantErrCode: "alias_invalid",
		},
		{
			name:        "semicolon",
			alias:       "jane;doe",
			wantErrCode: "alias_invalid",
		},

		// Invalid — outside the restricted ASCII alphabet
		{
			name:        "non-ASCII letter",
			alias:       "jöhn",
			wantErrCode: "alias_invalid",
		},
		{
			name:        "ASCII punctuation outside allowlist",
			alias:       "jane|doe",
			wantErrCode: "alias_invalid",
		},
		{
			name:        "apostrophe outside allowlist",
			alias:       "o'brien",
			wantErrCode: "alias_invalid",
		},

		// Reserved — subaddressing and ASCII look-alikes
		{
			name:        "subaddressed reserved name",
			alias:       "admin+anything",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "subaddressed reserved name uppercase",
			alias:       "SUPPORT+x",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "reserved name with empty subaddress",
			alias:       "security+",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "rn look-alike of m",
			alias:       "adrnin",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "zero look-alike of o",
			alias:       "r00t",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "one look-alike of l",
			alias:       "1inux",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "vv look-alike of w",
			alias:       "vvebmaster",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "subaddress on non-reserved name allowed",
			alias:       "adminton+x",
			wantNorm:    "adminton+x",
			wantErrCode: "",
		},
		{
			name:          "subaddressed extra reserved name",
			alias:         "cncf+x",
			extraReserved: []string{"cncf"},
			wantErrCode:   "alias_reserved",
		},
		{
			name:          "empty extra reserved entry is ignored",
			alias:         "jdoe",
			extraReserved: []string{"  "},
			wantNorm:      "jdoe",
			wantErrCode:   "",
		},
		{
			name:        "empty mailbox before subaddress",
			alias:       "+admin",
			wantErrCode: "alias_invalid",
		},
		{
			name:        "separators only",
			alias:       "-",
			wantErrCode: "alias_invalid",
		},
		{
			name:        "underscore variant of reserved name",
			alias:       "no_reply",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "dot variant of reserved name",
			alias:       "post.master",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "leading hyphen variant of reserved name",
			alias:       "-admin",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "one look-alike of i",
			alias:       "adm1n",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "cl look-alike of d",
			alias:       "aclmin",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "c1 composes into cl look-alike of d",
			alias:       "ac1min",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "ci composes into cl look-alike of d",
			alias:       "acimin",
			wantErrCode: "alias_reserved",
		},

		// Extra reserved
		{
			name:          "extra reserved name blocked",
			alias:         "cncf",
			extraReserved: []string{"cncf"},
			wantErrCode:   "alias_reserved",
		},
		{
			name:          "extra reserved case-insensitive",
			alias:         "CNCF",
			extraReserved: []string{"cncf"},
			wantErrCode:   "alias_reserved",
		},
		{
			name:          "extra reserved with whitespace",
			alias:         "cncf",
			extraReserved: []string{"  cncf  "},
			wantErrCode:   "alias_reserved",
		},
		{
			name:          "alias not in extra reserved",
			alias:         "jdoe",
			extraReserved: []string{"cncf"},
			wantNorm:      "jdoe",
			wantErrCode:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			norm, errCode := ValidateAlias(tt.alias, testDomain, tt.extraReserved)

			if errCode != tt.wantErrCode {
				t.Errorf("ValidateAlias(%q) errCode = %q, want %q", tt.alias, errCode, tt.wantErrCode)
			}

			if tt.wantErrCode == "" && norm != tt.wantNorm {
				t.Errorf("ValidateAlias(%q) norm = %q, want %q", tt.alias, norm, tt.wantNorm)
			}

			if tt.wantErrCode != "" && norm != "" {
				t.Errorf("ValidateAlias(%q) expected empty norm on error, got %q", tt.alias, norm)
			}
		})
	}

	// Loop over the canonical reserved set so any future additions to
	// aliasReservedNames are automatically covered without updating this file.
	for name := range aliasReservedNames {
		name := name
		t.Run(name+" reserved (builtin)", func(t *testing.T) {
			_, code := ValidateAlias(name, testDomain, nil)
			if code != "alias_reserved" {
				t.Errorf("expected alias_reserved for built-in reserved name %q, got %q", name, code)
			}
		})
		t.Run(name+" reserved uppercase (builtin)", func(t *testing.T) {
			_, code := ValidateAlias(strings.ToUpper(name), testDomain, nil)
			if code != "alias_reserved" {
				t.Errorf("expected alias_reserved for upper-cased built-in reserved name %q, got %q", strings.ToUpper(name), code)
			}
		})
		t.Run(name+" reserved subaddressed (builtin)", func(t *testing.T) {
			_, code := ValidateAlias(name+"+tag", testDomain, nil)
			if code != "alias_reserved" {
				t.Errorf("expected alias_reserved for subaddressed built-in reserved name %q, got %q", name+"+tag", code)
			}
		})
		// Every Cyrillic/Greek homoglyph substitution of a reserved name must
		// be refused; none may be returned as a valid alias.
		for i := 0; i < len(name); i++ {
			for _, glyph := range aliasTestHomoglyphs[name[i]] {
				spoof := name[:i] + string(glyph) + name[i+1:]
				t.Run(name+" homoglyph "+spoof, func(t *testing.T) {
					norm, code := ValidateAlias(spoof, testDomain, nil)
					if code == "" || norm != "" {
						t.Errorf("expected homoglyph %q of reserved name %q to be rejected, got norm=%q code=%q", spoof, name, norm, code)
					}
				})
			}
		}
	}
}

// aliasTestHomoglyphs maps ASCII letters to Cyrillic and Greek code points
// that render identically (or near-identically) in common fonts.
var aliasTestHomoglyphs = map[byte][]rune{
	'a': {'а', 'α'}, // Cyrillic а, Greek α
	'c': {'с', 'ϲ'}, // Cyrillic с, Greek lunate sigma ϲ
	'd': {'ԁ'},      // Cyrillic ԁ
	'e': {'е', 'ε'}, // Cyrillic е, Greek ε
	'h': {'һ'},      // Cyrillic һ
	'i': {'і', 'ι'}, // Cyrillic і, Greek ι
	'j': {'ј'},      // Cyrillic ј
	'l': {'ӏ'},      // Cyrillic ӏ
	'n': {'ո'},      // Armenian ո
	'o': {'о', 'ο'}, // Cyrillic о, Greek ο
	'p': {'р', 'ρ'}, // Cyrillic р, Greek ρ
	'r': {'г'},      // Cyrillic г
	's': {'ѕ'},      // Cyrillic ѕ
	't': {'τ'},      // Greek τ
	'u': {'υ'},      // Greek υ
	'v': {'ν'},      // Greek ν
	'w': {'ѡ'},      // Cyrillic ѡ
	'x': {'х', 'χ'}, // Cyrillic х, Greek χ
	'y': {'у'},      // Cyrillic у
}

// TestAliasReservedKeyIsFixedPoint guards against composed look-alikes (e.g.
// `ac1min`) slipping past the fold: canonicalising an already-canonical key
// must not change it.
func TestAliasReservedKeyIsFixedPoint(t *testing.T) {
	const alphabet = "rnvcli10omwd"
	var walk func(prefix string)
	walk = func(prefix string) {
		if key := aliasReservedKey(prefix); aliasReservedKey(key) != key {
			t.Fatalf("aliasReservedKey(%q) = %q is not a fixed point (refolds to %q)", prefix, key, aliasReservedKey(key))
		}
		if len(prefix) == 5 {
			return
		}
		for i := 0; i < len(alphabet); i++ {
			walk(prefix + alphabet[i:i+1])
		}
	}
	walk("")
}
