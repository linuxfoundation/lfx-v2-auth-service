// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package model

import (
	"strings"
	"testing"
)

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
	}
}
