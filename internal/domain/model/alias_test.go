// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package model

import (
	"strings"
	"testing"
)

func TestValidateLcomAlias(t *testing.T) {
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

		// Reserved names — all 19
		{
			name:        "postmaster reserved",
			alias:       "postmaster",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "abuse reserved",
			alias:       "abuse",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "hostmaster reserved",
			alias:       "hostmaster",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "admin reserved",
			alias:       "admin",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "administrator reserved",
			alias:       "administrator",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "noreply reserved",
			alias:       "noreply",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "no-reply reserved",
			alias:       "no-reply",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "root reserved",
			alias:       "root",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "mailer-daemon reserved",
			alias:       "mailer-daemon",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "linux reserved",
			alias:       "linux",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "linuxfoundation reserved",
			alias:       "linuxfoundation",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "lf reserved",
			alias:       "lf",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "security reserved",
			alias:       "security",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "support reserved",
			alias:       "support",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "info reserved",
			alias:       "info",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "webmaster reserved",
			alias:       "webmaster",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "ops reserved",
			alias:       "ops",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "devops reserved",
			alias:       "devops",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "itx-system reserved",
			alias:       "itx-system",
			wantErrCode: "alias_reserved",
		},
		{
			name:        "reserved name case-insensitive",
			alias:       "ADMIN",
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
			norm, errCode := ValidateLcomAlias(tt.alias, tt.extraReserved)

			if errCode != tt.wantErrCode {
				t.Errorf("ValidateLcomAlias(%q) errCode = %q, want %q", tt.alias, errCode, tt.wantErrCode)
			}

			if tt.wantErrCode == "" && norm != tt.wantNorm {
				t.Errorf("ValidateLcomAlias(%q) norm = %q, want %q", tt.alias, norm, tt.wantNorm)
			}

			if tt.wantErrCode != "" && norm != "" {
				t.Errorf("ValidateLcomAlias(%q) expected empty norm on error, got %q", tt.alias, norm)
			}
		})
	}
}
