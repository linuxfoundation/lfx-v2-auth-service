// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package cdpidentity holds the shared LFID-membership predicates over a
// CDP member's identities. Both the provisioning orchestrator and the
// merge-repair job classify through these, so the definition of "foreign"
// can never drift between the writer and the repairer.
package cdpidentity

import (
	"strings"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/cdp"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
)

// ForeignLFID reports the first LFID username on the member that is not this
// user's, if there is one.
//
// LFID usernames are one per person, so a member carrying two of them holds
// two people. Comparison is case-insensitive because CDP stores identity
// values as they arrive from each source.
func ForeignLFID(held []cdp.MemberIdentity, username string) (string, bool) {
	for _, identity := range held {
		if identity.Platform != constants.LFIDPlatform || identity.Type != constants.CDPIdentityTypeUsername {
			continue
		}
		value := strings.TrimSpace(identity.Value)
		if value == "" {
			continue
		}
		if !strings.EqualFold(value, username) {
			return identity.Value, true
		}
	}
	return "", false
}

// HoldsLFID reports whether the member already carries this user's own LFID.
//
// The mirror of ForeignLFID, and case-insensitive for the same reason: CDP
// stores identity values as each source supplies them.
func HoldsLFID(held []cdp.MemberIdentity, username string) bool {
	for _, identity := range held {
		if identity.Platform != constants.LFIDPlatform || identity.Type != constants.CDPIdentityTypeUsername {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(identity.Value), username) {
			return true
		}
	}
	return false
}
