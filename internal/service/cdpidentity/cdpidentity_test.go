// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package cdpidentity_test

import (
	"testing"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/cdp"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/service/cdpidentity"
	"github.com/stretchr/testify/assert"
)

func TestForeignLFID(t *testing.T) {
	lfid := func(v string) cdp.MemberIdentity {
		return cdp.MemberIdentity{Platform: "lfid", Type: "username", Value: v}
	}

	t.Run("own only is not foreign", func(t *testing.T) {
		other, occupied := cdpidentity.ForeignLFID([]cdp.MemberIdentity{lfid("psmith")}, "psmith")
		assert.False(t, occupied)
		assert.Empty(t, other)
	})

	t.Run("comparison ignores case and padding", func(t *testing.T) {
		_, occupied := cdpidentity.ForeignLFID([]cdp.MemberIdentity{lfid("  PSMITH ")}, "psmith")
		assert.False(t, occupied)
	})

	t.Run("another username is foreign", func(t *testing.T) {
		other, occupied := cdpidentity.ForeignLFID([]cdp.MemberIdentity{lfid("psmith"), lfid("kimmaida")}, "psmith")
		assert.True(t, occupied)
		assert.Equal(t, "kimmaida", other)
	})

	t.Run("non-lfid identities are skipped", func(t *testing.T) {
		other, occupied := cdpidentity.ForeignLFID([]cdp.MemberIdentity{
			{Platform: "email", Type: "email", Value: "someone-else@example.com"},
			lfid("psmith"),
		}, "psmith")
		assert.False(t, occupied)
		assert.Empty(t, other)
	})
}

func TestHoldsLFID(t *testing.T) {
	lfid := func(v string) cdp.MemberIdentity {
		return cdp.MemberIdentity{Platform: "lfid", Type: "username", Value: v}
	}

	assert.True(t, cdpidentity.HoldsLFID([]cdp.MemberIdentity{lfid("psmith")}, "PSMITH"))
	assert.False(t, cdpidentity.HoldsLFID([]cdp.MemberIdentity{lfid("kimmaida")}, "psmith"))
	assert.False(t, cdpidentity.HoldsLFID(nil, "psmith"))
}
