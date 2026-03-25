// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"testing"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/converters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuth0User_ToUser(t *testing.T) {
	tests := []struct {
		name      string
		auth0User Auth0User
		validate  func(t *testing.T, user *model.User)
	}{
		{
			name: "full user with identity and profileData",
			auth0User: Auth0User{
				UserID:        "auth0|abc123",
				Username:      "johndoe",
				Email:         "john@example.com",
				EmailVerified: true,
				Identities: []Auth0Identity{
					{
						Connection: "google-oauth2",
						UserID:     "google-id-456",
						Provider:   "google-oauth2",
						IsSocial:   true,
						ProfileData: &Auth0ProfileData{
							Email:         "john@gmail.com",
							EmailVerified: true,
						},
					},
				},
			},
			validate: func(t *testing.T, user *model.User) {
				assert.Equal(t, "auth0|abc123", user.UserID)
				assert.Equal(t, "johndoe", user.Username)
				assert.Equal(t, "john@example.com", user.PrimaryEmail)

				require.Len(t, user.Identities, 1)
				id := user.Identities[0]
				assert.Equal(t, "google-oauth2", id.Provider)
				assert.Equal(t, "google-id-456", id.IdentityID)
				assert.True(t, id.IsSocial)
				assert.Equal(t, "john@gmail.com", id.Email)
				assert.True(t, id.EmailVerified)
			},
		},
		{
			name: "identity with nil ProfileData",
			auth0User: Auth0User{
				UserID: "auth0|abc123",
				Identities: []Auth0Identity{
					{
						Provider:    "github",
						UserID:      "gh-789",
						IsSocial:    true,
						ProfileData: nil,
					},
				},
			},
			validate: func(t *testing.T, user *model.User) {
				require.Len(t, user.Identities, 1)
				id := user.Identities[0]
				assert.Equal(t, "github", id.Provider)
				assert.Equal(t, "gh-789", id.IdentityID)
				assert.True(t, id.IsSocial)
				assert.Empty(t, id.Email)
				assert.False(t, id.EmailVerified)
			},
		},
		{
			name: "numeric UserID is converted to string",
			auth0User: Auth0User{
				UserID: "auth0|abc123",
				Identities: []Auth0Identity{
					{
						Provider: "github",
						UserID:   float64(5818912),
						IsSocial: true,
					},
				},
			},
			validate: func(t *testing.T, user *model.User) {
				require.Len(t, user.Identities, 1)
				assert.Equal(t, "5818912", user.Identities[0].IdentityID)
			},
		},
		{
			name: "multiple identities are all converted",
			auth0User: Auth0User{
				UserID: "auth0|abc123",
				Identities: []Auth0Identity{
					{
						Provider: "google-oauth2",
						UserID:   "g-111",
						IsSocial: true,
						ProfileData: &Auth0ProfileData{
							Email:         "user@gmail.com",
							EmailVerified: true,
						},
					},
					{
						Provider: "github",
						UserID:   "gh-222",
						IsSocial: true,
						ProfileData: &Auth0ProfileData{
							Email:         "user@github.com",
							EmailVerified: false,
							Nickname:      "octocat",
							Name:          "Octo Cat",
						},
					},
					{
						Provider:    "auth0",
						UserID:      "auth0-333",
						IsSocial:    false,
						ProfileData: nil,
					},
				},
			},
			validate: func(t *testing.T, user *model.User) {
				require.Len(t, user.Identities, 3)

				assert.Equal(t, "google-oauth2", user.Identities[0].Provider)
				assert.Equal(t, "g-111", user.Identities[0].IdentityID)
				assert.True(t, user.Identities[0].EmailVerified)

				assert.Equal(t, "github", user.Identities[1].Provider)
				assert.Equal(t, "gh-222", user.Identities[1].IdentityID)
				assert.False(t, user.Identities[1].EmailVerified)
				assert.Equal(t, "octocat", user.Identities[1].Nickname)
				assert.Equal(t, "Octo Cat", user.Identities[1].Name)

				assert.Equal(t, "auth0", user.Identities[2].Provider)
				assert.Equal(t, "auth0-333", user.Identities[2].IdentityID)
				assert.Empty(t, user.Identities[2].Email)
			},
		},
		{
			name: "identity with nickname but no email",
			auth0User: Auth0User{
				UserID: "auth0|abc123",
				Identities: []Auth0Identity{
					{
						Provider: "github",
						UserID:   "gh-999",
						IsSocial: true,
						ProfileData: &Auth0ProfileData{
							Nickname: "devuser",
							Name:     "Dev User",
						},
					},
				},
			},
			validate: func(t *testing.T, user *model.User) {
				require.Len(t, user.Identities, 1)
				id := user.Identities[0]
				assert.Equal(t, "github", id.Provider)
				assert.Equal(t, "gh-999", id.IdentityID)
				assert.Empty(t, id.Email)
				assert.Equal(t, "devuser", id.Nickname)
				assert.Equal(t, "Dev User", id.Name)
			},
		},
		{
			name: "empty identities slice",
			auth0User: Auth0User{
				UserID:     "auth0|abc123",
				Identities: []Auth0Identity{},
			},
			validate: func(t *testing.T, user *model.User) {
				assert.Nil(t, user.Identities)
			},
		},
		{
			name: "nil UserMetadata",
			auth0User: Auth0User{
				UserID:       "auth0|abc123",
				UserMetadata: nil,
			},
			validate: func(t *testing.T, user *model.User) {
				assert.Nil(t, user.UserMetadata)
			},
		},
		{
			name: "with UserMetadata",
			auth0User: Auth0User{
				UserID: "auth0|abc123",
				UserMetadata: &Auth0UserMetadata{
					Name:      converters.StringPtr("John Doe"),
					GivenName: converters.StringPtr("John"),
					Country:   converters.StringPtr("US"),
				},
			},
			validate: func(t *testing.T, user *model.User) {
				require.NotNil(t, user.UserMetadata)
				assert.Equal(t, converters.StringPtr("John Doe"), user.UserMetadata.Name)
				assert.Equal(t, converters.StringPtr("John"), user.UserMetadata.GivenName)
				assert.Equal(t, converters.StringPtr("US"), user.UserMetadata.Country)
				assert.Nil(t, user.UserMetadata.FamilyName)
				assert.Nil(t, user.UserMetadata.Picture)
			},
		},
		{
			name: "alternate emails are converted",
			auth0User: Auth0User{
				UserID: "auth0|abc123",
				AlternateEmail: []Auth0ProfileData{
					{Email: "alt1@example.com", EmailVerified: true},
					{Email: "alt2@example.com", EmailVerified: false},
				},
			},
			validate: func(t *testing.T, user *model.User) {
				require.Len(t, user.AlternateEmails, 2)
				assert.Equal(t, "alt1@example.com", user.AlternateEmails[0].Email)
				assert.True(t, user.AlternateEmails[0].Verified)
				assert.Equal(t, "alt2@example.com", user.AlternateEmails[1].Email)
				assert.False(t, user.AlternateEmails[1].Verified)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := tt.auth0User.ToUser()
			require.NotNil(t, user)
			tt.validate(t, user)
		})
	}
}
