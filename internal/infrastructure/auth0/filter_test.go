// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"context"
	"net/url"
	"testing"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_newUserFilterer(t *testing.T) {
	user := &model.User{
		Username:     "testuser",
		PrimaryEmail: "test@example.com",
		AlternateEmail: []model.AlternateEmail{
			{Email: "alt@example.com", EmailVerified: true},
		},
	}

	tests := []struct {
		name         string
		criteriaType string
		want         userFilterer
	}{
		{
			name:         "creates email filter",
			criteriaType: constants.CriteriaTypeEmail,
			want:         &emailFilter{user: user},
		},
		{
			name:         "creates username filter",
			criteriaType: constants.CriteriaTypeUsername,
			want:         &usernameFilter{user: user},
		},
		{
			name:         "creates alternate email filter",
			criteriaType: constants.CriteriaTypeAlternateEmail,
			want:         &alternateEmailFilter{user: user},
		},
		{
			name:         "returns nil for unknown criteria type",
			criteriaType: "unknown",
			want:         nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newUserFilterer(tt.criteriaType, user)
			assert.IsType(t, tt.want, got)
		})
	}
}

func Test_usernameFilter_Endpoint(t *testing.T) {
	ctx := context.Background()
	user := &model.User{Username: "testuser"}
	filter := &usernameFilter{user: user}

	endpoint := filter.Endpoint(ctx)
	expectedEndpoint := criteriaEndpointMapping[constants.CriteriaTypeUsername]

	assert.Equal(t, expectedEndpoint, endpoint)
	assert.Contains(t, endpoint, "users?q=identities.user_id:")
}

func Test_usernameFilter_Args(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name     string
		username string
		want     string
	}{
		{
			name:     "returns escaped username",
			username: "testuser",
			want:     "testuser",
		},
		{
			name:     "escapes special characters",
			username: "test@user+name",
			want:     url.QueryEscape("test@user+name"),
		},
		{
			name:     "escapes spaces",
			username: "test user",
			want:     "test+user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &model.User{Username: tt.username}
			filter := &usernameFilter{user: user}

			args := filter.Args(ctx)
			require.Len(t, args, 1)
			assert.Equal(t, tt.want, args[0])
		})
	}
}

func Test_usernameFilter_Filter(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		user        *model.User
		auth0User   *Auth0User
		wantMatch   bool
		wantErr     bool
		errContains string
	}{
		{
			name: "matches when username and connection match",
			user: &model.User{Username: "testuser"},
			auth0User: &Auth0User{
				Identities: []Auth0Identity{
					{
						Connection: usernamePasswordAuthenticationFilter,
						UserID:     "testuser",
					},
				},
			},
			wantMatch: true,
			wantErr:   false,
		},
		{
			name: "returns error when username doesn't match",
			user: &model.User{Username: "testuser"},
			auth0User: &Auth0User{
				Identities: []Auth0Identity{
					{
						Connection: usernamePasswordAuthenticationFilter,
						UserID:     "differentuser",
					},
				},
			},
			wantMatch:   false,
			wantErr:     true,
			errContains: "user not found",
		},
		{
			name: "no match when connection type is different",
			user: &model.User{Username: "testuser"},
			auth0User: &Auth0User{
				Identities: []Auth0Identity{
					{
						Connection: "google-oauth2",
						UserID:     "testuser",
					},
				},
			},
			wantMatch: false,
			wantErr:   false,
		},
		{
			name: "no match when UserID is not a string",
			user: &model.User{Username: "testuser"},
			auth0User: &Auth0User{
				Identities: []Auth0Identity{
					{
						Connection: usernamePasswordAuthenticationFilter,
						UserID:     12345, // not a string
					},
				},
			},
			wantMatch: false,
			wantErr:   false,
		},
		{
			name: "checks multiple identities and finds match",
			user: &model.User{Username: "testuser"},
			auth0User: &Auth0User{
				Identities: []Auth0Identity{
					{
						Connection: "google-oauth2",
						UserID:     "testuser",
					},
					{
						Connection: usernamePasswordAuthenticationFilter,
						UserID:     "testuser",
					},
				},
			},
			wantMatch: true,
			wantErr:   false,
		},
		{
			name: "no match when identities array is empty",
			user: &model.User{Username: "testuser"},
			auth0User: &Auth0User{
				Identities: []Auth0Identity{},
			},
			wantMatch: false,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := &usernameFilter{user: tt.user}
			match, err := filter.Filter(ctx, tt.auth0User)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tt.wantMatch, match)

			// Verify that username was set when match is found
			if tt.wantMatch && !tt.wantErr {
				assert.NotEmpty(t, tt.user.Username)
			}
		})
	}
}

func Test_emailFilter_Endpoint(t *testing.T) {
	ctx := context.Background()
	user := &model.User{PrimaryEmail: "test@example.com"}
	filter := &emailFilter{user: user}

	endpoint := filter.Endpoint(ctx)
	expectedEndpoint := criteriaEndpointMapping[constants.CriteriaTypeEmail]

	assert.Equal(t, expectedEndpoint, endpoint)
	assert.Contains(t, endpoint, "users-by-email?email=")
}

func Test_emailFilter_Args(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name  string
		email string
		want  string
	}{
		{
			name:  "returns escaped email",
			email: "test@example.com",
			want:  "test%40example.com",
		},
		{
			name:  "escapes email with plus",
			email: "test+tag@example.com",
			want:  url.QueryEscape("test+tag@example.com"),
		},
		{
			name:  "escapes email with special characters",
			email: "test.user@example.com",
			want:  "test.user%40example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &model.User{PrimaryEmail: tt.email}
			filter := &emailFilter{user: user}

			args := filter.Args(ctx)
			require.Len(t, args, 1)
			assert.Equal(t, tt.want, args[0])
		})
	}
}

func Test_emailFilter_Filter(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		user      *model.User
		auth0User *Auth0User
		wantMatch bool
		wantErr   bool
	}{
		{
			name: "matches when connection is Username-Password-Authentication",
			user: &model.User{PrimaryEmail: "test@example.com"},
			auth0User: &Auth0User{
				Identities: []Auth0Identity{
					{
						Connection: usernamePasswordAuthenticationFilter,
						UserID:     "test@example.com",
					},
				},
			},
			wantMatch: true,
			wantErr:   false,
		},
		{
			name: "no match when connection type is different",
			user: &model.User{PrimaryEmail: "test@example.com"},
			auth0User: &Auth0User{
				Identities: []Auth0Identity{
					{
						Connection: "google-oauth2",
						UserID:     "test@example.com",
					},
				},
			},
			wantMatch: false,
			wantErr:   false,
		},
		{
			name: "no match when UserID is not a string",
			user: &model.User{PrimaryEmail: "test@example.com"},
			auth0User: &Auth0User{
				Identities: []Auth0Identity{
					{
						Connection: usernamePasswordAuthenticationFilter,
						UserID:     12345,
					},
				},
			},
			wantMatch: false,
			wantErr:   false,
		},
		{
			name: "checks multiple identities and finds match",
			user: &model.User{PrimaryEmail: "test@example.com"},
			auth0User: &Auth0User{
				Identities: []Auth0Identity{
					{
						Connection: "google-oauth2",
						UserID:     "other@example.com",
					},
					{
						Connection: usernamePasswordAuthenticationFilter,
						UserID:     "test@example.com",
					},
				},
			},
			wantMatch: true,
			wantErr:   false,
		},
		{
			name: "no match when identities array is empty",
			user: &model.User{PrimaryEmail: "test@example.com"},
			auth0User: &Auth0User{
				Identities: []Auth0Identity{},
			},
			wantMatch: false,
			wantErr:   false,
		},
		{
			name: "sets primary email from userID when match found",
			user: &model.User{PrimaryEmail: "test@example.com"},
			auth0User: &Auth0User{
				Identities: []Auth0Identity{
					{
						Connection: usernamePasswordAuthenticationFilter,
						UserID:     "newemail@example.com",
					},
				},
			},
			wantMatch: true,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := &emailFilter{user: tt.user}
			match, err := filter.Filter(ctx, tt.auth0User)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tt.wantMatch, match)

			// Verify that PrimaryEmail was set when match is found
			if tt.wantMatch && !tt.wantErr {
				assert.NotEmpty(t, tt.user.PrimaryEmail)
			}
		})
	}
}

func Test_alternateEmailFilter_Endpoint(t *testing.T) {
	ctx := context.Background()
	user := &model.User{
		AlternateEmail: []model.AlternateEmail{
			{Email: "alt@example.com"},
		},
	}
	filter := &alternateEmailFilter{user: user}

	endpoint := filter.Endpoint(ctx)
	expectedEndpoint := criteriaEndpointMapping[constants.CriteriaTypeAlternateEmail]

	assert.Equal(t, expectedEndpoint, endpoint)
	assert.Contains(t, endpoint, "users?q=identities.profileData.email:")
}

func Test_alternateEmailFilter_Args(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		alternateEmail []model.AlternateEmail
		wantLen        int
		wantFirst      string
	}{
		{
			name: "returns escaped alternate email",
			alternateEmail: []model.AlternateEmail{
				{Email: "alt@example.com", EmailVerified: true},
			},
			wantLen:   1,
			wantFirst: "alt%40example.com",
		},
		{
			name: "returns first email when multiple exist",
			alternateEmail: []model.AlternateEmail{
				{Email: "first@example.com", EmailVerified: true},
				{Email: "second@example.com", EmailVerified: false},
			},
			wantLen:   1,
			wantFirst: "first%40example.com",
		},
		{
			name:           "returns empty array when no alternate emails",
			alternateEmail: []model.AlternateEmail{},
			wantLen:        0,
		},
		{
			name:           "returns empty array when alternate email is nil",
			alternateEmail: nil,
			wantLen:        0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &model.User{AlternateEmail: tt.alternateEmail}
			filter := &alternateEmailFilter{user: user}

			args := filter.Args(ctx)
			assert.Len(t, args, tt.wantLen)

			if tt.wantLen > 0 {
				assert.Equal(t, tt.wantFirst, args[0])
			}
		})
	}
}

func Test_alternateEmailFilter_Filter(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		user      *model.User
		auth0User *Auth0User
		wantMatch bool
		wantErr   bool
	}{
		{
			name: "matches when alternate email and connection match",
			user: &model.User{
				AlternateEmail: []model.AlternateEmail{
					{Email: "alt@example.com", EmailVerified: true},
				},
			},
			auth0User: &Auth0User{
				Identities: []Auth0Identity{
					{
						Connection: emailAuthenticationFilter,
						ProfileData: &Auth0ProfileData{
							Email:         "alt@example.com",
							EmailVerified: true,
						},
					},
				},
			},
			wantMatch: true,
			wantErr:   false,
		},
		{
			name: "no match when connection type is different",
			user: &model.User{
				AlternateEmail: []model.AlternateEmail{
					{Email: "alt@example.com", EmailVerified: true},
				},
			},
			auth0User: &Auth0User{
				Identities: []Auth0Identity{
					{
						Connection: "google-oauth2",
						ProfileData: &Auth0ProfileData{
							Email:         "alt@example.com",
							EmailVerified: true,
						},
					},
				},
			},
			wantMatch: false,
			wantErr:   false,
		},
		{
			name: "no match when email doesn't match",
			user: &model.User{
				AlternateEmail: []model.AlternateEmail{
					{Email: "alt@example.com", EmailVerified: true},
				},
			},
			auth0User: &Auth0User{
				Identities: []Auth0Identity{
					{
						Connection: emailAuthenticationFilter,
						ProfileData: &Auth0ProfileData{
							Email:         "different@example.com",
							EmailVerified: true,
						},
					},
				},
			},
			wantMatch: false,
			wantErr:   false,
		},
		{
			name: "matches with multiple alternate emails",
			user: &model.User{
				AlternateEmail: []model.AlternateEmail{
					{Email: "alt1@example.com", EmailVerified: true},
					{Email: "alt2@example.com", EmailVerified: false},
				},
			},
			auth0User: &Auth0User{
				Identities: []Auth0Identity{
					{
						Connection: emailAuthenticationFilter,
						ProfileData: &Auth0ProfileData{
							Email:         "alt2@example.com",
							EmailVerified: true,
						},
					},
				},
			},
			wantMatch: true,
			wantErr:   false,
		},
		{
			name: "checks multiple identities and finds match",
			user: &model.User{
				AlternateEmail: []model.AlternateEmail{
					{Email: "alt@example.com", EmailVerified: true},
				},
			},
			auth0User: &Auth0User{
				Identities: []Auth0Identity{
					{
						Connection: "google-oauth2",
						ProfileData: &Auth0ProfileData{
							Email: "other@example.com",
						},
					},
					{
						Connection: emailAuthenticationFilter,
						ProfileData: &Auth0ProfileData{
							Email:         "alt@example.com",
							EmailVerified: true,
						},
					},
				},
			},
			wantMatch: true,
			wantErr:   false,
		},
		{
			name: "no match when identities array is empty",
			user: &model.User{
				AlternateEmail: []model.AlternateEmail{
					{Email: "alt@example.com", EmailVerified: true},
				},
			},
			auth0User: &Auth0User{
				Identities: []Auth0Identity{},
			},
			wantMatch: false,
			wantErr:   false,
		},
		{
			name: "no match when user has no alternate emails",
			user: &model.User{
				AlternateEmail: []model.AlternateEmail{},
			},
			auth0User: &Auth0User{
				Identities: []Auth0Identity{
					{
						Connection: emailAuthenticationFilter,
						ProfileData: &Auth0ProfileData{
							Email:         "alt@example.com",
							EmailVerified: true,
						},
					},
				},
			},
			wantMatch: false,
			wantErr:   false,
		},
		{
			name: "appends alternate email when match found",
			user: &model.User{
				AlternateEmail: []model.AlternateEmail{
					{Email: "alt@example.com", EmailVerified: false},
				},
			},
			auth0User: &Auth0User{
				Identities: []Auth0Identity{
					{
						Connection: emailAuthenticationFilter,
						ProfileData: &Auth0ProfileData{
							Email:         "alt@example.com",
							EmailVerified: true,
						},
					},
				},
			},
			wantMatch: true,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Store original length for verification
			originalLen := len(tt.auth0User.AlternateEmail)

			filter := &alternateEmailFilter{user: tt.user}
			match, err := filter.Filter(ctx, tt.auth0User)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tt.wantMatch, match)

			// Verify that alternate email was appended to auth0User when match is found
			if tt.wantMatch && !tt.wantErr {
				assert.Greater(t, len(tt.auth0User.AlternateEmail), originalLen)
			}
		})
	}
}

func Test_criteriaEndpointMapping(t *testing.T) {
	// Test that all expected criteria types have endpoints defined
	expectedCriteria := []string{
		constants.CriteriaTypeEmail,
		constants.CriteriaTypeUsername,
		constants.CriteriaTypeAlternateEmail,
	}

	for _, criteria := range expectedCriteria {
		t.Run("has endpoint for "+criteria, func(t *testing.T) {
			endpoint, exists := criteriaEndpointMapping[criteria]
			assert.True(t, exists, "endpoint should exist for criteria: %s", criteria)
			assert.NotEmpty(t, endpoint, "endpoint should not be empty for criteria: %s", criteria)
		})
	}

	// Test endpoint formats
	t.Run("email endpoint has correct format", func(t *testing.T) {
		endpoint := criteriaEndpointMapping[constants.CriteriaTypeEmail]
		assert.Contains(t, endpoint, "users-by-email?email=%s")
	})

	t.Run("username endpoint has correct format", func(t *testing.T) {
		endpoint := criteriaEndpointMapping[constants.CriteriaTypeUsername]
		assert.Contains(t, endpoint, "users?q=identities.user_id:")
		assert.Contains(t, endpoint, "search_engine=v3")
	})

	t.Run("alternate email endpoint has correct format", func(t *testing.T) {
		endpoint := criteriaEndpointMapping[constants.CriteriaTypeAlternateEmail]
		assert.Contains(t, endpoint, "users?q=identities.profileData.email:")
		assert.Contains(t, endpoint, "search_engine=v3")
	})
}
