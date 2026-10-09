// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package authelia

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/converters"
	errs "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/httpclient"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserWriter_UpdateUser_MetadataPatchBehavior(t *testing.T) {
	ctx := context.Background()

	// Test that the Patch method is called and behaves correctly
	existingUser := &AutheliaUser{
		User: &model.User{
			Username: "testuser",
			UserMetadata: &model.UserMetadata{
				Name:               converters.StringPtr("John Doe"),
				JobTitle:           converters.StringPtr("Engineer"),
				Organization:       converters.StringPtr("ACME Corp"),
				OrganizationDomain: converters.StringPtr("acme.com"),
				Country:            converters.StringPtr("USA"),
				Skills:             converters.StringPtr("Go, Python"),
			},
		},
	}

	inputUser := &model.User{
		Token:    "authelia_at_testuser",
		Username: "testuser",
		UserMetadata: &model.UserMetadata{
			Name:     converters.StringPtr("Jane Doe"), // Update
			JobTitle: nil,                              // Should not change existing
			City:     converters.StringPtr("New York"), // New field
			// Organization, OrganizationDomain, Country, and Skills not specified - should be preserved
		},
	}

	mockStorage := &mockStorageReaderWriter{
		users: map[string]*AutheliaUser{
			"testuser": existingUser,
		},
	}

	userWriter := newUserInfoTestWriter(t, mockStorage, map[string]OIDCUserInfo{
		"authelia_at_testuser": {Sub: "testuser-sub", PreferredUsername: "testuser"},
	})

	result, err := userWriter.UpdateUser(ctx, inputUser)
	if err != nil {
		t.Fatalf("UpdateUser() failed: %v", err)
	}

	if result.UserMetadata == nil {
		t.Fatal("UpdateUser() result should have UserMetadata")
	}

	// Verify updated field
	if result.UserMetadata.Name == nil || *result.UserMetadata.Name != "Jane Doe" {
		t.Error("UpdateUser() should update Name field")
	}

	// Verify preserved fields (not specified in input)
	if result.UserMetadata.JobTitle == nil || *result.UserMetadata.JobTitle != "Engineer" {
		t.Error("UpdateUser() should preserve JobTitle when not specified in input")
	}
	if result.UserMetadata.Organization == nil || *result.UserMetadata.Organization != "ACME Corp" {
		t.Error("UpdateUser() should preserve Organization when not specified in input")
	}
	if result.UserMetadata.OrganizationDomain == nil || *result.UserMetadata.OrganizationDomain != "acme.com" {
		t.Error("UpdateUser() should preserve OrganizationDomain when not specified in input")
	}
	if result.UserMetadata.Country == nil || *result.UserMetadata.Country != "USA" {
		t.Error("UpdateUser() should preserve Country when not specified in input")
	}
	if result.UserMetadata.Skills == nil || *result.UserMetadata.Skills != "Go, Python" {
		t.Error("UpdateUser() should preserve Skills when not specified in input")
	}

	// Verify new field
	if result.UserMetadata.City == nil || *result.UserMetadata.City != "New York" {
		t.Error("UpdateUser() should add new City field")
	}
}

// newUserInfoTestWriter returns a userReaderWriter whose OIDC userinfo
// endpoint answers for the given bearer tokens and rejects any other token.
func newUserInfoTestWriter(t *testing.T, storage *mockStorageReaderWriter, tokens map[string]OIDCUserInfo) *userReaderWriter {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, ok := tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	}))
	t.Cleanup(server.Close)
	return &userReaderWriter{
		storage:         storage,
		oidcUserInfoURL: server.URL,
		httpClient:      httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second}),
	}
}

// TestUserWriter_UpdateUser_RequiresVerifiedIdentity verifies that metadata
// updates are refused without a verified token and always apply to the account
// the token belongs to, never to a caller-supplied username.
func TestUserWriter_UpdateUser_RequiresVerifiedIdentity(t *testing.T) {
	ctx := context.Background()

	newStorage := func() *mockStorageReaderWriter {
		return &mockStorageReaderWriter{users: map[string]*AutheliaUser{
			"victim":   {User: &model.User{Username: "victim", UserMetadata: &model.UserMetadata{Name: converters.StringPtr("Victim")}}},
			"attacker": {User: &model.User{Username: "attacker", UserMetadata: &model.UserMetadata{Name: converters.StringPtr("Attacker")}}},
		}}
	}
	tokens := map[string]OIDCUserInfo{
		"authelia_at_attacker": {Sub: "attacker-sub", PreferredUsername: "attacker"},
		"authelia_at_nosub":    {PreferredUsername: "victim"},
	}

	for _, token := range []string{"", "authelia_at_invalid", "authelia_at_nosub"} {
		t.Run("rejects token "+token, func(t *testing.T) {
			storage := newStorage()
			rw := newUserInfoTestWriter(t, storage, tokens)
			_, err := rw.UpdateUser(ctx, &model.User{
				Token:        token,
				Username:     "victim",
				UserMetadata: &model.UserMetadata{Name: converters.StringPtr("Mallory")},
			})
			var unauthorized errs.Unauthorized
			require.ErrorAs(t, err, &unauthorized)
			assert.Equal(t, "Victim", *storage.users["victim"].UserMetadata.Name)
		})
	}

	t.Run("caller-supplied identity is ignored in favour of the token identity", func(t *testing.T) {
		storage := newStorage()
		rw := newUserInfoTestWriter(t, storage, tokens)
		input := &model.User{
			Token:        "authelia_at_attacker",
			UserID:       "victim-sub",
			Sub:          "victim-sub",
			Username:     "victim",
			UserMetadata: &model.UserMetadata{Name: converters.StringPtr("Mallory")},
		}
		result, err := rw.UpdateUser(ctx, input)
		require.NoError(t, err)
		assert.Equal(t, "attacker", result.Username)
		// The handler publishes input.UserID downstream, so it must carry the
		// verified identity rather than the caller-supplied one.
		assert.Equal(t, "attacker-sub", input.UserID)
		assert.Equal(t, "attacker-sub", input.Sub)
		assert.Equal(t, "Victim", *storage.users["victim"].UserMetadata.Name)
		assert.Equal(t, "Mallory", *storage.users["attacker"].UserMetadata.Name)
	})
}

// TestUserReaderWriter_GetUser_Identities tests that GetUser correctly returns the identities
// stored in the backing store without any transformation.
func TestUserReaderWriter_GetUser_Identities(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name               string
		storageUsers       map[string]*AutheliaUser
		storageErr         error
		inputUser          *model.User
		expectError        bool
		expectedIdentities []model.Identity
	}{
		{
			name: "GetUser_WithLinkedIdentities",
			storageUsers: map[string]*AutheliaUser{
				"testuser": {
					User: &model.User{
						Username: "testuser",
						Identities: []model.Identity{
							{Provider: "google-oauth2", IdentityID: "g123", IsSocial: true, Email: "u@gmail.com", EmailVerified: true},
						},
					},
				},
			},
			inputUser: &model.User{Username: "testuser"},
			expectedIdentities: []model.Identity{
				{Provider: "google-oauth2", IdentityID: "g123", IsSocial: true, Email: "u@gmail.com", EmailVerified: true},
			},
		},
		{
			name: "GetUser_WithNoIdentities",
			storageUsers: map[string]*AutheliaUser{
				"testuser": {
					User: &model.User{
						Username: "testuser",
					},
				},
			},
			inputUser:          &model.User{Username: "testuser"},
			expectedIdentities: nil,
		},
		{
			name: "GetUser_WithMultipleIdentities",
			storageUsers: map[string]*AutheliaUser{
				"testuser": {
					User: &model.User{
						Username: "testuser",
						Identities: []model.Identity{
							{Provider: "google-oauth2", IdentityID: "g123", IsSocial: true},
							{Provider: "github", IdentityID: "gh456", IsSocial: true, Nickname: "octocat"},
						},
					},
				},
			},
			inputUser: &model.User{Username: "testuser"},
			expectedIdentities: []model.Identity{
				{Provider: "google-oauth2", IdentityID: "g123", IsSocial: true},
				{Provider: "github", IdentityID: "gh456", IsSocial: true, Nickname: "octocat"},
			},
		},
		{
			name:         "GetUser_UserNotFound",
			storageUsers: map[string]*AutheliaUser{},
			inputUser:    &model.User{Username: "unknown"},
			expectError:  true,
		},
		{
			name:        "GetUser_NilInput",
			inputUser:   nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rw := &userReaderWriter{
				storage: &mockStorageReaderWriter{
					users:      tt.storageUsers,
					getUserErr: tt.storageErr,
				},
			}

			got, err := rw.GetUser(ctx, tt.inputUser)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, got)
			require.Len(t, got.Identities, len(tt.expectedIdentities))

			for i, want := range tt.expectedIdentities {
				assert.Equal(t, want.Provider, got.Identities[i].Provider, "identity[%d].Provider", i)
				assert.Equal(t, want.IdentityID, got.Identities[i].IdentityID, "identity[%d].IdentityID", i)
				assert.Equal(t, want.IsSocial, got.Identities[i].IsSocial, "identity[%d].IsSocial", i)
				assert.Equal(t, want.Email, got.Identities[i].Email, "identity[%d].Email", i)
				assert.Equal(t, want.Nickname, got.Identities[i].Nickname, "identity[%d].Nickname", i)
			}
		})
	}
}

// TestUserReaderWriter_MetadataLookup tests the MetadataLookup method for Authelia implementation
func TestUserReaderWriter_MetadataLookup(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name         string
		input        string
		expectError  bool
		errorMessage string
	}{
		{
			name:         "empty input",
			input:        "",
			expectError:  true,
			errorMessage: "input is required",
		},
		{
			name:        "invalid token - should fail OIDC fetch",
			input:       "invalid-token",
			expectError: false, // Now handled as username lookup
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create userReaderWriter without OIDC configuration
			// This will cause fetchOIDCUserInfo to fail, which is expected for most tests
			writer := &userReaderWriter{}

			user, err := writer.MetadataLookup(ctx, tt.input)

			// Check error expectation
			if tt.expectError {
				if err == nil {
					t.Errorf("MetadataLookup() expected error but got none")
					return
				}
				if tt.errorMessage != "" && err.Error() != tt.errorMessage {
					t.Errorf("MetadataLookup() error = %q, expected %q", err.Error(), tt.errorMessage)
				}
				return
			}

			// Check no error when not expected
			if err != nil {
				t.Errorf("MetadataLookup() unexpected error: %v", err)
				return
			}

			// Check user is not nil
			if user == nil {
				t.Errorf("MetadataLookup() returned nil user")
				return
			}
		})
	}
}

// TestUserReaderWriter_LinkIdentity_TokenVerification tests that LinkIdentity only
// accepts email identity tokens signed by this service.
func TestUserReaderWriter_LinkIdentity_TokenVerification(t *testing.T) {
	ctx := context.Background()

	const (
		userSub     = "attacker-sub"
		autheliaTok = "authelia_at_attacker"
		victimEmail = "victim@example.com"
	)
	lookupKey := "sub:" + (&model.User{Sub: userSub}).BuildSubIndexKey(ctx)

	mustToken := func(token string, err error) string {
		t.Helper()
		require.NoError(t, err)
		return token
	}
	enc := base64.RawURLEncoding.EncodeToString
	unsignedToken := enc([]byte(`{"alg":"none","typ":"JWT"}`)) + "." +
		enc([]byte(`{"sub":"email|victim@example.com","email":"victim@example.com"}`)) + "."

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	wrongKeyToken := mustToken(jwt.Generate(&jwt.GeneratorOptions{
		TokenType:     jwt.TokenTypeIdentity,
		Email:         victimEmail,
		Subject:       "email|" + victimEmail,
		ExpiresIn:     time.Hour,
		SigningMethod: jwa.RS256,
		SigningKey:    otherKey,
	}))

	tests := []struct {
		name          string
		authToken     string
		identityToken string
		expectError   bool
	}{
		{
			name:          "valid email identity token is linked",
			authToken:     autheliaTok,
			identityToken: mustToken(jwt.GenerateSimpleTestIdentityTokenWithSubject(victimEmail, "email|"+victimEmail, time.Hour)),
		},
		{
			name:          "unsigned alg=none token is rejected",
			authToken:     autheliaTok,
			identityToken: unsignedToken,
			expectError:   true,
		},
		{
			name:          "token signed with another key is rejected",
			authToken:     autheliaTok,
			identityToken: wrongKeyToken,
			expectError:   true,
		},
		{
			name:          "token without expiration is rejected",
			authToken:     autheliaTok,
			identityToken: mustToken(jwt.GenerateSimpleTestIdentityTokenWithSubject(victimEmail, "email|"+victimEmail, 0)),
			expectError:   true,
		},
		{
			name:          "access token is rejected",
			authToken:     autheliaTok,
			identityToken: mustToken(jwt.GenerateSimpleTestAccessToken("email|"+victimEmail, time.Hour)),
			expectError:   true,
		},
		{
			name:          "social subject is rejected",
			authToken:     autheliaTok,
			identityToken: mustToken(jwt.GenerateSimpleTestIdentityTokenWithSubject(victimEmail, "google-oauth2|123", time.Hour)),
			expectError:   true,
		},
		{
			name:          "subject and email mismatch is rejected",
			authToken:     autheliaTok,
			identityToken: mustToken(jwt.GenerateSimpleTestIdentityTokenWithSubject("attacker@example.com", "email|"+victimEmail, time.Hour)),
			expectError:   true,
		},
		{
			name:          "non-Authelia auth token is rejected",
			authToken:     "0b9f6a52-6c2c-4f0e-9a51-6c1f2d3e4a5b",
			identityToken: mustToken(jwt.GenerateSimpleTestIdentityTokenWithSubject(victimEmail, "email|"+victimEmail, time.Hour)),
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := &mockStorageReaderWriter{
				users: map[string]*AutheliaUser{
					lookupKey: {User: &model.User{Username: lookupKey, Sub: userSub}},
				},
			}
			rw := &userReaderWriter{storage: storage}

			request := &model.LinkIdentity{}
			request.User.UserID = userSub
			request.User.AuthToken = tt.authToken
			request.LinkWith.IdentityToken = tt.identityToken

			err := rw.LinkIdentity(ctx, request)

			stored := storage.users[lookupKey].AlternateEmails
			if tt.expectError {
				require.Error(t, err)
				assert.Empty(t, stored)
				assert.Empty(t, storage.users[lookupKey].Identities)
				return
			}

			require.NoError(t, err)
			require.Len(t, stored, 1)
			assert.Equal(t, victimEmail, stored[0].Email)
			assert.True(t, stored[0].Verified)
		})
	}
}

// TestUserReaderWriter_UnlinkIdentity_RequiresAutheliaToken tests that UnlinkIdentity
// rejects requests whose user was not resolved from an Authelia token.
func TestUserReaderWriter_UnlinkIdentity_RequiresAutheliaToken(t *testing.T) {
	ctx := context.Background()

	const userSub = "0b9f6a52-6c2c-4f0e-9a51-6c1f2d3e4a5b"
	lookupKey := "sub:" + (&model.User{Sub: userSub}).BuildSubIndexKey(ctx)

	tests := []struct {
		name        string
		authToken   string
		expectError bool
	}{
		{name: "Authelia token is accepted", authToken: "authelia_at_owner"},
		{name: "UUID is rejected", authToken: userSub, expectError: true},
		{name: "username is rejected", authToken: "owner", expectError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := &mockStorageReaderWriter{
				users: map[string]*AutheliaUser{
					lookupKey: {User: &model.User{
						Username:        lookupKey,
						Sub:             userSub,
						AlternateEmails: []model.Email{{Email: "alt@example.com", Verified: true}},
					}},
				},
			}
			rw := &userReaderWriter{storage: storage}

			request := &model.UnlinkIdentity{}
			request.User.UserID = userSub
			request.User.AuthToken = tt.authToken
			request.Unlink.Provider = "email"
			request.Unlink.IdentityID = "alt@example.com"

			err := rw.UnlinkIdentity(ctx, request)

			if tt.expectError {
				require.Error(t, err)
				assert.Len(t, storage.users[lookupKey].AlternateEmails, 1)
				return
			}

			require.NoError(t, err)
			assert.Empty(t, storage.users[lookupKey].AlternateEmails)
		})
	}
}
