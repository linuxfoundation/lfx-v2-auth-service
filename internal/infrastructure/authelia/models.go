// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package authelia

import (
	"time"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
)

// OIDCUserInfo represents the response from the OIDC userinfo endpoint
type OIDCUserInfo struct {
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Rat               int64  `json:"rat"`
	Sub               string `json:"sub"`
	UpdatedAt         int64  `json:"updated_at"`
}

// AutheliaUser wraps model.User with Authelia-specific fields
type AutheliaUser struct {
	*model.User

	// Authelia-specific fields
	Email       string    `json:"email"`       // email for Authelia
	Password    string    `json:"password"`    // bcrypt hash for Authelia
	DisplayName string    `json:"displayname"` // display name for Authelia
	CreatedAt   time.Time `json:"created_at"`  // creation timestamp
	UpdatedAt   time.Time `json:"updated_at"`  // update timestamp

	// not part of the user model, but used to track if the user is missing from the orchestrator
	// or if the password needs to be updated
	actionNeeded string
}

// AutheliaUserStorage represents the storage format for Authelia users
// This struct excludes sensitive fields like token, user_id, and primary_email
type AutheliaUserStorage struct {
	Username       string              `json:"username"`
	Sub            string              `json:"sub"`                       // sub for Authelia
	Email          string              `json:"email"`                     // email for Authelia
	DisplayName    string              `json:"displayname"`               // display name for Authelia
	UserMetadata   *model.UserMetadata `json:"user_metadata,omitempty"`   // user metadata from domain model
	AlternateEmail []model.Email       `json:"alternate_email,omitempty"` // alternate email for Authelia
	CreatedAt      time.Time           `json:"created_at"`                // creation timestamp
	UpdatedAt      time.Time           `json:"updated_at"`                // update timestamp
}

// SetUsername sets the username for the user
func (a *AutheliaUser) SetUsername(username string) {
	if a.User == nil {
		a.User = &model.User{}
	}
	a.Username = username
}

// ToStorage converts AutheliaUser to AutheliaUserStorage for storage operations
func (a *AutheliaUser) ToStorage() *AutheliaUserStorage {
	var (
		username       string
		userMetadata   *model.UserMetadata
		alternateEmail []model.Email
	)

	if a.User != nil {
		username = a.Username
		userMetadata = a.UserMetadata
		alternateEmail = a.AlternateEmails
	}

	return &AutheliaUserStorage{
		Username:       username,
		Sub:            a.Sub,
		Email:          a.Email,
		DisplayName:    a.DisplayName,
		UserMetadata:   userMetadata,
		AlternateEmail: alternateEmail,
		CreatedAt:      a.CreatedAt,
		UpdatedAt:      a.UpdatedAt,
	}
}

// FromStorage converts AutheliaUserStorage to AutheliaUser
func (a *AutheliaUser) FromStorage(storage *AutheliaUserStorage) {
	if a.User == nil {
		a.User = &model.User{}
	}
	a.Username = storage.Username
	a.UserMetadata = storage.UserMetadata
	a.AlternateEmails = storage.AlternateEmail
	// for consistency in naming across implementations,
	// we use the unique identifier as the user_id
	a.UserID = storage.Sub
	a.Sub = storage.Sub
	a.Email = storage.Email
	a.DisplayName = storage.DisplayName
	a.CreatedAt = storage.CreatedAt
	a.UpdatedAt = storage.UpdatedAt
}

// AutheliaUserYAML represents the YAML structure for Authelia users_database.yml
type AutheliaUserYAML struct {
	DisplayName string `yaml:"displayname"`
	Password    string `yaml:"password"`
	Email       string `yaml:"email"`
}

// ToAutheliaYAML converts AutheliaUser to the format expected by Authelia
func (a *AutheliaUser) ToAutheliaYAML() AutheliaUserYAML {
	return AutheliaUserYAML{
		DisplayName: a.DisplayName,
		Password:    a.Password,
		Email:       a.Email,
	}
}

// convertUsersToAutheliaFormat converts a map of AutheliaUser to Authelia YAML format
func convertUsersToAutheliaFormat(users map[string]*AutheliaUser) map[string]map[string]AutheliaUserYAML {
	result := map[string]map[string]AutheliaUserYAML{
		"users": make(map[string]AutheliaUserYAML),
	}

	for username, user := range users {
		result["users"][username] = user.ToAutheliaYAML()
	}

	return result
}
