// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package mock

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"strings"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/jwt"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
	"gopkg.in/yaml.v3"
)

type userWriter struct {
	// In-memory storage for mock users
	users map[string]*model.User
}

//go:embed users.yaml
var usersYAML []byte

// UserData represents the structure for YAML file
type UserData struct {
	Users []model.User `yaml:"users"`
}

// loadUsersFromYAML loads users from embedded YAML file
func loadUsersFromYAML(ctx context.Context) ([]*model.User, error) {
	var userData UserData
	if err := yaml.Unmarshal(usersYAML, &userData); err != nil {
		slog.ErrorContext(ctx, "failed to unmarshal YAML users", "error", err)
		return nil, fmt.Errorf("failed to unmarshal YAML users: %w", err)
	}

	users := make([]*model.User, len(userData.Users))
	for i := range userData.Users {
		users[i] = &userData.Users[i]
	}

	slog.InfoContext(ctx, "loaded users from embedded YAML", "count", len(users))
	return users, nil
}

func (u *userWriter) GetUser(ctx context.Context, user *model.User) (*model.User, error) {
	slog.InfoContext(ctx, "mock: getting user", "user", user)

	// For mock implementation, we'll use user_id, sub, username, or primary email as key
	key := user.UserID
	if key == "" {
		key = user.Sub
	}
	if key == "" {
		key = user.Username
	}
	if key == "" {
		key = user.PrimaryEmail
	}

	if key == "" {
		return nil, fmt.Errorf("mock: user identifier (user_id, sub, username, or primary email) is required")
	}

	// Check if user exists in mock storage
	if existingUser, exists := u.users[key]; exists {
		slog.InfoContext(ctx, "mock: user found in storage", "key", key)
		return existingUser, nil
	}

	// If not found, return error (consistent with Auth0 behavior)
	slog.InfoContext(ctx, "mock: user not found in storage", "key", key)
	return nil, fmt.Errorf("user not found")
}

func (u *userWriter) SearchUser(ctx context.Context, user *model.User, criteria string) (*model.User, error) {
	slog.InfoContext(ctx, "mock: searching user", "user", user, "criteria", criteria)

	// For mock implementation, we'll search by the criteria string as a key first
	if existingUser, exists := u.users[criteria]; exists {
		slog.InfoContext(ctx, "mock: user found by criteria", "criteria", criteria)
		return existingUser, nil
	}

	// If not found by criteria, try GetUser behavior
	result, err := u.GetUser(ctx, user)
	if err != nil {
		// Return a more specific search error
		slog.InfoContext(ctx, "mock: user not found by search criteria", "criteria", criteria)
		return nil, fmt.Errorf("user not found by criteria")
	}

	return result, nil
}

func (u *userWriter) UpdateUser(ctx context.Context, user *model.User) (*model.User, error) {
	slog.InfoContext(ctx, "mock: updating user", "user", user)

	// For mock implementation, we'll use user_id, sub, username, or primary email as key
	key := user.UserID
	if key == "" {
		key = user.Sub
	}
	if key == "" {
		key = user.Username
	}
	if key == "" {
		key = user.PrimaryEmail
	}

	if key == "" {
		return nil, fmt.Errorf("mock: user identifier (user_id, sub, username, or primary email) is required")
	}

	// Get existing user from storage
	existingUser, exists := u.users[key]
	if !exists {
		// If user doesn't exist, create a new one with the provided data
		u.users[key] = user
		slog.InfoContext(ctx, "mock: new user created in storage", "key", key)
		return user, nil
	}

	// PATCH-style update: only update fields that are provided (non-empty/non-nil)
	updatedUser := *existingUser // Create a copy of the existing user

	// Update basic fields only if they're provided (non-empty)
	if user.Token != "" {
		updatedUser.Token = user.Token
	}
	if user.UserID != "" {
		updatedUser.UserID = user.UserID
	}
	if user.Sub != "" {
		updatedUser.Sub = user.Sub
	}
	if user.Username != "" {
		updatedUser.Username = user.Username
	}
	if user.PrimaryEmail != "" {
		updatedUser.PrimaryEmail = user.PrimaryEmail
	}

	// Update UserMetadata only if it's provided (not nil)
	if user.UserMetadata != nil {
		if updatedUser.UserMetadata == nil {
			// If existing user has no metadata, use the provided metadata
			updatedUser.UserMetadata = user.UserMetadata
		} else {
			// Partial update of metadata fields - only update non-nil fields
			if user.UserMetadata.Picture != nil {
				updatedUser.UserMetadata.Picture = user.UserMetadata.Picture
			}
			if user.UserMetadata.Zoneinfo != nil {
				updatedUser.UserMetadata.Zoneinfo = user.UserMetadata.Zoneinfo
			}
			if user.UserMetadata.Name != nil {
				updatedUser.UserMetadata.Name = user.UserMetadata.Name
			}
			if user.UserMetadata.GivenName != nil {
				updatedUser.UserMetadata.GivenName = user.UserMetadata.GivenName
			}
			if user.UserMetadata.FamilyName != nil {
				updatedUser.UserMetadata.FamilyName = user.UserMetadata.FamilyName
			}
			if user.UserMetadata.JobTitle != nil {
				updatedUser.UserMetadata.JobTitle = user.UserMetadata.JobTitle
			}
			if user.UserMetadata.Organization != nil {
				updatedUser.UserMetadata.Organization = user.UserMetadata.Organization
			}
			if user.UserMetadata.Country != nil {
				updatedUser.UserMetadata.Country = user.UserMetadata.Country
			}
			if user.UserMetadata.StateProvince != nil {
				updatedUser.UserMetadata.StateProvince = user.UserMetadata.StateProvince
			}
			if user.UserMetadata.City != nil {
				updatedUser.UserMetadata.City = user.UserMetadata.City
			}
			if user.UserMetadata.Address != nil {
				updatedUser.UserMetadata.Address = user.UserMetadata.Address
			}
			if user.UserMetadata.PostalCode != nil {
				updatedUser.UserMetadata.PostalCode = user.UserMetadata.PostalCode
			}
			if user.UserMetadata.PhoneNumber != nil {
				updatedUser.UserMetadata.PhoneNumber = user.UserMetadata.PhoneNumber
			}
			if user.UserMetadata.TShirtSize != nil {
				updatedUser.UserMetadata.TShirtSize = user.UserMetadata.TShirtSize
			}
		}
	}

	// Store the updated user back to storage
	u.users[key] = &updatedUser
	slog.InfoContext(ctx, "mock: user updated in storage with PATCH semantics", "key", key)

	return &updatedUser, nil
}

func (u *userWriter) SendVerificationAlternateEmail(ctx context.Context, alternateEmail string) error {
	slog.DebugContext(ctx, "mock: sending alternate email verification", "alternate_email", redaction.Redact(alternateEmail))
	return nil
}

func (u *userWriter) VerifyAlternateEmail(ctx context.Context, email *model.Email) (*model.User, error) {
	slog.DebugContext(ctx, "mock: verifying alternate email", "email", redaction.Redact(email.Email))
	// For mock implementation, return a basic user object
	return &model.User{
		PrimaryEmail: email.Email,
	}, nil
}

func (u *userWriter) MetadataLookup(ctx context.Context, input string) (*model.User, error) {
	slog.DebugContext(ctx, "mock: metadata lookup", "input", input)

	// Trim whitespace from input
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, errors.NewValidation("input is required")
	}

	user := &model.User{}

	// First, try to parse as JWT token to extract the sub
	if cleanToken, isJWT := jwt.LooksLikeJWT(input); isJWT {
		sub, err := u.extractSubFromJWT(ctx, cleanToken)
		if err != nil {
			slog.WarnContext(ctx, "mock: failed to parse JWT, treating as regular input", "error", err)
			// If JWT parsing fails, fall back to regular input processing
		} else {
			// Successfully extracted sub from JWT
			input = sub
			slog.InfoContext(ctx, "mock: extracted sub from JWT", "sub", sub)
		}
	}

	// Determine lookup strategy based on input format
	switch {
	case strings.Contains(input, "|"):
		// Input contains "|", use as sub for canonical lookup
		user.Sub = input
		user.UserID = input
		user.Username = ""
		user.PrimaryEmail = ""
		slog.InfoContext(ctx, "mock: canonical lookup strategy", "sub", input)
	case strings.Contains(input, "@"):
		// Input looks like an email, use for email search
		user.PrimaryEmail = strings.ToLower(input) // Normalize email to lowercase
		user.Sub = ""
		user.UserID = ""
		user.Username = ""
		slog.InfoContext(ctx, "mock: email search strategy", "email", user.PrimaryEmail)
	default:
		// Input doesn't contain "|" or "@", use for username search
		user.Username = input
		user.Sub = ""
		user.UserID = ""
		user.PrimaryEmail = ""
		slog.InfoContext(ctx, "mock: username search strategy", "username", input)
	}

	return user, nil
}

// extractSubFromJWT extracts the 'sub' claim from a JWT token
func (u *userWriter) extractSubFromJWT(ctx context.Context, tokenString string) (string, error) {
	// Use the JWT utility to extract the subject
	subject, err := jwt.ExtractSubject(ctx, tokenString)
	if err != nil {
		return "", err
	}

	slog.DebugContext(ctx, "mock: extracted sub from JWT", "sub", subject)
	return subject, nil
}

// NewUserReaderWriter creates a new mock UserReaderWriter with YAML file as the data source
func NewUserReaderWriter(ctx context.Context) port.UserReaderWriter {
	users := make(map[string]*model.User)

	// Load users from embedded YAML file
	mockUsers, err := loadUsersFromYAML(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "failed to load users from YAML file", "error", err)
		return &userWriter{users: users} // Return empty store if YAML fails
	}

	if len(mockUsers) == 0 {
		slog.WarnContext(ctx, "no users found in YAML file")
		return &userWriter{users: users} // Return empty store if no users
	}

	slog.InfoContext(ctx, "successfully loaded users from YAML file", "count", len(mockUsers))

	// Add users to storage with multiple keys for lookup flexibility
	for _, user := range mockUsers {
		// Add by user_id (primary key)
		if user.UserID != "" {
			users[user.UserID] = user
		}
		// Add by sub if different from user_id
		if user.Sub != "" && user.Sub != user.UserID {
			users[user.Sub] = user
		}
		// Add by username
		if user.Username != "" {
			users[user.Username] = user
		}
		// Add by primary email
		if user.PrimaryEmail != "" {
			users[user.PrimaryEmail] = user
		}

		slog.InfoContext(ctx, "mock: loaded user",
			"user_id", user.UserID,
			"sub", user.Sub,
			"username", user.Username,
			"primary_email", user.PrimaryEmail,
			"name", func() string {
				if user.UserMetadata != nil && user.UserMetadata.Name != nil {
					return *user.UserMetadata.Name
				}
				return "unknown"
			}(),
		)
	}

	slog.InfoContext(ctx, "mock: initialized user store", "total_users", len(mockUsers), "total_keys", len(users))

	return &userWriter{
		users: users,
	}
}
