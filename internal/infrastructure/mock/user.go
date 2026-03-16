// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package mock

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/jwt"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/password"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
	"gopkg.in/yaml.v3"
)

// otpEntry stores OTP data with expiration time
type otpEntry struct {
	otp       string
	expiresAt time.Time
}

type userWriter struct {
	// In-memory storage for mock users
	users map[string]*model.User
	// In-memory storage for OTPs (email -> OTP)
	otps map[string]*otpEntry
	// Mutex for thread-safe OTP operations
	otpMutex sync.RWMutex
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
	return nil, errors.NewNotFound("user not found")
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
		return nil, errors.NewNotFound("user not found by criteria")
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

	// Validate email format
	email := &model.Email{Email: alternateEmail}
	if !email.IsValidEmail() {
		return errors.NewValidation("invalid email format")
	}

	// Check if email is already registered as primary or alternate email
	normalizedEmail := strings.ToLower(strings.TrimSpace(alternateEmail))
	for _, user := range u.users {
		// Check primary email
		if strings.ToLower(user.PrimaryEmail) == normalizedEmail {
			return errors.NewValidation("alternate email already linked")
		}
		// Check alternate emails
		for _, altEmail := range user.AlternateEmails {
			if strings.ToLower(altEmail.Email) == normalizedEmail {
				return errors.NewValidation("alternate email already linked")
			}
		}
	}

	// Generate a 6-digit OTP
	otp, err := password.OnlyNumbers(6)
	if err != nil {
		return errors.NewUnexpected("failed to generate OTP", err)
	}

	// Store OTP with 5-minute expiration
	u.otpMutex.Lock()
	u.otps[normalizedEmail] = &otpEntry{
		otp:       otp,
		expiresAt: time.Now().Add(5 * time.Minute),
	}
	u.otpMutex.Unlock()

	slog.InfoContext(ctx, "mock: OTP generated for email verification",
		"email", redaction.Redact(alternateEmail),
		"otp", otp,
		"expires_in", "5m",
	)

	return nil
}

func (u *userWriter) VerifyAlternateEmail(ctx context.Context, email *model.Email) (*model.AuthResponse, error) {
	slog.DebugContext(ctx, "mock: verifying alternate email", "email", redaction.Redact(email.Email))

	if email.Email == "" || email.OTP == "" {
		return nil, errors.NewValidation("email and OTP are required")
	}

	// Validate email format
	if !email.IsValidEmail() {
		return nil, errors.NewValidation("invalid email format")
	}

	normalizedEmail := strings.ToLower(strings.TrimSpace(email.Email))

	// Check if email is already linked (re-check to prevent race conditions)
	for _, user := range u.users {
		if strings.ToLower(user.PrimaryEmail) == normalizedEmail {
			return nil, errors.NewValidation("alternate email already linked")
		}
		for _, altEmail := range user.AlternateEmails {
			if strings.ToLower(altEmail.Email) == normalizedEmail {
				return nil, errors.NewValidation("alternate email already linked")
			}
		}
	}

	// Verify OTP
	u.otpMutex.RLock()
	entry, exists := u.otps[normalizedEmail]
	u.otpMutex.RUnlock()

	if !exists {
		return nil, errors.NewValidation("OTP not found or expired")
	}

	// Check if OTP is expired
	if time.Now().After(entry.expiresAt) {
		// Clean up expired OTP
		u.otpMutex.Lock()
		delete(u.otps, normalizedEmail)
		u.otpMutex.Unlock()
		return nil, errors.NewValidation("OTP expired")
	}

	// Verify OTP matches
	if entry.otp != email.OTP {
		return nil, errors.NewValidation("invalid OTP")
	}

	// OTP is valid, clean it up
	u.otpMutex.Lock()
	delete(u.otps, normalizedEmail)
	u.otpMutex.Unlock()

	// Generate an identity token for the verified email
	idToken, err := jwt.GenerateSimpleTestIdentityToken(email.Email, 1*time.Hour)
	if err != nil {
		return nil, errors.NewUnexpected("failed to generate identity token", err)
	}

	slog.InfoContext(ctx, "mock: email verified successfully",
		"email", redaction.Redact(email.Email),
	)

	// Return auth response with identity token
	return &model.AuthResponse{
		IDToken:   idToken,
		TokenType: "Bearer",
		ExpiresIn: 3600, // 1 hour
	}, nil
}

func (u *userWriter) LinkIdentity(ctx context.Context, request *model.LinkIdentity) error {
	slog.DebugContext(ctx, "mock: linking identity")

	if request == nil {
		return errors.NewValidation("link identity request is required")
	}

	if request.User.UserID == "" {
		return errors.NewValidation("user_id is required")
	}

	if request.LinkWith.IdentityToken == "" {
		return errors.NewValidation("identity_token is required")
	}

	// Extract email from the identity token
	email, err := jwt.ExtractEmail(ctx, request.LinkWith.IdentityToken)
	if err != nil {
		return errors.NewValidation("failed to extract email from identity token")
	}

	if email == "" {
		return errors.NewValidation("identity token does not contain email claim")
	}

	normalizedEmail := strings.ToLower(strings.TrimSpace(email))

	slog.InfoContext(ctx, "mock: linking email to user",
		"user_id", redaction.Redact(request.User.UserID),
		"email", redaction.Redact(email),
	)

	// Find the user by user_id
	user, exists := u.users[request.User.UserID]
	if !exists {
		return errors.NewNotFound("user not found")
	}

	// Check if email is already the primary email
	if strings.ToLower(user.PrimaryEmail) == normalizedEmail {
		return errors.NewValidation("email is already the primary email")
	}

	// Check if email is already in alternate emails
	for _, altEmail := range user.AlternateEmails {
		if strings.ToLower(altEmail.Email) == normalizedEmail {
			return errors.NewValidation("email is already linked as alternate email")
		}
	}

	// Check if this email is linked to any other user
	for _, otherUser := range u.users {
		if otherUser.UserID == user.UserID {
			continue
		}
		if strings.ToLower(otherUser.PrimaryEmail) == normalizedEmail {
			return errors.NewValidation("email is already linked to another user")
		}
		for _, altEmail := range otherUser.AlternateEmails {
			if strings.ToLower(altEmail.Email) == normalizedEmail {
				return errors.NewValidation("email is already linked to another user")
			}
		}
	}

	// Add email to alternate emails
	user.AlternateEmails = append(user.AlternateEmails, model.Email{
		Email:    email,
		Verified: true,
	})

	slog.InfoContext(ctx, "mock: identity linked successfully",
		"user_id", redaction.Redact(request.User.UserID),
		"email", redaction.Redact(email),
		"total_alternate_emails", len(user.AlternateEmails),
	)

	return nil
}

func (u *userWriter) UnlinkIdentity(ctx context.Context, request *model.UnlinkIdentity) error {
	slog.DebugContext(ctx, "mock: unlink identity - not implemented")
	return errors.NewServiceUnavailable("unlink identity is not implemented for mock")
}

func (u *userWriter) MetadataLookup(ctx context.Context, input string, requiredScopes ...string) (*model.User, error) {
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
	otps := make(map[string]*otpEntry)

	// Load users from embedded YAML file
	mockUsers, err := loadUsersFromYAML(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "failed to load users from YAML file", "error", err)
		return &userWriter{users: users, otps: otps} // Return empty store if YAML fails
	}

	if len(mockUsers) == 0 {
		slog.WarnContext(ctx, "no users found in YAML file")
		return &userWriter{users: users, otps: otps} // Return empty store if no users
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
		users:    users,
		otps:     otps,
		otpMutex: sync.RWMutex{},
	}
}
