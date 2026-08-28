// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

// Auth0User represents a user in Auth0
type Auth0User struct {
	UserID         string             `json:"user_id"`
	Username       string             `json:"username"`
	Email          string             `json:"email"`
	Name           string             `json:"name"`
	EmailVerified  bool               `json:"email_verified"`
	FamilyName     string             `json:"family_name"`
	GivenName      string             `json:"given_name"`
	Identities     []Auth0Identity    `json:"identities"`
	AlternateEmail []Auth0ProfileData `json:"alternate_email,omitempty"`
	UserMetadata   *Auth0UserMetadata `json:"user_metadata"`
	AppMetadata    *Auth0AppMetadata  `json:"app_metadata,omitempty"`
}

// Auth0AppMetadata represents the application-level metadata Auth0 stores on a user.
// Only fields relevant to this service are modeled; unknown keys are ignored.
type Auth0AppMetadata struct {
	// SystemManaged marks an identity that was created by this service on behalf
	// of the user (e.g. a system-managed alias such as `@linux.com`) and must
	// not be unlinked through the normal user-initiated unlink flow.
	SystemManaged bool `json:"system_managed,omitempty"`

	// CDPUUID is the user's resolved CDP member id. Once set it is permanent:
	// absent to present is the only legal transition.
	CDPUUID string `json:"cdp_uuid,omitempty"`

	// CDPUUIDSource records which path produced the record — one of
	// `backfill`, `login-resolve`, or `provisioning`. It is present even when
	// no member was found, which is what marks a user as already checked.
	CDPUUIDSource string `json:"cdp_uuid_source,omitempty"`

	// CDPUUIDCheckedAt is the RFC3339 timestamp of the last CDP check.
	CDPUUIDCheckedAt string `json:"cdp_uuid_checked_at,omitempty"`
}

// systemManagedUserPayload is the body for POST /api/v2/users when creating a
// stub passwordless user that will be linked as a system-managed identity.
type systemManagedUserPayload struct {
	Connection    string            `json:"connection"`
	Email         string            `json:"email"`
	EmailVerified bool              `json:"email_verified"`
	AppMetadata   *Auth0AppMetadata `json:"app_metadata,omitempty"`
}

// linkSubIdentityPayload is the body for POST /api/v2/users/{id}/identities when
// linking by `{provider, user_id}` (the M2M direct-link path), as opposed to the
// passwordless `link_with` ID-token flow used by LinkIdentityPayload.
type linkSubIdentityPayload struct {
	Provider string `json:"provider"`
	UserID   string `json:"user_id"`
}

// Auth0Identity represents an identity in Auth0
type Auth0Identity struct {
	Connection  string            `json:"connection"`
	UserID      any               `json:"user_id"`
	Provider    string            `json:"provider"`
	IsSocial    bool              `json:"isSocial"`
	ProfileData *Auth0ProfileData `json:"profileData"`
}

// Auth0ProfileData represents the profile data of a user in Auth0.
type Auth0ProfileData struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Nickname      string `json:"nickname"`
	Name          string `json:"name"`
}

// Auth0UserMetadata represents the metadata of a user in Auth0.
//
// It's the same as the domain User.UserMetadata, but it might be useful
// to have it separated for Auth0 to handle it separately if needed.
type Auth0UserMetadata struct {
	Name               *string `json:"name"`
	FamilyName         *string `json:"family_name"`
	GivenName          *string `json:"given_name"`
	Picture            *string `json:"picture"`
	JobTitle           *string `json:"job_title"`
	Organization       *string `json:"organization"`
	OrganizationDomain *string `json:"organization_domain"`
	Country            *string `json:"country"`
	StateProvince      *string `json:"state_province"`
	City               *string `json:"city"`
	Address            *string `json:"address"`
	PostalCode         *string `json:"postal_code"`
	PhoneNumber        *string `json:"phone_number"`
	TShirtSize         *string `json:"t_shirt_size"`
	Bio                *string `json:"bio"`
	Zoneinfo           *string `json:"zoneinfo"`
}

// ToUser converts an Auth0User to a User
func (u *Auth0User) ToUser() *model.User {
	var meta *model.UserMetadata
	if u.UserMetadata != nil {
		meta = &model.UserMetadata{
			Name:               u.UserMetadata.Name,
			FamilyName:         u.UserMetadata.FamilyName,
			GivenName:          u.UserMetadata.GivenName,
			Picture:            u.UserMetadata.Picture,
			JobTitle:           u.UserMetadata.JobTitle,
			Organization:       u.UserMetadata.Organization,
			OrganizationDomain: u.UserMetadata.OrganizationDomain,
			Country:            u.UserMetadata.Country,
			StateProvince:      u.UserMetadata.StateProvince,
			City:               u.UserMetadata.City,
			Address:            u.UserMetadata.Address,
			PostalCode:         u.UserMetadata.PostalCode,
			PhoneNumber:        u.UserMetadata.PhoneNumber,
			TShirtSize:         u.UserMetadata.TShirtSize,
			Bio:                u.UserMetadata.Bio,
			Zoneinfo:           u.UserMetadata.Zoneinfo,
		}
	}

	var identities []model.Identity
	for _, auth0Id := range u.Identities {
		var identityID string
		switch v := auth0Id.UserID.(type) {
		case float64:
			identityID = strconv.FormatFloat(v, 'f', -1, 64)
		case string:
			identityID = v
		default:
			identityID = fmt.Sprintf("%v", v)
		}

		identity := model.Identity{
			Provider:   auth0Id.Provider,
			IdentityID: identityID,
			Connection: auth0Id.Connection,
			IsSocial:   auth0Id.IsSocial,
		}
		if auth0Id.ProfileData != nil {
			identity.Email = auth0Id.ProfileData.Email
			identity.EmailVerified = auth0Id.ProfileData.EmailVerified
			identity.Nickname = auth0Id.ProfileData.Nickname
			identity.Name = auth0Id.ProfileData.Name
		}
		identities = append(identities, identity)
	}

	return &model.User{
		UserID:       u.UserID,
		Username:     u.Username,
		PrimaryEmail: u.Email,
		Identities:   identities,
		UserMetadata: meta,
	}
}

// unknownAuth0Error is returned when the provider body carries no usable message,
// so a raw response body is never surfaced as an error string.
const unknownAuth0Error = "auth0 request failed"

// ErrorResponse represents an error response from Auth0
type ErrorResponse struct {
	StatusCode int    `json:"statusCode"`
	Error      string `json:"error"`
	Message    string `json:"message"`
	Attributes struct {
		Error string `json:"error"`
	} `json:"attributes"`
}

// ErrorMessage extracts Auth0's human-readable message from a raw error response
// body. The body is unsanitized and may echo submitted values, so it is never
// returned or logged verbatim: anything unparseable yields a generic fallback.
func (e *ErrorResponse) ErrorMessage(rawBody string) string {
	var parsed ErrorResponse
	if err := json.Unmarshal([]byte(rawBody), &parsed); err != nil {
		// Non-JSON bodies are normal for some Auth0 endpoints, not a fault.
		slog.Debug("auth0 error body was not JSON; using generic message")
		return unknownAuth0Error
	}
	if parsed.Message != "" {
		return sanitizeProviderMessage(parsed.Message)
	}
	if parsed.Error != "" {
		return sanitizeProviderMessage(parsed.Error)
	}
	return unknownAuth0Error
}

// sanitizeProviderMessage redacts identifiers Auth0 echoes back from the request
// (emails, provider-delimited user IDs). Valid JSON is not the same as safe
// content: this text is returned inside a domain error that callers log.
func sanitizeProviderMessage(message string) string {
	fields := strings.Fields(message)
	for i, field := range fields {
		trimmed := strings.Trim(field, `"'.,;:()[]{}`)
		if trimmed == "" {
			continue
		}
		var replacement string
		switch {
		case strings.Contains(trimmed, "@"):
			replacement = redaction.RedactEmail(trimmed)
		default:
			// Any "<provider>|<id>" identifier, not just a fixed set of providers:
			// Auth0 also emits email|, google-oauth2|, windowslive|, and others.
			provider, id, found := strings.Cut(trimmed, "|")
			if !found || provider == "" || id == "" {
				continue
			}
			replacement = provider + "|" + redaction.Redact(id)
		}
		fields[i] = strings.ReplaceAll(field, trimmed, replacement)
	}
	return strings.Join(fields, " ")
}

// NewErrorResponse creates a new ErrorResponse
func NewErrorResponse() *ErrorResponse {
	return &ErrorResponse{}
}

// PasswordlessStartResponse represents the response from Auth0 passwordless start endpoint
type PasswordlessStartResponse struct {
	ID            string `json:"_id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

// TokenResponse represents the response from Auth0 token endpoint
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
}

// LinkIdentityPayload represents the payload for linking an identity to a user
type LinkIdentityPayload struct {
	// LinkWith is the ID token obtained from the passwordless authentication flow
	LinkWith string `json:"link_with"`
}
