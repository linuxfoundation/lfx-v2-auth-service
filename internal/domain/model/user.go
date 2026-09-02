// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package model

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/cases"

	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

// User represents a user in the system
type User struct {
	Token           string        `json:"token" yaml:"token"`
	UserID          string        `json:"user_id" yaml:"user_id"`
	Sub             string        `json:"sub,omitempty" yaml:"sub,omitempty"`
	Username        string        `json:"username" yaml:"username"`
	PrimaryEmail    string        `json:"primary_email" yaml:"primary_email"`
	AlternateEmails []Email       `json:"alternate_emails,omitempty" yaml:"alternate_emails,omitempty"`
	Identities      []Identity    `json:"identities,omitempty" yaml:"identities,omitempty"`
	UserMetadata    *UserMetadata `json:"user_metadata,omitempty" yaml:"user_metadata,omitempty"`
}

// UserMetadata represents the metadata of a user
type UserMetadata struct {
	Picture            *string `json:"picture,omitempty" yaml:"picture,omitempty"`
	Zoneinfo           *string `json:"zoneinfo,omitempty" yaml:"zoneinfo,omitempty"`
	Name               *string `json:"name,omitempty" yaml:"name,omitempty"`
	GivenName          *string `json:"given_name,omitempty" yaml:"given_name,omitempty"`
	FamilyName         *string `json:"family_name,omitempty" yaml:"family_name,omitempty"`
	JobTitle           *string `json:"job_title,omitempty" yaml:"job_title,omitempty"`
	Organization       *string `json:"organization,omitempty" yaml:"organization,omitempty"`
	OrganizationDomain *string `json:"organization_domain,omitempty" yaml:"organization_domain,omitempty"`
	Country            *string `json:"country,omitempty" yaml:"country,omitempty"`
	StateProvince      *string `json:"state_province,omitempty" yaml:"state_province,omitempty"`
	City               *string `json:"city,omitempty" yaml:"city,omitempty"`
	Address            *string `json:"address,omitempty" yaml:"address,omitempty"`
	PostalCode         *string `json:"postal_code,omitempty" yaml:"postal_code,omitempty"`
	PhoneNumber        *string `json:"phone_number,omitempty" yaml:"phone_number,omitempty"`
	TShirtSize         *string `json:"t_shirt_size,omitempty" yaml:"t_shirt_size,omitempty"`
	Bio                *string `json:"bio,omitempty" yaml:"bio,omitempty"`
	Skills             *string `json:"skills,omitempty" yaml:"skills,omitempty"`
}

// bioMaxLength is the maximum number of characters allowed in the About Me (bio)
// field. Auth0 imposes no limit, so this is the chokepoint cap; longer values are
// truncated during sanitization.
const bioMaxLength = 2000

// skillsMaxLength is the maximum number of characters allowed in the
// comma-separated Skills string. Auth0 imposes no limit, so this is the
// chokepoint cap; items that would not fit within it are dropped whole
// during sanitization, and the first item is truncated only if no item
// fits at all.
const skillsMaxLength = 2000

// skillsMaxCount is the maximum number of individual skill items allowed in
// the comma-separated Skills string. Items beyond this count are dropped
// during sanitization, before the length cap is applied.
const skillsMaxCount = 50

// skillsMaxRawLength bounds the raw Skills value before it is split into
// items, so a delimiter-heavy payload can't force an oversized allocation.
const skillsMaxRawLength = 4000

// Validate validates the user data and returns an error if validation fails
func (u *User) Validate() error {

	errRequiredMsg := func(field string) string {
		return fmt.Sprintf("%s is required", field)
	}

	if strings.TrimSpace(u.Token) == "" {
		return errors.NewValidation(errRequiredMsg("token"))
	}

	if u.UserMetadata == nil {
		return errors.NewValidation(errRequiredMsg("user_metadata"))
	}

	return nil
}

// UserSanitize sanitizes the user data by cleaning up string fields
func (u *User) UserSanitize() {
	// Sanitize basic user fields
	u.Token = strings.TrimSpace(u.Token)
	u.UserID = strings.TrimSpace(u.UserID)
	u.Sub = strings.TrimSpace(u.Sub)
	u.Username = strings.TrimSpace(u.Username)
	u.PrimaryEmail = strings.TrimSpace(u.PrimaryEmail)

	// Sanitize UserMetadata if it exists
	if u.UserMetadata != nil {
		u.UserMetadata.userMetadataSanitize()
	}

	// add more sanitization functions as needed
}

func (u User) buildIndexKey(ctx context.Context, kind, data string) string {

	hash := sha256.Sum256([]byte(data))

	key := hex.EncodeToString(hash[:])

	slog.DebugContext(ctx, "index key built",
		"kind", kind,
		"data", redaction.Redact(data),
		"key", key,
	)

	return key
}

// BuildEmailIndexKey builds the index key for the email
func (u User) BuildEmailIndexKey(ctx context.Context) string {
	data := strings.TrimSpace(strings.ToLower(u.PrimaryEmail))
	if data == "" {
		return ""
	}
	return u.buildIndexKey(ctx, "email", data)
}

// BuildAlternateEmailIndexKey builds the index key for the alternate email
func (u User) BuildAlternateEmailIndexKey(ctx context.Context, alternateEmail string) string {
	data := strings.TrimSpace(strings.ToLower(alternateEmail))
	if data == "" {
		return ""
	}
	return u.buildIndexKey(ctx, "alternate-email", data)
}

// BuildSubIndexKey builds the index key for the sub
func (u User) BuildSubIndexKey(ctx context.Context) string {
	data := strings.TrimSpace(strings.ToLower(u.Sub))
	if data == "" {
		return ""
	}
	return u.buildIndexKey(ctx, "sub", data)
}

// sanitize sanitizes the user metadata by cleaning up string fields
func (um *UserMetadata) userMetadataSanitize() {
	if um.Name != nil {
		*um.Name = strings.TrimSpace(*um.Name)
	}
	if um.GivenName != nil {
		*um.GivenName = strings.TrimSpace(*um.GivenName)
	}
	if um.FamilyName != nil {
		*um.FamilyName = strings.TrimSpace(*um.FamilyName)
	}
	if um.JobTitle != nil {
		*um.JobTitle = strings.TrimSpace(*um.JobTitle)
	}
	if um.Organization != nil {
		*um.Organization = strings.TrimSpace(*um.Organization)
	}
	if um.OrganizationDomain != nil {
		*um.OrganizationDomain = strings.TrimSpace(*um.OrganizationDomain)
	}
	if um.Country != nil {
		*um.Country = strings.TrimSpace(*um.Country)
	}
	if um.StateProvince != nil {
		*um.StateProvince = strings.TrimSpace(*um.StateProvince)
	}
	if um.City != nil {
		*um.City = strings.TrimSpace(*um.City)
	}
	if um.Address != nil {
		*um.Address = strings.TrimSpace(*um.Address)
	}
	if um.PostalCode != nil {
		*um.PostalCode = strings.TrimSpace(*um.PostalCode)
	}
	if um.PhoneNumber != nil {
		*um.PhoneNumber = strings.TrimSpace(*um.PhoneNumber)
	}
	if um.TShirtSize != nil {
		*um.TShirtSize = strings.TrimSpace(*um.TShirtSize)
	}
	if um.Bio != nil {
		*um.Bio = strings.TrimSpace(*um.Bio)
		if runes := []rune(*um.Bio); len(runes) > bioMaxLength {
			*um.Bio = string(runes[:bioMaxLength])
		}
	}
	if um.Skills != nil {
		*um.Skills = sanitizeSkills(*um.Skills)
	}
	if um.Picture != nil {
		*um.Picture = strings.TrimSpace(*um.Picture)
	}
	if um.Zoneinfo != nil {
		*um.Zoneinfo = strings.TrimSpace(*um.Zoneinfo)
	}
}

// sanitizeSkills normalizes a comma-separated Skills value: it trims and
// bounds the raw input, splits on commas, trims and dedupes items via
// Unicode case folding, and rejoins the survivors with ", ". Both length
// guards below operate on whole items only, never mid-item, so an item that
// doesn't fit is dropped entirely rather than stored as a partial fragment.
// The one exception: if no item fits at all, the first item is hard-truncated
// so the value isn't emptied entirely.
func sanitizeSkills(raw string) string {
	// Trim before bounding raw length, matching the Bio field's
	// trim-then-cap order, so leading/trailing whitespace doesn't eat into
	// the raw-length budget ahead of real content.
	raw = strings.TrimSpace(raw)

	// Bound the raw input before splitting so a delimiter-heavy payload
	// can't force an oversized allocation ahead of the item-count cap.
	// Walk runes directly rather than via []rune, which would itself
	// allocate proportional to the full input and defeat the guard.
	count := 0
	truncated := false
	cutOnDelimiter := false
	for i, r := range raw {
		if count == skillsMaxRawLength {
			raw = raw[:i]
			truncated = true
			cutOnDelimiter = r == ','
			break
		}
		count++
	}
	if truncated && !cutOnDelimiter {
		// The cut landed mid-item (the excluded rune wasn't the delimiter
		// right after a complete item); back off to the last complete item
		// so a truncated fragment is never parsed as a real skill. If the
		// cut landed inside the very first item, there is no prior comma
		// and no complete item to keep, so discard the fragment entirely.
		if j := strings.LastIndexByte(raw, ','); j >= 0 {
			raw = raw[:j]
		} else {
			raw = ""
		}
	}

	// Scan for commas manually instead of strings.Split, so a
	// delimiter-heavy input stops at skillsMaxCount unique items without
	// first building a slice of every segment.
	cleaned := make([]string, 0, skillsMaxCount)
	seen := make(map[string]struct{}, skillsMaxCount)
	folder := cases.Fold()
	for len(cleaned) < skillsMaxCount && raw != "" {
		item := raw
		if idx := strings.IndexByte(raw, ','); idx >= 0 {
			item = raw[:idx]
			raw = raw[idx+1:]
		} else {
			raw = ""
		}
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		// Use Unicode case folding (not strings.ToLower) so that case
		// variants like "Σ" and "ς" are recognized as duplicates.
		key := folder.String(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		cleaned = append(cleaned, item)
	}

	// Build the joined value one whole item at a time so the length cap
	// can never land inside an item: an item that doesn't fit whole is
	// dropped entirely and the scan continues, so a later, shorter item
	// still gets a chance to fit rather than being dropped along with the
	// oversized one that preceded it. The only exception is when nothing
	// fit at all, which hard-truncates the first item since there would
	// otherwise be nothing to keep.
	var b strings.Builder
	used := 0
	for _, item := range cleaned {
		n := utf8.RuneCountInString(item)
		sep := 0
		if b.Len() > 0 {
			sep = 2 // len(", ") in runes
		}
		if used+sep+n > skillsMaxLength {
			continue // an item that doesn't fit is dropped whole
		}
		if sep > 0 {
			b.WriteString(", ")
		}
		b.WriteString(item)
		used += sep + n
	}
	if b.Len() == 0 && len(cleaned) > 0 {
		// Nothing fit whole; keep a truncated first item rather than
		// emptying the field entirely.
		b.WriteString(string([]rune(cleaned[0])[:skillsMaxLength]))
	}
	return b.String()
}

// Patch updates the UserMetadata with the update values only if the update values are not nil
func (a *UserMetadata) Patch(update *UserMetadata) bool {

	if update == nil {
		return false
	}

	updated := false

	if update.Picture != nil {
		a.Picture = update.Picture
		updated = true
	}

	if update.Zoneinfo != nil {
		a.Zoneinfo = update.Zoneinfo
		updated = true
	}

	if update.Name != nil {
		a.Name = update.Name
		updated = true
	}

	if update.GivenName != nil {
		a.GivenName = update.GivenName
		updated = true
	}

	if update.FamilyName != nil {
		a.FamilyName = update.FamilyName
		updated = true
	}

	if update.JobTitle != nil {
		a.JobTitle = update.JobTitle
		updated = true
	}

	if update.Organization != nil {
		a.Organization = update.Organization
		updated = true
	}

	if update.OrganizationDomain != nil {
		a.OrganizationDomain = update.OrganizationDomain
		updated = true
	}

	if update.Country != nil {
		a.Country = update.Country
		updated = true
	}

	if update.StateProvince != nil {
		a.StateProvince = update.StateProvince
		updated = true
	}
	if update.City != nil {
		a.City = update.City
		updated = true
	}

	if update.Address != nil {
		a.Address = update.Address
		updated = true
	}

	if update.PostalCode != nil {
		a.PostalCode = update.PostalCode
		updated = true
	}

	if update.PhoneNumber != nil {
		a.PhoneNumber = update.PhoneNumber
		updated = true
	}

	if update.TShirtSize != nil {
		a.TShirtSize = update.TShirtSize
		updated = true
	}

	if update.Bio != nil {
		a.Bio = update.Bio
		updated = true
	}

	if update.Skills != nil {
		a.Skills = update.Skills
		updated = true
	}

	return updated
}
