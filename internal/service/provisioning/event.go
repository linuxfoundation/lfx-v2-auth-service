// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package provisioning

import (
	"encoding/json"
	"strings"

	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	errs "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
)

// Event is an Auth0 Event Stream delivery.
//
// The payload is Auth0's, not ours, and the field paths below are recorded from
// the event-type documentation rather than from a captured event. The handler
// therefore logs the raw body on arrival: the first real delivery is what
// confirms these paths, and a mismatch shows up as visible data rather than as
// a silently empty struct.
type Event struct {
	ID   string          `json:"id"`
	Type string          `json:"type"`
	Time string          `json:"time"`
	Data json.RawMessage `json:"data"`
}

// EventUser is the user record carried on an event.
type EventUser struct {
	UserID        string          `json:"user_id"`
	Username      string          `json:"username"`
	Email         string          `json:"email"`
	EmailVerified *bool           `json:"email_verified"`
	Name          string          `json:"name"`
	AppMetadata   *EventMetadata  `json:"app_metadata"`
	Identities    []EventIdentity `json:"identities"`
}

// EventMetadata is the subset of `app_metadata` the gate reads.
type EventMetadata struct {
	CDPUUID string `json:"cdp_uuid"`
}

// EventIdentity is one identity on the event's user record.
type EventIdentity struct {
	Connection string `json:"connection"`
	Provider   string `json:"provider"`
}

// eventData accommodates the two shapes an event's `data` may take: the user
// nested under `object` (or `user`), or inlined directly.
type eventData struct {
	Object *EventUser `json:"object"`
	User   *EventUser `json:"user"`
	EventUser
}

// Event types this handler acts on. There is no `user.verified` type — the
// verification click surfaces as a `user.updated`, which is the assumption the
// delivery logging exists to confirm.
const (
	EventTypeUserUpdated = "user.updated"
	EventTypeUserCreated = "user.created"
)

// ParseEvent decodes an Auth0 event body.
//
// A parse failure is permanent: redelivering the same bytes cannot help, so the
// caller answers 4xx rather than 5xx.
func ParseEvent(raw []byte) (Event, EventUser, error) {
	var event Event
	if err := json.Unmarshal(raw, &event); err != nil {
		return Event{}, EventUser{}, errs.NewValidation("event payload is not valid JSON")
	}

	if len(event.Data) == 0 {
		return event, EventUser{}, errs.NewValidation("event payload carries no data")
	}

	var data eventData
	if err := json.Unmarshal(event.Data, &data); err != nil {
		return event, EventUser{}, errs.NewValidation("event data is not a JSON object")
	}

	user := data.EventUser
	switch {
	case data.Object != nil && strings.TrimSpace(data.Object.UserID) != "":
		user = *data.Object
	case data.User != nil && strings.TrimSpace(data.User.UserID) != "":
		user = *data.User
	}

	if strings.TrimSpace(user.UserID) == "" {
		return event, EventUser{}, errs.NewValidation("event data carries no user_id")
	}

	return event, user, nil
}

// ToRequest maps an event's user record onto a provisioning request.
func (u EventUser) ToRequest() Request {
	verified := u.EmailVerified != nil && *u.EmailVerified

	storedUUID := ""
	if u.AppMetadata != nil {
		storedUUID = u.AppMetadata.CDPUUID
	}

	return Request{
		UserID:              u.UserID,
		Username:            u.Username,
		Email:               u.Email,
		EmailVerified:       verified,
		StoredCDPUUID:       storedUUID,
		HasDatabaseIdentity: u.hasDatabaseIdentity(),
		DisplayName:         u.Name,
	}
}

// hasDatabaseIdentity reports whether the user holds an identity on the Auth0
// database connection.
//
// A user record with no identities at all is treated as a database user when
// its id carries the `auth0|` prefix, since some event payloads omit the
// identity list.
func (u EventUser) hasDatabaseIdentity() bool {
	for _, identity := range u.Identities {
		if identity.Connection == constants.DatabaseConnection {
			return true
		}
	}
	if len(u.Identities) == 0 {
		return strings.HasPrefix(u.UserID, "auth0|")
	}
	return false
}
