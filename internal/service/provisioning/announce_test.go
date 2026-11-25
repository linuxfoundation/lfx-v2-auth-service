// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package provisioning

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockAnnouncementStore struct {
	state    port.UserAnnouncementState
	readErr  error
	markErr  error
	reads    int
	marked   []string
	markedAt string
}

func (m *mockAnnouncementStore) ReadAnnouncementState(context.Context, string) (port.UserAnnouncementState, error) {
	m.reads++
	return m.state, m.readErr
}

func (m *mockAnnouncementStore) MarkAnnounced(_ context.Context, userID, announcedAt string) error {
	m.marked = append(m.marked, userID)
	m.markedAt = announcedAt
	return m.markErr
}

type publishedMessage struct {
	subject string
	data    []byte
}

type mockEventPublisher struct {
	err       error
	published []publishedMessage
}

func (m *mockEventPublisher) PublishConfirmed(_ context.Context, subject string, data []byte) error {
	if m.err != nil {
		return m.err
	}
	m.published = append(m.published, publishedMessage{subject: subject, data: data})
	return nil
}

func announceRequest() Request {
	verified := true
	return Request{UserID: "auth0|1", EmailVerified: &verified}
}

func announceState() port.UserAnnouncementState {
	return port.UserAnnouncementState{EmailVerified: true, Email: "jane@example.com", Username: "jane"}
}

func newTestAnnouncer(t *testing.T, store port.UserAnnouncementStore, publisher port.ConfirmedEventPublisher) Announcer {
	t.Helper()

	a, err := NewAnnouncer(store, publisher)
	require.NoError(t, err)
	a.(*announcer).now = func() time.Time { return time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC) }
	return a
}

func TestNewAnnouncerValidation(t *testing.T) {
	_, err := NewAnnouncer(nil, &mockEventPublisher{})
	require.Error(t, err)

	_, err = NewAnnouncer(&mockAnnouncementStore{}, nil)
	require.Error(t, err)
}

func TestAnnounce(t *testing.T) {
	ctx := context.Background()

	t.Run("a verified, unannounced user is published then marked", func(t *testing.T) {
		store := &mockAnnouncementStore{state: announceState()}
		publisher := &mockEventPublisher{}

		newTestAnnouncer(t, store, publisher).Announce(ctx, announceRequest())

		require.Len(t, publisher.published, 1)
		assert.Equal(t, constants.UserEmailVerifiedSubject, publisher.published[0].subject)

		var event UserEmailVerifiedEvent
		require.NoError(t, json.Unmarshal(publisher.published[0].data, &event))
		assert.Equal(t, "jane", event.Username)
		assert.Equal(t, "jane@example.com", event.Email)
		assert.Equal(t, time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC), event.Timestamp)

		assert.Equal(t, []string{"auth0|1"}, store.marked)
		assert.Equal(t, "2026-11-24T12:00:00Z", store.markedAt)
	})

	t.Run("payload pre-filters never reach Auth0", func(t *testing.T) {
		unverified := false
		cases := map[string]Request{
			"unverified":        {UserID: "auth0|1", EmailVerified: &unverified},
			"already announced": {UserID: "auth0|1", EmailVerified: announceRequest().EmailVerified, AnnouncedAt: "2026-11-01T00:00:00Z"},
			"no user id":        {EmailVerified: announceRequest().EmailVerified},
		}
		for name, req := range cases {
			t.Run(name, func(t *testing.T) {
				store := &mockAnnouncementStore{state: announceState()}
				publisher := &mockEventPublisher{}

				newTestAnnouncer(t, store, publisher).Announce(ctx, req)

				assert.Zero(t, store.reads, "the common path must not cost a Management API read")
				assert.Empty(t, publisher.published)
			})
		}
	})

	t.Run("a payload that omits the verified flag is decided by the record", func(t *testing.T) {
		store := &mockAnnouncementStore{state: announceState()}
		publisher := &mockEventPublisher{}

		newTestAnnouncer(t, store, publisher).Announce(ctx, Request{UserID: "auth0|1"})

		assert.Equal(t, 1, store.reads)
		require.Len(t, publisher.published, 1)
		assert.Equal(t, []string{"auth0|1"}, store.marked)
	})

	t.Run("the record overrides a stale payload", func(t *testing.T) {
		cases := map[string]port.UserAnnouncementState{
			"no longer verified": {EmailVerified: false, Email: "jane@example.com", Username: "jane"},
			"already announced":  {EmailVerified: true, Email: "jane@example.com", Username: "jane", AnnouncedAt: "2026-11-01T00:00:00Z"},
			"no LFID username":   {EmailVerified: true, Email: "jane@example.com"},
			"no email":           {EmailVerified: true, Username: "jane"},
		}
		for name, state := range cases {
			t.Run(name, func(t *testing.T) {
				store := &mockAnnouncementStore{state: state}
				publisher := &mockEventPublisher{}

				newTestAnnouncer(t, store, publisher).Announce(ctx, announceRequest())

				assert.Empty(t, publisher.published)
				assert.Empty(t, store.marked)
			})
		}
	})

	t.Run("a read failure publishes nothing", func(t *testing.T) {
		store := &mockAnnouncementStore{readErr: errors.New("boom")}
		publisher := &mockEventPublisher{}

		newTestAnnouncer(t, store, publisher).Announce(ctx, announceRequest())

		assert.Empty(t, publisher.published)
		assert.Empty(t, store.marked)
	})

	t.Run("a publish failure leaves the user unmarked so a later event retries", func(t *testing.T) {
		store := &mockAnnouncementStore{state: announceState()}
		publisher := &mockEventPublisher{err: errors.New("nats down")}

		newTestAnnouncer(t, store, publisher).Announce(ctx, announceRequest())

		assert.Empty(t, store.marked)
	})

	t.Run("a marker write failure is tolerated after the publish", func(t *testing.T) {
		store := &mockAnnouncementStore{state: announceState(), markErr: errors.New("auth0 down")}
		publisher := &mockEventPublisher{}

		newTestAnnouncer(t, store, publisher).Announce(ctx, announceRequest())

		assert.Len(t, publisher.published, 1)
	})
}
