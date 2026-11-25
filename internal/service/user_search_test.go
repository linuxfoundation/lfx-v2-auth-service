// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package service

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
)

// mockUserSearcher is a mock implementation of port.UserSearcher.
type mockUserSearcher struct {
	users []model.UserSearchResult
	err   error

	calls        int
	subjectToken string
	query        string
	limit        int
}

func (m *mockUserSearcher) SearchUsers(_ context.Context, subjectToken, query string, limit int) ([]model.UserSearchResult, error) {
	m.calls++
	m.subjectToken, m.query, m.limit = subjectToken, query, limit
	return m.users, m.err
}

func TestSearchUsers(t *testing.T) {
	tests := []struct {
		name        string
		searcher    *mockUserSearcher
		withoutImpl bool
		payload     string
		wantCalls   int
		wantSuccess bool
		wantError   string
		wantUsers   int
	}{
		{
			name:        "returns matching users",
			searcher:    &mockUserSearcher{users: []model.UserSearchResult{{UserID: "auth0|1", Username: "jdoe", Name: "J Doe", Email: "j@example.com"}}},
			payload:     `{"subject_token":" tok ","query":" jdoe ","limit":5}`,
			wantCalls:   1,
			wantSuccess: true,
			wantUsers:   1,
		},
		{
			name:        "no matches is an empty list, not null",
			searcher:    &mockUserSearcher{},
			payload:     `{"subject_token":"tok","query":"nobody"}`,
			wantCalls:   1,
			wantSuccess: true,
		},
		{
			name:      "unavailable when no searcher is wired",
			searcher:  &mockUserSearcher{},
			payload:   `{"subject_token":"tok","query":"jdoe"}`,
			wantError: "user search unavailable",

			withoutImpl: true,
		},
		{name: "invalid JSON", searcher: &mockUserSearcher{}, payload: `{`, wantError: "invalid request: unexpected end of JSON input"},
		{name: "missing subject_token", searcher: &mockUserSearcher{}, payload: `{"query":"jdoe"}`, wantError: "subject_token is required"},
		{name: "blank subject_token", searcher: &mockUserSearcher{}, payload: `{"subject_token":"  ","query":"jdoe"}`, wantError: "subject_token is required"},
		{name: "missing query", searcher: &mockUserSearcher{}, payload: `{"subject_token":"tok"}`, wantError: "query is required"},
		{
			name:      "searcher errors are returned in the reply",
			searcher:  &mockUserSearcher{err: errors.NewForbidden("subject_token is not authorized to impersonate")},
			payload:   `{"subject_token":"tok","query":"jdoe"}`,
			wantCalls: 1,
			wantError: "subject_token is not authorized to impersonate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var opts []MessageHandlerOrchestratorOption
			if !tt.withoutImpl {
				opts = append(opts, WithUserSearcherForMessageHandler(tt.searcher))
			}
			handler := NewMessageHandlerOrchestrator(opts...)

			reply, err := handler.SearchUsers(context.Background(), &mockTransportMessenger{data: []byte(tt.payload)})
			if err != nil {
				t.Fatalf("handler must reply, not return an error: %v", err)
			}

			var got struct {
				Success bool                     `json:"success"`
				Error   string                   `json:"error"`
				Users   []model.UserSearchResult `json:"users"`
			}
			if err := json.Unmarshal(reply, &got); err != nil {
				t.Fatalf("invalid reply %s: %v", reply, err)
			}
			if got.Success != tt.wantSuccess || got.Error != tt.wantError {
				t.Fatalf("reply = %s, want success=%v error=%q", reply, tt.wantSuccess, tt.wantError)
			}
			if tt.wantSuccess {
				if len(got.Users) != tt.wantUsers {
					t.Fatalf("got %d users, want %d", len(got.Users), tt.wantUsers)
				}
				if string(reply) != "" && tt.wantUsers == 0 && !jsonHasEmptyUsersArray(reply) {
					t.Fatalf("users must serialize as [], got %s", reply)
				}
			}
			if tt.searcher.calls != tt.wantCalls {
				t.Fatalf("searcher called %d times, want %d", tt.searcher.calls, tt.wantCalls)
			}
		})
	}
}

func jsonHasEmptyUsersArray(reply []byte) bool {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(reply, &raw); err != nil {
		return false
	}
	return string(raw["users"]) == "[]"
}

func TestSearchUsers_TrimsInputAndForwardsLimit(t *testing.T) {
	searcher := &mockUserSearcher{}
	handler := NewMessageHandlerOrchestrator(WithUserSearcherForMessageHandler(searcher))

	_, err := handler.SearchUsers(context.Background(),
		&mockTransportMessenger{data: []byte(`{"subject_token":" tok ","query":" jdoe ","limit":5}`)})
	if err != nil {
		t.Fatal(err)
	}
	if searcher.subjectToken != "tok" || searcher.query != "jdoe" || searcher.limit != 5 {
		t.Fatalf("got token=%q query=%q limit=%d", searcher.subjectToken, searcher.query, searcher.limit)
	}
}
