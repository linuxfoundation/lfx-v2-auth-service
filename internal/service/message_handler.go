// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package service

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

// UserDataResponse represents the response structure for user update operations
type UserDataResponse struct {
	Success bool   `json:"success"`
	Data    any    `json:"data,omitempty"`
	Error   string `json:"error,omitempty"`
}

// messageHandlerOrchestrator orchestrates the message handling process
type messageHandlerOrchestrator struct {
	userWriter port.UserWriter
	userReader port.UserReader
}

// messageHandlerOrchestratorOption defines a function type for setting options
type messageHandlerOrchestratorOption func(*messageHandlerOrchestrator)

// WithUserWriterForMessageHandler sets the user writer for the message handler orchestrator
func WithUserWriterForMessageHandler(userWriter port.UserWriter) messageHandlerOrchestratorOption {
	return func(m *messageHandlerOrchestrator) {
		m.userWriter = userWriter
	}
}

// WithUserReaderForMessageHandler sets the user reader for the message handler orchestrator
func WithUserReaderForMessageHandler(userReader port.UserReader) messageHandlerOrchestratorOption {
	return func(m *messageHandlerOrchestrator) {
		m.userReader = userReader
	}
}

func (m *messageHandlerOrchestrator) errorResponse(error string) []byte {
	response := UserDataResponse{
		Success: false,
		Error:   error,
	}
	responseJSON, _ := json.Marshal(response)
	return responseJSON
}

// searchByEmail normalizes the email (lowercases and trims whitespace) and returns the matching user or an error
func (m *messageHandlerOrchestrator) searchByEmail(ctx context.Context, msg port.TransportMessenger) (*model.User, error) {
	if m.userReader == nil {
		return nil, errors.NewUnexpected("user service unavailable")
	}

	email := strings.ToLower(strings.TrimSpace(string(msg.Data())))
	if email == "" {
		return nil, errors.NewUnexpected("email is required")
	}

	slog.DebugContext(ctx, "search by email",
		"email", redaction.RedactEmail(email),
	)

	user := &model.User{
		PrimaryEmail: email,
	}

	// SearchUser is used to find “root” user emails, not linked email
	//
	// Finding users by alternate emails is NOT available
	user, err := m.userReader.SearchUser(ctx, user, constants.CriteriaTypeEmail)
	if err != nil {
		return nil, err
	}

	return user, nil

}

// EmailToUsername converts an email to a username
func (m *messageHandlerOrchestrator) EmailToUsername(ctx context.Context, msg port.TransportMessenger) ([]byte, error) {
	user, err := m.searchByEmail(ctx, msg)
	if err != nil {
		return m.errorResponse(err.Error()), nil
	}
	return []byte(user.Username), nil
}

// EmailToSub converts an email to a sub
func (m *messageHandlerOrchestrator) EmailToSub(ctx context.Context, msg port.TransportMessenger) ([]byte, error) {
	user, err := m.searchByEmail(ctx, msg)
	if err != nil {
		return m.errorResponse(err.Error()), nil
	}
	return []byte(user.UserID), nil
}

// GetUserMetadata retrieves user metadata based on the input strategy
func (m *messageHandlerOrchestrator) GetUserMetadata(ctx context.Context, msg port.TransportMessenger) ([]byte, error) {
	if m.userReader == nil {
		return m.errorResponse("user service unavailable"), nil
	}

	input := strings.TrimSpace(string(msg.Data()))
	if input == "" {
		return m.errorResponse("input is required"), nil
	}

	slog.DebugContext(ctx, "get user metadata",
		"input", redaction.Redact(input),
	)

	user := &model.User{}
	useCanonicalLookup := m.userReader.MetadataLookup(ctx, input, user)

	var (
		retrievedUser *model.User
		err           error
	)

	lookup := func() (*model.User, error) {
		if useCanonicalLookup {
			slog.DebugContext(ctx, "using canonical lookup for user metadata",
				"sub", redaction.Redact(user.Sub),
			)
			return m.userReader.GetUser(ctx, user)
		}
		slog.DebugContext(ctx, "using search lookup for user metadata",
			"username", redaction.Redact(user.Username),
		)
		return m.userReader.SearchUser(ctx, user, constants.CriteriaTypeUsername)
	}

	retrievedUser, err = lookup()
	if err != nil {
		slog.ErrorContext(ctx, "error getting user metadata", "error", err,
			"input", redaction.Redact(input),
			"useCanonicalLookup", useCanonicalLookup,
		)
		return m.errorResponse(err.Error()), nil
	}

	// Return success response with user metadata
	response := UserDataResponse{
		Success: true,
		Data:    retrievedUser.UserMetadata,
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		errorResponseJSON := m.errorResponse("failed to marshal response")
		return errorResponseJSON, nil
	}

	return responseJSON, nil
}

// UpdateUser updates the user in the identity provider
func (m *messageHandlerOrchestrator) UpdateUser(ctx context.Context, msg port.TransportMessenger) ([]byte, error) {

	if m.userWriter == nil {
		return m.errorResponse("user service unavailable"), nil
	}

	user := &model.User{}
	err := json.Unmarshal(msg.Data(), user)
	if err != nil {
		responseJSON := m.errorResponse("failed to unmarshal user data")
		return responseJSON, nil
	}

	// Sanitize user data first
	user.UserSanitize()

	// Validate user data
	if err := user.Validate(); err != nil {
		responseJSON := m.errorResponse(err.Error())
		return responseJSON, nil
	}

	// It's calling another service to update the user because in case of
	// need to expose the same functionality using another pattern, like http rest,
	// we can do without changing the user writer orchestrator
	updatedUser, err := m.userWriter.UpdateUser(ctx, user)
	if err != nil {
		responseJSON := m.errorResponse(err.Error())
		return responseJSON, nil
	}

	// Return success response with user metadata
	response := UserDataResponse{
		Success: true,
		Data:    updatedUser.UserMetadata,
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		errorResponseJSON := m.errorResponse("failed to marshal response")
		return errorResponseJSON, nil
	}

	return responseJSON, nil
}

// NewMessageHandlerOrchestrator creates a new message handler orchestrator using the option pattern
func NewMessageHandlerOrchestrator(opts ...messageHandlerOrchestratorOption) port.MessageHandler {
	m := &messageHandlerOrchestrator{}
	for _, opt := range opts {
		opt(m)
	}
	return m
}
