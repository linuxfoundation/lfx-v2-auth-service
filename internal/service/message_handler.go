// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package service

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	errs "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

// UserDataResponse represents the response structure for user update operations
type UserDataResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Data    any    `json:"data,omitempty"`
	Error   string `json:"error,omitempty"`
}

// messageHandlerOrchestrator orchestrates the message handling process
type messageHandlerOrchestrator struct {
	userWriter       port.UserWriter
	userReader       port.UserReader
	emailHandler     port.EmailHandler
	identityLinker   port.IdentityLinker
	identityUnlinker port.IdentityLinker
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

// WithEmailHandlerForMessageHandler sets the email handler for the message handler orchestrator
func WithEmailHandlerForMessageHandler(emailHandler port.EmailHandler) messageHandlerOrchestratorOption {
	return func(m *messageHandlerOrchestrator) {
		m.emailHandler = emailHandler
	}
}

// WithIdentityLinkerForMessageHandler sets the identity linker for the message handler orchestrator
func WithIdentityLinkerForMessageHandler(identityLinker port.IdentityLinker) messageHandlerOrchestratorOption {
	return func(m *messageHandlerOrchestrator) {
		m.identityLinker = identityLinker
	}
}

// WithIdentityUnlinkerForMessageHandler sets the identity unlinker for the message handler orchestrator
func WithIdentityUnlinkerForMessageHandler(identityUnlinker port.IdentityLinker) messageHandlerOrchestratorOption {
	return func(m *messageHandlerOrchestrator) {
		m.identityUnlinker = identityUnlinker
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
func (m *messageHandlerOrchestrator) searchByEmail(ctx context.Context, criteria string, email string) (*model.User, error) {
	if m.userReader == nil {
		return nil, errs.NewUnexpected("auth service unavailable")
	}

	slog.DebugContext(ctx, "search by email",
		"email", redaction.RedactEmail(email),
	)

	user := &model.User{
		PrimaryEmail: email,
	}
	if criteria == constants.CriteriaTypeAlternateEmail {
		user.AlternateEmails = []model.Email{{Email: email}}
	}

	// SearchUser is used to find “root” user emails, not linked email
	//
	// Finding users by alternate emails is NOT available
	user, err := m.userReader.SearchUser(ctx, user, criteria)
	if err != nil {
		return nil, err
	}

	return user, nil

}

// EmailToUsername converts an email to a username
func (m *messageHandlerOrchestrator) EmailToUsername(ctx context.Context, msg port.TransportMessenger) ([]byte, error) {

	email := strings.ToLower(strings.TrimSpace(string(msg.Data())))
	if email == "" {
		return m.errorResponse("email is required"), nil
	}

	user, err := m.searchByEmail(ctx, constants.CriteriaTypeEmail, email)
	if err != nil {
		return m.errorResponse(err.Error()), nil
	}
	return []byte(user.Username), nil
}

// EmailToSub converts an email to a sub
func (m *messageHandlerOrchestrator) EmailToSub(ctx context.Context, msg port.TransportMessenger) ([]byte, error) {

	email := strings.ToLower(strings.TrimSpace(string(msg.Data())))
	if email == "" {
		return m.errorResponse("email is required"), nil
	}

	user, err := m.searchByEmail(ctx, constants.CriteriaTypeEmail, email)
	if err != nil {
		return m.errorResponse(err.Error()), nil
	}
	return []byte(user.UserID), nil
}

func (m *messageHandlerOrchestrator) getUserByInput(ctx context.Context, msg port.TransportMessenger) (*model.User, error) {
	if m.userReader == nil {
		return nil, errs.NewUnexpected("auth service unavailable")
	}

	input := strings.TrimSpace(string(msg.Data()))
	if input == "" {
		return nil, errs.NewValidation("input is required")
	}

	slog.DebugContext(ctx, "get user metadata",
		"input", redaction.Redact(input),
	)

	user, errMetadataLookup := m.userReader.MetadataLookup(ctx, input)
	if errMetadataLookup != nil {
		slog.ErrorContext(ctx, "error getting user metadata",
			"error", errMetadataLookup,
			"input", redaction.Redact(input),
		)
		return nil, errMetadataLookup
	}

	search := func() (*model.User, error) {
		if user.UserID != "" {
			return m.userReader.GetUser(ctx, user)
		}
		return m.userReader.SearchUser(ctx, user, constants.CriteriaTypeUsername)
	}

	return search()
}

// GetUserMetadata retrieves user metadata based on the input strategy
func (m *messageHandlerOrchestrator) GetUserMetadata(ctx context.Context, msg port.TransportMessenger) ([]byte, error) {

	userRetrieved, errGetUser := m.getUserByInput(ctx, msg)
	if errGetUser != nil {
		slog.ErrorContext(ctx, "error getting user metadata",
			"error", errGetUser,
			"input", redaction.Redact(string(msg.Data())),
		)
		return m.errorResponse(errGetUser.Error()), nil
	}

	// Return success response with user metadata
	response := UserDataResponse{
		Success: true,
		Data:    userRetrieved.UserMetadata,
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		errorResponseJSON := m.errorResponse("failed to marshal response")
		return errorResponseJSON, nil
	}

	return responseJSON, nil
}

// GetUserEmails retrieves the user emails based on the input strategy
func (m *messageHandlerOrchestrator) GetUserEmails(ctx context.Context, msg port.TransportMessenger) ([]byte, error) {

	user, errGetUser := m.getUserByInput(ctx, msg)
	if errGetUser != nil {
		slog.ErrorContext(ctx, "error getting user emails",
			"error", errGetUser,
			"input", redaction.Redact(string(msg.Data())),
		)
		return m.errorResponse(errGetUser.Error()), nil
	}

	response := UserDataResponse{
		Success: true,
		Data:    map[string]any{"primary_email": user.PrimaryEmail, "alternate_emails": user.AlternateEmails},
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
		return m.errorResponse("auth service unavailable"), nil
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

func (m *messageHandlerOrchestrator) checkEmailExists(ctx context.Context, email string) error {

	email = strings.ToLower(strings.TrimSpace(email))

	var notFound errs.NotFound
	for _, criteria := range []string{constants.CriteriaTypeAlternateEmail, constants.CriteriaTypeEmail} {
		user, errSearch := m.searchByEmail(ctx, criteria, email)
		if errSearch != nil && !errors.As(errSearch, &notFound) {
			return errSearch
		}
		if user != nil && (user.UserID != "" || user.Username != "") {
			slog.DebugContext(ctx, "user found", "user_id", redaction.Redact(user.UserID))

			if strings.EqualFold(user.PrimaryEmail, email) {
				return errs.NewValidation("email already linked")
			}

			for _, alternateEmail := range user.AlternateEmails {
				if strings.EqualFold(alternateEmail.Email, email) && alternateEmail.Verified {
					return errs.NewValidation("email already linked")
				}
			}
		}
	}

	return nil
}

// StartEmailLinking starts the email linking process
func (m *messageHandlerOrchestrator) StartEmailLinking(ctx context.Context, msg port.TransportMessenger) ([]byte, error) {

	if m.emailHandler == nil {
		return m.errorResponse("email service unavailable"), nil
	}

	alternateEmailInput := strings.ToLower(strings.TrimSpace(string(msg.Data())))
	if alternateEmailInput == "" {
		return m.errorResponse("alternate email is required"), nil
	}

	email := model.Email{Email: alternateEmailInput}
	if !email.IsValidEmail() {
		return m.errorResponse("invalid email"), nil
	}

	err := m.checkEmailExists(ctx, alternateEmailInput)
	if err != nil {
		return m.errorResponse(err.Error()), nil
	}

	errLinkAlternateEmail := m.emailHandler.SendVerificationAlternateEmail(ctx, alternateEmailInput)
	if errLinkAlternateEmail != nil {
		return m.errorResponse(errLinkAlternateEmail.Error()), nil
	}

	// Return success response with user metadata
	response := UserDataResponse{
		Success: true,
		Message: "alternate email verification sent",
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		errorResponseJSON := m.errorResponse("failed to marshal response")
		return errorResponseJSON, nil
	}

	return responseJSON, nil
}

// VerifyEmailLinking verifies the email linking
func (m *messageHandlerOrchestrator) VerifyEmailLinking(ctx context.Context, msg port.TransportMessenger) ([]byte, error) {

	if m.emailHandler == nil {
		return m.errorResponse("email service unavailable"), nil
	}

	email := &model.Email{}
	err := json.Unmarshal(msg.Data(), email)
	if err != nil {
		responseJSON := m.errorResponse("failed to unmarshal email data")
		return responseJSON, nil
	}

	if !email.IsValidEmail() {
		return m.errorResponse("invalid email"), nil
	}

	//
	errExists := m.checkEmailExists(ctx, email.Email)
	if errExists != nil {
		return m.errorResponse(errExists.Error()), nil
	}

	authResponse, errVerifyAlternateEmail := m.emailHandler.VerifyAlternateEmail(ctx, email)
	if errVerifyAlternateEmail != nil {
		return m.errorResponse(errVerifyAlternateEmail.Error()), nil
	}

	// Return success response with user metadata
	response := UserDataResponse{
		Success: true,
		Data:    authResponse,
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		errorResponseJSON := m.errorResponse("failed to marshal response")
		return errorResponseJSON, nil
	}

	return responseJSON, nil
}

// LinkIdentity links a verified email identity to a user account
func (m *messageHandlerOrchestrator) LinkIdentity(ctx context.Context, msg port.TransportMessenger) ([]byte, error) {

	if m.identityLinker == nil {
		return m.errorResponse("auth service unavailable"), nil
	}

	if m.userReader == nil {
		return m.errorResponse("auth service unavailable"), nil
	}

	linkRequest := &model.LinkIdentity{}
	err := json.Unmarshal(msg.Data(), linkRequest)
	if err != nil {
		responseJSON := m.errorResponse("failed to unmarshal link identity request")
		return responseJSON, nil
	}

	errValidateLinkRequest := m.identityLinker.ValidateLinkRequest(ctx, linkRequest)
	if errValidateLinkRequest != nil {
		return m.errorResponse(errValidateLinkRequest.Error()), nil
	}

	user, errMetadataLookup := m.userReader.MetadataLookup(ctx, linkRequest.User.AuthToken)
	if errMetadataLookup != nil {
		return m.errorResponse(errMetadataLookup.Error()), nil
	}
	linkRequest.User.UserID = user.UserID

	errLinkIdentity := m.identityLinker.LinkIdentity(ctx, linkRequest)
	if errLinkIdentity != nil {
		return m.errorResponse(errLinkIdentity.Error()), nil
	}

	// Return success response
	response := UserDataResponse{
		Success: true,
		Message: "identity linked successfully",
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		errorResponseJSON := m.errorResponse("failed to marshal response")
		return errorResponseJSON, nil
	}

	return responseJSON, nil
}

// UnlinkIdentity removes a secondary identity from a user account
func (m *messageHandlerOrchestrator) UnlinkIdentity(ctx context.Context, msg port.TransportMessenger) ([]byte, error) {

	if m.identityUnlinker == nil {
		return m.errorResponse("auth service unavailable"), nil
	}

	if m.userReader == nil {
		return m.errorResponse("auth service unavailable"), nil
	}

	unlinkRequest := &model.UnlinkIdentity{}
	err := json.Unmarshal(msg.Data(), unlinkRequest)
	if err != nil {
		return m.errorResponse("failed to unmarshal unlink identity request"), nil
	}

	user, errMetadataLookup := m.userReader.MetadataLookup(ctx, unlinkRequest.User.AuthToken, constants.UserUpdateIdentityRequiredScope)
	if errMetadataLookup != nil {
		return m.errorResponse(errMetadataLookup.Error()), nil
	}
	unlinkRequest.User.UserID = user.UserID

	errUnlinkIdentity := m.identityUnlinker.UnlinkIdentity(ctx, unlinkRequest)
	if errUnlinkIdentity != nil {
		return m.errorResponse(errUnlinkIdentity.Error()), nil
	}

	response := UserDataResponse{
		Success: true,
		Message: "identity unlinked successfully",
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		return m.errorResponse("failed to marshal response"), nil
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
