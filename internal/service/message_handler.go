// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package service

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	errs "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
)

// UserProfileUpdatedEvent is published after a successful user_metadata update.
// Consumers use the full UserMetadata object (not just changed fields) to sync
// profile state to other systems.
type UserProfileUpdatedEvent struct {
	UserID    string              `json:"user_id"`
	Principal string              `json:"principal"`
	Metadata  *model.UserMetadata `json:"user_metadata"`
	Timestamp time.Time           `json:"timestamp"`
}

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
	passwordHandler  port.PasswordHandler
	impersonator     port.Impersonator
	eventPublisher   port.EventPublisher
}

// MessageHandlerOrchestratorOption defines a function type for setting options
type MessageHandlerOrchestratorOption func(*messageHandlerOrchestrator)

// WithUserWriterForMessageHandler sets the user writer for the message handler orchestrator
func WithUserWriterForMessageHandler(userWriter port.UserWriter) MessageHandlerOrchestratorOption {
	return func(m *messageHandlerOrchestrator) {
		m.userWriter = userWriter
	}
}

// WithUserReaderForMessageHandler sets the user reader for the message handler orchestrator
func WithUserReaderForMessageHandler(userReader port.UserReader) MessageHandlerOrchestratorOption {
	return func(m *messageHandlerOrchestrator) {
		m.userReader = userReader
	}
}

// WithEmailHandlerForMessageHandler sets the email handler for the message handler orchestrator
func WithEmailHandlerForMessageHandler(emailHandler port.EmailHandler) MessageHandlerOrchestratorOption {
	return func(m *messageHandlerOrchestrator) {
		m.emailHandler = emailHandler
	}
}

// WithIdentityLinkerForMessageHandler sets the identity linker for the message handler orchestrator
func WithIdentityLinkerForMessageHandler(identityLinker port.IdentityLinker) MessageHandlerOrchestratorOption {
	return func(m *messageHandlerOrchestrator) {
		m.identityLinker = identityLinker
	}
}

// WithIdentityUnlinkerForMessageHandler sets the identity unlinker for the message handler orchestrator
func WithIdentityUnlinkerForMessageHandler(identityUnlinker port.IdentityLinker) MessageHandlerOrchestratorOption {
	return func(m *messageHandlerOrchestrator) {
		m.identityUnlinker = identityUnlinker
	}
}

// WithPasswordHandlerForMessageHandler sets the password handler for the message handler orchestrator
func WithPasswordHandlerForMessageHandler(passwordHandler port.PasswordHandler) MessageHandlerOrchestratorOption {
	return func(m *messageHandlerOrchestrator) {
		m.passwordHandler = passwordHandler
	}
}

// WithImpersonatorForMessageHandler sets the impersonator for the message handler orchestrator
func WithImpersonatorForMessageHandler(impersonator port.Impersonator) MessageHandlerOrchestratorOption {
	return func(m *messageHandlerOrchestrator) {
		m.impersonator = impersonator
	}
}

// WithEventPublisherForMessageHandler sets the event publisher for the message handler orchestrator
func WithEventPublisherForMessageHandler(eventPublisher port.EventPublisher) MessageHandlerOrchestratorOption {
	return func(m *messageHandlerOrchestrator) {
		m.eventPublisher = eventPublisher
	}
}

func (m *messageHandlerOrchestrator) errorResponse(error string) []byte {
	response := UserDataResponse{
		Success: false,
		Error:   error,
	}
	responseJSON, err := json.Marshal(response)
	if err != nil {
		slog.Error("failed to marshal error response",
			"error", err,
		)
	}
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

// UsernameToSub converts a username to a sub
func (m *messageHandlerOrchestrator) UsernameToSub(ctx context.Context, msg port.TransportMessenger) ([]byte, error) {

	if m.userReader == nil {
		return m.errorResponse("auth service unavailable"), nil
	}

	username := strings.TrimSpace(string(msg.Data()))
	if username == "" {
		return m.errorResponse("username is required"), nil
	}

	user := &model.User{Username: username}
	user, err := m.userReader.SearchUser(ctx, user, constants.CriteriaTypeUsername)
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

// userEmailsRequest represents the input for retrieving user emails
type userEmailsRequest struct {
	User struct {
		AuthToken string `json:"auth_token"`
	} `json:"user"`
}

// GetUserEmails retrieves the user emails based on an auth token
func (m *messageHandlerOrchestrator) GetUserEmails(ctx context.Context, msg port.TransportMessenger) ([]byte, error) {

	if m.userReader == nil {
		return m.errorResponse("auth service unavailable"), nil
	}

	var request userEmailsRequest
	if err := json.Unmarshal(msg.Data(), &request); err != nil {
		return m.errorResponse("failed to unmarshal request"), nil
	}

	authToken := strings.TrimSpace(request.User.AuthToken)
	if authToken == "" {
		return m.errorResponse("auth_token is required"), nil
	}

	slog.DebugContext(ctx, "get user emails",
		"input", redaction.Redact(authToken),
	)

	user, err := m.userReader.MetadataLookup(ctx, authToken)
	if err != nil {
		slog.ErrorContext(ctx, "error looking up user for email read",
			"error", err,
		)
		return m.errorResponse(err.Error()), nil
	}

	fullUser, err := m.userReader.GetUser(ctx, user)
	if err != nil {
		slog.ErrorContext(ctx, "error getting user for email read",
			"error", err,
		)
		return m.errorResponse(err.Error()), nil
	}

	alternateEmails := make([]model.Email, 0, len(fullUser.Identities))
	for _, id := range fullUser.Identities {
		if id.Connection != constants.EmailConnection {
			continue
		}
		if id.Email == "" {
			continue
		}
		alternateEmails = append(alternateEmails, model.Email{
			Email:    id.Email,
			Verified: id.EmailVerified,
		})
	}

	response := UserDataResponse{
		Success: true,
		Data:    map[string]any{"primary_email": fullUser.PrimaryEmail, "alternate_emails": alternateEmails},
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		return m.errorResponse("failed to marshal response"), nil
	}

	return responseJSON, nil
}

// identityListRequest represents the input for listing user identities
type identityListRequest struct {
	User struct {
		AuthToken string `json:"auth_token"`
	} `json:"user"`
}

// identityResponse is the response DTO matching the UI's expected format
type identityResponse struct {
	Provider    string               `json:"provider"`
	UserID      string               `json:"user_id"`
	IsSocial    bool                 `json:"isSocial"`
	ProfileData *identityProfileData `json:"profileData,omitempty"`
}

type identityProfileData struct {
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Nickname      string `json:"nickname,omitempty"`
	Name          string `json:"name,omitempty"`
}

// ListIdentities retrieves the user's linked identities
func (m *messageHandlerOrchestrator) ListIdentities(ctx context.Context, msg port.TransportMessenger) ([]byte, error) {

	if m.userReader == nil {
		return m.errorResponse("auth service unavailable"), nil
	}

	var request identityListRequest
	if err := json.Unmarshal(msg.Data(), &request); err != nil {
		return m.errorResponse("failed to unmarshal request"), nil
	}

	authToken := strings.TrimSpace(request.User.AuthToken)
	if authToken == "" {
		return m.errorResponse("auth_token is required"), nil
	}

	slog.DebugContext(ctx, "list identities",
		"input", redaction.Redact(authToken),
	)

	user, err := m.userReader.MetadataLookup(ctx, authToken)
	if err != nil {
		slog.ErrorContext(ctx, "error looking up user for identity list",
			"error", err,
		)
		return m.errorResponse(err.Error()), nil
	}

	fullUser, err := m.userReader.GetUser(ctx, user)
	if err != nil {
		slog.ErrorContext(ctx, "error getting user for identity list",
			"error", err,
		)
		return m.errorResponse(err.Error()), nil
	}

	identities := make([]identityResponse, 0, len(fullUser.Identities))
	for _, id := range fullUser.Identities {
		resp := identityResponse{
			Provider: id.Provider,
			UserID:   id.IdentityID,
			IsSocial: id.IsSocial,
		}
		if id.Email != "" || id.Nickname != "" || id.Name != "" {
			resp.ProfileData = &identityProfileData{
				Email:         id.Email,
				EmailVerified: id.EmailVerified,
				Nickname:      id.Nickname,
				Name:          id.Name,
			}
		}
		identities = append(identities, resp)
	}

	response := UserDataResponse{
		Success: true,
		Data:    identities,
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		return m.errorResponse("failed to marshal response"), nil
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

	// Publish domain event so downstream consumers (e.g. v1-sync-helper) can
	// react to profile changes. Fire-and-forget: a publish failure must not
	// block the user-facing response.
	if m.eventPublisher != nil {
		event := UserProfileUpdatedEvent{
			UserID:    user.UserID,
			Principal: user.UserID, // the JWT subject — identifies the caller
			Metadata:  updatedUser.UserMetadata,
			Timestamp: time.Now().UTC(),
		}
		eventJSON, jsonErr := json.Marshal(event)
		if jsonErr != nil {
			slog.WarnContext(ctx, "failed to marshal user profile updated event",
				"error", jsonErr,
				"user_id", redaction.Redact(user.UserID),
			)
		} else if pubErr := m.eventPublisher.Publish(ctx, constants.UserProfileUpdatedSubject, eventJSON); pubErr != nil {
			slog.WarnContext(ctx, "failed to publish user profile updated event",
				"error", pubErr,
				"user_id", redaction.Redact(user.UserID),
			)
		}
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

			// Authelia and Mock adapters expose linked emails via AlternateEmails;
			// the Auth0 adapter exposes them as identities with Connection == "email".
			for _, alternateEmail := range user.AlternateEmails {
				if strings.EqualFold(alternateEmail.Email, email) && alternateEmail.Verified {
					return errs.NewValidation("email already linked")
				}
			}
			for _, id := range user.Identities {
				if id.Connection != constants.EmailConnection {
					continue
				}
				if strings.EqualFold(id.Email, email) && id.EmailVerified {
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
		slog.ErrorContext(ctx, "auth service unavailable")
		return m.errorResponse("auth service unavailable"), nil
	}

	if m.userReader == nil {
		slog.ErrorContext(ctx, "auth service unavailable")
		return m.errorResponse("auth service unavailable"), nil
	}

	linkRequest := &model.LinkIdentity{}
	err := json.Unmarshal(msg.Data(), linkRequest)
	if err != nil {
		slog.ErrorContext(ctx, "failed to unmarshal link identity request",
			"error", err,
		)
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

// ChangePassword handles password change requests
func (m *messageHandlerOrchestrator) ChangePassword(ctx context.Context, msg port.TransportMessenger) ([]byte, error) {

	if m.passwordHandler == nil || m.userReader == nil {
		return m.errorResponse("password service unavailable"), nil
	}

	var request model.ChangePasswordRequest
	if err := json.Unmarshal(msg.Data(), &request); err != nil {
		return m.errorResponse("failed to unmarshal change password request"), nil
	}

	if strings.TrimSpace(request.Token) == "" {
		return m.errorResponse("token is required"), nil
	}
	if strings.TrimSpace(request.CurrentPassword) == "" {
		return m.errorResponse("current_password is required"), nil
	}
	if strings.TrimSpace(request.NewPassword) == "" {
		return m.errorResponse("new_password is required"), nil
	}

	user, errMetadataLookup := m.userReader.MetadataLookup(ctx, request.Token, constants.UserChangePasswordRequiredScope)
	if errMetadataLookup != nil {
		return m.errorResponse(errMetadataLookup.Error()), nil
	}

	errChange := m.passwordHandler.ChangePassword(ctx, user, request.CurrentPassword, request.NewPassword)
	if errChange != nil {
		return m.errorResponse(errChange.Error()), nil
	}

	response := UserDataResponse{
		Success: true,
		Message: "password updated successfully",
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		return m.errorResponse("failed to marshal response"), nil
	}

	return responseJSON, nil
}

// SendResetPasswordLink handles password reset link requests
func (m *messageHandlerOrchestrator) SendResetPasswordLink(ctx context.Context, msg port.TransportMessenger) ([]byte, error) {

	if m.passwordHandler == nil || m.userReader == nil {
		return m.errorResponse("password service unavailable"), nil
	}

	var request model.ResetPasswordLinkRequest
	if err := json.Unmarshal(msg.Data(), &request); err != nil {
		return m.errorResponse("failed to unmarshal reset password link request"), nil
	}

	if strings.TrimSpace(request.Token) == "" {
		return m.errorResponse("token is required"), nil
	}

	user, errMetadataLookup := m.userReader.MetadataLookup(ctx, request.Token, constants.UserChangePasswordRequiredScope)
	if errMetadataLookup != nil {
		return m.errorResponse(errMetadataLookup.Error()), nil
	}

	errReset := m.passwordHandler.SendResetPasswordLink(ctx, user)
	if errReset != nil {
		return m.errorResponse(errReset.Error()), nil
	}

	response := UserDataResponse{
		Success: true,
		Message: "password reset link sent successfully",
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		return m.errorResponse("failed to marshal response"), nil
	}

	return responseJSON, nil
}

// setPrimaryEmailRequest represents the JSON payload for set_primary email requests
type setPrimaryEmailRequest struct {
	User struct {
		AuthToken string `json:"auth_token"`
	} `json:"user"`
	Email string `json:"email"`
}

// SetPrimaryEmail handles requests to swap an alternate email to become the user's primary email
func (m *messageHandlerOrchestrator) SetPrimaryEmail(ctx context.Context, msg port.TransportMessenger) ([]byte, error) {

	if m.userWriter == nil || m.userReader == nil {
		return m.errorResponse("auth service unavailable"), nil
	}

	var request setPrimaryEmailRequest
	if err := json.Unmarshal(msg.Data(), &request); err != nil {
		return m.errorResponse("failed to unmarshal set primary email request"), nil
	}

	if strings.TrimSpace(request.User.AuthToken) == "" {
		return m.errorResponse("auth_token is required"), nil
	}
	email := strings.ToLower(strings.TrimSpace(request.Email))
	if email == "" {
		return m.errorResponse("email is required"), nil
	}
	if !(&model.Email{Email: email}).IsValidEmail() {
		return m.errorResponse("invalid email format"), nil
	}

	user, errMetadataLookup := m.userReader.MetadataLookup(ctx, request.User.AuthToken, constants.UserUpdateIdentityRequiredScope)
	if errMetadataLookup != nil {
		return m.errorResponse(errMetadataLookup.Error()), nil
	}

	errSetPrimary := m.userWriter.SetPrimaryEmail(ctx, user.UserID, email)
	if errSetPrimary != nil {
		return m.errorResponse(errSetPrimary.Error()), nil
	}

	response := UserDataResponse{
		Success: true,
		Message: "primary email updated successfully",
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		return m.errorResponse("failed to marshal response"), nil
	}

	return responseJSON, nil
}

// impersonationRequest is the JSON payload expected on the NATS subject.
type impersonationRequest struct {
	SubjectToken string `json:"subject_token"`
	TargetUser   string `json:"target_user"`
}

// ImpersonateUser handles an impersonation token exchange request over NATS.
// Request: JSON {"subject_token": "...", "target_user": "email_or_username"}
// Response: UserDataResponse with Data.AccessToken on success, or Error on failure.
func (m *messageHandlerOrchestrator) ImpersonateUser(ctx context.Context, msg port.TransportMessenger) ([]byte, error) {
	if m.impersonator == nil {
		return m.errorResponse("impersonation flow unavailable"), nil
	}

	var req impersonationRequest
	if err := json.Unmarshal(msg.Data(), &req); err != nil {
		return m.errorResponse("invalid request: " + err.Error()), nil
	}

	req.SubjectToken = strings.TrimSpace(req.SubjectToken)
	req.TargetUser = strings.TrimSpace(req.TargetUser)

	if req.SubjectToken == "" {
		return m.errorResponse("subject_token is required"), nil
	}
	if req.TargetUser == "" {
		return m.errorResponse("target_user is required"), nil
	}

	slog.DebugContext(ctx, "impersonation token exchange requested",
		"target_user", redaction.RedactEmail(req.TargetUser),
	)

	accessToken, err := m.impersonator.ImpersonateUser(ctx, req.SubjectToken, req.TargetUser)
	if err != nil {
		slog.WarnContext(ctx, "impersonation token exchange failed",
			"error", err,
			"target_user", redaction.RedactEmail(req.TargetUser),
		)
		return m.errorResponse(err.Error()), nil
	}

	response := UserDataResponse{
		Success: true,
		Data:    map[string]string{"access_token": accessToken},
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		return m.errorResponse("failed to marshal response"), nil
	}

	return responseJSON, nil
}

// NewMessageHandlerOrchestrator creates a new message handler orchestrator using the option pattern
func NewMessageHandlerOrchestrator(opts ...MessageHandlerOrchestratorOption) port.MessageHandler {
	m := &messageHandlerOrchestrator{}
	for _, opt := range opts {
		opt(m)
	}
	return m
}
