// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package constants

const (
	// AuthServiceQueue is the queue for the auth service.
	// The queue is of the form: lfx.auth-service.queue
	AuthServiceQueue = "lfx.auth-service.queue"

	// UserEmailToUserSubject is the subject for the user email to username event.
	// The subject is of the form: lfx.auth-service.email_to_username
	UserEmailToUserSubject = "lfx.auth-service.email_to_username"

	// UserMetadataUpdateSubject is the subject for the user metadata update event.
	// The subject is of the form: lfx.auth-service.user_metadata.update
	UserMetadataUpdateSubject = "lfx.auth-service.user_metadata.update"

	// UserMetadataReadSubject is the subject for the user metadata read event.
	// The subject is of the form: lfx.auth-service.user_metadata.read
	UserMetadataReadSubject = "lfx.auth-service.user_metadata.read"
)
