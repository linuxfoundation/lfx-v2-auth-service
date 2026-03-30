// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package constants

const (
	// AuthServiceQueue is the queue for the auth service.
	// The queue is of the form: lfx.auth-service.queue
	AuthServiceQueue = "lfx.auth-service.queue"
)

const (

	// Lookup subjects

	// UserEmailToUserSubject is the subject for the user email to username event.
	// The subject is of the form: lfx.auth-service.email_to_username
	UserEmailToUserSubject = "lfx.auth-service.email_to_username"

	// UserEmailToSubSubject is the subject for the user email to sub event.
	// The subject is of the form: lfx.auth-service.email_to_sub
	UserEmailToSubSubject = "lfx.auth-service.email_to_sub"
)

const (

	// User read/write subjects

	// UserMetadataUpdateSubject is the subject for the user metadata update event.
	// The subject is of the form: lfx.auth-service.user_metadata.update
	UserMetadataUpdateSubject = "lfx.auth-service.user_metadata.update"

	// UserMetadataReadSubject is the subject for the user metadata read event.
	// The subject is of the form: lfx.auth-service.user_metadata.read
	UserMetadataReadSubject = "lfx.auth-service.user_metadata.read"

	// UserEmailReadSubject is the subject for the user email read event.
	// The subject is of the form: lfx.auth-service.user_emails.read
	UserEmailReadSubject = "lfx.auth-service.user_emails.read"
)

const (

	// Email and Identity linking subjects

	// EmailLinkingSendVerificationSubject is the subject for the email linking start event.
	// The subject is of the form: lfx.auth-service.email_linking.send_verification
	EmailLinkingSendVerificationSubject = "lfx.auth-service.email_linking.send_verification"

	// EmailLinkingVerifySubject is the subject for the email linking verify event.
	// The subject is of the form: lfx.auth-service.email_linking.verify
	EmailLinkingVerifySubject = "lfx.auth-service.email_linking.verify"

	// UserIdentityLinkSubject is the subject for the user identity linking event.
	// The subject is of the form: lfx.auth-service.user_identity.link
	UserIdentityLinkSubject = "lfx.auth-service.user_identity.link"

	// UserIdentityUnlinkSubject is the subject for the user identity unlinking event.
	// The subject is of the form: lfx.auth-service.user_identity.unlink
	UserIdentityUnlinkSubject = "lfx.auth-service.user_identity.unlink"

	// UserIdentityListSubject is the subject for listing user identities.
	// The subject is of the form: lfx.auth-service.user_identity.list
	UserIdentityListSubject = "lfx.auth-service.user_identity.list"
)
