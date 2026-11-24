// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package constants

// EmailVerifiedAnnouncedAtKey is the Auth0 `app_metadata` key recording when the
// user_email_verified event was published for a user. The events consumer
// reads it from the stream payload to skip users already announced, and writes
// it after a successful publish.
const EmailVerifiedAnnouncedAtKey = "email_verified_announced_at"
