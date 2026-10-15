// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package authelia

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/nats"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	errs "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/redaction"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	kvLookupPrefix = "lookup/"

	// otpMaxAttempts is the number of verification attempts allowed per code.
	otpMaxAttempts = 5
	// otpLifetime is how long a verification code is valid after it is issued. The
	// email OTP bucket TTL must be at least this long, otherwise a locked record
	// could be dropped (and its attempt count reset) before it expires.
	otpLifetime = 5 * time.Minute
	// otpResendCooldown is the minimum time between codes sent to the same address.
	otpResendCooldown = time.Minute
)

type internalStorageReaderWriter interface {
	internalStorageReader
	internalStorageWriter
	emailHandler
}

type internalStorageReader interface {
	GetUser(ctx context.Context, key string) (*AutheliaUser, error)
	GetUserWithRevision(ctx context.Context, key string) (*AutheliaUser, uint64, error)
	ListUsers(ctx context.Context) (map[string]*AutheliaUser, error)
	BuildLookupKey(ctx context.Context, lookupKey, key string) string
}

type internalStorageWriter interface {
	SetUser(ctx context.Context, user *AutheliaUser) (any, error)
	UpdateUserWithRevision(ctx context.Context, user *AutheliaUser, revision uint64) error
}

type emailHandler interface {
	CreateVerificationCode(ctx context.Context, email, otp string) (uint64, error)
	ConsumeVerificationCode(ctx context.Context, email, otp string) error
	DeleteVerificationCode(ctx context.Context, email string, revision uint64) error
}

// natsUserStorage implements UserStorage using NATS KV store
type natsUserStorage struct {
	natsClient *nats.NATSClient
	kvStore    map[string]jetstream.KeyValue
	now        func() time.Time
}

func (n *natsUserStorage) lookupUser(ctx context.Context, key string) (string, error) {

	if !strings.HasPrefix(key, kvLookupPrefix) {
		return key, nil
	}

	entry, err := n.kvStore[constants.KVBucketNameAutheliaUsers].Get(ctx, key)
	if err != nil {
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			return "", errs.NewNotFound("user not found")
		}
		return "", errs.NewUnexpected("failed to get user from NATS KV", err)
	}
	return string(entry.Value()), nil
}

func (n *natsUserStorage) GetUser(ctx context.Context, key string) (*AutheliaUser, error) {
	user, _, err := n.GetUserWithRevision(ctx, key)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (n *natsUserStorage) GetUserWithRevision(ctx context.Context, key string) (*AutheliaUser, uint64, error) {

	if key == "" {
		return nil, 0, errs.NewUnexpected("key is required")
	}

	username, errLookupUser := n.lookupUser(ctx, key)
	if errLookupUser != nil {
		return nil, 0, errLookupUser
	}

	entry, err := n.kvStore[constants.KVBucketNameAutheliaUsers].Get(ctx, username)
	if err != nil {
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			return nil, 0, errs.NewNotFound("user not found")
		}
		return nil, 0, errs.NewUnexpected("failed to get user from NATS KV", err)
	}

	var storageUser AutheliaUserStorage
	if err := json.Unmarshal(entry.Value(), &storageUser); err != nil {
		return nil, 0, errs.NewUnexpected("failed to unmarshal user data", err)
	}

	// Convert storage format back to AutheliaUser
	var autheliaUser AutheliaUser
	autheliaUser.FromStorage(&storageUser)

	return &autheliaUser, entry.Revision(), nil
}

func (n *natsUserStorage) ListUsers(ctx context.Context) (map[string]*AutheliaUser, error) {
	users := make(map[string]*AutheliaUser)

	// Get all keys from the KV store
	keys, err := n.kvStore[constants.KVBucketNameAutheliaUsers].Keys(ctx)
	if err != nil && !strings.Contains(err.Error(), "no keys found") {
		return nil, errs.NewUnexpected("failed to list keys from NATS KV", err)
	}

	// Retrieve each user
	for _, key := range keys {

		// Skip lookup keys since they are not users
		if strings.HasPrefix(key, kvLookupPrefix) {
			continue
		}

		user, err := n.GetUser(ctx, key)
		if err != nil {
			slog.WarnContext(ctx, "failed to get user during list operation",
				"username", key, "error", err)
			continue
		}
		users[key] = user
	}

	return users, nil
}

func (n *natsUserStorage) setLookupKeys(ctx context.Context, user *AutheliaUser) error {
	if user.Email != "" {
		_, errPutLookup := n.kvStore[constants.KVBucketNameAutheliaUsers].Put(ctx, n.BuildLookupKey(ctx, "email", user.BuildEmailIndexKey(ctx)), []byte(user.Username))
		if errPutLookup != nil {
			return errs.NewUnexpected("failed to set lookup key in NATS KV", errPutLookup)
		}
	}

	if len(user.AlternateEmails) > 0 {
		for _, alternateEmail := range user.AlternateEmails {
			_, errPutLookup := n.kvStore[constants.KVBucketNameAutheliaUsers].Put(ctx, n.BuildLookupKey(ctx, "email", user.BuildAlternateEmailIndexKey(ctx, alternateEmail.Email)), []byte(user.Username))
			if errPutLookup != nil {
				return errs.NewUnexpected("failed to set alternate email lookup key in NATS KV", errPutLookup)
			}
		}
	}

	if user.Sub != "" {
		_, errPutLookup := n.kvStore[constants.KVBucketNameAutheliaUsers].Put(ctx, n.BuildLookupKey(ctx, "sub", user.BuildSubIndexKey(ctx)), []byte(user.Username))
		if errPutLookup != nil {
			return errs.NewUnexpected("failed to set sub lookup key in NATS KV", errPutLookup)
		}
	}
	return nil
}

func (n *natsUserStorage) SetUser(ctx context.Context, user *AutheliaUser) (any, error) {

	// Update timestamp
	user.UpdatedAt = time.Now()

	// If this is a new user (no CreatedAt), set it
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now()
	}

	// Convert to storage format (excludes sensitive fields)
	storageUser := user.ToStorage()

	data, err := json.Marshal(storageUser)
	if err != nil {
		return nil, errs.NewUnexpected("failed to marshal user data", err)
	}

	// user main data
	_, errPut := n.kvStore[constants.KVBucketNameAutheliaUsers].Put(ctx, user.Username, data)
	if errPut != nil {
		return nil, errs.NewUnexpected("failed to set user in NATS KV", errPut)
	}

	// lookup keys
	errSetLookupKeys := n.setLookupKeys(ctx, user)
	if errSetLookupKeys != nil {
		return nil, errs.NewUnexpected("failed to set lookup keys in NATS KV", errSetLookupKeys)
	}

	return user, nil
}

func (n *natsUserStorage) UpdateUserWithRevision(ctx context.Context, user *AutheliaUser, revision uint64) error {

	// Update timestamp
	user.UpdatedAt = time.Now()

	// Convert to storage format (excludes sensitive fields)
	storageUser := user.ToStorage()

	data, err := json.Marshal(storageUser)
	if err != nil {
		return errs.NewUnexpected("failed to marshal user data", err)
	}

	// Use Update instead of Put to ensure optimistic locking with revision
	_, errUpdate := n.kvStore[constants.KVBucketNameAutheliaUsers].Update(ctx, user.Username, data, revision)
	if errUpdate != nil {
		if errors.Is(errUpdate, jetstream.ErrKeyNotFound) {
			return errs.NewNotFound("user not found for update")
		}
		// NATS returns an error if the revision doesn't match (concurrent modification)
		return errs.NewConflict("user has been modified by another process, please retry", errUpdate)
	}

	// lookup keys - these are not subject to revision control as they're separate keys
	// lookup keys
	errSetLookupKeys := n.setLookupKeys(ctx, user)
	if errSetLookupKeys != nil {
		return errs.NewUnexpected("failed to set lookup keys in NATS KV", errSetLookupKeys)
	}

	return nil
}

// verificationCodeRecord is the value stored in the email OTP bucket for one address.
// ExpiresAt is enforced here rather than relying on the bucket TTL alone, because
// every revision-checked write restarts the bucket TTL for that key.
type verificationCodeRecord struct {
	OTP       string    `json:"otp"`
	Attempts  int       `json:"attempts"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	// Consumed marks a code that was accepted. The record is kept until it expires so
	// the resend cooldown still applies, but it can never be accepted again.
	Consumed bool `json:"consumed,omitempty"`
}

func (r *verificationCodeRecord) expired(now time.Time) bool {
	return !now.Before(r.ExpiresAt)
}

func (r *verificationCodeRecord) locked() bool {
	return r.Attempts >= otpMaxAttempts
}

// isRevisionMismatch reports whether a revision-checked KV write lost to another writer.
func isRevisionMismatch(err error) bool {
	var jsErr jetstream.JetStreamError
	return errors.As(err, &jsErr) && jsErr.APIError() != nil &&
		jsErr.APIError().ErrorCode == jetstream.JSErrCodeStreamWrongLastSequence
}

// verificationCodeWriteError maps a failed revision-checked write to a client-facing error
// without exposing KV internals in the message.
func verificationCodeWriteError(ctx context.Context, email string, err error) error {
	slog.WarnContext(ctx, "failed to write verification code",
		"email", redaction.RedactEmail(email),
		"error", err,
	)
	if isRevisionMismatch(err) {
		return errs.NewConflict("verification code was modified concurrently, please retry")
	}
	return errs.NewUnexpected("failed to write verification code")
}

func (n *natsUserStorage) clock() time.Time {
	if n.now != nil {
		return n.now()
	}
	return time.Now()
}

// getVerificationCodeRecord returns the stored record and its revision. A value that
// cannot be decoded is reported as (nil, revision, nil) so callers can replace it.
func (n *natsUserStorage) getVerificationCodeRecord(ctx context.Context, key string) (*verificationCodeRecord, uint64, error) {
	entry, err := n.kvStore[constants.KVBucketNameAutheliaEmailOTP].Get(ctx, key)
	if err != nil {
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			return nil, 0, errs.NewNotFound("verification code not found or expired")
		}
		return nil, 0, errs.NewUnexpected("failed to get verification code from NATS KV", err)
	}

	var record verificationCodeRecord
	if errUnmarshal := json.Unmarshal(entry.Value(), &record); errUnmarshal != nil || (record.OTP == "" && !record.Consumed) {
		return nil, entry.Revision(), nil
	}
	return &record, entry.Revision(), nil
}

// CreateVerificationCode stores a new verification code (OTP) for an email address in the
// email OTP bucket and returns the revision it was written at. A new code is refused while
// the current one is inside its resend cooldown, or while it is locked after too many
// failed attempts and not yet expired.
func (n *natsUserStorage) CreateVerificationCode(ctx context.Context, email, otp string) (uint64, error) {
	if email == "" {
		return 0, errs.NewUnexpected("email is required")
	}
	if otp == "" {
		return 0, errs.NewUnexpected("otp is required")
	}

	now := n.clock()
	existing, revision, errGet := n.getVerificationCodeRecord(ctx, email)
	var notFound errs.NotFound
	switch {
	case errGet == nil:
	case errors.As(errGet, &notFound):
	default:
		return 0, errGet
	}

	if existing != nil && !existing.expired(now) {
		if existing.locked() && !existing.Consumed {
			return 0, errs.NewRateLimited("too many failed verification attempts, please try again later", existing.ExpiresAt.Sub(now))
		}
		if resendAt := existing.CreatedAt.Add(otpResendCooldown); now.Before(resendAt) {
			return 0, errs.NewRateLimited("a verification code was sent recently, please try again later", resendAt.Sub(now))
		}
	}

	record := &verificationCodeRecord{
		OTP:       otp,
		CreatedAt: now,
		ExpiresAt: now.Add(otpLifetime),
	}
	// Failed attempts carry over to a replacement code, so resending cannot be used
	// to reset the attempt budget before the current code expires.
	if existing != nil && !existing.expired(now) && !existing.Consumed {
		record.Attempts = existing.Attempts
	}

	data, errMarshal := json.Marshal(record)
	if errMarshal != nil {
		return 0, errs.NewUnexpected("failed to marshal verification code", errMarshal)
	}

	kv := n.kvStore[constants.KVBucketNameAutheliaEmailOTP]
	var (
		newRevision uint64
		errWrite    error
	)
	if errGet != nil {
		newRevision, errWrite = kv.Create(ctx, email, data)
	} else {
		newRevision, errWrite = kv.Update(ctx, email, data, revision)
	}
	if errWrite != nil {
		return 0, verificationCodeWriteError(ctx, email, errWrite)
	}

	slog.InfoContext(ctx, "verification code stored successfully",
		"email", redaction.RedactEmail(email),
	)

	return newRevision, nil
}

// ConsumeVerificationCode checks a submitted verification code (OTP) for an email address.
// Each check spends one of a bounded number of attempts before the comparison is made, and
// a matching code is marked consumed in the same revision-checked operation that accepts it,
// so a code can be accepted at most once.
func (n *natsUserStorage) ConsumeVerificationCode(ctx context.Context, email, otp string) error {
	if email == "" {
		return errs.NewUnexpected("email is required")
	}

	kv := n.kvStore[constants.KVBucketNameAutheliaEmailOTP]
	now := n.clock()

	record, revision, errGet := n.getVerificationCodeRecord(ctx, email)
	if errGet != nil {
		return errGet
	}
	if record == nil || record.expired(now) {
		if errDelete := kv.Delete(ctx, email, jetstream.LastRevision(revision)); errDelete != nil {
			slog.WarnContext(ctx, "failed to delete expired verification code",
				"email", redaction.RedactEmail(email),
				"error", errDelete,
			)
		}
		return errs.NewNotFound("verification code not found or expired")
	}
	if record.Consumed {
		return errs.NewNotFound("verification code not found or expired")
	}
	if record.locked() {
		return errs.NewValidation("too many failed verification attempts, please try again later")
	}

	// Reserve the attempt before comparing so that concurrent guesses against the
	// same revision cannot be evaluated without being counted.
	record.Attempts++
	data, errMarshal := json.Marshal(record)
	if errMarshal != nil {
		return errs.NewUnexpected("failed to marshal verification code", errMarshal)
	}
	reservedRevision, errUpdate := kv.Update(ctx, email, data, revision)
	if errUpdate != nil {
		return verificationCodeWriteError(ctx, email, errUpdate)
	}

	if subtle.ConstantTimeCompare([]byte(record.OTP), []byte(otp)) != 1 {
		slog.WarnContext(ctx, "invalid verification code submitted",
			"email", redaction.RedactEmail(email),
			"attempts", record.Attempts,
		)
		return errs.NewValidation("invalid verification code")
	}

	consumed, errMarshal := json.Marshal(&verificationCodeRecord{
		Attempts:  record.Attempts,
		CreatedAt: record.CreatedAt,
		ExpiresAt: record.ExpiresAt,
		Consumed:  true,
	})
	if errMarshal != nil {
		return errs.NewUnexpected("failed to marshal verification code", errMarshal)
	}
	if _, errConsume := kv.Update(ctx, email, consumed, reservedRevision); errConsume != nil {
		return verificationCodeWriteError(ctx, email, errConsume)
	}

	slog.InfoContext(ctx, "verification code consumed successfully",
		"email", redaction.RedactEmail(email),
	)

	return nil
}

// DeleteVerificationCode removes the verification code for an email address if it is still
// at the given revision.
func (n *natsUserStorage) DeleteVerificationCode(ctx context.Context, email string, revision uint64) error {
	if email == "" {
		return errs.NewUnexpected("email is required")
	}
	if errDelete := n.kvStore[constants.KVBucketNameAutheliaEmailOTP].Delete(ctx, email, jetstream.LastRevision(revision)); errDelete != nil {
		return errs.NewUnexpected("failed to delete verification code from NATS KV", errDelete)
	}
	return nil
}

// BuildLookupKey builds the lookup key for the given lookup key and key
func (n *natsUserStorage) BuildLookupKey(ctx context.Context, lookupKey, key string) string {
	prefix := fmt.Sprintf(constants.KVLookupPrefixAuthelia, lookupKey)
	return fmt.Sprintf("%s/%s", prefix, key)
}

// newNATSUserStorage creates a new NATS-based user storage
func newNATSUserStorage(ctx context.Context, natsClient *nats.NATSClient) (internalStorageReaderWriter, error) {
	// Get the KV store for authelia users
	kvStores := make(map[string]jetstream.KeyValue)
	for _, bucketName := range []string{constants.KVBucketNameAutheliaUsers, constants.KVBucketNameAutheliaEmailOTP} {
		kvStore, exists := natsClient.GetKVStore(bucketName)
		if !exists {
			return nil, errs.NewUnexpected("KV bucket not found in NATS client")
		}
		kvStores[bucketName] = kvStore
	}
	slog.DebugContext(ctx, "created NATS user storage", "kvStores", kvStores)

	return &natsUserStorage{
		natsClient: natsClient,
		kvStore:    kvStores,
	}, nil
}
