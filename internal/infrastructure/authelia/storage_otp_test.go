// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package authelia

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	errs "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
)

// fakeOTPKV is an in-memory, revision-checked stand-in for the email OTP bucket.
// It embeds the interface so any method the OTP code did not use before would
// panic rather than silently pass.
type fakeOTPKV struct {
	jetstream.KeyValue

	values    map[string][]byte
	revisions map[string]uint64
	seq       uint64

	// unconditionalDeletes counts deletes made without a revision guard.
	unconditionalDeletes int
}

func newFakeOTPKV() *fakeOTPKV {
	return &fakeOTPKV{values: map[string][]byte{}, revisions: map[string]uint64{}}
}

func (f *fakeOTPKV) Get(_ context.Context, key string) (jetstream.KeyValueEntry, error) {
	value, ok := f.values[key]
	if !ok {
		return nil, jetstream.ErrKeyNotFound
	}
	return fakeOTPEntry{value: value, revision: f.revisions[key]}, nil
}

func (f *fakeOTPKV) Create(_ context.Context, key string, value []byte, _ ...jetstream.KVCreateOpt) (uint64, error) {
	if _, ok := f.values[key]; ok {
		return 0, jetstream.ErrKeyExists
	}
	return f.write(key, value), nil
}

func (f *fakeOTPKV) Update(_ context.Context, key string, value []byte, revision uint64) (uint64, error) {
	if f.revisions[key] != revision {
		return 0, errors.New("wrong last sequence")
	}
	return f.write(key, value), nil
}

func (f *fakeOTPKV) Delete(_ context.Context, key string, opts ...jetstream.KVDeleteOpt) error {
	if len(opts) == 0 {
		f.unconditionalDeletes++
	}
	delete(f.values, key)
	f.seq++
	f.revisions[key] = f.seq
	return nil
}

func (f *fakeOTPKV) write(key string, value []byte) uint64 {
	f.seq++
	f.values[key] = append([]byte(nil), value...)
	f.revisions[key] = f.seq
	return f.seq
}

type fakeOTPEntry struct {
	jetstream.KeyValueEntry

	value    []byte
	revision uint64
}

func (e fakeOTPEntry) Value() []byte    { return e.value }
func (e fakeOTPEntry) Revision() uint64 { return e.revision }

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newOTPTestStorage() (*natsUserStorage, *fakeOTPKV, *fakeClock) {
	kv := newFakeOTPKV()
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	storage := &natsUserStorage{
		kvStore: map[string]jetstream.KeyValue{constants.KVBucketNameAutheliaEmailOTP: kv},
		now:     clock.now,
	}
	return storage, kv, clock
}

func TestNATSUserStorage_VerificationCode(t *testing.T) {
	ctx := context.Background()
	const key = "email-key"

	t.Run("a correct code is accepted exactly once", func(t *testing.T) {
		storage, kv, _ := newOTPTestStorage()
		_, err := storage.CreateVerificationCode(ctx, key, "123456")
		require.NoError(t, err)

		require.NoError(t, storage.ConsumeVerificationCode(ctx, key, "123456"))

		err = storage.ConsumeVerificationCode(ctx, key, "123456")
		var notFound errs.NotFound
		require.ErrorAs(t, err, &notFound, "a consumed code must not be replayable")
		assert.Zero(t, kv.unconditionalDeletes, "the consume must be revision-checked")
	})

	t.Run("the code is locked after the attempt limit, even for the correct value", func(t *testing.T) {
		storage, _, _ := newOTPTestStorage()
		_, err := storage.CreateVerificationCode(ctx, key, "123456")
		require.NoError(t, err)

		for i := 0; i < otpMaxAttempts; i++ {
			err := storage.ConsumeVerificationCode(ctx, key, "000000")
			var validation errs.Validation
			require.ErrorAs(t, err, &validation)
		}

		err = storage.ConsumeVerificationCode(ctx, key, "123456")
		require.Error(t, err, "the correct code must be rejected once the attempt limit is reached")

		_, err = storage.CreateVerificationCode(ctx, key, "654321")
		var rateLimited errs.RateLimited
		require.ErrorAs(t, err, &rateLimited, "a locked code must not be replaced before it expires")
	})

	t.Run("a locked code can be replaced once it expires", func(t *testing.T) {
		storage, _, clock := newOTPTestStorage()
		_, err := storage.CreateVerificationCode(ctx, key, "123456")
		require.NoError(t, err)
		for i := 0; i < otpMaxAttempts; i++ {
			require.Error(t, storage.ConsumeVerificationCode(ctx, key, "000000"))
		}

		clock.advance(otpLifetime)

		_, err = storage.CreateVerificationCode(ctx, key, "654321")
		require.NoError(t, err)
		require.NoError(t, storage.ConsumeVerificationCode(ctx, key, "654321"))
	})

	t.Run("resending is rate limited per address", func(t *testing.T) {
		storage, _, clock := newOTPTestStorage()
		_, err := storage.CreateVerificationCode(ctx, key, "123456")
		require.NoError(t, err)

		_, err = storage.CreateVerificationCode(ctx, key, "654321")
		var rateLimited errs.RateLimited
		require.ErrorAs(t, err, &rateLimited)

		_, err = storage.CreateVerificationCode(ctx, "other-key", "111111")
		require.NoError(t, err, "the limit applies per address")

		clock.advance(otpResendCooldown)
		_, err = storage.CreateVerificationCode(ctx, key, "654321")
		require.NoError(t, err)

		require.Error(t, storage.ConsumeVerificationCode(ctx, key, "123456"), "the replaced code must no longer verify")
		require.NoError(t, storage.ConsumeVerificationCode(ctx, key, "654321"))
	})

	t.Run("a resend does not extend the attempt budget during the cooldown", func(t *testing.T) {
		storage, _, _ := newOTPTestStorage()
		_, err := storage.CreateVerificationCode(ctx, key, "123456")
		require.NoError(t, err)
		require.Error(t, storage.ConsumeVerificationCode(ctx, key, "000000"))

		_, err = storage.CreateVerificationCode(ctx, key, "654321")
		require.Error(t, err)
	})

	t.Run("an expired code is rejected", func(t *testing.T) {
		storage, _, clock := newOTPTestStorage()
		_, err := storage.CreateVerificationCode(ctx, key, "123456")
		require.NoError(t, err)

		clock.advance(otpLifetime)

		err = storage.ConsumeVerificationCode(ctx, key, "123456")
		var notFound errs.NotFound
		require.ErrorAs(t, err, &notFound)
	})

	t.Run("expiry is not extended by failed attempts", func(t *testing.T) {
		storage, _, clock := newOTPTestStorage()
		_, err := storage.CreateVerificationCode(ctx, key, "123456")
		require.NoError(t, err)

		clock.advance(otpLifetime - time.Second)
		require.Error(t, storage.ConsumeVerificationCode(ctx, key, "000000"))
		clock.advance(time.Second)

		err = storage.ConsumeVerificationCode(ctx, key, "123456")
		var notFound errs.NotFound
		require.ErrorAs(t, err, &notFound)
	})

	t.Run("a legacy plain-text value never verifies", func(t *testing.T) {
		storage, kv, _ := newOTPTestStorage()
		kv.write(key, []byte("123456"))

		err := storage.ConsumeVerificationCode(ctx, key, "123456")
		var notFound errs.NotFound
		require.ErrorAs(t, err, &notFound)

		_, err = storage.CreateVerificationCode(ctx, key, "654321")
		require.NoError(t, err)
	})

	t.Run("a missing code is not found", func(t *testing.T) {
		storage, _, _ := newOTPTestStorage()
		err := storage.ConsumeVerificationCode(ctx, key, "123456")
		var notFound errs.NotFound
		require.ErrorAs(t, err, &notFound)
	})

	t.Run("a concurrent send is reported as a conflict", func(t *testing.T) {
		storage, kv, _ := newOTPTestStorage()
		kv.write(key, []byte(`{"otp":"999999","created_at":"2000-01-01T00:00:00Z","expires_at":"2000-01-01T00:05:00Z"}`))
		staleKV := &staleRevisionKV{fakeOTPKV: kv}
		storage.kvStore[constants.KVBucketNameAutheliaEmailOTP] = staleKV

		_, err := storage.CreateVerificationCode(ctx, key, "123456")
		var conflict errs.Conflict
		require.ErrorAs(t, err, &conflict)
	})

	t.Run("a guess is not compared unless its attempt was recorded", func(t *testing.T) {
		storage, kv, _ := newOTPTestStorage()
		_, err := storage.CreateVerificationCode(ctx, key, "123456")
		require.NoError(t, err)
		storage.kvStore[constants.KVBucketNameAutheliaEmailOTP] = &staleRevisionKV{fakeOTPKV: kv}

		err = storage.ConsumeVerificationCode(ctx, key, "123456")
		var conflict errs.Conflict
		require.ErrorAs(t, err, &conflict, "a correct code must not be accepted without recording the attempt")
	})

	t.Run("the rollback delete is revision-checked", func(t *testing.T) {
		storage, kv, _ := newOTPTestStorage()
		revision, err := storage.CreateVerificationCode(ctx, key, "123456")
		require.NoError(t, err)

		require.NoError(t, storage.DeleteVerificationCode(ctx, key, revision))
		assert.Zero(t, kv.unconditionalDeletes)
	})
}

// staleRevisionKV simulates another writer changing the key between the read
// and the revision-checked write.
type staleRevisionKV struct {
	*fakeOTPKV
}

func (s *staleRevisionKV) Update(ctx context.Context, key string, value []byte, revision uint64) (uint64, error) {
	s.write(key, []byte(`{}`))
	return s.fakeOTPKV.Update(ctx, key, value, revision)
}
