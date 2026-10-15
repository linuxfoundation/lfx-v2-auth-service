// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package authelia

import (
	"context"
	"errors"
	"reflect"
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

	t testing.TB

	values    map[string][]byte
	revisions map[string]uint64
	seq       uint64

	// unconditionalDeletes counts deletes made without a revision guard.
	unconditionalDeletes int
	// writeErr, when set, fails every write with this error.
	writeErr error
}

var errWrongLastSequence = &jetstream.APIError{Code: 400, ErrorCode: jetstream.JSErrCodeStreamWrongLastSequence}

// deleteRevision extracts the revision from a jetstream.LastRevision option. The
// option type is unexported, so it is applied by reflection to a zero options value.
func deleteRevision(t testing.TB, opt jetstream.KVDeleteOpt) uint64 {
	fn := reflect.ValueOf(opt)
	if fn.Kind() != reflect.Func || fn.Type().NumIn() != 1 {
		t.Fatalf("unexpected delete option type %T", opt)
	}
	opts := reflect.New(fn.Type().In(0).Elem())
	fn.Call([]reflect.Value{opts})
	return opts.Elem().FieldByName("revision").Uint()
}

func newFakeOTPKV(t testing.TB) *fakeOTPKV {
	return &fakeOTPKV{t: t, values: map[string][]byte{}, revisions: map[string]uint64{}}
}

func (f *fakeOTPKV) Get(_ context.Context, key string) (jetstream.KeyValueEntry, error) {
	value, ok := f.values[key]
	if !ok {
		return nil, jetstream.ErrKeyNotFound
	}
	return fakeOTPEntry{value: value, revision: f.revisions[key]}, nil
}

func (f *fakeOTPKV) Create(_ context.Context, key string, value []byte, _ ...jetstream.KVCreateOpt) (uint64, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	if _, ok := f.values[key]; ok {
		return 0, jetstream.ErrKeyExists
	}
	return f.write(key, value), nil
}

func (f *fakeOTPKV) Update(_ context.Context, key string, value []byte, revision uint64) (uint64, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	if f.revisions[key] != revision {
		return 0, errWrongLastSequence
	}
	return f.write(key, value), nil
}

func (f *fakeOTPKV) Delete(_ context.Context, key string, opts ...jetstream.KVDeleteOpt) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	revision := uint64(0)
	for _, opt := range opts {
		revision = deleteRevision(f.t, opt)
	}
	if revision == 0 {
		f.unconditionalDeletes++
	} else if f.revisions[key] != revision {
		return errWrongLastSequence
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

func newOTPTestStorage(t testing.TB) (*natsUserStorage, *fakeOTPKV, *fakeClock) {
	kv := newFakeOTPKV(t)
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
		storage, kv, _ := newOTPTestStorage(t)
		_, err := storage.CreateVerificationCode(ctx, key, "123456")
		require.NoError(t, err)

		require.NoError(t, storage.ConsumeVerificationCode(ctx, key, "123456"))

		err = storage.ConsumeVerificationCode(ctx, key, "123456")
		var notFound errs.NotFound
		require.ErrorAs(t, err, &notFound, "a consumed code must not be replayable")
		assert.Zero(t, kv.unconditionalDeletes, "the consume must be revision-checked")
	})

	t.Run("the code is locked after the attempt limit, even for the correct value", func(t *testing.T) {
		storage, _, _ := newOTPTestStorage(t)
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
		storage, _, clock := newOTPTestStorage(t)
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
		storage, _, clock := newOTPTestStorage(t)
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
		storage, _, _ := newOTPTestStorage(t)
		_, err := storage.CreateVerificationCode(ctx, key, "123456")
		require.NoError(t, err)
		require.Error(t, storage.ConsumeVerificationCode(ctx, key, "000000"))

		_, err = storage.CreateVerificationCode(ctx, key, "654321")
		require.Error(t, err)
	})

	t.Run("failed attempts carry over to a resent code", func(t *testing.T) {
		storage, _, clock := newOTPTestStorage(t)
		_, err := storage.CreateVerificationCode(ctx, key, "123456")
		require.NoError(t, err)
		for i := 0; i < otpMaxAttempts-1; i++ {
			require.Error(t, storage.ConsumeVerificationCode(ctx, key, "000000"))
		}

		clock.advance(otpResendCooldown)
		_, err = storage.CreateVerificationCode(ctx, key, "654321")
		require.NoError(t, err)
		require.Error(t, storage.ConsumeVerificationCode(ctx, key, "000000"))

		require.Error(t, storage.ConsumeVerificationCode(ctx, key, "654321"),
			"resending must not reset the attempt budget")
		_, err = storage.CreateVerificationCode(ctx, key, "111111")
		var rateLimited errs.RateLimited
		require.ErrorAs(t, err, &rateLimited)
	})

	t.Run("a correct code is not accepted if another attempt lands before it is consumed", func(t *testing.T) {
		storage, kv, _ := newOTPTestStorage(t)
		_, err := storage.CreateVerificationCode(ctx, key, "123456")
		require.NoError(t, err)
		storage.kvStore[constants.KVBucketNameAutheliaEmailOTP] = &interleavingDeleteKV{fakeOTPKV: kv}

		err = storage.ConsumeVerificationCode(ctx, key, "123456")
		var conflict errs.Conflict
		require.ErrorAs(t, err, &conflict)
		_, stillStored := kv.values[key]
		assert.True(t, stillStored, "the code must not be consumed by the losing request")
	})

	t.Run("KV failures are not reported as conflicts and do not leak details", func(t *testing.T) {
		storage, kv, _ := newOTPTestStorage(t)
		_, err := storage.CreateVerificationCode(ctx, key, "123456")
		require.NoError(t, err)
		kv.writeErr = errors.New("nats: internal detail")

		err = storage.ConsumeVerificationCode(ctx, key, "123456")
		var unexpected errs.Unexpected
		require.ErrorAs(t, err, &unexpected)
		assert.NotContains(t, err.Error(), "internal detail")
	})

	t.Run("an expired code is rejected", func(t *testing.T) {
		storage, _, clock := newOTPTestStorage(t)
		_, err := storage.CreateVerificationCode(ctx, key, "123456")
		require.NoError(t, err)

		clock.advance(otpLifetime)

		err = storage.ConsumeVerificationCode(ctx, key, "123456")
		var notFound errs.NotFound
		require.ErrorAs(t, err, &notFound)
	})

	t.Run("expiry is not extended by failed attempts", func(t *testing.T) {
		storage, _, clock := newOTPTestStorage(t)
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
		storage, kv, _ := newOTPTestStorage(t)
		kv.write(key, []byte("123456"))

		err := storage.ConsumeVerificationCode(ctx, key, "123456")
		var notFound errs.NotFound
		require.ErrorAs(t, err, &notFound)

		_, err = storage.CreateVerificationCode(ctx, key, "654321")
		require.NoError(t, err)
	})

	t.Run("a missing code is not found", func(t *testing.T) {
		storage, _, _ := newOTPTestStorage(t)
		err := storage.ConsumeVerificationCode(ctx, key, "123456")
		var notFound errs.NotFound
		require.ErrorAs(t, err, &notFound)
	})

	t.Run("a concurrent send is reported as a conflict", func(t *testing.T) {
		storage, kv, _ := newOTPTestStorage(t)
		kv.write(key, []byte(`{"otp":"999999","created_at":"2000-01-01T00:00:00Z","expires_at":"2000-01-01T00:05:00Z"}`))
		staleKV := &staleRevisionKV{fakeOTPKV: kv}
		storage.kvStore[constants.KVBucketNameAutheliaEmailOTP] = staleKV

		_, err := storage.CreateVerificationCode(ctx, key, "123456")
		var conflict errs.Conflict
		require.ErrorAs(t, err, &conflict)
	})

	t.Run("a guess is not compared unless its attempt was recorded", func(t *testing.T) {
		storage, kv, _ := newOTPTestStorage(t)
		_, err := storage.CreateVerificationCode(ctx, key, "123456")
		require.NoError(t, err)
		storage.kvStore[constants.KVBucketNameAutheliaEmailOTP] = &staleRevisionKV{fakeOTPKV: kv}

		err = storage.ConsumeVerificationCode(ctx, key, "123456")
		var conflict errs.Conflict
		require.ErrorAs(t, err, &conflict, "a correct code must not be accepted without recording the attempt")
	})

	t.Run("the rollback delete is revision-checked", func(t *testing.T) {
		storage, kv, _ := newOTPTestStorage(t)
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

// interleavingDeleteKV simulates another attempt being recorded between the
// attempt reservation and the consuming delete.
type interleavingDeleteKV struct {
	*fakeOTPKV
}

func (i *interleavingDeleteKV) Delete(ctx context.Context, key string, opts ...jetstream.KVDeleteOpt) error {
	i.write(key, i.values[key])
	return i.fakeOTPKV.Delete(ctx, key, opts...)
}
