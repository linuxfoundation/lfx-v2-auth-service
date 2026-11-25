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

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
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
	// ttl is the bucket TTL reported by Status.
	ttl time.Duration
}

func (f *fakeOTPKV) Status(context.Context) (jetstream.KeyValueStatus, error) {
	return fakeOTPStatus{ttl: f.ttl}, nil
}

type fakeOTPStatus struct {
	jetstream.KeyValueStatus

	ttl time.Duration
}

func (s fakeOTPStatus) TTL() time.Duration { return s.ttl }

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
		storage, _, _ := newOTPTestStorage(t)
		err := storage.CreateVerificationCode(ctx, key, "123456")
		require.NoError(t, err)

		require.NoError(t, storage.ConsumeVerificationCode(ctx, key, "123456"))

		err = storage.ConsumeVerificationCode(ctx, key, "123456")
		var notFound errs.NotFound
		require.ErrorAs(t, err, &notFound, "a consumed code must not be replayable")
	})

	t.Run("the code is locked after the attempt limit, even for the correct value", func(t *testing.T) {
		storage, _, _ := newOTPTestStorage(t)
		err := storage.CreateVerificationCode(ctx, key, "123456")
		require.NoError(t, err)

		for i := 0; i < otpMaxAttempts; i++ {
			err := storage.ConsumeVerificationCode(ctx, key, "000000")
			var validation errs.Validation
			require.ErrorAs(t, err, &validation)
		}

		err = storage.ConsumeVerificationCode(ctx, key, "123456")
		require.Error(t, err, "the correct code must be rejected once the attempt limit is reached")

		err = storage.CreateVerificationCode(ctx, key, "654321")
		var rateLimited errs.RateLimited
		require.ErrorAs(t, err, &rateLimited, "a locked code must not be replaced before it expires")
	})

	t.Run("a locked code can be replaced once it expires", func(t *testing.T) {
		storage, _, clock := newOTPTestStorage(t)
		err := storage.CreateVerificationCode(ctx, key, "123456")
		require.NoError(t, err)
		for i := 0; i < otpMaxAttempts; i++ {
			require.Error(t, storage.ConsumeVerificationCode(ctx, key, "000000"))
		}

		clock.advance(otpLifetime)

		err = storage.CreateVerificationCode(ctx, key, "654321")
		require.NoError(t, err)
		require.NoError(t, storage.ConsumeVerificationCode(ctx, key, "654321"))
	})

	t.Run("resending is rate limited per address", func(t *testing.T) {
		storage, _, clock := newOTPTestStorage(t)
		err := storage.CreateVerificationCode(ctx, key, "123456")
		require.NoError(t, err)

		err = storage.CreateVerificationCode(ctx, key, "654321")
		var rateLimited errs.RateLimited
		require.ErrorAs(t, err, &rateLimited)

		err = storage.CreateVerificationCode(ctx, "other-key", "111111")
		require.NoError(t, err, "the limit applies per address")

		clock.advance(otpResendCooldown)
		err = storage.CreateVerificationCode(ctx, key, "654321")
		require.NoError(t, err)

		require.Error(t, storage.ConsumeVerificationCode(ctx, key, "123456"), "the replaced code must no longer verify")
		require.NoError(t, storage.ConsumeVerificationCode(ctx, key, "654321"))
	})

	t.Run("a resend does not extend the attempt budget during the cooldown", func(t *testing.T) {
		storage, _, _ := newOTPTestStorage(t)
		err := storage.CreateVerificationCode(ctx, key, "123456")
		require.NoError(t, err)
		require.Error(t, storage.ConsumeVerificationCode(ctx, key, "000000"))

		err = storage.CreateVerificationCode(ctx, key, "654321")
		require.Error(t, err)
	})

	t.Run("failed attempts carry over to a resent code", func(t *testing.T) {
		storage, _, clock := newOTPTestStorage(t)
		err := storage.CreateVerificationCode(ctx, key, "123456")
		require.NoError(t, err)
		for i := 0; i < otpMaxAttempts-1; i++ {
			require.Error(t, storage.ConsumeVerificationCode(ctx, key, "000000"))
		}

		clock.advance(otpResendCooldown)
		err = storage.CreateVerificationCode(ctx, key, "654321")
		require.NoError(t, err)
		require.Error(t, storage.ConsumeVerificationCode(ctx, key, "000000"))

		require.Error(t, storage.ConsumeVerificationCode(ctx, key, "654321"),
			"resending must not reset the attempt budget")
		err = storage.CreateVerificationCode(ctx, key, "111111")
		var rateLimited errs.RateLimited
		require.ErrorAs(t, err, &rateLimited)
	})

	t.Run("a correct code is not accepted if another attempt lands before it is consumed", func(t *testing.T) {
		storage, kv, _ := newOTPTestStorage(t)
		err := storage.CreateVerificationCode(ctx, key, "123456")
		require.NoError(t, err)
		storage.kvStore[constants.KVBucketNameAutheliaEmailOTP] = &interleavingConsumeKV{fakeOTPKV: kv}

		err = storage.ConsumeVerificationCode(ctx, key, "123456")
		var conflict errs.Conflict
		require.ErrorAs(t, err, &conflict)

		storage.kvStore[constants.KVBucketNameAutheliaEmailOTP] = kv
		require.NoError(t, storage.ConsumeVerificationCode(ctx, key, "123456"),
			"the code must not be consumed by the losing request")
	})

	t.Run("a resend right after a successful verification is still rate limited", func(t *testing.T) {
		storage, _, clock := newOTPTestStorage(t)
		err := storage.CreateVerificationCode(ctx, key, "123456")
		require.NoError(t, err)
		require.NoError(t, storage.ConsumeVerificationCode(ctx, key, "123456"))

		err = storage.CreateVerificationCode(ctx, key, "654321")
		var rateLimited errs.RateLimited
		require.ErrorAs(t, err, &rateLimited)

		clock.advance(otpResendCooldown)
		err = storage.CreateVerificationCode(ctx, key, "654321")
		require.NoError(t, err)
		require.NoError(t, storage.ConsumeVerificationCode(ctx, key, "654321"))
	})

	t.Run("KV failures are not reported as conflicts and do not leak details", func(t *testing.T) {
		storage, kv, _ := newOTPTestStorage(t)
		err := storage.CreateVerificationCode(ctx, key, "123456")
		require.NoError(t, err)
		kv.writeErr = errors.New("nats: internal detail")

		err = storage.ConsumeVerificationCode(ctx, key, "123456")
		var unexpected errs.Unexpected
		require.ErrorAs(t, err, &unexpected)
		assert.NotContains(t, err.Error(), "internal detail")
	})

	t.Run("an expired code is rejected", func(t *testing.T) {
		storage, kv, clock := newOTPTestStorage(t)
		err := storage.CreateVerificationCode(ctx, key, "123456")
		require.NoError(t, err)

		clock.advance(otpLifetime)

		err = storage.ConsumeVerificationCode(ctx, key, "123456")
		var notFound errs.NotFound
		require.ErrorAs(t, err, &notFound)
		_, stillStored := kv.values[key]
		assert.False(t, stillStored, "an expired code is cleaned up")
		assert.Zero(t, kv.unconditionalDeletes, "the cleanup delete must be revision-checked")
	})

	t.Run("expiry is not extended by failed attempts", func(t *testing.T) {
		storage, _, clock := newOTPTestStorage(t)
		err := storage.CreateVerificationCode(ctx, key, "123456")
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

		err = storage.CreateVerificationCode(ctx, key, "654321")
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

		err := storage.CreateVerificationCode(ctx, key, "123456")
		var conflict errs.Conflict
		require.ErrorAs(t, err, &conflict)
	})

	t.Run("a guess is not compared unless its attempt was recorded", func(t *testing.T) {
		storage, kv, _ := newOTPTestStorage(t)
		err := storage.CreateVerificationCode(ctx, key, "123456")
		require.NoError(t, err)
		storage.kvStore[constants.KVBucketNameAutheliaEmailOTP] = &staleRevisionKV{fakeOTPKV: kv}

		err = storage.ConsumeVerificationCode(ctx, key, "123456")
		var conflict errs.Conflict
		require.ErrorAs(t, err, &conflict, "a correct code must not be accepted without recording the attempt")
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

// interleavingConsumeKV simulates another attempt being recorded between the
// attempt reservation (the first update) and the consuming update.
type interleavingConsumeKV struct {
	*fakeOTPKV

	updates int
}

func (i *interleavingConsumeKV) Update(ctx context.Context, key string, value []byte, revision uint64) (uint64, error) {
	i.updates++
	if i.updates == 2 {
		i.write(key, i.values[key])
	}
	return i.fakeOTPKV.Update(ctx, key, value, revision)
}

func TestValidateEmailOTPBucketTTL(t *testing.T) {
	ctx := context.Background()
	for _, tt := range []struct {
		name    string
		ttl     time.Duration
		wantErr bool
	}{
		{name: "no expiry", ttl: 0},
		{name: "equal to the code lifetime", ttl: otpLifetime},
		{name: "longer than the code lifetime", ttl: time.Hour},
		{name: "shorter than the code lifetime", ttl: 30 * time.Second, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			kv := newFakeOTPKV(t)
			kv.ttl = tt.ttl
			err := validateEmailOTPBucketTTL(ctx, kv)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

type failingEmailFlow struct{}

func (failingEmailFlow) SendEmail(context.Context, string, string) error {
	return errors.New("smtp unavailable")
}

func (failingEmailFlow) LoginWithEmail(context.Context) error { return nil }

func TestUserReaderWriter_SendVerificationAlternateEmail_FailedSendKeepsAttempts(t *testing.T) {
	ctx := context.Background()
	storage, _, clock := newOTPTestStorage(t)
	rw := &userReaderWriter{storage: storage, emailLinkingFlow: failingEmailFlow{}}
	const address = "someone@example.com"
	key := (&model.User{}).BuildAlternateEmailIndexKey(ctx, address)

	require.NoError(t, storage.CreateVerificationCode(ctx, key, "123456"))
	for i := 0; i < otpMaxAttempts-1; i++ {
		require.Error(t, storage.ConsumeVerificationCode(ctx, key, "000000"))
	}
	clock.advance(otpResendCooldown)

	require.Error(t, rw.SendVerificationAlternateEmail(ctx, address))

	require.Error(t, storage.ConsumeVerificationCode(ctx, key, "000000"))
	err := storage.CreateVerificationCode(ctx, key, "654321")
	var rateLimited errs.RateLimited
	require.ErrorAs(t, err, &rateLimited, "a failed send must not reset the attempt count")
}
