// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package provisioning

import (
	"context"
	"errors"
	"testing"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
)

// mockKV embeds the interface so only the two methods under test need a body;
// anything else the store started calling would panic loudly rather than pass.
type mockKV struct {
	jetstream.KeyValue

	value     string
	getErr    error
	deleteErr error
	puts      []string
	deletes   []string
}

func (m *mockKV) Get(context.Context, string) (jetstream.KeyValueEntry, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return mockKVEntry{value: m.value}, nil
}

func (m *mockKV) Put(_ context.Context, _ string, value []byte) (uint64, error) {
	m.puts = append(m.puts, string(value))
	return uint64(len(m.puts)), nil
}

func (m *mockKV) Delete(_ context.Context, key string, _ ...jetstream.KVDeleteOpt) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	m.deletes = append(m.deletes, key)
	return nil
}

type mockKVEntry struct {
	jetstream.KeyValueEntry

	value string
}

func (e mockKVEntry) Value() []byte { return []byte(e.value) }

func TestKVOffsetStore(t *testing.T) {
	ctx := context.Background()

	t.Run("a bucket is required", func(t *testing.T) {
		_, err := NewKVOffsetStore(nil)
		require.Error(t, err)
	})

	t.Run("an unset key reads as no offset, not as an error", func(t *testing.T) {
		store, err := NewKVOffsetStore(&mockKV{getErr: jetstream.ErrKeyNotFound})
		require.NoError(t, err)

		offset, err := store.Load(ctx)

		require.NoError(t, err, "a first run has nothing stored and must still start")
		assert.Empty(t, offset)
	})

	t.Run("a read failure is surfaced", func(t *testing.T) {
		store, err := NewKVOffsetStore(&mockKV{getErr: errors.New("bucket unavailable")})
		require.NoError(t, err)

		_, err = store.Load(ctx)

		require.Error(t, err, "resuming from nothing would replay the whole window")
	})

	t.Run("round-trips an offset", func(t *testing.T) {
		kv := &mockKV{value: "  o1  "}
		store, err := NewKVOffsetStore(kv)
		require.NoError(t, err)

		offset, err := store.Load(ctx)
		require.NoError(t, err)
		assert.Equal(t, "o1", offset)

		require.NoError(t, store.Save(ctx, "o2"))
		assert.Equal(t, []string{"o2"}, kv.puts)
	})

	t.Run("saving an empty offset does not write an empty value", func(t *testing.T) {
		kv := &mockKV{}
		store, err := NewKVOffsetStore(kv)
		require.NoError(t, err)

		require.NoError(t, store.Save(ctx, ""))

		assert.Empty(t, kv.puts, "an empty value would read back as a stored offset of nothing")
	})

	t.Run("clear deletes the key so the next start falls back to the window", func(t *testing.T) {
		kv := &mockKV{value: "stale"}
		store, err := NewKVOffsetStore(kv)
		require.NoError(t, err)

		require.NoError(t, store.Clear(ctx))

		assert.Equal(t, []string{constants.KVKeyProvisioningCursor}, kv.deletes)
		assert.Empty(t, kv.puts, "an expired offset cannot be retired by writing over it")
	})

	t.Run("clearing an absent key is not an error", func(t *testing.T) {
		store, err := NewKVOffsetStore(&mockKV{deleteErr: jetstream.ErrKeyNotFound})
		require.NoError(t, err)

		assert.NoError(t, store.Clear(ctx), "nothing stored is the state clear is asking for")
	})

	t.Run("a failed clear is surfaced", func(t *testing.T) {
		store, err := NewKVOffsetStore(&mockKV{deleteErr: errors.New("bucket unavailable")})
		require.NoError(t, err)

		assert.Error(t, store.Clear(ctx), "the caller must back off rather than reconnect onto the dead offset")
	})
}
