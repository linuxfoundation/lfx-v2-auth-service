// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package backfill

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
)

// testKV opens a scratch KV bucket on a real NATS server.
//
// The cursor is the sweep's only durable state, and the things that can go
// wrong with it — an unset key reading as a cold start, a value surviving a
// round trip — are properties of JetStream rather than of the code around it.
// A mock would assert the mock.
//
// Skips when no server is reachable, so the suite still runs in a bare
// environment; point NATS_TEST_URL at one to include it.
func testKV(t *testing.T) jetstream.KeyValue {
	t.Helper()

	url := os.Getenv("NATS_TEST_URL")
	if url == "" {
		url = nats.DefaultURL
	}

	conn, err := nats.Connect(url, nats.Timeout(2*time.Second))
	if err != nil {
		t.Skipf("no NATS server at %s: %v", url, err)
	}
	t.Cleanup(conn.Close)

	js, err := jetstream.New(conn)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bucket := "cdp-sweep-cursor-test"
	// Start from nothing so a previous run cannot make this one pass.
	_ = js.DeleteKeyValue(ctx, bucket)

	kv, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket:  bucket,
		History: 1,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_ = js.DeleteKeyValue(cleanupCtx, bucket)
	})

	return kv
}

func TestKVCursorStoreRequiresABucket(t *testing.T) {
	_, err := NewKVCursorStore(nil)
	require.Error(t, err, "a nil bucket must fail here, not on the first save")
}

func TestKVCursorStoreReadsAnUnsetKeyAsAColdStart(t *testing.T) {
	// The sweep tells a cold start from a resumed run by the zero timestamp,
	// so an absent key must not surface as an error — that would turn a first
	// run into a failed one.
	store, err := NewKVCursorStore(testKV(t))
	require.NoError(t, err)

	cursor, err := store.Load(context.Background())
	require.NoError(t, err)
	assert.True(t, cursor.LastUpdatedAt.IsZero())
}

func TestKVCursorStoreRoundTripsThroughRealJetStream(t *testing.T) {
	store, err := NewKVCursorStore(testKV(t))
	require.NoError(t, err)
	ctx := context.Background()

	at := time.Date(2026, 8, 20, 10, 30, 0, 0, time.UTC)
	saved := Cursor{
		LastUpdatedAt:       at,
		LastProcessedUserID: "auth0|abc",
		RunStats:            RunStats{Scanned: 7, Found: 3, NoMatch: 3, Conflicted: 1},
	}
	require.NoError(t, store.Save(ctx, saved))

	loaded, err := store.Load(ctx)
	require.NoError(t, err)

	assert.True(t, loaded.LastUpdatedAt.Equal(at),
		"the cursor must survive the round trip exactly; a shifted boundary skips or repeats users")
	assert.Equal(t, "auth0|abc", loaded.LastProcessedUserID)
	assert.Equal(t, 7, loaded.RunStats.Scanned)
	assert.Equal(t, 1, loaded.RunStats.Conflicted)
}

func TestKVCursorStoreRefusesToRecordAZeroPosition(t *testing.T) {
	// Saving a zero cursor would read back as a cold start on the next run and
	// re-scan the cohort from the configured start.
	kv := testKV(t)
	store, err := NewKVCursorStore(kv)
	require.NoError(t, err)
	ctx := context.Background()

	at := time.Date(2026, 8, 20, 10, 30, 0, 0, time.UTC)
	require.NoError(t, store.Save(ctx, Cursor{LastUpdatedAt: at}))
	require.NoError(t, store.Save(ctx, Cursor{}))

	loaded, err := store.Load(ctx)
	require.NoError(t, err)
	assert.True(t, loaded.LastUpdatedAt.Equal(at),
		"a run that processed nothing must leave the stored position alone")
}

func TestKVCursorStoreReportsAnUnreadableRecord(t *testing.T) {
	// Silently restarting from the configured start would re-scan the whole
	// cohort. An operator should choose that rather than discover it.
	kv := testKV(t)
	ctx := context.Background()

	_, err := kv.Put(ctx, constants.KVKeySweepCursor, []byte("not json"))
	require.NoError(t, err)

	store, err := NewKVCursorStore(kv)
	require.NoError(t, err)

	_, err = store.Load(ctx)
	require.Error(t, err)
}
