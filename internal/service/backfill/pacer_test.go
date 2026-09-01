// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package backfill

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRatePacerRejectsANonPositiveRate(t *testing.T) {
	// A zero rate would block the first call forever, which looks like a hung
	// job rather than a misconfiguration.
	for _, perMinute := range []int{0, -1} {
		_, err := NewRatePacer(perMinute)
		require.Error(t, err, "rate %d must be refused at construction", perMinute)
	}
}

func TestRatePacerAllowsTheFirstCallImmediately(t *testing.T) {
	pacer, err := NewRatePacer(DefaultRatePerMinute)
	require.NoError(t, err)

	start := time.Now()
	require.NoError(t, pacer.Wait(context.Background()))
	assert.Less(t, time.Since(start), 250*time.Millisecond,
		"burst of one means the first call does not wait out an interval")
}

func TestRatePacerSpacesSubsequentCalls(t *testing.T) {
	// 600/min is one call per 100ms, fast enough to assert on without making
	// the suite slow.
	pacer, err := NewRatePacer(600)
	require.NoError(t, err)

	require.NoError(t, pacer.Wait(context.Background()))
	start := time.Now()
	require.NoError(t, pacer.Wait(context.Background()))

	assert.GreaterOrEqual(t, time.Since(start), 50*time.Millisecond,
		"a second call must be spaced, or the job bunches against a shared budget")
}

func TestRatePacerStopsWaitingWhenTheContextIsCancelled(t *testing.T) {
	// One call per minute: the second would wait far past the deadline.
	pacer, err := NewRatePacer(1)
	require.NoError(t, err)
	require.NoError(t, pacer.Wait(context.Background()))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err = pacer.Wait(ctx)
	require.Error(t, err, "a cancelled run must not sit in the limiter")
}

func TestNoopPacerNeverWaits(t *testing.T) {
	start := time.Now()
	for i := 0; i < 100; i++ {
		require.NoError(t, NewNoopPacer().Wait(context.Background()))
	}
	assert.Less(t, time.Since(start), 100*time.Millisecond)
}
