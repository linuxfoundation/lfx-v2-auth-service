// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package concurrent

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkerPool_Run(t *testing.T) {
	ctx := context.Background()
	pool := NewWorkerPool(2)

	var counter int64
	functions := []func() error{
		func() error {
			atomic.AddInt64(&counter, 1)
			time.Sleep(10 * time.Millisecond) // Simulate work
			return nil
		},
		func() error {
			atomic.AddInt64(&counter, 2)
			time.Sleep(10 * time.Millisecond)
			return nil
		},
		func() error {
			atomic.AddInt64(&counter, 3)
			time.Sleep(10 * time.Millisecond)
			return nil
		},
	}

	err := pool.Run(ctx, functions...)
	require.NoError(t, err)
	assert.Equal(t, int64(6), atomic.LoadInt64(&counter))
}

func TestWorkerPool_Run_WithError(t *testing.T) {
	ctx := context.Background()
	pool := NewWorkerPool(2)

	expectedError := errors.New("job failed")
	functions := []func() error{
		func() error {
			time.Sleep(10 * time.Millisecond)
			return nil
		},
		func() error {
			time.Sleep(5 * time.Millisecond)
			return expectedError
		},
		func() error {
			time.Sleep(20 * time.Millisecond)
			return nil
		},
	}

	err := pool.Run(ctx, functions...)
	require.Error(t, err)
	assert.Equal(t, expectedError, err)
}

func TestWorkerPool_Run_EmptyFunctions(t *testing.T) {
	ctx := context.Background()
	pool := NewWorkerPool(2)

	err := pool.Run(ctx)
	require.NoError(t, err)
}

func TestWorkerPool_Run_WithCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pool := NewWorkerPool(2)

	// Cancel context immediately
	cancel()

	functions := []func() error{
		func() error {
			return nil
		},
	}

	err := pool.Run(ctx, functions...)
	require.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}
