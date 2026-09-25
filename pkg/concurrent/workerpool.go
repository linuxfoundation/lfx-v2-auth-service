// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package concurrent

import (
	"context"

	"golang.org/x/sync/errgroup"
)

// WorkerPool represents a pool of workers that can process jobs concurrently
type WorkerPool struct {
	workerCount int
}

// Run executes all functions using errgroup with goroutine limiting
// Returns the first error encountered, and cancels remaining work
func (wp *WorkerPool) Run(ctx context.Context, functions ...func() error) error {
	if len(functions) == 0 {
		return nil
	}

	// Create errgroup with context
	g, groupCtx := errgroup.WithContext(ctx)

	// Set the limit of concurrent goroutines
	g.SetLimit(wp.workerCount)

	// Submit all functions to the errgroup
	for _, fn := range functions {
		fn := fn // capture loop variable
		g.Go(func() error {
			// Check if context was cancelled before starting
			select {
			case <-groupCtx.Done():
				return groupCtx.Err()
			default:
			}

			return fn()
		})
	}

	// Wait for all functions to complete and return first error
	return g.Wait()
}

// NewWorkerPool creates a new worker pool with the specified number of workers
func NewWorkerPool(workerCount int) *WorkerPool {
	if workerCount <= 0 {
		workerCount = 1
	}
	return &WorkerPool{
		workerCount: workerCount,
	}
}
