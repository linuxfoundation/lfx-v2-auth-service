// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package holderwalk

import (
	"context"
	"errors"
	"log/slog"
	"time"

	lferrors "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
)

// Limiter paces CDP calls to a fixed per-minute rate. Every CDP call — resolve
// and identity read alike — takes one slot: the budget is per client, not per
// endpoint. Shared by both CDP repair commands.
type Limiter struct {
	interval time.Duration
	next     time.Time
}

// NewLimiter paces calls to perMinute per minute.
func NewLimiter(perMinute int) *Limiter {
	return &Limiter{interval: time.Minute / time.Duration(perMinute)}
}

// Wait blocks until the next slot opens.
func (l *Limiter) Wait(ctx context.Context) error {
	now := time.Now()
	if now.Before(l.next) {
		timer := time.NewTimer(l.next.Sub(now))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	l.next = time.Now().Add(l.interval)
	return nil
}

const cdpCallMaxAttempts = 5
const defaultRateLimitWait = time.Minute

// maxRateLimitWait caps a server Retry-After hint: a wrong or hostile header
// must not park a ~21h walk for hours per attempt.
const maxRateLimitWait = 5 * time.Minute

// BoundedRetryAfter converts a Retry-After hint into a bounded wait.
func BoundedRetryAfter(hint time.Duration) time.Duration {
	switch {
	case hint <= 0:
		return defaultRateLimitWait
	case hint > maxRateLimitWait:
		return maxRateLimitWait
	default:
		return hint
	}
}

// CallWithRateLimitRetry paces one CDP call and waits out bare 429s, giving
// up after cdpCallMaxAttempts. Any other error returns immediately.
func CallWithRateLimitRetry[T any](ctx context.Context, pace *Limiter, call func(context.Context) (T, error)) (T, error) {
	var zero T
	for attempt := 1; ; attempt++ {
		if err := pace.Wait(ctx); err != nil {
			return zero, err
		}

		result, err := call(ctx)
		if err == nil {
			return result, nil
		}

		var rateLimited lferrors.RateLimited
		if !errors.As(err, &rateLimited) || attempt >= cdpCallMaxAttempts {
			return zero, err
		}

		waitFor := BoundedRetryAfter(rateLimited.RetryAfter)
		slog.WarnContext(ctx, "CDP rate limited, waiting", "retry_after", waitFor.String(), "attempt", attempt)
		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case <-time.After(waitFor):
		}
	}
}
