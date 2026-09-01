// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package backfill

import (
	"context"

	"golang.org/x/time/rate"

	errs "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
)

// DefaultRatePerMinute is the CDP call rate an out-of-band job uses when none
// is configured.
//
// Deliberately far below CDP's 200 req/min per-client ceiling, for two reasons.
// The ceiling is shared with US3 provisioning on the same M2M client, so a job
// that claimed all of it would starve the consumer it runs alongside. And the
// production load test's apparent headroom at 800 req/min is an artifact: CDP's
// limiter is in-memory across two pods, so the burst that looked clean was
// really two half-sized buckets, not spare budget. Raise this only against an
// agreed operating rate (T032).
const DefaultRatePerMinute = 50

// NewRatePacer paces CDP calls at a fixed rate per minute.
//
// Burst is one: the jobs have nothing to gain from bunching calls, and a smooth
// rate is what leaves room for the provisioning consumer sharing the budget.
func NewRatePacer(perMinute int) (Pacer, error) {
	if perMinute <= 0 {
		return nil, errs.NewValidation("a positive rate per minute is required")
	}
	return &ratePacer{
		limiter: rate.NewLimiter(rate.Limit(float64(perMinute)/60.0), 1),
	}, nil
}

type ratePacer struct {
	limiter *rate.Limiter
}

func (p *ratePacer) Wait(ctx context.Context) error {
	return p.limiter.Wait(ctx)
}

// NewNoopPacer returns a pacer that never waits. For dry runs and tests.
func NewNoopPacer() Pacer { return noopPacer{} }
