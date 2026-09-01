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
// CDP allows 200 req/min per M2M client. These jobs authenticate as the
// auth-service, so they cannot starve the login Action — that is a different
// client — but they do share this budget with US3 provisioning. Measured
// 2026-09-01: provisioning's busiest day wrote 4,792 users at ~3.3/min, which
// at two to three CDP calls each is ~10 req/min and roughly 20 at burst. 150
// leaves that room and still stops well short of 200.
//
// Do NOT raise this toward the 800 req/min the production load test absorbed.
// CDP's limiter is in-memory across two pods, so that apparent headroom was two
// half-sized buckets rather than budget, and traffic landing unevenly on one
// pod would trip the real limit.
const DefaultRatePerMinute = 150

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
