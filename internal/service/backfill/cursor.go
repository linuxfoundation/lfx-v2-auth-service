// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

// Package backfill holds the out-of-band CDP jobs: the full-cohort population
// sweep and the no-match re-check.
//
// Both resolve against live CDP and write through the shared Auth0 metadata
// writer, so a value they store cannot differ from one the login path would
// have stored. Neither reads a data warehouse.
package backfill

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	errs "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
)

// Cursor is the population sweep's persisted progress.
//
// There is exactly one of these in the feature and it belongs to the sweep. The
// no-match re-check re-derives its population from marker presence on every
// run and stores nothing, which is what makes a merged user reappear without
// anything having to remember them.
type Cursor struct {
	// LastUpdatedAt is the INCLUSIVE lower bound for the next search.
	//
	// Inclusive is load-bearing. Auth0 sorts on a single field, so order among
	// users sharing a timestamp is not stable; advancing even a millisecond
	// past the boundary would permanently skip anyone sharing it who was not
	// on the page. Re-scanning the boundary is cheap because the cohort query
	// excludes everyone already processed.
	LastUpdatedAt time.Time `json:"last_updated_at"`

	// LastProcessedUserID is a within-run tie-breaker for observability. It is
	// not the no-skip guarantee — the processed-marker exclusion is.
	LastProcessedUserID string `json:"last_processed_user_id,omitempty"`

	// RunStats is the most recent run's counts, kept alongside the position so
	// an operator reading the bucket sees both.
	RunStats RunStats `json:"run_stats"`
}

// CursorStore persists the sweep's position between runs.
type CursorStore interface {
	Load(ctx context.Context) (Cursor, error)
	Save(ctx context.Context, cursor Cursor) error
}

type kvCursorStore struct {
	kv jetstream.KeyValue
}

// NewKVCursorStore stores the sweep cursor in a NATS key-value bucket.
func NewKVCursorStore(kv jetstream.KeyValue) (CursorStore, error) {
	if kv == nil {
		return nil, errs.NewValidation("a key-value bucket is required")
	}
	return &kvCursorStore{kv: kv}, nil
}

// Load returns the stored cursor, or a zero cursor when none is stored.
//
// A zero cursor is how the caller recognises a cold start; it is not an error.
// Losing the bucket costs a re-scan from the configured start rather than lost
// users, because the cohort query excludes anyone already carrying a marker.
func (s *kvCursorStore) Load(ctx context.Context) (Cursor, error) {
	entry, err := s.kv.Get(ctx, constants.KVKeySweepCursor)
	if err != nil {
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			return Cursor{}, nil
		}
		return Cursor{}, err
	}

	var cursor Cursor
	if err := json.Unmarshal(entry.Value(), &cursor); err != nil {
		// A corrupt record is reported rather than silently reset: restarting
		// from the configured start would re-scan the whole cohort, and an
		// operator should choose that rather than discover it.
		return Cursor{}, errs.NewUnexpected("stored sweep cursor is not readable", err)
	}
	return cursor, nil
}

func (s *kvCursorStore) Save(ctx context.Context, cursor Cursor) error {
	if cursor.LastUpdatedAt.IsZero() {
		// Saving a zero position would look like a cold start on the next run
		// and re-scan the cohort. A run that processed nothing has nothing to
		// record.
		return nil
	}
	encoded, err := json.Marshal(cursor)
	if err != nil {
		return errs.NewUnexpected("failed to encode the sweep cursor", err)
	}
	_, err = s.kv.Put(ctx, constants.KVKeySweepCursor, encoded)
	return err
}
