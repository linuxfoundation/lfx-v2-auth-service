// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package provisioning

import (
	"context"
	"errors"
	"strings"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	errs "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
)

// OffsetStore remembers how far the consumer has read into the Auth0 events
// stream.
//
// Auth0 has no server-side acknowledgement — the position is entirely ours to
// keep, and losing it costs a replay bounded by the configured window.
type OffsetStore interface {
	// Load returns the stored offset, or an empty string when none is stored.
	Load(ctx context.Context) (string, error)

	// Save records the offset. It is called for every message, including the
	// position markers that carry no event.
	Save(ctx context.Context, offset string) error
}

type kvOffsetStore struct {
	kv jetstream.KeyValue
}

// NewKVOffsetStore stores the offset in a NATS key-value bucket.
func NewKVOffsetStore(kv jetstream.KeyValue) (OffsetStore, error) {
	if kv == nil {
		return nil, errs.NewValidation("a key-value bucket is required")
	}
	return &kvOffsetStore{kv: kv}, nil
}

func (s *kvOffsetStore) Load(ctx context.Context) (string, error) {
	entry, err := s.kv.Get(ctx, constants.KVKeyProvisioningCursor)
	if err != nil {
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(entry.Value())), nil
}

func (s *kvOffsetStore) Save(ctx context.Context, offset string) error {
	if strings.TrimSpace(offset) == "" {
		return nil
	}
	_, err := s.kv.Put(ctx, constants.KVKeyProvisioningCursor, []byte(offset))
	return err
}
