// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package port

import "context"

// EventPublisher publishes domain events to a messaging system.
type EventPublisher interface {
	Publish(ctx context.Context, subject string, data []byte) error
}

// ConfirmedEventPublisher publishes an event and returns only once the
// messaging server has confirmed it received the message. Use it where the
// caller records that the event was sent and must not do so for a message that
// is still buffered in the client.
type ConfirmedEventPublisher interface {
	PublishConfirmed(ctx context.Context, subject string, data []byte) error
}
