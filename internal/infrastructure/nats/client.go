// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package nats

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// NATSClient wraps the NATS connection and provides access control operations
type NATSClient struct {
	conn    *nats.Conn
	config  Config
	kvStore map[string]jetstream.KeyValue
	timeout time.Duration
}

// NATSClientInterface defines the interface for NATS operations
// This allows for easy mocking and testing
type NATSClientInterface interface {
	Close() error
	IsReady(ctx context.Context) error
}

// Close gracefully closes the NATS connection
func (c *NATSClient) Close() error {
	if c.conn != nil {
		c.conn.Close()
	}
	return nil
}

// IsReady checks if the NATS client is ready
func (c *NATSClient) IsReady(ctx context.Context) error {
	if c.conn == nil {
		return errors.NewServiceUnavailable("NATS client is not initialized or not connected")
	}
	if !c.conn.IsConnected() || c.conn.IsDraining() {
		return errors.NewServiceUnavailable("NATS client is not ready, connection is not established or is draining")
	}
	return nil
}

// KeyValueStore creates a JetStream client and gets the key-value store for projects.
func (c *NATSClient) KeyValueStore(ctx context.Context, bucketName string) error {
	js, err := jetstream.New(c.conn)
	if err != nil {
		slog.ErrorContext(ctx, "error creating NATS JetStream client",
			"error", err,
			"nats_url", c.conn.ConnectedUrl(),
		)
		return err
	}
	kvStore, err := js.KeyValue(ctx, bucketName)
	if err != nil {
		slog.ErrorContext(ctx, "error getting NATS JetStream key-value store",
			"error", err,
			"nats_url", c.conn.ConnectedUrl(),
			"bucket", bucketName,
		)
		return err
	}

	if c.kvStore == nil {
		c.kvStore = make(map[string]jetstream.KeyValue)
	}
	c.kvStore[bucketName] = kvStore
	return nil
}

// GetKVStore returns the KV store for a given bucket name
func (c *NATSClient) GetKVStore(bucketName string) (jetstream.KeyValue, bool) {
	if c.kvStore == nil {
		return nil, false
	}
	kvStore, exists := c.kvStore[bucketName]
	return kvStore, exists
}

// Publish publishes a message to a NATS subject. Used for fire-and-forget
// domain events (not request/reply).
func (c *NATSClient) Publish(ctx context.Context, subject string, data []byte) error {
	if err := c.IsReady(ctx); err != nil {
		return err
	}
	return c.conn.Publish(subject, data)
}

// SubscribeWithTransportMessenger subscribes to a subject with proper TransportMessenger handling
func (c *NATSClient) SubscribeWithTransportMessenger(ctx context.Context, subject string, queueName string, handler func(context.Context, port.TransportMessenger)) (*nats.Subscription, error) {

	if err := c.IsReady(ctx); err != nil {
		return nil, err
	}

	return c.conn.QueueSubscribe(subject, queueName, func(msg *nats.Msg) {
		transportMsg := NewTransportMessenger(msg)

		defer func() {
			if r := recover(); r != nil {
				slog.ErrorContext(ctx, "panic in NATS handler",
					"subject", subject,
					"queue", queueName,
					"panic", r,
				)
			}
		}()

		handler(ctx, transportMsg)
	})
}

// NewClient creates a new NATS client with the given configuration
func NewClient(ctx context.Context, config Config) (*NATSClient, error) {
	slog.InfoContext(ctx, "creating NATS client",
		"url", config.URL,
		"timeout", config.Timeout,
	)

	// Validate configuration
	if config.URL == "" {
		return nil, errors.NewUnexpected("NATS URL is required")
	}

	// Configure NATS connection options
	opts := []nats.Option{
		nats.Name(constants.ServiceName),
		nats.Timeout(config.Timeout),
		nats.MaxReconnects(config.MaxReconnect),
		nats.ReconnectWait(config.ReconnectWait),
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			slog.WarnContext(ctx, "NATS disconnected", "error", err)
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			slog.InfoContext(ctx, "NATS reconnected", "url", nc.ConnectedUrl())
		}),
		nats.ErrorHandler(func(_ *nats.Conn, s *nats.Subscription, err error) {
			if s != nil {
				slog.With("error", err, "subject", s.Subject, "queue", s.Queue).Error("async NATS error")
			} else {
				slog.With("error", err).Error("async NATS error outside subscription")
			}
		}),
		nats.ClosedHandler(func(nc *nats.Conn) {
			slog.InfoContext(ctx, "NATS connection closed")
		}),
	}

	// Establish connection
	conn, err := nats.Connect(config.URL, opts...)
	if err != nil {
		return nil, errors.NewServiceUnavailable("failed to connect to NATS", err)
	}

	client := &NATSClient{
		conn:    conn,
		config:  config,
		timeout: config.Timeout,
	}

	// The username→sub cache bucket is best-effort: if it doesn't exist or is
	// unavailable the service still works, just without caching.
	if err := client.KeyValueStore(ctx, constants.KVBucketNameUsernameSubCache); err != nil {
		slog.WarnContext(ctx, "username→sub cache bucket unavailable, caching disabled",
			"error", err,
			"bucket", constants.KVBucketNameUsernameSubCache,
		)
	} else {
		slog.InfoContext(ctx, "NATS key-value store initialized",
			"bucket", constants.KVBucketNameUsernameSubCache,
		)
	}

	// Authelia-specific buckets are required when Authelia is the user repository.
	if os.Getenv(constants.UserRepositoryTypeEnvKey) == constants.UserRepositoryTypeAuthelia {
		for _, bucketName := range []string{constants.KVBucketNameAutheliaUsers, constants.KVBucketNameAutheliaEmailOTP} {
			if err := client.KeyValueStore(ctx, bucketName); err != nil {
				slog.ErrorContext(ctx, "failed to initialize NATS key-value store",
					"error", err,
					"bucket", bucketName,
				)
				return nil, errors.NewServiceUnavailable("failed to initialize NATS key-value store", err)
			}
			slog.InfoContext(ctx, "NATS key-value store initialized",
				"bucket", bucketName,
			)
		}
	}

	slog.InfoContext(ctx, "NATS client created successfully",
		"connected_url", conn.ConnectedUrl(),
		"status", conn.Status(),
	)

	return client, nil
}
