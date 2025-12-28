// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package service

import (
	"context"
	"fmt"

	authservice "github.com/linuxfoundation/lfx-v2-auth-service/gen/auth_service"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/nats"
)

type authService struct {
	natsClient *nats.NATSClient
}

// Livez implements the liveness check endpoint
func (s *authService) Livez(ctx context.Context) ([]byte, error) {
	// Liveness check - should always return OK unless the service is completely dead
	return []byte("OK"), nil
}

// Readyz implements the readiness check endpoint
func (s *authService) Readyz(ctx context.Context) ([]byte, error) {
	// Check NATS connection status
	if s.natsClient != nil {
		if err := s.natsClient.IsReady(ctx); err != nil {
			return nil, fmt.Errorf("NATS not ready: %w", err)
		}
	}

	return []byte("OK"), nil
}

// NewAuthService creates a new auth service
func NewAuthService() authservice.Service {
	return &authService{
		natsClient: getNATSClient(),
	}
}
