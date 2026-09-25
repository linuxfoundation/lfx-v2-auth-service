// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package port

import "context"

// Orchestrator defines the behavior of the orchestrator which is responsible
// for syncing users within the environment
type UserOrchestrator interface {
	Get(ctx context.Context, kind string, key any) (any, error)
	Update(ctx context.Context, kind string, data ...any) error
}
