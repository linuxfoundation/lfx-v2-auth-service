// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package log

import (
	stderrors "errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
)

func TestLevelForError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected slog.Level
	}{
		{"nil", nil, slog.LevelInfo},
		{"validation", errors.NewValidation("bad input"), slog.LevelInfo},
		{"not found", errors.NewNotFound("missing"), slog.LevelInfo},
		{"conflict", errors.NewConflict("already exists"), slog.LevelWarn},
		{"unauthorized", errors.NewUnauthorized("bad credentials"), slog.LevelWarn},
		{"forbidden", errors.NewForbidden("mfa required"), slog.LevelWarn},
		{"unexpected", errors.NewUnexpected("boom"), slog.LevelError},
		{"service unavailable", errors.NewServiceUnavailable("down"), slog.LevelError},
		{"untyped", stderrors.New("boom"), slog.LevelError},
		{"wrapped not found", fmt.Errorf("resolving user: %w", errors.NewNotFound("missing")), slog.LevelInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LevelForError(tt.err); got != tt.expected {
				t.Errorf("LevelForError(%v) = %v, want %v", tt.err, got, tt.expected)
			}
		})
	}
}
