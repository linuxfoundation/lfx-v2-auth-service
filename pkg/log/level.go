// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package log

import (
	stderrors "errors"
	"log/slog"

	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
)

// LevelForError maps a typed domain error to the level convention documented in
// .knowledge/v2/how-development/service-logging-and-observability.md, so error is
// reserved for genuine service faults and Datadog does not alert on expected traffic.
//
//	not-found / validation  -> info  (expected control flow)
//	conflict                -> warn  (caller-visible, recoverable)
//	unauthorized/forbidden  -> warn  (expected; stays visible for probing detection)
//	everything else         -> error (genuine fault)
func LevelForError(err error) slog.Level {
	if err == nil {
		return slog.LevelInfo
	}

	var (
		validation   errors.Validation
		notFound     errors.NotFound
		conflict     errors.Conflict
		unauthorized errors.Unauthorized
		forbidden    errors.Forbidden
	)

	switch {
	case stderrors.As(err, &validation), stderrors.As(err, &notFound):
		return slog.LevelInfo
	case stderrors.As(err, &conflict), stderrors.As(err, &unauthorized), stderrors.As(err, &forbidden):
		return slog.LevelWarn
	default:
		return slog.LevelError
	}
}
