// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/linuxfoundation/lfx-v2-auth-service/cmd/server/service"

	authservice "github.com/linuxfoundation/lfx-v2-auth-service/gen/auth_service"
	logging "github.com/linuxfoundation/lfx-v2-auth-service/pkg/log"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/utils"
)

// Build-time variables set via ldflags
var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

const (
	defaultPort = "8080"
	// gracefulShutdownSeconds should be higher than NATS client
	// request timeout, and lower than the pod or liveness probe's
	// terminationGracePeriodSeconds.
	gracefulShutdownSeconds = 25
)

func init() {
	// slog is the standard library logger, we use it to log errors and
	logging.InitStructureLogConfig()
}

func main() {
	// Define command line flags
	var (
		dbgF = flag.Bool("d", false, "enable debug logging")
		port = flag.String("p", defaultPort, "listen port")
		bind = flag.String("bind", "*", "interface to bind on")
	)
	flag.Usage = func() {
		flag.PrintDefaults()
		os.Exit(2)
	}
	flag.Parse()

	ctx := context.Background()

	// Set up OpenTelemetry SDK.
	// Command-line/environment OTEL_SERVICE_VERSION takes precedence over
	// the build-time Version variable.
	otelConfig := utils.OTelConfigFromEnv()
	if otelConfig.ServiceVersion == "" {
		otelConfig.ServiceVersion = Version
	}
	otelShutdown, err := utils.SetupOTelSDKWithConfig(ctx, otelConfig)
	if err != nil {
		slog.ErrorContext(ctx, "error setting up OpenTelemetry SDK", "error", err)
		os.Exit(1)
	}
	// Handle shutdown properly so nothing leaks.
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), gracefulShutdownSeconds*time.Second)
		defer cancel()
		if shutdownErr := otelShutdown(shutdownCtx); shutdownErr != nil {
			slog.ErrorContext(ctx, "error shutting down OpenTelemetry SDK", "error", shutdownErr)
		}
	}()

	slog.InfoContext(ctx, "Starting auth service",
		"bind", *bind,
		"http-port", *port,
		"graceful-shutdown-seconds", gracefulShutdownSeconds,
	)

	// Initialize the health service
	authSvc := service.NewAuthService()

	// Wrap the service in endpoints
	authEndpoints := authservice.NewEndpoints(authSvc)

	// Create channel for shutdown signals
	errc := make(chan error, 1)

	// Setup interrupt handler
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errc <- fmt.Errorf("%s", <-c)
	}()

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(ctx)

	// Start the HTTP server for health checks
	addr := ":" + *port
	if *bind != "*" {
		addr = *bind + ":" + *port
	}

	handleHTTPServer(ctx, addr, authEndpoints, &wg, errc, *dbgF)

	// Start NATS subscriptions
	if err := service.QueueSubscriptions(ctx); err != nil {
		slog.ErrorContext(ctx, "failed to start NATS subscriptions", "error", err)
		errc <- fmt.Errorf("failed to start NATS subscriptions: %w", err)
	}

	// Wait for signal
	slog.InfoContext(ctx, "received shutdown signal, stopping servers",
		"signal", <-errc,
	)

	// Send cancellation signal to the goroutines
	cancel()

	// Create a timeout context for graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), gracefulShutdownSeconds*time.Second)
	defer shutdownCancel()

	// Wait for all goroutines to finish with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		slog.InfoContext(ctx, "graceful shutdown completed")
	case <-shutdownCtx.Done():
		slog.WarnContext(ctx, "graceful shutdown timed out")
	}

	slog.InfoContext(ctx, "exited")
}
