// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	authservice "github.com/linuxfoundation/lfx-v2-auth-service/gen/auth_service"
	authserver "github.com/linuxfoundation/lfx-v2-auth-service/gen/http/auth_service/server"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"goa.design/clue/debug"
	goahttp "goa.design/goa/v3/http"
)

// handleHTTPServer starts the HTTP server for health check endpoints
func handleHTTPServer(ctx context.Context, host string, authEndpoints *authservice.Endpoints, wg *sync.WaitGroup, errc chan<- error, dbg bool) {

	// Provide the transport specific request decoder and response encoder.
	// The goa http package has built-in support for JSON, XML and gob.
	// Other encodings can be used by providing the corresponding functions,
	// see goa.design/implement/encoding.
	var (
		dec = goahttp.RequestDecoder
		enc = goahttp.ResponseEncoder
	)

	// Build the service HTTP request multiplexer and mount debug and profiler
	// endpoints in debug mode.
	var mux goahttp.Muxer
	{
		mux = goahttp.NewMuxer()
		if dbg {
			// Mount pprof handlers for memory profiling under /debug/pprof.
			debug.MountPprofHandlers(debug.Adapt(mux))
			// Mount /debug endpoint to enable or disable debug logs at runtime.
			debug.MountDebugLogEnabler(debug.Adapt(mux))
		}
	}

	// Wrap the endpoints with the transport specific layers
	var (
		authServer *authserver.Server
	)
	{
		eh := errorHandler(ctx)
		authServer = authserver.New(authEndpoints, mux, dec, enc, eh, nil)
	}
	// Configure the mux.
	authserver.Mount(mux, authServer)

	// Wrap the multiplexer with additional middlewares. Middlewares mounted
	// here apply to all the service endpoints.
	var handler http.Handler = mux
	if dbg {
		// Log query and response bodies if debug logs are enabled.
		handler = debug.HTTP()(handler)
	}
	// Wrap the handler with OpenTelemetry instrumentation
	handler = otelhttp.NewHandler(handler, "auth-service",
		otelhttp.WithFilter(func(r *http.Request) bool {
			p := r.URL.Path
			return p != authserver.LivezAuthServicePath() && p != authserver.ReadyzAuthServicePath()
		}),
	)

	// Start HTTP server using default configuration, change the code to
	// configure the server as required by your service.
	srv := &http.Server{Addr: host, Handler: handler, ReadHeaderTimeout: time.Second * 60}
	for _, m := range authServer.Mounts {
		slog.InfoContext(ctx, "HTTP endpoint mounted",
			"method", m.Method,
			"verb", m.Verb,
			"pattern", m.Pattern,
		)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()

		go func() {
			<-ctx.Done()
			slog.InfoContext(ctx, "shutting down HTTP server", "host", host)

			// Shutdown gracefully with a 30 second timeout.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			if err := srv.Shutdown(ctx); err != nil {
				slog.ErrorContext(ctx, "HTTP server shutdown error", "error", err)
			}
		}()

		slog.InfoContext(ctx, "HTTP server listening", "host", host)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			errc <- err
		}
	}()
}

// errorHandler returns a function that writes and logs the given error.
// The function also writes and logs the error unique ID so that it's possible
// to correlate.
func errorHandler(logCtx context.Context) func(context.Context, http.ResponseWriter, error) {
	return func(ctx context.Context, w http.ResponseWriter, err error) {
		slog.ErrorContext(logCtx, "HTTP error occurred", "error", err)
	}
}
