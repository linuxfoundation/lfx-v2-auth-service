// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package middleware

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	goahttp "goa.design/goa/v3/http"
)

func decodeAccessLog(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()

	var record map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &record); err != nil {
		t.Fatalf("failed to decode log record %q: %v", buf.String(), err)
	}
	return record
}

func runAccessLog(t *testing.T, req *http.Request, next http.Handler) (map[string]any, *httptest.ResponseRecorder) {
	t.Helper()

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	rr := httptest.NewRecorder()
	AccessLogMiddleware()(next).ServeHTTP(rr, req)

	return decodeAccessLog(t, &buf), rr
}

func TestAccessLogMiddlewareLogsCompletedRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	req.Pattern = "GET /readyz"
	req.Header.Set("User-Agent", "test-agent/1.0")

	record, _ := runAccessLog(t, req, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))

	// Healthy probe is downgraded to DEBUG
	if record["level"] != "DEBUG" {
		t.Errorf("got level %v, want DEBUG", record["level"])
	}
	if record["verb"] != http.MethodGet {
		t.Errorf("got verb %v, want %v", record["verb"], http.MethodGet)
	}
	if record["pattern"] != "/readyz" {
		t.Errorf("got pattern %v, want /readyz", record["pattern"])
	}
	if record["path"] != "/readyz" {
		t.Errorf("got path %v, want /readyz", record["path"])
	}
	if status, ok := record["status"].(float64); !ok || int(status) != http.StatusOK {
		t.Errorf("got status %v, want %d", record["status"], http.StatusOK)
	}
	if record["user_agent"] != "test-agent/1.0" {
		t.Errorf("got user_agent %v, want test-agent/1.0", record["user_agent"])
	}
	if _, ok := record["duration_ms"].(float64); !ok {
		t.Errorf("expected numeric duration_ms, got %v", record["duration_ms"])
	}
	if bytesWritten, ok := record["bytes_written"].(float64); !ok || int(bytesWritten) != 2 {
		t.Errorf("got bytes_written %v, want 2", record["bytes_written"])
	}
}

// Registering on a real Goa muxer is what makes r.Pattern available; wrapping
// the muxer from outside silently yields "<unmatched>" for every request.
func TestAccessLogMiddlewareResolvesPatternFromGoaMuxer(t *testing.T) {
	mux := goahttp.NewMuxer()
	mux.Use(AccessLogMiddleware())
	mux.Handle(http.MethodGet, "/users/{email}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	req := httptest.NewRequest(http.MethodGet, "/users/johndoe@example.com", nil)
	mux.ServeHTTP(httptest.NewRecorder(), req)

	record := decodeAccessLog(t, &buf)
	if want := "/users/{email}"; record["pattern"] != want {
		t.Errorf("got pattern %v, want %q", record["pattern"], want)
	}
	if want := "/users/joh****@example.com"; record["path"] != want {
		t.Errorf("got path %v, want %q", record["path"], want)
	}
	if status, ok := record["status"].(float64); !ok || int(status) != http.StatusOK {
		t.Errorf("got status %v, want %d", record["status"], http.StatusOK)
	}
}

// An unrouted request must not put its concrete URL in pattern, otherwise
// scanning for arbitrary paths inflates route cardinality.
func TestAccessLogMiddlewareReportsUnmatchedRoute(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/definitely/not/a/route", nil)

	record, _ := runAccessLog(t, req, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	if record["pattern"] != unmatchedRoute {
		t.Errorf("got pattern %v, want %q", record["pattern"], unmatchedRoute)
	}
	// The path of an unmatched request is entirely caller-controlled, so it is
	// reported as the marker rather than persisted verbatim.
	if record["path"] != unmatchedRoute {
		t.Errorf("got path %v, want %q", record["path"], unmatchedRoute)
	}
	if record["level"] != "INFO" {
		t.Errorf("got level %v, want INFO", record["level"])
	}
}

func TestAccessLogMiddlewareDefaultsStatusToOK(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/livez", nil)

	record, _ := runAccessLog(t, req, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))

	if status, ok := record["status"].(float64); !ok || int(status) != http.StatusOK {
		t.Errorf("got status %v, want %d", record["status"], http.StatusOK)
	}
}

func TestAccessLogMiddlewareIncludesRequestID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/users/123", nil)
	req.Header.Set("X-Request-Id", "req-abc")

	record, _ := runAccessLog(t, req, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	if record["request_id"] != "req-abc" {
		t.Errorf("got request_id %v, want req-abc", record["request_id"])
	}
}

func TestAccessLogMiddlewareRedactsEmailInPath(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/users/johndoe@example.com", nil)
	req.Pattern = "GET /users/{email}"

	record, _ := runAccessLog(t, req, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	pattern, _ := record["path"].(string)
	if strings.Contains(pattern, "johndoe") {
		t.Errorf("path %q leaks the email local part", pattern)
	}
	if want := "/users/joh****@example.com"; pattern != want {
		t.Errorf("got path %q, want %q", pattern, want)
	}
}

// chi routes on the escaped path, so an address whose local part contains an
// encoded slash still reaches the {email} route. It must be redacted as one
// value rather than split across segments.
func TestAccessLogMiddlewareRedactsEncodedSlashEmail(t *testing.T) {
	mux := goahttp.NewMuxer()
	mux.Use(AccessLogMiddleware())
	mux.Handle(http.MethodGet, "/users/{email}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	req := httptest.NewRequest(http.MethodGet, "/users/john%2Fdoe%40example.com", nil)
	mux.ServeHTTP(httptest.NewRecorder(), req)

	record := decodeAccessLog(t, &buf)
	path, _ := record["path"].(string)
	for _, leak := range []string{"john/doe", "john%2Fdoe", "johndoe"} {
		if strings.Contains(path, leak) {
			t.Errorf("path %q leaks %q", path, leak)
		}
	}
	if want := "/users/joh****@example.com"; path != want {
		t.Errorf("got path %q, want %q", path, want)
	}
}

func TestAccessLogMiddlewareLogsHealthProbesAtDebug(t *testing.T) {
	for _, path := range []string{"/livez", "/readyz"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)

			record, _ := runAccessLog(t, req, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))

			if record["level"] != "DEBUG" {
				t.Errorf("got level %v, want DEBUG", record["level"])
			}
		})
	}
}

// A 5xx failing probe is a server/readiness incident and is logged at ERROR.
// A 4xx probe (e.g. 404/429) stays visible at INFO.
func TestAccessLogMiddlewareLogsFailedHealthProbes(t *testing.T) {
	tests := []struct {
		status    int
		wantLevel string
	}{
		{http.StatusServiceUnavailable, "ERROR"},
		{http.StatusInternalServerError, "ERROR"},
		{http.StatusNotFound, "INFO"},
		{http.StatusTooManyRequests, "INFO"},
	}

	for _, tt := range tests {
		t.Run(http.StatusText(tt.status), func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/readyz", nil)

			record, _ := runAccessLog(t, req, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
			}))

			if record["level"] != tt.wantLevel {
				t.Errorf("got level %v, want %s", record["level"], tt.wantLevel)
			}
			if got, ok := record["status"].(float64); !ok || int(got) != tt.status {
				t.Errorf("got status %v, want %d", record["status"], tt.status)
			}
		})
	}
}

func TestAccessLogMiddlewareFlushCommitsImplicitOK(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/stream", nil)
	req.Pattern = "GET /stream"

	record, _ := runAccessLog(t, req, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Attempting WriteHeader after flush should not change the recorded 200 OK
		w.WriteHeader(http.StatusInternalServerError)
	}))

	if status, ok := record["status"].(float64); !ok || int(status) != http.StatusOK {
		t.Errorf("got status %v, want %d", record["status"], http.StatusOK)
	}
}

func TestAccessLogMiddlewareLogsPanicAsServerError(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "panic before writing",
			handler: func(_ http.ResponseWriter, _ *http.Request) {
				panic("boom")
			},
		},
		{
			// The status was already written, but net/http abandons the
			// response, so recording 200 would report a false success.
			name: "panic after writing a success status",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("partial"))
				panic("boom")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/livez", nil)

			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
			t.Cleanup(func() { slog.SetDefault(prev) })

			handler := AccessLogMiddleware()(tc.handler)

			func() {
				defer func() {
					if recover() == nil {
						t.Error("expected the panic to propagate to the server")
					}
				}()
				handler.ServeHTTP(httptest.NewRecorder(), req)
			}()

			record := decodeAccessLog(t, &buf)
			if status, ok := record["status"].(float64); !ok || int(status) != http.StatusInternalServerError {
				t.Errorf("got status %v, want %d", record["status"], http.StatusInternalServerError)
			}
			if record["panic"] != true {
				t.Errorf("got panic %v, want true", record["panic"])
			}
			if record["level"] != "ERROR" {
				t.Errorf("got level %v, want ERROR", record["level"])
			}
		})
	}
}

// TestAccessLog_UnmatchedPathIsNotLoggedVerbatim pins that an unmatched request,
// whose path is entirely caller-controlled, is reported as the fixed marker.
func TestAccessLog_UnmatchedPathIsNotLoggedVerbatim(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	handler := AccessLogMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	req := httptest.NewRequest(http.MethodGet, "/reset/super-secret-token", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	logOutput := buf.String()
	if strings.Contains(logOutput, "super-secret-token") {
		t.Errorf("unmatched path logged verbatim: %s", logOutput)
	}
	if !strings.Contains(logOutput, unmatchedRoute) {
		t.Errorf("expected %q marker in output: %s", unmatchedRoute, logOutput)
	}
}
