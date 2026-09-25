// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package log

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/baggage"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestAppendCtx(t *testing.T) {
	tests := []struct {
		name          string
		parentCtx     context.Context
		attr          slog.Attr
		existingAttrs []slog.Attr
		expectedLen   int
	}{
		{
			name:        "nil parent context",
			parentCtx:   nil,
			attr:        slog.String("key", "value"),
			expectedLen: 1,
		},
		{
			name:        "empty context",
			parentCtx:   context.Background(),
			attr:        slog.String("key", "value"),
			expectedLen: 1,
		},
		{
			name:          "context with existing attrs",
			parentCtx:     context.WithValue(context.Background(), slogFields, []slog.Attr{slog.String("existing", "attr")}),
			attr:          slog.String("new", "attr"),
			existingAttrs: []slog.Attr{slog.String("existing", "attr")},
			expectedLen:   2,
		},
		{
			name:        "integer attribute",
			parentCtx:   context.Background(),
			attr:        slog.Int("count", 42),
			expectedLen: 1,
		},
		{
			name:        "bool attribute",
			parentCtx:   context.Background(),
			attr:        slog.Bool("enabled", true),
			expectedLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AppendCtx(tt.parentCtx, tt.attr)

			if result == nil {
				t.Error("AppendCtx() returned nil context")
				return
			}

			attrs, ok := result.Value(slogFields).([]slog.Attr)
			if !ok {
				t.Error("AppendCtx() did not store attrs in context")
				return
			}

			if len(attrs) != tt.expectedLen {
				t.Errorf("AppendCtx() stored %d attrs, want %d", len(attrs), tt.expectedLen)
			}

			// Verify the new attr is in the slice
			found := false
			for _, a := range attrs {
				if a.Key == tt.attr.Key && a.Value.String() == tt.attr.Value.String() {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("AppendCtx() did not include the new attribute %v", tt.attr)
			}
		})
	}
}

func TestAppendCtxMultipleAttrs(t *testing.T) {
	t.Run("chaining multiple AppendCtx calls", func(t *testing.T) {
		ctx := context.Background()
		ctx = AppendCtx(ctx, slog.String("first", "1"))
		ctx = AppendCtx(ctx, slog.String("second", "2"))
		ctx = AppendCtx(ctx, slog.String("third", "3"))

		attrs, ok := ctx.Value(slogFields).([]slog.Attr)
		if !ok {
			t.Fatal("could not retrieve attrs from context")
		}

		if len(attrs) != 3 {
			t.Errorf("expected 3 attrs, got %d", len(attrs))
		}

		expectedKeys := []string{"first", "second", "third"}
		for i, key := range expectedKeys {
			if attrs[i].Key != key {
				t.Errorf("attr[%d].Key = %q, want %q", i, attrs[i].Key, key)
			}
		}
	})
}

func TestPriority(t *testing.T) {
	tests := []struct {
		name     string
		level    string
		expected string
	}{
		{
			name:     "critical level",
			level:    "critical",
			expected: "critical",
		},
		{
			name:     "warning level",
			level:    "warning",
			expected: "warning",
		},
		{
			name:     "info level",
			level:    "info",
			expected: "info",
		},
		{
			name:     "empty level",
			level:    "",
			expected: "",
		},
		{
			name:     "custom level",
			level:    "custom-priority",
			expected: "custom-priority",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Priority(tt.level)

			if result.Key != "priority" {
				t.Errorf("Priority() key = %q, want %q", result.Key, "priority")
			}

			if result.Value.String() != tt.expected {
				t.Errorf("Priority(%q) value = %q, want %q", tt.level, result.Value.String(), tt.expected)
			}
		})
	}
}

func TestPriorityCritical(t *testing.T) {
	t.Run("returns critical priority attr", func(t *testing.T) {
		result := PriorityCritical()

		if result.Key != "priority" {
			t.Errorf("PriorityCritical() key = %q, want %q", result.Key, "priority")
		}

		if result.Value.String() != priorityCritical {
			t.Errorf("PriorityCritical() value = %q, want %q", result.Value.String(), priorityCritical)
		}
	})
}

// mockHandler is a test handler that captures records
type mockHandler struct {
	records []slog.Record
	attrs   []slog.Attr
}

func (m *mockHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return true
}

func (m *mockHandler) Handle(_ context.Context, r slog.Record) error {
	m.records = append(m.records, r)
	r.Attrs(func(a slog.Attr) bool {
		m.attrs = append(m.attrs, a)
		return true
	})
	return nil
}

func (m *mockHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return m
}

func (m *mockHandler) WithGroup(name string) slog.Handler {
	return m
}

func TestContextHandlerHandle(t *testing.T) {
	tests := []struct {
		name          string
		ctxAttrs      []slog.Attr
		recordMsg     string
		expectedAttrs int
	}{
		{
			name:          "no context attrs",
			ctxAttrs:      nil,
			recordMsg:     "test message",
			expectedAttrs: 0,
		},
		{
			name:          "single context attr",
			ctxAttrs:      []slog.Attr{slog.String("key", "value")},
			recordMsg:     "test message",
			expectedAttrs: 1,
		},
		{
			name: "multiple context attrs",
			ctxAttrs: []slog.Attr{
				slog.String("key1", "value1"),
				slog.String("key2", "value2"),
				slog.Int("key3", 123),
			},
			recordMsg:     "test message",
			expectedAttrs: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockHandler{}
			handler := contextHandler{Handler: mock}

			ctx := context.Background()
			if tt.ctxAttrs != nil {
				ctx = context.WithValue(ctx, slogFields, tt.ctxAttrs)
			}

			record := slog.NewRecord(time.Now(), slog.LevelInfo, tt.recordMsg, 0)
			err := handler.Handle(ctx, record)

			if err != nil {
				t.Errorf("Handle() returned error: %v", err)
			}

			if len(mock.attrs) != tt.expectedAttrs {
				t.Errorf("Handle() captured %d attrs, want %d", len(mock.attrs), tt.expectedAttrs)
			}
		})
	}
}

func TestContextHandlerHandleWithLogger(t *testing.T) {
	t.Run("context attrs appear in log output", func(t *testing.T) {
		var buf bytes.Buffer
		baseHandler := slog.NewJSONHandler(&buf, nil)
		handler := contextHandler{Handler: baseHandler}
		logger := slog.New(handler)

		ctx := context.Background()
		ctx = AppendCtx(ctx, slog.String("request_id", "test-123"))
		ctx = AppendCtx(ctx, slog.String("user_id", "user-456"))

		logger.InfoContext(ctx, "test log message")

		output := buf.String()
		if output == "" {
			t.Error("no log output captured")
			return
		}

		// Verify context attrs are in the output
		if !bytes.Contains(buf.Bytes(), []byte(`"request_id":"test-123"`)) {
			t.Errorf("log output missing request_id: %s", output)
		}
		if !bytes.Contains(buf.Bytes(), []byte(`"user_id":"user-456"`)) {
			t.Errorf("log output missing user_id: %s", output)
		}
	})
}

func TestInitStructureLogConfig(t *testing.T) {
	tests := []struct {
		name         string
		logLevel     string
		addSource    string
		wantLogLevel slog.Level
	}{
		{
			name:         "debug level",
			logLevel:     "debug",
			addSource:    "false",
			wantLogLevel: slog.LevelDebug,
		},
		{
			name:         "info level",
			logLevel:     "info",
			addSource:    "false",
			wantLogLevel: slog.LevelInfo,
		},
		{
			name:         "warn level",
			logLevel:     "warn",
			addSource:    "false",
			wantLogLevel: slog.LevelWarn,
		},
		{
			name:         "default level on invalid",
			logLevel:     "invalid",
			addSource:    "false",
			wantLogLevel: slog.LevelDebug,
		},
		{
			name:         "default level on empty",
			logLevel:     "",
			addSource:    "false",
			wantLogLevel: slog.LevelDebug,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prev := slog.Default()
			defer slog.SetDefault(prev)

			// Set test env vars
			t.Setenv("LOG_LEVEL", tt.logLevel)
			t.Setenv("LOG_ADD_SOURCE", tt.addSource)

			// Call the function - it modifies global state
			InitStructureLogConfig()

			// Verify the default logger is enabled at expected level
			logger := slog.Default()
			if !logger.Enabled(context.Background(), tt.wantLogLevel) {
				t.Errorf("logger not enabled at level %v", tt.wantLogLevel)
			}
		})
	}
}

// InitStructureLogConfig must install the JSON stdout handler before emitting
// any startup log, otherwise Datadog reads the plain-text stderr default as
// status:error.
func TestInitStructureLogConfigWritesNothingToStderr(t *testing.T) {
	t.Setenv("LOG_LEVEL", "info")
	t.Setenv("LOG_ADD_SOURCE", "true")

	prevLogger := slog.Default()
	prevStderr := os.Stderr
	prevStdout := os.Stdout
	t.Cleanup(func() {
		slog.SetDefault(prevLogger)
		os.Stderr = prevStderr
		os.Stdout = prevStdout
	})

	errRead, errWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stderr pipe: %v", err)
	}
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}
	os.Stderr = errWrite
	os.Stdout = outWrite
	slog.SetDefault(slog.New(slog.NewTextHandler(errWrite, nil)))

	InitStructureLogConfig()

	_ = errWrite.Close()
	_ = outWrite.Close()

	stderrOutput, err := io.ReadAll(errRead)
	if err != nil {
		t.Fatalf("failed to read stderr: %v", err)
	}
	stdoutOutput, err := io.ReadAll(outRead)
	if err != nil {
		t.Fatalf("failed to read stdout: %v", err)
	}

	if len(stderrOutput) != 0 {
		t.Errorf("expected no stderr output, got %q", stderrOutput)
	}
	if len(stdoutOutput) == 0 {
		t.Error("expected the logging configuration record on stdout")
	}
}

// otelhttp extracts client-supplied baggage into the request context (the
// OTEL_PROPAGATORS default includes it), so baggage enrichment must stay off:
// a caller could otherwise inject PII or shadow trusted fields.
func TestInitStructureLogConfigDropsContextBaggage(t *testing.T) {
	t.Setenv("LOG_LEVEL", "info")

	prevLogger := slog.Default()
	prevStdout := os.Stdout
	t.Cleanup(func() {
		slog.SetDefault(prevLogger)
		os.Stdout = prevStdout
	})

	out, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatalf("failed to create temp stdout: %v", err)
	}
	os.Stdout = out

	InitStructureLogConfig()

	member, err := baggage.NewMember("leaked_pii", "victim@example.com")
	if err != nil {
		t.Fatalf("failed to build baggage member: %v", err)
	}
	bag, err := baggage.New(member)
	if err != nil {
		t.Fatalf("failed to build baggage: %v", err)
	}

	// slog-otel only copies baggage when a recording span is present, which
	// is always the case for records emitted under otelhttp.
	tp := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	ctx, span := tp.Tracer("test").Start(baggage.ContextWithBaggage(context.Background(), bag), "probe")
	defer span.End()
	if !span.IsRecording() {
		t.Fatal("test span must be recording, otherwise baggage is never copied")
	}

	slog.InfoContext(ctx, "probe")

	if err := out.Close(); err != nil {
		t.Fatalf("failed to close temp stdout: %v", err)
	}
	logged, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatalf("failed to read temp stdout: %v", err)
	}

	if !strings.Contains(string(logged), `"msg":"probe"`) {
		t.Fatalf("probe record missing from stdout: %s", logged)
	}
	for _, leak := range []string{"leaked_pii", "victim@example.com"} {
		if strings.Contains(string(logged), leak) {
			t.Errorf("baggage %q leaked into the log record: %s", leak, logged)
		}
	}
}

// TestAppendCtxSiblingIsolation guards the make+copy in AppendCtx: two children
// forked from one parent must not share a backing array and overwrite each
// other's final attribute. The parent is built by chaining three attributes so
// an append-in-place implementation leaves spare capacity for siblings to
// collide in — a shallower parent would pass either way.
func TestAppendCtxSiblingIsolation(t *testing.T) {
	base := AppendCtx(context.Background(), slog.String("a", "1"))
	base = AppendCtx(base, slog.String("b", "2"))
	base = AppendCtx(base, slog.String("c", "3"))

	first := AppendCtx(base, slog.String("branch", "first"))
	second := AppendCtx(base, slog.String("branch", "second"))

	lastAttr := func(ctx context.Context) string {
		t.Helper()
		attrs, ok := ctx.Value(slogFields).([]slog.Attr)
		if !ok || len(attrs) == 0 {
			t.Fatal("expected context to carry slog attributes")
		}
		return attrs[len(attrs)-1].Value.String()
	}

	if got := lastAttr(first); got != "first" {
		t.Errorf("first child last attr = %q, want %q (sibling clobbered it)", got, "first")
	}
	if got := lastAttr(second); got != "second" {
		t.Errorf("second child last attr = %q, want %q", got, "second")
	}
	if attrs, _ := base.Value(slogFields).([]slog.Attr); len(attrs) != 3 {
		t.Errorf("parent context mutated: len = %d, want 3", len(attrs))
	}
}
