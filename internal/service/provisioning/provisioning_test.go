// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package provisioning

import (
	"context"
	"testing"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/port"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/infrastructure/cdp"
	"github.com/linuxfoundation/lfx-v2-auth-service/pkg/constants"
	errs "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockCDPClient records every call so a test can assert that a gated-out
// request never reaches CDP at all.
type mockCDPClient struct {
	resolveResults []cdp.ResolveResult
	resolveErr     error
	createResult   cdp.CreateResult
	createErr      error
	attachErr      error

	resolveCalls int
	createCalls  int
	attachCalls  int
	attachedTo   string
}

func (m *mockCDPClient) Resolve(_ context.Context, _ string, _ string) (cdp.ResolveResult, error) {
	m.resolveCalls++
	if m.resolveErr != nil {
		return cdp.ResolveResult{}, m.resolveErr
	}
	if len(m.resolveResults) == 0 {
		return cdp.ResolveResult{Outcome: cdp.OutcomeNoMatch}, nil
	}
	index := m.resolveCalls - 1
	if index >= len(m.resolveResults) {
		index = len(m.resolveResults) - 1
	}
	return m.resolveResults[index], nil
}

func (m *mockCDPClient) CreateMember(_ context.Context, _ string, _ cdp.Identity) (cdp.CreateResult, error) {
	m.createCalls++
	return m.createResult, m.createErr
}

func (m *mockCDPClient) AttachIdentity(_ context.Context, memberID string, _ cdp.Identity) error {
	m.attachCalls++
	m.attachedTo = memberID
	return m.attachErr
}

// mockMetadataWriter records the write it was asked to make.
type mockMetadataWriter struct {
	err     error
	calls   int
	written port.CDPMetadata
	userID  string
}

func (m *mockMetadataWriter) WriteCDPMetadata(_ context.Context, userID string, record port.CDPMetadata) error {
	m.calls++
	m.userID = userID
	m.written = record
	return m.err
}

func newTestOrchestrator(client *mockCDPClient, writer *mockMetadataWriter) Orchestrator {
	return NewOrchestrator(WithCDPClient(client), WithMetadataWriter(writer))
}

// verifiedRequest is an eligible user: verified, database-connection, no UUID.
func verifiedRequest() Request {
	return Request{
		UserID:              "auth0|1",
		Username:            "psmith",
		Email:               "p@example.org",
		EmailVerified:       true,
		HasDatabaseIdentity: true,
		DisplayName:         "P. Smith",
	}
}

func TestProvisionGate(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name    string
		mutate  func(*Request)
		reason  string
		comment string
	}{
		{
			name:   "unverified email is skipped",
			mutate: func(r *Request) { r.EmailVerified = false },
			reason: reasonEmailNotVerified,
		},
		{
			name:   "a user who already has a uuid is skipped",
			mutate: func(r *Request) { r.StoredCDPUUID = "uuid-1" },
			reason: reasonAlreadyProvisioned,
			// This is the half that stops the flow re-triggering on its own
			// write-back: that write emits a user.updated of its own.
		},
		{
			name:   "a non-database user is skipped",
			mutate: func(r *Request) { r.HasDatabaseIdentity = false },
			reason: reasonNoDatabaseIdentity,
		},
		{
			name:   "a database user with no username is skipped",
			mutate: func(r *Request) { r.Username = "" },
			reason: reasonNoLFIDUsername,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := verifiedRequest()
			tt.mutate(&request)

			client := &mockCDPClient{}
			writer := &mockMetadataWriter{}

			result, err := newTestOrchestrator(client, writer).Provision(ctx, request)

			require.NoError(t, err)
			assert.Equal(t, OutcomeSkipped, result.Outcome)
			assert.Equal(t, tt.reason, result.Reason)
			assert.Zero(t, client.resolveCalls, "a gated-out user must not spend CDP budget")
			assert.Zero(t, writer.calls)
		})
	}

	t.Run("an empty user id is a validation error", func(t *testing.T) {
		request := verifiedRequest()
		request.UserID = ""

		_, err := newTestOrchestrator(&mockCDPClient{}, &mockMetadataWriter{}).Provision(ctx, request)

		var validation errs.Validation
		require.ErrorAs(t, err, &validation)
	})
}

func TestProvisionFlow(t *testing.T) {
	ctx := context.Background()

	t.Run("an existing member is attached and written back", func(t *testing.T) {
		client := &mockCDPClient{resolveResults: []cdp.ResolveResult{{Outcome: cdp.OutcomeFound, MemberID: "MEM-1"}}}
		writer := &mockMetadataWriter{}

		result, err := newTestOrchestrator(client, writer).Provision(ctx, verifiedRequest())

		require.NoError(t, err)
		assert.Equal(t, OutcomeProvisioned, result.Outcome)
		assert.Equal(t, 1, client.attachCalls)
		assert.Equal(t, "MEM-1", client.attachedTo)
		assert.Zero(t, client.createCalls)

		assert.Equal(t, "auth0|1", writer.userID)
		assert.Equal(t, "mem-1", writer.written.UUID, "the stored uuid is lowercased")
		assert.Equal(t, constants.CDPUUIDSourceProvisioning, writer.written.Source)
	})

	t.Run("no member creates one and writes it back", func(t *testing.T) {
		client := &mockCDPClient{
			resolveResults: []cdp.ResolveResult{{Outcome: cdp.OutcomeNoMatch}},
			createResult:   cdp.CreateResult{Outcome: cdp.OutcomeFound, MemberID: "new-1"},
		}
		writer := &mockMetadataWriter{}

		result, err := newTestOrchestrator(client, writer).Provision(ctx, verifiedRequest())

		require.NoError(t, err)
		assert.Equal(t, OutcomeProvisioned, result.Outcome)
		assert.Equal(t, 1, client.createCalls)
		assert.Zero(t, client.attachCalls)
		assert.Equal(t, "new-1", writer.written.UUID)
	})

	t.Run("a create conflict recovers by re-resolving", func(t *testing.T) {
		// The 409 body carries no member id, so the only way back is another
		// resolve — which works here because this path always holds an LFID.
		client := &mockCDPClient{
			resolveResults: []cdp.ResolveResult{
				{Outcome: cdp.OutcomeNoMatch},
				{Outcome: cdp.OutcomeFound, MemberID: "raced-1"},
			},
			createResult: cdp.CreateResult{Outcome: cdp.OutcomeConflict},
		}
		writer := &mockMetadataWriter{}

		result, err := newTestOrchestrator(client, writer).Provision(ctx, verifiedRequest())

		require.NoError(t, err)
		assert.Equal(t, OutcomeProvisioned, result.Outcome)
		assert.Equal(t, 2, client.resolveCalls)
		assert.Equal(t, "raced-1", writer.written.UUID)
	})

	t.Run("a create conflict that still cannot resolve is skipped, not looped", func(t *testing.T) {
		client := &mockCDPClient{
			resolveResults: []cdp.ResolveResult{
				{Outcome: cdp.OutcomeNoMatch},
				{Outcome: cdp.OutcomeNoMatch},
			},
			createResult: cdp.CreateResult{Outcome: cdp.OutcomeConflict},
		}
		writer := &mockMetadataWriter{}

		result, err := newTestOrchestrator(client, writer).Provision(ctx, verifiedRequest())

		require.NoError(t, err)
		assert.Equal(t, OutcomeSkipped, result.Outcome)
		assert.Equal(t, reasonConflict, result.Reason)
		assert.Equal(t, 1, client.createCalls, "the create must not be retried into a loop")
		assert.Zero(t, writer.calls)
	})

	t.Run("a resolve conflict writes nothing", func(t *testing.T) {
		// Picking one of several matching members would store an arbitrary
		// identity permanently.
		client := &mockCDPClient{resolveResults: []cdp.ResolveResult{{Outcome: cdp.OutcomeConflict}}}
		writer := &mockMetadataWriter{}

		result, err := newTestOrchestrator(client, writer).Provision(ctx, verifiedRequest())

		require.NoError(t, err)
		assert.Equal(t, OutcomeSkipped, result.Outcome)
		assert.Equal(t, reasonConflict, result.Reason)
		assert.Zero(t, client.createCalls)
		assert.Zero(t, writer.calls)
	})

	t.Run("a resolve failure surfaces as an error so the event is retried", func(t *testing.T) {
		client := &mockCDPClient{resolveErr: assert.AnError}
		writer := &mockMetadataWriter{}

		_, err := newTestOrchestrator(client, writer).Provision(ctx, verifiedRequest())

		require.Error(t, err)
		assert.Zero(t, writer.calls)
	})

	t.Run("a write-once rejection ends the event rather than retrying it", func(t *testing.T) {
		// Another writer got there first. The end state is correct, so asking
		// Auth0 to redeliver would just repeat the same rejection.
		client := &mockCDPClient{resolveResults: []cdp.ResolveResult{{Outcome: cdp.OutcomeFound, MemberID: "mem-1"}}}
		writer := &mockMetadataWriter{err: errs.NewConflict("cdp_uuid is write-once")}

		result, err := newTestOrchestrator(client, writer).Provision(ctx, verifiedRequest())

		require.NoError(t, err)
		assert.Equal(t, OutcomeSkipped, result.Outcome)
	})

	t.Run("an unexpected write failure is retryable", func(t *testing.T) {
		client := &mockCDPClient{resolveResults: []cdp.ResolveResult{{Outcome: cdp.OutcomeFound, MemberID: "mem-1"}}}
		writer := &mockMetadataWriter{err: errs.NewUnexpected("auth0 down")}

		_, err := newTestOrchestrator(client, writer).Provision(ctx, verifiedRequest())

		require.Error(t, err)
	})

	t.Run("an unconfigured orchestrator errors rather than silently skipping", func(t *testing.T) {
		_, err := NewOrchestrator().Provision(ctx, verifiedRequest())
		require.Error(t, err)
	})
}
