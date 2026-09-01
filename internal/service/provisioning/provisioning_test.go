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
	attachResult   cdp.AttachResult
	identities     []cdp.MemberIdentity
	identitiesErr  error

	// identitiesByMember overrides identities per member id, for the paths
	// that read a second member's identities as well as the resolved one's.
	identitiesByMember map[string][]cdp.MemberIdentity

	resolveCalls    int
	createCalls     int
	attachCalls     int
	identitiesCalls int
	attachedTo      string
	resolvedLFID    string

	createdDisplayName string
}

func (m *mockCDPClient) Resolve(_ context.Context, lfid string, _ string) (cdp.ResolveResult, error) {
	m.resolveCalls++
	m.resolvedLFID = lfid
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

func (m *mockCDPClient) ListIdentities(_ context.Context, memberID string) ([]cdp.MemberIdentity, error) {
	m.identitiesCalls++
	if m.identitiesByMember != nil {
		held, ok := m.identitiesByMember[memberID]
		if !ok {
			return nil, m.identitiesErr
		}
		return held, nil
	}
	return m.identities, m.identitiesErr
}

func (m *mockCDPClient) CreateMember(_ context.Context, displayName string, _ cdp.Identity) (cdp.CreateResult, error) {
	m.createCalls++
	m.createdDisplayName = displayName
	return m.createResult, m.createErr
}

func (m *mockCDPClient) AttachIdentity(_ context.Context, memberID string, _ cdp.Identity) (cdp.AttachResult, error) {
	m.attachCalls++
	m.attachedTo = memberID
	if m.attachErr != nil {
		return cdp.AttachResult{}, m.attachErr
	}
	if m.attachResult.Outcome != "" {
		return m.attachResult, nil
	}
	return cdp.AttachResult{Outcome: cdp.OutcomeFound}, nil
}

// mockMetadataStore records the write it was asked to make and serves the
// authoritative state the gate re-reads.
type mockMetadataStore struct {
	err     error
	calls   int
	written port.CDPMetadata
	userID  string

	// state is what Auth0 reports; defaults to an eligible user.
	state     *port.UserProvisioningState
	stateErr  error
	readCalls int
}

func (m *mockMetadataStore) WriteCDPMetadata(_ context.Context, userID string, record port.CDPMetadata) error {
	m.calls++
	m.userID = userID
	m.written = record
	return m.err
}

func (m *mockMetadataStore) ReadCDPMetadata(_ context.Context, _ string) (port.CDPMetadata, error) {
	return port.CDPMetadata{}, nil
}

func (m *mockMetadataStore) ReadProvisioningState(_ context.Context, _ string) (port.UserProvisioningState, error) {
	m.readCalls++
	if m.stateErr != nil {
		return port.UserProvisioningState{}, m.stateErr
	}
	if m.state != nil {
		return *m.state, nil
	}
	return port.UserProvisioningState{
		EmailVerified:       true,
		Username:            "psmith",
		HasDatabaseIdentity: true,
	}, nil
}

func newTestOrchestrator(client *mockCDPClient, store *mockMetadataStore) Orchestrator {
	return NewOrchestrator(WithCDPClient(client), WithMetadataStore(store))
}

func boolPtr(v bool) *bool { return &v }

// verifiedRequest is an eligible user: verified, database-connection, no UUID.
func verifiedRequest() Request {
	return Request{
		UserID:              "auth0|1",
		Username:            "psmith",
		Email:               "p@example.org",
		EmailVerified:       boolPtr(true),
		HasDatabaseIdentity: true,
		DisplayName:         "P. Smith",
	}
}

func TestProvisionGate(t *testing.T) {
	ctx := context.Background()

	// The payload is only a pre-filter. It can cheaply rule a delivery out,
	// but it can never rule one in — anything that proceeds is re-checked
	// against Auth0 first.
	payloadTests := []struct {
		name   string
		mutate func(*Request)
		reason string
	}{
		{
			name:   "unverified email is skipped without reading Auth0",
			mutate: func(r *Request) { r.EmailVerified = boolPtr(false) },
			reason: reasonEmailNotVerified,
		},
		{
			name:   "a payload carrying a uuid is skipped without reading Auth0",
			mutate: func(r *Request) { r.StoredCDPUUID = "uuid-1" },
			reason: reasonAlreadyProvisioned,
		},
	}

	for _, tt := range payloadTests {
		t.Run(tt.name, func(t *testing.T) {
			request := verifiedRequest()
			tt.mutate(&request)

			client := &mockCDPClient{}
			store := &mockMetadataStore{}

			result, err := newTestOrchestrator(client, store).Provision(ctx, request)

			require.NoError(t, err)
			assert.Equal(t, OutcomeSkipped, result.Outcome)
			assert.Equal(t, tt.reason, result.Reason)
			assert.Zero(t, store.readCalls, "an obvious skip should not cost an Auth0 call")
			assert.Zero(t, client.resolveCalls, "a gated-out user must not spend CDP budget")
			assert.Zero(t, store.calls)
		})
	}

	t.Run("an absent email_verified asks Auth0 rather than skipping", func(t *testing.T) {
		// The live payload shape is unconfirmed. Reading absence as false
		// would skip every user permanently, and the skip would be
		// indistinguishable from an ordinary unverified account.
		request := verifiedRequest()
		request.EmailVerified = nil

		store := &mockMetadataStore{}
		result, err := newTestOrchestrator(&mockCDPClient{}, store).Provision(ctx, request)

		require.NoError(t, err)
		assert.Positive(t, store.readCalls, "an unknown flag is not a no")
		assert.NotEqual(t, reasonEmailNotVerified, result.Reason)
	})

	// A stale or malformed event claiming eligibility must not get past the
	// authoritative read: the stream proves Auth0 sent the event, not that its
	// fields are still true.
	stateTests := []struct {
		name   string
		state  port.UserProvisioningState
		reason string
	}{
		{
			name: "Auth0 says the email is not verified",
			state: port.UserProvisioningState{
				Username:            "psmith",
				HasDatabaseIdentity: true,
			},
			reason: reasonEmailNotVerified,
		},
		{
			name: "Auth0 already holds a uuid",
			// This is what stops the flow re-triggering on its own write-back,
			// which emits a user.updated of its own.
			state: port.UserProvisioningState{
				CDPMetadata:         port.CDPMetadata{UUID: "uuid-1"},
				EmailVerified:       true,
				Username:            "psmith",
				HasDatabaseIdentity: true,
			},
			reason: reasonAlreadyProvisioned,
		},
		{
			name: "Auth0 shows no database identity",
			state: port.UserProvisioningState{
				EmailVerified: true,
				Username:      "psmith",
			},
			reason: reasonNoDatabaseIdentity,
		},
		{
			name: "Auth0 shows no LFID username",
			state: port.UserProvisioningState{
				EmailVerified:       true,
				HasDatabaseIdentity: true,
			},
			reason: reasonNoLFIDUsername,
		},
	}

	for _, tt := range stateTests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockCDPClient{}
			store := &mockMetadataStore{state: &tt.state}

			result, err := newTestOrchestrator(client, store).Provision(ctx, verifiedRequest())

			require.NoError(t, err)
			assert.Equal(t, OutcomeSkipped, result.Outcome)
			assert.Equal(t, tt.reason, result.Reason)
			assert.Zero(t, client.resolveCalls, "a gated-out user must not spend CDP budget")
			assert.Zero(t, store.calls)
		})
	}

	t.Run("the LFID comes from Auth0, not from the payload", func(t *testing.T) {
		// A caller that could choose the LFID could attach a victim's Auth0
		// account to a CDP identity of its choosing.
		client := &mockCDPClient{resolveResults: []cdp.ResolveResult{{Outcome: cdp.OutcomeFound, MemberID: "mem-1"}}}
		store := &mockMetadataStore{state: &port.UserProvisioningState{
			EmailVerified:       true,
			Username:            "real-lfid",
			HasDatabaseIdentity: true,
		}}

		request := verifiedRequest()
		request.Username = "attacker-chosen"

		_, err := newTestOrchestrator(client, store).Provision(ctx, request)

		require.NoError(t, err)
		assert.Equal(t, "real-lfid", client.resolvedLFID)
	})

	t.Run("a deleted user is a terminal skip, not a retry", func(t *testing.T) {
		// Replaying cannot bring the user back, so a retryable error here would
		// just burn the attempt ceiling.
		client := &mockCDPClient{}
		store := &mockMetadataStore{stateErr: errs.NewNotFound("user not found")}

		result, err := newTestOrchestrator(client, store).Provision(ctx, verifiedRequest())

		require.NoError(t, err)
		assert.Equal(t, OutcomeSkipped, result.Outcome)
		assert.Equal(t, reasonUserNotFound, result.Reason)
		assert.Zero(t, client.resolveCalls)
	})

	t.Run("an Auth0 read failure is retryable and writes nothing", func(t *testing.T) {
		client := &mockCDPClient{}
		store := &mockMetadataStore{stateErr: assert.AnError}

		_, err := newTestOrchestrator(client, store).Provision(ctx, verifiedRequest())

		require.Error(t, err)
		assert.Zero(t, client.resolveCalls)
		assert.Zero(t, store.calls)
	})

	t.Run("an empty user id is a validation error", func(t *testing.T) {
		request := verifiedRequest()
		request.UserID = ""

		_, err := newTestOrchestrator(&mockCDPClient{}, &mockMetadataStore{}).Provision(ctx, request)

		var validation errs.Validation
		require.ErrorAs(t, err, &validation)
	})
}

func TestProvisionFlow(t *testing.T) {
	ctx := context.Background()

	t.Run("an existing member is attached and written back", func(t *testing.T) {
		client := &mockCDPClient{resolveResults: []cdp.ResolveResult{{Outcome: cdp.OutcomeFound, MemberID: "MEM-1"}}}
		store := &mockMetadataStore{}

		result, err := newTestOrchestrator(client, store).Provision(ctx, verifiedRequest())

		require.NoError(t, err)
		assert.Equal(t, OutcomeProvisioned, result.Outcome)
		assert.Equal(t, 1, client.attachCalls)
		assert.Equal(t, "MEM-1", client.attachedTo)
		assert.Zero(t, client.createCalls)

		assert.Equal(t, "auth0|1", store.userID)
		assert.Equal(t, "mem-1", store.written.UUID, "the stored uuid is lowercased")
		assert.Equal(t, constants.CDPUUIDSourceProvisioning, store.written.Source)
	})

	t.Run("a member already holding another LFID is not attached to", func(t *testing.T) {
		// Two LFID usernames on one member means it holds two people. CDP
		// answers a single confident match, so nothing else in the flow
		// notices; attaching would add a third person to a record that
		// already needs splitting.
		client := &mockCDPClient{
			resolveResults: []cdp.ResolveResult{{Outcome: cdp.OutcomeFound, MemberID: "MEM-1"}},
			identities: []cdp.MemberIdentity{
				{Value: "someoneelse", Platform: constants.LFIDPlatform, Type: constants.CDPIdentityTypeUsername},
			},
		}
		store := &mockMetadataStore{}

		result, err := newTestOrchestrator(client, store).Provision(ctx, verifiedRequest())

		require.NoError(t, err, "a skip is a final answer, not a retry")
		assert.Equal(t, OutcomeSkipped, result.Outcome)
		assert.Equal(t, reasonMemberHoldsForeignLFID, result.Reason)
		assert.Zero(t, client.attachCalls)
		assert.Zero(t, client.createCalls)
		assert.Zero(t, store.calls, "no uuid is written, so a later run can retry once CDP is fixed")
	})

	t.Run("the user's own LFID on the member does not block the attach", func(t *testing.T) {
		// Re-delivery is at-least-once, so the identity may already be there.
		client := &mockCDPClient{
			resolveResults: []cdp.ResolveResult{{Outcome: cdp.OutcomeFound, MemberID: "MEM-1"}},
			identities: []cdp.MemberIdentity{
				{Value: "PSmith", Platform: constants.LFIDPlatform, Type: constants.CDPIdentityTypeUsername},
				{Value: "psmith@example.org", Platform: constants.LFIDPlatform, Type: "email"},
				{Value: "someoneelse", Platform: "github", Type: constants.CDPIdentityTypeUsername},
			},
		}
		store := &mockMetadataStore{}

		result, err := newTestOrchestrator(client, store).Provision(ctx, verifiedRequest())

		require.NoError(t, err)
		assert.Equal(t, OutcomeProvisioned, result.Outcome, "case differences and other platforms are not another person")
		assert.Equal(t, 1, client.attachCalls)
	})

	t.Run("an attach conflict is not recorded as provisioned", func(t *testing.T) {
		// 409 on attach means the LFID is verified on a different member than
		// the one resolve returned. Writing the member id would store a
		// permanent identifier the LFID was never attached to.
		client := &mockCDPClient{
			resolveResults: []cdp.ResolveResult{{Outcome: cdp.OutcomeFound, MemberID: "MEM-1"}},
			attachResult:   cdp.AttachResult{Outcome: cdp.OutcomeConflict},
		}
		store := &mockMetadataStore{}

		result, err := newTestOrchestrator(client, store).Provision(ctx, verifiedRequest())

		require.NoError(t, err)
		assert.Equal(t, OutcomeSkipped, result.Outcome)
		assert.Equal(t, reasonLFIDOnAnotherMember, result.Reason)
		assert.Zero(t, store.calls, "no uuid is written when the identity did not attach")
	})

	t.Run("the member named by an attach conflict is adopted once verified", func(t *testing.T) {
		// The 409 body names the member that actually holds the LFID, read on
		// the primary while the error was built. Verifying it turns a skip
		// into a provision for a user who is not ambiguous at all — CDP simply
		// pointed resolve at the wrong member.
		client := &mockCDPClient{
			resolveResults: []cdp.ResolveResult{{Outcome: cdp.OutcomeFound, MemberID: "MEM-1"}},
			attachResult:   cdp.AttachResult{Outcome: cdp.OutcomeConflict, ConflictMemberID: "MEM-2"},
			identitiesByMember: map[string][]cdp.MemberIdentity{
				"MEM-1": {},
				"MEM-2": {{Value: "psmith", Platform: constants.LFIDPlatform, Type: constants.CDPIdentityTypeUsername}},
			},
		}
		store := &mockMetadataStore{}

		result, err := newTestOrchestrator(client, store).Provision(ctx, verifiedRequest())

		require.NoError(t, err)
		assert.Equal(t, OutcomeProvisioned, result.Outcome)
		assert.Equal(t, "MEM-2", result.MemberID, "the member that holds the LFID is the one stored")
		assert.Equal(t, "mem-2", store.written.UUID, "stored lowercased, as every cdp_uuid write is")
	})

	t.Run("a conflict naming a member that does not hold the LFID is still a skip", func(t *testing.T) {
		// CDP named it as the holder and it does not hold it. The two answers
		// disagree, and a stored member id is permanent.
		client := &mockCDPClient{
			resolveResults: []cdp.ResolveResult{{Outcome: cdp.OutcomeFound, MemberID: "MEM-1"}},
			attachResult:   cdp.AttachResult{Outcome: cdp.OutcomeConflict, ConflictMemberID: "MEM-2"},
			identitiesByMember: map[string][]cdp.MemberIdentity{
				"MEM-1": {},
				"MEM-2": {},
			},
		}
		store := &mockMetadataStore{}

		result, err := newTestOrchestrator(client, store).Provision(ctx, verifiedRequest())

		require.NoError(t, err)
		assert.Equal(t, OutcomeSkipped, result.Outcome)
		assert.Equal(t, reasonLFIDOnAnotherMember, result.Reason)
		assert.Zero(t, store.calls)
	})

	t.Run("a conflict naming a member holding somebody else's LFID is a skip", func(t *testing.T) {
		client := &mockCDPClient{
			resolveResults: []cdp.ResolveResult{{Outcome: cdp.OutcomeFound, MemberID: "MEM-1"}},
			attachResult:   cdp.AttachResult{Outcome: cdp.OutcomeConflict, ConflictMemberID: "MEM-2"},
			identitiesByMember: map[string][]cdp.MemberIdentity{
				"MEM-1": {},
				"MEM-2": {
					{Value: "psmith", Platform: constants.LFIDPlatform, Type: constants.CDPIdentityTypeUsername},
					{Value: "someoneelse", Platform: constants.LFIDPlatform, Type: constants.CDPIdentityTypeUsername},
				},
			},
		}
		store := &mockMetadataStore{}

		result, err := newTestOrchestrator(client, store).Provision(ctx, verifiedRequest())

		require.NoError(t, err)
		assert.Equal(t, OutcomeSkipped, result.Outcome, "a member holding two LFIDs holds two people")
		assert.Equal(t, reasonLFIDOnAnotherMember, result.Reason)
		assert.Zero(t, store.calls)
	})

	t.Run("a conflict whose member cannot be verified is retried, not guessed", func(t *testing.T) {
		// Nothing is stored yet, so a transient CDP failure should cost a
		// replay rather than this user's trigger.
		client := &mockCDPClient{
			resolveResults: []cdp.ResolveResult{{Outcome: cdp.OutcomeFound, MemberID: "MEM-1"}},
			attachResult:   cdp.AttachResult{Outcome: cdp.OutcomeConflict, ConflictMemberID: "MEM-2"},
			identitiesByMember: map[string][]cdp.MemberIdentity{
				"MEM-1": {},
			},
			identitiesErr: errs.NewUnexpected("cdp unavailable"),
		}
		store := &mockMetadataStore{}

		_, err := newTestOrchestrator(client, store).Provision(ctx, verifiedRequest())

		require.Error(t, err, "the event must be retried, not completed")
		assert.Zero(t, store.calls)
	})

	t.Run("the created member is named from Auth0, not from the payload", func(t *testing.T) {
		// A forged payload could otherwise put an attacker-chosen name on a
		// real person's new CDP member.
		client := &mockCDPClient{
			resolveResults: []cdp.ResolveResult{{Outcome: cdp.OutcomeNoMatch}},
			createResult:   cdp.CreateResult{Outcome: cdp.OutcomeFound, MemberID: "new-1"},
		}
		store := &mockMetadataStore{state: &port.UserProvisioningState{
			EmailVerified:       true,
			Username:            "psmith",
			Name:                "Real Name",
			HasDatabaseIdentity: true,
		}}

		request := verifiedRequest()
		request.DisplayName = "Attacker Chosen"

		_, err := newTestOrchestrator(client, store).Provision(ctx, request)

		require.NoError(t, err)
		assert.Equal(t, "Real Name", client.createdDisplayName)
	})

	t.Run("no member creates one and writes it back", func(t *testing.T) {
		client := &mockCDPClient{
			resolveResults: []cdp.ResolveResult{{Outcome: cdp.OutcomeNoMatch}},
			createResult:   cdp.CreateResult{Outcome: cdp.OutcomeFound, MemberID: "new-1"},
		}
		store := &mockMetadataStore{}

		result, err := newTestOrchestrator(client, store).Provision(ctx, verifiedRequest())

		require.NoError(t, err)
		assert.Equal(t, OutcomeProvisioned, result.Outcome)
		assert.Equal(t, 1, client.createCalls)
		assert.Zero(t, client.attachCalls)
		assert.Equal(t, "new-1", store.written.UUID)
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
		store := &mockMetadataStore{}

		result, err := newTestOrchestrator(client, store).Provision(ctx, verifiedRequest())

		require.NoError(t, err)
		assert.Equal(t, OutcomeProvisioned, result.Outcome)
		assert.Equal(t, 2, client.resolveCalls)
		assert.Equal(t, "raced-1", store.written.UUID)
	})

	t.Run("a create conflict re-resolve skips a member holding another LFID", func(t *testing.T) {
		client := &mockCDPClient{
			resolveResults: []cdp.ResolveResult{
				{Outcome: cdp.OutcomeNoMatch},
				{Outcome: cdp.OutcomeFound, MemberID: "raced-1"},
			},
			createResult: cdp.CreateResult{Outcome: cdp.OutcomeConflict},
			identities: []cdp.MemberIdentity{
				{Value: "someoneelse", Platform: constants.LFIDPlatform, Type: constants.CDPIdentityTypeUsername},
			},
		}
		store := &mockMetadataStore{}

		result, err := newTestOrchestrator(client, store).Provision(ctx, verifiedRequest())

		require.NoError(t, err)
		assert.Equal(t, OutcomeSkipped, result.Outcome)
		assert.Equal(t, reasonMemberHoldsForeignLFID, result.Reason)
		assert.Zero(t, store.calls)
	})

	t.Run("a create conflict never stores a member that has vanished", func(t *testing.T) {
		// This path attaches nothing, so the identity read is the only thing
		// standing between a disappeared member and a permanent record of it.
		// The id would go to Auth0 write-once and on to Segment as the
		// user_id, neither of which can be corrected afterwards, so a
		// retryable failure is the only safe answer.
		client := &mockCDPClient{
			resolveResults: []cdp.ResolveResult{
				{Outcome: cdp.OutcomeNoMatch},
				{Outcome: cdp.OutcomeFound, MemberID: "vanished-1"},
			},
			createResult:  cdp.CreateResult{Outcome: cdp.OutcomeConflict},
			identitiesErr: cdp.ErrMemberNotFound,
		}
		store := &mockMetadataStore{}

		_, err := newTestOrchestrator(client, store).Provision(ctx, verifiedRequest())

		require.ErrorIs(t, err, cdp.ErrMemberNotFound, "the event must be retried, not completed")
		assert.Zero(t, store.calls, "nothing may be written for a member we cannot confirm exists")
	})

	t.Run("a vanished member is not stored on the attach path either", func(t *testing.T) {
		client := &mockCDPClient{
			resolveResults: []cdp.ResolveResult{{Outcome: cdp.OutcomeFound, MemberID: "vanished-2"}},
			identitiesErr:  cdp.ErrMemberNotFound,
		}
		store := &mockMetadataStore{}

		_, err := newTestOrchestrator(client, store).Provision(ctx, verifiedRequest())

		require.ErrorIs(t, err, cdp.ErrMemberNotFound)
		assert.Zero(t, client.attachCalls, "there is nothing to attach to")
		assert.Zero(t, store.calls)
	})

	t.Run("a create conflict whose LFID does not resolve yet is retried", func(t *testing.T) {
		// The 409 says the LFID is claimed, so a no-match is replica lag
		// rather than an answer.
		client := &mockCDPClient{
			resolveResults: []cdp.ResolveResult{
				{Outcome: cdp.OutcomeNoMatch},
				{Outcome: cdp.OutcomeNoMatch},
			},
			createResult: cdp.CreateResult{Outcome: cdp.OutcomeConflict},
		}
		store := &mockMetadataStore{}

		_, err := newTestOrchestrator(client, store).Provision(ctx, verifiedRequest())

		require.Error(t, err, "replica lag must be retried, not read as a final answer")
		assert.Equal(t, 1, client.createCalls, "the create must not be retried within one attempt")
		assert.Zero(t, store.calls)
	})

	t.Run("a create conflict whose re-resolve returns an unknown outcome is retried", func(t *testing.T) {
		// Anything this code cannot classify must not be read as "found" and
		// stored: the id becomes a permanent Segment user_id.
		client := &mockCDPClient{
			resolveResults: []cdp.ResolveResult{
				{Outcome: cdp.OutcomeNoMatch},
				{Outcome: cdp.Outcome("something-cdp-added-later"), MemberID: "MEM-9"},
			},
			createResult: cdp.CreateResult{Outcome: cdp.OutcomeConflict},
		}
		store := &mockMetadataStore{}

		_, err := newTestOrchestrator(client, store).Provision(ctx, verifiedRequest())

		require.Error(t, err)
		assert.Zero(t, store.calls)
	})

	t.Run("a create conflict whose re-resolve matches several members is skipped", func(t *testing.T) {
		// Only CDP can merge them, so replaying asks the same question.
		client := &mockCDPClient{
			resolveResults: []cdp.ResolveResult{
				{Outcome: cdp.OutcomeNoMatch},
				{Outcome: cdp.OutcomeConflict},
			},
			createResult: cdp.CreateResult{Outcome: cdp.OutcomeConflict},
		}
		store := &mockMetadataStore{}

		result, err := newTestOrchestrator(client, store).Provision(ctx, verifiedRequest())

		require.NoError(t, err)
		assert.Equal(t, OutcomeSkipped, result.Outcome)
		assert.Equal(t, reasonConflict, result.Reason)
		assert.Equal(t, 1, client.createCalls)
		assert.Zero(t, store.calls)
	})

	t.Run("a resolve conflict writes nothing", func(t *testing.T) {
		// Picking one of several matching members would store an arbitrary
		// identity permanently.
		client := &mockCDPClient{resolveResults: []cdp.ResolveResult{{Outcome: cdp.OutcomeConflict}}}
		store := &mockMetadataStore{}

		result, err := newTestOrchestrator(client, store).Provision(ctx, verifiedRequest())

		require.NoError(t, err)
		assert.Equal(t, OutcomeSkipped, result.Outcome)
		assert.Equal(t, reasonConflict, result.Reason)
		assert.Zero(t, client.createCalls)
		assert.Zero(t, store.calls)
	})

	t.Run("a resolve failure surfaces as an error so the event is retried", func(t *testing.T) {
		client := &mockCDPClient{resolveErr: assert.AnError}
		store := &mockMetadataStore{}

		_, err := newTestOrchestrator(client, store).Provision(ctx, verifiedRequest())

		require.Error(t, err)
		assert.Zero(t, store.calls)
	})

	t.Run("a write-once rejection ends the event rather than retrying it", func(t *testing.T) {
		// Another writer got there first. The end state is correct, so replaying
		// would just repeat the same rejection.
		client := &mockCDPClient{resolveResults: []cdp.ResolveResult{{Outcome: cdp.OutcomeFound, MemberID: "mem-1"}}}
		store := &mockMetadataStore{err: errs.NewConflict("cdp_uuid is write-once")}

		result, err := newTestOrchestrator(client, store).Provision(ctx, verifiedRequest())

		require.NoError(t, err)
		assert.Equal(t, OutcomeSkipped, result.Outcome)
	})

	t.Run("an unexpected write failure is retryable", func(t *testing.T) {
		client := &mockCDPClient{resolveResults: []cdp.ResolveResult{{Outcome: cdp.OutcomeFound, MemberID: "mem-1"}}}
		store := &mockMetadataStore{err: errs.NewUnexpected("auth0 down")}

		_, err := newTestOrchestrator(client, store).Provision(ctx, verifiedRequest())

		require.Error(t, err)
	})

	t.Run("an unconfigured orchestrator errors rather than silently skipping", func(t *testing.T) {
		_, err := NewOrchestrator().Provision(ctx, verifiedRequest())
		require.Error(t, err)
	})
}
