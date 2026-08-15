// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package service

import (
	"context"
	"testing"

	authservice "github.com/linuxfoundation/lfx-v2-auth-service/gen/auth_service"
	"github.com/linuxfoundation/lfx-v2-auth-service/internal/service/provisioning"
	errs "github.com/linuxfoundation/lfx-v2-auth-service/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubProvisioner records whether the orchestrator was reached.
type stubProvisioner struct {
	result provisioning.Result
	err    error
	calls  int
}

func (s *stubProvisioner) Provision(_ context.Context, _ provisioning.Request) (provisioning.Result, error) {
	s.calls++
	return s.result, s.err
}

const testSecret = "s3cret-token"

func newTestAuthService(provisioner provisioning.Orchestrator, secret string) *authService {
	return &authService{
		provisioner:        provisioner,
		provisioningSecret: secret,
	}
}

func validBody() []byte {
	return []byte(`{"id":"evt_1","type":"user.updated","data":{"object":{
		"user_id":"auth0|1","username":"psmith","email":"p@example.org","email_verified":true,
		"identities":[{"connection":"Username-Password-Authentication"}]}}}`)
}

func strptr(s string) *string { return &s }

func TestProvisionCdpUUIDAuthorization(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name   string
		header *string
		secret string
	}{
		{name: "missing header", header: nil, secret: testSecret},
		{name: "wrong secret", header: strptr("Bearer nope"), secret: testSecret},
		{name: "empty bearer", header: strptr("Bearer "), secret: testSecret},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provisioner := &stubProvisioner{}
			svc := newTestAuthService(provisioner, tt.secret)

			err := svc.ProvisionCdpUUID(ctx, &authservice.ProvisionCdpUUIDPayload{
				Authorization: tt.header,
				Body:          validBody(),
			})

			var unauthorized authservice.Unauthorized
			require.ErrorAs(t, err, &unauthorized)
			assert.Zero(t, provisioner.calls, "an unauthorized request must not reach provisioning")
		})
	}

	t.Run("an unconfigured secret asks for redelivery rather than rejecting", func(t *testing.T) {
		// Our misconfiguration, not the caller's. A 401 would tell Auth0 to
		// stop retrying and the events would be lost for its duration.
		provisioner := &stubProvisioner{}
		svc := newTestAuthService(provisioner, "")

		err := svc.ProvisionCdpUUID(ctx, &authservice.ProvisionCdpUUIDPayload{
			Authorization: strptr("Bearer " + testSecret),
			Body:          validBody(),
		})

		var internal authservice.InternalServerError
		require.ErrorAs(t, err, &internal)
		assert.Zero(t, provisioner.calls)
	})

	t.Run("the configured secret is accepted", func(t *testing.T) {
		provisioner := &stubProvisioner{result: provisioning.Result{Outcome: provisioning.OutcomeProvisioned}}
		svc := newTestAuthService(provisioner, testSecret)

		err := svc.ProvisionCdpUUID(ctx, &authservice.ProvisionCdpUUIDPayload{
			Authorization: strptr("Bearer " + testSecret),
			Body:          validBody(),
		})

		require.NoError(t, err)
		assert.Equal(t, 1, provisioner.calls)
	})

	t.Run("a bare secret without the Bearer prefix is accepted", func(t *testing.T) {
		provisioner := &stubProvisioner{result: provisioning.Result{Outcome: provisioning.OutcomeProvisioned}}
		svc := newTestAuthService(provisioner, testSecret)

		err := svc.ProvisionCdpUUID(ctx, &authservice.ProvisionCdpUUIDPayload{
			Authorization: strptr(testSecret),
			Body:          validBody(),
		})

		require.NoError(t, err)
	})
}

// TestProvisionCdpUUIDStatusMapping covers the property that decides whether
// Auth0 redelivers: a 4xx drops the event permanently, so it is reserved for
// requests that cannot succeed no matter how often they are retried.
func TestProvisionCdpUUIDStatusMapping(t *testing.T) {
	ctx := context.Background()
	auth := strptr("Bearer " + testSecret)

	t.Run("an unparseable body is a permanent rejection", func(t *testing.T) {
		provisioner := &stubProvisioner{}
		svc := newTestAuthService(provisioner, testSecret)

		err := svc.ProvisionCdpUUID(ctx, &authservice.ProvisionCdpUUIDPayload{
			Authorization: auth,
			Body:          []byte(`not json`),
		})

		var badRequest authservice.BadRequest
		require.ErrorAs(t, err, &badRequest)
		assert.Zero(t, provisioner.calls)
	})

	t.Run("a transient failure asks for redelivery", func(t *testing.T) {
		provisioner := &stubProvisioner{err: errs.NewUnexpected("CDP unreachable")}
		svc := newTestAuthService(provisioner, testSecret)

		err := svc.ProvisionCdpUUID(ctx, &authservice.ProvisionCdpUUIDPayload{
			Authorization: auth,
			Body:          validBody(),
		})

		var internal authservice.InternalServerError
		require.ErrorAs(t, err, &internal, "a transient failure must not be answered with a 4xx, or the event is lost")
	})

	t.Run("a validation failure is permanent", func(t *testing.T) {
		provisioner := &stubProvisioner{err: errs.NewValidation("user_id is required")}
		svc := newTestAuthService(provisioner, testSecret)

		err := svc.ProvisionCdpUUID(ctx, &authservice.ProvisionCdpUUIDPayload{
			Authorization: auth,
			Body:          validBody(),
		})

		var badRequest authservice.BadRequest
		require.ErrorAs(t, err, &badRequest)
	})

	t.Run("an unconfigured provisioner asks for redelivery", func(t *testing.T) {
		svc := newTestAuthService(nil, testSecret)

		err := svc.ProvisionCdpUUID(ctx, &authservice.ProvisionCdpUUIDPayload{
			Authorization: auth,
			Body:          validBody(),
		})

		var internal authservice.InternalServerError
		require.ErrorAs(t, err, &internal)
	})

	t.Run("a skip is a success, so the event is not redelivered", func(t *testing.T) {
		provisioner := &stubProvisioner{result: provisioning.Result{
			Outcome: provisioning.OutcomeSkipped,
			Reason:  "already-has-cdp-uuid",
		}}
		svc := newTestAuthService(provisioner, testSecret)

		err := svc.ProvisionCdpUUID(ctx, &authservice.ProvisionCdpUUIDPayload{
			Authorization: auth,
			Body:          validBody(),
		})

		require.NoError(t, err)
	})

	t.Run("a nil payload is rejected", func(t *testing.T) {
		svc := newTestAuthService(&stubProvisioner{}, testSecret)

		err := svc.ProvisionCdpUUID(ctx, nil)

		var badRequest authservice.BadRequest
		require.ErrorAs(t, err, &badRequest)
	})
}
