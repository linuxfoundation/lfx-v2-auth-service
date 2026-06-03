// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"context"
	"testing"
	"time"

	"github.com/linuxfoundation/lfx-v2-auth-service/internal/domain/model"
	jwtgen "github.com/linuxfoundation/lfx-v2-auth-service/pkg/jwt"
)

func tokenWithSub(t *testing.T, sub string) string {
	t.Helper()
	token, err := jwtgen.GenerateSimpleTestIdentityTokenWithSubject("test@example.com", sub, time.Hour)
	if err != nil {
		t.Fatalf("failed to generate test token: %v", err)
	}
	return token
}

func TestValidateLinkRequest(t *testing.T) {
	ctx := context.Background()
	u := &userReaderWriter{}

	tests := []struct {
		name      string
		request   *model.LinkIdentity
		wantError bool
		errorMsg  string
	}{
		{
			name:      "nil request",
			request:   nil,
			wantError: true,
			errorMsg:  "link identity request is required",
		},
		{
			name: "empty identity token",
			request: func() *model.LinkIdentity {
				r := &model.LinkIdentity{}
				return r
			}(),
			wantError: true,
			errorMsg:  "link_with identity token is required",
		},
		{
			name: "malformed token",
			request: func() *model.LinkIdentity {
				r := &model.LinkIdentity{}
				r.LinkWith.IdentityToken = "not.a.valid.jwt"
				return r
			}(),
			wantError: true,
			errorMsg:  "invalid identity token: unable to extract subject",
		},
		{
			name: "auth0 database user sub rejected",
			request: func() *model.LinkIdentity {
				r := &model.LinkIdentity{}
				r.LinkWith.IdentityToken = tokenWithSub(t, "auth0|abc123")
				return r
			}(),
			wantError: true,
			errorMsg:  "the provided identity token belongs to an existing LFID account and cannot be linked",
		},
		{
			name: "google-oauth2 sub accepted",
			request: func() *model.LinkIdentity {
				r := &model.LinkIdentity{}
				r.LinkWith.IdentityToken = tokenWithSub(t, "google-oauth2|123456")
				return r
			}(),
			wantError: false,
		},
		{
			name: "github sub accepted",
			request: func() *model.LinkIdentity {
				r := &model.LinkIdentity{}
				r.LinkWith.IdentityToken = tokenWithSub(t, "github|789012")
				return r
			}(),
			wantError: false,
		},
		{
			name: "linkedin sub accepted",
			request: func() *model.LinkIdentity {
				r := &model.LinkIdentity{}
				r.LinkWith.IdentityToken = tokenWithSub(t, "linkedin|345678")
				return r
			}(),
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := u.ValidateLinkRequest(ctx, tt.request)
			if tt.wantError {
				if err == nil {
					t.Errorf("ValidateLinkRequest() expected error but got nil")
					return
				}
				if tt.errorMsg != "" && err.Error() != tt.errorMsg {
					t.Errorf("ValidateLinkRequest() error = %q, want %q", err.Error(), tt.errorMsg)
				}
			} else if err != nil {
				t.Errorf("ValidateLinkRequest() unexpected error: %v", err)
			}
		})
	}
}
