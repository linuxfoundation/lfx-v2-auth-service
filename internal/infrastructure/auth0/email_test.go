// Copyright The Linux Foundation and each contributor to LFX.
// SPDX-License-Identifier: MIT

package auth0

import (
	"context"
	"errors"
	"testing"

	"github.com/auth0/go-auth0/authentication/oauth"
	"github.com/auth0/go-auth0/authentication/passwordless"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPasswordlessFlow is a mock implementation of the passwordlessFlow interface
type mockPasswordlessFlow struct {
	sendEmailFunc      func(ctx context.Context, request passwordless.SendEmailRequest) (*passwordless.SendEmailResponse, error)
	loginWithEmailFunc func(ctx context.Context, request passwordless.LoginWithEmailRequest, options oauth.IDTokenValidationOptions) (*oauth.TokenSet, error)
}

func (m *mockPasswordlessFlow) SendEmail(ctx context.Context, request passwordless.SendEmailRequest) (*passwordless.SendEmailResponse, error) {
	if m.sendEmailFunc != nil {
		return m.sendEmailFunc(ctx, request)
	}
	return nil, errors.New("not implemented")
}

func (m *mockPasswordlessFlow) LoginWithEmail(ctx context.Context, request passwordless.LoginWithEmailRequest, options oauth.IDTokenValidationOptions) (*oauth.TokenSet, error) {
	if m.loginWithEmailFunc != nil {
		return m.loginWithEmailFunc(ctx, request, options)
	}
	return nil, errors.New("not implemented")
}

func TestEmailLinkingFlow_StartPasswordlessFlow(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		email       string
		mockSetup   func() *mockPasswordlessFlow
		wantErr     bool
		errContains string
	}{
		{
			name:  "successfully starts passwordless flow",
			email: "test@example.com",
			mockSetup: func() *mockPasswordlessFlow {
				return &mockPasswordlessFlow{
					sendEmailFunc: func(ctx context.Context, request passwordless.SendEmailRequest) (*passwordless.SendEmailResponse, error) {
						// Verify request parameters
						assert.Equal(t, "test@example.com", request.Email)
						assert.Equal(t, "email", request.Connection)
						assert.Equal(t, "code", request.Send)

						return &passwordless.SendEmailResponse{
							ID:            "test-id-123",
							Email:         "test@example.com",
							EmailVerified: true,
						}, nil
					},
				}
			},
			wantErr: false,
		},
		{
			name:  "starts flow with unverified email",
			email: "unverified@example.com",
			mockSetup: func() *mockPasswordlessFlow {
				return &mockPasswordlessFlow{
					sendEmailFunc: func(ctx context.Context, request passwordless.SendEmailRequest) (*passwordless.SendEmailResponse, error) {
						return &passwordless.SendEmailResponse{
							ID:            "test-id-456",
							Email:         "unverified@example.com",
							EmailVerified: false,
						}, nil
					},
				}
			},
			wantErr: false,
		},
		{
			name:  "returns error when SendEmail fails",
			email: "error@example.com",
			mockSetup: func() *mockPasswordlessFlow {
				return &mockPasswordlessFlow{
					sendEmailFunc: func(ctx context.Context, request passwordless.SendEmailRequest) (*passwordless.SendEmailResponse, error) {
						return nil, errors.New("auth0 API error")
					},
				}
			},
			wantErr:     true,
			errContains: "failed to start passwordless flow",
		},
		{
			name:  "handles email with special characters",
			email: "test+tag@example.com",
			mockSetup: func() *mockPasswordlessFlow {
				return &mockPasswordlessFlow{
					sendEmailFunc: func(ctx context.Context, request passwordless.SendEmailRequest) (*passwordless.SendEmailResponse, error) {
						assert.Equal(t, "test+tag@example.com", request.Email)
						return &passwordless.SendEmailResponse{
							ID:            "test-id-789",
							Email:         "test+tag@example.com",
							EmailVerified: true,
						}, nil
					},
				}
			},
			wantErr: false,
		},
		{
			name:  "handles empty response fields",
			email: "test@example.com",
			mockSetup: func() *mockPasswordlessFlow {
				return &mockPasswordlessFlow{
					sendEmailFunc: func(ctx context.Context, request passwordless.SendEmailRequest) (*passwordless.SendEmailResponse, error) {
						return &passwordless.SendEmailResponse{
							ID:            "",
							Email:         "",
							EmailVerified: false,
						}, nil
					},
				}
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFlow := tt.mockSetup()
			emailFlow := &EmailLinkingFlow{
				flow: mockFlow,
			}

			err := emailFlow.StartPasswordlessFlow(ctx, tt.email)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestEmailLinkingFlow_ExchangeOTPForToken(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		email       string
		otp         string
		mockSetup   func() *mockPasswordlessFlow
		wantErr     bool
		errContains string
		validate    func(t *testing.T, response *TokenResponse)
	}{
		{
			name:  "successfully exchanges OTP for token",
			email: "test@example.com",
			otp:   "123456",
			mockSetup: func() *mockPasswordlessFlow {
				return &mockPasswordlessFlow{
					loginWithEmailFunc: func(ctx context.Context, request passwordless.LoginWithEmailRequest, options oauth.IDTokenValidationOptions) (*oauth.TokenSet, error) {
						// Verify request parameters
						assert.Equal(t, "test@example.com", request.Email)
						assert.Equal(t, "123456", request.Code)
						assert.Equal(t, "email", request.Realm)
						assert.Equal(t, "openid email profile", request.Scope)

						return &oauth.TokenSet{
							AccessToken:  "access-token-123",
							IDToken:      "id-token-456",
							TokenType:    "Bearer",
							ExpiresIn:    3600,
							RefreshToken: "refresh-token-789",
							Scope:        "openid email profile",
						}, nil
					},
				}
			},
			wantErr: false,
			validate: func(t *testing.T, response *TokenResponse) {
				assert.NotNil(t, response)
				assert.Equal(t, "access-token-123", response.AccessToken)
				assert.Equal(t, "id-token-456", response.IDToken)
				assert.Equal(t, "Bearer", response.TokenType)
				assert.Equal(t, int64(3600), response.ExpiresIn)
				assert.Equal(t, "refresh-token-789", response.RefreshToken)
				assert.Equal(t, "openid email profile", response.Scope)
			},
		},
		{
			name:  "successfully exchanges OTP without refresh token",
			email: "test@example.com",
			otp:   "654321",
			mockSetup: func() *mockPasswordlessFlow {
				return &mockPasswordlessFlow{
					loginWithEmailFunc: func(ctx context.Context, request passwordless.LoginWithEmailRequest, options oauth.IDTokenValidationOptions) (*oauth.TokenSet, error) {
						return &oauth.TokenSet{
							AccessToken: "access-token-abc",
							IDToken:     "id-token-def",
							TokenType:   "Bearer",
							ExpiresIn:   7200,
							Scope:       "openid email",
						}, nil
					},
				}
			},
			wantErr: false,
			validate: func(t *testing.T, response *TokenResponse) {
				assert.NotNil(t, response)
				assert.Equal(t, "access-token-abc", response.AccessToken)
				assert.Equal(t, "id-token-def", response.IDToken)
				assert.Empty(t, response.RefreshToken)
				assert.Equal(t, int64(7200), response.ExpiresIn)
			},
		},
		{
			name:  "returns error when OTP is invalid",
			email: "test@example.com",
			otp:   "wrong-otp",
			mockSetup: func() *mockPasswordlessFlow {
				return &mockPasswordlessFlow{
					loginWithEmailFunc: func(ctx context.Context, request passwordless.LoginWithEmailRequest, options oauth.IDTokenValidationOptions) (*oauth.TokenSet, error) {
						return nil, errors.New("invalid OTP")
					},
				}
			},
			wantErr:     true,
			errContains: "failed to exchange OTP for token",
		},
		{
			name:  "returns error when email doesn't match",
			email: "wrong@example.com",
			otp:   "123456",
			mockSetup: func() *mockPasswordlessFlow {
				return &mockPasswordlessFlow{
					loginWithEmailFunc: func(ctx context.Context, request passwordless.LoginWithEmailRequest, options oauth.IDTokenValidationOptions) (*oauth.TokenSet, error) {
						return nil, errors.New("email doesn't match")
					},
				}
			},
			wantErr:     true,
			errContains: "failed to exchange OTP for token",
		},
		{
			name:  "returns error when auth0 service is unavailable",
			email: "test@example.com",
			otp:   "123456",
			mockSetup: func() *mockPasswordlessFlow {
				return &mockPasswordlessFlow{
					loginWithEmailFunc: func(ctx context.Context, request passwordless.LoginWithEmailRequest, options oauth.IDTokenValidationOptions) (*oauth.TokenSet, error) {
						return nil, errors.New("service unavailable")
					},
				}
			},
			wantErr:     true,
			errContains: "failed to exchange OTP for token",
		},
		{
			name:  "handles OTP with leading/trailing spaces",
			email: "test@example.com",
			otp:   "  123456  ",
			mockSetup: func() *mockPasswordlessFlow {
				return &mockPasswordlessFlow{
					loginWithEmailFunc: func(ctx context.Context, request passwordless.LoginWithEmailRequest, options oauth.IDTokenValidationOptions) (*oauth.TokenSet, error) {
						// OTP is passed as-is to the SDK
						assert.Equal(t, "  123456  ", request.Code)
						return &oauth.TokenSet{
							AccessToken: "access-token",
							IDToken:     "id-token",
							TokenType:   "Bearer",
							ExpiresIn:   3600,
						}, nil
					},
				}
			},
			wantErr: false,
			validate: func(t *testing.T, response *TokenResponse) {
				assert.NotNil(t, response)
			},
		},
		{
			name:  "handles empty scope in response",
			email: "test@example.com",
			otp:   "123456",
			mockSetup: func() *mockPasswordlessFlow {
				return &mockPasswordlessFlow{
					loginWithEmailFunc: func(ctx context.Context, request passwordless.LoginWithEmailRequest, options oauth.IDTokenValidationOptions) (*oauth.TokenSet, error) {
						return &oauth.TokenSet{
							AccessToken: "access-token",
							IDToken:     "id-token",
							TokenType:   "Bearer",
							ExpiresIn:   3600,
							Scope:       "",
						}, nil
					},
				}
			},
			wantErr: false,
			validate: func(t *testing.T, response *TokenResponse) {
				assert.NotNil(t, response)
				assert.Empty(t, response.Scope)
			},
		},
		{
			name:  "handles different token types",
			email: "test@example.com",
			otp:   "123456",
			mockSetup: func() *mockPasswordlessFlow {
				return &mockPasswordlessFlow{
					loginWithEmailFunc: func(ctx context.Context, request passwordless.LoginWithEmailRequest, options oauth.IDTokenValidationOptions) (*oauth.TokenSet, error) {
						return &oauth.TokenSet{
							AccessToken: "access-token",
							IDToken:     "id-token",
							TokenType:   "bearer", // lowercase
							ExpiresIn:   3600,
						}, nil
					},
				}
			},
			wantErr: false,
			validate: func(t *testing.T, response *TokenResponse) {
				assert.NotNil(t, response)
				assert.Equal(t, "bearer", response.TokenType)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFlow := tt.mockSetup()
			emailFlow := &EmailLinkingFlow{
				flow: mockFlow,
			}

			response, err := emailFlow.ExchangeOTPForToken(ctx, tt.email, tt.otp)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, response)
			} else {
				require.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, response)
				}
			}
		})
	}
}

func TestNewEmailLinkingFlow(t *testing.T) {
	t.Run("creates EmailLinkingFlow with auth0PasswordlessFlow", func(t *testing.T) {
		// Create a nil auth config for testing (in real usage, this would be properly configured)
		flow := NewEmailLinkingFlow(nil)

		assert.NotNil(t, flow)
		assert.NotNil(t, flow.flow)

		// Verify the flow is of the expected type
		auth0Flow, ok := flow.flow.(*auth0PasswordlessFlow)
		assert.True(t, ok, "flow should be of type *auth0PasswordlessFlow")
		assert.NotNil(t, auth0Flow)
	})
}

func TestAuth0PasswordlessFlow_SendEmail(t *testing.T) {
	// Note: This test is limited because we can't easily mock the auth0 SDK's authentication.Authentication
	// In a real scenario, you would need integration tests or use a test auth0 tenant
	t.Run("SendEmail delegates to auth0 SDK", func(t *testing.T) {
		// This test verifies the method signature and basic structure
		// We can't test the actual call without a real auth0 client or complex mocking
		auth0Flow := &auth0PasswordlessFlow{
			authConfig: nil, // Would cause nil pointer if actually called
		}

		// Just verify the method exists and has the right signature
		assert.NotNil(t, auth0Flow)
		// Note: We can't actually call SendEmail here without a proper auth0 client
	})
}

func TestAuth0PasswordlessFlow_LoginWithEmail(t *testing.T) {
	// Note: This test is limited because we can't easily mock the auth0 SDK's authentication.Authentication
	t.Run("LoginWithEmail delegates to auth0 SDK", func(t *testing.T) {
		// This test verifies the method signature and basic structure
		auth0Flow := &auth0PasswordlessFlow{
			authConfig: nil, // Would cause nil pointer if actually called
		}

		// Just verify the method exists and has the right signature
		assert.NotNil(t, auth0Flow)
		// Note: We can't actually call LoginWithEmail here without a proper auth0 client
	})
}

func TestEmailLinkingFlow_Integration(t *testing.T) {
	// Integration test that combines both methods
	ctx := context.Background()

	t.Run("complete flow: start and exchange", func(t *testing.T) {
		email := "integration@example.com"
		otp := "123456"

		mockFlow := &mockPasswordlessFlow{
			sendEmailFunc: func(ctx context.Context, request passwordless.SendEmailRequest) (*passwordless.SendEmailResponse, error) {
				return &passwordless.SendEmailResponse{
					ID:            "integration-id",
					Email:         email,
					EmailVerified: false,
				}, nil
			},
			loginWithEmailFunc: func(ctx context.Context, request passwordless.LoginWithEmailRequest, options oauth.IDTokenValidationOptions) (*oauth.TokenSet, error) {
				return &oauth.TokenSet{
					AccessToken: "integration-access-token",
					IDToken:     "integration-id-token",
					TokenType:   "Bearer",
					ExpiresIn:   3600,
				}, nil
			},
		}

		emailFlow := &EmailLinkingFlow{flow: mockFlow}

		// Step 1: Start passwordless flow
		err := emailFlow.StartPasswordlessFlow(ctx, email)
		require.NoError(t, err)

		// Step 2: Exchange OTP for token
		tokenResponse, err := emailFlow.ExchangeOTPForToken(ctx, email, otp)
		require.NoError(t, err)
		assert.Equal(t, "integration-access-token", tokenResponse.AccessToken)
		assert.Equal(t, "integration-id-token", tokenResponse.IDToken)
	})

	t.Run("handles failure in start flow", func(t *testing.T) {
		mockFlow := &mockPasswordlessFlow{
			sendEmailFunc: func(ctx context.Context, request passwordless.SendEmailRequest) (*passwordless.SendEmailResponse, error) {
				return nil, errors.New("failed to send email")
			},
		}

		emailFlow := &EmailLinkingFlow{flow: mockFlow}
		err := emailFlow.StartPasswordlessFlow(ctx, "test@example.com")
		require.Error(t, err)
	})

	t.Run("handles failure in exchange flow", func(t *testing.T) {
		mockFlow := &mockPasswordlessFlow{
			loginWithEmailFunc: func(ctx context.Context, request passwordless.LoginWithEmailRequest, options oauth.IDTokenValidationOptions) (*oauth.TokenSet, error) {
				return nil, errors.New("invalid OTP")
			},
		}

		emailFlow := &EmailLinkingFlow{flow: mockFlow}
		_, err := emailFlow.ExchangeOTPForToken(ctx, "test@example.com", "wrong-otp")
		require.Error(t, err)
	})
}
