# Flow E: Link Email Identity via Passwordless

## Description
SSR flow for linking additional email addresses to a user's account using passwordless authentication. Uses the LFX One Profile Client for the passwordless OTP flow. All Auth0 API calls (both passwordless and Management API) are made by Auth Service, with SSR communicating via NATS pub/sub pattern. Uses access_token_mgmt_self from Flow C (Management API token) to perform the actual linking operation. The user verifies ownership of the email by entering a one-time verification code in LFX One.

## Sequence Diagram

```mermaid
sequenceDiagram
    participant Browser as User Browser
    participant SSR as LFX One SSR
    participant NATS as NATS
    participant AuthSvc as Auth Service
    participant Auth0 as Auth0 Authentication API
    participant MUA as Mail User Agent
    participant Auth0Mgmt as Auth0 Management API

    Note over Browser,Auth0Mgmt: Flow E: Link email identity via passwordless<br/>(email verification with OTP code using LFX One Profile Client)
    
    Browser->>SSR: User clicks "Add Email"<br/>and enters new email address
    
    SSR->>NATS: E1: Publish passwordless<br/>start request with email
    Note over NATS,AuthSvc: Auth Service subscribed to NATS subject
    NATS->>AuthSvc: Deliver request
    
    AuthSvc->>Auth0: E2: POST /passwordless/start<br/>w/ "LFX One Profile" client credentials<br/>email=new_email@example.com<br/>connection=email<br/>send=code
    
    Auth0->>MUA: Send verification code
    
    MUA->>Browser: User receives code<br/>in their inbox
    
    Auth0-->>AuthSvc: Code sent confirmation
    AuthSvc->>NATS: Publish response
    NATS->>SSR: Deliver response
    SSR-->>Browser: Show "Enter code" UI
    
    Browser->>SSR: User enters code from email<br/>in LFX One
    
    Note over SSR: SSR already has<br/>access_token_mgmt_self from Flow C<br/>(Management API token)

    SSR->>NATS: E3: Publish verification request<br/>with code + access_token_mgmt_self
    NATS->>AuthSvc: Deliver request

    AuthSvc->>Auth0: E4: POST /oauth2/token<br/>[passwordless grant]<br/>w/ "LFX One Profile" client credentials<br/>username=new_email@example.com<br/>otp=verification_code<br/>[NO audience]

    Auth0-->>AuthSvc: E5: access_token_pwdless<br/>for /userinfo (IGNORE) +<br/>id_token_pwdless

    AuthSvc->>AuthSvc: E6: Validate email from<br/>id_token_pwdless matches<br/>the requested email

    AuthSvc->>Auth0Mgmt: E7: Link email identity<br/>using access_token_mgmt_self<br/>w/ id_token_pwdless claims
    
    Auth0Mgmt-->>AuthSvc: Identity linked successfully
    AuthSvc->>NATS: Publish response
    NATS->>SSR: Deliver response
    
    SSR-->>Browser: Update UI with<br/>newly linked email
    
    Note over Browser,Auth0Mgmt: Auth Service abstracts all Auth0 API calls via NATS
```
