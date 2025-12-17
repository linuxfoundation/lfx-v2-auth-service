# Flow D: Link Social Identity via Regular Web Client (No Audience)

## Description
Regular web client flow for linking social identities by authenticating with the social provider. Uses the LFX One Profile Client and access_token_mgmt_self from Flow C (Management API token) to perform the actual linking operation. This flow uses server-side redirects instead of popup/webmessage pattern.

## Sequence Diagram

```mermaid
sequenceDiagram
    participant Browser as User Browser
    participant SSR as LFX One SSR
    participant Auth0 as Auth0 Authentication API
    participant NATS as NATS
    participant AuthSvc as Auth Service
    participant Auth0Mgmt as Auth0 Management API

    Note over Browser,Auth0Mgmt: Flow D: Link social identity via regular web client<br/>(no audience - just authenticate with social provider)
    
    Browser->>SSR: User clicks "Link Google"<br/>(or other social provider)
    
    SSR->>Auth0: D1: GET /authorize<br/>w/ "LFX One Profile" client<br/>response_type=code<br/>[NO audience]<br/>connection=google-oauth2<br/>redirect_uri=SSR_callback
    
    Auth0->>Browser: Present social provider<br/>authentication
    
    Browser->>Auth0: User authenticates with<br/>social provider
    
    Auth0->>SSR: D2: Redirect with auth_code
    
    SSR->>Auth0: D3: POST /oauth2/token<br/>[authorization_code grant]<br/>w/ "LFX One Profile" client credentials<br/>+ auth_code<br/>[NO audience]
    
    Auth0-->>SSR: D4: access_token_social<br/>for /userinfo (IGNORE) +<br/>id_token_social

    Note over SSR: SSR uses<br/>access_token_mgmt_self from Flow C<br/>(Management API token)

    SSR->>NATS: D5: Publish link request<br/>with access_token_mgmt_self + id_token_social
    Note over NATS,AuthSvc: Auth Service subscribed to NATS subject
    NATS->>AuthSvc: Deliver request

    AuthSvc->>Auth0Mgmt: Link social identity<br/>using access_token_mgmt_self<br/>w/ id_token_social claims
    
    Auth0Mgmt-->>AuthSvc: Identity linked successfully
    AuthSvc->>NATS: Publish response
    NATS->>SSR: Deliver response
    
    SSR-->>Browser: Update UI with<br/>newly linked identity
    
    Note over Browser,Auth0Mgmt: Auth Service abstracts all Auth0 Management API calls
```
