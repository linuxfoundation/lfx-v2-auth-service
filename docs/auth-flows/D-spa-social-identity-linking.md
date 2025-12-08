# Flow D: Link Social Identity via Popup/WebMessage (No Audience)

## Description
SPA flow for linking social identities by authenticating with the social provider in a popup. Uses access_token2 from Flow C (Management API token) to perform the actual linking operation.

## Sequence Diagram

```mermaid
sequenceDiagram
    participant Browser as User Browser/SPA
    participant Popup as Auth Popup
    participant Auth0 as Auth0 Authentication API
    participant NATS as NATS
    participant AuthSvc as Auth Service
    participant Auth0Mgmt as Auth0 Management API

    Note over Browser,Auth0Mgmt: Flow D: Link social identity via popup<br/>(no audience - just authenticate with social provider)
    
    Browser->>Browser: User clicks "Link Google"<br/>(or other social provider)
    
    Browser->>Popup: D1: Open popup with<br/>GET /authorize<br/>w/ "LFX One Profile" client<br/>response_type=code<br/>[NO audience]<br/>connection=google-oauth2<br/>(popup/webmessage)
    
    Popup->>Auth0: Forward authorize request
    
    Auth0->>Popup: Present social provider<br/>authentication
    
    Popup->>Auth0: User authenticates with<br/>social provider
    
    Auth0->>Popup: D2: Redirect with auth_code
    
    Popup->>Auth0: D3: POST /oauth2/token<br/>[authorization_code grant]<br/>w/ "LFX One Profile" client credentials<br/>+ auth_code<br/>[NO audience]
    
    Auth0-->>Popup: D4: access_token_social<br/>for /userinfo (IGNORE) +<br/>id_token_social

    Popup->>Browser: D5: Post message with<br/>id_token_social<br/>(webmessage/postMessage)

    Note over Browser: Browser uses<br/>access_token_mgmt_self from Flow C<br/>(Management API token)

    Browser->>NATS: D6: Publish link request<br/>with access_token_mgmt_self + id_token_social
    Note over NATS,AuthSvc: Auth Service subscribed to NATS subject
    NATS->>AuthSvc: Deliver request

    AuthSvc->>Auth0Mgmt: Link social identity<br/>using access_token_mgmt_self<br/>w/ id_token_social claims
    
    Auth0Mgmt-->>AuthSvc: Identity linked successfully
    AuthSvc->>NATS: Publish response
    NATS->>Browser: Deliver response
    
    Browser->>Browser: Update UI with<br/>newly linked identity
    
    Note over Browser,Auth0Mgmt: Auth Service abstracts all Auth0 Management API calls
```
