# Flow C: Self-Service Profile Update via SPA OIDC for Management API audience ('self' Auth0 access)

## Description
OpenID Connect (OIDC) flow for the Auth0 Management API audience, allowing users to manage their own profiles (“self” Auth0 access). This flow shares the same client used by Flow D’s SPA client.

## Sequence Diagram

```mermaid
sequenceDiagram
    participant User as User Browser
    participant SSR as LFX One SSR
    participant NATS as NATS
    participant AuthSvc as Auth Service
    participant Auth0 as Auth0 Authentication API
    participant Auth0Mgmt as Auth0 Management API

    Note over User,Auth0Mgmt: Flow C: 2nd OIDC flow for Management API audience<br/>("self" Auth0 access)

    User->>SSR: Request to update own profile

    SSR->>Auth0: C1: GET /authorize<br/>w/ "LFX One Profile" client<br/>response_type=code<br/>aud=auth0_mgmt<br/>redirect_uri=SSR_callback

    Auth0->>User: Present consent/authentication<br/>(if needed)

    User->>Auth0: Grant consent/authenticate

    Auth0->>SSR: C2: Redirect with auth_code

    SSR->>Auth0: C3: POST /oauth2/token<br/>[authorization_code grant]<br/>w/ "LFX One Profile" client credentials<br/>+ auth_code<br/>aud=auth0_mgmt

    Auth0-->>SSR: C4: id_token_mgmt (IGNORE) +<br/>access_token_mgmt_self

    SSR->>SSR: C5: Validate that<br/>id_token_user (from Flow B).sub<br/>== access_token_mgmt_self.sub

    SSR->>NATS: C6: Publish update request<br/>with access_token_mgmt_self
    Note over NATS,AuthSvc: Auth Service subscribed to NATS subject
    NATS->>AuthSvc: Deliver request

    AuthSvc->>Auth0Mgmt: Update user profile<br/>using access_token_mgmt_self<br/>(user can only update self)

    Auth0Mgmt-->>AuthSvc: Updated profile data
    AuthSvc->>NATS: Publish response
    NATS->>SSR: Deliver response

    SSR-->>User: Render success/updated page

    Note over User,Auth0Mgmt: Auth Service abstracts all Auth0 Management API calls
```

