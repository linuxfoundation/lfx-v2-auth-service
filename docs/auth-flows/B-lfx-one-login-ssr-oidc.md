# Flow B: LFX One Login SSR OIDC Sequence Diagram

## Description
LFX One login using SSR (server-side rendering) with privileged OIDC flow. This flow authenticates the user and obtains access tokens for the LFX v2 API (Traefik/Heimdall).

## Sequence Diagram

```mermaid
sequenceDiagram
    participant User as User Browser
    participant SSR as LFX One SSR
    participant Auth0 as Auth0 Authentication API
    participant LFXv2 as LFX v2 API<br/>(Traefik/Heimdall)

    Note over User,LFXv2: Flow B: LFX One login - SSR [privileged] OIDC,<br/>with LFX v2 API audience
    
    User->>SSR: Initiate login
    
    SSR->>Auth0: B1: GET /authorize<br/>w/ SSR client<br/>response_type=code<br/>aud=lfxv2<br/>redirect_uri=SSR_callback
    
    Auth0->>User: Present login page/<br/>authentication challenge
    
    User->>Auth0: Enter credentials/<br/>authenticate
    
    Auth0->>SSR: B2: Redirect with auth_code
    
    SSR->>Auth0: B3: POST /oauth2/token<br/>[authorization_code grant]<br/>w/ SSR client credentials<br/>+ auth_code<br/>aud=lfxv2
    
    Auth0-->>SSR: B4: id_token + access_token1<br/>(for LFX v2 API audience)
    
    Note over SSR: SSR stores tokens in session
    
    SSR->>LFXv2: B5: API request with<br/>access_token1
    
    LFXv2-->>SSR: API response
    
    SSR-->>User: Render authenticated page
    
    Note over User,LFXv2: access_token1 is used for all LFX v2 API calls
```
