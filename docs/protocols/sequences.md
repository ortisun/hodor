# Protocol sequences and lifecycles

Participants: **UA** is the browser, **UI** is `auth-ui`, **H** is `hodor-server`. Context names in notes say which crate owns the step.

## 1. Local authentication with conditional MFA

```mermaid
sequenceDiagram
    autonumber
    participant UA as Browser + auth-ui
    participant H as hodor-server
    participant AUT as authentication
    participant CRD as credential
    participant SES as session
    participant DB as PostgreSQL

    UA->>H: POST /interaction/login {return_to}
    H->>AUT: StartAuthentication(tenant, flow, required_acr)
    AUT->>DB: insert AuthTransaction (TTL 10 min)
    H-->>UA: 200 {transaction_id, step: identifier}
    UA->>H: POST /interaction/{id}/steps/identifier {identifier}
    AUT->>AUT: routing rules (home realm discovery)
    H-->>UA: 200 {step: password}
    UA->>H: POST /interaction/{id}/steps/password {password}
    AUT->>AUT: AttemptGuard.check(account, ip)
    AUT->>CRD: VerifyPassword(user or dummy hash)
    CRD-->>AUT: verified | failed
    alt failed
        AUT->>DB: insert LoginAttempt(failed), maybe lock account
        H-->>UA: 401 generic error, same timing
    else verified
        AUT->>AUT: RiskEvaluator(ip, device, history)
        alt MFA required by policy, risk or requested acr
            H-->>UA: 200 {step: mfa, options: [webauthn, totp]}
            UA->>H: POST /interaction/{id}/steps/totp {code}
            AUT->>CRD: VerifyTotp
        end
        AUT->>SES: StartSession(user, acr, amr, device)
        SES->>DB: insert SsoSession
        AUT->>DB: delete AuthTransaction, outbox AuthenticationSucceeded
        H-->>UA: 200 {redirect: return_to}, Set-Cookie __Host-hodor_sid
    end
```

Notes:

- When the account does not exist, `credential` verifies against a fixed dummy hash so that timing does not reveal existence (FR-AUT-03).
- `return_to` is an opaque, server-stored reference, never a URL taken from the request.
- The session ID is rotated on every privilege change (login, step-up).

## 2. OAuth 2.0 Authorization Code with PKCE

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant UA as Browser
    participant H as hodor-server
    participant OAU as oauth
    participant SES as session
    participant KEY as keys

    C->>C: code_verifier, code_challenge = S256(verifier), state
    C->>UA: redirect to /authorize
    UA->>H: GET /t/acme/oauth2/authorize?response_type=code&client_id&redirect_uri&scope&state&code_challenge&code_challenge_method=S256
    H->>OAU: AuthorizeRequest
    OAU->>OAU: validate client, exact redirect_uri, PKCE, scopes, resource
    Note over OAU: Invalid client or redirect_uri: render an error page, never redirect
    OAU->>SES: GetSession(cookie)
    alt no session, or acr / max_age / prompt not satisfied
        H-->>UA: 302 to auth-ui with interaction_id
        Note over UA,H: Sequence 1 runs, then the browser returns to /authorize/resume
    end
    alt consent missing for requested scopes
        H-->>UA: 302 to consent screen
        UA->>H: POST /interaction/{id}/consent {granted_scopes}
    end
    OAU->>OAU: create Grant, AuthorizationCode (hash stored, TTL 60 s)
    H-->>UA: 302 redirect_uri?code&state&iss
    UA->>C: code, state, iss
    C->>C: verify state and iss
    C->>H: POST /t/acme/oauth2/token grant_type=authorization_code, code, code_verifier, redirect_uri + client auth
    H->>OAU: TokenRequest
    OAU->>OAU: authenticate client, load code by hash
    OAU->>OAU: check S256(code_verifier) equals code_challenge, client and redirect_uri match
    alt code already used
        OAU->>OAU: revoke Grant and every token derived from it
        H-->>C: 400 invalid_grant
    else valid
        OAU->>KEY: Sign(access token claims)
        OAU->>OAU: create RefreshTokenFamily, store hash only
        H-->>C: 200 {access_token, refresh_token, expires_in, token_type}
    end
```

Security properties enforced here: PKCE S256 only (`plain` rejected), exact redirect URI comparison, `iss` in the authorization response (RFC 9207), single-use codes, and no code or token ever written to logs.

## 3. OpenID Provider

```mermaid
sequenceDiagram
    autonumber
    participant RP as Relying Party
    participant UA as Browser
    participant H as hodor-server
    participant OAU as oauth
    participant IDN as identity
    participant KEY as keys

    RP->>H: GET /t/acme/.well-known/openid-configuration
    H-->>RP: metadata (issuer, endpoints, supported algs, scopes, claims)
    RP->>H: GET /t/acme/oauth2/jwks
    H-->>RP: JWKS (active and retiring keys)
    RP->>UA: redirect to /authorize with scope=openid profile email, nonce, acr_values, max_age
    UA->>H: GET /authorize
    Note over H: Sequence 2, with the session facts checked against max_age and acr_values
    H-->>UA: 302 redirect_uri?code&state&iss
    RP->>H: POST /token
    OAU->>IDN: GetClaims(user, consented scopes)
    OAU->>OAU: subject = public id or pairwise(sector, user, salt)
    OAU->>KEY: Sign ID Token {iss, sub, aud, exp, iat, auth_time, nonce, acr, amr, sid, at_hash}
    H-->>RP: {id_token, access_token, refresh_token}
    RP->>RP: validate signature, iss, aud, exp, nonce
    RP->>H: GET /t/acme/oauth2/userinfo with bearer token
    H-->>RP: claims for consented scopes
    Note over RP,H: Logout
    RP->>UA: redirect to /logout?id_token_hint&post_logout_redirect_uri&state
    UA->>H: GET /t/acme/oauth2/logout
    H->>OAU: validate hint and registered post_logout_redirect_uri
    H->>H: revoke SsoSession, enqueue back-channel logout
    H-->>UA: 302 post_logout_redirect_uri?state
    H->>RP: POST backchannel_logout_uri {logout_token} from the worker
```

## 4. Social login over OIDC

```mermaid
sequenceDiagram
    autonumber
    participant UA as Browser + auth-ui
    participant H as hodor-server
    participant AUT as authentication
    participant FED as federation
    participant IDP as External IdP
    participant IDN as identity
    participant SES as session

    UA->>H: POST /interaction/{id}/steps/idp {provider_id}
    AUT->>FED: ExternalIdpAuthenticator.begin(transaction, provider)
    FED->>FED: create FederationState {state, nonce, code_verifier}, bound to the transaction
    H-->>UA: 200 {redirect: IdP authorize URL with state, nonce, code_challenge}
    UA->>IDP: GET authorize
    IDP-->>UA: 302 /t/acme/federation/callback/{provider}?code&state
    UA->>H: GET callback
    H->>FED: HandleCallback(code, state, browser cookie)
    FED->>FED: load FederationState by state, check it belongs to this browser, consume it
    FED->>IDP: POST token {code, code_verifier, client auth}
    IDP-->>FED: {id_token, access_token}
    FED->>IDP: GET JWKS (cached, SSRF-safe client)
    FED->>FED: validate signature, iss, aud, exp, nonce
    FED->>FED: apply claim mapping to ExternalIdentity
    FED->>IDN: FindUserByExternalIdentity(provider, subject)
    alt already linked
        IDN-->>FED: user
        FED->>IDN: sync profile per provider policy
    else not linked, JIT allowed and no identifier collision
        FED->>IDN: CreateUser + LinkExternalIdentity
    else not linked, an existing user holds the same email
        FED-->>AUT: LinkingRequired
        Note over UA,H: Sequence 5
    end
    FED-->>AUT: step satisfied {user, amr}
    AUT->>AUT: continue flow (MFA policy for this provider)
    AUT->>SES: StartSession
    H-->>UA: 302 return_to, Set-Cookie
```

Connector-specific handling stays inside the connector: Apple returns user data once in a form post, GitHub needs a separate call for verified emails, Microsoft's multi-tenant issuer is templated by `tid`. For generic OAuth 2.0 providers there is no ID Token; identity comes from the configured UserInfo endpoint and its `subject` field mapping.

## 5. Identity linking

Two entry points: a signed-in user links a new provider from the account console, or a social login collides with an existing account.

```mermaid
sequenceDiagram
    autonumber
    participant UA as Browser
    participant H as hodor-server
    participant FED as federation
    participant AUT as authentication
    participant IDP as External IdP
    participant IDN as identity
    participant NOT as notification

    alt A. Linking from the account console
        UA->>H: POST /account/identities/link {provider_id}
        H->>AUT: require recent authentication (step-up if auth_time is old)
        H->>FED: BeginLink(user, provider)
        FED->>FED: create LinkRequest + FederationState(purpose = link, user)
        UA->>IDP: authorize
        IDP-->>UA: callback with code
        UA->>H: GET callback
        FED->>FED: validate tokens, obtain (provider, subject)
        Note over FED: Proof of control of both identities: active session + fresh login at the IdP
    else B. Collision during social login
        FED->>FED: create LinkRequest(pending, external identity, candidate user)
        H-->>UA: prompt: sign in to the existing account to link
        UA->>H: authenticate as the existing user (password, passkey or another linked IdP)
        Note over FED: Proof of control: IdP login in this transaction + local authentication
    end
    FED->>IDN: is (provider, subject) linked to another user?
    alt linked elsewhere
        H-->>UA: 409 identity already linked
    else free
        FED->>IDN: LinkExternalIdentity(user, provider, subject, method)
        IDN->>IDN: outbox ExternalIdentityLinked
        H->>NOT: notify the user through the primary verified email
        H-->>UA: linked
    end
```

Automatic linking (no local authentication) happens only when all of these hold: the tenant enabled it for this provider; the provider asserts `email_verified = true`; the provider is marked authoritative for that email domain (for example Entra ID for a verified tenant domain); and the local identifier is verified. Otherwise path B applies. Matching on email alone is never enough.

## 6. Token lifecycle

```mermaid
stateDiagram-v2
    [*] --> CodeIssued: authorize approved
    CodeIssued --> Redeemed: token request with valid PKCE
    CodeIssued --> Expired: 60 s elapsed
    CodeIssued --> GrantRevoked: second redemption attempt
    Redeemed --> Active: access token + refresh token generation 1
    Active --> Active: refresh, rotate to generation n+1
    Active --> GrantRevoked: old refresh token presented (reuse)
    Active --> GrantRevoked: revocation endpoint, consent revoked, session revoked, user disabled
    Active --> Expired: refresh token absolute lifetime reached
    GrantRevoked --> [*]
    Expired --> [*]
```

| Artifact | Format | Storage | Default lifetime | Revocation |
|---|---|---|---|---|
| Authorization code | Opaque, 256-bit random | SHA-256 hash | 60 s, single use | Consumed on use |
| Access token | JWT (RFC 9068) signed by the tenant key; opaque as a per-client option | Not stored (JWT) or hash (opaque) | 5 min | Short lifetime; `jti` deny-list for immediate revocation; introspection reflects the grant state |
| Refresh token | Opaque, 256-bit random | SHA-256 hash, family and generation | 30 days absolute, 14 days idle | Rotation; reuse revokes the family |
| ID token | JWT | Not stored | 5 min | Not revocable; it is a login assertion, not a credential |
| PAR `request_uri` | Opaque reference | Row with TTL | 60 s, single use | Consumed on use |
| Device code | Opaque + short user code | Hash | 10 min | Consumed or expired |

Rules:

- Sessions, access tokens and refresh tokens have independent lifetimes. A refresh token issued with `offline_access` survives session end; one without it is revoked with the session.
- Rotation tolerates one benign retry: the immediately previous generation is accepted for a few seconds and returns the same successor, so a client that lost the response does not trip reuse detection.
- Sender-constrained tokens (DPoP, mTLS) carry `cnf`; bearer refresh tokens for public clients are always rotated.
- Signing keys rotate on a schedule. A key leaves the JWKS only after every token it signed has expired.

## 7. Session lifecycle

```mermaid
stateDiagram-v2
    [*] --> Authenticating: AuthTransaction started
    Authenticating --> Active: flow completed, session created
    Authenticating --> [*]: transaction expired or failed
    Active --> Active: activity (touch, throttled)
    Active --> Elevated: step-up, id rotated, acr raised
    Elevated --> Active: elevation window ends
    Active --> Expired: idle timeout or absolute timeout
    Active --> Revoked: user logout, admin revocation, global logout, password change, account disabled
    Elevated --> Revoked: same triggers
    Expired --> [*]
    Revoked --> [*]
```

| Aspect | Rule |
|---|---|
| Cookie | Opaque 256-bit value, `Secure; HttpOnly; SameSite=Lax`; only its hash is stored. On a tenant's own domain: `__Host-hodor_sid` with `Path=/`. On the shared host: `__Secure-hodor_sid` with `Path=/t/{slug}` (the `__Host-` prefix requires `Path=/`) |
| Scope | One SSO session per browser per tenant. The lookup is tenant-scoped, so a cookie presented to another tenant is not found. Path scoping is not a browser security boundary: tenants on the shared host share an origin, see [multi-tenancy](../architecture/multi-tenancy.md#shared-host-caveat) |
| Idle timeout | Default 30 min; `last_activity` is written at most once a minute |
| Absolute timeout | Default 12 h; never extended |
| Client sessions | Created when a client first receives a code in this session; each has a `sid` used in ID Tokens and logout tokens |
| Revocation effects | `SessionRevoked` event → revoke grants bound to the session (except `offline_access`) → enqueue back-channel logout per client session |
| Password change | Revokes all other sessions of the user |
| Concurrent limit | Evaluated at creation: deny, or revoke the oldest |
| Trusted device | Separate long-lived cookie; lets the flow skip MFA when policy allows; never substitutes for the first factor |
