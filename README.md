<p align="center">
  <img src="docs/images/logo/hodor.png" alt="The Hodor logo: someone braced against a heavy wooden door, holding it shut" width="260">
</p>

# Hodor

**Identity, authentication and authorization for many tenants, written in Rust.**

Hodor is one server that knows who people are and lets them in. A company runs it once and gives each customer, product or environment a **tenant** of its own: its own users, its own sign-in page, its own identity providers, its own audit log, and nothing shared with any other tenant.

The goal is a complete identity platform: identity provider, OAuth 2.x authorization server, OpenID Provider, federation broker and policy decision point. It is built in phases. This page says what exists today, explains the ideas the code is built on, and draws the flows that run through it. Every section links to the page in [`docs/`](docs/README.md) that specifies it; when this page and `docs/` disagree, `docs/` is right.

<p align="center">
  <img src="docs/images/sign-in.png" alt="The hosted sign-in page of the tenant acme: an email address or username, then a choice of the development identity provider or the company directory" width="380">
</p>
<p align="center"><sub>The sign-in page of the tenant <code>acme</code> on the development stack, offering a password, an OpenID Connect provider and a directory.</sub></p>

## Contents

- [Where it stands](#where-it-stands)
- [Hodor at a glance](#hodor-at-a-glance)
- [Concepts](#concepts)
- [How it is built](#how-it-is-built)
- [How tenants are kept apart](#how-tenants-are-kept-apart)
- [Flows](#flows)
  - [Signing in with a password](#signing-in-with-a-password)
  - [Registering through the mailbox](#registering-through-the-mailbox)
  - [Signing in through an OpenID Connect provider](#signing-in-through-an-openid-connect-provider)
  - [Deciding who the person is](#deciding-who-the-person-is)
  - [Signing in through a SAML identity provider](#signing-in-through-a-saml-identity-provider)
  - [Signing in through a directory](#signing-in-through-a-directory)
  - [The life of a session](#the-life-of-a-session)
  - [From a change to the audit log](#from-a-change-to-the-audit-log)
  - [Planned: Hodor as an OpenID Provider](#planned-hodor-as-an-openid-provider)
- [Try it](#try-it)
- [Repository layout](#repository-layout)
- [Documentation map](#documentation-map)
- [Development](#development)
- [Contributing](#contributing)

## Where it stands

Hodor lets people **into** a tenant. It does not yet let applications **ask** Hodor who someone is: the OAuth authorization server and the OpenID Provider are the next phase. [Progress](docs/product/progress.md) tracks every issue.

| Capability | Status |
|---|---|
| Tenants, each isolated in the database by row-level security | Built ([Milestone 1](docs/product/epics.md#milestone-1-walking-skeleton)) |
| Registration and password recovery, decided by who reads the mailbox | Built |
| Sign-in with an email address and a password, with lockout on repeated failures | Built |
| Sessions, sign-out, ending one's other sessions | Built |
| Sign-in through an OpenID Connect provider: Google, Microsoft Entra ID, Keycloak, any compliant provider | Built ([Milestone 2](docs/product/epics.md#milestone-2-signing-in-with-external-identities)). Hodor is the relying party |
| Sign-in through GitHub | Built |
| Sign-in through an LDAP directory: OpenLDAP, Active Directory | Built. Tried against OpenLDAP only |
| Sign-in through a SAML identity provider: Entra ID, Okta, Active Directory Federation Services, Keycloak, Shibboleth | Built. Needs a review from outside the project before production ([Decision 0019](docs/decisions/0019-saml-signature-verification.md)) |
| Administration interface (HTTP, with an OpenAPI document) and the command-line tool | Built: users, sessions, identity providers, audit log |
| Admin console in the browser | Built: users, audit records, identity providers |
| Audit log, chained with SHA-256 so that a changed record is found | Built |
| Email in English and Brazilian Portuguese, logs, metrics and traces over OpenTelemetry | Built |
| OAuth 2.x authorization server and OpenID Provider: clients, authorization code with PKCE, tokens, discovery, consent, logout | Planned: Phase 2 |
| Multi-factor authentication, passkeys, step-up | Planned: Phase 4 |
| Authorization engine with policies, Open Policy Agent | Planned: Phase 5 |
| SCIM provisioning, Hodor as a SAML identity provider | Planned: Phase 6 |

The [roadmap](docs/product/roadmap.md) has the phases and the order they are built in.

<p align="center">
  <img src="docs/images/admin-console.png" alt="The admin console of the tenant acme: the users screen, listing five users with their status, email addresses and whether each address is verified">
</p>
<p align="center"><sub>The admin console: a tenant administrator's view of the tenant's users. It has no sign-in of its own; it recognizes the session from the hosted pages.</sub></p>

## Hodor at a glance

Solid lines exist today; dashed lines are planned.

```mermaid
flowchart LR
    people(["People<br/>sign in · register · recover"]):::person
    administrators(["Administrators<br/>console · interface · command line"]):::person
    applications(["Applications<br/>Phase 2"]):::planned

    hodor["Hodor<br/>one installation<br/>many tenants"]:::hodor

    providers["Identity providers<br/>OpenID Connect · GitHub<br/>SAML · LDAP"]:::outside
    mail["Mail server"]:::outside
    database[("PostgreSQL")]:::store

    people --> hodor
    administrators --> hodor
    applications -.->|"OAuth · OpenID Connect"| hodor
    hodor -->|"asks who people are"| providers
    hodor -->|"sends links"| mail
    hodor -->|"keeps everything"| database

    classDef person fill:#fff4d6,stroke:#c99a06,color:#3b2c00
    classDef hodor fill:#007b92,stroke:#005566,color:#ffffff
    classDef part fill:#e0f2f5,stroke:#007b92,color:#06323b
    classDef outside fill:#f1f3f5,stroke:#868e96,color:#212529
    classDef store fill:#e7f0ff,stroke:#3b6fd4,color:#0d2350
    classDef planned fill:#ffffff,stroke:#868e96,color:#495057,stroke-dasharray:5 4
    classDef good fill:#d8f5df,stroke:#2b8a3e,color:#0b3d17
    classDef bad fill:#ffe3e3,stroke:#c92a2a,color:#4a0d0d
    classDef ask fill:#ffffff,stroke:#495057,color:#212529
```

## Concepts

These are the words the code and the documentation use. Each has one meaning. The full vocabulary is in the [domain model](docs/architecture/domain-model.md#ubiquitous-language).

```mermaid
flowchart TB
    tenant["Tenant<br/>acme"]:::hodor
    provider["Identity provider<br/>openid_connect · github · ldap · saml"]:::outside
    user["User"]:::part
    audit[("Audit log<br/>SHA-256 chain")]:::store
    identifier["Login identifier<br/>email address"]:::part
    password["Password<br/>Argon2id hash"]:::part
    external["External identity<br/>provider + subject"]:::part
    signin["Sign-in in progress<br/>one browser · ten minutes"]:::part
    pending["Pending authorization<br/>used once"]:::part
    session["Session<br/>token stored as a hash"]:::store

    tenant -->|"has"| user
    tenant -->|"trusts up to 20"| provider
    tenant -->|"keeps"| audit
    user -->|"found by"| identifier
    user -->|"proves itself with"| password
    user -->|"linked to"| external
    provider -->|"vouches for"| external
    signin -->|"while away, keeps"| pending
    signin -->|"ends in"| session
    session -->|"belongs to"| user

    classDef person fill:#fff4d6,stroke:#c99a06,color:#3b2c00
    classDef hodor fill:#007b92,stroke:#005566,color:#ffffff
    classDef part fill:#e0f2f5,stroke:#007b92,color:#06323b
    classDef outside fill:#f1f3f5,stroke:#868e96,color:#212529
    classDef store fill:#e7f0ff,stroke:#3b6fd4,color:#0d2350
    classDef planned fill:#ffffff,stroke:#868e96,color:#495057,stroke-dasharray:5 4
    classDef good fill:#d8f5df,stroke:#2b8a3e,color:#0b3d17
    classDef bad fill:#ffe3e3,stroke:#c92a2a,color:#4a0d0d
    classDef ask fill:#ffffff,stroke:#495057,color:#212529
```

| Concept | What it is |
|---|---|
| **Tenant** | The boundary of isolation. Its own users, sessions, identity providers, settings and audit log; nothing crosses to another tenant. Addressed by a slug in the path: `/t/acme`. A special **system** tenant holds the operators of the installation |
| **User** | A person known to one tenant. The same email address in two tenants is two unrelated users |
| **Login identifier** | What a user is found by when signing in: an email address today. Normalized and unique in the tenant |
| **Credential** | What a user proves who they are with. Today a password, hashed with Argon2id, never stored or logged in the clear |
| **Identity provider** | Something outside Hodor that knows people and can vouch for them. Four kinds: `openid_connect`, `github`, `ldap`, `saml`. Each tenant configures its own; its client secret is encrypted and never read back |
| **External identity** | One person as one identity provider knows them: the provider and its own unchanging identifier for the person, the **subject**. Linked to at most one user, and found by provider and subject only, **never by email address** |
| **Flow** | The steps a sign-in goes through, stored as data and run by one engine. The built-in flow is an identifier, then a password. A flow may also list **alternatives**, such as an identity provider, that complete the sign-in in one step |
| **Authenticator** | What performs one step: `identifier`, `password`, or an identity provider of the federation context |
| **Sign-in in progress** | One run of a flow, tied to the one browser that started it by a cookie only that browser holds. Lives ten minutes |
| **Pending authorization** | What Hodor keeps while the person is away at an identity provider, to recognize the answer when they come back. Belongs to one sign-in and is used once |
| **Session** | The record that a user signed in from a browser, with when and how. Ends on an idle timeout, on an absolute expiry that never moves, or when revoked. The browser holds a random token; Hodor stores only its hash |
| **Event** | The record that something changed, written in the same transaction as the change. Events carry no personal data |
| **Audit record** | One event, as kept forever in the tenant's audit log. Each record holds the hash of the one before it |
| **Role** | What an administrator may do through the administration interface and the console. Two fixed roles today; policies come in Phase 5 |

## How it is built

Hodor is a **modular monolith**: one Rust workspace in which each bounded context is a crate with its own rules, and anything outside the process (the database, cryptography, mail, HTTP, LDAP) is reached through a port that an adapter crate implements. Three binaries are assembled from the same crates. The [architecture overview](docs/architecture/overview.md) and [the crates](docs/architecture/crates.md) say more; [Decision 0001](docs/decisions/0001-modular-monolith-clean-architecture.md) says why.

```mermaid
flowchart TB
    apps["Binaries<br/>server · worker · cli"]:::hodor
    protocol["protocol-http<br/>routes · cookies · CSRF"]:::part
    adapters["Adapters<br/>postgres · crypto<br/>http · ldap · smtp<br/>observability"]:::outside
    contexts["Bounded contexts<br/>tenant · identity<br/>credential · session<br/>authentication · federation<br/>saml · authorization<br/>audit · notification"]:::part
    kernel["kernel<br/>identifiers · TenantContext<br/>ports · events"]:::store

    apps --> protocol --> contexts --> kernel
    apps --> adapters
    adapters -->|"implement the ports of"| contexts

    classDef person fill:#fff4d6,stroke:#c99a06,color:#3b2c00
    classDef hodor fill:#007b92,stroke:#005566,color:#ffffff
    classDef part fill:#e0f2f5,stroke:#007b92,color:#06323b
    classDef outside fill:#f1f3f5,stroke:#868e96,color:#212529
    classDef store fill:#e7f0ff,stroke:#3b6fd4,color:#0d2350
    classDef planned fill:#ffffff,stroke:#868e96,color:#495057,stroke-dasharray:5 4
    classDef good fill:#d8f5df,stroke:#2b8a3e,color:#0b3d17
    classDef bad fill:#ffe3e3,stroke:#c92a2a,color:#4a0d0d
    classDef ask fill:#ffffff,stroke:#495057,color:#212529
```

The rules that hold everywhere:

- **A context sees another only through its public facade**, and the allowed edges between crates form a fixed graph. An architecture test fails the build when a crate reaches for something it may not.
- **Every port that touches tenant data takes a `TenantContext`.** There is no way to ask for "all users"; only for the users of one tenant.
- **A change and its events are stored in one transaction**, through an outbox. The worker delivers them afterwards: to the audit log, to email. Nothing is lost and nothing is done twice ([Decision 0003](docs/decisions/0003-context-communication.md)).
- **Secrets never reach a log, a trace, an error message or an event.** Tokens are stored as hashes; client secrets are sealed with AES-256-GCM, bound to their tenant and purpose ([secrets at rest](docs/security/secrets-at-rest.md)).
- **Every request Hodor makes to the outside goes through one guarded client**: HTTPS only, public addresses only, no redirects, bounded in time and size ([outbound HTTP](docs/security/outbound-http.md)).

What runs in the development stack:

```mermaid
flowchart TB
    browser(["Browser"]):::person

    subgraph hodor["Hodor"]
        cli["hodor-cli"]:::hodor
        server["hodor-server"]:::hodor
        worker["hodor-worker"]:::hodor
    end

    database[("PostgreSQL<br/>state · outbox · audit")]:::store
    providers["Identity providers<br/>directories"]:::outside
    mail["Mail server"]:::outside
    telemetry["VictoriaMetrics<br/>VictoriaTraces"]:::outside

    browser -->|"HTTPS"| server
    cli --> database
    server --> database
    worker --> database
    server --> providers
    worker -->|"SMTP"| mail
    worker -.->|"OpenTelemetry"| telemetry
    server -.-> telemetry

    classDef person fill:#fff4d6,stroke:#c99a06,color:#3b2c00
    classDef hodor fill:#007b92,stroke:#005566,color:#ffffff
    classDef part fill:#e0f2f5,stroke:#007b92,color:#06323b
    classDef outside fill:#f1f3f5,stroke:#868e96,color:#212529
    classDef store fill:#e7f0ff,stroke:#3b6fd4,color:#0d2350
    classDef planned fill:#ffffff,stroke:#868e96,color:#495057,stroke-dasharray:5 4
    classDef good fill:#d8f5df,stroke:#2b8a3e,color:#0b3d17
    classDef bad fill:#ffe3e3,stroke:#c92a2a,color:#4a0d0d
    classDef ask fill:#ffffff,stroke:#495057,color:#212529
    style hodor fill:#007b9214,stroke:#007b92,stroke-width:1px,color:#007b92
```

## How tenants are kept apart

A tenant is decided **once per request, from the address and nothing else**. A tenant identifier in a body, a header or a query parameter is never believed. Every credential presented afterwards, whether a session cookie, a sign-in cookie, an access token or a link from a message, is looked up inside that tenant; if it belongs to another, it is not found. Underneath, PostgreSQL enforces the same thing with row-level security, so a query that forgot the tenant returns nothing rather than another tenant's rows. Details: [multi-tenancy](docs/architecture/multi-tenancy.md) and [Decision 0006](docs/decisions/0006-tenant-isolation.md).

```mermaid
flowchart LR
    request(["GET /t/acme/..."]):::person
    known{"acme serves<br/>requests?"}:::ask
    context["TenantContext<br/>of acme"]:::part
    lookup["Cookie, token or link<br/>looked up in acme only"]:::part
    rls[("Row-level security<br/>rows of acme only")]:::store
    gone["404<br/>as if it did not exist"]:::bad
    suspended["403<br/>tenant.suspended"]:::bad

    request --> known
    known -->|"yes"| context --> lookup --> rls
    known -->|"unknown · provisioning · deleted"| gone
    known -->|"suspended · pending deletion"| suspended

    classDef person fill:#fff4d6,stroke:#c99a06,color:#3b2c00
    classDef hodor fill:#007b92,stroke:#005566,color:#ffffff
    classDef part fill:#e0f2f5,stroke:#007b92,color:#06323b
    classDef outside fill:#f1f3f5,stroke:#868e96,color:#212529
    classDef store fill:#e7f0ff,stroke:#3b6fd4,color:#0d2350
    classDef planned fill:#ffffff,stroke:#868e96,color:#495057,stroke-dasharray:5 4
    classDef good fill:#d8f5df,stroke:#2b8a3e,color:#0b3d17
    classDef bad fill:#ffe3e3,stroke:#c92a2a,color:#4a0d0d
    classDef ask fill:#ffffff,stroke:#495057,color:#212529
```

A suite of tests on the real server creates two tenants that share a person's email address and password, and shows that cookies, sign-ins, access tokens, links and identifiers of one are each refused by the other ([the cross-tenant suite](docs/architecture/multi-tenancy.md#the-cross-tenant-suite)).

## Flows

Every diagram below matches what the server does today, except the last one, which is planned. Paths are relative to the tenant, `/t/{slug}`. The detailed rules for each flow are on the page linked under it.

### Signing in with a password

The hosted pages never decide anything. They ask the [interaction interface](docs/api/interaction-api.md) which step comes next, show the form for it, and submit what the person typed.

```mermaid
sequenceDiagram
    autonumber
    actor Person
    participant Pages as Hosted pages
    box rgba(0, 123, 146, 0.10) Hodor
        participant Interaction as Interaction interface
        participant Authentication as authentication
        participant Credential as credential
        participant Session as session
    end

    rect rgba(0, 123, 146, 0.06)
        Note over Person,Session: Start
        Person->>Pages: open /account/sign-in
        Pages->>Interaction: POST /interaction/sign-in
        Interaction->>Authentication: start the tenant's flow
        Interaction-->>Pages: pending · step identifier<br/>sign-in cookie · CSRF token
    end

    rect rgba(0, 123, 146, 0.06)
        Note over Person,Session: Identifier
        Person->>Pages: email address
        Pages->>Interaction: POST …/steps/identifier
        Interaction->>Authentication: note who it belongs to, if anyone
        Interaction-->>Pages: pending · step password
    end

    rect rgba(0, 123, 146, 0.06)
        Note over Person,Session: Password
        Person->>Pages: password
        Pages->>Interaction: POST …/steps/password
        Note over Authentication: locked out? stop here
        Authentication->>Credential: verify
        alt right password and the user may sign in
            Authentication->>Session: start a session
            Interaction-->>Pages: completed · session cookie
        else anything else
            Interaction-->>Pages: rejected · the same answer every time
        end
    end
```

What protects it:

- The sign-in belongs to the browser that started it: the cookie holds a secret only that browser has, and is `HttpOnly`, `Secure`, `SameSite=Strict` and scoped to the tenant's interaction paths.
- Every request that changes something carries a CSRF token derived from that secret, and a request naming another origin is refused.
- After five wrong passwords in fifteen minutes the identifier is locked out for a minute, and each further lockout doubles, up to an hour. The lockout applies whether or not the identifier belongs to anyone, so it reveals nothing; while it lasts no password is checked. Attempts are also counted per address.

The answers a sign-in gives move through four states:

```mermaid
stateDiagram-v2
    direction LR
    [*] --> pending: start
    pending: pending · next step asked
    pending --> rejected: step refused
    rejected --> pending: try again
    rejected --> failed: too many rejections
    pending --> completed: last step satisfied
    pending --> [*]: expired · abandoned
    completed --> [*]
    failed --> [*]

    classDef ok fill:#d8f5df,stroke:#2b8a3e,color:#0b3d17
    classDef ko fill:#ffe3e3,stroke:#c92a2a,color:#4a0d0d
    classDef wait fill:#e0f2f5,stroke:#007b92,color:#06323b
    class completed ok
    class failed,rejected ko
    class pending wait
```

Specified in [the authentication context](docs/architecture/contexts/authentication.md) and [the interaction interface](docs/api/interaction-api.md#signing-in).

### Registering through the mailbox

**Only the mailbox decides.** Asking to register answers the same whoever the address belongs to; the message that arrives is what differs, and only the owner of the mailbox reads it. The password is chosen at the end, by whoever holds the link. Password recovery follows the same shape, and a recovery ends every session of the user.

```mermaid
sequenceDiagram
    autonumber
    actor Person
    participant Pages as Hosted pages
    box rgba(0, 123, 146, 0.10) Hodor
        participant Server as hodor-server
        participant Worker as hodor-worker
    end
    box rgba(134, 142, 150, 0.12) Outside
        participant Mailbox as Mailbox
    end

    rect rgba(0, 123, 146, 0.06)
        Note over Person,Mailbox: Ask
        Person->>Pages: email address
        Pages->>Server: POST /interaction/registration
        alt no account with that address
            Note over Server: token (hash only) + message with a link
        else already registered
            Note over Server: message without a link
        end
        Server-->>Pages: 202 · always the same
    end

    Worker->>Mailbox: deliver the queued message

    rect rgba(0, 123, 146, 0.06)
        Note over Person,Mailbox: Finish
        Person->>Pages: follow the link
        Note right of Pages: token in the fragment,<br/>never sent to a server
        Pages->>Server: POST …/registration/complete · token + password
        Note over Server: use the token once · create the user · set the password
        Server-->>Pages: 204 · now sign in
    end
```

Specified in [registration and password recovery](docs/architecture/contexts/authentication.md#registration-and-password-recovery).

### Signing in through an OpenID Connect provider

For a provider of the kind `openid_connect`, **Hodor is the relying party**: it sends the person to the provider and, when they come back, asks the provider who they are. Signing in this way is an alternative of the tenant's flow, and ends in the same session as a password.

Hodor makes three values of 256 random bits for each attempt: `state`, which lets it recognize the answer it is waiting for; `nonce`, which the provider puts inside the ID token to tie it to this request; and a PKCE verifier, whose SHA-256 hash is sent so that only Hodor can exchange the code.

```mermaid
sequenceDiagram
    autonumber
    actor Person
    participant Pages as Hosted pages
    box rgba(0, 123, 146, 0.10) Hodor
        participant Interaction as Interaction interface
        participant Federation as federation
    end
    box rgba(134, 142, 150, 0.12) Outside
        participant Provider as OpenID Connect provider
    end

    rect rgba(0, 123, 146, 0.06)
        Note over Person,Provider: Choose a provider
        Person->>Pages: Continue with Google
        Pages->>Interaction: POST …/providers/google
        Federation->>Provider: discovery document and keys · cached an hour
        Note over Federation: state · nonce · PKCE verifier<br/>keep a pending authorization
        Interaction-->>Pages: address at the provider
    end

    rect rgba(0, 123, 146, 0.06)
        Note over Person,Provider: At the provider
        Pages->>Provider: authorize · state · nonce · code_challenge S256
        Person->>Provider: sign in
        Provider-->>Pages: /account/providers/google/callback · code · state
    end

    rect rgba(0, 123, 146, 0.06)
        Note over Person,Provider: Finish
        Pages->>Interaction: POST …/google/callback · code · state
        Note over Federation: take the pending authorization once · state must match
        Federation->>Provider: exchange the code · verifier · client secret
        Provider-->>Federation: ID token
        Note over Federation: check the ID token · decide who the person is
        alt accepted
            Interaction-->>Pages: completed · session cookie
        else refused
            Interaction-->>Pages: rejected · reason to the audit log only
        end
    end
```

The ID token is believed only after every check passes. The algorithms accepted are `RS256`, `PS256` and `ES256`; `none` and the `HS` family are refused, RSA keys under 2048 bits are refused, and the issuer is compared character by character. Microsoft Entra ID must be configured with the organization's own tenant identifier, never `common`. GitHub issues no ID token, so for the kind `github` Hodor asks GitHub's interface for the person by number and for an address that is both primary and verified.

Specified in [the federation context](docs/architecture/contexts/federation.md#asking-an-openid-connect-provider-who-somebody-is), with [recipes](docs/architecture/contexts/federation.md#recipes) for each provider.

A tenant administrator adds providers through the administration interface, the command-line tool or the console. The answer gives the callback address to register at the provider; the client secret is written once and never shown again.

<p align="center">
  <img src="docs/images/identity-providers.png" alt="The identity providers screen of the admin console, listing an OpenID Connect provider with the alias development and an LDAP directory with the alias directory, both enabled and both creating accounts for new people">
</p>

### Deciding who the person is

Whatever the kind of provider, the answer ends in the same decision. The rule that matters most is the last branch: **an external identity is never let into an existing account because of an email address**. An address at a provider proves control of a mailbox at best; letting it in would make every provider a tenant adds a way into every account of the tenant.

```mermaid
flowchart TB
    start(["The provider vouched for a subject"]):::person
    linked{"Linked to<br/>a user?"}:::ask
    allowed{"May that user<br/>sign in?"}:::ask
    creates{"Provider<br/>creates users?"}:::ask
    vouched{"Address vouched for,<br/>or provider trusts email?"}:::ask
    taken{"Address already<br/>has an account?"}:::ask

    signin["Sign the user in"]:::good
    create["Create the user and the link<br/>in one transaction · sign in"]:::good
    refuseUser["Refuse<br/>suspended · pending · deactivated"]:::bad
    refuseCreate["Refuse"]:::bad
    refuseAddress["Refuse<br/>no usable address"]:::bad
    refuseTaken["Refuse<br/>never opened by address"]:::bad

    start --> linked
    linked -->|"yes"| allowed
    allowed -->|"yes"| signin
    allowed -->|"no"| refuseUser
    linked -->|"no"| creates
    creates -->|"no"| refuseCreate
    creates -->|"yes"| vouched
    vouched -->|"no"| refuseAddress
    vouched -->|"yes"| taken
    taken -->|"yes"| refuseTaken
    taken -->|"no"| create

    classDef person fill:#fff4d6,stroke:#c99a06,color:#3b2c00
    classDef hodor fill:#007b92,stroke:#005566,color:#ffffff
    classDef part fill:#e0f2f5,stroke:#007b92,color:#06323b
    classDef outside fill:#f1f3f5,stroke:#868e96,color:#212529
    classDef store fill:#e7f0ff,stroke:#3b6fd4,color:#0d2350
    classDef planned fill:#ffffff,stroke:#868e96,color:#495057,stroke-dasharray:5 4
    classDef good fill:#d8f5df,stroke:#2b8a3e,color:#0b3d17
    classDef bad fill:#ffe3e3,stroke:#c92a2a,color:#4a0d0d
    classDef ask fill:#ffffff,stroke:#495057,color:#212529
```

Connecting an external identity to an existing account needs proof of both, which comes with the account console. Specified in [who the person is](docs/architecture/contexts/federation.md#who-the-person-is).

### Signing in through a SAML identity provider

For a provider of the kind `saml`, **Hodor is the service provider**. The identity provider's site makes the browser post a signed response to Hodor. Because that request comes from another site, it does not carry the sign-in cookie, so the response is only kept there; it is read and checked when Hodor's own page finishes the sign-in. A **receipt**, given only to the browser that posted the response, stops an attacker from finishing their own sign-in with a victim's response.

```mermaid
sequenceDiagram
    autonumber
    actor Person
    participant Pages as Hosted pages
    box rgba(0, 123, 146, 0.10) Hodor
        participant Interaction as Interaction interface
        participant Saml as saml
    end
    box rgba(134, 142, 150, 0.12) Outside
        participant Provider as SAML identity provider
    end

    rect rgba(0, 123, 146, 0.06)
        Note over Person,Provider: Send the person
        Pages->>Interaction: POST …/providers/okta
        Note over Interaction: pending authorization · relay state · request identifier
        Interaction-->>Pages: single sign-on address · SAMLRequest · RelayState
        Pages->>Provider: go there
        Person->>Provider: sign in
    end

    rect rgba(0, 123, 146, 0.06)
        Note over Person,Provider: Keep the response
        Provider->>Interaction: POST …/okta/saml · SAMLResponse · RelayState<br/>posted from the provider's site, without the sign-in cookie
        Note over Interaction: keep it unread · hash of a new receipt
        Interaction-->>Pages: 303 to the callback page · state · receipt
    end

    rect rgba(0, 123, 146, 0.06)
        Note over Person,Provider: Finish on Hodor's own page
        Pages->>Interaction: POST …/okta/callback · state · receipt · sign-in cookie
        Note over Interaction: take the pending authorization once · check the receipt
        Interaction->>Saml: check the response against this browser's request
        Saml-->>Interaction: subject · email · name, or why not
        Interaction-->>Pages: completed or rejected
    end
```

Signatures are verified with `xml-sec` behind a narrow profile of Hodor's own ([Decision 0019](docs/decisions/0019-saml-signature-verification.md)). Every case of the [SAML attack corpus](docs/security/saml-attack-corpus.md) is a test. Specified in [signing in through a SAML identity provider](docs/architecture/contexts/federation.md#signing-in-through-a-saml-identity-provider).

### Signing in through a directory

For a provider of the kind `ldap`, nobody leaves Hodor's page. The person types what the directory knows them by and their password; Hodor asks the directory. Only directories on the operator's list, `HODOR_DIRECTORY_HOSTS`, can ever be reached.

```mermaid
sequenceDiagram
    autonumber
    actor Person
    participant Pages as Hosted pages
    box rgba(0, 123, 146, 0.10) Hodor
        participant Interaction as Interaction interface
    end
    box rgba(134, 142, 150, 0.12) Outside
        participant Directory as LDAP directory
    end

    Person->>Pages: username and password
    Pages->>Interaction: POST …/providers/corporate/password
    Note over Interaction: empty password? refuse<br/>count the attempt · locked out? refuse
    Interaction->>Directory: bind as Hodor · search with the escaped username
    Directory-->>Interaction: exactly one entry
    Interaction->>Directory: bind as that entry with the password
    Directory-->>Interaction: success
    Note over Interaction: subject = the entry's unchanging identifier<br/>decide who the person is
    Interaction-->>Pages: completed or rejected
```

Specified in [signing in through a directory](docs/architecture/contexts/federation.md#signing-in-through-a-directory).

### The life of a session

A session is decided on the server every time it is presented; the cookie holds nothing but a random token. Expiry needs nothing to run: it is computed from the stored times.

```mermaid
stateDiagram-v2
    direction LR
    [*] --> Active: sign-in completes
    Active --> Expired: idle 30 min<br/>or 12 h absolute
    Active --> Revoked: sign out · administrator<br/>password recovered
    Expired --> [*]
    Revoked --> [*]

    classDef ok fill:#d8f5df,stroke:#2b8a3e,color:#0b3d17
    classDef ko fill:#ffe3e3,stroke:#c92a2a,color:#4a0d0d
    classDef idle fill:#f1f3f5,stroke:#868e96,color:#212529
    class Active ok
    class Revoked ko
    class Expired idle
```

Specified in [the session context](docs/architecture/contexts/session.md).

### From a change to the audit log

Every change is stored with its event in one transaction. The worker turns each event into one audit record in the transaction that marks the event delivered, so an event is recorded exactly once. Each record holds the hash of the record before it, so a changed, removed or inserted record breaks the chain, and `hodor-cli audit verify` finds it.

```mermaid
flowchart TB
    change["A use case<br/>changes something"]:::part
    outbox[("Outbox")]:::store
    worker["hodor-worker"]:::hodor

    subgraph log["Audit log of the tenant"]
        direction LR
        first["Record 1<br/>previous: zeros"]:::outside
        second["Record 2<br/>previous: hash of 1"]:::outside
        third["Record 3<br/>previous: hash of 2"]:::outside
        first --> second --> third
    end

    change -->|"change + event<br/>one transaction"| outbox
    outbox --> worker
    worker -->|"append + mark delivered<br/>one transaction"| log

    classDef person fill:#fff4d6,stroke:#c99a06,color:#3b2c00
    classDef hodor fill:#007b92,stroke:#005566,color:#ffffff
    classDef part fill:#e0f2f5,stroke:#007b92,color:#06323b
    classDef outside fill:#f1f3f5,stroke:#868e96,color:#212529
    classDef store fill:#e7f0ff,stroke:#3b6fd4,color:#0d2350
    classDef planned fill:#ffffff,stroke:#868e96,color:#495057,stroke-dasharray:5 4
    classDef good fill:#d8f5df,stroke:#2b8a3e,color:#0b3d17
    classDef bad fill:#ffe3e3,stroke:#c92a2a,color:#4a0d0d
    classDef ask fill:#ffffff,stroke:#495057,color:#212529
    style log fill:#8888880d,stroke:#adb5bd,stroke-width:1px,color:#868e96
```

Specified in [the audit context](docs/architecture/contexts/audit.md).

### Planned: Hodor as an OpenID Provider

> **Not built.** This is the design for Phase 2, when applications sign people in through Hodor. It is kept here so the direction is visible; the full sequences, the token lifecycle and the logout flows are in [protocol sequences](docs/protocols/sequences.md#2-oauth-20-authorization-code-with-pkce).

```mermaid
sequenceDiagram
    autonumber
    participant Application
    actor Person
    box rgba(0, 123, 146, 0.10) Hodor · Phase 2
        participant Server as hodor-server
    end

    Application->>Server: discovery document and keys
    Note over Application: code verifier · S256 challenge · state · nonce
    Application->>Person: redirect to /oauth2/authorize
    Person->>Server: authorize · client · redirect address · scope openid
    Note over Server: client and exact redirect address checked
    opt no session, or not strong or recent enough
        Person->>Server: any of the sign-in flows above
    end
    Server-->>Person: redirect · code · state · iss
    Person->>Application: code · state · iss
    Application->>Server: POST /oauth2/token · code · verifier
    Note over Server: code used once · S256(verifier) = challenge
    Server-->>Application: ID token · access token · refresh token
```

The rules already decided for it: PKCE with `S256` only, exact comparison of redirect addresses, `iss` in every authorization response, codes good for one use whose second use revokes everything issued from them, and refresh tokens that rotate. See [token formats](docs/decisions/0004-token-formats.md) and the [roadmap](docs/product/roadmap.md).

## Try it

The [quick-start](docs/operations/quick-start.md) goes from a clean checkout to a tenant people sign in to, with Docker and nothing else:

```bash
docker compose -f deploy/docker/compose.yaml up --build --wait
```

```bash
python3 deploy/demo/demo.py
```

```bash
python3 deploy/demo/external_identities.py
```

The first command starts Hodor with PostgreSQL, a development mail server, development identity providers for OpenID Connect and SAML, a development directory, VictoriaMetrics and VictoriaTraces. The second is the [demonstration of Milestone 1](docs/operations/quick-start.md#the-demonstration): it creates two tenants and shows, checking every answer, that they are kept apart. The third is the [demonstration of Milestone 2](docs/operations/quick-start.md#the-demonstration-of-milestone-2): signing in through an OpenID Connect provider, a directory and a SAML identity provider, no account taken over by its address, and a tampered SAML response refused. Both run in continuous integration.

| What | Where |
|---|---|
| A tenant's pages, once [created](docs/operations/quick-start.md#2-create-a-tenant) | <http://localhost:8080/t/acme/account> |
| The messages Hodor sends | <http://localhost:8025> |
| Metrics | <http://localhost:8428/vmui> |
| Traces | <http://localhost:10428/select/vmui> |

This is a development stack: its passwords are in the repository and it speaks plain HTTP. The quick-start lists [what must change before anything real](docs/operations/quick-start.md#before-anything-real).

## Repository layout

| Path | Contents |
|---|---|
| `apps/` | The three binaries: `hodor-server`, `hodor-worker`, `hodor-cli` |
| `crates/` | One crate per bounded context, `protocol-http`, the `kernel`, and the adapters |
| `frontend/` | `auth-ui`, the hosted pages; `admin-console`; and the showcase of the design system. React, built on Astryx with the Hodor theme |
| `migrations/` | The database schema |
| `deploy/` | The container image, the development stack, its development identity providers and directory, the demonstrations, and the two installation packages: Docker Compose and a Helm chart |
| `docs/` | Product, architecture, protocols, interfaces, security, operations and the decision records. The design lives there |

## Documentation map

Start with the [index](docs/README.md). The pages most readers want first:

| To learn | Read |
|---|---|
| Why Hodor exists and what it must do | [Product requirements](docs/product/product-requirements.md), [requirements](docs/product/requirements.md) |
| What is built and what is not | [Progress](docs/product/progress.md), [roadmap](docs/product/roadmap.md) |
| How it is structured | [Architecture overview](docs/architecture/overview.md), [domain model](docs/architecture/domain-model.md), [crates](docs/architecture/crates.md), [database](docs/architecture/database.md) |
| The rules of each part | [tenant](docs/architecture/contexts/tenant.md), [identity](docs/architecture/contexts/identity.md), [credential](docs/architecture/contexts/credential.md), [session](docs/architecture/contexts/session.md), [authentication](docs/architecture/contexts/authentication.md), [federation](docs/architecture/contexts/federation.md), [notification](docs/architecture/contexts/notification.md), [audit](docs/architecture/contexts/audit.md), [authorization](docs/architecture/contexts/authorization.md) |
| The HTTP interfaces | [Conventions](docs/api/api-spec.md), [interaction interface](docs/api/interaction-api.md), [administration interface](docs/api/admin-api.md), [console interface](docs/api/console-interface.md) |
| What could go wrong and what stops it | [Threat model](docs/security/threat-model.md), [SAML attack corpus](docs/security/saml-attack-corpus.md) |
| Why it was built this way | [Decision records](docs/decisions/README.md) |
| How it looks | [Design system](docs/design/design-system.md), [hosted pages](docs/architecture/hosted-pages.md), [admin console](docs/architecture/admin-console.md) |
| How to run it | [Quick-start](docs/operations/quick-start.md), [installing with Docker](docs/operations/install-with-docker.md), [installing on Kubernetes](docs/operations/install-on-kubernetes.md), [deployment](docs/operations/deployment.md) |

## Development

[Local setup](docs/development/local-setup.md) says how to build Hodor, run its checks and work on it; the [conventions](docs/development/conventions.md) say how changes are made. A change is done when, among other things, its documentation was updated **before** the code, and these pass:

```bash
cargo fmt --check && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo test --workspace
```

## Contributing

- The documentation comes first: a change to behavior starts with the page in `docs/` that specifies it.
- Commits follow [Conventional Commits](https://www.conventionalcommits.org/), with no co-author trailers.
- Branching follows Gitflow: feature branches are cut from `develop` and merged back through pull requests; `main` holds releases.
- A pull request is merged only when continuous integration is green.
