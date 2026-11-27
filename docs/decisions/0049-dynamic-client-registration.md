# Decision 0049: Dynamic client registration is off in every tenant until an administrator chooses who may register, by initial access token, by software statement, or openly with bounds

Status: Proposed (requested by the project owner, who asked for every OpenID certification profile)

## Context

A client registers itself with [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html) and [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591), and reads, changes and removes its registration with [RFC 7592](https://www.rfc-editor.org/rfc/rfc7592). The Dynamic OpenID Provider profile of the [OpenID conformance suite](../operations/conformance.md) registers every client it uses that way, and so do the suite's pairwise tests that Hodor cannot run today ([Decision 0040](0040-pairwise-subjects.md)). Requirement-OAuth-19 asks for it, protected by an initial access token, and the [threat model](../security/threat-model.md#oauth-2x) names malicious registration as Threat-OAuth-12.

Today every client is made by an administrator, through the administration interface or the command-line tool, inside an application ([clients](../architecture/contexts/oauth.md#clients)). A tenant is a boundary of isolation: whatever a registration may do must stay inside its tenant, and a tenant that never asked for it must see nothing of it.

Three ways to allow a registration are in use:

- **An initial access token** (RFC 7591, section 3): a bearer token an administrator hands to a developer, presented at the registration endpoint.
- **A software statement** (RFC 7591, section 2.3): a JSON Web Token signed by someone the tenant trusts, such as the operator of an ecosystem, saying what a piece of software may register as. Open banking ecosystems use them.
- **Open registration**: anyone may register. OpenID Connect allows it, and the suite expects it unless it is given an initial access token.

## Decision

### Off unless the tenant turns it on

- A tenant has no registration endpoint until an administrator turns registration on. Until then `registration_endpoint` is not in discovery and the address answers `404`, like any route that does not exist.
- Turning it on names **one application** that the registered clients belong to, so that every client still belongs to an application as [the OAuth context](../architecture/contexts/oauth.md#clients) requires, and an administrator sees them together. An application may hold at most 20 clients today; an application of registered clients may hold up to 1000, set by the tenant.
- Every registration, change and removal is an audit record, with how it was allowed.

### Who may register is the tenant's policy, among three ways

| Way | What the request carries | What it allows |
|---|---|---|
| Initial access token | `Authorization: Bearer` with a token made by an administrator | What the token's policy allows. A token is shown once, kept as a hash, expires (one hour to 90 days), and is good for a number of registrations set when it is made, one by default |
| Software statement | `software_statement` in the body, signed by a key of an issuer the tenant trusts | What the statement says, within the tenant's policy. Its claims win over the same members in the body, as RFC 7591 says |
| Open | Nothing | What the tenant's policy for open registration allows. Off unless chosen, and refused for a tenant that holds any client of a [security profile](0052-security-profiles.md) |

A tenant may allow several ways at once.

### A registration policy bounds what any way may register

A policy is a set of limits written by an administrator, checked against every registration and every change, whichever way allowed it:

- the grants and response types allowed; `client_credentials` and the token exchange grant are never registered, so a registered client never acts as a workload;
- the scopes allowed, never `groups` or a resource server's scope unless named;
- the authentication methods allowed; `none` only when named;
- whether `redirect_uris`, `request_uris`, `jwks_uri`, `sector_identifier_uri`, `initiate_login_uri`, `frontchannel_logout_uri` and `backchannel_logout_uri` may name any host or only hosts the policy lists;
- the subject type, a security profile the client must keep, and whether consent is always asked. A registered client is never first party, so its person is always asked for consent.

Every address of a registration is checked by the rules a client's addresses already follow, and the addresses Hodor will call, `jwks_uri`, `request_uris`, `sector_identifier_uri` and `backchannel_logout_uri`, by the guarded outbound client's destination check when they are set.

### What a registration gives back

- **The client's identifier**, made by Hodor, and a secret when the method needs one, shown once, kept as a hash as any secret is, with `client_secret_expires_at`.
- **A registration access token** (RFC 7592) and `registration_client_uri`, `{issuer}/oauth2/register/{client_id}`. The token is shown once, kept as a hash, and replaced at every change. It reads, changes and removes that registration only, never any other.
- **Every member Hodor kept**, and none it did not: a member Hodor does not support is left out of the answer, as OpenID Connect Registration says.

### The client's keys may live at its `jwks_uri`

A registered client, and from then on any client, may name `jwks_uri` instead of keys. Hodor fetches it through the guarded outbound client when it needs a key it does not have, keeps the set for at most one hour, fetches it again when an assertion or a request object names a `kid` it does not know, at most once a minute per client, and never follows a redirect. This is what the suite's tests of key rotation by the client need.

### Bounds

- At most 10 registrations per minute per tenant and per address, and the bound on clients per application of registered clients.
- A registration that has not been used for a token in 90 days may be removed by the worker when the tenant chooses so.

## Consequences

- The Dynamic OpenID Provider profile, and the pairwise tests that come with it, can run with an initial access token: the suite sends one when its configuration holds it, so open registration is not needed even for conformance. The third-party initiated login profile reads a registration back with its registration access token. The Dynamic plan also requires discovery to name `code`, `id_token` and `id_token token`, which discovery does whatever the policy says. A registered client is never marked for access tokens through the browser, and a policy never allows the response types that need the mark ([Decision 0083](0083-the-mark-for-access-tokens-through-the-browser.md), which replaces what this decision first said of the conformance tenant's policy).
- A tenant that never turns registration on sees no change and offers nothing to an attacker.
- Open registration lets anyone make clients in a tenant that allows it. The policy limits what they may be, a registered client is never first party, and every one is audited; a tenant that serves real people should prefer initial access tokens or software statements, and the console says so.
- `jwks_uri` makes Hodor fetch a client's keys. It is bounded per client and goes through the guarded client like every other address Hodor calls.

## Alternatives considered

- **Initial access tokens only**, as Requirement-OAuth-19 says. Simpler. Set aside: software statements are how ecosystems such as open banking let software register, and the suite needs open registration or an initial access token configured; a policy common to all three ways keeps the difference small.
- **Open registration as the default for development.** Easier to try. Set aside: a default that is forgotten in production is the threat itself.
- **Registered clients in an application of their own each.** Each registration would make an application. Set aside: the console would fill with applications nobody made, and the tenant's limit on applications would decide registrations by accident.
- **Keeping registered clients apart from those made by administrators**, in a table of their own. Set aside: a client is a client at every endpoint; one table, with how it was made recorded, keeps one set of checks.
