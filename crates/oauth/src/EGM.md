# hodor-oauth source

## Overview

The OAuth context. `lib.rs` keeps `application` and `domain` private and
exposes the public surface through `pub mod api`. The specification it
follows is `docs/architecture/contexts/oauth.md`.

## Interface

- `api` re-exports:
  - Ports: `ApplicationStore`, `ClientStore`, `ResourceServerStore`.
  - Service: `ApplicationService`, `ApplicationPorts`, `CreateClient`,
    `RotateSecret`, `CreateResourceServer`.
  - Event: `OauthEvent`.
  - Domain: `Application`, `ApplicationId`, `ApplicationSettings`,
    `ApplicationSnapshot`, `Status`, `Client`, `ClientId`, `ClientType`,
    `ClientSettings`, `ClientSnapshot`, `AuthenticationMethod`, `GrantType`,
    `TokenPolicy`, `ClientSecret`, `ClientSecretId`, `ClientSecretHash`,
    `ClientSecretValue`, `ClientKey`, `ResourceServer`, `ResourceServerId`,
    `ResourceServerSettings`, `ResourceServerSnapshot`, `ScopeDefinition`,
    `Audience`, `is_scope`, and the limits `MAX_APPLICATIONS`,
    `MAX_CLIENTS`, `MAX_REDIRECT_URIS`, `MAX_SCOPES`, `MAX_KEYS`,
    `MAX_SCOPE_LENGTH`, `OPENID_SCOPES`.
- `testing` (compiled only under `#[cfg(any(test, feature = "testing"))]`):
  - `InMemoryApplications`, `InMemoryClients::new(&applications)`,
    `InMemoryResourceServers::new(&applications)`, and `InMemoryStores`,
    the three wired together. The two last refuse a row of an application
    the tenant does not have, as the database does.
  - `DistinctRandom`: a `RandomSource` whose every call gives different
    bytes, for tests only.
  - `Ports<'a> { units_of_work, applications, clients, resource_servers }`
    and `run_contract(ports)`: the contract every store passes.
- Subdirectories:
  - [application](./application/EGM.md): the ports and the use cases.
  - [domain](./domain/EGM.md): the aggregates and their rules.

## Invariants

- The contract (`testing.rs:run_contract`) requires that what is stored
  loads back unchanged, secrets, keys and scopes in their order; that no
  read or change crosses tenants; that a stale version is refused with
  `oauth.*_modified_concurrently`; that a client or resource server names
  an application of its own tenant (`oauth.application_not_found`); that
  an audience is found by exact equality and is unique in a tenant
  (`oauth.audience_taken`); and that an application has at most one
  resource server (`oauth.application_has_resource_server`).

## Side Effects

- None at the crate root. `testing` mutates in-process memory only.

## Verification

- Run: `cargo test -p hodor-oauth`
