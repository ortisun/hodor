# OAuth application layer

## Overview

The use cases of applications, clients and resource servers, those of the
authorization endpoint, and the storage ports they need. Every use case runs in a unit of work bound to one
tenant and records its events in it.

## Interface

### Ports (`ports.rs`)

| Port | Methods |
| --- | --- |
| `ApplicationStore` | `insert`, `update` (version checked), `get`, `list` (oldest first) |
| `ClientStore` | `insert` (`oauth.application_not_found` for an application the tenant does not have), `update` (version checked; replaces secrets and keys), `get`, `list_for_application` (oldest first) |
| `ResourceServerStore` | `insert` (`oauth.audience_taken`, `oauth.application_has_resource_server`, `oauth.application_not_found`), `update` (version checked; replaces the scopes), `get`, `find_by_audience` (exact), `list` (oldest first) |
| `AuthorizationRequestStore` | `insert` (`oauth.client_not_found`), `get`, `remove` (answers whether this call removed it) |
| `GrantStore` | `insert` (`oauth.client_not_found`), `get`, `update` (status and revocation; `oauth.grant_not_found`) |
| `AuthorizationCodeStore` | `insert` (`oauth.grant_not_found`), `find` (by hash), `redeem` (only if not redeemed; answers whether this call redeemed it) |

### Service (`service.rs`)

`ApplicationService::new(ApplicationPorts { units_of_work, applications,
clients, resource_servers, digest, random, clock })`:

- Applications: `create_application` (at most 100,
  `oauth.too_many_applications`), `change_application`,
  `set_application_status`, `application`, `applications`.
- Clients: `create_client(CreateClient)` (the application must exist; at
  most 20 per application, `oauth.too_many_clients`; returns the first
  secret once), `change_client`, `rotate_client_secret(RotateSecret)`,
  `revoke_client_secret`, `add_client_key` (the key as JSON),
  `remove_client_key`, `set_client_status`, `client`, `clients`.
- Resource servers: `create_resource_server(CreateResourceServer)`,
  `change_resource_server`, `resource_server`,
  `resource_server_by_audience` (`oauth.resource_server_not_found` also for
  a value that cannot be an audience), `resource_servers`.

### Authorization endpoint (`authorization.rs`)

`AuthorizationCodeService::new(AuthorizationCodePorts { units_of_work,
applications, clients, resource_servers, requests, grants, codes, digest,
random, clock })`:

- `check(tenant, parameters)`: loads the client the request names in this
  tenant, its application and the tenant's resource servers, and runs
  `check_request`. The outer `Result` is storage; the inner one the refusal.
- `hold(tenant, request)`: stores a pending request for ten minutes;
  returns its identifier and the browser's secret.
- `resume(tenant, id, secret)`: `None` unless the secret is the browser's;
  removes the request (once, even when expired) and returns it while it
  lives.
- `issue_code(tenant, request, person, caller)`: stores a grant and a code
  in one unit of work with `oauth.authorization_code_issued`; returns the
  code once.
- `redeem_code(tenant, code, presentation, caller)`: every refusal is
  `oauth.code_refused` with the reason as its detail (`unknown`,
  `already_redeemed`, `expired`, `other_client`, ...). A second redemption,
  found as redeemed or lost in the conditional `redeem`, revokes the grant
  (`oauth.grant_revoked`, reason `code_reused`) and commits that.

## Invariants

- A change that changes nothing stores nothing and announces nothing.
- Not found is `oauth.application_not_found`, `oauth.client_not_found` or
  `oauth.resource_server_not_found`, the same for a row of another tenant.

## Verification

- Run: `cargo test -p hodor-oauth --test service` and
  `cargo test -p hodor-oauth --test authorization`
