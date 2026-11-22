# OAuth application layer

## Overview

The use cases of applications, clients and resource servers, and the
storage ports they need. Every use case runs in a unit of work bound to one
tenant and records its events in it.

## Interface

### Ports (`ports.rs`)

| Port | Methods |
| --- | --- |
| `ApplicationStore` | `insert`, `update` (version checked), `get`, `list` (oldest first) |
| `ClientStore` | `insert` (`oauth.application_not_found` for an application the tenant does not have), `update` (version checked; replaces secrets and keys), `get`, `list_for_application` (oldest first) |
| `ResourceServerStore` | `insert` (`oauth.audience_taken`, `oauth.application_has_resource_server`, `oauth.application_not_found`), `update` (version checked; replaces the scopes), `get`, `find_by_audience` (exact), `list` (oldest first) |

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

## Invariants

- A change that changes nothing stores nothing and announces nothing.
- Not found is `oauth.application_not_found`, `oauth.client_not_found` or
  `oauth.resource_server_not_found`, the same for a row of another tenant.

## Verification

- Run: `cargo test -p hodor-oauth --test service`
