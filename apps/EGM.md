# apps

## Overview

The three binaries of a Hodor installation, and two that run apart from
them: `hodor-ext-authz`, beside a service mesh's proxies, and
`hodor-cert-manager-issuer`, in the clusters of the meshes. Each is a Cargo
package of the workspace (`members` in the root `Cargo.toml` includes
`apps/*`) with a `src/main.rs`; the last two also have a library their tests
and the server's drive, and reach Hodor only over HTTP. The other three share
PostgreSQL through `hodor-adapters-postgres` but
connect with different roles: `hodor-cli migrate` as the schema owner, the
server as the application role (`hodor_app`), and the worker as both the
application role and the platform role (`hodor_platform`).

## Subdirectories & Boundaries

- hodor-cert-manager-issuer:
  [./hodor-cert-manager-issuer/EGM.md](./hodor-cert-manager-issuer/EGM.md) -
  cert-manager's outside issuer: the approved requests for an authority of
  its two kinds, signed through the tenant's certificate authority with an
  access token of its own client; it connects to no database and depends on
  no context crate.
- hodor-cli: [./hodor-cli/EGM.md](./hodor-cli/EGM.md) - the operations tool:
  migrations, tenants, the first administrator, audit verification, identity
  providers, secret keys and a health probe.
- hodor-server: [./hodor-server/EGM.md](./hodor-server/EGM.md) - the HTTP
  server: the public router and the operations router; it queues messages and
  reads the audit log.
- hodor-ext-authz: [./hodor-ext-authz/EGM.md](./hodor-ext-authz/EGM.md) -
  Envoy's external authorization over gRPC, each check one call of the
  Authorization API's `evaluate`; it connects to no database and depends on
  no context crate.
- hodor-worker: [./hodor-worker/EGM.md](./hodor-worker/EGM.md) - the
  background process: outbox events become audit records, queued messages
  are sent over SMTP, and expired pending authorizations are removed.

## Verification

- Run: `cargo test -p hodor-cli -p hodor-server -p hodor-worker -p hodor-ext-authz -p hodor-cert-manager-issuer`
