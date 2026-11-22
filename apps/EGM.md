# apps

## Overview

The three binaries of a Hodor installation. Each is a Cargo package of the
workspace (`members` in the root `Cargo.toml` includes `apps/*`) with a single
`src/main.rs`. They share PostgreSQL through `hodor-adapters-postgres` but
connect with different roles: `hodor-cli migrate` as the schema owner, the
server as the application role (`hodor_app`), and the worker as both the
application role and the platform role (`hodor_platform`).

## Subdirectories & Boundaries

- hodor-cli: [./hodor-cli/EGM.md](./hodor-cli/EGM.md) - the operations tool:
  migrations, tenants, the first administrator, audit verification, identity
  providers, secret keys and a health probe.
- hodor-server: [./hodor-server/EGM.md](./hodor-server/EGM.md) - the HTTP
  server: the public router and the operations router; it queues messages and
  reads the audit log.
- hodor-worker: [./hodor-worker/EGM.md](./hodor-worker/EGM.md) - the
  background process: outbox events become audit records, queued messages
  are sent over SMTP, and expired pending authorizations are removed.

## Verification

- Run: `cargo test -p hodor-cli -p hodor-server -p hodor-worker`
