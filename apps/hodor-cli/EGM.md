# hodor-cli

## Overview

The package `hodor-cli` (`Cargo.toml`, description "Operations tool:
migrations, bootstrap and tenant management.") builds the `hodor-cli` binary.
It is the only binary that applies database migrations, and it does so as the
schema owner (`Command::Migrate` in `src/main.rs`).

## Subdirectories & Boundaries

- src: [./src/EGM.md](./src/EGM.md) - the commands `migrate`, `tenant`,
  `admin bootstrap`, `audit verify`, `provider`, `user claims`, `secrets generate-key`, `secrets reseal`,
  `policy-agent`, `policy`, `trust-domain`, `mesh linkerd-policy` and `probe`,
  and the services each one calls.

## Dependencies

From `Cargo.toml`: `clap`, `serde_json`, `tokio`, `time`, and the workspace crates
`hodor-adapters-crypto`, `hodor-adapters-http`, `hodor-adapters-kms`, `hodor-adapters-postgres`, `hodor-audit`,
`hodor-authorization`, `hodor-credential`, `hodor-federation`,
`hodor-identity`, `hodor-kernel` and `hodor-tenant`. The tests use
`hodor-adapters-postgres` and `hodor-authorization-opa` with the `testing`
feature, `hodor-keys` with it for the sample bundles of
`tests/trust_domain_commands.rs`, and `regex` to check what
`mesh linkerd-policy` writes against the schemas of Linkerd's custom resource
definitions kept in `tests/linkerd_policy_crds.json`.

## Verification

- Run: `cargo test -p hodor-cli`
