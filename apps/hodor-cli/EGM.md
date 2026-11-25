# hodor-cli

## Overview

The package `hodor-cli` (`Cargo.toml`, description "Operations tool:
migrations, bootstrap and tenant management.") builds the `hodor-cli` binary.
It is the only binary that applies database migrations, and it does so as the
schema owner (`Command::Migrate` in `src/main.rs`).

## Subdirectories & Boundaries

- src: [./src/EGM.md](./src/EGM.md) - the commands `migrate`, `tenant`,
  `admin bootstrap`, `audit verify`, `provider`, `secrets generate-key`, `secrets reseal`,
  `policy-agent`, `policy`, `trust-domain` and `probe`, and the services each
  one calls.

## Dependencies

From `Cargo.toml`: `clap`, `serde_json`, `tokio`, `time`, and the workspace crates
`hodor-adapters-crypto`, `hodor-adapters-http`, `hodor-adapters-kms`, `hodor-adapters-postgres`, `hodor-audit`,
`hodor-authorization`, `hodor-credential`, `hodor-federation`,
`hodor-identity`, `hodor-kernel` and `hodor-tenant`. The tests use
`hodor-adapters-postgres` and `hodor-authorization-opa` with the `testing`
feature, and `hodor-keys` with it for the sample bundles of
`tests/trust_domain_commands.rs`.

## Verification

- Run: `cargo test -p hodor-cli`
