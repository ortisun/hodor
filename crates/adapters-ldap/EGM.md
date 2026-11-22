# hodor-adapters-ldap

## Overview

The directory adapter crate (package `hodor-adapters-ldap`). Its manifest describes it as asking "LDAP directories whether a person and a password belong together" (`Cargo.toml` `description`).

It implements the federation context port `hodor_federation::api::DirectoryClient`, from `crates/federation`: `impl DirectoryClient for LdapDirectoryClient` (`src/lib.rs:128`). It implements no kernel port; it uses `DomainError`, `ErrorKind` and `Secret` from [the kernel](../kernel/EGM.md).

## Subdirectories & Boundaries

- `src`: [./src/EGM.md](./src/EGM.md) - `LdapDirectoryClient`, which checks a host against the allowed list, then searches the directory and binds as the person found. It also holds the `testing` module (`TestDirectory`, `Person`). Its side effect is network access to the directory.
- `tests`: integration tests (not documented here).

## Workspace Dependencies

From `Cargo.toml`:

- Hodor crates: `hodor-kernel`, `hodor-federation`.
- Runtime: `async-trait`, `ldap3`, and the optional `testcontainers` and `tokio`.
- Development only: this crate itself with the `testing` feature, and `tokio`.

## Features

- `testing = ["dep:testcontainers", "dep:tokio"]`: compiles the public `testing` module, which runs a directory in a container with people in it, for tests (`Cargo.toml` `[features]`; `#[cfg(feature = "testing")]` in `src/lib.rs`).

## Verification

- Run: `cargo test -p hodor-adapters-ldap`
