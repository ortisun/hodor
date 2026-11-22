# hodor-adapters-ldap source

## Overview

The directory adapter. It asks LDAP directories whether a person and a password belong together, using one search followed by one bind. The crate documentation points to `docs/architecture/contexts/federation.md` (`lib.rs` crate documentation). It implements a port of the federation context, not a kernel port.

## Interface

- `impl DirectoryClient for LdapDirectoryClient` (`lib.rs:128`, under `#[async_trait::async_trait]`) implements `hodor_federation::api::DirectoryClient`, a port of the federation context in `crates/federation`. Its one method is `verify(&self, query: &DirectoryQuery, password: &Secret<String>) -> Result<DirectoryAnswer, DomainError>`. `DirectoryQuery`, `DirectoryAnswer`, `DirectoryEntry` and `directory_host` come from `hodor_federation::api` (`lib.rs` imports).
- `LdapDirectoryClient::new(allowed_hosts: &[String]) -> Self` (`#[must_use]`) takes the directories that may be contacted, written as `host:port`. It sets a fixed timeout of 10 seconds (`lib.rs:LdapDirectoryClient::new`).
- `testing` (public test-support module): compiled only under `#[cfg(feature = "testing")]` (`lib.rs:21`). The Cargo feature `testing` pulls in the optional `testcontainers` and `tokio`. It provides (`testing.rs`):
  - the constants `BASE`, `BIND_NAME` and `BIND_PASSWORD`;
  - `Person { uid, name, email, password }`;
  - `TestDirectory { address, host }` with `start()`, `add(&Person)` and `change_email(uid, email)`. It runs an OpenLDAP container.

## Invariants

- A directory may be contacted only if `directory_host(address)` returns a host that equals one of `allowed_hosts`, ignoring ASCII case. Otherwise `verify` returns `Forbidden` with `federation.directory_not_allowed`, without connecting (`lib.rs:LdapDirectoryClient::is_allowed`, `lib.rs:verify`).
- An empty password returns `Refused("empty_password")` before any connection, because a directory answers an empty-password bind as an anonymous success (`lib.rs:verify`).
- The flow is: connect, bind as Hodor with `query.bind_name` and `query.bind_password`, run a subtree search of `query.base` with `query.filter` and `query.attributes`, bind as the found entry with the person's password, then unbind (`lib.rs:LdapDirectoryClient::ask`).
- The search is limited to 2 entries. Its outcome is mapped as follows (`lib.rs:ask`):
  - result code 4, or more than one entry, gives `Refused("ambiguous")`;
  - no entry gives `Refused("not_found")`;
  - result code 49 on the person's bind gives `Refused("wrong_password")`.
- On success, `verify` returns `Verified(DirectoryEntry { name, attributes })`. Text and binary attributes are both turned into bytes and sorted by name, so the same entry always gives the same answer (`lib.rs:ask`).
- Every `LdapError` maps to `Unavailable` with `federation.provider_unavailable`. The directory's own message goes only into `detail` (`lib.rs:unavailable`).
- The crate does no filter escaping: `query.filter` is passed to the search as received (`lib.rs:ask`). It sets no TLS options; the address scheme comes from `query.address` (`lib.rs:ask`).

## Side Effects

- Network connections to the directory at `query.address` through `ldap3::LdapConnAsync`, made only for an allowed host and a non-empty password (`lib.rs:ask`).
- Two simple binds (Hodor's account, then the person's), one subtree search and one unbind on each verification (`lib.rs:ask`).
- Test support only:
  - starts a Docker container from `osixia/openldap:1.5.0` with `LDAP_TLS=false` (`testing.rs:TestDirectory::start`);
  - writes entries as the directory administrator (`testing.rs:TestDirectory::add`, `testing.rs:TestDirectory::change_email`);
  - the container is removed when the `TestDirectory` value is dropped (`testing.rs:TestDirectory`).

## Verification

- Run: `cargo test -p hodor-adapters-ldap`
