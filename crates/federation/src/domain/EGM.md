# hodor-federation domain

## Overview

The domain model of the federation context (`mod.rs`): the identity providers a tenant trusts, the links that say which external identity belongs to which user, the pending authorization a sign-in keeps while the person is away at a provider, and the events the context announces. Every module is `pub(crate)`. Other crates reach these types only through `hodor_federation::api`, which re-exports them (`crates/federation/src/lib.rs`).

## Interface

Each type below is re-exported in `hodor_federation::api` unless marked crate-private.

- `provider.rs`
  - `ProviderId` is the identifier of an identity provider, declared with `hodor_kernel::define_id!`.
  - `Alias` is the name of a provider in addresses, and it never changes. `parse(value)` checks it and `as_str()` returns it.
  - `ProviderKind` has the variants `OpenIdConnect`, `GitHub`, `Ldap` and `Saml`. `as_str()` returns `openid_connect`, `github`, `ldap` or `saml`, and `from_stored(value)` reads those names back.
  - `ProviderStatus` has the variants `Enabled` and `Disabled`. `as_str()` returns `enabled` or `disabled`, and `from_stored(value)` reads those names back. A disabled provider keeps its links (doc comment).
  - `DirectorySettings` has the public fields `base`, `filter`, `subject_attribute`, `email_attribute` and `name_attribute`. `new(base, filter)` uses the default attribute names `entryUUID`, `mail` and `cn`.
  - `SamlSettings` has the public fields `single_sign_on_address`, `certificate`, `email_attribute` and `name_attribute`. `new(single_sign_on_address, certificate)` uses the default attribute names `email` and `name`. `key()` turns the certificate into a `hodor_saml::IdentityProviderKey`. If the certificate cannot be used, it returns `federation.saml_invalid` with the certificate error's reason as the error detail.
  - `ProviderSettings` has the public fields `display_name`, `issuer`, `client_id`, `scopes`, `creates_users`, `trusts_email`, `directory: Option<DirectorySettings>` and `saml: Option<SamlSettings>`. Its methods are:
    - `default_scopes()` and `default_scopes_for(kind)`: `openid email profile` for OpenID Connect, `read:user user:email` for GitHub, and none for LDAP or SAML.
    - `default_issuer_for(kind)`: `https://github.com` for GitHub, and `None` for every other kind.
    - `checked()` and `checked_allowing(development_hosts)`, which both check the settings as OpenID Connect.
    - `checked_for(kind, development_hosts)`, which checks every rule for the given kind.
  - `ProviderSnapshot` holds all of a provider's stored state: `id`, `alias`, `kind`, `settings`, `client_secret: SealedSecret`, `status`, `created_at`, `updated_at` and `version: u32`.
  - `IdentityProvider` is the aggregate. Its functions are:
    - `create(alias, kind, settings, client_secret, development_hosts, now)` checks the settings and makes a new provider that is enabled, at version 0, with a newly generated id.
    - `from_snapshot(state)`, `snapshot()`, `id()`, `alias()` and `is_enabled()` rebuild or read it.
    - `change(settings, development_hosts, now) -> Result<bool, _>` checks and replaces the settings. It returns `false` and changes nothing when the checked settings equal the current ones.
    - `change_secret(sealed, now)` replaces the sealed client secret.
    - `set_status(status, now) -> bool` returns `false` when the status is already the one asked for.
  - `directory_host(address) -> Option<String>` returns the lowercased `host:port` of an `ldap://` or `ldaps://` address. The default ports are 389 and 636.
  - Crate-private: `MAX_PROVIDERS` = 20, `IDENTIFIER_PLACE` = `{identifier}` and `is_development_address(address, development_hosts)`.
- `link.rs`
  - `Subject` is a provider's identifier for a person. `parse(value)` checks it and `expose()` returns it. Its `Debug` output is `Subject([REDACTED])`.
  - `ExternalIdentity` has the public fields `provider_id`, `subject`, `user_id`, `linked_at` and `last_used_at`.
- `pending_authorization.rs`
  - `PendingAuthorization` has the public fields `transaction_id`, `provider_id`, `state_hash: [u8; 32]`, `nonce`, `code_verifier: SealedSecret`, `redirect_uri`, `expires_at`, `saml_response: Option<String>` and `saml_receipt_hash: Option<[u8; 32]>`.
- `event.rs`
  - `FederationEvent` is serialized untagged and implements `hodor_kernel::DomainEvent`. Each variant has its own event type:

| Variant | Fields | `event_type()` |
| --- | --- | --- |
| `ProviderCreated` | `provider_id`, `alias`, `kind` | `federation.provider_created` |
| `ProviderChanged` | `provider_id`, `alias` | `federation.provider_changed` |
| `ProviderSecretChanged` | `provider_id`, `alias` | `federation.provider_secret_changed` |
| `ProviderDisabled` | `provider_id`, `alias` | `federation.provider_disabled` |
| `ProviderEnabled` | `provider_id`, `alias` | `federation.provider_enabled` |
| `IdentityLinked` | `provider_id`, `user_id` | `federation.identity_linked` |
| `IdentityUnlinked` | `provider_id`, `user_id` | `federation.identity_unlinked` |
| `SignInRefused` | `provider_id: Option<ProviderId>`, `reason: &'static str`, `detail: Option<String>` (skipped when `None`) | `federation.sign_in_refused` |

## Invariants

- No event carries a secret or a subject (`event.rs` module doc comment). None of the variant fields above is a secret or a `Subject`.
- `Alias::parse` accepts 2 to 32 bytes of lowercase letters, digits and hyphens, starting with a letter or digit. Anything else is `federation.alias_invalid`.
- `Subject::parse` accepts 1 to 255 characters with no control characters, and changes nothing: no trimming and no change of case. Anything else is `federation.subject_invalid`. A subject must not be logged (`Subject::expose` doc comment), and its `Debug` output is redacted.
- `ProviderSettings::checked_for` checks the settings as a whole, and it stops at the first broken rule with an `Invalid` error:
  - Display name: trimmed, then 1 to 64 characters with no control characters (`federation.display_name_invalid`).
  - Issuer, by kind (`federation.issuer_invalid`):
    - SAML: an absolute `http://` or `https://` address, or a `urn:` name, of at most 512 printable characters (`check_entity_id`).
    - LDAP: `ldaps://`, or plain `ldap://` only when its `host:port` is in `development_hosts`.
    - Every other kind: an `https://` address with a host, with no user information, query or fragment, and at most 512 characters. Plain `http://` is accepted only at a host listed in `development_hosts` (`check_issuer`, `check_address`, `is_development_address`).
  - Client identifier: empty for SAML. For every other kind, 1 to 255 characters with no control characters, and no whitespace except for LDAP, where the bind name may contain spaces (`federation.client_id_invalid`).
  - Scopes (`federation.scopes_invalid`): each scope uses only the characters RFC 6749 allows and is at most 128 bytes. Repeated scopes are dropped. There are at most `MAX_SCOPES` = 16. The list must be empty for LDAP and SAML, and non-empty for every other kind. OpenID Connect must include `openid`.
  - Directory settings must be present for `Ldap` and absent for every other kind (`federation.directory_invalid`). `DirectorySettings::checked` requires the following:
    - a base of 1 to 255 characters;
    - a filter of at most 512 characters, wrapped in parentheses, with `{identifier}` exactly once;
    - attribute names of 1 to 64 bytes, made of a letter followed by letters, digits and hyphens.
  - SAML settings must be present for `Saml` and absent for every other kind (`federation.saml_invalid`). `SamlSettings::checked` requires the following:
    - a single sign-on address that passes `check_address`;
    - a certificate of at most 16 kibibytes that `key()` accepts;
    - attribute names of 1 to 255 characters with no whitespace.
- `IdentityProvider::change` checks the new settings against the provider's stored kind. The kind and alias of a provider cannot be changed: no method sets them.
- `ProviderSnapshot::version` is incremented on every stored change, for optimistic locking (field doc comment). The store does the incrementing (`ProviderStore::update` in [application](../application/EGM.md)), not this module.
- `ProviderKind::from_stored` and `ProviderStatus::from_stored` return the internal error `federation.stored_data_invalid` for a name they do not know.
- `PendingAuthorization` belongs to one sign-in and is used once (doc comment). `saml_response` is kept at most once, and only for SAML providers (field doc comment).

## Side Effects

- None. The module does no input or output, and it never reads the clock: every time comes in as a `now: Timestamp` parameter. The only exception is `IdentityProvider::create`, which generates a fresh `ProviderId` through `ProviderId::generate()`.

## Verification

- Run: `cargo test -p hodor-federation`
