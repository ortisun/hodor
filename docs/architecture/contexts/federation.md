# The federation context

The federation context lets a person sign in to a tenant with an identity they already have somewhere else. It knows two things: the **identity providers** a tenant trusts, and which **external identity** belongs to which user.

It is built in steps ([Milestone 2](../../product/epics.md#milestone-2-signing-in-with-external-identities)). This page describes what exists and is extended with every issue; the last section says what does not exist yet.

## Words

| Word | Meaning |
|---|---|
| Identity provider | Something outside Hodor that knows people and can vouch for them: an OpenID Connect provider such as a social login, later a directory or a SAML identity provider |
| External identity | One person as one identity provider knows them: the provider and the provider's own, unchanging identifier for the person, its **subject** |
| Link | The record that an external identity belongs to a user of the tenant |

## Identity providers

A tenant has its own identity providers. Nothing about a provider is shared between tenants: two tenants that both use the same social login each configure it, each with their own client registered there.

| Part | Rules |
|---|---|
| Identifier | Generated; never changes |
| Alias | The name of the provider in addresses, such as `google`. 2 to 32 lowercase letters, digits and hyphens, starting with a letter or digit. Unique in the tenant. **Never changes**: it is part of the address registered at the provider, where answers are sent back |
| Kind | `openid_connect`. Further kinds come with their issues |
| Display name | What a person reads on the sign-in page, such as "Google". 1 to 64 characters |
| Issuer | The address that identifies the provider, such as `https://accounts.google.com`. HTTPS, no query and no fragment, at most 512 characters. Compared exactly, character by character, with what the provider says about itself |
| Client identifier | Who Hodor is to the provider. 1 to 255 characters |
| Client secret | What Hodor proves that with. [Kept encrypted](../../security/secrets-at-rest.md), for the purpose `federation.client_secret`. Written, never read back: no operation, interface or event returns it |
| Scopes | What Hodor asks the provider for. Always includes `openid`; `openid email profile` unless said otherwise. At most 16 |
| Creates users | Whether a person nobody knows yet is created on their first sign-in through this provider. Yes unless said otherwise |
| Status | Enabled or disabled. A disabled provider is not offered and signs nobody in; its links are kept |

A tenant has at most 20 identity providers.

The issuer, the client identifier and the scopes are not secret, and an administrator reads them back. They are still not shown to people signing in.

### Why the alias never changes

Every provider gets its own address for answers, built from its alias. An answer that arrives at the address of one provider is only ever checked against that provider. If two providers shared an address, an answer made for one could be presented as coming from the other. A changed alias would also silently break the registration at the provider.

### Operations on providers

| Operation | What it does |
|---|---|
| Create | Adds a provider, enabled. The secret is sealed before anything is stored |
| Change | Changes the display name, the issuer, the client identifier, the scopes and whether users are created. Not the alias, not the kind |
| Change the secret | Replaces the client secret |
| Disable, enable | Changes the status |
| Get, find by alias, list | Read providers, without their secrets |

A change is refused if the provider was changed by someone else in the meantime (`federation.provider_modified_concurrently`).

There is no operation that deletes a provider. Deleting one would delete the only record of how its users were let in; disabling it is what stops it.

## Links

A link says that one external identity belongs to one user.

| Part | Rules |
|---|---|
| Provider | The identity provider, by its identifier |
| Subject | The provider's own identifier for the person. 1 to 255 characters, compared exactly: no trimming, no change of case |
| User | The user of this tenant it belongs to |
| Linked at, last used at | When the link was made, and when it last signed the user in |

- **An external identity belongs to at most one user.** The pair of provider and subject is unique in the tenant.
- **A user may have several external identities**, at the same provider or at different ones.
- **A link is found by provider and subject, and by nothing else.** Never by an email address, a name or anything else the provider says about the person. An email address can be given to somebody else at the provider; the subject cannot (Threat-Federation-11).

### Operations on links

| Operation | What it does |
|---|---|
| Find the user | Answers whose a provider's subject is, if anyone's |
| Link | Records that an external identity belongs to a user. Refused if it already belongs to anyone (`federation.identity_already_linked`), the same user included |
| Mark as used | Records that the link just signed its user in |
| List | The external identities of a user |
| Unlink | Removes a link |

The federation context does not check that the user exists: users belong to the identity context, and whoever asks for a link has just read or created the user in the same unit of work.

## Events

| Event | When | Carries |
|---|---|---|
| `federation.provider_created` | A provider was added | Its identifier, alias and kind |
| `federation.provider_changed` | Its settings were changed | Its identifier and alias |
| `federation.provider_secret_changed` | Its secret was replaced | Its identifier and alias |
| `federation.provider_disabled`, `federation.provider_enabled` | Its status changed | Its identifier and alias |
| `federation.identity_linked` | A link was made | The provider, the user. Not the subject |
| `federation.identity_unlinked` | A link was removed | The provider, the user |

No event carries a secret. No event carries a subject either: it identifies a person at another organization, and events are kept for a long time and read by many.

## Errors

| Code | Kind | When |
|---|---|---|
| `federation.alias_invalid`, `federation.display_name_invalid`, `federation.issuer_invalid`, `federation.client_id_invalid`, `federation.client_secret_invalid`, `federation.scopes_invalid`, `federation.subject_invalid` | Invalid | A value breaks its rule above |
| `federation.alias_taken` | Conflict | The tenant already has a provider with this alias |
| `federation.too_many_providers` | Conflict | The tenant already has 20 |
| `federation.provider_not_found` | Not found | No provider has this identifier or alias in this tenant |
| `federation.provider_modified_concurrently` | Conflict | Someone else changed the provider first |
| `federation.identity_already_linked` | Conflict | The external identity already belongs to a user |
| `federation.link_not_found` | Not found | There is no such link |

## Ports

| Port | What it is for |
|---|---|
| `ProviderStore` | Stores identity providers |
| `LinkStore` | Stores links |
| `SecretBox`, from the kernel | Seals and opens client secrets |

Each store has an implementation in memory, behind the crate's `testing` feature, and one on PostgreSQL. Both pass the same contract suite, which includes the tenant isolation cases.

## Storage

Both tables are under [forced row-level security](../multi-tenancy.md#isolation-by-layer).

### `federation.identity_provider`

| Column | Type | Notes |
|---|---|---|
| `tenant_id`, `id` | `uuid` | Primary key |
| `alias` | `text` | Unique with `tenant_id` |
| `kind` | `text` | `openid_connect` |
| `display_name`, `issuer`, `client_id` | `text` | |
| `client_secret` | `bytea` | The sealed secret |
| `scopes` | `text[]` | |
| `creates_users` | `boolean` | |
| `status` | `text` | `enabled` or `disabled` |
| `created_at`, `updated_at` | `timestamptz` | |
| `version` | `integer` | For optimistic locking |

### `federation.external_identity`

| Column | Type | Notes |
|---|---|---|
| `tenant_id`, `provider_id`, `subject` | `uuid`, `uuid`, `text` | Primary key. The provider is a foreign key within the tenant |
| `user_id` | `uuid` | A user of the identity context; deliberately not a foreign key, since contexts do not reference each other's tables |
| `linked_at`, `last_used_at` | `timestamptz` | |

## Not built yet

| Item | Planned in |
|---|---|
| Asking a provider who somebody is: discovery, keys, checking what comes back | Issue-39 |
| Signing in through a provider, creating a user on first sign-in, the rules against taking over an account | Issue-40 |
| Managing providers through the administration interface and the command-line tool | Issue-41 |
| Providers that are not plain OpenID Connect: GitHub, Apple; directories; SAML | Issue-43, Issue-44, Issue-48 |
| What happens to the sessions of a provider's users when it is disabled (Threat-Federation-10). Today disabling stops new sign-ins only | With the consoles |
| Mapping what a provider says about a person to the user's profile, groups or roles | Issue-40 for the profile; groups and roles are not in Milestone 2 |
| Linking and unlinking by the person themself, routing by email domain | The account console |
