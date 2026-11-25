# Secrets at rest

Some secrets must be read back, so they cannot be stored as a hash the way passwords and tokens are: the client secret Hodor presents to an external identity provider, the password it binds to an LDAP directory with, the PKCE verifier of a sign-in through a provider, the secret of an authenticator application, the secret a webhook is signed with. These are stored encrypted. This page says how.

Since Issue-52, every secret is encrypted under a **data key of its tenant**, a key version of the [keys context](../architecture/contexts/keys.md). The keys of `HODOR_SECRET_KEYS` no longer encrypt secrets: they are **root keys**, and wrap the data keys and the signing keys. This is the envelope encryption of [Decision 0008](../decisions/0008-cryptography.md). Until Issue-52 the root keys sealed every secret directly, in the format described under [the first format](#the-first-format), and an installation moves its secrets to the second with [one command](#moving-the-secrets-of-an-earlier-version).

## The port

A context that needs to keep a secret uses the `SecretBox` port of the kernel. It never sees a key or an algorithm.

| Operation | What it does |
|---|---|
| `seal(tenant, purpose, secret)` | Encrypts the secret for one tenant and one purpose and answers a sealed secret: opaque bytes to store |
| `open(tenant, purpose, sealed)` | Decrypts a sealed secret. It answers only if the tenant and the purpose are the ones it was sealed for and not one bit was changed |
| `needs_resealing(tenant, sealed)` | Says whether the sealed secret was made otherwise than new secrets are sealed now: in the first format, or under a data key that is no longer the active one |

The operations are asynchronous: sealing and opening read the tenant's data keys from the database.

The purpose is a fixed name chosen by the context, such as `federation.client_secret`. Together with the tenant it is bound into the ciphertext. A sealed secret copied to another tenant's row, or to another column, does not open: the database alone cannot be used to make Hodor decrypt a secret in the wrong place.

A sealed secret that does not open is one error, `secret.unreadable`, whatever the reason: changed bytes, the wrong tenant, the wrong purpose, a data key that is retired or revoked, a root key that is no longer configured, the first format once the tenant has refused it. The reason is written to the log, never to a caller.

## Sealing under a data key

`TenantSecretBox` in the keys context implements the port. It holds no cryptography: the key provider encrypts and decrypts with the data key, and for the local provider that is AES-256-GCM from `aws-lc-rs`.

- **Sealing** uses the tenant's active data key, the active `A256GCM` version of its `data` key set. A tenant that has none gets one the first time it seals a secret: a version is made and activated, with the events of any other key version. Two sealings racing to make the first key both end with the one that was activated; the version that lost is revoked, with the reason `lost the race to become the first data key`.
- **Opening** reads the version the sealed secret names. An active or retiring version opens; a pending, retired or revoked one does not.
- **What is bound in.** The associated data, authenticated and not stored, is a fixed label, the tenant, the purpose and the version's identifier. The provider binds the tenant, the version and the algorithm into the key material besides.
- Every sealing draws a new random nonce of 96 bits. With random nonces, one data key must not seal more than about four thousand million secrets; a data key is changed long before.

A sealed secret is laid out as follows. Nothing in it is secret except the ciphertext.

| Part | Size | Contents |
|---|---|---|
| Format | 1 byte | `2` |
| Data key version | 16 bytes | The identifier of the key version that sealed it |
| What the provider made | The rest | For the local provider: its format (1 byte, `1`), the nonce (12 bytes), the ciphertext and tag (the secret's length plus 16 bytes) |

## Root keys

The root keys come from configuration: `HODOR_SECRET_KEYS`, a list of `identifier:key` pairs separated by commas.

```
HODOR_SECRET_KEYS=2026-11:q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJA=,2026-05:…
```

- An identifier is 1 to 32 lowercase letters, digits and hyphens. It is stored with every key it wraps, so it must never be reused for another key.
- A key is 32 random bytes in Base64. `hodor-cli secrets generate-key` prints one.
- **The first root key wraps new key versions. Every root key unwraps.**
- The setting is read by `hodor-server` and `hodor-cli`. Without it the server starts, logs a warning, and offers no identity provider and no authenticator application.

A root key wraps a key version once, when the version is made. Putting a new root key first therefore protects the versions made afterwards; the versions made before stay wrapped under the old one, which must stay in the list while they are in use. Moving a tenant's secrets under a new root key is changing its data key: making and activating a new data key version, which the new root key wraps, then [sealing everything again](#sealing-everything-again). Neither the rotation of signing keys nor anything else makes a new data key version yet: it is listed under [not built yet](../architecture/contexts/keys.md#not-built-yet).

### What the root key protects against

| Someone who has | Can read the secrets |
|---|---|
| A copy of the database, or a backup | No |
| Read access to the database through the application role | No |
| The database and the configuration of the server | Yes |

The root key lives in the same place as the database password. It protects backups, replicas and anyone who reaches the database without reaching the server's configuration. Holding the root key outside the server's configuration is what the cloud key management services of Phase 9 are for.

A key that leaked protects nothing that was sealed with it: changing the key is not enough, the secrets themselves must be changed at their providers.

## Sealing everything again

`hodor-cli secrets reseal` seals again every secret that `needs_resealing` says was made otherwise than new secrets are sealed now, in every tenant or in one (`--tenant`):

1. For each table that holds sealed secrets, it reads the rows a page at a time, opens each secret that needs it, seals it again and writes it back only if the row still holds what was read. A secret written meanwhile by someone else is left as they wrote it.
2. Each row is its own transaction. Stopping the command loses nothing, and running it again does only what is left: it can be run as often as wanted.
3. When a tenant has no secret left in the first format, the command records that the tenant **refuses the first format**. From then on a secret of the first format does not open in that tenant, even with the root key that sealed it.
4. It prints one line per tenant: how many secrets it sealed again, how many were already current, how many needed it and did not open, and whether the first format is now refused. A secret that does not open is left as it was, the tenant keeps accepting the first format, and the command ends with a failure, so that a root key missing from the setting is noticed before secrets are lost.

A secret counts as current from its format and the state of the data key it names, without being opened: the command finds what is sealed the old way, not what is damaged.

The tables are listed in one place in `hodor-adapters-postgres`, each with its purpose. A test of the schema fails when a `bytea` column holding a sealed secret is not in the list.

| Table | Column | Purpose |
|---|---|---|
| `federation.identity_provider` | `client_secret` | `federation.client_secret` |
| `federation.pending_authorization` | `code_verifier` | `federation.code_verifier` |
| `credential.totp` | `sealed_secret` | `credential.totp_secret` |
| `oauth.refresh_token_family` | `sealed_secret` | `oauth.refresh_token_family_secret` |
| `oauth.pairwise_secret` | `sealed_secret` | `oauth.pairwise_secret` |
| `webhooks.signing_secret` | `sealed_secret` | `webhooks.signing_secret` |

### Moving the secrets of an earlier version

An installation of 0.1.0 holds its secrets in the first format. After upgrading, they still open with the same root keys, and new secrets are sealed under data keys. Run `hodor-cli secrets reseal` once, with the same `HODOR_SECRET_KEYS` as the server, to move the old ones and refuse the first format from then on. [Deployment](../operations/deployment.md#upgrades) lists it among the steps of an upgrade.

## The first format

What 0.1.0 wrote: the root key sealed the secret directly with AES-256-GCM, the tenant and the purpose as associated data. It is still read, until the tenant refuses it.

| Part | Size | Contents |
|---|---|---|
| Format | 1 byte | `1` |
| Length of the key identifier | 1 byte | |
| Key identifier | 1 to 32 bytes | Which root key sealed this |
| Nonce | 12 bytes | |
| Ciphertext and tag | The secret's length plus 16 bytes | |

## Not built yet

| Item | Planned in |
|---|---|
| Changing a tenant's data key on a schedule | Issue-51 rotates key versions; a data key may be retired only once nothing is sealed under it, which the rotation must check |
| Wrapping existing key versions again under a new root key, without changing the data key | Not scheduled: changing the data key does the same |
| Keeping recently read data keys in memory instead of reading them for every secret | When reading them shows in the time of a sign-in |
| Keys held by a key management service or a vault | Phase 9 |
