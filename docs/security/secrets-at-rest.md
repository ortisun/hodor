# Secrets at rest

Some secrets must be read back, so they cannot be stored as a hash the way passwords and tokens are: the client secret Hodor presents to an external identity provider, the password it binds to an LDAP directory with. These are stored encrypted. This page says how.

It describes what exists since Issue-35: one set of keys from configuration. The key domain of Phase 2, with a key per tenant held by a key provider ([Decision 0008](../decisions/0008-cryptography.md)), grows out of it.

## The port

A context that needs to keep a secret uses the `SecretBox` port of the kernel. It never sees a key or an algorithm.

| Operation | What it does |
|---|---|
| `seal(tenant, purpose, secret)` | Encrypts the secret for one tenant and one purpose and answers a sealed secret: opaque bytes to store |
| `open(tenant, purpose, sealed)` | Decrypts a sealed secret. It answers only if the tenant and the purpose are the ones it was sealed for and not one bit was changed |
| `needs_resealing(sealed)` | Says whether the sealed secret was made with a key that is no longer the current one |

The purpose is a fixed name chosen by the context, such as `federation.client_secret`. Together with the tenant it is bound into the ciphertext. A sealed secret copied to another tenant's row, or to another column, does not open: the database alone cannot be used to make Hodor decrypt a secret in the wrong place.

A sealed secret that does not open is one error, `secret.unreadable`, whatever the reason: changed bytes, the wrong tenant, the wrong purpose, a key that is no longer configured. The reason is written to the log, never to a caller.

## The implementation

`hodor-adapters-crypto` implements the port with AES-256-GCM from `aws-lc-rs`, the library Decision 0008 names. Hodor implements no cryptography of its own.

- Every sealing draws a new random nonce of 96 bits from the library.
- The tenant and the purpose are the associated data: authenticated, not stored.
- A sealed secret is laid out as follows. Nothing in it is secret except the ciphertext.

| Part | Size | Contents |
|---|---|---|
| Format | 1 byte | `1` |
| Length of the key identifier | 1 byte | |
| Key identifier | 1 to 32 bytes | Which configured key sealed this |
| Nonce | 12 bytes | |
| Ciphertext and tag | The secret's length plus 16 bytes | |

With random nonces, one key must not seal more than about four thousand million secrets. Provider secrets are written when an administrator changes them, which is many orders of magnitude below that.

## Keys

Keys come from configuration: `HODOR_SECRET_KEYS`, a list of `identifier:key` pairs separated by commas.

```
HODOR_SECRET_KEYS=2026-11:q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJA=,2026-05:…
```

- An identifier is 1 to 32 lowercase letters, digits and hyphens. It is stored with every sealed secret, so it must never be reused for another key.
- A key is 32 random bytes in Base64. `hodor-cli secrets generate-key` prints one.
- **The first key seals. Every key opens.**
- The setting is read by `hodor-server`. Without it the server starts, logs a warning, and offers no identity provider.

### Changing the key

1. Generate a new key and put it first in the list, keeping the old ones after it. Restart.
2. New secrets are sealed with the new key. Old ones still open, and are sealed again with the new key the next time they are written.
3. When nothing is left under an old key, remove it from the list.

A key that leaked protects nothing that was sealed with it: changing the key is not enough, the secrets themselves must be changed at their providers.

### What the key protects against

| Someone who has | Can read the secrets |
|---|---|
| A copy of the database, or a backup | No |
| Read access to the database through the application role | No |
| The database and the configuration of the server | Yes |

The key lives in the same place as the database password. It protects backups, replicas and anyone who reaches the database without reaching the server's configuration. Holding keys outside the server's configuration is what the key provider of Phase 2 and the cloud key management services of Phase 9 are for.

## Not built yet

| Item | Planned in |
|---|---|
| A key per tenant, wrapped by a key provider | Phase 2 |
| Sealing everything again under the current key without waiting for a write | With the first secret that is rarely written |
| Keys held by a key management service or a vault | Phase 9 |
