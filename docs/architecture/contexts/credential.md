# The credential context

The `credential` context owns what a user proves their identity with. It stores each credential safely and answers one kind of question: is this the right secret for this user?

It does not decide whether a sign-in succeeds. That belongs to the `authentication` context, which also counts failed attempts and locks accounts. The credential context only says whether a secret is right.

This page specifies passwords (Milestone 1), access tokens, and authenticator applications (Milestone 4). Passkeys, recovery codes and keys for programs are credentials too and are specified here when their turn comes.

## Passwords

A user has at most one password.

| What is stored | Why |
|---|---|
| The hash of the password | To check a typed password without being able to recover it |
| When it was last changed | For display and for policies about age |
| Whether it must be changed at the next sign-in | Set when an administrator chooses a password for someone |
| The hashes of the previous passwords, up to the history depth | To refuse reusing a recent password |

The password itself is never stored, logged, placed in an event or returned by any operation. In memory it is held in a type that cannot be printed and is wiped when dropped.

### What makes a password acceptable

The rules come from the tenant's [password policy](tenant.md#password-policy). The credential context receives them from its caller; it does not read tenant settings itself.

| Rule | Detail |
|---|---|
| Length | Between the policy's minimum and maximum, counted in characters, not bytes |
| No composition rules | No required digits, symbols or mixed case. Length is what makes a password strong, and composition rules push people toward predictable patterns |
| Not one of the user's own names | A password equal to one of the user's login identifiers, ignoring letter case, is refused |
| Not a recent password | A password equal to the current one or to one in the history is refused |
| Any character is allowed | Including spaces and characters outside the Latin alphabet. Nothing is trimmed or altered: the password is hashed exactly as typed |

A password longer than 4,096 bytes is refused before any other work is done, whatever the policy says, so that an oversized input cannot be used to exhaust the server.

### How a password is hashed

| Aspect | Choice |
|---|---|
| Algorithm | Argon2id |
| Parameters | 19 MiB of memory, 2 passes, 1 lane by default: the baseline recommended by OWASP. Each deployment can raise them |
| Salt | 16 random bytes per password, from the operating system |
| Output | 32 bytes |
| Stored form | The standard text format that names the algorithm, its parameters, the salt and the hash together |

Because the parameters are stored with every hash, they can be raised at any time. A password hashed with different parameters than the current ones still verifies, and is hashed again with the current parameters the next time its owner signs in. No one has to change their password for the installation to become stronger.

### Protecting the server from the cost of hashing

Hashing is deliberately expensive in processor time and memory. Left unbounded, a burst of sign-in attempts could exhaust the server.

- Hashing runs on threads set aside for blocking work, never on the threads that serve requests.
- At most a fixed number of hashes run at once: by default one per processor core.
- A bounded number of requests may wait for their turn: by default four times that number. A request arriving when the queue is full is refused at once with an "unavailable, try again" error rather than waiting.
- The memory the server needs for hashing is therefore known in advance: the number of concurrent hashes times the memory parameter.
- No database transaction stays open while a hash is computed. Every operation reads what it needs, releases the transaction, hashes, and then writes in a second transaction that is rejected if the record changed in between. Slow hashing therefore never holds database connections.

### Checking a password without revealing anything

A wrong password and a user who has no password, or does not exist, must be indistinguishable to whoever is asking, in the answer and in how long the answer takes.

- The answer to a check is only "verified" or "rejected". There is no separate answer for "no such user" or "no password set".
- When there is nothing to check against, a real hash computation with the current parameters is still performed and its result discarded, so that the time taken is the same.

## Access tokens

An access token lets a program act as a user on Hodor's administration interface. It exists so that the interface can be used before OAuth is built; when OAuth access tokens arrive in Phase 2 they replace it.

| Property | Rule |
|---|---|
| Shape | The text `hodor_at_` followed by 64 hexadecimal characters: 32 random bytes from the operating system. The fixed beginning lets tools that scan for leaked secrets recognize one |
| Storage | Only the SHA-256 of the token is stored. The token is returned once, when it is issued |
| Owner | One user. The token can do what that user may do, in that user's tenant, and nothing else |
| Lifetime | Chosen when it is issued, from one minute to 30 days. There is no token that does not expire |
| Ending early | A token can be revoked. Revoking is final |

A token that is malformed, unknown, expired or revoked is refused in the same way. A token of one tenant presented to another is unknown there.

Holding a valid token is not enough: whoever accepts it must still ask the identity context whether the user may sign in, and the [authorization context](authorization.md) whether the user may do what is asked. A suspended user's tokens stop working without anyone revoking them.

## Authenticator applications

An authenticator application on the person's phone shows a six-digit code that changes every thirty seconds: a time-based one-time password, TOTP, as RFC 6238 defines it. It is something the person has, and a second factor after the password.

### The secret and the codes

| Property | Rule |
|---|---|
| Secret | 20 random bytes from the operating system, 160 bits, the length RFC 4226 recommends |
| Parameters | HMAC-SHA-1, six digits, a step of thirty seconds counted from the Unix epoch. These are the values every authenticator application accepts; they are fixed, not stored, and not chosen per tenant |
| At rest | The secret is [sealed](../../security/secrets-at-rest.md) for its tenant with the purpose `credential.totp_secret`. A copy of the database yields no secret |
| Read back | Never by anyone. The secret is shown once, when enrollment begins, and is opened afterwards only to check a code inside the server |
| How many | A user has at most one authenticator application in use, and at most one enrollment waiting to be confirmed |

HMAC-SHA-1 is what the standard and the applications use. [Decision 0008](../../decisions/0008-cryptography.md) offers SHA-2 for new uses; SHA-1 is still sound inside an HMAC, and choosing SHA-256 would leave out applications that only know SHA-1. The computation is done by the `HmacSha1` port, implemented in `adapters-crypto`: the context only turns the result into six digits, as RFC 4226 describes.

### Enrolling

Enrolling takes two calls, so that an application that never received the secret cannot be put in use:

1. **Begin.** A new secret is made and stored as an enrollment waiting to be confirmed, replacing any earlier one that was never confirmed. The answer, given once, holds the secret in Base32 and an `otpauth://totp/` address for a QR code, naming the tenant as the issuer and the person's login identifier as the account. A user who already has an application in use keeps it until the new one is confirmed.
2. **Confirm.** The person types a code their application shows. A right code puts the new application in use and removes the old one; that code counts as used. A wrong code leaves everything as it was. An enrollment not confirmed within ten minutes of beginning is gone: confirming it is refused, and the person begins again.

Who may enroll is decided by the caller. Until the account pages of Issue-70, enrolling is done with the command-line tool by an operator.

### Checking a code

A code is right when it is the code of the current step or of the step just before or just after it, so that a phone whose clock is up to thirty seconds off still works.

- **A code works once.** The step of the last accepted code is kept. A code of that step or of an earlier one is refused, even if it is right: whoever reads a code over someone's shoulder cannot use it after them. Of two requests that present the same code at the same moment, one is accepted.
- **The answer is only "verified" or "rejected"**, as for a password. A user without an application in use, an application waiting to be confirmed, a wrong code, a used code and something that is not six digits are all "rejected". Spaces in what was typed are ignored, since applications show codes as two groups of three.
- **Attempts are limited by the authentication context**, with the same counts and lockouts as passwords: six digits are guessed by repetition, not by luck.

### Removing

Removing takes away the application in use and any enrollment waiting to be confirmed. Removing a user's last second factor under a tenant policy that requires one is refused by the caller (Issue-70), not here.

## Operations

| Use case | What it does |
|---|---|
| Set password | Gives a user a password without asking for the current one: at registration, at recovery, or when an administrator resets it. Checks the rules, moves the current hash to the history, stores the new one |
| Check new password | Says whether a password would be accepted for a user, by the same rules as setting it, without storing anything. Lets a caller refuse a password before doing something that cannot be undone, such as using up a recovery token |
| Change password | The user replaces their own password: the current one must verify first |
| Issue access token | Makes a token for a user with a lifetime and a note of what it is for, and returns it once |
| Authenticate access token | Says which user and token a presented token belongs to, or nothing |
| Revoke access token | Ends a token |
| Verify password | Answers "verified" or "rejected". On success, if the stored hash uses old parameters, it is replaced with a fresh one |
| Remove password | Deletes the password and its history, for example when a user is erased |
| Has password | Says whether a user has a password; for administrators and the account pages, never for a sign-in form |
| Begin authenticator application enrollment | Makes a secret, stores it as waiting to be confirmed, and returns it once with its `otpauth://` address |
| Confirm authenticator application enrollment | Puts the waiting application in use when the code typed is right |
| Verify authenticator application code | Answers "verified" or "rejected", and marks an accepted code as used |
| Has authenticator application | Says whether a user has an application in use; asked by the sign-in once the person has proved a first factor |
| Remove authenticator application | Takes away the application in use and any enrollment waiting to be confirmed |

### Events

| Event type | When |
|---|---|
| `credential.password_set` | A password was set or reset; says whether it must be changed at the next sign-in |
| `credential.password_changed` | A user changed their own password |
| `credential.password_removed` | A password was removed |
| `credential.access_token_issued` | An access token was issued; carries the user, the token's identifier and when it expires |
| `credential.access_token_revoked` | An access token was revoked; carries the user and the token's identifier |
| `credential.totp_enrolled` | A user's authenticator application was put in use; carries the user |
| `credential.totp_removed` | A user's authenticator application was removed; carries the user |

Events carry the user's identifier and nothing derived from the password, from a token or from a secret of an authenticator application. Beginning an enrollment produces no event: nothing is in use until it is confirmed. Replacing a hash because the parameters changed produces no event: nothing the user or an auditor cares about happened.

### Ports

| Port | Purpose |
|---|---|
| `PasswordStore` | Store and load a user's password record and history, with optimistic locking |
| `AccessTokenStore` | Store access tokens, find one by the hash of its token, mark one revoked |
| `PasswordHasher` | Hash a password, verify a password against a stored hash and say whether the hash should be renewed, and perform a discarded computation of equal cost |
| `TotpStore` | Store a user's authenticator application and the enrollment waiting to be confirmed; put one in use; mark a step used only if it is later than the last one, in one statement |
| `HmacSha1` | Compute HMAC-SHA-1, from which the codes are made |
| `SecretBox` | The kernel's port that seals and opens the secret of an authenticator application |

The hasher is a port because the choice of library is an infrastructure decision ([Decision 0008](../../decisions/0008-cryptography.md)); the context only knows that hashing is slow and can be unavailable.

## Storage

### `credential.password`

| Column | Type | Notes |
|---|---|---|
| `tenant_id`, `user_id` | `uuid` | Primary key: one password per user |
| `password_hash` | `text` | Algorithm, parameters, salt and hash in the standard text format |
| `must_change` | `boolean` | |
| `changed_at` | `timestamptz` | |
| `version` | `integer` | Incremented on every update; a stale update is rejected |

### `credential.password_history`

| Column | Type | Notes |
|---|---|---|
| `tenant_id`, `id` | `uuid` | Primary key |
| `user_id` | `uuid` | References the password row; removed with it |
| `position` | `smallint` | 0 for the most recently replaced; unique per user |
| `password_hash` | `text` | A previous hash |
| `replaced_at` | `timestamptz` | When it stopped being the current password |

### `credential.access_token`

| Column | Type | Notes |
|---|---|---|
| `tenant_id`, `id` | `uuid` | Primary key |
| `user_id` | `uuid` | The user the token acts as |
| `token_hash` | `bytea` | SHA-256 of the token; unique within the tenant |
| `description` | `text` | What the token is for, as written by whoever issued it |
| `created_at`, `expires_at` | `timestamptz` | |
| `revoked_at` | `timestamptz` | Null unless revoked |

### `credential.totp`

| Column | Type | Notes |
|---|---|---|
| `tenant_id`, `id` | `uuid` | Primary key |
| `user_id` | `uuid` | The user the application belongs to |
| `status` | `text` | `pending` while waiting to be confirmed, `active` once in use. At most one of each per user |
| `sealed_secret` | `bytea` | The secret, sealed for the tenant and the purpose `credential.totp_secret` |
| `created_at` | `timestamptz` | When enrollment began |
| `confirmed_at` | `timestamptz` | Null while pending |
| `last_used_step` | `bigint` | The step of the last accepted code; null until one is accepted |

All four are tenant tables under row-level security. `user_id` refers to a user of the identity context but is not a database foreign key: contexts do not reference each other's tables.

The design's data model has a general `credential` table with one row per credential of any kind. It is introduced with the second kind of credential; with only passwords it would add a table and a join for nothing.

## Not built yet

| Item | Planned in |
|---|---|
| Refusing passwords found in breach lists. The tenant setting exists and is stored, but nothing checks it yet | Later in Phase 1 |
| A secret key mixed into every hash, kept outside the database | With the keys context, Phase 2 |
| Passkeys and security keys | Issue-67 and Issue-68 |
| Recovery codes | Issue-66 |
| Enrolling and removing an authenticator application from the account pages, after proving oneself again | Issue-70 |
| Moving the sealed secrets of authenticator applications under the keys of the key domain | Issue-52 |
| HOTP, the counter-based codes of RFC 4226, and codes sent by email or text message | Phase 4, outside the plan of 0.2.0 |
| Keys for programs and certificates | Phases 5 and 6 |
| Listing and revoking access tokens through an interface, and recording when one was last used | With OAuth in Phase 2, which replaces them |
