# The credential context

The `credential` context owns what a user proves their identity with. It stores each credential safely and answers one kind of question: is this the right secret for this user?

It does not decide whether a sign-in succeeds. That belongs to the `authentication` context, which also counts failed attempts and locks accounts. The credential context only says whether a secret is right.

This page specifies the part built in Milestone 1: passwords. One-time password generators, passkeys, recovery codes and keys for programs are credentials too and are specified here when their turn comes.

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

## Operations

| Use case | What it does |
|---|---|
| Set password | Gives a user a password without asking for the current one: at registration, at recovery, or when an administrator resets it. Checks the rules, moves the current hash to the history, stores the new one |
| Check new password | Says whether a password would be accepted for a user, by the same rules as setting it, without storing anything. Lets a caller refuse a password before doing something that cannot be undone, such as using up a recovery token |
| Change password | The user replaces their own password: the current one must verify first |
| Verify password | Answers "verified" or "rejected". On success, if the stored hash uses old parameters, it is replaced with a fresh one |
| Remove password | Deletes the password and its history, for example when a user is erased |
| Has password | Says whether a user has a password; for administrators and the account pages, never for a sign-in form |

### Events

| Event type | When |
|---|---|
| `credential.password_set` | A password was set or reset; says whether it must be changed at the next sign-in |
| `credential.password_changed` | A user changed their own password |
| `credential.password_removed` | A password was removed |

Events carry the user's identifier and nothing derived from the password. Replacing a hash because the parameters changed produces no event: nothing the user or an auditor cares about happened.

### Ports

| Port | Purpose |
|---|---|
| `PasswordStore` | Store and load a user's password record and history, with optimistic locking |
| `PasswordHasher` | Hash a password, verify a password against a stored hash and say whether the hash should be renewed, and perform a discarded computation of equal cost |

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

Both are tenant tables under row-level security. `user_id` refers to a user of the identity context but is not a database foreign key: contexts do not reference each other's tables.

The design's data model has a general `credential` table with one row per credential of any kind. It is introduced with the second kind of credential; with only passwords it would add a table and a join for nothing.

## Not built yet

| Item | Planned in |
|---|---|
| Refusing passwords found in breach lists. The tenant setting exists and is stored, but nothing checks it yet | Later in Phase 1 |
| A secret key mixed into every hash, kept outside the database | With the keys context, Phase 2 |
| One-time password generators, passkeys, recovery codes | Phase 4 |
| Keys for programs and certificates | Phases 5 and 6 |
