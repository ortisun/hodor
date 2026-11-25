# The credential context

The `credential` context owns what a user proves their identity with. It stores each credential safely and answers one kind of question: is this the right secret for this user?

It does not decide whether a sign-in succeeds. That belongs to the `authentication` context, which also counts failed attempts and locks accounts. The credential context only says whether a secret is right.

This page specifies passwords (Milestone 1), access tokens, authenticator applications, security keys, passkeys and recovery codes (Milestone 4), and the API keys of service accounts and agents (Milestone 8, Issue-94).

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

## API keys

An API key lets a [service account or an agent](identity.md#service-accounts-and-agents) call Hodor's administration interface and its Authorization API without a token endpoint: the key is presented as it is, as a bearer token ([Decision 0033](../../decisions/0033-api-keys.md)).

| Property | Rule |
|---|---|
| Holder | One service account or agent of the tenant. A person holds no key: a person signs in |
| Shape | The text `hodor_ak_` followed by 64 lowercase hexadecimal characters: 32 random bytes from the operating system |
| Storage | Only the SHA-256 of the key, unique within the tenant. The key is returned once, when it is made or rotated, and never again; the last four characters are kept as a **hint**, so that a person can tell their keys apart |
| Name | 1 to 100 characters without control characters, for administrators |
| Scopes | 1 to 50 of the scopes Hodor's own interfaces understand: a permission of the administration interface, such as `users:read`, or a scope of [the Authorization API](authorization.md#who-may-ask), `authz:evaluate`, `authz:simulate` or `authz:explain`. Each once |
| Application | The application whose resource server the key asks the Authorization API about. Required with a scope of the Authorization API, refused without one |
| Lifetime | 1 to 365 days; 90 unless chosen. There is no key that does not expire |
| Last use | When it was last accepted, to the minute |
| How many | A workload holds at most 10 keys that are neither revoked nor expired, not counting a key that was rotated and still works for its overlap |

### Recognizing a key

The prefix tells anyone who finds a key in a repository, a log or a ticket what it is. Secret scanning tools can be given these patterns, one per kind of secret Hodor makes:

| Secret | Pattern |
|---|---|
| API key | `hodor_ak_[0-9a-f]{64}` |
| Client secret | `hodor_cs_[0-9a-f]{64}` |
| Access token of the administration interface | `hodor_at_[0-9a-f]{64}` |

A key found where it should not be is revoked by an administrator of its tenant. A value with the prefix but not the shape matches no key, and nothing is computed or looked up for it.

### When a key is accepted

A presented key is accepted only when all of these hold; otherwise it is refused in one way, whatever the reason:

- it has the shape of a key, and its hash is a key of this tenant;
- it is not revoked and has not expired;
- its holder is a service account or an agent of the tenant that may act. Disabling the workload stops its keys at once; enabling it again lets them work.

What an accepted key may then do is the interface's to decide:

- **At the administration interface** a request needs the route's permission among the key's scopes **and** among the permissions of the built-in roles its holder holds ([the administration interface](../../api/admin-api.md#who-may-call-it)). A key never does more than its holder may. A workload is given a built-in role by the operator, with `hodor-cli admin grant`.
- **At the Authorization API** the key stands for its application, as a client's token does: the resource server asked about is the application's, and the scopes open the routes as a token's do ([who may ask](authorization.md#who-may-ask)).

### Rotation and revocation

- **Rotating** a key makes a new one, with the same holder, name, scopes and application, a lifetime of its own, and returns it once. The old key keeps working for an **overlap** of 0 to 30 days, 7 unless chosen, and never longer than it would have; it then names the key that replaced it. Only a key that was not replaced can be rotated: rotating the same key twice would leave two lines.
- **Revoking** a key ends it at once. Revoking is final, and revoking a revoked key changes nothing.
- **Deleting a workload** revokes its keys, with the reason `workload_deleted`.

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

Who may enroll is decided by the caller: the person, from [their own pages](authentication.md#a-persons-own-factors) after proving themselves again, or an operator with the command-line tool.

### Checking a code

A code is right when it is the code of the current step or of the step just before or just after it, so that a phone whose clock is up to thirty seconds off still works.

- **A code works once.** The step of the last accepted code is kept. A code of that step or of an earlier one is refused, even if it is right: whoever reads a code over someone's shoulder cannot use it after them. Of two requests that present the same code at the same moment, one is accepted.
- **The answer is only "verified" or "rejected"**, as for a password. A user without an application in use, an application waiting to be confirmed, a wrong code, a used code and something that is not six digits are all "rejected". Spaces in what was typed are ignored, since applications show codes as two groups of three.
- **Attempts are limited by the authentication context**, with the same counts and lockouts as passwords: six digits are guessed by repetition, not by luck.

### Removing

Removing takes away the application in use and any enrollment waiting to be confirmed. Removing a user's last second factor under a tenant policy that requires one is refused by the caller, [the authentication context](authentication.md#the-last-second-factor), not here.

## Security keys and platform authenticators

A **WebAuthn credential** is a key pair made by an authenticator: a security key, or the one built into a telephone or a computer. The private key never leaves the authenticator; Hodor keeps the public key, and later checks that the authenticator signed a challenge Hodor chose. It proves something the person has. How the checks are written is [Decision 0024](../../decisions/0024-webauthn-checks.md).

### The relying party

The **relying party** is who a credential is made for. A browser lets a page use only the credentials made for the page's own site.

| Part | Value |
|---|---|
| Identifier | The host of the installation's public address, `HODOR_PUBLIC_URL`: `id.example.com` for `https://id.example.com` |
| Origin | The public address without its path: scheme, host and port |
| Name | `Hodor` |

Every tenant is served under the same public address, at `/t/{slug}`, so every tenant has the same relying party. What keeps tenants apart is where a credential is stored: in the tenant it was registered in, under row-level security. A credential registered in one tenant is unknown in every other, and a challenge belongs to one sign-in of one tenant.

### What is stored

| What | Why |
|---|---|
| The credential identifier, as the authenticator made it | To tell the browser which credentials may answer, and to find the one that did. Unique within the tenant |
| The public key, as the COSE key the authenticator sent, and its algorithm | To check signatures. Kept as sent, so that algorithms added later need no conversion |
| The signature counter | To notice a copied authenticator |
| Whether the credential may be backed up, and whether it is | Reported by the authenticator. A credential that may be backed up is a synchronized passkey |
| Whether the credential is discoverable, when the browser said | A discoverable credential can sign a person in without an identifier first, which [passkeys](../../product/epics.md#milestone-4-strong-authentication) will use |
| How the authenticator is reached, as the browser said: `usb`, `nfc`, `ble`, `internal`, `hybrid` | Passed back to the browser, which uses it to offer the right authenticator |
| A name the person gives it | So that they can tell their keys apart |
| When it was registered and last used | For display |

The **user handle** given to an authenticator is the user's identifier, the 16 bytes of the UUID. It names no one: it is not an email address or a login identifier.

### Registering a credential

Registration is done by a person who is signed in, in two requests.

1. **Asking.** Hodor makes a challenge of 32 random bytes and keeps it for five minutes, for this user, as a pending registration. It answers with the options the browser passes to the authenticator:
   - the relying party, the user handle, the user's primary login identifier as the name, and their display name;
   - the challenge;
   - ES256, then RS256, as the algorithms accepted;
   - the user's existing credentials, so that the same authenticator is not registered twice;
   - a discoverable credential preferred, and user verification discouraged: a second factor needs the key, not a fingerprint or a PIN on it;
   - no attestation;
   - the `credProps` extension, so that the browser says whether the credential is discoverable.
2. **Finishing.** The person's browser sends what the authenticator answered. The pending registration is used up first: whatever follows, it cannot be presented again. Then, in order, anything that fails refuses the registration:

| Check | Refused when |
|---|---|
| The pending registration | It is unknown, belongs to another user, or is older than five minutes |
| The client data, read as JSON | Its `type` is not `webauthn.create`; its `challenge` is not the pending one; its `origin` is not the relying party's; it says `crossOrigin` is true |
| The attestation object, read as CBOR | It is not a map holding `fmt`, `attStmt` and `authData`. The statement is not checked, whatever its format |
| The authenticator data | It is shorter than its fixed part; the hash of the relying party identifier is not SHA-256 of Hodor's; the user was not present; it carries no credential; it says the credential is backed up but may not be; anything is left over at its end |
| The credential identifier | It is longer than 1,023 bytes, or the tenant already has a credential with it |
| The public key | It is not an ES256 key on P-256 or an RS256 key of at least 2,048 bits |

The credential is stored with the counter the authenticator reported, and `credential.webauthn_registered` is recorded.

### Renaming and removing a credential

A person tells their keys apart by name, and removes one they lost or no longer use.

- **Renaming** gives a credential a new name, by the rules of a name given at registration: trimmed, at most 64 characters, not empty and without control characters. A name that breaks them is refused, `credential.webauthn_name_invalid`, rather than replaced by the default. `credential.webauthn_renamed` is recorded.
- **Removing** deletes the credential. An authenticator that still holds it can no longer answer for it: its answers are rejected as from an unknown credential. `credential.webauthn_removed` is recorded.
- Both act only on a credential of the user named, in the tenant. Another user's credential, or one that does not exist, is answered in the same way, `credential.webauthn_credential_not_found`, so that a person cannot learn about another's.

### Checking a credential

A sign-in asks for a challenge first and checks the answer second; the challenge is kept with the sign-in, by the [authentication context](authentication.md#steps-that-need-a-challenge).

1. **The challenge.** 32 random bytes, and the options for the browser: the challenge, the relying party identifier, the user's credentials with how each is reached, and user verification discouraged.
2. **The answer.** The browser sends the credential identifier, the client data, the authenticator data, the signature and, when the authenticator gave one, the user handle. Anything that fails is a rejection, and the rejections are not told apart:

| Check | Rejected when |
|---|---|
| The credential | It is not one of this user's in this tenant |
| The user handle | It was sent and is not this user's |
| The client data | Its `type` is not `webauthn.get`; its `challenge` is not the sign-in's; its `origin` is not the relying party's; it says `crossOrigin` is true |
| The authenticator data | It is shorter than 37 bytes; the hash of the relying party identifier is not Hodor's; the user was not present; it says the credential is backed up but may not be; whether the credential may be backed up differs from what was registered |
| The signature | It is not a signature of the authenticator data followed by SHA-256 of the client data, by the stored key |
| The counter | The stored counter or the reported one is not zero, and the reported one is not greater than the stored one |

A counter that does not grow means two authenticators answer for one credential: the credential was copied. The answer is refused and `credential.webauthn_counter_not_increased` is recorded, so that an administrator can see it. An authenticator that keeps no counter reports zero every time, and is accepted.

When every check passes, the counter, whether the credential is backed up and when it was last used are stored.

### Passkeys

A **passkey** is a WebAuthn credential that signs a person in on its own: it is discoverable, so the authenticator keeps it and offers it without being told which credential to use, and the authenticator verifies the person, with a PIN, a fingerprint or a face, before it answers. The person holds the key and unlocked it; that is two factors in one gesture.

**Registering a passkey** is a registration as above, asked for as a passkey. What changes:

| Part | For a passkey |
|---|---|
| What is asked of the authenticator | A discoverable credential **required**, and user verification **required** |
| The user, as the authenticator is told | The display name is followed by the tenant's name in brackets, `Ana Lima (Acme)`, so that a person with accounts in several tenants of one installation can tell their passkeys apart: every tenant shares one relying party |
| The checks of the answer | Every check above, and: the authenticator data must say the user was verified; the browser must not say the credential is not discoverable |
| What is stored | The credential, marked discoverable |

Whether a registration is for a passkey is kept with the pending registration, so the person cannot ask for one kind and finish as the other.

**Checking a passkey's answer** comes before anyone is identified, so the challenge names no credentials:

1. **The challenge.** 32 random bytes, and the options for the browser: the challenge, the relying party identifier, **no** list of credentials, and user verification required. Making it reads nothing from storage.
2. **The answer.** The credential is found by the identifier the answer names, **within the tenant** only. Then, in order, anything that fails is a rejection, and the rejections are not told apart:

| Check | Rejected when |
|---|---|
| The credential | The tenant has no credential with this identifier |
| The user handle | It is missing, or it is not the handle of the user the credential belongs to |
| Everything of [checking a credential](#checking-a-credential) | As there: the client data, the authenticator data, the signature and the counter |
| User verification | The authenticator data does not say the user was verified |

When every check passes, the counter is stored as for any answer, and the answer is the user the credential belongs to.

Any discoverable credential can answer this challenge, including a security key registered as a second factor that happened to be made discoverable, as long as its authenticator verifies the person. The user handle is the user's identifier, so the answer names who is signing in without anyone typing anything.

### What keeps tenants apart

Every tenant of an installation is served under one public address, so every tenant has the same relying party, and a browser may offer a person every passkey it holds for that relying party, whichever tenant it was registered in. Hodor cannot hide those: it gives the browser no list to choose from. What it guarantees is the other half:

- a credential is looked up only in the tenant of the sign-in, under row-level security, so a passkey of another tenant is unknown there, and its answer is a rejection like any other;
- a challenge belongs to one sign-in of one tenant.

The tenant's name in the display name is what lets the person pick the right one.

## Recovery codes

Recovery codes let a person in who has lost their second factor: the phone with the authenticator application, or the security key. They are written down or printed when the person enrolls, and each is used in place of the second factor once.

### The codes

| Property | Rule |
|---|---|
| How many | A set of ten codes per user. A user has at most one set |
| Shape | Sixteen characters from the alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, shown in four groups of four separated by hyphens, such as `7K2M-QX9D-4HVN-R8TA` |
| Strength | Each character carries five bits, so a code carries 80 bits from the operating system's random source |
| At rest | Only the SHA-256 of each code is stored. A copy of the database yields no code |
| Read back | Never. The set is shown once, when it is generated |

The alphabet leaves out `I`, `L`, `O` and `U`, so that a code copied by hand is not misread. What a person types is read generously: lowercase counts as uppercase, spaces and hyphens are ignored, `O` is read as `0`, and `I` and `L` as `1`. Anything else that is not sixteen characters of the alphabet is not a code.

80 bits is why a plain SHA-256 is enough, as for the other high-entropy secrets of [Decision 0004](../../decisions/0004-token-formats.md): guessing one code online is stopped by the lockout long before luck matters, and finding a code from its hash in a copy of the database would take about 2⁸⁰ hashes. A slow password hash would add nothing but the cost of checking ten of them on every attempt.

### Generating

- **Generating makes a new set and ends the old one whole.** Every code of the earlier set, used or not, stops working in the same transaction. Two requests that generate at the same moment never leave two sets: one of them is refused, and the person asks again.
- **A set is generated when a person enrolls their first second factor of any kind**, an authenticator application, a security key or a passkey, if they have no set with an unused code: whatever enrolls the factor asks for one and shows it with the confirmation. [The person's own pages](authentication.md#a-persons-own-factors) show it after confirming an authenticator application or registering a key; the command-line tool shows it after confirming an authenticator application.
- **A set can be generated again on request**, which is what a person does after using several codes or when they fear a copy was seen.

### Using a code

- **A code works once.** It is marked used in the statement that accepts it. Of many requests that present the same code at the same moment, exactly one is accepted.
- **The answer is only "verified" or "rejected"**, as for a password, with the number of unused codes left on success, so that the person can be told to generate a new set. A user without a set, a wrong code, a used code, a code of an earlier set and something that is not a code are all "rejected".
- **Attempts are limited by the authentication context**, with the same counts and lockouts as passwords and codes of an authenticator application.
- Using a code is an event of its own, carrying the user and how many codes are left, so that an auditor sees every use.

### Removing

Removing takes away the user's set. The credential context does not remove a set by itself when the last second factor goes; [the authentication context](authentication.md#the-last-second-factor) does, since the codes are useless without a second factor step to stand in for.

## Operations

| Use case | What it does |
|---|---|
| Set password | Gives a user a password without asking for the current one: at registration, at recovery, or when an administrator resets it. Checks the rules, moves the current hash to the history, stores the new one |
| Check new password | Says whether a password would be accepted for a user, by the same rules as setting it, without storing anything. Lets a caller refuse a password before doing something that cannot be undone, such as using up a recovery token |
| Change password | The user replaces their own password: the current one must verify first |
| Issue access token | Makes a token for a user with a lifetime and a note of what it is for, and returns it once |
| Authenticate access token | Says which user and token a presented token belongs to, or nothing |
| Revoke access token | Ends a token |
| Create API key | Makes a key for a workload with a name, scopes, an application when it needs one, and a lifetime, and returns it once |
| List API keys | A workload's keys, newest first, with their hint and status, never the key |
| Rotate API key | Makes the next key of a line, returned once, and shortens the old one to the overlap |
| Revoke API key | Ends a key; ending one that is revoked changes nothing |
| Revoke every API key of a workload | In the caller's unit of work, when the workload is deleted |
| Authenticate API key | Says which key a presented value is, if it is one that works, and records its use |
| Verify password | Answers "verified" or "rejected". On success, if the stored hash uses old parameters, it is replaced with a fresh one |
| Remove password | Deletes the password and its history, for example when a user is erased |
| Has password | Says whether a user has a password; for administrators and the account pages, never for a sign-in form |
| Begin authenticator application enrollment | Makes a secret, stores it as waiting to be confirmed, and returns it once with its `otpauth://` address |
| Confirm authenticator application enrollment | Puts the waiting application in use when the code typed is right |
| Verify authenticator application code | Answers "verified" or "rejected", and marks an accepted code as used |
| Has authenticator application | Says whether a user has an application in use; asked by the sign-in once the person has proved a first factor |
| Remove authenticator application | Takes away the application in use and any enrollment waiting to be confirmed |
| Begin WebAuthn registration | Makes a pending registration for a user and returns the options for the browser |
| Finish WebAuthn registration | Checks what the authenticator answered and stores the credential |
| WebAuthn challenge | Makes a challenge for a user's credentials and returns it with the options for the browser |
| Verify WebAuthn assertion | Answers "verified" or "rejected" for an answer to a challenge, and stores the new counter |
| Has WebAuthn credentials | Says whether a user has at least one credential, for the authentication context to know whether a step can be performed |
| Begin passkey registration | Makes a pending registration for a passkey and returns the options for the browser |
| Passkey challenge | Makes a challenge that any discoverable credential may answer, with the options for the browser |
| Verify passkey assertion | Answers which user signed in, or nothing, for an answer to a passkey challenge, and stores the new counter |
| List WebAuthn credentials | A user's credentials, oldest first, with their names and when they were registered and last used |
| Rename WebAuthn credential | Gives one of a user's credentials a new name |
| Remove WebAuthn credential | Deletes one of a user's credentials |
| Generate recovery codes | Makes a set of ten codes in place of the user's set, if any, and returns it once |
| Generate recovery codes if none | The same, only when the user has no set with an unused code; answers nothing otherwise. Asked when a first second factor is enrolled |
| Verify recovery code | Answers "verified", with the number of unused codes left, or "rejected", and marks an accepted code as used |
| Count recovery codes | Says how many unused codes a user has |
| Remove recovery codes | Takes away the user's set |

### Events

| Event type | When |
|---|---|
| `credential.password_set` | A password was set or reset; says whether it must be changed at the next sign-in |
| `credential.password_changed` | A user changed their own password |
| `credential.password_removed` | A password was removed |
| `credential.access_token_issued` | An access token was issued; carries the user, the token's identifier and when it expires |
| `credential.access_token_revoked` | An access token was revoked; carries the user and the token's identifier |
| `credential.api_key_created` | An API key was made; carries the holder, the key's identifier, its scopes and when it expires |
| `credential.api_key_rotated` | A key was replaced; carries the holder, the old key's identifier, the new one's, when the old one now stops and when the new one expires |
| `credential.api_key_revoked` | A key was revoked; carries the holder, the key's identifier and the reason, `revoked_by_administrator` or `workload_deleted` |
| `credential.totp_enrolled` | A user's authenticator application was put in use; carries the user |
| `credential.totp_removed` | A user's authenticator application was removed; carries the user |
| `credential.webauthn_registered` | A WebAuthn credential was registered; carries the user and Hodor's identifier of the credential |
| `credential.webauthn_counter_not_increased` | An answer came with a counter that did not grow; carries the user and Hodor's identifier of the credential |
| `credential.webauthn_renamed` | A credential was given a new name; carries the user and Hodor's identifier of the credential, not the name |
| `credential.webauthn_removed` | A credential was removed; carries the user and Hodor's identifier of the credential |
| `credential.recovery_codes_generated` | A set of recovery codes was made in place of any earlier one; carries the user |
| `credential.recovery_code_used` | A recovery code was accepted; carries the user and how many unused codes are left |
| `credential.recovery_codes_removed` | A user's set of recovery codes was removed; carries the user |


Events carry the user's identifier and nothing derived from the password, from a token, from a secret of an authenticator application, from a key or from a recovery code. Beginning an enrollment produces no event: nothing is in use until it is confirmed. Replacing a hash because the parameters changed produces no event: nothing the user or an auditor cares about happened.


### Ports

| Port | Purpose |
|---|---|
| `PasswordStore` | Store and load a user's password record and history, with optimistic locking |
| `AccessTokenStore` | Store access tokens, find one by the hash of its token, mark one revoked |
| `ApiKeyStore` | Store API keys, find one by its hash, list a holder's, count a holder's that work, store a change, and record a use at most once a minute in one statement |
| `PasswordHasher` | Hash a password, verify a password against a stored hash and say whether the hash should be renewed, and perform a discarded computation of equal cost |
| `TotpStore` | Store a user's authenticator application and the enrollment waiting to be confirmed; put one in use; mark a step used only if it is later than the last one, in one statement |
| `HmacSha1` | Compute HMAC-SHA-1, from which the codes are made |
| `SecretBox` | The kernel's port that seals and opens the secret of an authenticator application |
| `WebAuthnStore` | Keep pending registrations and use one up exactly once; store credentials, list a user's, find one in the tenant by the identifier the authenticator made, store a new counter only over the one that was read; rename and remove one of a user's credentials |
| `SignatureVerifier` (kernel) | Check a signature made with a WebAuthn credential's key |
| `RecoveryCodeStore` | Store a user's set of recovery codes in place of the earlier one; mark a code used only if it is unused, in one statement; count the unused codes; remove the set |
| `Digest` | The kernel's port that computes the SHA-256 of a recovery code |

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

### `credential.api_key`

| Column | Type | Notes |
|---|---|---|
| `tenant_id`, `id` | `uuid` | Primary key |
| `holder_id` | `uuid` | The workload. Deliberately not a reference: contexts do not reference each other's tables |
| `key_hash` | `bytea` | SHA-256 of the key, 32 bytes; unique within the tenant |
| `hint` | `text` | The last four characters of the key |
| `name` | `text` | |
| `scopes` | `text[]` | |
| `application_id` | `uuid` | Or null. Not a reference: the application is the OAuth context's |
| `created_at`, `expires_at` | `timestamptz` | |
| `last_used_at` | `timestamptz` | Null until used |
| `revoked_at`, `revocation_reason` | `timestamptz`, `text` | Both null or both set |
| `replaced_by` | `uuid` | The key that replaced it, once rotated. Not a reference, so that the cleanup job can remove either first |

A tenant table under row-level security. The cleanup job removes a key 30 days after it expired or was revoked ([cleanup](../../operations/deployment.md#cleanup)).

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

### `credential.webauthn_credential`

| Column | Type | Notes |
|---|---|---|
| `tenant_id`, `id` | `uuid` | Primary key |
| `user_id` | `uuid` | The user the credential belongs to |
| `credential_id` | `bytea` | As the authenticator made it; unique within the tenant; at most 1,023 bytes |
| `public_key` | `bytea` | The COSE key |
| `algorithm` | `integer` | The COSE algorithm: `-7` or `-257` |
| `sign_count` | `bigint` | The counter last reported |
| `backup_eligible`, `backed_up` | `boolean` | |
| `discoverable` | `boolean` | Null when the browser did not say |
| `transports` | `text[]` | |
| `name` | `text` | |
| `created_at` | `timestamptz` | |
| `last_used_at` | `timestamptz` | Null until first used |

### `credential.webauthn_registration`

| Column | Type | Notes |
|---|---|---|
| `tenant_id`, `id` | `uuid` | Primary key |
| `user_id` | `uuid` | Who asked |
| `challenge` | `bytea` | 32 bytes |
| `passkey` | `boolean` | Whether a passkey was asked for |
| `created_at`, `expires_at` | `timestamptz` | Five minutes apart |

A pending registration is deleted when it is used.

### `credential.recovery_code_set`

| Column | Type | Notes |
|---|---|---|
| `tenant_id`, `id` | `uuid` | Primary key |
| `user_id` | `uuid` | The user the set belongs to; unique within the tenant, so a user has at most one set |
| `created_at` | `timestamptz` | When the set was generated |

### `credential.recovery_code`

| Column | Type | Notes |
|---|---|---|
| `tenant_id`, `id` | `uuid` | Primary key |
| `set_id` | `uuid` | The set the code belongs to; the code is removed with it |
| `code_hash` | `bytea` | SHA-256 of the code, as read from what was typed; unique within its set |
| `used_at` | `timestamptz` | Null until the code is accepted |

All eight are tenant tables under row-level security. `user_id` refers to a user of the identity context but is not a database foreign key: contexts do not reference each other's tables.

The design's data model has a general `credential` table with one row per credential of any kind. Each kind still has its own table: what is stored differs too much between kinds, and nothing yet needs to list every credential of a user at once.

## Not built yet

| Item | Planned in |
|---|---|
| Refusing passwords found in breach lists. The tenant setting exists and is stored, but nothing checks it yet | Later in Phase 1 |
| A secret key mixed into every hash, kept outside the database | With the keys context, Phase 2 |
| HOTP, the counter-based codes of RFC 4226, and codes sent by email or text message | Phase 4, outside the plan of 0.2.0 |
| A relying party of each tenant's own, so that a browser offers only that tenant's passkeys | With custom domains for tenants, Phase 3 |
| Checking attestation, EdDSA keys | When someone needs them ([Decision 0024](../../decisions/0024-webauthn-checks.md)) |
| A checksum in API keys, so that a scanner can check a key offline | When a scanning service asks for it ([Decision 0033](../../decisions/0033-api-keys.md)) |
| Certificates for programs | Phase 6 |
| Listing and revoking access tokens through an interface, and recording when one was last used | With OAuth in Phase 2, which replaces them |
