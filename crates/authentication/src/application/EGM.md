# authentication/src/application

## Overview

The use cases of the authentication context and the storage ports they need
(`mod.rs`: "Use cases of the authentication context and the ports they
need"). It runs a sign-in through the flow engine, guards against guessing by
counting attempts, offers the two built-in authenticators (login identifier
and password), and handles registration and password recovery by email link.
Every module is `pub(crate)`; the public names reach other crates only through
`hodor_authentication::api` in `../lib.rs`.

## Interface

### Port traits (`ports.rs`)

Implemented outside this crate by `crates/adapters-postgres/src/authentication.rs`
(`PgAttemptStore`, `PgTransactionStore`, `PgVerificationTokenStore`) and, for
tests, by the in-memory stores in `../testing.rs`. Every method works inside
the tenant the unit of work is bound to.

- `AttemptStore` (`ports.rs:AttemptStore`)
  - `lock(uow, subject, now) -> AttemptCounter`: loads the counter of a
    subject, creating an empty one if there is none, and keeps it to itself
    until the unit of work ends.
  - `save(uow, counter)`: stores a counter obtained from `lock` in the same
    unit of work.
  - `clear(uow, subject)`: forgets everything counted against a subject.
- `TransactionStore` (`ports.rs:TransactionStore`)
  - `insert(uow, transaction)`: stores a new sign-in transaction.
  - `get(uow, id) -> Option<AuthTransaction>`: loads a transaction of the tenant.
  - `update(uow, transaction)`: stores changes to a transaction loaded earlier,
    guarded by its version.
- `VerificationTokenStore` (`ports.rs:VerificationTokenStore`)
  - `insert(uow, token)`: stores a new token.
  - `replace_earlier(uow, purpose, email, now)`: marks every unused token of
    the purpose for the email address as replaced.
  - `find(uow, hash, purpose) -> Option<VerificationToken>`: loads the token
    with the given hash and purpose, whether or not it is still good.
  - `use_up(uow, hash, purpose, now) -> Option<VerificationToken>`: uses the
    token up if it is good at `now`, and returns it.

### Service entry points (`service.rs`)

- `AuthenticationService` (`service.rs:AuthenticationService`), `Clone`; its
  `Debug` shows only the flow name.
  - `new(units_of_work, transactions, engine, flow, identity, sessions, tenants, digest, random, clock)`:
    wires the use cases; returns `Invalid` if `FlowEngine::validate` rejects
    the flow.
  - `start_step_up(tenant, client, StepUpRequest { session_id, user_id, carried, demanded }) -> StepUp`
    (`Started(StartedSignIn)`, `Unreachable`, `NotNeeded`): a step-up of a
    session, counted against the person's primary identifier; completing it
    raises the session through `SessionService::raise` instead of starting one
    (`service.rs:start_step_up`, `complete`). `assurance_of(methods)` asks the
    engine.
  - `start(tenant, client) -> StartedSignIn`: starts a sign-in and returns its
    identifier, the browser secret and the first step.
  - `describe(tenant, id, secret) -> SignIn`: says which step a sign-in is
    waiting for.
  - `submit(tenant, id, secret, input: StepInput) -> SignIn`: runs the current
    step with what was submitted. Reads the tenant's second factor policy on
    every step and again at completion: when it is `Required`, the sign-in
    must reach `Assurance::MultiFactor` or it ends as `SignIn::Failed` with
    `authentication.failed` and no session (`service.rs:demanded`).
  - `cancel(tenant, id, secret)`: ends a sign-in; ending one that has already
    ended changes nothing.
- `SignIn` (`service.rs:SignIn`): `Pending { transaction_id, step }`,
  `Rejected { transaction_id, step, attempts_left }`, `Failed`,
  `Completed { session, token }`.
- `StartedSignIn` (`service.rs:StartedSignIn`): `transaction_id`, `secret`
  (`Secret<String>`), `step`.

### Registration and recovery (`account.rs`)

- `AccountRequest<'a>` (`account.rs:AccountRequest`): `email`, `locale`,
  `address` (where the request came from, used to limit requests).
- `AccountService` (`account.rs:AccountService`), `Clone`; its `Debug` shows
  only `public_url`.
  - `new(...)`: wires the use cases; a trailing `/` on `public_url` is trimmed.
  - `request_registration`: sends a link to finish registering if the address
    has no account, otherwise a notice that it is already registered.
  - `complete_registration -> UserId`: creates the user, active with the
    address verified, and sets the password.
  - `request_recovery`: sends a recovery link if the address belongs to a
    user who may sign in.
  - `reset_password -> UserId`: sets the password, ends every session of the
    user and tells the owner of the address.

### Attempt counting (`guard.rs`)

- `AttemptGuard` (`guard.rs:AttemptGuard`), `Clone`.
  - `new(units_of_work, attempts, digest, clock)`.
  - `admit(tenant, rules, identifier_key, address, caller)`: admits one
    attempt, counting it against the identifier and, when given, the address.
  - `admit_address(tenant, rules, address, caller)`: admits an attempt that
    names no identifier, counting it against the address only; without an
    address nothing is counted.
  - `succeeded(tenant, identifier_key)`: forgets the identifier's count and
    lockout history.

### Built-in authenticators (`authenticators.rs`)

Both implement the `Authenticator` trait from [`../domain/EGM.md`](../domain/EGM.md).

- `IdentifierAuthenticator` (`authenticators.rs:IdentifierAuthenticator`):
  `kind()` is `"identifier"`; traits `identifies: true`, no factor, no method.
  `new(identity, digest)`.
- `PasswordAuthenticator` (`authenticators.rs:PasswordAuthenticator`):
  `kind()` is `"password"`; traits `identifies: false`,
  `factor: Some(Factor::Knowledge)`, `method: Some("password")`.
  `new(credentials, identity, tenants, guard)`.
- `TotpAuthenticator` (`authenticators.rs:TotpAuthenticator`): `kind()` is
  `TotpAuthenticator::KIND`, `"totp"`; traits `identifies: false`,
  `factor: Some(Factor::Possession)`, `method: Some("totp")`.
  `new(totp: TotpService, tenants, guard)`. `has_means` asks
  `TotpService::has_totp` for the candidate, and is `false` without one.
- `WebAuthnAuthenticator` (`authenticators.rs:WebAuthnAuthenticator`):
  `kind()` and `KIND` are `"webauthn"`; traits `identifies: false`,
  `factor: Some(Factor::Possession)`, `method: Some("webauthn")`.
  `new(webauthn: WebAuthnService)`. Rejects without a candidate, without a
  challenge in the transaction, or with fields that are not base64url;
  `has_means` asks whether the candidate has credentials; `challenge` asks the
  credential context for one.
- `PasskeyAuthenticator` (`authenticators.rs:PasskeyAuthenticator`):
  `kind()` and `KIND` are `"passkey"`, used as an alternative; traits
  `identifies: true`, `factor: Some(Factor::Possession)`,
  `second_factor: Some(Factor::Inherence)`, `method: Some("passkey")`.
  `new(webauthn, identity, tenants, guard)`. Admits the attempt with
  `AttemptGuard::admit_address` first; answers `Authenticated` with the user
  `WebAuthnService::verify_passkey` names, and rejects without a challenge,
  for an answer that is refused, and for a user who may not sign in;
  `challenge` asks for a passkey challenge, which names no credential.
- `FactorService` (`factors.rs`): `new(identity, tenants, webauthn,
  recovery_codes)` and `with_totp(totp)`; without it no authenticator
  application is offered (`NotFound` `credential.totp_unavailable`).
  - `factors(tenant, user_id) -> Factors { authenticator_application:
    Option<bool>, keys, recovery_codes_remaining, second_factor_required }`;
    `Factors::second_factors()` counts the application in use and the keys.
  - `begin_authenticator_application` (issuer: the tenant's display name;
    account: the primary email address, else username) and
    `confirm_authenticator_application(tenant, user_id, code, caller) ->
    Option<RecoveryCodes>`.
  - `begin_webauthn_registration(tenant, user_id)` (names the person by their
    primary email address, else username, and display name),
    `begin_passkey_registration(tenant, user_id)` (the same, with the
    tenant's display name in brackets after the display name) and
    `finish_webauthn_registration(tenant, user_id, id, response, caller) ->
    RegisteredKey { credential, recovery_codes }`. Both confirmations call
    `RecoveryCodeService::generate_if_none`.
  - `rename_key`, `remove_key(.., by: Remover, caller)`,
    `remove_authenticator_application(.., by, caller)`: removing the last
    second factor under `SecondFactorPolicy::Required` is `Invalid`
    `authentication.last_second_factor` for `Remover::Person` only; when no
    second factor is left the recovery codes are removed.
  - `generate_recovery_codes` (`Invalid` `authentication.second_factor_missing`
    without a second factor) and `remove_recovery_codes` (`NotFound`
    `credential.recovery_codes_not_found`).
- `factors.rs` also holds `RECENT_SIGN_IN` (five minutes),
  `signed_in_recently(signed_in_at, now)`, `recent_sign_in_until` and
  `recent_sign_in_required()` (`Forbidden`
  `authentication.recent_sign_in_required`), which the interaction routes
  apply to the session's `signed_in_at`.
- `AuthenticationService::challenge(tenant, id, secret, step) -> Value`: asks
  the current step, or an alternative at the start, for a challenge through
  `FlowEngine::challenge` and stores the transaction.
- `RecoveryCodeAuthenticator` (`authenticators.rs:RecoveryCodeAuthenticator`):
  `kind()` is `RecoveryCodeAuthenticator::KIND`, `"recovery_code"`; traits
  `identifies: false`, `factor: Some(Factor::Possession)`,
  `method: Some("recovery_code")`. `new(codes: RecoveryCodeService, tenants,
  guard)`. Used as a substitute of the `webauthn` and `totp` steps
  (`AuthFlow::with_substitute`); `has_means` asks
  `RecoveryCodeService::unused` for the candidate.

## Invariants

- Completion happens once: `TransactionStore::update` must fail with
  `Conflict` code `authentication.transaction_modified_concurrently` when the
  stored version differs, and `NotFound` when the tenant has no such
  transaction (`ports.rs:TransactionStore::update`).
- Of any number of simultaneous `use_up` calls for one token exactly one gets
  it; the others and every later call get nothing
  (`ports.rs:VerificationTokenStore::use_up`).
- Two units of work locking the same attempt subject are served one after the
  other, which keeps the attempt limit exact (`ports.rs:AttemptStore::lock`).
- A wrong sign-in secret is answered exactly like a missing sign-in:
  `NotFound` code `authentication.transaction_not_found`
  (`service.rs:AuthenticationService::load`, `service.rs:not_found`). The
  secret is 32 random bytes as hexadecimal; only its SHA-256 is bound to the
  transaction (`service.rs:AuthenticationService::start`).
- At completion the candidate must still be allowed to sign in
  (`IdentityService::get` then `may_sign_in`) and the engine must report an
  assurance; otherwise the transaction is cancelled and `SignIn::Failed` is
  returned (`service.rs:AuthenticationService::complete`).
- `pending_step` returns `Conflict` code `authentication.no_step_pending`
  when every step is satisfied (`service.rs:AuthenticationService::pending_step`).
- An attempt is counted when it is admitted, before the password is checked.
  Subjects are sorted before locking so two attempts never wait for each
  other. If any subject is locked out, `admit` returns `RateLimited` code
  `authentication.too_many_attempts` with a retry-after of at least one
  second, counts nothing, and the caller must not check any password
  (`guard.rs:AttemptGuard::admit`, `guard.rs:too_many_attempts`).
- `succeeded` clears only the identifier subject; the address keeps its count
  (`guard.rs:AttemptGuard::succeeded`).
- `IdentifierAuthenticator` always answers `StepOutcome::Identified`, with an
  empty candidate when the identifier belongs to nobody; attempts are keyed
  by the SHA-256 of `"<kind>:<normalized>"`, or `"malformed:<trimmed lowercase>"`
  for input that is not a well-formed identifier
  (`authenticators.rs:IdentifierAuthenticator::perform`).
- `PasswordAuthenticator` rejects when there is no identifier key, admits the
  attempt through the guard first, and does the same lookups and password
  hashing for an unknown identifier (with a generated `UserId`) so neither
  answer nor timing tells the cases apart; it answers `Proven` only when the
  password is verified, the user may sign in and a candidate exists
  (`authenticators.rs:PasswordAuthenticator::perform`).
- `TotpAuthenticator` takes only `StepInput::Totp`, rejects when there is no
  identifier key, admits the attempt through the guard with the tenant's
  lockout rules first (shared with the password by `lockout_rules`), and
  clears the identifier's count when the code is verified
  (`authenticators.rs:TotpAuthenticator::perform`).
- `RecoveryCodeAuthenticator` takes only `StepInput::RecoveryCode`, and
  admits and clears the attempt the same way; a wrong, used, earlier or
  malformed code is the same `StepOutcome::Rejected`
  (`authenticators.rs:RecoveryCodeAuthenticator::perform`).
- Registration is refused with `Forbidden` code
  `authentication.registration_closed` unless the tenant's registration
  policy is `RegistrationPolicy::Open`, checked before anything is counted
  (`account.rs:AccountService::request_registration`).
- `request_registration` and `request_recovery` give the same answer whether
  or not the address has an account or is well formed
  (`account.rs:AccountService::request_registration`,
  `account.rs:AccountService::request_recovery`). Their requests are counted
  under the scopes `"registration"` and `"recovery"`, kept apart from sign-in
  (`account.rs:AccountService::admit`, `account.rs:AccountService::asking_key`).
- Every token failure is `NotFound` code
  `authentication.verification_token_invalid` (`account.rs:invalid_token`).
- `complete_registration` and `reset_password` check the password (and, for
  registration, the display name) before using up the token, so a refused
  password leaves the link usable (`account.rs:AccountService::complete_registration`,
  `account.rs:AccountService::reset_password`).
- Links have the form `<public_url>/t/<tenant slug>/account/<page>#token=<secret>`,
  with pages `complete-registration` and `reset-password`; the token travels
  in the URL fragment (`account.rs:AccountService::link`,
  `account.rs:AccountService::send_link`). Notices without a link expire after
  `NOTICE_LIFETIME` (24 hours) (`account.rs:NOTICE_LIFETIME`).

## Side Effects

- Each `AuthenticationService` operation opens its own unit of work through
  `hodor_kernel::UnitOfWorkFactory::begin` and calls `TransactionStore`
  `insert`, `get` or `update` (`service.rs:AuthenticationService::start`,
  `::load`, `::store`). The step's authenticator runs with no unit of work
  open (`service.rs:AuthenticationService::submit`).
- Records `AuthenticationEvent::Failed` with a rejected or failed step and
  `AuthenticationEvent::Succeeded` after a session starts, through
  `UnitOfWork::record_event` (`service.rs:AuthenticationService::record`).
- Starts a session with `hodor_session::api::SessionService::start`, using
  idle and absolute timeouts read from `hodor_tenant::api::TenantService::get`
  (`service.rs:AuthenticationService::start_session`).
- Uses `hodor_kernel::RandomSource`, `Digest::sha256` and `Clock::now`
  (`service.rs:AuthenticationService::start`).
- `AttemptGuard::admit` locks and saves counters in one unit of work and
  records `AuthenticationEvent::LockedOut` when a lockout starts;
  `succeeded` calls `AttemptStore::clear` (`guard.rs:AttemptGuard`).
- `IdentifierAuthenticator` calls `hodor_identity::api::IdentityService::find_by_login`;
  `PasswordAuthenticator` calls `TenantService::get` (lockout policy),
  `IdentityService::get` and `hodor_credential::api::CredentialService::verify_password`
  (`authenticators.rs`).
- `AccountService` reads tenant settings, looks up and creates users and
  verifies identifiers through `IdentityService`, sets passwords through
  `CredentialService`, ends sessions with `SessionService::revoke_all_for_user`
  (reason `"password_reset"`), issues and uses up tokens through
  `VerificationTokenStore`, enqueues messages with
  `hodor_notification::api::Notifier::enqueue`, and records
  `RegistrationCompleted`, `RecoveryRequested` and `PasswordReset` events
  (`account.rs:AccountService`).

## Verification

- Run: `cargo test -p hodor-authentication`
