# hodor-authentication

## Overview

The authentication context: "runs a sign-in from the first step to the start
of a session" (`Cargo.toml` description). It drives every sign-in through a
data-defined flow and `FlowEngine`, protects against guessing with attempt
counters and lockouts, and handles registration and password recovery by
email link. Users, credentials, sessions, tenants and messages belong to other
contexts, which this crate calls through their services. The specification is
`docs/architecture/contexts/authentication.md` (`src/lib.rs`).

## Interface

- [src](./src/EGM.md): the public surface `hodor_authentication::api`, the
  `testing` module, and links to `application` and `domain`.
- Port traits implemented by adapters: `AttemptStore`, `TransactionStore`,
  `VerificationTokenStore`, `EmailSignInStore` (implemented in
  `crates/adapters-postgres/src/authentication.rs`).
- Service entry points: `AuthenticationService` (`start`, `describe`,
  `submit`, `cancel`), `AccountService` (`request_registration`,
  `complete_registration`, `request_recovery`, `reset_password`),
  `AttemptGuard` (`admit`, `succeeded`).
- Domain events: `AuthenticationEvent` (`authentication.succeeded`,
  `authentication.failed`, `authentication.locked_out`,
  `authentication.registration_completed`,
  `authentication.recovery_requested`, `authentication.password_reset`,
  `authentication.email_sign_in_sent`).
- Extension point: the `Authenticator` trait, with the built-in
  `IdentifierAuthenticator`, `PasswordAuthenticator`, `TotpAuthenticator`,
  `RecoveryCodeAuthenticator`, a substitute of the second factor step, and
  the alternatives `PasskeyAuthenticator` and `EmailAuthenticator` (a code
  or a link by email).

### Workspace dependencies (`Cargo.toml`)

- `hodor-kernel` (`crates/kernel`): units of work, events, errors, clock,
  digest, random source.
- `hodor-identity` (`crates/identity`): `IdentityService`, `NormalizedIdentifier`.
- `hodor-credential` (`crates/credential`): `CredentialService`, `PasswordCheck`.
- `hodor-session` (`crates/session`): `SessionService`, `Assurance`, `ClientInfo`.
- `hodor-tenant` (`crates/tenant`): `TenantService`, tenant settings.
- `hodor-notification` (`crates/notification`): `Notifier`, message templates.
- External: `async-trait`, `serde`, `time`.

### Feature

- `testing = ["hodor-kernel/testing"]`: enables `src/testing.rs`, the
  in-memory stores and their contract suites.

## Invariants

- No hand-written sign-in procedure: every flow, including
  `AuthFlow::built_in`, runs through `FlowEngine`, and a flow that fails
  `FlowEngine::validate` is never run (`src/domain/engine.rs:FlowEngine`,
  `src/application/service.rs:AuthenticationService::new`).
- Completing a sign-in happens once, guarded by the transaction version
  (`src/application/ports.rs:TransactionStore::update`).
- Answers do not reveal whether an identifier or email address has an
  account (`src/application/authenticators.rs`, `src/application/account.rs`).
- Details per directory are in [src](./src/EGM.md).

## Side Effects

- Storage only through the three port traits, each inside a
  `hodor_kernel` unit of work.
- Calls into the identity, credential, session, tenant and notification
  contexts, and records `AuthenticationEvent` values with
  `UnitOfWork::record_event`.

## Verification

- Run: `cargo test -p hodor-authentication`
