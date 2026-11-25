# authentication/src

## Overview

The source root of the `hodor-authentication` crate. `lib.rs` describes the
context: it "decides whether someone has proved who they are: runs a sign-in
from the first step to the moment a session starts. It owns the procedure,
not the users, credentials or sessions." The specification it follows is
`docs/architecture/contexts/authentication.md` (`lib.rs` crate comment).

The modules `application` and `domain` are private (`mod application;`,
`mod domain;`); other crates use only `pub mod api`.

## Interface

### `lib.rs: pub mod api`

- Application: `AccountRequest`, `AccountService`, `IdentifierAuthenticator`,
  `PasswordAuthenticator`, `TotpAuthenticator`, `WebAuthnAuthenticator`,
  `RecoveryCodeAuthenticator`, `PasskeyAuthenticator`, `EmailAuthenticator`,
  `EmailSignInPorts`, `EnrollmentAuthenticator`, `FactorService`, `StepChallenge`, `AttemptGuard`, the port
  traits `AttemptStore`,
  `TransactionStore`, `VerificationTokenStore`, `EmailSignInStore`, and `AuthenticationService`,
  `SignIn`, `StartedSignIn`.
- Domain: `AttemptCounter`, `AttemptSubject`, `LockoutRules`, `Authenticator`,
  `AuthenticatorTraits`, `ExternalInput`, `Factor`, `StepInput`, `StepOutcome`,
  `FlowEngine`, `Progress`, `Submitted`, `BegunEnrollment`, `Enrolled`,
  `EnrollmentKind`, `AuthenticationEvent`, `AuthFlow`, `FlowStep`,
  `Requirement`, `Condition`, `AuthTransaction`, `TransactionId`, `TransactionSnapshot`,
  `TransactionState`, `TransactionStatus`, `TokenPurpose`,
  `VerificationSecret`, `VerificationToken`, `VerificationTokenHash`,
  `VerificationTokenId`, `VerificationTokenSnapshot`, `EmailMethod`,
  `EmailSecret`, `EmailSecretHash`, `EmailSignIn`, `EmailSignInSnapshot`,
  `EmailUse`.

### `testing.rs` (public test support)

Compiled only under `#[cfg(any(test, feature = "testing"))]` (`lib.rs`), that
is, with the crate feature `testing`.

- `InMemoryAttempts` (implements `AttemptStore`), `AttemptPorts`,
  `run_attempt_contract(ports)`.
- `InMemoryTransactions` (implements `TransactionStore`), `TransactionPorts`,
  `run_transaction_contract(ports)`.
- `InMemoryVerificationTokens` (implements `VerificationTokenStore`),
  `VerificationTokenPorts`, `run_verification_token_contract(ports)`.
- `InMemoryEmailSignIns` (implements `EmailSignInStore`, atomic under one
  lock; `count()`), `EmailSignInPortsUnderTest`,
  `run_email_sign_in_contract(ports)`.
- `TestSecondFactor` (implements `Authenticator`): a stand-in second factor
  of kind `test-second-factor`, a possession factor whose method is
  `test-second-factor`. `enroll(user)` gives a person the means for it; it is
  satisfied by an `External` input whose field `code` is `TestSecondFactor::CODE`
  (`"246810"`), for someone enrolled. Used until real second factors exist.

### Subdirectories

- [application](./application/EGM.md): `AuthenticationService`,
  `AccountService`, `AttemptGuard`, the two built-in authenticators, and the
  port traits.
- [domain](./domain/EGM.md): flows, `FlowEngine`, `AuthTransaction`, the
  `Authenticator` trait, attempt counting, verification tokens and
  `AuthenticationEvent`.

## Invariants

- The contract suites in `testing.rs` state what every store implementation
  must do (`testing.rs:run_attempt_contract`, `run_transaction_contract`,
  `run_verification_token_contract`):
  - attempt counters are separate per subject kind and per tenant, load back
    as saved (lockout included), and `clear` resets only one subject;
  - a transaction loads back only in its own tenant; `update` raises the
    version, and of two updates from the same version the second fails with
    `authentication.transaction_modified_concurrently`; an update from
    another tenant fails with `authentication.transaction_not_found`;
  - a token is found and used up only in its own tenant and purpose, works
    once, cannot be used at or after expiry, and `replace_earlier` marks only
    unused, unreplaced tokens of the same purpose, address and tenant.

## Side Effects

- `lib.rs` has none.
- The in-memory stores in `testing.rs` keep state in an
  `Arc<Mutex<BTreeMap<..>>>` and recover a poisoned lock; they do not
  serialize concurrent access the way `AttemptStore::lock` requires of a real
  store (`testing.rs:InMemoryAttempts`).
- Side effects of the use cases are listed in
  [application](./application/EGM.md).

## Verification

- Run: `cargo test -p hodor-authentication`
