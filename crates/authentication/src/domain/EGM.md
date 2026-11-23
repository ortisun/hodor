# authentication/src/domain

## Overview

The domain model of the authentication context: flows as data, the engine that
interprets them, the sign-in transaction and its states, the authenticator
extension point, attempt counting and lockout, verification tokens, and the
context's events. The code here does no input or output; time, randomness and
hashing arrive as parameters. Every module is `pub(crate)`; the public names
reach other crates only through `hodor_authentication::api` in `../lib.rs`.

## Interface

### Flows (`flow.rs`)

- `AuthFlow { name, version, steps, alternatives, minimum_assurance }`
  (`flow.rs:AuthFlow`); `AuthFlow::built_in()` is the `"sign-in"` flow,
  version 1, with steps `identifier` then `password` and minimum assurance
  `Assurance::SingleFactor`; `with_step(key, authenticator, requirement)` adds
  a step at the end; `with_alternative(key, authenticator)` adds an
  alternative step; `with_substitute(key, authenticator)` lets the kind of
  authenticator satisfy the step with that key in its place;
  `required_steps()` counts the leading required steps.
- `FlowStep { key, authenticator, requirement, substitutes }`
  (`flow.rs:FlowStep`); `substitutes` are kinds of authenticator, each
  submitted under its own kind as key.
- `Requirement` (`flow.rs:Requirement`): `Required`, `Optional` (performed when
  the authenticator's `has_means` says yes), `Conditional(Condition)`
  (performed when the condition holds and `has_means` says yes);
  `is_required()`.
- `Condition` (`flow.rs:Condition`): `AssuranceNotReached`, which holds while
  the satisfied methods are below the assurance the sign-in must reach, and
  `MultiFactorNotReached`, which holds while they are below multi-factor, and
  `StrongerAssuranceNeeded`, which holds while they are below the higher of
  multi-factor and what the sign-in must reach.

### Engine (`engine.rs`)

- `FlowEngine` (`engine.rs:FlowEngine`): `new()`, `with(authenticator)`
  (a later registration of the same kind replaces the earlier one),
  `validate(flow)`,
  `submit(tenant, flow, transaction, input, demanded, now) -> Progress`
  (`demanded` is the assurance the tenant's policy asks beyond the flow's
  minimum; after a satisfied step the steps to be passed over are passed over,
  and an error leaves the transaction unchanged),
  `challenge(tenant, flow, transaction, step, now)` (the current step's, or
  an alternative's while `current_step` is 0),
  `assurance(transaction) -> Option<Assurance>` over the carried and satisfied
  methods, `assurance_of_methods(methods)` (counts `factor` and
  `second_factor` of every method; two kinds with an authenticator whose
  `resists_phishing()` is true are `PhishingResistant`),
  `satisfied_by(flow, carried)` (steps a step-up starts past),
  `reachable(tenant, flow, transaction, must_reach)` and
  `settle(tenant, flow, transaction, demanded)` for a step-up just started.
- `Authenticator::resists_phishing()` defaults to `false`; the WebAuthn and
  passkey authenticators answer `true`.
- `AuthTransaction::start_step_up(...)` makes a step-up transaction with
  `carried_methods`, `demanded` and `raised_session`; `counted_methods()` is
  the carried methods followed by the satisfied ones.
- Validity rules added for steps that are not required: they come after every
  required step, never establish who is signing in, and prove a factor; only
  required steps count towards the minimum assurance.
- `Progress` (`engine.rs:Progress`): `Next { step }`, `ReadyToComplete`,
  `Rejected { attempts_left }`, `Failed`.

### Authenticators (`authenticator.rs`)

- `Authenticator` trait (`authenticator.rs:Authenticator`), the context's
  extension point: `kind() -> &'static str`, `traits() -> AuthenticatorTraits`,
  `perform(tenant, transaction, input) -> StepOutcome`, and
  `has_means(tenant, transaction) -> bool`, asked only for steps that are not
  required; the default answers `true`; and `challenge(tenant, transaction) ->
  Option<StepChallenge>`, for a step that checks an answer only to a question
  it asked; the default answers `None`.
- `StepChallenge { challenge: [u8; 32], options: serde_json::Value }`: what the
  engine keeps in the transaction, and what the browser needs.
- `AuthenticatorTraits { identifies, factor, second_factor, method }`;
  `second_factor` is a second kind of evidence the same step provides, as a
  passkey's user verification does.
- `Factor`: `Knowledge`, `Possession`, `Inherence`.
- `StepInput`: `Identifier(String)`, `Password(Secret<String>)`,
  `Totp(Secret<String>)`, `RecoveryCode(Secret<String>)`,
  `External(ExternalInput)`; `step_key()` gives `"identifier"`,
  `"password"`, `"totp"`, `"recovery_code"` or the external input's step.
- `ExternalInput { step, fields }` with `field(name)`.
- `StepOutcome`: `Identified { candidate, identifier_key }`, `Proven`,
  `Authenticated { user }`, `Rejected`.

### Transactions (`transaction.rs`)

- `TransactionId` (defined with `hodor_kernel::define_id!`).
- `AuthTransaction` (`transaction.rs:AuthTransaction`): `LIFETIME` (10
  minutes), `MAX_REJECTIONS` (5), `start(flow, client, binding, now)`,
  `from_snapshot`, `snapshot`, `id`, `candidate`, `is_bound_to`, `state_at`,
  `all_steps_satisfied`, `require_in_progress`, `complete(flow, now) -> UserId`,
  `cancel()`.
- `TransactionSnapshot` (`transaction.rs:TransactionSnapshot`): the stored
  state, including `current_step`, `candidate`, `identifier_key`,
  `satisfied_methods`, `rejections`, `status`, `expires_at`, `client`,
  `binding` and `version`.
- `TransactionStatus`: `InProgress`, `Completed`, `Failed`, `Cancelled`, with
  stored names `in_progress`, `completed`, `failed`, `cancelled`
  (`as_str`, `from_stored`).
- `TransactionState`: the status plus `Expired`.

### Attempts (`attempt.rs`)

- `AttemptSubject`: `Identifier([u8; 32])`, `Address([u8; 32])`; `kind()`
  gives `"identifier"` or `"address"`, `key()` the digest.
- `LockoutRules { max_failures, window, first_lockout, longest_lockout }`;
  `ADDRESS_FACTOR` is 10; `limit_for(subject)`.
- `AttemptCounter`: `new`, `from_stored`, accessors, `locked_until(now)`,
  `count(rules, now) -> Option<Timestamp>`.

### Verification tokens (`verification.rs`)

- `TokenPurpose`: `Registration` (stored `registration`, lifetime 24 hours)
  and `PasswordRecovery` (stored `password_recovery`, lifetime 1 hour);
  `as_str`, `from_stored`, `lifetime`.
- `VerificationSecret` (`LENGTH` 64, `expose()`), `VerificationTokenHash`
  (`of_presented`, `from_stored`, `as_bytes`), `VerificationTokenId`,
  `VerificationTokenSnapshot`, `VerificationToken` (`issue`, `from_snapshot`,
  `snapshot`, `id`, `is_good_at`, `mark_used`, `mark_replaced`).

### Domain events (`event.rs`)

`AuthenticationEvent` (`event.rs:AuthenticationEvent`), serialized untagged,
implements `hodor_kernel::DomainEvent`:

| Variant | Fields | `event_type` |
| --- | --- | --- |
| `Succeeded` | `user_id`, `session_id`, `methods` | `authentication.succeeded` |
| `Failed` | `step`, `user_id` (optional) | `authentication.failed` |
| `LockedOut` | `subject`, `until` (RFC 3339) | `authentication.locked_out` |
| `RegistrationCompleted` | `user_id` | `authentication.registration_completed` |
| `RecoveryRequested` | `user_id` | `authentication.recovery_requested` |
| `PasswordReset` | `user_id` | `authentication.password_reset` |

## Invariants

- Events never carry the typed identifier, an email address, a token, a link
  or anything about a password (`event.rs` module comment; the variants
  carry only the fields above).
- `FlowEngine::validate` returns `Invalid` code `authentication.flow_invalid`
  when a flow has no steps, repeats a step key, names an unknown
  authenticator, proves an identity before any step established whose, has
  no identifying step, does not reach its minimum assurance, has an
  alternative that does not both identify and prove at that assurance, or
  has a substitute that stands for a required step, belongs to an
  alternative, repeats a key, names an unknown authenticator, identifies or
  proves nothing (`engine.rs:FlowEngine::validate`,
  `validate_substitutes`).
- A substitute is accepted only while the sign-in waits for its step; what it
  proves is recorded under its own method, and a rejected substitute counts
  as a rejection of the step, which still waits (`engine.rs:FlowEngine::submit`).
- Assurance: one kind of factor is single-factor, two different kinds are
  multi-factor, none is `None` (`engine.rs:assurance_of`).
- `FlowEngine::submit` requires the transaction to be in progress, accepts an
  alternative only while no step has been satisfied, returns `Invalid` code
  `authentication.unexpected_step` for input meant for another step and
  `Conflict` code `authentication.no_step_pending` when nothing is pending;
  an outcome that the step's place does not allow returns an internal error
  code `authentication.authenticator_misbehaved`. In every error case the
  transaction is left unchanged (`engine.rs:FlowEngine::submit`).
- A wrong secret is not an error for an authenticator: it is
  `StepOutcome::Rejected` (`authenticator.rs:Authenticator::perform`). Only an
  alternative may answer `Authenticated` (`authenticator.rs:StepOutcome`).
- A transaction expires `LIFETIME` after it starts; `state_at` reports
  `Expired` for an in-progress transaction at or past `expires_at`
  (`transaction.rs:AuthTransaction::state_at`). `require_in_progress` returns
  `Conflict` code `authentication.transaction_not_active` otherwise.
- After `MAX_REJECTIONS` rejections the status becomes `Failed`
  (`transaction.rs:AuthTransaction::record_rejection`).
- `complete` returns `Conflict` code `authentication.transaction_incomplete`
  unless every step is satisfied and a candidate is known
  (`transaction.rs:AuthTransaction::complete`); `cancel` does nothing once the
  transaction has ended (`transaction.rs:AuthTransaction::cancel`).
- An unknown stored status is an internal error code
  `authentication.stored_data_invalid` (`transaction.rs:TransactionStatus::from_stored`).
- `version` is incremented on every stored change, for optimistic locking
  (`transaction.rs:TransactionSnapshot::version`); the transaction is bound to
  the SHA-256 of the browser secret (`transaction.rs:TransactionSnapshot::binding`).
- An address may fail `ADDRESS_FACTOR` times more than an identifier
  (`attempt.rs:LockoutRules::limit_for`). `count` resets the window when it
  has passed; reaching the limit starts a lockout whose length doubles with
  each lockout of the same subject, up to `longest_lockout`, and resets the
  failures (`attempt.rs:AttemptCounter::count`).
- A verification token is good only while unused, not replaced and not
  expired (`verification.rs:VerificationToken::is_good_at`). Only the SHA-256
  of its 64-character hexadecimal secret is stored; a presented value of the
  wrong shape yields no hash and nothing is looked up
  (`verification.rs:VerificationTokenHash::of_presented`).
- `Debug` of `VerificationSecret` prints `VerificationSecret([REDACTED])` and
  of `VerificationTokenHash` prints `VerificationTokenHash(..)`
  (`verification.rs`).
- `TokenPurpose::from_stored` returns `Invalid` code
  `authentication.unknown_token_purpose` for an unknown name.

## Side Effects

- None from input or output: no storage, network or clock reads in this
  directory.
- `VerificationToken::issue` draws 32 bytes from the `hodor_kernel::RandomSource`
  it is given and hashes the secret with the given `Digest`
  (`verification.rs:VerificationToken::issue`); `VerificationTokenHash::of_presented`
  hashes with the given `Digest`.
- `FlowEngine::submit` calls the registered `Authenticator::perform`, whose
  side effects belong to the authenticator (`engine.rs:FlowEngine::submit`).

## Verification

- Run: `cargo test -p hodor-authentication`
