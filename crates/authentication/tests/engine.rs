//! The flow engine, driven with stand-in authenticators.

use hodor_authentication::api::{
    AuthFlow, AuthTransaction, Authenticator, AuthenticatorTraits, Condition, ExternalInput,
    Factor, FlowEngine, FlowStep, Progress, Requirement, StepInput, StepOutcome, TransactionState,
};
use hodor_kernel::{DomainError, ErrorKind, Secret, TenantContext, TenantId, Timestamp, UserId};
use hodor_session::api::{Assurance, ClientInfo};
use proptest::prelude::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use time::Duration;

const START: Timestamp = Timestamp::UNIX_EPOCH;

/// Knows one person, "ana".
struct Directory {
    ana: UserId,
}

#[async_trait::async_trait]
impl Authenticator for Directory {
    fn kind(&self) -> &'static str {
        "identifier"
    }

    fn traits(&self) -> AuthenticatorTraits {
        AuthenticatorTraits {
            identifies: true,
            factor: None,
            method: None,
        }
    }

    async fn perform(
        &self,
        _tenant: &TenantContext,
        _transaction: &AuthTransaction,
        input: &StepInput,
    ) -> Result<StepOutcome, DomainError> {
        let StepInput::Identifier(typed) = input else {
            return Ok(StepOutcome::Rejected);
        };
        Ok(StepOutcome::Identified {
            candidate: (typed == "ana").then_some(self.ana),
            identifier_key: [typed.len() as u8; 32],
        })
    }
}

/// Accepts the password "right" for a known candidate. Can be switched to
/// fail, as a dependency that is down would.
#[derive(Default)]
struct Secrets {
    unavailable: AtomicBool,
}

#[async_trait::async_trait]
impl Authenticator for Secrets {
    fn kind(&self) -> &'static str {
        "password"
    }

    fn traits(&self) -> AuthenticatorTraits {
        AuthenticatorTraits {
            identifies: false,
            factor: Some(Factor::Knowledge),
            method: Some("password"),
        }
    }

    async fn perform(
        &self,
        _tenant: &TenantContext,
        transaction: &AuthTransaction,
        input: &StepInput,
    ) -> Result<StepOutcome, DomainError> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(DomainError::new(
                ErrorKind::Unavailable,
                "credential.hashing_overloaded",
                "busy",
            ));
        }
        let right = matches!(input, StepInput::Password(p) if p.expose() == "right");
        Ok(if right && transaction.candidate().is_some() {
            StepOutcome::Proven
        } else {
            StepOutcome::Rejected
        })
    }
}

/// An authenticator that only exists to be named in flows under test.
struct Named {
    kind: &'static str,
    traits: AuthenticatorTraits,
}

#[async_trait::async_trait]
impl Authenticator for Named {
    fn kind(&self) -> &'static str {
        self.kind
    }

    fn traits(&self) -> AuthenticatorTraits {
        self.traits
    }

    async fn perform(
        &self,
        _tenant: &TenantContext,
        _transaction: &AuthTransaction,
        _input: &StepInput,
    ) -> Result<StepOutcome, DomainError> {
        Ok(StepOutcome::Rejected)
    }
}

struct World {
    engine: FlowEngine,
    flow: AuthFlow,
    tenant: TenantContext,
    ana: UserId,
    secrets: Arc<Secrets>,
    /// What the tenant's policy demands beyond the flow's minimum.
    demanded: Assurance,
}

fn world() -> World {
    let ana = UserId::generate();
    let secrets = Arc::new(Secrets::default());
    let proves = |kind, factor| {
        Arc::new(Named {
            kind,
            traits: AuthenticatorTraits {
                identifies: false,
                factor: Some(factor),
                method: Some(kind),
            },
        })
    };
    let engine = FlowEngine::new()
        .with(Arc::new(Directory { ana }))
        .with(secrets.clone())
        .with(proves("pin", Factor::Knowledge))
        .with(proves("security-key", Factor::Possession));
    World {
        engine,
        flow: AuthFlow::built_in(),
        tenant: TenantContext::assume(TenantId::generate()),
        ana,
        secrets,
        demanded: Assurance::SingleFactor,
    }
}

impl World {
    fn begin(&self) -> AuthTransaction {
        AuthTransaction::start(&self.flow, ClientInfo::default(), [9; 32], START)
    }

    async fn submit(
        &self,
        transaction: &mut AuthTransaction,
        input: StepInput,
        now: Timestamp,
    ) -> Result<Progress, DomainError> {
        self.engine
            .submit(
                &self.tenant,
                &self.flow,
                transaction,
                &input,
                self.demanded,
                now,
            )
            .await
    }
}

fn identifier(value: &str) -> StepInput {
    StepInput::Identifier(value.to_owned())
}

fn password(value: &str) -> StepInput {
    StepInput::Password(Secret::from(value.to_owned()))
}

fn step(key: &str, authenticator: &str) -> FlowStep {
    FlowStep {
        key: key.to_owned(),
        authenticator: authenticator.to_owned(),
        requirement: Requirement::Required,
        substitutes: Vec::new(),
    }
}

fn flow(steps: Vec<FlowStep>, minimum_assurance: Assurance) -> AuthFlow {
    AuthFlow {
        name: "under-test".to_owned(),
        version: 1,
        steps,
        alternatives: Vec::new(),
        minimum_assurance,
    }
}

#[test]
fn the_built_in_flow_is_valid() {
    let world = world();
    world.engine.validate(&world.flow).expect("valid");
    let keys: Vec<&str> = world.flow.steps.iter().map(|s| s.key.as_str()).collect();
    assert_eq!(keys, ["identifier", "password"]);
    assert_eq!(world.flow.minimum_assurance, Assurance::SingleFactor);
}

#[test]
fn every_validity_rule_is_enforced() {
    let world = world();
    let single = Assurance::SingleFactor;
    let multi = Assurance::MultiFactor;
    let cases = [
        ("no steps", flow(vec![], single), "at least one step"),
        (
            "a key twice",
            flow(
                vec![
                    step("identifier", "identifier"),
                    step("identifier", "password"),
                ],
                single,
            ),
            "appears twice",
        ),
        (
            "an unknown authenticator",
            flow(
                vec![step("identifier", "identifier"), step("magic", "wizardry")],
                single,
            ),
            "unknown authenticator",
        ),
        (
            "proof before identification",
            flow(
                vec![
                    step("password", "password"),
                    step("identifier", "identifier"),
                ],
                single,
            ),
            "before any step has established whose",
        ),
        (
            "no step proves anything",
            flow(vec![step("identifier", "identifier")], single),
            "minimum assurance",
        ),
        (
            "one factor where two are required",
            flow(
                vec![
                    step("identifier", "identifier"),
                    step("password", "password"),
                ],
                multi,
            ),
            "minimum assurance",
        ),
        (
            "two factors of the same kind are still one",
            flow(
                vec![
                    step("identifier", "identifier"),
                    step("password", "password"),
                    step("pin", "pin"),
                ],
                multi,
            ),
            "minimum assurance",
        ),
    ];
    for (name, invalid, expected) in cases {
        let error = world.engine.validate(&invalid).expect_err(name);
        assert_eq!(error.code(), "authentication.flow_invalid", "{name}");
        assert!(
            error.message().contains(expected),
            "{name}: {}",
            error.message()
        );
    }

    let two_kinds = flow(
        vec![
            step("identifier", "identifier"),
            step("password", "password"),
            step("key", "security-key"),
        ],
        multi,
    );
    world
        .engine
        .validate(&two_kinds)
        .expect("two different kinds reach multi-factor");
}

#[tokio::test]
async fn the_right_password_for_a_known_user_completes_the_sign_in() {
    let world = world();
    let mut transaction = world.begin();

    let after_identifier = world
        .submit(&mut transaction, identifier("ana"), START)
        .await
        .expect("identifier");
    assert_eq!(
        after_identifier,
        Progress::Next {
            step: "password".to_owned()
        }
    );
    let after_password = world
        .submit(&mut transaction, password("right"), START)
        .await
        .expect("password");
    assert_eq!(after_password, Progress::ReadyToComplete);

    assert_eq!(
        world.engine.assurance(&transaction),
        Some(Assurance::SingleFactor)
    );
    assert_eq!(transaction.snapshot().satisfied_methods, ["password"]);
    assert_eq!(
        transaction.complete(&world.flow, START).expect("complete"),
        world.ana
    );
    assert_eq!(transaction.state_at(START), TransactionState::Completed);
}

#[tokio::test]
async fn an_unknown_identifier_gets_the_same_answer_and_can_never_complete() {
    let world = world();
    let (mut known, mut unknown) = (world.begin(), world.begin());

    let for_known = world
        .submit(&mut known, identifier("ana"), START)
        .await
        .expect("known");
    let for_unknown = world
        .submit(&mut unknown, identifier("nobody"), START)
        .await
        .expect("unknown");
    assert_eq!(
        for_known, for_unknown,
        "the identifier step never tells them apart"
    );

    // Even the right password is rejected when there is no one behind it.
    let answer = world
        .submit(&mut unknown, password("right"), START)
        .await
        .expect("password");
    assert_eq!(answer, Progress::Rejected { attempts_left: 4 });
    let error = unknown
        .complete(&world.flow, START)
        .expect_err("incomplete");
    assert_eq!(error.code(), "authentication.transaction_incomplete");
}

#[tokio::test]
async fn input_for_another_step_is_refused_and_changes_nothing() {
    let world = world();
    let mut transaction = world.begin();
    let before = transaction.clone();

    let error = world
        .submit(&mut transaction, password("right"), START)
        .await
        .expect_err("out of order");

    assert_eq!(error.code(), "authentication.unexpected_step");
    assert!(error.message().contains("identifier"));
    assert_eq!(transaction, before);
}

#[tokio::test]
async fn five_rejections_fail_the_transaction_for_good() {
    let world = world();
    let mut transaction = world.begin();
    world
        .submit(&mut transaction, identifier("ana"), START)
        .await
        .expect("identifier");

    for attempts_left in (1..=4).rev() {
        let answer = world
            .submit(&mut transaction, password("wrong"), START)
            .await
            .expect("password");
        assert_eq!(answer, Progress::Rejected { attempts_left });
    }
    let last = world
        .submit(&mut transaction, password("wrong"), START)
        .await
        .expect("password");
    assert_eq!(last, Progress::Failed);
    assert_eq!(transaction.state_at(START), TransactionState::Failed);

    // Not even the right password helps now.
    let error = world
        .submit(&mut transaction, password("right"), START)
        .await
        .expect_err("failed");
    assert_eq!(error.code(), "authentication.transaction_not_active");
    assert!(transaction.complete(&world.flow, START).is_err());
}

#[tokio::test]
async fn a_rejection_does_not_advance_and_the_right_password_still_works_after_it() {
    let world = world();
    let mut transaction = world.begin();
    world
        .submit(&mut transaction, identifier("ana"), START)
        .await
        .expect("identifier");
    world
        .submit(&mut transaction, password("wrong"), START)
        .await
        .expect("password");

    assert_eq!(transaction.snapshot().current_step, 1);
    let answer = world
        .submit(&mut transaction, password("right"), START)
        .await
        .expect("password");
    assert_eq!(answer, Progress::ReadyToComplete);
}

#[tokio::test]
async fn a_transaction_expires_ten_minutes_after_it_starts() {
    let world = world();
    let mut transaction = world.begin();
    let just_before = START + Duration::minutes(10) - Duration::seconds(1);
    let at_expiry = START + Duration::minutes(10);

    world
        .submit(&mut transaction, identifier("ana"), just_before)
        .await
        .expect("in time");
    let error = world
        .submit(&mut transaction, password("right"), at_expiry)
        .await
        .expect_err("too late");

    assert_eq!(error.code(), "authentication.transaction_not_active");
    assert_eq!(transaction.state_at(at_expiry), TransactionState::Expired);
    assert!(transaction.complete(&world.flow, at_expiry).is_err());
}

#[tokio::test]
async fn a_step_that_could_not_be_performed_is_an_error_and_not_a_rejection() {
    let world = world();
    let mut transaction = world.begin();
    world
        .submit(&mut transaction, identifier("ana"), START)
        .await
        .expect("identifier");
    let before = transaction.clone();
    world.secrets.unavailable.store(true, Ordering::SeqCst);

    let error = world
        .submit(&mut transaction, password("right"), START)
        .await
        .expect_err("unavailable");

    assert_eq!(error.kind(), ErrorKind::Unavailable);
    assert_eq!(transaction, before, "an outage does not use up an attempt");

    world.secrets.unavailable.store(false, Ordering::SeqCst);
    let answer = world
        .submit(&mut transaction, password("right"), START)
        .await
        .expect("password");
    assert_eq!(answer, Progress::ReadyToComplete);
}

#[tokio::test]
async fn a_transaction_completes_once_and_a_cancelled_one_accepts_nothing() {
    let world = world();
    let mut transaction = world.begin();
    world
        .submit(&mut transaction, identifier("ana"), START)
        .await
        .expect("identifier");
    world
        .submit(&mut transaction, password("right"), START)
        .await
        .expect("password");

    transaction.complete(&world.flow, START).expect("first");
    let again = transaction
        .complete(&world.flow, START)
        .expect_err("second");
    assert_eq!(again.code(), "authentication.transaction_not_active");
    let after = world
        .submit(&mut transaction, password("right"), START)
        .await
        .expect_err("completed");
    assert_eq!(after.code(), "authentication.transaction_not_active");

    let mut cancelled = world.begin();
    cancelled.cancel();
    assert_eq!(cancelled.state_at(START), TransactionState::Cancelled);
    assert!(
        world
            .submit(&mut cancelled, identifier("ana"), START)
            .await
            .is_err()
    );
    // Cancelling a finished transaction changes nothing.
    transaction.cancel();
    assert_eq!(transaction.state_at(START), TransactionState::Completed);
}

#[derive(Debug, Clone)]
enum Move {
    Identifier(bool),
    Password(bool),
    Wait(i64),
    Complete,
    Cancel,
}

fn a_move() -> impl Strategy<Value = Move> {
    prop_oneof![
        any::<bool>().prop_map(Move::Identifier),
        any::<bool>().prop_map(Move::Password),
        (0_i64..400).prop_map(Move::Wait),
        Just(Move::Complete),
        Just(Move::Cancel),
    ]
}

proptest! {
    /// Whatever a client sends, in whatever order and however slowly, a
    /// sign-in completes only for a known person who gave the right
    /// password, within the time allowed and within the attempts allowed.
    #[test]
    fn a_sign_in_completes_only_when_every_step_was_truly_satisfied(
        moves in proptest::collection::vec(a_move(), 0..40)
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread().build().expect("runtime");
        let world = world();
        let mut transaction = world.begin();
        let mut now = START;
        let (mut known, mut proven, mut rejections) = (false, false, 0_u32);

        for next in moves {
            let before = transaction.clone();
            let active = transaction.state_at(now) == TransactionState::InProgress;
            match next {
                Move::Wait(seconds) => now += Duration::seconds(seconds),
                Move::Cancel => transaction.cancel(),
                Move::Complete => {
                    let completed = transaction.complete(&world.flow, now);
                    prop_assert_eq!(completed.is_ok(), active && known && proven);
                    if let Ok(user) = completed {
                        prop_assert_eq!(user, world.ana);
                    }
                }
                Move::Identifier(is_ana) => {
                    let typed = if is_ana { "ana" } else { "nobody" };
                    let result = runtime.block_on(world.submit(&mut transaction, identifier(typed), now));
                    let expected_step = before.snapshot().current_step == 0;
                    prop_assert_eq!(result.is_ok(), active && expected_step);
                    if result.is_ok() {
                        known = is_ana;
                    }
                }
                Move::Password(right) => {
                    let typed = if right { "right" } else { "wrong" };
                    let result = runtime.block_on(world.submit(&mut transaction, password(typed), now));
                    let expected_step = before.snapshot().current_step == 1;
                    prop_assert_eq!(result.is_ok(), active && expected_step);
                    match result {
                        Ok(Progress::ReadyToComplete) => {
                            prop_assert!(right && known);
                            proven = true;
                        }
                        Ok(Progress::Rejected { .. } | Progress::Failed) => {
                            prop_assert!(!(right && known));
                            rejections += 1;
                        }
                        Ok(Progress::Next { .. }) => prop_assert!(false, "no step follows the password"),
                        Err(_) => prop_assert_eq!(&transaction, &before, "a refused step changes nothing"),
                    }
                }
            }
            prop_assert!(rejections <= AuthTransaction::MAX_REJECTIONS);
            prop_assert_eq!(transaction.snapshot().rejections, rejections);
            if transaction.state_at(now) == TransactionState::Completed {
                prop_assert!(known && proven);
            }
        }
    }
}

/// Stands for somewhere else that knows people: it recognizes whoever
/// brings the word "ana" and answers in the way it is told to.
struct Outside {
    ana: UserId,
    answers_as: &'static str,
}

#[async_trait::async_trait]
impl Authenticator for Outside {
    fn kind(&self) -> &'static str {
        "outside"
    }

    fn traits(&self) -> AuthenticatorTraits {
        AuthenticatorTraits {
            identifies: true,
            factor: Some(Factor::Possession),
            method: Some("outside"),
        }
    }

    async fn perform(
        &self,
        _tenant: &TenantContext,
        _transaction: &AuthTransaction,
        input: &StepInput,
    ) -> Result<StepOutcome, DomainError> {
        let StepInput::External(input) = input else {
            return Ok(StepOutcome::Rejected);
        };
        let recognized = input
            .field("word")
            .is_some_and(|word| word.expose() == "ana");
        Ok(match (recognized, self.answers_as) {
            (false, _) => StepOutcome::Rejected,
            (true, "proven") => StepOutcome::Proven,
            (true, "identified") => StepOutcome::Identified {
                candidate: Some(self.ana),
                identifier_key: [1; 32],
            },
            (true, _) => StepOutcome::Authenticated { user: self.ana },
        })
    }
}

fn outside(word: &str) -> StepInput {
    StepInput::External(ExternalInput {
        step: "outside".to_owned(),
        fields: vec![("word".to_owned(), Secret::from(word.to_owned()))],
    })
}

/// The built-in flow with one alternative, "outside".
fn world_with_alternative(answers_as: &'static str) -> World {
    let mut world = world();
    world.engine = world.engine.with(Arc::new(Outside {
        ana: world.ana,
        answers_as,
    }));
    world.flow = AuthFlow::built_in().with_alternative("outside", "outside");
    world
}

#[test]
fn the_validity_rules_of_alternatives_are_enforced() {
    let world = world_with_alternative("authenticated");
    world.engine.validate(&world.flow).expect("valid");

    let broken = |flow: AuthFlow, expected: &str| {
        let error = world.engine.validate(&flow).expect_err(expected);
        assert_eq!(error.code(), "authentication.flow_invalid");
        assert!(format!("{error:?}").contains(expected), "{error:?}");
    };
    broken(
        AuthFlow::built_in().with_alternative("password", "outside"),
        "appears twice",
    );
    broken(
        AuthFlow::built_in()
            .with_alternative("outside", "outside")
            .with_alternative("outside", "outside"),
        "appears twice",
    );
    broken(
        AuthFlow::built_in().with_alternative("elsewhere", "nobody-knows"),
        "unknown authenticator",
    );
    // One that only names the person, and one that only proves.
    broken(
        AuthFlow::built_in().with_alternative("other", "identifier"),
        "must both establish who is signing in and prove it",
    );
    broken(
        AuthFlow::built_in().with_alternative("other", "pin"),
        "must both establish who is signing in and prove it",
    );
    // One factor does not reach a flow that asks for two.
    let mut demanding = AuthFlow::built_in().with_alternative("outside", "outside");
    demanding.steps.push(step("security-key", "security-key"));
    demanding.minimum_assurance = Assurance::MultiFactor;
    broken(demanding, "does not reach the flow's minimum assurance");
}

#[tokio::test]
async fn an_alternative_completes_the_sign_in_in_place_of_every_step() {
    let world = world_with_alternative("authenticated");
    let mut transaction = world.begin();

    let progress = world
        .submit(&mut transaction, outside("ana"), START)
        .await
        .expect("submit");

    assert_eq!(progress, Progress::ReadyToComplete);
    assert!(transaction.all_steps_satisfied(&world.flow));
    assert_eq!(transaction.snapshot().satisfied_methods, ["outside"]);
    assert_eq!(
        world.engine.assurance(&transaction),
        Some(Assurance::SingleFactor)
    );
    let user = transaction.complete(&world.flow, START).expect("complete");
    assert_eq!(user, world.ana);
}

#[tokio::test]
async fn the_steps_still_complete_a_flow_that_has_an_alternative() {
    let world = world_with_alternative("authenticated");
    let mut transaction = world.begin();
    world
        .submit(&mut transaction, identifier("ana"), START)
        .await
        .expect("identifier");
    let progress = world
        .submit(&mut transaction, password("right"), START)
        .await
        .expect("password");
    assert_eq!(progress, Progress::ReadyToComplete);
    assert_eq!(transaction.snapshot().satisfied_methods, ["password"]);
}

#[tokio::test]
async fn an_alternative_is_refused_once_a_step_has_been_satisfied() {
    let world = world_with_alternative("authenticated");
    let mut transaction = world.begin();
    world
        .submit(&mut transaction, identifier("somebody else"), START)
        .await
        .expect("identifier");
    let before = transaction.clone();

    // Half of each: an identifier naming one person, then the outside
    // world vouching for another.
    let error = world
        .submit(&mut transaction, outside("ana"), START)
        .await
        .expect_err("too late for the alternative");

    assert_eq!(error.code(), "authentication.unexpected_step");
    assert_eq!(transaction, before, "nothing changed");
    assert!(transaction.complete(&world.flow, START).is_err());
}

#[tokio::test]
async fn nothing_can_be_added_after_an_alternative() {
    let world = world_with_alternative("authenticated");
    let mut transaction = world.begin();
    world
        .submit(&mut transaction, outside("ana"), START)
        .await
        .expect("submit");
    let before = transaction.clone();

    for input in [
        identifier("somebody else"),
        password("right"),
        outside("ana"),
    ] {
        let error = world
            .submit(&mut transaction, input, START)
            .await
            .expect_err("nothing is pending");
        assert_eq!(error.code(), "authentication.no_step_pending");
    }
    assert_eq!(transaction, before);
}

#[tokio::test]
async fn a_rejected_alternative_counts_like_a_rejected_step() {
    let world = world_with_alternative("authenticated");
    let mut transaction = world.begin();

    let progress = world
        .submit(&mut transaction, outside("a stranger"), START)
        .await
        .expect("submit");
    assert_eq!(progress, Progress::Rejected { attempts_left: 4 });
    assert_eq!(transaction.candidate(), None);

    // Either way is still open, and the tolerance is shared.
    world
        .submit(&mut transaction, identifier("ana"), START)
        .await
        .expect("identifier");
    for left in (1..4).rev() {
        let progress = world
            .submit(&mut transaction, password("wrong"), START)
            .await
            .expect("password");
        assert_eq!(
            progress,
            Progress::Rejected {
                attempts_left: left
            }
        );
    }
    let progress = world
        .submit(&mut transaction, password("wrong"), START)
        .await
        .expect("password");
    assert_eq!(progress, Progress::Failed);
    assert_eq!(transaction.state_at(START), TransactionState::Failed);
}

#[tokio::test]
async fn an_alternative_that_answers_like_a_step_does_not_advance_the_sign_in() {
    for answers_as in ["proven", "identified"] {
        let world = world_with_alternative(answers_as);
        let mut transaction = world.begin();
        let before = transaction.clone();

        let error = world
            .submit(&mut transaction, outside("ana"), START)
            .await
            .expect_err("a defect, not a sign-in");

        assert_eq!(error.code(), "authentication.authenticator_misbehaved");
        assert_eq!(error.kind(), ErrorKind::Internal);
        assert_eq!(transaction, before, "{answers_as}");
    }
}

#[tokio::test]
async fn a_step_that_answers_like_an_alternative_does_not_advance_the_sign_in() {
    // The same authenticator, placed as the first step of a flow. Such a
    // flow does not pass validation; the engine holds even if one ran.
    let mut world = world_with_alternative("authenticated");
    world.flow = flow(
        vec![step("outside", "outside"), step("password", "password")],
        Assurance::SingleFactor,
    );
    assert!(world.engine.validate(&world.flow).is_err());
    let mut transaction = world.begin();
    let before = transaction.clone();

    let error = world
        .submit(&mut transaction, outside("ana"), START)
        .await
        .expect_err("a defect, not a sign-in");

    assert_eq!(error.code(), "authentication.authenticator_misbehaved");
    assert_eq!(transaction, before);
}

#[tokio::test]
async fn a_flow_without_alternatives_accepts_none() {
    let world = world();
    let mut transaction = world.begin();
    let error = world
        .submit(&mut transaction, outside("ana"), START)
        .await
        .expect_err("the built-in flow has no alternative");
    assert_eq!(error.code(), "authentication.unexpected_step");
}

/// A factor some people have enrolled in and others have not: satisfied
/// by the field `code` holding "1234" for someone enrolled.
struct Enrollable {
    kind: &'static str,
    factor: Factor,
    enrolled: AtomicBool,
    /// How many times it was asked whether the person has the means.
    asked: std::sync::atomic::AtomicU32,
}

impl Enrollable {
    fn new(kind: &'static str, factor: Factor, enrolled: bool) -> Arc<Self> {
        Arc::new(Self {
            kind,
            factor,
            enrolled: AtomicBool::new(enrolled),
            asked: std::sync::atomic::AtomicU32::new(0),
        })
    }
}

#[async_trait::async_trait]
impl Authenticator for Enrollable {
    fn kind(&self) -> &'static str {
        self.kind
    }

    fn traits(&self) -> AuthenticatorTraits {
        AuthenticatorTraits {
            identifies: false,
            factor: Some(self.factor),
            method: Some(self.kind),
        }
    }

    async fn perform(
        &self,
        _tenant: &TenantContext,
        _transaction: &AuthTransaction,
        input: &StepInput,
    ) -> Result<StepOutcome, DomainError> {
        let right = matches!(
            input,
            StepInput::External(external)
                if external.field("code").is_some_and(|code| code.expose() == "1234")
        );
        Ok(if right && self.enrolled.load(Ordering::SeqCst) {
            StepOutcome::Proven
        } else {
            StepOutcome::Rejected
        })
    }

    async fn has_means(
        &self,
        _tenant: &TenantContext,
        _transaction: &AuthTransaction,
    ) -> Result<bool, DomainError> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        Ok(self.enrolled.load(Ordering::SeqCst))
    }
}

fn code(step: &str, value: &str) -> StepInput {
    StepInput::External(ExternalInput {
        step: step.to_owned(),
        fields: vec![("code".to_owned(), Secret::from(value.to_owned()))],
    })
}

/// The built-in flow followed by one more step, "key", performed by a
/// security key the person may or may not have enrolled.
fn world_with_second_step(requirement: Requirement, enrolled: bool) -> (World, Arc<Enrollable>) {
    let mut world = world();
    let key = Enrollable::new("key", Factor::Possession, enrolled);
    world.engine = world.engine.with(key.clone());
    world.flow = AuthFlow::built_in().with_step("key", "key", requirement);
    (world, key)
}

const WHEN_NOT_REACHED: Requirement = Requirement::Conditional(Condition::AssuranceNotReached);

async fn through_the_password(world: &World) -> (AuthTransaction, Progress) {
    let mut transaction = world.begin();
    world
        .submit(&mut transaction, identifier("ana"), START)
        .await
        .expect("identifier");
    let progress = world
        .submit(&mut transaction, password("right"), START)
        .await
        .expect("password");
    (transaction, progress)
}

#[test]
fn the_validity_rules_of_steps_that_are_not_required_are_enforced() {
    let (mut world, _) = world_with_second_step(Requirement::Optional, true);
    world.engine = world.engine.with(Arc::new(Named {
        kind: "remark",
        traits: AuthenticatorTraits {
            identifies: false,
            factor: None,
            method: None,
        },
    }));
    world
        .engine
        .validate(&world.flow)
        .expect("an optional second step is valid");
    let single = Assurance::SingleFactor;
    let cases = [
        (
            "a required step after an optional one",
            flow(
                vec![
                    step("identifier", "identifier"),
                    FlowStep {
                        requirement: Requirement::Optional,
                        ..step("key", "key")
                    },
                    step("password", "password"),
                ],
                single,
            ),
            "comes after a step that is not required",
        ),
        (
            "an identifying step that is not required",
            AuthFlow::built_in().with_step("again", "identifier", Requirement::Optional),
            "must be required",
        ),
        (
            "a step that is not required and proves nothing",
            AuthFlow::built_in().with_step("remark", "remark", WHEN_NOT_REACHED),
            "proves nothing",
        ),
        (
            "a minimum reached only by a step that may be passed over",
            AuthFlow {
                minimum_assurance: Assurance::MultiFactor,
                ..AuthFlow::built_in().with_step("key", "key", Requirement::Optional)
            },
            "minimum assurance",
        ),
    ];
    for (case, flow, expected) in cases {
        let error = world.engine.validate(&flow).expect_err(case);
        assert_eq!(error.code(), "authentication.flow_invalid", "{case}");
        assert!(
            error.message().contains(expected),
            "{case}: `{}` does not mention `{expected}`",
            error.message()
        );
    }
}

#[tokio::test]
async fn an_optional_step_is_performed_for_whoever_has_the_means() {
    let (world, key) = world_with_second_step(Requirement::Optional, true);
    let (mut transaction, progress) = through_the_password(&world).await;
    assert_eq!(
        progress,
        Progress::Next {
            step: "key".to_owned()
        }
    );
    assert_eq!(key.asked.load(Ordering::SeqCst), 1);
    let wrong = world
        .submit(&mut transaction, code("key", "0000"), START)
        .await
        .expect("rejected, not refused");
    assert!(matches!(wrong, Progress::Rejected { .. }));
    let right = world
        .submit(&mut transaction, code("key", "1234"), START)
        .await
        .expect("satisfied");
    assert_eq!(right, Progress::ReadyToComplete);
    assert_eq!(
        world.engine.assurance(&transaction),
        Some(Assurance::MultiFactor)
    );
    assert_eq!(
        transaction.snapshot().satisfied_methods,
        ["password", "key"],
        "the methods from which `amr` will be made"
    );
}

#[tokio::test]
async fn an_optional_step_is_passed_over_for_whoever_has_not() {
    let (world, _) = world_with_second_step(Requirement::Optional, false);
    let (mut transaction, progress) = through_the_password(&world).await;
    assert_eq!(progress, Progress::ReadyToComplete);
    assert_eq!(
        world.engine.assurance(&transaction),
        Some(Assurance::SingleFactor)
    );
    let error = world
        .submit(&mut transaction, code("key", "1234"), START)
        .await
        .expect_err("a step passed over cannot be performed afterwards");
    assert_eq!(error.code(), "authentication.no_step_pending");
}

#[tokio::test]
async fn a_step_that_is_performed_cannot_be_declined() {
    let (world, _) = world_with_second_step(Requirement::Optional, true);
    let (mut transaction, _) = through_the_password(&world).await;
    let before = transaction.clone();
    for input in [password("right"), identifier("ana")] {
        let error = world
            .submit(&mut transaction, input, START)
            .await
            .expect_err("only the waiting step is accepted");
        assert_eq!(error.code(), "authentication.unexpected_step");
    }
    assert_eq!(transaction, before);
    assert!(
        !transaction.all_steps_satisfied(&world.flow),
        "the sign-in is still waiting for the security key"
    );
}

#[tokio::test]
async fn a_conditional_step_is_passed_over_once_the_assurance_is_reached() {
    let (world, key) = world_with_second_step(WHEN_NOT_REACHED, true);
    let (_, progress) = through_the_password(&world).await;
    assert_eq!(progress, Progress::ReadyToComplete);
    assert_eq!(
        key.asked.load(Ordering::SeqCst),
        0,
        "the means are not asked about when the condition does not hold"
    );
}

#[tokio::test]
async fn a_conditional_step_is_performed_while_the_assurance_demanded_is_not_reached() {
    let (mut world, _) = world_with_second_step(WHEN_NOT_REACHED, true);
    world.demanded = Assurance::MultiFactor;
    let (mut transaction, progress) = through_the_password(&world).await;
    assert_eq!(
        progress,
        Progress::Next {
            step: "key".to_owned()
        }
    );
    let done = world
        .submit(&mut transaction, code("key", "1234"), START)
        .await
        .expect("satisfied");
    assert_eq!(done, Progress::ReadyToComplete);
    assert_eq!(
        world.engine.assurance(&transaction),
        Some(Assurance::MultiFactor)
    );
}

#[tokio::test]
async fn a_conditional_step_is_passed_over_for_whoever_has_not_the_means_even_when_it_holds() {
    let (mut world, key) = world_with_second_step(WHEN_NOT_REACHED, false);
    world.demanded = Assurance::MultiFactor;
    let (transaction, progress) = through_the_password(&world).await;
    assert_eq!(progress, Progress::ReadyToComplete);
    assert_eq!(key.asked.load(Ordering::SeqCst), 1);
    assert_eq!(
        world.engine.assurance(&transaction),
        Some(Assurance::SingleFactor),
        "what the sign-in reached falls short; the service refuses it at completion"
    );
}

#[tokio::test]
async fn a_second_factor_of_the_same_kind_does_not_make_two() {
    let mut world = world();
    let pin = Enrollable::new("pin", Factor::Knowledge, true);
    world.engine = world.engine.with(pin);
    world.demanded = Assurance::MultiFactor;
    world.flow = AuthFlow::built_in().with_step("pin", "pin", WHEN_NOT_REACHED);
    let (mut transaction, progress) = through_the_password(&world).await;
    assert_eq!(
        progress,
        Progress::Next {
            step: "pin".to_owned()
        }
    );
    world
        .submit(&mut transaction, code("pin", "1234"), START)
        .await
        .expect("satisfied");
    assert_eq!(
        world.engine.assurance(&transaction),
        Some(Assurance::SingleFactor)
    );
}

#[tokio::test]
async fn the_steps_that_are_not_required_still_apply_after_an_alternative() {
    let mut world = world_with_alternative("authenticated");
    let pin = Enrollable::new("pin", Factor::Knowledge, true);
    world.engine = world.engine.with(pin);
    world.flow = world.flow.with_step("pin", "pin", WHEN_NOT_REACHED);
    world.demanded = Assurance::MultiFactor;
    let mut transaction = world.begin();
    let progress = world
        .submit(&mut transaction, outside("ana"), START)
        .await
        .expect("the alternative");
    assert_eq!(
        progress,
        Progress::Next {
            step: "pin".to_owned()
        },
        "the alternative takes the place of the required steps only"
    );
    world
        .submit(&mut transaction, code("pin", "1234"), START)
        .await
        .expect("satisfied");
    assert_eq!(
        world.engine.assurance(&transaction),
        Some(Assurance::MultiFactor)
    );

    world.demanded = Assurance::SingleFactor;
    let mut transaction = world.begin();
    let progress = world
        .submit(&mut transaction, outside("ana"), START)
        .await
        .expect("the alternative");
    assert_eq!(progress, Progress::ReadyToComplete);
}

#[tokio::test]
async fn a_failure_to_learn_the_means_leaves_the_sign_in_unchanged() {
    struct Unreachable;
    #[async_trait::async_trait]
    impl Authenticator for Unreachable {
        fn kind(&self) -> &'static str {
            "key"
        }
        fn traits(&self) -> AuthenticatorTraits {
            AuthenticatorTraits {
                identifies: false,
                factor: Some(Factor::Possession),
                method: Some("key"),
            }
        }
        async fn perform(
            &self,
            _tenant: &TenantContext,
            _transaction: &AuthTransaction,
            _input: &StepInput,
        ) -> Result<StepOutcome, DomainError> {
            Ok(StepOutcome::Rejected)
        }
        async fn has_means(
            &self,
            _tenant: &TenantContext,
            _transaction: &AuthTransaction,
        ) -> Result<bool, DomainError> {
            Err(DomainError::new(
                ErrorKind::Unavailable,
                "credential.unavailable",
                "busy",
            ))
        }
    }
    let mut world = world();
    world.engine = world.engine.with(Arc::new(Unreachable));
    world.flow = AuthFlow::built_in().with_step("key", "key", Requirement::Optional);
    let mut transaction = world.begin();
    world
        .submit(&mut transaction, identifier("ana"), START)
        .await
        .expect("identifier");
    let before = transaction.clone();
    let error = world
        .submit(&mut transaction, password("right"), START)
        .await
        .expect_err("the means could not be learned");
    assert_eq!(error.kind(), ErrorKind::Unavailable);
    assert_eq!(
        transaction, before,
        "the password step is not recorded either"
    );
}

/// The built-in flow, then the security key "key" as an optional step, with
/// "spare" as its substitute; both enrolled or not as asked.
fn world_with_substitute(key_enrolled: bool, spare_enrolled: bool) -> (World, Arc<Enrollable>) {
    let (mut world, _) = world_with_second_step(Requirement::Optional, key_enrolled);
    let spare = Enrollable::new("spare", Factor::Possession, spare_enrolled);
    world.engine = world.engine.with(spare.clone());
    world.flow = world.flow.with_substitute("key", "spare");
    (world, spare)
}

#[test]
fn the_validity_rules_of_substitutes_are_enforced() {
    let (mut world, _) = world_with_substitute(true, true);
    world.engine = world.engine.with(Arc::new(Named {
        kind: "remark",
        traits: AuthenticatorTraits {
            identifies: false,
            factor: None,
            method: None,
        },
    }));
    world.engine = world.engine.with(Arc::new(Named {
        kind: "badge",
        traits: AuthenticatorTraits {
            identifies: true,
            factor: Some(Factor::Possession),
            method: Some("badge"),
        },
    }));
    world
        .engine
        .validate(&world.flow)
        .expect("a substitute of an optional second step is valid");
    let optional_key = || AuthFlow::built_in().with_step("key", "key", Requirement::Optional);
    let mut alternative_with_substitute =
        AuthFlow::built_in().with_alternative("security-key", "security-key");
    alternative_with_substitute.alternatives[0]
        .substitutes
        .push("spare".to_owned());
    let cases = [
        (
            "a substitute of a required step",
            AuthFlow::built_in().with_substitute("password", "spare"),
            "is required",
        ),
        (
            "a substitute with the key of a step",
            optional_key().with_substitute("key", "password"),
            "has the key of another step",
        ),
        (
            "the same substitute twice for one step",
            optional_key()
                .with_substitute("key", "spare")
                .with_substitute("key", "spare"),
            "has the key of another step",
        ),
        (
            "a substitute that establishes who is signing in",
            optional_key().with_substitute("key", "badge"),
            "without establishing who is signing in",
        ),
        (
            "a substitute that proves nothing",
            optional_key().with_substitute("key", "remark"),
            "must prove a factor",
        ),
        (
            "a substitute the engine does not know",
            optional_key().with_substitute("key", "carrier-pigeon"),
            "unknown authenticator",
        ),
        (
            "an alternative with a substitute",
            alternative_with_substitute,
            "has substitutes",
        ),
    ];
    for (case, flow, expected) in cases {
        let error = world.engine.validate(&flow).expect_err(case);
        assert_eq!(error.code(), "authentication.flow_invalid", "{case}");
        assert!(
            error.message().contains(expected),
            "{case}: `{}` does not mention `{expected}`",
            error.message()
        );
    }
}

#[tokio::test]
async fn a_substitute_satisfies_the_step_and_records_its_own_method() {
    let (world, _) = world_with_substitute(true, true);
    let (mut transaction, progress) = through_the_password(&world).await;
    assert_eq!(
        progress,
        Progress::Next {
            step: "key".to_owned()
        },
        "the step is what the pages show"
    );
    let done = world
        .submit(&mut transaction, code("spare", "1234"), START)
        .await
        .expect("satisfied by the substitute");
    assert_eq!(done, Progress::ReadyToComplete);
    assert_eq!(
        world.engine.assurance(&transaction),
        Some(Assurance::MultiFactor)
    );
    assert_eq!(
        transaction.snapshot().satisfied_methods,
        ["password", "spare"],
        "the substitute's method, not the step's"
    );
    let error = world
        .submit(&mut transaction, code("key", "1234"), START)
        .await
        .expect_err("the step is satisfied already");
    assert_eq!(error.code(), "authentication.no_step_pending");
}

#[tokio::test]
async fn a_rejected_substitute_counts_against_the_step_which_still_waits() {
    let (world, _) = world_with_substitute(true, true);
    let (mut transaction, _) = through_the_password(&world).await;
    let first = world
        .submit(&mut transaction, code("spare", "0000"), START)
        .await
        .expect("rejected, not refused");
    let Progress::Rejected {
        attempts_left: after_substitute,
    } = first
    else {
        panic!("a wrong substitute is a rejection, not {first:?}");
    };
    let second = world
        .submit(&mut transaction, code("key", "0000"), START)
        .await
        .expect("rejected, not refused");
    let Progress::Rejected {
        attempts_left: after_step,
    } = second
    else {
        panic!("a wrong code of the step is a rejection, not {second:?}");
    };
    assert_eq!(
        after_step + 1,
        after_substitute,
        "both ways count against the same tolerance"
    );
    let done = world
        .submit(&mut transaction, code("key", "1234"), START)
        .await
        .expect("the step itself still works");
    assert_eq!(done, Progress::ReadyToComplete);
    assert_eq!(
        transaction.snapshot().satisfied_methods,
        ["password", "key"]
    );
}

#[tokio::test]
async fn a_substitute_is_not_offered_for_a_step_that_is_passed_over() {
    let (world, spare) = world_with_substitute(false, true);
    let (mut transaction, progress) = through_the_password(&world).await;
    assert_eq!(
        progress,
        Progress::ReadyToComplete,
        "without the security key the step is passed over, whatever the substitute"
    );
    assert_eq!(
        spare.asked.load(Ordering::SeqCst),
        0,
        "whether the step is performed is the step's own question"
    );
    let error = world
        .submit(&mut transaction, code("spare", "1234"), START)
        .await
        .expect_err("nothing waits for a substitute");
    assert_eq!(error.code(), "authentication.no_step_pending");
}

#[tokio::test]
async fn a_substitute_is_accepted_only_while_its_step_waits() {
    let (world, _) = world_with_substitute(true, true);
    let mut transaction = world.begin();
    world
        .submit(&mut transaction, identifier("ana"), START)
        .await
        .expect("identifier");
    let before = transaction.clone();
    let error = world
        .submit(&mut transaction, code("spare", "1234"), START)
        .await
        .expect_err("the sign-in waits for the password");
    assert_eq!(error.code(), "authentication.unexpected_step");
    assert_eq!(transaction, before, "a refused substitute changes nothing");
}
