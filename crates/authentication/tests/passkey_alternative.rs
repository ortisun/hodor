//! An alternative that needs a challenge and proves two factors at once,
//! as a passkey does, driven through the engine with stand-in
//! authenticators; and the condition that passes over a second factor once
//! the sign-in is multi-factor.

use hodor_authentication::api::{
    AuthFlow, AuthTransaction, Authenticator, AuthenticatorTraits, Condition, ExternalInput,
    Factor, FlowEngine, FlowStep, Progress, Requirement, StepChallenge, StepInput, StepOutcome,
};
use hodor_kernel::{DomainError, Secret, TenantContext, TenantId, Timestamp, UserId};
use hodor_session::api::{Assurance, ClientInfo};
use serde_json::json;
use std::sync::Arc;

const START: Timestamp = Timestamp::UNIX_EPOCH;

/// Identifies everyone as the same person.
struct Anyone(UserId);

#[async_trait::async_trait]
impl Authenticator for Anyone {
    fn kind(&self) -> &'static str {
        "identifier"
    }

    fn traits(&self) -> AuthenticatorTraits {
        AuthenticatorTraits {
            identifies: true,
            factor: None,
            second_factor: None,
            method: None,
        }
    }

    async fn perform(
        &self,
        _tenant: &TenantContext,
        _transaction: &AuthTransaction,
        _input: &StepInput,
    ) -> Result<StepOutcome, DomainError> {
        Ok(StepOutcome::Identified {
            candidate: Some(self.0),
            identifier_key: [1; 32],
        })
    }
}

/// Accepts any input: something the person knows.
struct Knows;

#[async_trait::async_trait]
impl Authenticator for Knows {
    fn kind(&self) -> &'static str {
        "password"
    }

    fn traits(&self) -> AuthenticatorTraits {
        AuthenticatorTraits {
            identifies: false,
            factor: Some(Factor::Knowledge),
            second_factor: None,
            method: Some("password"),
        }
    }

    async fn perform(
        &self,
        _tenant: &TenantContext,
        _transaction: &AuthTransaction,
        _input: &StepInput,
    ) -> Result<StepOutcome, DomainError> {
        Ok(StepOutcome::Proven)
    }
}

/// A second factor every person has: something they have.
struct Has(&'static str);

#[async_trait::async_trait]
impl Authenticator for Has {
    fn kind(&self) -> &'static str {
        self.0
    }

    fn traits(&self) -> AuthenticatorTraits {
        AuthenticatorTraits {
            identifies: false,
            factor: Some(Factor::Possession),
            second_factor: None,
            method: Some(self.0),
        }
    }

    async fn perform(
        &self,
        _tenant: &TenantContext,
        _transaction: &AuthTransaction,
        _input: &StepInput,
    ) -> Result<StepOutcome, DomainError> {
        Ok(StepOutcome::Proven)
    }
}

/// Names the person from an answer to its challenge, and proves two
/// factors: a stand-in for a passkey.
struct Passkey(UserId);

#[async_trait::async_trait]
impl Authenticator for Passkey {
    fn kind(&self) -> &'static str {
        "passkey"
    }

    fn traits(&self) -> AuthenticatorTraits {
        AuthenticatorTraits {
            identifies: true,
            factor: Some(Factor::Possession),
            second_factor: Some(Factor::Inherence),
            method: Some("passkey"),
        }
    }

    async fn perform(
        &self,
        _tenant: &TenantContext,
        transaction: &AuthTransaction,
        input: &StepInput,
    ) -> Result<StepOutcome, DomainError> {
        let StepInput::External(input) = input else {
            return Ok(StepOutcome::Rejected);
        };
        let right = transaction.challenge().is_some_and(|challenge| {
            input
                .field("signed")
                .is_some_and(|signed| *signed.expose() == challenge[0].to_string())
        });
        Ok(if right {
            StepOutcome::Authenticated { user: self.0 }
        } else {
            StepOutcome::Rejected
        })
    }

    async fn challenge(
        &self,
        _tenant: &TenantContext,
        _transaction: &AuthTransaction,
        _asked: &ExternalInput,
    ) -> Result<Option<StepChallenge>, DomainError> {
        Ok(Some(StepChallenge {
            challenge: Some([7; 32]),
            enrollment: None,
            options: json!({ "allowCredentials": [] }),
        }))
    }
}

struct World {
    engine: FlowEngine,
    flow: AuthFlow,
    tenant: TenantContext,
    ana: UserId,
}

const NOT_MULTI_FACTOR: Requirement = Requirement::Conditional(Condition::MultiFactorNotReached);

/// The flow the server runs, with stand-ins: an identifier and a password,
/// then two second factors asked only while the sign-in is not
/// multi-factor, and a passkey as an alternative.
fn world() -> World {
    let ana = UserId::generate();
    let required = |key: &str| FlowStep {
        key: key.to_owned(),
        authenticator: key.to_owned(),
        requirement: Requirement::Required,
        substitutes: Vec::new(),
    };
    let flow = AuthFlow {
        name: "under-test".to_owned(),
        version: 1,
        steps: vec![required("identifier"), required("password")],
        alternatives: Vec::new(),
        minimum_assurance: Assurance::SingleFactor,
    }
    .with_step("key", "key", NOT_MULTI_FACTOR)
    .with_step("code", "code", NOT_MULTI_FACTOR)
    .with_alternative("passkey", "passkey");
    let engine = FlowEngine::new()
        .with(Arc::new(Anyone(ana)))
        .with(Arc::new(Knows))
        .with(Arc::new(Has("key")))
        .with(Arc::new(Has("code")))
        .with(Arc::new(Passkey(ana)));
    engine.validate(&flow).expect("valid");
    World {
        engine,
        flow,
        tenant: TenantContext::assume(TenantId::generate()),
        ana,
    }
}

fn answer(step: &str, value: u8) -> StepInput {
    StepInput::External(ExternalInput {
        step: step.to_owned(),
        fields: vec![("signed".to_owned(), Secret::from(value.to_string()))],
    })
}

impl World {
    fn start(&self) -> AuthTransaction {
        AuthTransaction::start(&self.flow, ClientInfo::default(), [9; 32], START)
    }

    async fn challenge(
        &self,
        transaction: &mut AuthTransaction,
        step: &str,
    ) -> Result<serde_json::Value, DomainError> {
        let asked = ExternalInput {
            step: step.to_owned(),
            fields: Vec::new(),
        };
        self.engine
            .challenge(&self.tenant, &self.flow, transaction, &asked, START)
            .await
    }

    async fn submit(
        &self,
        transaction: &mut AuthTransaction,
        input: StepInput,
    ) -> Result<Progress, DomainError> {
        self.engine
            .submit(
                &self.tenant,
                &self.flow,
                transaction,
                &input,
                Assurance::SingleFactor,
                START,
            )
            .await
    }
}

#[tokio::test]
async fn a_passkey_is_asked_for_its_challenge_at_the_start_and_is_multi_factor_alone() {
    let world = world();
    let mut transaction = world.start();
    let options = world
        .challenge(&mut transaction, "passkey")
        .await
        .expect("a challenge for the alternative");
    assert_eq!(options, json!({ "allowCredentials": [] }));
    assert_eq!(transaction.challenge(), Some(&[7; 32]));

    let progress = world
        .submit(&mut transaction, answer("passkey", 7))
        .await
        .expect("submitted");
    // Neither second factor is asked for: the passkey is multi-factor.
    assert_eq!(progress, Progress::ReadyToComplete);
    assert_eq!(transaction.candidate(), Some(world.ana));
    assert_eq!(
        world.engine.assurance(&transaction),
        Some(Assurance::MultiFactor)
    );
    assert_eq!(transaction.snapshot().satisfied_methods, ["passkey"]);
}

#[tokio::test]
async fn a_rejected_passkey_leaves_the_sign_in_waiting_for_the_identifier() {
    let world = world();
    let mut transaction = world.start();
    world
        .challenge(&mut transaction, "passkey")
        .await
        .expect("a challenge");
    let progress = world
        .submit(&mut transaction, answer("passkey", 1))
        .await
        .expect("rejected, not refused");
    assert!(matches!(progress, Progress::Rejected { .. }));
    assert_eq!(transaction.challenge(), None, "the challenge is used up");
    assert_eq!(transaction.snapshot().current_step, 0);
    // An answer with no challenge asked for is a rejection too.
    let progress = world
        .submit(&mut transaction, answer("passkey", 7))
        .await
        .expect("rejected");
    assert!(matches!(progress, Progress::Rejected { .. }));
}

#[tokio::test]
async fn the_challenge_of_an_alternative_is_refused_once_a_step_is_satisfied() {
    let world = world();
    let mut transaction = world.start();
    world
        .submit(&mut transaction, StepInput::Identifier("ana".to_owned()))
        .await
        .expect("identified");
    let error = world
        .challenge(&mut transaction, "passkey")
        .await
        .expect_err("too late for the alternative");
    assert_eq!(error.code(), "authentication.unexpected_step");
    let error = world
        .challenge(&mut transaction, "nothing")
        .await
        .expect_err("not a step");
    assert_eq!(error.code(), "authentication.unexpected_step");
}

#[tokio::test]
async fn a_second_factor_is_asked_for_until_the_sign_in_is_multi_factor() {
    let world = world();
    let mut transaction = world.start();
    world
        .submit(&mut transaction, StepInput::Identifier("ana".to_owned()))
        .await
        .expect("identified");
    let progress = world
        .submit(
            &mut transaction,
            StepInput::Password(Secret::from("right".to_owned())),
        )
        .await
        .expect("password");
    // One factor so far: the first second factor is asked for.
    assert_eq!(
        progress,
        Progress::Next {
            step: "key".to_owned()
        }
    );
    let progress = world
        .submit(&mut transaction, answer("key", 0))
        .await
        .expect("key");
    // Multi-factor now: the code would add nothing.
    assert_eq!(progress, Progress::ReadyToComplete);
    assert_eq!(
        transaction.snapshot().satisfied_methods,
        ["password", "key"]
    );
}

#[test]
fn an_alternative_reaches_a_multi_factor_minimum_with_two_factors_of_its_own() {
    let world = world();
    let flow = AuthFlow {
        minimum_assurance: Assurance::MultiFactor,
        steps: world
            .flow
            .steps
            .iter()
            .cloned()
            .map(|step| FlowStep {
                requirement: Requirement::Required,
                ..step
            })
            .collect(),
        ..world.flow.clone()
    };
    world
        .engine
        .validate(&flow)
        .expect("the passkey reaches multi-factor by itself");
}
