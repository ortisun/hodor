//! Steps that need a challenge, driven through the engine with stand-in
//! authenticators: a challenge is asked for the current step only, kept in
//! the transaction, and used once.

use hodor_authentication::api::{
    AuthFlow, AuthTransaction, Authenticator, AuthenticatorTraits, ExternalInput, Factor,
    FlowEngine, FlowStep, Progress, Requirement, StepChallenge, StepInput, StepOutcome,
};
use hodor_kernel::{DomainError, Secret, TenantContext, TenantId, Timestamp, UserId};
use hodor_session::api::{Assurance, ClientInfo};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

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

/// Accepts the field `signed` holding the first byte of the challenge kept
/// in the transaction. Every challenge it makes is different.
#[derive(Default)]
struct Signer {
    made: AtomicU8,
}

#[async_trait::async_trait]
impl Authenticator for Signer {
    fn kind(&self) -> &'static str {
        "signer"
    }

    fn traits(&self) -> AuthenticatorTraits {
        AuthenticatorTraits {
            identifies: false,
            factor: Some(Factor::Possession),
            second_factor: None,
            method: Some("signer"),
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
            StepOutcome::Proven
        } else {
            StepOutcome::Rejected
        })
    }

    async fn challenge(
        &self,
        _tenant: &TenantContext,
        _transaction: &AuthTransaction,
    ) -> Result<Option<StepChallenge>, DomainError> {
        let byte = self.made.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(Some(StepChallenge {
            challenge: [byte; 32],
            options: json!({ "challenge": byte }),
        }))
    }
}

struct World {
    engine: FlowEngine,
    flow: AuthFlow,
    tenant: TenantContext,
}

fn world() -> World {
    let step = |key: &str| FlowStep {
        key: key.to_owned(),
        authenticator: key.to_owned(),
        requirement: Requirement::Required,
        substitutes: Vec::new(),
    };
    let flow = AuthFlow {
        name: "under-test".to_owned(),
        version: 1,
        steps: vec![step("identifier"), step("signer")],
        alternatives: Vec::new(),
        minimum_assurance: Assurance::SingleFactor,
    };
    let engine = FlowEngine::new()
        .with(Arc::new(Anyone(UserId::generate())))
        .with(Arc::new(Signer::default()));
    engine.validate(&flow).expect("valid");
    World {
        engine,
        flow,
        tenant: TenantContext::assume(TenantId::generate()),
    }
}

fn signed(value: u8) -> StepInput {
    StepInput::External(ExternalInput {
        step: "signer".to_owned(),
        fields: vec![("signed".to_owned(), Secret::from(value.to_string()))],
    })
}

impl World {
    async fn identified(&self) -> AuthTransaction {
        let mut transaction =
            AuthTransaction::start(&self.flow, ClientInfo::default(), [9; 32], START);
        self.submit(&mut transaction, StepInput::Identifier("ana".to_owned()))
            .await
            .expect("identified");
        transaction
    }

    async fn challenge(
        &self,
        transaction: &mut AuthTransaction,
        step: &str,
    ) -> Result<serde_json::Value, DomainError> {
        self.engine
            .challenge(&self.tenant, &self.flow, transaction, step, START)
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
async fn an_answer_to_the_challenge_satisfies_the_step_and_uses_the_challenge_up() {
    let world = world();
    let mut transaction = world.identified().await;
    let options = world
        .challenge(&mut transaction, "signer")
        .await
        .expect("a challenge");
    assert_eq!(options, json!({ "challenge": 1 }));
    assert_eq!(transaction.challenge(), Some(&[1; 32]));
    assert_eq!(
        world
            .submit(&mut transaction, signed(1))
            .await
            .expect("submitted"),
        Progress::ReadyToComplete
    );
    assert_eq!(transaction.challenge(), None);
}

#[tokio::test]
async fn a_rejected_answer_uses_the_challenge_up_too() {
    let world = world();
    let mut transaction = world.identified().await;
    world
        .challenge(&mut transaction, "signer")
        .await
        .expect("a challenge");
    assert!(matches!(
        world
            .submit(&mut transaction, signed(7))
            .await
            .expect("submitted"),
        Progress::Rejected { .. }
    ));
    assert_eq!(transaction.challenge(), None);
    // The right answer to the challenge that was used up is now an answer
    // to nothing.
    assert!(matches!(
        world
            .submit(&mut transaction, signed(1))
            .await
            .expect("submitted"),
        Progress::Rejected { .. }
    ));
}

#[tokio::test]
async fn an_answer_with_no_challenge_asked_for_is_a_rejection() {
    let world = world();
    let mut transaction = world.identified().await;
    assert!(matches!(
        world
            .submit(&mut transaction, signed(0))
            .await
            .expect("submitted"),
        Progress::Rejected { attempts_left: 4 }
    ));
}

#[tokio::test]
async fn asking_again_replaces_the_challenge() {
    let world = world();
    let mut transaction = world.identified().await;
    world
        .challenge(&mut transaction, "signer")
        .await
        .expect("first");
    world
        .challenge(&mut transaction, "signer")
        .await
        .expect("second");
    assert!(matches!(
        world
            .submit(&mut transaction, signed(1))
            .await
            .expect("submitted"),
        Progress::Rejected { .. }
    ));
    world
        .challenge(&mut transaction, "signer")
        .await
        .expect("third");
    assert_eq!(
        world
            .submit(&mut transaction, signed(3))
            .await
            .expect("submitted"),
        Progress::ReadyToComplete
    );
}

#[tokio::test]
async fn a_challenge_is_asked_for_the_current_step_only() {
    let world = world();
    let mut transaction =
        AuthTransaction::start(&world.flow, ClientInfo::default(), [9; 32], START);
    let error = world
        .challenge(&mut transaction, "signer")
        .await
        .expect_err("not the current step");
    assert_eq!(error.code(), "authentication.unexpected_step");
    let error = world
        .challenge(&mut transaction, "identifier")
        .await
        .expect_err("needs none");
    assert_eq!(error.code(), "authentication.step_has_no_challenge");
    assert_eq!(transaction.challenge(), None);
}

#[tokio::test]
async fn a_sign_in_that_ended_gives_no_challenge() {
    let world = world();
    let mut transaction = world.identified().await;
    transaction.cancel();
    let error = world
        .challenge(&mut transaction, "signer")
        .await
        .expect_err("ended");
    assert_eq!(error.code(), "authentication.transaction_not_active");
}
