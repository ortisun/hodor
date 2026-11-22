//! A whole sign-in through the use cases: from the first step to a
//! session, over the real contexts running on their in-memory ports.

use hodor_authentication::api::{
    AttemptGuard, AuthFlow, AuthTransaction, AuthenticationService, Authenticator,
    AuthenticatorTraits, Condition, ExternalInput, Factor, FlowEngine, IdentifierAuthenticator,
    PasswordAuthenticator, Requirement, SignIn, StepInput, StepOutcome, TransactionId,
};
use hodor_authentication::testing::{
    InMemoryAttempts, InMemoryTransactions, TestSecondFactor, TransactionPorts,
    run_transaction_contract,
};
use hodor_credential::api::{CredentialService, NewPassword, PasswordRules};
use hodor_credential::testing::{FakeHasher, InMemoryPasswords};
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_identity::testing::InMemoryUsers;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, DomainError, Secret, TenantContext, TenantId, Timestamp, UserId};
use hodor_session::api::{Assurance, ClientInfo, SessionService};
use hodor_session::testing::{InMemorySessions, SequentialRandom};
use hodor_tenant::api::{CreateTenant, SecondFactorPolicy, TenantService};
use hodor_tenant::testing::InMemoryTenants;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use time::Duration;

const PASSWORD: &str = "correct horse battery staple";

/// A stand-in for the password step that is satisfied by anything, so
/// that the check made at completion can be seen on its own.
struct AlwaysProven;

#[async_trait::async_trait]
impl Authenticator for AlwaysProven {
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
        _transaction: &AuthTransaction,
        _input: &StepInput,
    ) -> Result<StepOutcome, DomainError> {
        Ok(StepOutcome::Proven)
    }
}

struct World {
    service: AuthenticationService,
    sessions: SessionService,
    identity: IdentityService,
    clock: Arc<FixedClock>,
    units_of_work: InMemoryUnitOfWorkFactory,
    tenant: TenantContext,
    tenants: TenantService,
    ana: UserId,
    /// The stand-in second factor, which the flow names only when asked.
    second_factor: TestSecondFactor,
    /// The secret of each sign-in started here, as the browser's cookie
    /// would hold it.
    secrets: Mutex<HashMap<TransactionId, String>>,
}

async fn world_with(lenient_password_step: bool) -> World {
    world_with_flow(lenient_password_step, None).await
}

/// The built-in flow, followed by the stand-in second factor required in
/// the given way when there is one.
async fn world_with_flow(
    lenient_password_step: bool,
    second_factor_step: Option<Requirement>,
) -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let clock = Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH));
    let digest = Arc::new(FakeDigest);
    let factory = || Arc::new(units_of_work.clone());

    let tenant_rows = InMemoryTenants::default();
    let tenants = TenantService::new(
        factory(),
        Arc::new(tenant_rows.clone()),
        Arc::new(tenant_rows),
        clock.clone(),
    );
    let identity =
        IdentityService::new(factory(), Arc::new(InMemoryUsers::default()), clock.clone());
    let credentials = CredentialService::new(
        factory(),
        Arc::new(InMemoryPasswords::default()),
        Arc::new(FakeHasher::default()),
        clock.clone(),
    );
    let sessions = SessionService::new(
        factory(),
        Arc::new(InMemorySessions::default()),
        digest.clone(),
        Arc::new(SequentialRandom::default()),
        clock.clone(),
    );
    let guard = AttemptGuard::new(
        factory(),
        Arc::new(InMemoryAttempts::default()),
        digest.clone(),
        clock.clone(),
    );
    let password_step: Arc<dyn Authenticator> = if lenient_password_step {
        Arc::new(AlwaysProven)
    } else {
        Arc::new(PasswordAuthenticator::new(
            credentials.clone(),
            identity.clone(),
            tenants.clone(),
            guard,
        ))
    };
    let second_factor = TestSecondFactor::default();
    let engine = FlowEngine::new()
        .with(Arc::new(IdentifierAuthenticator::new(
            identity.clone(),
            digest,
        )))
        .with(password_step)
        .with(Arc::new(second_factor.clone()));
    let flow = match second_factor_step {
        Some(requirement) => {
            AuthFlow::built_in().with_step("second-factor", TestSecondFactor::KIND, requirement)
        }
        None => AuthFlow::built_in(),
    };
    let service = AuthenticationService::new(
        factory(),
        Arc::new(InMemoryTransactions::default()),
        engine,
        flow,
        identity.clone(),
        sessions.clone(),
        tenants.clone(),
        Arc::new(FakeDigest),
        Arc::new(SequentialRandom::default()),
        clock.clone(),
    )
    .expect("the built-in flow is valid");

    let created = tenants
        .create(
            CreateTenant {
                slug: "acme".to_owned(),
                display_name: "Acme".to_owned(),
                open_registration: false,
                system: false,
            },
            Caller::system(),
        )
        .await
        .expect("tenant");
    let tenant = TenantContext::assume(created.id());

    let ana = identity
        .create(
            &tenant,
            CreateUser {
                kind: UserKind::Human,
                identifiers: vec![(IdentifierKind::Email, "ana@example.com".to_owned())],
                profile: Profile::default(),
                confirmed: true,
            },
            Caller::system(),
        )
        .await
        .expect("user")
        .id();
    let password = Secret::from(PASSWORD.to_owned());
    let new = NewPassword {
        password: &password,
        rules: PasswordRules {
            min_length: 12,
            max_length: 128,
            history_depth: 5,
        },
        own_names: &[],
    };
    credentials
        .set_password(&tenant, ana, new, false, Caller::system())
        .await
        .expect("password");

    World {
        service,
        sessions,
        identity,
        clock,
        units_of_work,
        tenant,
        tenants,
        ana,
        second_factor,
        secrets: Mutex::new(HashMap::new()),
    }
}

async fn world() -> World {
    world_with(false).await
}

impl World {
    async fn start(&self) -> TransactionId {
        let client = ClientInfo {
            address: Some("203.0.113.1".to_owned()),
            description: Some("Example Browser".to_owned()),
        };
        let started = self
            .service
            .start(&self.tenant, client)
            .await
            .expect("start");
        assert_eq!(started.step, "identifier");
        self.secrets
            .lock()
            .expect("secrets")
            .insert(started.transaction_id, started.secret.expose().clone());
        started.transaction_id
    }

    fn secret(&self, id: TransactionId) -> String {
        self.secrets
            .lock()
            .expect("secrets")
            .get(&id)
            .cloned()
            .unwrap_or_else(|| "f".repeat(64))
    }

    async fn identifier(&self, id: TransactionId, typed: &str) -> SignIn {
        self.service
            .submit(
                &self.tenant,
                id,
                &self.secret(id),
                StepInput::Identifier(typed.to_owned()),
            )
            .await
            .expect("identifier step")
    }

    async fn password(&self, id: TransactionId, typed: &str) -> Result<SignIn, DomainError> {
        self.service
            .submit(
                &self.tenant,
                id,
                &self.secret(id),
                StepInput::Password(Secret::from(typed.to_owned())),
            )
            .await
    }

    async fn second_factor(&self, id: TransactionId, code: &str) -> Result<SignIn, DomainError> {
        self.service
            .submit(
                &self.tenant,
                id,
                &self.secret(id),
                StepInput::External(ExternalInput {
                    step: "second-factor".to_owned(),
                    fields: vec![("code".to_owned(), Secret::from(code.to_owned()))],
                }),
            )
            .await
    }

    async fn require_second_factor(&self, policy: SecondFactorPolicy) {
        let mut settings = self
            .tenants
            .get(&self.tenant)
            .await
            .expect("tenant")
            .snapshot()
            .settings
            .clone();
        settings.authentication.second_factor = policy;
        self.tenants
            .change_settings(&self.tenant, settings, Caller::system())
            .await
            .expect("settings changed");
    }

    fn events_since(&self, count: usize) -> Vec<String> {
        self.units_of_work.committed_event_types()[count..].to_vec()
    }
}

#[tokio::test]
async fn the_in_memory_transaction_store_passes_the_contract() {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let transactions = InMemoryTransactions::default();
    run_transaction_contract(TransactionPorts {
        units_of_work: &units_of_work,
        transactions: &transactions,
    })
    .await;
}

#[tokio::test]
async fn signing_in_starts_a_session_that_the_session_context_recognizes() {
    let world = world().await;
    let before = world.units_of_work.committed_events().len();
    let id = world.start().await;

    let next = world.identifier(id, "Ana@Example.com").await;
    assert!(
        matches!(next, SignIn::Pending { ref step, .. } if step == "password"),
        "{next:?}"
    );
    let done = world.password(id, PASSWORD).await.expect("password");

    let SignIn::Completed { session, token } = done else {
        panic!("expected completion: {done:?}");
    };
    let state = session.snapshot();
    assert_eq!(state.user_id, world.ana);
    assert_eq!(state.assurance, Assurance::SingleFactor);
    assert_eq!(state.methods, ["password"]);
    assert_eq!(state.client.address.as_deref(), Some("203.0.113.1"));
    // The tenant's default policy: 30 minutes idle, 12 hours at most.
    assert_eq!(state.idle_timeout, Duration::minutes(30));
    assert_eq!(
        state.absolute_expires_at,
        Timestamp::UNIX_EPOCH + Duration::hours(12)
    );

    let found = world
        .sessions
        .find_by_token(&world.tenant, token.expose())
        .await
        .expect("find")
        .expect("the token belongs to the new session");
    assert_eq!(found.id(), session.id());
    assert_eq!(
        world.events_since(before),
        ["session.started", "authentication.succeeded"]
    );
}

#[tokio::test]
async fn a_wrong_password_is_rejected_announced_and_can_be_followed_by_the_right_one() {
    let world = world().await;
    let before = world.units_of_work.committed_events().len();
    let id = world.start().await;
    world.identifier(id, "ana@example.com").await;

    let rejected = world
        .password(id, "not the password")
        .await
        .expect("password");
    assert!(
        matches!(rejected, SignIn::Rejected { attempts_left: 4, ref step, .. } if step == "password"),
        "{rejected:?}"
    );
    assert_eq!(world.events_since(before), ["authentication.failed"]);
    let failure = &world.units_of_work.committed_events()[before];
    assert_eq!(failure.payload["step"], "password");
    assert_eq!(failure.payload["user_id"], world.ana.to_string());

    assert!(matches!(
        world.password(id, PASSWORD).await.expect("password"),
        SignIn::Completed { .. }
    ));
}

#[tokio::test]
async fn nothing_announced_contains_the_identifier_the_password_or_the_token() {
    let world = world().await;
    let id = world.start().await;
    world.identifier(id, "ana@example.com").await;
    world
        .password(id, "a wrong secret guess")
        .await
        .expect("password");
    let SignIn::Completed { token, .. } = world.password(id, PASSWORD).await.expect("password")
    else {
        panic!("expected completion");
    };
    let published = format!("{:?}", world.units_of_work.committed_events());
    for secret in [
        "ana@example.com",
        "a wrong secret guess",
        PASSWORD,
        token.expose(),
    ] {
        assert!(!published.contains(secret), "{secret} leaked");
    }
}

#[tokio::test]
async fn a_sign_in_for_nobody_looks_the_same_step_by_step_and_never_completes() {
    let world = world().await;
    let (for_ana, for_nobody) = (world.start().await, world.start().await);

    let ana_next = format!("{:?}", world.identifier(for_ana, "ana@example.com").await);
    let nobody_next = format!(
        "{:?}",
        world.identifier(for_nobody, "ghost@example.com").await
    );
    // Only the transaction identifiers differ.
    assert_eq!(
        ana_next.replace(&for_ana.to_string(), "ID"),
        nobody_next.replace(&for_nobody.to_string(), "ID")
    );

    let ana_wrong = format!(
        "{:?}",
        world
            .password(for_ana, "wrong guess")
            .await
            .expect("password")
    );
    let nobody_any = format!(
        "{:?}",
        world
            .password(for_nobody, PASSWORD)
            .await
            .expect("password")
    );
    assert_eq!(
        ana_wrong.replace(&for_ana.to_string(), "ID"),
        nobody_any.replace(&for_nobody.to_string(), "ID")
    );
}

#[tokio::test]
async fn five_rejections_fail_the_sign_in_and_a_new_one_must_be_started() {
    let world = world().await;
    let id = world.start().await;
    world.identifier(id, "ghost@example.com").await;
    for _ in 0..4 {
        assert!(matches!(
            world.password(id, "guess").await.expect("password"),
            SignIn::Rejected { .. }
        ));
    }
    assert!(matches!(
        world.password(id, "guess").await.expect("password"),
        SignIn::Failed
    ));

    let error = world.password(id, PASSWORD).await.expect_err("failed");
    assert_eq!(error.code(), "authentication.transaction_not_active");
    let error = world
        .service
        .describe(&world.tenant, id, &world.secret(id))
        .await
        .expect_err("failed");
    assert_eq!(error.code(), "authentication.transaction_not_active");
}

#[tokio::test]
async fn a_completed_sign_in_cannot_be_used_again() {
    let world = world().await;
    let id = world.start().await;
    world.identifier(id, "ana@example.com").await;
    world.password(id, PASSWORD).await.expect("password");

    let again = world.password(id, PASSWORD).await.expect_err("completed");
    assert_eq!(again.code(), "authentication.transaction_not_active");
    let sessions = world
        .sessions
        .list_for_user(&world.tenant, world.ana)
        .await
        .expect("list");
    assert_eq!(sessions.len(), 1, "one sign-in, one session");
}

#[tokio::test]
async fn a_sign_in_expires_can_be_described_and_can_be_cancelled() {
    let world = world().await;
    let id = world.start().await;
    world.identifier(id, "ana@example.com").await;

    // A reload of the page asks where the sign-in stands.
    let described = world
        .service
        .describe(&world.tenant, id, &world.secret(id))
        .await
        .expect("describe");
    assert!(matches!(described, SignIn::Pending { ref step, .. } if step == "password"));

    world.clock.advance(Duration::minutes(10));
    let expired = world.password(id, PASSWORD).await.expect_err("expired");
    assert_eq!(expired.code(), "authentication.transaction_not_active");

    let other = world.start().await;
    world
        .service
        .cancel(&world.tenant, other, &world.secret(other))
        .await
        .expect("cancel");
    world
        .service
        .cancel(&world.tenant, other, &world.secret(other))
        .await
        .expect("cancel again");
    let cancelled = world
        .service
        .submit(
            &world.tenant,
            other,
            &world.secret(other),
            StepInput::Identifier("ana@example.com".to_owned()),
        )
        .await
        .expect_err("cancelled");
    assert_eq!(cancelled.code(), "authentication.transaction_not_active");
}

#[tokio::test]
async fn a_sign_in_belongs_to_its_tenant() {
    let world = world().await;
    let id = world.start().await;
    let elsewhere = TenantContext::assume(TenantId::generate());

    for error in [
        world
            .service
            .describe(&elsewhere, id, &world.secret(id))
            .await
            .expect_err("describe"),
        world
            .service
            .submit(
                &elsewhere,
                id,
                &world.secret(id),
                StepInput::Identifier("ana@example.com".to_owned()),
            )
            .await
            .expect_err("submit"),
        world
            .service
            .cancel(&elsewhere, id, &world.secret(id))
            .await
            .expect_err("cancel"),
        world
            .service
            .describe(&world.tenant, TransactionId::generate(), &world.secret(id))
            .await
            .expect_err("unknown"),
    ] {
        assert_eq!(error.code(), "authentication.transaction_not_found");
    }
}

#[tokio::test]
async fn a_user_who_may_no_longer_sign_in_is_stopped_at_completion() {
    // The password step here is satisfied by anything, so that only the
    // check made at completion stands between the user and a session.
    let world = world_with(true).await;
    world
        .identity
        .suspend(
            &world.tenant,
            world.ana,
            "left the company",
            Caller::system(),
        )
        .await
        .expect("suspend");
    let id = world.start().await;
    world.identifier(id, "ana@example.com").await;

    let answer = world.password(id, "anything").await.expect("password");

    assert!(matches!(answer, SignIn::Failed), "{answer:?}");
    let sessions = world
        .sessions
        .list_for_user(&world.tenant, world.ana)
        .await
        .expect("list");
    assert!(
        sessions.is_empty(),
        "no session for a user who may not sign in"
    );

    // A sign-in for nobody is stopped there too.
    let id = world.start().await;
    world.identifier(id, "ghost@example.com").await;
    assert!(matches!(
        world.password(id, "anything").await.expect("password"),
        SignIn::Failed
    ));
}

#[tokio::test]
async fn a_sign_in_can_be_continued_only_with_its_secret() {
    let world = world().await;
    let id = world.start().await;
    let other = world.start().await;
    let right = world.secret(id);
    assert_eq!(right.len(), 64, "a secret of 256 bits, in hexadecimal");
    assert_ne!(right, world.secret(other), "every sign-in has its own");

    // Knowing the identifier is not enough: a wrong secret, another
    // sign-in's secret and no secret are all answered as if the sign-in
    // did not exist, and change nothing.
    for wrong in [
        world.secret(other),
        "0".repeat(64),
        String::new(),
        right.to_uppercase(),
    ] {
        let submit = world
            .service
            .submit(
                &world.tenant,
                id,
                &wrong,
                StepInput::Identifier("ana@example.com".to_owned()),
            )
            .await
            .expect_err("submit");
        let describe = world
            .service
            .describe(&world.tenant, id, &wrong)
            .await
            .expect_err("describe");
        let cancel = world
            .service
            .cancel(&world.tenant, id, &wrong)
            .await
            .expect_err("cancel");
        for error in [submit, describe, cancel] {
            assert_eq!(error.code(), "authentication.transaction_not_found");
        }
    }

    // The rightful holder is unaffected and still at the first step.
    let described = world
        .service
        .describe(&world.tenant, id, &right)
        .await
        .expect("describe");
    assert!(matches!(described, SignIn::Pending { ref step, .. } if step == "identifier"));
    world.identifier(id, "ana@example.com").await;
    assert!(matches!(
        world.password(id, PASSWORD).await.expect("password"),
        SignIn::Completed { .. }
    ));
}

const WHEN_NOT_REACHED: Requirement = Requirement::Conditional(Condition::AssuranceNotReached);

fn pending_step(sign_in: &SignIn) -> &str {
    match sign_in {
        SignIn::Pending { step, .. } | SignIn::Rejected { step, .. } => step,
        other => panic!("not waiting for a step: {other:?}"),
    }
}

#[tokio::test]
async fn with_the_policy_on_the_built_in_flow_completes_no_sign_in() {
    let world = world().await;
    world
        .require_second_factor(SecondFactorPolicy::Required)
        .await;
    let id = world.start().await;
    world.identifier(id, "ana@example.com").await;
    let events = world.units_of_work.committed_event_types().len();
    let outcome = world.password(id, PASSWORD).await.expect("answered");
    assert!(
        matches!(outcome, SignIn::Failed),
        "one factor is not enough: {outcome:?}"
    );
    assert_eq!(world.events_since(events), ["authentication.failed"]);
    let sessions = world
        .sessions
        .list_for_user(&world.tenant, world.ana)
        .await
        .expect("sessions");
    assert!(sessions.is_empty(), "no session started");
}

#[tokio::test]
async fn with_the_policy_off_a_second_factor_on_the_condition_is_not_asked() {
    let world = world_with_flow(false, Some(WHEN_NOT_REACHED)).await;
    world.second_factor.enroll(world.ana);
    let id = world.start().await;
    world.identifier(id, "ana@example.com").await;
    let outcome = world.password(id, PASSWORD).await.expect("answered");
    let SignIn::Completed { session, .. } = outcome else {
        panic!("one factor is enough with the policy off: {outcome:?}");
    };
    assert_eq!(session.snapshot().assurance, Assurance::SingleFactor);
}

#[tokio::test]
async fn with_the_policy_on_the_second_factor_is_asked_and_the_session_is_multi_factor() {
    let world = world_with_flow(false, Some(WHEN_NOT_REACHED)).await;
    world.second_factor.enroll(world.ana);
    world
        .require_second_factor(SecondFactorPolicy::Required)
        .await;
    let id = world.start().await;
    world.identifier(id, "ana@example.com").await;
    let after_password = world.password(id, PASSWORD).await.expect("answered");
    assert_eq!(pending_step(&after_password), "second-factor");
    let wrong = world.second_factor(id, "000000").await.expect("answered");
    assert_eq!(pending_step(&wrong), "second-factor");
    assert!(matches!(wrong, SignIn::Rejected { .. }));
    let outcome = world
        .second_factor(id, TestSecondFactor::CODE)
        .await
        .expect("answered");
    let SignIn::Completed { session, .. } = outcome else {
        panic!("two factors complete the sign-in: {outcome:?}");
    };
    assert_eq!(session.snapshot().assurance, Assurance::MultiFactor);
    assert_eq!(
        session.snapshot().methods,
        ["password", TestSecondFactor::METHOD]
    );
}

#[tokio::test]
async fn with_the_policy_on_a_person_without_a_second_factor_cannot_sign_in() {
    let world = world_with_flow(false, Some(WHEN_NOT_REACHED)).await;
    world
        .require_second_factor(SecondFactorPolicy::Required)
        .await;
    let id = world.start().await;
    world.identifier(id, "ana@example.com").await;
    let outcome = world.password(id, PASSWORD).await.expect("answered");
    assert!(matches!(outcome, SignIn::Failed), "{outcome:?}");
}

#[tokio::test]
async fn an_optional_second_factor_is_asked_of_whoever_enrolled_even_with_the_policy_off() {
    let world = world_with_flow(false, Some(Requirement::Optional)).await;
    world.second_factor.enroll(world.ana);
    let id = world.start().await;
    world.identifier(id, "ana@example.com").await;
    let after_password = world.password(id, PASSWORD).await.expect("answered");
    assert_eq!(pending_step(&after_password), "second-factor");
    let outcome = world
        .second_factor(id, TestSecondFactor::CODE)
        .await
        .expect("answered");
    assert!(matches!(outcome, SignIn::Completed { .. }), "{outcome:?}");
}

#[tokio::test]
async fn the_policy_turned_on_during_a_sign_in_applies_at_its_completion() {
    let world = world().await;
    let id = world.start().await;
    world.identifier(id, "ana@example.com").await;
    world
        .require_second_factor(SecondFactorPolicy::Required)
        .await;
    let outcome = world.password(id, PASSWORD).await.expect("answered");
    assert!(matches!(outcome, SignIn::Failed), "{outcome:?}");

    world
        .require_second_factor(SecondFactorPolicy::NotRequired)
        .await;
    let id = world.start().await;
    world.identifier(id, "ana@example.com").await;
    let outcome = world.password(id, PASSWORD).await.expect("answered");
    assert!(
        matches!(outcome, SignIn::Completed { .. }),
        "with the policy off again nothing has changed: {outcome:?}"
    );
}
