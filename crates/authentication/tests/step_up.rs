//! Step-up: raising a session to what an application asked for, asking
//! only for what it lacks. The real engine, use cases, password and
//! identifier authenticators, over the real identity, credential, session
//! and tenant contexts on their in-memory ports, with stand-ins for a code
//! of an application and for a security key, which resists phishing.

use hodor_authentication::api::{
    AttemptGuard, AuthFlow, AuthenticationService, Condition, FlowEngine, IdentifierAuthenticator,
    PasswordAuthenticator, Requirement, SignIn, StepInput, StepUp, StepUpRequest, TransactionId,
};
use hodor_authentication::testing::{
    InMemoryAttempts, InMemoryTransactions, TestSecondFactor, TestSecurityKey,
};
use hodor_credential::api::{CredentialService, NewPassword, PasswordRules};
use hodor_credential::testing::{FakeHasher, InMemoryPasswords};
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_identity::testing::InMemoryUsers;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, Clock as _, DomainError, Secret, TenantContext, Timestamp, UserId};
use hodor_session::api::{
    Assurance, ClientInfo, Session, SessionService, SessionTimeouts, SessionToken, StartSession,
};
use hodor_session::testing::{InMemorySessions, SequentialRandom};
use hodor_tenant::api::{CreateTenant, TenantService};
use hodor_tenant::testing::InMemoryTenants;
use std::sync::Arc;
use time::Duration;

const PASSWORD: &str = "correct horse battery staple";

struct World {
    service: AuthenticationService,
    sessions: SessionService,
    code: TestSecondFactor,
    key: TestSecurityKey,
    clock: Arc<FixedClock>,
    acme: TenantContext,
    globex: TenantContext,
    ana: UserId,
}

fn methods(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

async fn world() -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + Duration::days(20_000),
    ));
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
    let code = TestSecondFactor::default();
    let key = TestSecurityKey::default();
    let engine = FlowEngine::new()
        .with(Arc::new(IdentifierAuthenticator::new(
            identity.clone(),
            digest,
        )))
        .with(Arc::new(PasswordAuthenticator::new(
            credentials.clone(),
            identity.clone(),
            tenants.clone(),
            guard,
        )))
        .with(Arc::new(key.clone()))
        .with(Arc::new(code.clone()));
    // As the server's flow: the key first, also asked for to make a sign-in
    // phishing-resistant; the code only until the sign-in is multi-factor.
    let flow = AuthFlow::built_in()
        .with_step(
            TestSecurityKey::KIND,
            TestSecurityKey::KIND,
            Requirement::Conditional(Condition::StrongerAssuranceNeeded),
        )
        .with_step(
            TestSecondFactor::KIND,
            TestSecondFactor::KIND,
            Requirement::Conditional(Condition::MultiFactorNotReached),
        );
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
    .expect("the flow is valid");

    let mut contexts = Vec::new();
    for slug in ["acme", "globex"] {
        let created = tenants
            .create(
                CreateTenant {
                    slug: slug.to_owned(),
                    display_name: slug.to_uppercase(),
                    open_registration: false,
                    system: false,
                },
                Caller::system(),
            )
            .await
            .expect("tenant");
        contexts.push(TenantContext::assume(created.id()));
    }
    let (acme, globex) = (contexts[0].clone(), contexts[1].clone());
    let ana = identity
        .create(
            &acme,
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
    credentials
        .set_password(
            &acme,
            ana,
            NewPassword {
                password: &Secret::from(PASSWORD.to_owned()),
                rules: PasswordRules {
                    min_length: 12,
                    max_length: 128,
                    history_depth: 5,
                },
                own_names: &[],
            },
            false,
            Caller::system(),
        )
        .await
        .expect("password");

    World {
        service,
        sessions,
        code,
        key,
        clock,
        acme,
        globex,
        ana,
    }
}

impl World {
    /// A session of Ana's that signed in with `signed_in`.
    async fn session(&self, signed_in: &[&str], assurance: Assurance) -> (Session, SessionToken) {
        self.sessions
            .start(
                &self.acme,
                StartSession {
                    user_id: self.ana,
                    assurance,
                    methods: methods(signed_in),
                    timeouts: SessionTimeouts {
                        idle: Duration::hours(1),
                        absolute: Duration::hours(12),
                    },
                    client: ClientInfo::default(),
                },
                Caller::system(),
            )
            .await
            .expect("session")
    }

    async fn step_up(
        &self,
        tenant: &TenantContext,
        session: &Session,
        carried: &[&str],
        demanded: Option<Assurance>,
    ) -> StepUp {
        self.service
            .start_step_up(
                tenant,
                ClientInfo::default(),
                StepUpRequest {
                    session_id: session.id(),
                    user_id: session.user_id(),
                    carried: methods(carried),
                    demanded,
                },
            )
            .await
            .expect("start")
    }

    async fn submit(
        &self,
        id: TransactionId,
        secret: &str,
        input: StepInput,
    ) -> Result<SignIn, DomainError> {
        self.service.submit(&self.acme, id, secret, input).await
    }
}

fn answer(step: &str, code: &str) -> StepInput {
    StepInput::External(hodor_authentication::api::ExternalInput {
        step: step.to_owned(),
        fields: vec![("code".to_owned(), Secret::from(code.to_owned()))],
    })
}

fn started(step_up: StepUp) -> (TransactionId, String, String) {
    match step_up {
        StepUp::Started(started) => (
            started.transaction_id,
            started.secret.expose().clone(),
            started.step,
        ),
        other => panic!("expected a step-up to start, got {other:?}"),
    }
}

#[tokio::test]
async fn methods_amount_to_an_assurance_by_kind_of_factor_and_phishing_resistance() {
    let world = world().await;
    let of = |names: &[&str]| world.service.assurance_of(&methods(names));
    assert_eq!(of(&[]), None);
    assert_eq!(of(&["password"]), Some(Assurance::SingleFactor));
    assert_eq!(
        of(&[TestSecurityKey::KIND]),
        Some(Assurance::SingleFactor),
        "a key alone is one factor"
    );
    assert_eq!(
        of(&["password", TestSecondFactor::METHOD]),
        Some(Assurance::MultiFactor)
    );
    assert_eq!(
        of(&["password", TestSecurityKey::KIND]),
        Some(Assurance::PhishingResistant)
    );
    assert_eq!(
        of(&[TestSecondFactor::METHOD, TestSecurityKey::KIND]),
        Some(Assurance::SingleFactor),
        "two things held are one kind of factor"
    );
    assert_eq!(of(&["something-unknown"]), None);
}

#[tokio::test]
async fn a_password_session_asked_for_multi_factor_is_asked_only_for_a_second_factor() {
    let world = world().await;
    world.code.enroll(world.ana);
    let (session, old_token) = world.session(&["password"], Assurance::SingleFactor).await;

    let (id, secret, step) = started(
        world
            .step_up(
                &world.acme,
                &session,
                &["password"],
                Some(Assurance::MultiFactor),
            )
            .await,
    );
    assert_eq!(
        step,
        TestSecondFactor::KIND,
        "the identifier and the password are not asked"
    );
    world.clock.advance(Duration::minutes(1));
    let outcome = world
        .submit(
            id,
            &secret,
            answer(TestSecondFactor::KIND, TestSecondFactor::CODE),
        )
        .await
        .expect("submit");
    let SignIn::Completed {
        session: raised,
        token,
        ..
    } = outcome
    else {
        panic!("expected completion, got {outcome:?}");
    };
    assert_eq!(raised.id(), session.id(), "the same session, raised");
    let state = raised.snapshot();
    assert_eq!(state.assurance, Assurance::MultiFactor);
    assert_eq!(
        state.methods,
        methods(&["password", TestSecondFactor::METHOD])
    );
    assert_eq!(state.signed_in_at, world.clock.now());
    assert_eq!(
        raised.proofs()[0].1,
        session.snapshot().signed_in_at,
        "the password keeps its time"
    );
    assert_ne!(token.expose(), old_token.expose());
    assert!(
        world
            .sessions
            .find_by_token(&world.acme, old_token.expose())
            .await
            .expect("lookup")
            .is_none(),
        "the token from before the step-up is useless"
    );
    assert!(
        world
            .sessions
            .find_by_token(&world.acme, token.expose())
            .await
            .expect("lookup")
            .is_some()
    );
}

#[tokio::test]
async fn asked_for_phishing_resistance_a_person_with_a_code_is_asked_for_their_key() {
    let world = world().await;
    world.code.enroll(world.ana);
    world.key.enroll(world.ana);
    let (session, _) = world
        .session(
            &["password", TestSecondFactor::METHOD],
            Assurance::MultiFactor,
        )
        .await;
    let (id, secret, step) = started(
        world
            .step_up(
                &world.acme,
                &session,
                &["password", TestSecondFactor::METHOD],
                Some(Assurance::PhishingResistant),
            )
            .await,
    );
    assert_eq!(step, TestSecurityKey::KIND);
    let outcome = world
        .submit(
            id,
            &secret,
            answer(TestSecurityKey::KIND, TestSecurityKey::CODE),
        )
        .await
        .expect("submit");
    let SignIn::Completed {
        session: raised, ..
    } = outcome
    else {
        panic!("expected completion, got {outcome:?}");
    };
    assert_eq!(raised.snapshot().assurance, Assurance::PhishingResistant);
}

#[tokio::test]
async fn a_level_the_person_cannot_reach_is_not_started_and_one_they_reach_is_not_needed() {
    let world = world().await;
    world.code.enroll(world.ana);
    let (session, _) = world
        .session(
            &["password", TestSecondFactor::METHOD],
            Assurance::MultiFactor,
        )
        .await;
    assert!(matches!(
        world
            .step_up(
                &world.acme,
                &session,
                &["password", TestSecondFactor::METHOD],
                Some(Assurance::PhishingResistant),
            )
            .await,
        StepUp::Unreachable
    ));
    assert!(matches!(
        world
            .step_up(
                &world.acme,
                &session,
                &["password", TestSecondFactor::METHOD],
                Some(Assurance::MultiFactor),
            )
            .await,
        StepUp::NotNeeded
    ));
    // Without any second factor, multi-factor is out of reach too.
    let other = crate::world().await;
    let (single, _) = other.session(&["password"], Assurance::SingleFactor).await;
    assert!(matches!(
        other
            .step_up(
                &other.acme,
                &single,
                &["password"],
                Some(Assurance::MultiFactor)
            )
            .await,
        StepUp::Unreachable
    ));
}

#[tokio::test]
async fn when_nothing_counts_any_more_the_password_is_asked_again_and_not_the_identifier() {
    let world = world().await;
    let (session, _) = world.session(&["password"], Assurance::SingleFactor).await;
    let (id, secret, step) = started(world.step_up(&world.acme, &session, &[], None).await);
    assert_eq!(step, "password");
    let wrong = world
        .submit(
            id,
            &secret,
            StepInput::Password(Secret::from("not the password".to_owned())),
        )
        .await
        .expect("submit");
    assert!(matches!(wrong, SignIn::Rejected { .. }));
    let outcome = world
        .submit(
            id,
            &secret,
            StepInput::Password(Secret::from(PASSWORD.to_owned())),
        )
        .await
        .expect("submit");
    let SignIn::Completed {
        session: raised, ..
    } = outcome
    else {
        panic!("expected completion, got {outcome:?}");
    };
    assert_eq!(raised.id(), session.id());
    assert_eq!(raised.proofs(), vec![("password", world.clock.now())]);
}

#[tokio::test]
async fn a_step_up_never_accepts_the_identifier_again() {
    let world = world().await;
    world.code.enroll(world.ana);
    let (session, _) = world.session(&["password"], Assurance::SingleFactor).await;
    let (id, secret, _) = started(
        world
            .step_up(
                &world.acme,
                &session,
                &["password"],
                Some(Assurance::MultiFactor),
            )
            .await,
    );
    let error = world
        .submit(
            id,
            &secret,
            StepInput::Identifier("someone-else@example.com".to_owned()),
        )
        .await
        .expect_err("refused");
    assert_eq!(error.code(), "authentication.unexpected_step");
}

#[tokio::test]
async fn a_session_ended_during_its_step_up_is_not_brought_back() {
    let world = world().await;
    world.code.enroll(world.ana);
    let (session, _) = world.session(&["password"], Assurance::SingleFactor).await;
    let (id, secret, _) = started(
        world
            .step_up(
                &world.acme,
                &session,
                &["password"],
                Some(Assurance::MultiFactor),
            )
            .await,
    );
    world
        .sessions
        .revoke(&world.acme, session.id(), "signed_out", Caller::system())
        .await
        .expect("revoke");
    let outcome = world
        .submit(
            id,
            &secret,
            answer(TestSecondFactor::KIND, TestSecondFactor::CODE),
        )
        .await
        .expect("submit");
    assert!(matches!(outcome, SignIn::Failed), "{outcome:?}");
}

#[tokio::test]
async fn a_session_cannot_be_stepped_up_in_another_tenant() {
    let world = world().await;
    world.code.enroll(world.ana);
    let (session, _) = world.session(&["password"], Assurance::SingleFactor).await;
    assert!(matches!(
        world
            .step_up(
                &world.globex,
                &session,
                &["password"],
                Some(Assurance::MultiFactor),
            )
            .await,
        StepUp::Unreachable
    ));
}
