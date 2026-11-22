//! Signing in with a password and a code of an authenticator application:
//! the real authenticators, the attempt guard and the use cases, over the
//! real identity, credential, session and tenant contexts running on their
//! in-memory ports.

use hodor_authentication::api::{
    AttemptGuard, AuthFlow, AuthenticationService, FlowEngine, IdentifierAuthenticator,
    PasswordAuthenticator, Requirement, SignIn, StepInput, TotpAuthenticator, TransactionId,
};
use hodor_authentication::testing::{InMemoryAttempts, InMemoryTransactions};
use hodor_credential::api::{
    CredentialService, NewPassword, PasswordRules, STEP_SECONDS, TotpEnrollment, TotpService,
    totp_code_at,
};
use hodor_credential::testing::{
    FakeHasher, FakeHmacSha1, InMemoryPasswords, InMemoryTotps, base32_secret,
};
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_identity::testing::InMemoryUsers;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::{CountingRandom, FakeDigest};
use hodor_kernel::sealing::testing::FakeSecretBox;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, Clock as _, DomainError, Secret, TenantContext, Timestamp, UserId};
use hodor_session::api::{Assurance, ClientInfo, SessionService};
use hodor_session::testing::{InMemorySessions, SequentialRandom};
use hodor_tenant::api::{CreateTenant, SecondFactorPolicy, TenantService};
use hodor_tenant::testing::InMemoryTenants;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use time::Duration;

const PASSWORD: &str = "correct horse battery staple";

struct World {
    service: AuthenticationService,
    sessions: SessionService,
    totp: TotpService,
    tenants: TenantService,
    clock: Arc<FixedClock>,
    tenant: TenantContext,
    ana: UserId,
    secrets: Mutex<HashMap<TransactionId, String>>,
}

async fn world() -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + Duration::seconds(STEP_SECONDS * 60_000_000),
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
    let totp = TotpService::new(
        factory(),
        Arc::new(InMemoryTotps::default()),
        Arc::new(FakeSecretBox),
        Arc::new(FakeHmacSha1),
        Arc::new(CountingRandom::default()),
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
    let engine = FlowEngine::new()
        .with(Arc::new(IdentifierAuthenticator::new(
            identity.clone(),
            digest,
        )))
        .with(Arc::new(PasswordAuthenticator::new(
            credentials.clone(),
            identity.clone(),
            tenants.clone(),
            guard.clone(),
        )))
        .with(Arc::new(TotpAuthenticator::new(
            totp.clone(),
            tenants.clone(),
            guard,
        )));
    let flow = AuthFlow::built_in().with_step(
        TotpAuthenticator::KIND,
        TotpAuthenticator::KIND,
        Requirement::Optional,
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
    .expect("the flow with the authenticator application step is valid");

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
    credentials
        .set_password(
            &tenant,
            ana,
            NewPassword {
                password: &password,
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
        totp,
        tenants,
        clock,
        tenant,
        ana,
        secrets: Mutex::new(HashMap::new()),
    }
}

impl World {
    /// Gives Ana an authenticator application, and moves past the step of
    /// the code that confirmed it.
    async fn enroll(&self) -> TotpEnrollment {
        let enrollment = self
            .totp
            .begin_enrollment(&self.tenant, self.ana, "Acme", "ana@example.com")
            .await
            .expect("begin");
        let code = Secret::from(self.phone(&enrollment));
        self.totp
            .confirm_enrollment(&self.tenant, self.ana, &code, Caller::system())
            .await
            .expect("confirm");
        self.clock.advance(Duration::seconds(STEP_SECONDS));
        enrollment
    }

    /// What Ana's phone shows now.
    fn phone(&self, enrollment: &TotpEnrollment) -> String {
        totp_code_at(
            &FakeHmacSha1,
            &base32_secret(enrollment.secret()),
            self.clock.now(),
        )
    }

    async fn start(&self) -> TransactionId {
        let started = self
            .service
            .start(
                &self.tenant,
                ClientInfo {
                    address: Some("203.0.113.1".to_owned()),
                    description: Some("Example Browser".to_owned()),
                },
            )
            .await
            .expect("start");
        self.secrets
            .lock()
            .expect("secrets")
            .insert(started.transaction_id, started.secret.expose().clone());
        started.transaction_id
    }

    async fn submit(&self, id: TransactionId, input: StepInput) -> Result<SignIn, DomainError> {
        let secret = self.secrets.lock().expect("secrets")[&id].clone();
        self.service.submit(&self.tenant, id, &secret, input).await
    }

    /// Starts a sign-in and gets through the identifier and the password.
    async fn after_password(&self) -> (TransactionId, SignIn) {
        let id = self.start().await;
        self.submit(id, StepInput::Identifier("ana@example.com".to_owned()))
            .await
            .expect("identifier");
        let answer = self
            .submit(id, StepInput::Password(Secret::from(PASSWORD.to_owned())))
            .await
            .expect("password");
        (id, answer)
    }

    async fn code(&self, id: TransactionId, typed: &str) -> Result<SignIn, DomainError> {
        self.submit(id, StepInput::Totp(Secret::from(typed.to_owned())))
            .await
    }

    async fn require_second_factor(&self) {
        let mut settings = self
            .tenants
            .get(&self.tenant)
            .await
            .expect("tenant")
            .snapshot()
            .settings
            .clone();
        settings.authentication.second_factor = SecondFactorPolicy::Required;
        self.tenants
            .change_settings(&self.tenant, settings, Caller::system())
            .await
            .expect("settings");
    }
}

fn step_of(answer: &SignIn) -> &str {
    match answer {
        SignIn::Pending { step, .. } | SignIn::Rejected { step, .. } => step,
        other => panic!("not waiting for a step: {other:?}"),
    }
}

#[tokio::test]
async fn with_the_policy_on_a_person_signs_in_with_the_password_and_a_code() {
    let world = world().await;
    let enrollment = world.enroll().await;
    world.require_second_factor().await;

    let (id, after_password) = world.after_password().await;
    assert_eq!(step_of(&after_password), "totp");
    let wrong = world.code(id, "000000").await.expect("answered");
    assert!(matches!(wrong, SignIn::Rejected { .. }), "{wrong:?}");
    let outcome = world
        .code(id, &world.phone(&enrollment))
        .await
        .expect("answered");
    let SignIn::Completed { session, .. } = outcome else {
        panic!("two factors complete the sign-in: {outcome:?}");
    };
    assert_eq!(session.snapshot().assurance, Assurance::MultiFactor);
    assert_eq!(session.snapshot().methods, ["password", "totp"]);
}

#[tokio::test]
async fn a_person_who_enrolled_is_asked_for_a_code_even_with_the_policy_off() {
    let world = world().await;
    let enrollment = world.enroll().await;
    let (id, after_password) = world.after_password().await;
    assert_eq!(step_of(&after_password), "totp");
    let outcome = world
        .code(id, &world.phone(&enrollment))
        .await
        .expect("answered");
    assert!(matches!(outcome, SignIn::Completed { .. }), "{outcome:?}");
}

#[tokio::test]
async fn a_person_without_an_application_signs_in_with_the_password_alone() {
    let world = world().await;
    let (_, outcome) = world.after_password().await;
    let SignIn::Completed { session, .. } = outcome else {
        panic!("nothing more to ask: {outcome:?}");
    };
    assert_eq!(session.snapshot().assurance, Assurance::SingleFactor);
}

#[tokio::test]
async fn with_the_policy_on_a_person_without_an_application_cannot_sign_in() {
    let world = world().await;
    world.require_second_factor().await;
    let (_, outcome) = world.after_password().await;
    assert!(matches!(outcome, SignIn::Failed), "{outcome:?}");
    assert!(
        world
            .sessions
            .list_for_user(&world.tenant, world.ana)
            .await
            .expect("sessions")
            .is_empty()
    );
}

#[tokio::test]
async fn a_code_that_signed_someone_in_does_not_sign_in_again() {
    let world = world().await;
    let enrollment = world.enroll().await;
    let code = world.phone(&enrollment);

    let (first, _) = world.after_password().await;
    let outcome = world.code(first, &code).await.expect("answered");
    assert!(matches!(outcome, SignIn::Completed { .. }), "{outcome:?}");

    // Whoever read the code over her shoulder is too late, within the
    // same thirty seconds.
    let (second, _) = world.after_password().await;
    let outcome = world.code(second, &code).await.expect("answered");
    assert!(matches!(outcome, SignIn::Rejected { .. }), "{outcome:?}");
}

#[tokio::test]
async fn wrong_codes_count_towards_the_lockout_of_the_identifier() {
    let world = world().await;
    world.enroll().await;
    let (id, _) = world.after_password().await;
    // The default policy locks an identifier out at five failures.
    let mut locked = false;
    for _ in 0..5 {
        match world.code(id, "000000").await {
            Ok(SignIn::Rejected { .. } | SignIn::Failed) => {}
            Err(error) if error.code() == "authentication.too_many_attempts" => {
                locked = true;
                break;
            }
            other => panic!("unexpected answer: {other:?}"),
        }
    }
    // Locked out, the password of a new sign-in is not even looked at.
    let id = world.start().await;
    world
        .submit(id, StepInput::Identifier("ana@example.com".to_owned()))
        .await
        .expect("identifier");
    let error = world
        .submit(id, StepInput::Password(Secret::from(PASSWORD.to_owned())))
        .await
        .expect_err("locked out");
    assert_eq!(error.code(), "authentication.too_many_attempts", "{locked}");
}

#[tokio::test]
async fn a_code_is_not_accepted_at_the_password_step_nor_a_password_at_the_code_step() {
    let world = world().await;
    let enrollment = world.enroll().await;
    let id = world.start().await;
    world
        .submit(id, StepInput::Identifier("ana@example.com".to_owned()))
        .await
        .expect("identifier");
    let error = world
        .code(id, &world.phone(&enrollment))
        .await
        .expect_err("not the step waited for");
    assert_eq!(error.code(), "authentication.unexpected_step");
    let after_password = world
        .submit(id, StepInput::Password(Secret::from(PASSWORD.to_owned())))
        .await
        .expect("password");
    assert_eq!(step_of(&after_password), "totp");
    let error = world
        .submit(id, StepInput::Password(Secret::from(PASSWORD.to_owned())))
        .await
        .expect_err("not the step waited for");
    assert_eq!(error.code(), "authentication.unexpected_step");
}
