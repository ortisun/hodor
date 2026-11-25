//! Signing in with a code or a link sent by email: the real email
//! alternatives, the attempt guard and the use cases, over the real
//! identity, credential, session, notification and tenant contexts running
//! on their in-memory ports.

use hodor_authentication::api::{
    AttemptGuard, AuthFlow, AuthenticationService, EmailAuthenticator, EmailSignInPorts,
    ExternalInput, FlowEngine, IdentifierAuthenticator, PasswordAuthenticator, Requirement, SignIn,
    StepInput, TransactionId,
};
use hodor_authentication::testing::{
    InMemoryAttempts, InMemoryEmailSignIns, InMemoryTransactions, TestSecondFactor,
};
use hodor_credential::api::{CredentialService, NewPassword, PasswordRules};
use hodor_credential::testing::{FakeHasher, InMemoryPasswords};
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_identity::testing::InMemoryUsers;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::{CountingRandom, FakeDigest};
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, DomainError, ErrorKind, Secret, TenantContext, Timestamp, UserId};
use hodor_notification::api::{Notifier, Template};
use hodor_notification::testing::InMemoryMessages;
use hodor_session::api::{Assurance, ClientInfo, SessionService};
use hodor_session::testing::{InMemorySessions, SequentialRandom};
use hodor_tenant::api::{CreateTenant, SecondFactorPolicy, TenantService};
use hodor_tenant::testing::InMemoryTenants;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use time::Duration;

const PASSWORD: &str = "correct horse battery staple";
const ANA: &str = "ana@example.com";

struct World {
    service: AuthenticationService,
    identity: IdentityService,
    tenants: TenantService,
    units_of_work: InMemoryUnitOfWorkFactory,
    messages: InMemoryMessages,
    sent: InMemoryEmailSignIns,
    second_factor: TestSecondFactor,
    clock: Arc<FixedClock>,
    tenant: TenantContext,
    ana: UserId,
    secrets: Mutex<HashMap<TransactionId, String>>,
    /// The messages a test has looked at already.
    seen: Mutex<HashSet<String>>,
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
    let messages = InMemoryMessages::default();
    let sent = InMemoryEmailSignIns::default();
    let ports = EmailSignInPorts {
        units_of_work: factory(),
        sent: Arc::new(sent.clone()),
        identity: identity.clone(),
        tenants: tenants.clone(),
        notifier: Notifier::new(Arc::new(messages.clone()), clock.clone()),
        guard: guard.clone(),
        digest: digest.clone(),
        random: Arc::new(CountingRandom::default()),
        clock: clock.clone(),
        public_url: "https://login.example.com/".to_owned(),
    };
    let second_factor = TestSecondFactor::default();
    let engine = FlowEngine::new()
        .with(Arc::new(IdentifierAuthenticator::new(
            identity.clone(),
            digest.clone(),
        )))
        .with(Arc::new(PasswordAuthenticator::new(
            credentials.clone(),
            identity.clone(),
            tenants.clone(),
            guard,
        )))
        .with(Arc::new(EmailAuthenticator::code(ports.clone())))
        .with(Arc::new(EmailAuthenticator::link(ports)))
        .with(Arc::new(second_factor.clone()));
    let flow = AuthFlow::built_in()
        .with_step(
            TestSecondFactor::KIND,
            TestSecondFactor::KIND,
            Requirement::Conditional(hodor_authentication::api::Condition::MultiFactorNotReached),
        )
        .with_alternative(EmailAuthenticator::CODE_KIND, EmailAuthenticator::CODE_KIND)
        .with_alternative(EmailAuthenticator::LINK_KIND, EmailAuthenticator::LINK_KIND);
    let service = AuthenticationService::new(
        factory(),
        Arc::new(InMemoryTransactions::default()),
        engine,
        flow,
        identity.clone(),
        sessions,
        tenants.clone(),
        digest,
        Arc::new(SequentialRandom::default()),
        clock.clone(),
    )
    .expect("the flow with both email alternatives is valid");

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
    let world = World {
        service,
        identity,
        tenants,
        units_of_work,
        messages,
        sent,
        second_factor,
        clock,
        tenant,
        ana: UserId::generate(),
        secrets: Mutex::new(HashMap::new()),
        seen: Mutex::new(HashSet::new()),
    };
    let ana = world.person(ANA).await;
    let password = Secret::from(PASSWORD.to_owned());
    credentials
        .set_password(
            &world.tenant,
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
    World { ana, ..world }
}

fn asked(step: &str, email: &str) -> ExternalInput {
    ExternalInput {
        step: step.to_owned(),
        fields: vec![
            ("email".to_owned(), Secret::from(email.to_owned())),
            ("locale".to_owned(), Secret::from("pt-BR".to_owned())),
        ],
    }
}

fn code(typed: &str) -> StepInput {
    StepInput::External(ExternalInput {
        step: EmailAuthenticator::CODE_KIND.to_owned(),
        fields: vec![("code".to_owned(), Secret::from(typed.to_owned()))],
    })
}

fn token(typed: &str) -> StepInput {
    StepInput::External(ExternalInput {
        step: EmailAuthenticator::LINK_KIND.to_owned(),
        fields: vec![("token".to_owned(), Secret::from(typed.to_owned()))],
    })
}

impl World {
    async fn person(&self, email: &str) -> UserId {
        self.identity
            .create(
                &self.tenant,
                CreateUser {
                    kind: UserKind::Human,
                    identifiers: vec![(IdentifierKind::Email, email.to_owned())],
                    profile: Profile::default(),
                    confirmed: true,
                },
                Caller::system(),
            )
            .await
            .expect("user")
            .id()
    }

    async fn offer(&self, code: bool, link: bool) {
        let mut settings = self
            .tenants
            .get(&self.tenant)
            .await
            .expect("tenant")
            .snapshot()
            .settings
            .clone();
        settings.authentication.email_sign_in.code = code;
        settings.authentication.email_sign_in.link = link;
        self.tenants
            .change_settings(&self.tenant, settings, Caller::system())
            .await
            .expect("settings");
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

    fn secret(&self, id: TransactionId) -> String {
        self.secrets.lock().expect("secrets")[&id].clone()
    }

    async fn ask(&self, id: TransactionId, step: &str, email: &str) -> Result<(), DomainError> {
        self.service
            .challenge(&self.tenant, id, &self.secret(id), asked(step, email))
            .await
            .map(|options| assert_eq!(options, serde_json::json!({})))
    }

    async fn submit(&self, id: TransactionId, input: StepInput) -> Result<SignIn, DomainError> {
        self.service
            .submit(&self.tenant, id, &self.secret(id), input)
            .await
    }

    /// The one message queued since the last look, whole.
    fn newest_message(&self) -> hodor_notification::api::Message {
        let mut seen = self.seen.lock().expect("seen");
        let fresh: Vec<_> = self
            .messages
            .of_tenant(self.tenant.tenant_id())
            .into_iter()
            .filter(|message| !seen.contains(&message.snapshot().id.to_string()))
            .collect();
        assert_eq!(fresh.len(), 1, "exactly one new message");
        seen.insert(fresh[0].snapshot().id.to_string());
        fresh[0].clone()
    }

    /// A variable of the one message queued since the last look, and its
    /// template.
    fn newest(&self, variable: &str) -> (Template, String) {
        let message = self.newest_message();
        let message = message.snapshot();
        (message.template, message.variables[variable].clone())
    }

    fn message_count(&self) -> usize {
        self.messages.of_tenant(self.tenant.tenant_id()).len()
    }

    fn events(&self, event_type: &str) -> Vec<serde_json::Value> {
        self.units_of_work
            .committed_events()
            .into_iter()
            .filter(|event| event.event_type == event_type)
            .map(|event| event.payload)
            .collect()
    }
}

fn completed_methods(answer: &SignIn) -> Vec<String> {
    match answer {
        SignIn::Completed { session, .. } => session.snapshot().methods.clone(),
        other => panic!("not completed: {other:?}"),
    }
}

#[tokio::test]
async fn a_person_signs_in_with_a_code_once() {
    let world = world().await;
    world.offer(true, false).await;
    assert_eq!(
        world
            .service
            .alternatives(&world.tenant)
            .await
            .expect("alternatives"),
        vec!["email_code".to_owned()]
    );
    let id = world.start().await;
    world
        .ask(id, "email_code", "Ana@Example.com")
        .await
        .expect("asked");

    let message = world.newest_message();
    let message = message.snapshot();
    assert_eq!(message.template, Template::SignInCode);
    let sent = message.variables["code"].clone();
    assert_eq!(sent.len(), 6);
    assert!(sent.bytes().all(|b| b.is_ascii_digit()));
    assert_eq!(message.recipient, "Ana@Example.com");
    assert_eq!(message.locale.as_str(), "pt-BR");
    assert_eq!(message.variables["tenant_name"], "Acme");
    assert_eq!(
        message.expires_at,
        world.clock_now() + Duration::minutes(10)
    );
    let announced = world.events("authentication.email_sign_in_sent");
    assert_eq!(announced.len(), 1);
    assert_eq!(announced[0]["user_id"], world.ana.to_string());
    assert_eq!(announced[0]["method"], "email_code");
    assert!(
        !announced[0].to_string().contains(&sent),
        "no event carries the code"
    );

    let answer = world
        .submit(id, code(&format!(" {sent} ")))
        .await
        .expect("code");
    assert_eq!(completed_methods(&answer), vec!["email_code".to_owned()]);
    match &answer {
        SignIn::Completed { session, .. } => {
            assert_eq!(session.user_id(), world.ana);
            assert_eq!(session.snapshot().assurance, Assurance::SingleFactor);
        }
        _ => unreachable!(),
    }

    // The second time it is refused: the sign-in it belonged to is over.
    let again = world.submit(id, code(&sent)).await.expect_err("spent");
    assert_eq!(again.code(), "authentication.transaction_not_active");
    // And a new sign-in never asked for it.
    let other = world.start().await;
    assert!(matches!(
        world.submit(other, code(&sent)).await.expect("answered"),
        SignIn::Rejected { .. }
    ));
}

impl World {
    fn clock_now(&self) -> Timestamp {
        use hodor_kernel::Clock as _;
        self.clock.now()
    }
}

#[tokio::test]
async fn a_person_signs_in_with_a_link_once() {
    let world = world().await;
    world.offer(false, true).await;
    let id = world.start().await;
    world.ask(id, "email_link", ANA).await.expect("asked");
    let (template, link) = world.newest("link");
    assert_eq!(template, Template::SignInLink);
    let (page, sent) = link.split_once("#token=").expect("token in the fragment");
    assert_eq!(
        page,
        "https://login.example.com/t/acme/account/sign-in-link"
    );
    assert_eq!(sent.len(), 64);

    // A code is refused while codes are off.
    let refused = world.submit(id, code("123456")).await.expect_err("off");
    assert_eq!(refused.code(), "authentication.method_not_offered");
    let answer = world.submit(id, token(sent)).await.expect("link");
    assert_eq!(completed_methods(&answer), vec!["email_link".to_owned()]);
    let again = world.submit(id, token(sent)).await.expect_err("spent");
    assert_eq!(again.code(), "authentication.transaction_not_active");
}

#[tokio::test]
async fn neither_is_offered_until_the_tenant_turns_it_on() {
    let world = world().await;
    assert!(
        world
            .service
            .alternatives(&world.tenant)
            .await
            .expect("alternatives")
            .is_empty()
    );
    let id = world.start().await;
    for step in ["email_code", "email_link"] {
        let refused = world.ask(id, step, ANA).await.expect_err("off");
        assert_eq!(refused.code(), "authentication.method_not_offered");
        assert_eq!(refused.kind(), ErrorKind::Forbidden);
    }
    let refused = world.submit(id, code("123456")).await.expect_err("off");
    assert_eq!(refused.code(), "authentication.method_not_offered");
    assert_eq!(world.message_count(), 0);
    assert_eq!(world.sent.count(), 0);

    // Turned on, then off again: what was sent is no longer accepted.
    world.offer(true, true).await;
    assert_eq!(
        world
            .service
            .alternatives(&world.tenant)
            .await
            .expect("alternatives"),
        vec!["email_code".to_owned(), "email_link".to_owned()]
    );
    world.ask(id, "email_code", ANA).await.expect("asked");
    let (_, sent) = world.newest("code");
    world.offer(false, true).await;
    let refused = world.submit(id, code(&sent)).await.expect_err("off");
    assert_eq!(refused.code(), "authentication.method_not_offered");
}

#[tokio::test]
async fn asking_answers_the_same_whoever_the_address_belongs_to() {
    let world = world().await;
    world.offer(true, true).await;
    let bia = world.person("bia@example.com").await;
    world
        .identity
        .suspend(&world.tenant, bia, "left", Caller::system())
        .await
        .expect("suspended");

    for (address, step) in [
        ("nobody@example.com", "email_code"),
        ("bia@example.com", "email_code"),
        ("not an address", "email_code"),
        ("nobody@example.com", "email_link"),
        ("", "email_link"),
    ] {
        let id = world.start().await;
        let before = world.sent.count();
        world.ask(id, step, address).await.expect("the same answer");
        assert_eq!(
            world.sent.count(),
            before + 1,
            "a row is kept for {address:?}"
        );
        assert_eq!(world.message_count(), 0, "nothing is sent to {address:?}");
        // Whatever is presented, nothing signs in.
        for typed in ["000000", "123456"] {
            assert!(matches!(
                world.submit(id, code(typed)).await,
                Ok(SignIn::Rejected { .. }) | Err(_)
            ));
        }
    }
    assert!(world.events("authentication.email_sign_in_sent").is_empty());

    // And for a person who may sign in, the answer is the same too.
    let id = world.start().await;
    world
        .ask(id, "email_code", ANA)
        .await
        .expect("the same answer");
    assert_eq!(world.message_count(), 1);
    // A token for a code is a rejection like any other.
    assert!(matches!(
        world
            .submit(id, token(&"a".repeat(64)))
            .await
            .expect("answered"),
        SignIn::Rejected { .. }
    ));
}

#[tokio::test]
async fn a_code_belongs_to_the_sign_in_that_asked_for_it() {
    let world = world().await;
    world.offer(true, false).await;
    let asking = world.start().await;
    let elsewhere = world.start().await;
    world.ask(asking, "email_code", ANA).await.expect("asked");
    let (_, sent) = world.newest("code");

    // Another sign-in, which asked nothing, or asked for the same address.
    assert!(matches!(
        world
            .submit(elsewhere, code(&sent))
            .await
            .expect("answered"),
        SignIn::Rejected { .. }
    ));
    world
        .ask(elsewhere, "email_code", ANA)
        .await
        .expect("asked");
    let (_, theirs) = world.newest("code");
    if theirs != sent {
        assert!(matches!(
            world
                .submit(elsewhere, code(&sent))
                .await
                .expect("answered"),
            SignIn::Rejected { .. }
        ));
    }

    // The sign-in that asked still signs in with it.
    let answer = world.submit(asking, code(&sent)).await.expect("code");
    assert_eq!(completed_methods(&answer), vec!["email_code".to_owned()]);
}

#[tokio::test]
async fn a_mistyped_code_can_be_typed_again_and_asking_again_replaces_it() {
    let world = world().await;
    world.offer(true, false).await;
    let id = world.start().await;
    world.ask(id, "email_code", ANA).await.expect("asked");
    let (_, first) = world.newest("code");
    let wrong = if first == "000000" {
        "000001"
    } else {
        "000000"
    };
    for typed in [wrong, "12345", "abcdef"] {
        assert!(matches!(
            world.submit(id, code(typed)).await.expect("answered"),
            SignIn::Rejected { .. }
        ));
    }

    world.ask(id, "email_code", ANA).await.expect("asked again");
    let (_, second) = world.newest("code");
    assert_ne!(first, second);
    assert!(
        matches!(
            world.submit(id, code(&first)).await.expect("answered"),
            SignIn::Rejected {
                attempts_left: 1,
                ..
            }
        ),
        "only the newest code is good"
    );
    let answer = world.submit(id, code(&second)).await.expect("code");
    assert_eq!(completed_methods(&answer), vec!["email_code".to_owned()]);
}

#[tokio::test]
async fn five_rejections_end_the_sign_in() {
    let world = world().await;
    world.offer(true, false).await;
    let id = world.start().await;
    world.ask(id, "email_code", ANA).await.expect("asked");
    let (_, sent) = world.newest("code");
    let wrong = if sent == "000000" { "000001" } else { "000000" };
    for _ in 0..4 {
        assert!(matches!(
            world.submit(id, code(wrong)).await.expect("answered"),
            SignIn::Rejected { .. }
        ));
    }
    assert!(matches!(
        world.submit(id, code(wrong)).await.expect("answered"),
        SignIn::Failed
    ));
    let over = world.submit(id, code(&sent)).await.expect_err("over");
    assert_eq!(over.code(), "authentication.transaction_not_active");
}

#[tokio::test]
async fn wrong_codes_count_towards_the_lockout_of_the_password() {
    let world = world().await;
    world.offer(true, false).await;
    // Four wrong codes in one sign-in and one in another: five failures for
    // the address, the tenant's limit.
    for wrong_codes in [4, 1] {
        let id = world.start().await;
        world.ask(id, "email_code", ANA).await.expect("asked");
        let (_, sent) = world.newest("code");
        let wrong = if sent == "000000" { "000001" } else { "000000" };
        for _ in 0..wrong_codes {
            assert!(matches!(
                world.submit(id, code(wrong)).await.expect("answered"),
                SignIn::Rejected { .. }
            ));
        }
    }
    // The password is not even checked for the same identifier now.
    let id = world.start().await;
    world
        .submit(id, StepInput::Identifier(ANA.to_owned()))
        .await
        .expect("identifier");
    let limited = world
        .submit(id, StepInput::Password(Secret::from(PASSWORD.to_owned())))
        .await
        .expect_err("locked out");
    assert_eq!(limited.code(), "authentication.too_many_attempts");
    assert_eq!(world.events("authentication.locked_out").len(), 1);
}

#[tokio::test]
async fn asking_is_limited_apart_from_signing_in() {
    let world = world().await;
    world.offer(true, false).await;
    let id = world.start().await;
    for _ in 0..5 {
        world.ask(id, "email_code", ANA).await.expect("asked");
    }
    let limited = world
        .ask(id, "email_code", "ANA@example.com")
        .await
        .expect_err("limited");
    assert_eq!(limited.code(), "authentication.too_many_attempts");
    assert_eq!(world.message_count(), 5);

    // Signing in with the password is not limited by it.
    let other = world.start().await;
    world
        .submit(other, StepInput::Identifier(ANA.to_owned()))
        .await
        .expect("identifier");
    let answer = world
        .submit(
            other,
            StepInput::Password(Secret::from(PASSWORD.to_owned())),
        )
        .await
        .expect("password");
    assert!(matches!(answer, SignIn::Completed { .. }));
}

#[tokio::test]
async fn neither_is_taken_once_a_step_was_satisfied() {
    let world = world().await;
    world.offer(true, true).await;
    let id = world.start().await;
    world
        .submit(id, StepInput::Identifier(ANA.to_owned()))
        .await
        .expect("identifier");
    for step in ["email_code", "email_link"] {
        let refused = world.ask(id, step, ANA).await.expect_err("too late");
        assert_eq!(refused.code(), "authentication.unexpected_step");
    }
    assert_eq!(world.message_count(), 0);
}

#[tokio::test]
async fn a_person_who_may_no_longer_sign_in_is_rejected_like_a_wrong_code() {
    let world = world().await;
    world.offer(true, false).await;
    let id = world.start().await;
    world.ask(id, "email_code", ANA).await.expect("asked");
    let (_, sent) = world.newest("code");
    world
        .identity
        .suspend(&world.tenant, world.ana, "left", Caller::system())
        .await
        .expect("suspended");
    assert!(matches!(
        world.submit(id, code(&sent)).await.expect("answered"),
        SignIn::Rejected { .. }
    ));
}

#[tokio::test]
async fn a_code_dies_with_the_sign_in_that_asked_for_it() {
    let world = world().await;
    world.offer(true, false).await;
    let id = world.start().await;
    world.ask(id, "email_code", ANA).await.expect("asked");
    let (_, sent) = world.newest("code");
    world.clock.advance(Duration::minutes(10));
    // The sign-in expired with it.
    let expired = world.submit(id, code(&sent)).await.expect_err("expired");
    assert_eq!(expired.code(), "authentication.transaction_not_active");
}

#[tokio::test]
async fn a_second_factor_is_asked_for_after_it_and_makes_the_sign_in_multi_factor() {
    let world = world().await;
    world.offer(true, false).await;
    world.second_factor.enroll(world.ana);
    let mut settings = world
        .tenants
        .get(&world.tenant)
        .await
        .expect("tenant")
        .snapshot()
        .settings
        .clone();
    settings.authentication.second_factor = SecondFactorPolicy::Required;
    world
        .tenants
        .change_settings(&world.tenant, settings, Caller::system())
        .await
        .expect("settings");

    let id = world.start().await;
    world.ask(id, "email_code", ANA).await.expect("asked");
    let (_, sent) = world.newest("code");
    let answer = world.submit(id, code(&sent)).await.expect("code");
    assert!(
        matches!(&answer, SignIn::Pending { step, .. } if step == TestSecondFactor::KIND),
        "{answer:?}"
    );
    let answer = world
        .submit(
            id,
            StepInput::External(ExternalInput {
                step: TestSecondFactor::KIND.to_owned(),
                fields: vec![(
                    "code".to_owned(),
                    Secret::from(TestSecondFactor::CODE.to_owned()),
                )],
            }),
        )
        .await
        .expect("second factor");
    match answer {
        SignIn::Completed { session, .. } => {
            assert_eq!(session.snapshot().assurance, Assurance::MultiFactor);
            assert_eq!(
                session.snapshot().methods,
                vec!["email_code".to_owned(), TestSecondFactor::METHOD.to_owned()]
            );
        }
        other => panic!("not completed: {other:?}"),
    }
}

#[tokio::test]
async fn the_in_memory_store_passes_the_contract() {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    hodor_authentication::testing::run_email_sign_in_contract(
        hodor_authentication::testing::EmailSignInPortsUnderTest {
            units_of_work: &units_of_work,
            sent: &InMemoryEmailSignIns::default(),
        },
    )
    .await;
}
