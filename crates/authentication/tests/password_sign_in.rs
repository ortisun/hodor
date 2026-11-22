//! Signing in with a login identifier and a password: the real
//! authenticators and the attempt guard, over the real identity,
//! credential and tenant contexts running on their in-memory ports.

use hodor_authentication::api::{
    AttemptGuard, AuthFlow, AuthTransaction, FlowEngine, IdentifierAuthenticator,
    PasswordAuthenticator, Progress, StepInput,
};
use hodor_authentication::testing::{AttemptPorts, InMemoryAttempts, run_attempt_contract};
use hodor_credential::api::{CredentialService, NewPassword, PasswordRules};
use hodor_credential::testing::{FakeHasher, InMemoryPasswords};
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_identity::testing::InMemoryUsers;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, Clock as _, DomainError, ErrorKind, Secret, TenantContext, Timestamp, UserId,
};
use hodor_session::api::ClientInfo;
use hodor_tenant::api::{CreateTenant, TenantService};
use hodor_tenant::testing::InMemoryTenants;
use std::sync::Arc;
use time::Duration;

const PASSWORD: &str = "correct horse battery staple";

struct World {
    engine: FlowEngine,
    flow: AuthFlow,
    identity: IdentityService,
    credentials: CredentialService,
    hasher: Arc<FakeHasher>,
    clock: Arc<FixedClock>,
    units_of_work: InMemoryUnitOfWorkFactory,
    tenant: TenantContext,
    ana: UserId,
}

async fn world() -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let clock = Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH));
    let digest = Arc::new(FakeDigest);
    let hasher = Arc::new(FakeHasher::default());

    let tenant_rows = InMemoryTenants::default();
    let tenants = TenantService::new(
        Arc::new(units_of_work.clone()),
        Arc::new(tenant_rows.clone()),
        Arc::new(tenant_rows),
        clock.clone(),
    );
    let identity = IdentityService::new(
        Arc::new(units_of_work.clone()),
        Arc::new(InMemoryUsers::default()),
        clock.clone(),
    );
    let credentials = CredentialService::new(
        Arc::new(units_of_work.clone()),
        Arc::new(InMemoryPasswords::default()),
        hasher.clone(),
        clock.clone(),
    );
    let guard = AttemptGuard::new(
        Arc::new(units_of_work.clone()),
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
            guard,
        )));

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

    let mut world = World {
        engine,
        flow: AuthFlow::built_in(),
        identity,
        credentials,
        hasher,
        clock,
        units_of_work,
        tenant,
        ana: UserId::generate(),
    };
    world.ana = world.person("ana@example.com", Some(PASSWORD)).await;
    world
}

impl World {
    /// Creates a confirmed person, with a password if one is given.
    async fn person(&self, email: &str, password: Option<&str>) -> UserId {
        let user = self
            .identity
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
            .expect("user");
        if let Some(password) = password {
            let password = Secret::from(password.to_owned());
            let new = NewPassword {
                password: &password,
                rules: PasswordRules {
                    min_length: 12,
                    max_length: 128,
                    history_depth: 5,
                },
                own_names: &[],
            };
            self.credentials
                .set_password(&self.tenant, user.id(), new, false, Caller::system())
                .await
                .expect("password");
        }
        user.id()
    }

    fn begin_from(&self, address: &str) -> AuthTransaction {
        let client = ClientInfo {
            address: Some(address.to_owned()),
            description: None,
        };
        AuthTransaction::start(&self.flow, client, [9; 32], self.clock.now())
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
                self.clock.now(),
            )
            .await
    }

    /// One whole attempt in a fresh transaction: identifier, then password.
    async fn attempt_from(
        &self,
        address: &str,
        identifier: &str,
        password: &str,
    ) -> Result<Progress, DomainError> {
        let mut transaction = self.begin_from(address);
        self.submit(
            &mut transaction,
            StepInput::Identifier(identifier.to_owned()),
        )
        .await
        .expect("the identifier step always succeeds");
        self.submit(
            &mut transaction,
            StepInput::Password(Secret::from(password.to_owned())),
        )
        .await
    }

    async fn attempt(&self, identifier: &str, password: &str) -> Result<Progress, DomainError> {
        self.attempt_from("203.0.113.1", identifier, password).await
    }

    fn hashing_work(&self) -> usize {
        self.hasher.verifications() + self.hasher.checks_against_nothing()
    }
}

fn rejected(result: &Result<Progress, DomainError>) -> bool {
    matches!(result, Ok(Progress::Rejected { .. }))
}

fn too_many(result: &Result<Progress, DomainError>) -> Option<u64> {
    match result {
        Err(error) if error.code() == "authentication.too_many_attempts" => {
            assert_eq!(error.kind(), ErrorKind::RateLimited);
            error.retry_after_seconds()
        }
        _ => None,
    }
}

#[tokio::test]
async fn the_in_memory_attempt_store_passes_the_contract() {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let attempts = InMemoryAttempts::default();
    run_attempt_contract(AttemptPorts {
        units_of_work: &units_of_work,
        attempts: &attempts,
    })
    .await;
}

#[tokio::test]
async fn the_right_password_signs_in_however_the_identifier_is_spelled() {
    let world = world().await;
    for typed in ["ana@example.com", "  ANA@Example.COM "] {
        let mut transaction = world.begin_from("203.0.113.1");
        world
            .submit(&mut transaction, StepInput::Identifier(typed.to_owned()))
            .await
            .expect("identifier");
        let answer = world
            .submit(
                &mut transaction,
                StepInput::Password(Secret::from(PASSWORD.to_owned())),
            )
            .await
            .expect("password");
        assert_eq!(answer, Progress::ReadyToComplete, "{typed}");
        assert_eq!(
            transaction
                .complete(&world.flow, world.clock.now())
                .expect("complete"),
            world.ana
        );
    }
}

#[tokio::test]
async fn every_kind_of_failure_looks_the_same_and_costs_the_same() {
    let world = world().await;
    world.person("no-password@example.com", None).await;
    let pending = world.person("pending@example.com", Some(PASSWORD)).await;
    world
        .identity
        .suspend(&world.tenant, pending, "review", Caller::system())
        .await
        .expect("suspend");

    let cases = [
        ("wrong password", "ana@example.com", "not the password"),
        ("nobody", "nobody@example.com", PASSWORD),
        ("not an identifier at all", "!!! ???", PASSWORD),
        ("no password set", "no-password@example.com", PASSWORD),
        (
            "suspended, with the right password",
            "pending@example.com",
            PASSWORD,
        ),
    ];
    let mut answers = Vec::new();
    for (name, identifier, password) in cases {
        let before = world.hashing_work();
        let answer = world.attempt(identifier, password).await;
        assert!(rejected(&answer), "{name}: {answer:?}");
        assert_eq!(
            world.hashing_work() - before,
            1,
            "{name}: one hash computation, like any other"
        );
        answers.push(format!("{answer:?}"));
    }
    assert!(
        answers.windows(2).all(|pair| pair[0] == pair[1]),
        "{answers:?}"
    );
}

#[tokio::test]
async fn the_sixth_attempt_is_refused_without_looking_at_the_password() {
    let world = world().await;
    for _ in 0..5 {
        assert!(rejected(
            &world.attempt("ana@example.com", "wrong guess").await
        ));
    }
    let work_before = world.hashing_work();

    // Even the right password is refused now, and nothing is hashed.
    let refused = world.attempt("ana@example.com", PASSWORD).await;
    assert_eq!(too_many(&refused), Some(60), "{refused:?}");
    assert_eq!(
        world.hashing_work(),
        work_before,
        "no password is checked during a lockout"
    );

    // A different spelling of the same identifier is the same identifier.
    assert!(too_many(&world.attempt("ANA@EXAMPLE.COM", PASSWORD).await).is_some());
    // Another person is not affected.
    world.person("bia@example.com", Some(PASSWORD)).await;
    assert_eq!(
        world
            .attempt("bia@example.com", PASSWORD)
            .await
            .expect("bia"),
        Progress::ReadyToComplete
    );

    // Once the lockout has passed, the right password works.
    world.clock.advance(Duration::seconds(60));
    assert_eq!(
        world
            .attempt("ana@example.com", PASSWORD)
            .await
            .expect("ana"),
        Progress::ReadyToComplete
    );
}

#[tokio::test]
async fn an_identifier_that_belongs_to_nobody_is_locked_out_in_the_same_way() {
    let world = world().await;
    let mut for_nobody = Vec::new();
    let mut for_ana = Vec::new();
    for _ in 0..7 {
        for_nobody.push(format!(
            "{:?}",
            world
                .attempt_from("203.0.113.1", "ghost@example.com", "guess")
                .await
        ));
        for_ana.push(format!(
            "{:?}",
            world
                .attempt_from("203.0.113.2", "ana@example.com", "guess")
                .await
        ));
    }
    assert_eq!(
        for_nobody, for_ana,
        "a lockout reveals nothing about who exists"
    );
}

#[tokio::test]
async fn lockouts_double_and_a_success_wipes_the_slate() {
    let world = world().await;
    let fail_until_locked = async || {
        loop {
            if let Some(seconds) = too_many(&world.attempt("ana@example.com", "wrong guess").await)
            {
                return seconds;
            }
        }
    };

    assert_eq!(fail_until_locked().await, 60);
    world.clock.advance(Duration::seconds(60));
    assert_eq!(fail_until_locked().await, 120);
    world.clock.advance(Duration::seconds(120));
    assert_eq!(fail_until_locked().await, 240);

    // A successful sign-in forgets the history...
    world.clock.advance(Duration::seconds(240));
    assert_eq!(
        world
            .attempt("ana@example.com", PASSWORD)
            .await
            .expect("ana"),
        Progress::ReadyToComplete
    );
    // ...so the next lockout is a first one again, after a full five tries.
    for _ in 0..5 {
        assert!(rejected(
            &world.attempt("ana@example.com", "wrong guess").await
        ));
    }
    assert_eq!(
        too_many(&world.attempt("ana@example.com", "wrong guess").await),
        Some(60)
    );
}

#[tokio::test]
async fn attempts_outside_the_window_do_not_add_up() {
    let world = world().await;
    for _ in 0..4 {
        assert!(rejected(
            &world.attempt("ana@example.com", "wrong guess").await
        ));
    }
    world.clock.advance(Duration::minutes(15));
    for _ in 0..4 {
        assert!(
            rejected(&world.attempt("ana@example.com", "wrong guess").await),
            "a new window"
        );
    }
}

#[tokio::test]
async fn an_address_that_tries_many_identifiers_is_locked_out_itself() {
    let world = world().await;
    // Fifty guesses, each against a different identifier, so that no
    // identifier reaches its own limit.
    for n in 0..50 {
        let answer = world
            .attempt_from("198.51.100.7", &format!("person{n}@example.com"), "guess")
            .await;
        assert!(rejected(&answer), "attempt {n}: {answer:?}");
    }

    // The address is now refused, even for a real person's right password.
    let refused = world
        .attempt_from("198.51.100.7", "ana@example.com", PASSWORD)
        .await;
    assert!(too_many(&refused).is_some(), "{refused:?}");
    // The same person from elsewhere is fine.
    let elsewhere = world
        .attempt_from("203.0.113.50", "ana@example.com", PASSWORD)
        .await;
    assert_eq!(elsewhere.expect("elsewhere"), Progress::ReadyToComplete);
}

#[tokio::test]
async fn a_lockout_is_announced_and_nothing_announced_names_the_identifier() {
    let world = world().await;
    for _ in 0..5 {
        world
            .attempt("ana@example.com", "wrong guess")
            .await
            .expect("attempt");
    }
    let events = world.units_of_work.committed_events();
    let lockouts: Vec<_> = events
        .iter()
        .filter(|event| event.event_type == "authentication.locked_out")
        .collect();
    assert_eq!(lockouts.len(), 1);
    assert_eq!(lockouts[0].payload["subject"], "identifier");
    assert_eq!(lockouts[0].payload["until"], "1970-01-01T00:01:00Z");
    let published = format!("{events:?}");
    assert!(!published.contains("wrong guess"), "no password in events");
}

#[tokio::test]
async fn an_overloaded_hasher_is_an_error_and_the_sign_in_can_be_retried() {
    let world = world().await;
    let mut transaction = world.begin_from("203.0.113.1");
    world
        .submit(
            &mut transaction,
            StepInput::Identifier("ana@example.com".to_owned()),
        )
        .await
        .expect("identifier");
    world.hasher.set_overloaded(true);

    let error = world
        .submit(
            &mut transaction,
            StepInput::Password(Secret::from(PASSWORD.to_owned())),
        )
        .await
        .expect_err("overloaded");
    assert_eq!(error.kind(), ErrorKind::Unavailable);
    assert_eq!(
        transaction.snapshot().rejections,
        0,
        "an outage is not a rejection"
    );

    world.hasher.set_overloaded(false);
    let answer = world
        .submit(
            &mut transaction,
            StepInput::Password(Secret::from(PASSWORD.to_owned())),
        )
        .await
        .expect("retry");
    assert_eq!(answer, Progress::ReadyToComplete);
}
