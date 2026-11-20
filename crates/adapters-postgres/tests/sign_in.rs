//! A whole sign-in with nothing faked: PostgreSQL, Argon2id, SHA-256 and
//! the operating system's random source.

use hodor_adapters_crypto::{
    Argon2Parameters, Argon2idHasher, HashingLimits, OsRandom, Sha256Digest,
};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgAttemptStore, PgPasswordStore, PgSessionStore, PgTenantDirectory, PgTenantRepository,
    PgTransactionStore, PgUserRepository,
};
use hodor_authentication::api::{
    AttemptGuard, AuthFlow, AuthenticationService, FlowEngine, IdentifierAuthenticator,
    PasswordAuthenticator, SignIn, StepInput, TransactionId,
};
use hodor_authentication::testing::{TransactionPorts, run_transaction_contract};
use hodor_credential::api::{CredentialService, NewPassword, PasswordRules};
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_kernel::{Caller, Secret, SystemClock, TenantContext, UserId};
use hodor_session::api::{ClientInfo, SessionService};
use hodor_tenant::api::{CreateTenant, TenantService};
use std::sync::Arc;

const PASSWORD: &str = "correct horse battery staple";

struct World {
    service: AuthenticationService,
    sessions: SessionService,
    tenant: TenantContext,
    ana: UserId,
}

async fn world(database: &TestDatabase) -> World {
    let units = || Arc::new(database.app().clone());
    let clock = Arc::new(SystemClock);
    let digest = Arc::new(Sha256Digest);
    let random = Arc::new(OsRandom);
    // Light parameters keep the test quick; the algorithm and every code
    // path are the real ones.
    let parameters = Argon2Parameters {
        memory_kibibytes: 1024,
        passes: 1,
        lanes: 1,
    };
    let limits = HashingLimits {
        concurrent: 4,
        queued: 64,
    };
    let hasher = Arc::new(Argon2idHasher::new(parameters, limits, random.clone()).expect("hasher"));

    let tenants = TenantService::new(
        units(),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.app().clone())),
        clock.clone(),
    );
    let identity = IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone());
    let credentials =
        CredentialService::new(units(), Arc::new(PgPasswordStore), hasher, clock.clone());
    let sessions = SessionService::new(
        units(),
        Arc::new(PgSessionStore),
        digest.clone(),
        random,
        clock.clone(),
    );
    let guard = AttemptGuard::new(
        units(),
        Arc::new(PgAttemptStore),
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
    let service = AuthenticationService::new(
        units(),
        Arc::new(PgTransactionStore),
        engine,
        AuthFlow::built_in(),
        identity.clone(),
        sessions.clone(),
        tenants.clone(),
        clock,
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
        own_names: &["ana@example.com"],
    };
    credentials
        .set_password(&tenant, ana, new, false, Caller::system())
        .await
        .expect("password");

    World {
        service,
        sessions,
        tenant,
        ana,
    }
}

impl World {
    async fn identified(&self, typed: &str) -> TransactionId {
        let client = ClientInfo {
            address: Some("203.0.113.1".to_owned()),
            description: Some("Example Browser".to_owned()),
        };
        let SignIn::Pending { transaction_id, .. } = self
            .service
            .start(&self.tenant, client)
            .await
            .expect("start")
        else {
            panic!("a new sign-in is pending");
        };
        self.service
            .submit(
                &self.tenant,
                transaction_id,
                StepInput::Identifier(typed.to_owned()),
            )
            .await
            .expect("identifier");
        transaction_id
    }

    async fn password(
        &self,
        id: TransactionId,
        typed: &str,
    ) -> Result<SignIn, hodor_kernel::DomainError> {
        self.service
            .submit(
                &self.tenant,
                id,
                StepInput::Password(Secret::from(typed.to_owned())),
            )
            .await
    }
}

#[tokio::test]
async fn the_postgres_transaction_store_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_transaction_contract(TransactionPorts {
        units_of_work: database.app(),
        transactions: &PgTransactionStore,
    })
    .await;
}

#[tokio::test]
async fn a_person_signs_in_with_nothing_faked() {
    let database = TestDatabase::start().await;
    let world = world(&database).await;

    // A wrong password first, then the right one, typed with other casing
    // in the identifier.
    let id = world.identified("ANA@example.com").await;
    let wrong = world
        .password(id, "not the password at all")
        .await
        .expect("password");
    assert!(
        matches!(
            wrong,
            SignIn::Rejected {
                attempts_left: 4,
                ..
            }
        ),
        "{wrong:?}"
    );
    let done = world.password(id, PASSWORD).await.expect("password");
    let SignIn::Completed { session, token } = done else {
        panic!("expected completion: {done:?}");
    };
    assert_eq!(session.user_id(), world.ana);

    // The token works, and is nowhere in the database.
    let found = world
        .sessions
        .find_by_token(&world.tenant, token.expose())
        .await
        .expect("find")
        .expect("active session");
    assert_eq!(found.id(), session.id());
    let everything: String = sqlx::query_scalar(
        r#"SELECT concat(
               (SELECT string_agg(to_jsonb(t)::text, '') FROM session.session t),
               (SELECT string_agg(to_jsonb(t)::text, '') FROM authentication.transaction t),
               (SELECT string_agg(to_jsonb(t)::text, '') FROM authentication.attempt_counter t),
               (SELECT string_agg(to_jsonb(t)::text, '') FROM credential.password t),
               (SELECT string_agg(to_jsonb(t)::text, '') FROM platform.outbox t))"#,
    )
    .fetch_one(database.owner())
    .await
    .expect("dump");
    assert!(
        !everything.contains(token.expose()),
        "the session token is stored nowhere"
    );
    assert!(
        !everything.contains(PASSWORD),
        "the password is stored nowhere"
    );
    assert!(
        everything.contains("$argon2id$v=19$"),
        "the password is stored as an Argon2id hash"
    );

    // What was announced, in order.
    let events: Vec<String> = sqlx::query_scalar(
        "SELECT event_type FROM platform.outbox
         WHERE event_type LIKE 'authentication.%' OR event_type LIKE 'session.%'
         ORDER BY created_at, id",
    )
    .fetch_all(database.owner())
    .await
    .expect("events");
    assert_eq!(
        events,
        [
            "authentication.failed",
            "session.started",
            "authentication.succeeded"
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_same_sign_in_submitted_many_times_at_once_starts_one_session() {
    let database = TestDatabase::start().await;
    let world = Arc::new(world(&database).await);
    let id = world.identified("ana@example.com").await;

    // The browser's "sign in" button, pressed eight times in the same
    // instant.
    let attempts: Vec<_> = (0..8)
        .map(|_| {
            let world = Arc::clone(&world);
            tokio::spawn(async move { world.password(id, PASSWORD).await })
        })
        .collect();
    let mut completed = 0;
    for attempt in attempts {
        match attempt.await.expect("task") {
            Ok(SignIn::Completed { .. }) => completed += 1,
            Ok(other) => panic!("unexpected answer: {other:?}"),
            // The others lose the race in one of three ways: they find the
            // transaction already advanced or already completed, or, since
            // every submission counts as an attempt until one succeeds,
            // they arrive after the identifier's limit was reached.
            Err(error) => assert!(
                matches!(
                    error.code(),
                    "authentication.transaction_modified_concurrently"
                        | "authentication.transaction_not_active"
                        | "authentication.too_many_attempts"
                ),
                "{error:?}"
            ),
        }
    }

    assert_eq!(completed, 1, "exactly one request completes the sign-in");
    let sessions = world
        .sessions
        .list_for_user(&world.tenant, world.ana)
        .await
        .expect("list");
    assert_eq!(sessions.len(), 1, "and exactly one session exists");

    // The burst leaves no lockout behind: the success cleared the count,
    // so the person can sign in again at once.
    let again = world.identified("ana@example.com").await;
    let answer = world
        .password(again, PASSWORD)
        .await
        .expect("no lockout remains");
    assert!(matches!(answer, SignIn::Completed { .. }), "{answer:?}");
}

#[tokio::test]
async fn a_lockout_holds_against_the_real_database_and_hasher() {
    let database = TestDatabase::start().await;
    let world = world(&database).await;

    // The tenant's default policy: five attempts.
    for _ in 0..5 {
        let id = world.identified("ana@example.com").await;
        let answer = world.password(id, "a wrong guess").await.expect("password");
        assert!(matches!(answer, SignIn::Rejected { .. }), "{answer:?}");
    }
    let id = world.identified("ana@example.com").await;
    let refused = world.password(id, PASSWORD).await.expect_err("locked out");
    assert_eq!(refused.code(), "authentication.too_many_attempts");
    assert!(
        refused
            .retry_after_seconds()
            .is_some_and(|seconds| (1..=60).contains(&seconds))
    );
}
