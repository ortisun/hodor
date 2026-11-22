//! Registration and password recovery with nothing faked: PostgreSQL,
//! Argon2id, SHA-256 and the operating system's random source.

use hodor_adapters_crypto::{
    Argon2Parameters, Argon2idHasher, HashingLimits, OsRandom, Sha256Digest,
};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgAttemptStore, PgMessageQueue, PgPasswordStore, PgSessionStore, PgTenantDirectory,
    PgTenantRepository, PgUserRepository, PgVerificationTokenStore,
};
use hodor_authentication::api::{AccountRequest, AccountService, AttemptGuard};
use hodor_authentication::testing::{VerificationTokenPorts, run_verification_token_contract};
use hodor_credential::api::{CredentialService, PasswordCheck};
use hodor_identity::api::IdentityService;
use hodor_kernel::{Caller, DomainError, Secret, SystemClock, TenantContext, UserId};
use hodor_notification::api::Notifier;
use hodor_session::api::SessionService;
use hodor_tenant::api::{CreateTenant, TenantService};
use std::sync::Arc;

const PASSWORD: &str = "correct horse battery staple";

struct World {
    accounts: AccountService,
    credentials: CredentialService,
    identity: IdentityService,
    tenant: TenantContext,
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
        random.clone(),
        clock.clone(),
    );
    let guard = AttemptGuard::new(
        units(),
        Arc::new(PgAttemptStore),
        digest.clone(),
        clock.clone(),
    );
    let accounts = AccountService::new(
        units(),
        Arc::new(PgVerificationTokenStore),
        identity.clone(),
        credentials.clone(),
        sessions,
        tenants.clone(),
        Notifier::new(Arc::new(PgMessageQueue), clock.clone()),
        guard,
        digest,
        random,
        clock,
        "https://login.example.com",
    );

    let created = tenants
        .create(
            CreateTenant {
                slug: "acme".to_owned(),
                display_name: "Acme".to_owned(),
                open_registration: true,
                system: false,
            },
            Caller::system(),
        )
        .await
        .expect("tenant");

    World {
        accounts,
        credentials,
        identity,
        tenant: TenantContext::assume(created.id()),
    }
}

fn request(email: &str) -> AccountRequest<'_> {
    AccountRequest {
        email,
        locale: Some("pt-BR"),
        address: Some("203.0.113.1"),
    }
}

/// The token in the link of the newest message, as the person's mailbox
/// would show it.
async fn newest_token(database: &TestDatabase) -> String {
    let link: String = sqlx::query_scalar(
        "SELECT variables->>'link' FROM notification.message
         WHERE variables ? 'link' ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .fetch_one(database.owner())
    .await
    .expect("a message with a link");
    link.split_once("#token=")
        .expect("token in the fragment")
        .1
        .to_owned()
}

impl World {
    async fn register(&self, database: &TestDatabase, email: &str) -> UserId {
        self.accounts
            .request_registration(&self.tenant, request(email), Caller::system())
            .await
            .expect("asked");
        self.accounts
            .complete_registration(
                &self.tenant,
                &newest_token(database).await,
                &Secret::from(PASSWORD.to_owned()),
                None,
                Caller::system(),
            )
            .await
            .expect("registered")
    }

    async fn verifies(&self, user: UserId, password: &str) -> bool {
        let check = self
            .credentials
            .verify_password(&self.tenant, Some(user), &Secret::from(password.to_owned()))
            .await
            .expect("verify");
        matches!(check, PasswordCheck::Verified { .. })
    }
}

fn lost_the_race(error: &DomainError) {
    assert_eq!(
        error.code(),
        "authentication.verification_token_invalid",
        "{error:?}"
    );
}

#[tokio::test]
async fn the_postgres_token_store_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_verification_token_contract(VerificationTokenPorts {
        units_of_work: database.app(),
        tokens: &PgVerificationTokenStore,
    })
    .await;
}

#[tokio::test]
async fn a_person_registers_and_recovers_and_no_token_is_stored_where_it_could_be_reused() {
    let database = TestDatabase::start().await;
    let world = world(&database).await;

    world
        .accounts
        .request_registration(&world.tenant, request("ana@example.com"), Caller::system())
        .await
        .expect("asked");
    let registration = newest_token(&database).await;
    let ana = world
        .accounts
        .complete_registration(
            &world.tenant,
            &registration,
            &Secret::from(PASSWORD.to_owned()),
            Some("Ana".to_owned()),
            Caller::system(),
        )
        .await
        .expect("registered");
    assert!(world.verifies(ana, PASSWORD).await);
    let user = world.identity.get(&world.tenant, ana).await.expect("user");
    assert!(user.may_sign_in());
    assert!(user.identifiers()[0].verified_at.is_some());

    world
        .accounts
        .request_recovery(&world.tenant, request("ana@example.com"), Caller::system())
        .await
        .expect("asked");
    let recovery = newest_token(&database).await;
    assert_ne!(recovery, registration);
    world
        .accounts
        .reset_password(
            &world.tenant,
            &recovery,
            &Secret::from("a different long passphrase".to_owned()),
            Caller::system(),
        )
        .await
        .expect("reset");
    assert!(world.verifies(ana, "a different long passphrase").await);
    assert!(!world.verifies(ana, PASSWORD).await);

    // Neither token is in the token table or in any event: only hashes
    // are kept, and events carry identifiers.
    let kept: String = sqlx::query_scalar(
        "SELECT (SELECT string_agg(to_jsonb(t)::text, '') FROM authentication.verification_token t)
             || (SELECT string_agg(to_jsonb(o)::text, '') FROM platform.outbox o)",
    )
    .fetch_one(database.owner())
    .await
    .expect("read");
    for secret in [&registration, &recovery] {
        assert!(!kept.contains(secret.as_str()), "{kept}");
    }
    assert!(!kept.contains(PASSWORD), "{kept}");
    for event in [
        "authentication.registration_completed",
        "authentication.recovery_requested",
        "authentication.password_reset",
    ] {
        assert!(kept.contains(event), "{event} was not announced");
    }

    // The request and the message stand or fall together: three messages
    // were queued with the three changes that caused them.
    let templates: Vec<String> =
        sqlx::query_scalar("SELECT template FROM notification.message ORDER BY created_at, id")
            .fetch_all(database.owner())
            .await
            .expect("read");
    assert_eq!(
        templates,
        [
            "email_verification",
            "password_recovery",
            "password_changed"
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_registration_link_used_many_times_at_once_creates_one_user() {
    let database = TestDatabase::start().await;
    let world = Arc::new(world(&database).await);
    world
        .accounts
        .request_registration(&world.tenant, request("ana@example.com"), Caller::system())
        .await
        .expect("asked");
    let token = newest_token(&database).await;

    let attempts: Vec<_> = (0..8)
        .map(|_| {
            let (world, token) = (Arc::clone(&world), token.clone());
            tokio::spawn(async move {
                world
                    .accounts
                    .complete_registration(
                        &world.tenant,
                        &token,
                        &Secret::from(PASSWORD.to_owned()),
                        None,
                        Caller::system(),
                    )
                    .await
            })
        })
        .collect();
    let mut registered = Vec::new();
    for attempt in attempts {
        match attempt.await.expect("task") {
            Ok(user) => registered.push(user),
            Err(error) => lost_the_race(&error),
        }
    }

    assert_eq!(registered.len(), 1, "exactly one request registers");
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM identity.user")
        .fetch_one(database.owner())
        .await
        .expect("count");
    assert_eq!(users, 1);
    assert!(world.verifies(registered[0], PASSWORD).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_recovery_link_used_many_times_at_once_sets_one_password() {
    let database = TestDatabase::start().await;
    let world = Arc::new(world(&database).await);
    let ana = world.register(&database, "ana@example.com").await;
    world
        .accounts
        .request_recovery(&world.tenant, request("ana@example.com"), Caller::system())
        .await
        .expect("asked");
    let token = newest_token(&database).await;

    // Eight requests, each choosing a different password.
    let attempts: Vec<_> = (0..8)
        .map(|index| {
            let (world, token) = (Arc::clone(&world), token.clone());
            let password = format!("a new passphrase number {index}");
            tokio::spawn(async move {
                let result = world
                    .accounts
                    .reset_password(
                        &world.tenant,
                        &token,
                        &Secret::from(password.clone()),
                        Caller::system(),
                    )
                    .await;
                (password, result)
            })
        })
        .collect();
    let mut winners = Vec::new();
    for attempt in attempts {
        match attempt.await.expect("task") {
            (password, Ok(_)) => winners.push(password),
            (_, Err(error)) => lost_the_race(&error),
        }
    }

    assert_eq!(winners.len(), 1, "exactly one request sets a password");
    assert!(world.verifies(ana, &winners[0]).await);
    assert!(!world.verifies(ana, PASSWORD).await);
    let changes: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM notification.message WHERE template = 'password_changed'",
    )
    .fetch_one(database.owner())
    .await
    .expect("count");
    assert_eq!(changes, 1, "and the owner is told once");
}

#[tokio::test]
async fn everything_that_happened_is_in_the_audit_log_and_no_secret_is() {
    use hodor_adapters_postgres::{OutboxDispatcher, PgAuditLog};
    use hodor_audit::api::{AuditHandler, AuditService};

    let database = TestDatabase::start().await;
    let world = world(&database).await;
    const CANARY: &str = "canary passphrase 7f3a9c";
    const SECOND_CANARY: &str = "second canary passphrase 51be0d";

    world
        .accounts
        .request_registration(
            &world.tenant,
            request("canary.person@example.com"),
            Caller::system(),
        )
        .await
        .expect("asked");
    let registration = newest_token(&database).await;
    world
        .accounts
        .complete_registration(
            &world.tenant,
            &registration,
            &Secret::from(CANARY.to_owned()),
            Some("Canary Person".to_owned()),
            Caller::system(),
        )
        .await
        .expect("registered");
    world
        .accounts
        .request_recovery(
            &world.tenant,
            request("canary.person@example.com"),
            Caller::system(),
        )
        .await
        .expect("asked");
    let recovery = newest_token(&database).await;
    world
        .accounts
        .reset_password(
            &world.tenant,
            &recovery,
            &Secret::from(SECOND_CANARY.to_owned()),
            Caller::system(),
        )
        .await
        .expect("reset");

    // The worker's part: every event becomes a record.
    let audit = AuditService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgAuditLog),
        Arc::new(Sha256Digest),
        Arc::new(SystemClock),
    );
    let dispatcher = OutboxDispatcher::new(
        database.platform().clone(),
        database.app().clone(),
        vec![Arc::new(AuditHandler::new(audit.clone()))],
    );
    while dispatcher
        .dispatch_batch(100)
        .await
        .expect("dispatch")
        .delivered
        > 0
    {}

    let verification = audit.verify(&world.tenant).await.expect("verify");
    assert!(verification.is_intact(), "{verification:?}");
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit.record WHERE tenant_id = $1 ORDER BY sequence",
    )
    .bind(world.tenant.tenant_id().as_uuid())
    .fetch_all(database.owner())
    .await
    .expect("read");
    assert_eq!(verification.records, actions.len() as u64);
    for expected in [
        "tenant.created",
        "identity.user_created",
        "identity.identifier_verified",
        "credential.password_set",
        "authentication.registration_completed",
        "authentication.recovery_requested",
        "authentication.password_reset",
    ] {
        assert!(
            actions.iter().any(|action| action == expected),
            "{expected} is missing from {actions:?}"
        );
    }

    // Nothing a person typed or was sent is in any record.
    let everything: String =
        sqlx::query_scalar("SELECT string_agg(to_jsonb(r)::text, '\n') FROM audit.record r")
            .fetch_one(database.owner())
            .await
            .expect("read");
    for secret in [
        CANARY,
        SECOND_CANARY,
        registration.as_str(),
        recovery.as_str(),
        "canary.person@example.com",
        "Canary Person",
    ] {
        assert!(
            !everything.contains(secret),
            "`{secret}` is in the audit log"
        );
    }
}
