//! Signing in by email on PostgreSQL: the store passes the contract, and a
//! code or a link presented many times at once signs in exactly once.

use hodor_adapters_crypto::{OsRandom, Sha256Digest};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgAttemptStore, PgEmailSignInStore, PgMessageQueue, PgSessionStore, PgTenantDirectory,
    PgTenantRepository, PgTransactionStore, PgUserRepository,
};
use hodor_authentication::api::{
    AttemptGuard, AuthFlow, AuthenticationService, EmailAuthenticator, EmailSignInPorts,
    ExternalInput, FlowEngine, IdentifierAuthenticator, SignIn, StepInput,
};
use hodor_authentication::testing::{EmailSignInPortsUnderTest, run_email_sign_in_contract};
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_kernel::{Caller, Secret, SystemClock, TenantContext, UserId};
use hodor_notification::api::Notifier;
use hodor_session::api::{ClientInfo, SessionService};
use hodor_tenant::api::{CreateTenant, TenantService};
use std::sync::Arc;

const ANA: &str = "ana@example.com";

struct World {
    database: TestDatabase,
    service: AuthenticationService,
    tenant: TenantContext,
    ana: UserId,
}

async fn world() -> World {
    let database = TestDatabase::start().await;
    let units = || Arc::new(database.app().clone());
    let clock = Arc::new(SystemClock);
    let digest = Arc::new(Sha256Digest);
    let random = Arc::new(OsRandom);
    let tenants = TenantService::new(
        units(),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.app().clone())),
        clock.clone(),
    );
    let identity = IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone());
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
    let ports = EmailSignInPorts {
        units_of_work: units(),
        sent: Arc::new(PgEmailSignInStore),
        identity: identity.clone(),
        tenants: tenants.clone(),
        notifier: Notifier::new(Arc::new(PgMessageQueue), clock.clone()),
        guard,
        digest: digest.clone(),
        random: random.clone(),
        clock: clock.clone(),
        public_url: "https://login.example.com".to_owned(),
    };
    let engine = FlowEngine::new()
        .with(Arc::new(IdentifierAuthenticator::new(
            identity.clone(),
            digest.clone(),
        )))
        .with(Arc::new(
            hodor_authentication::testing::TestSecondFactor::default(),
        ))
        .with(Arc::new(EmailAuthenticator::code(ports.clone())))
        .with(Arc::new(EmailAuthenticator::link(ports)));
    // The identifier alone is no flow; a stand-in step proves the factor
    // the built-in flow's password would.
    let flow = AuthFlow {
        steps: vec![
            AuthFlow::built_in().steps[0].clone(),
            hodor_authentication::api::FlowStep {
                key: hodor_authentication::testing::TestSecondFactor::KIND.to_owned(),
                authenticator: hodor_authentication::testing::TestSecondFactor::KIND.to_owned(),
                requirement: hodor_authentication::api::Requirement::Required,
                substitutes: Vec::new(),
            },
        ],
        ..AuthFlow::built_in()
    }
    .with_alternative(EmailAuthenticator::CODE_KIND, EmailAuthenticator::CODE_KIND)
    .with_alternative(EmailAuthenticator::LINK_KIND, EmailAuthenticator::LINK_KIND);
    let service = AuthenticationService::new(
        units(),
        Arc::new(PgTransactionStore),
        engine,
        flow,
        identity.clone(),
        sessions,
        tenants.clone(),
        digest,
        random,
        clock,
    )
    .expect("the flow is valid");

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
    let mut settings = created.snapshot().settings.clone();
    settings.authentication.email_sign_in.code = true;
    settings.authentication.email_sign_in.link = true;
    tenants
        .change_settings(&tenant, settings, Caller::system())
        .await
        .expect("settings");
    let ana = identity
        .create(
            &tenant,
            CreateUser {
                kind: UserKind::Human,
                identifiers: vec![(IdentifierKind::Email, ANA.to_owned())],
                profile: Profile::default(),
                confirmed: true,
            },
            Caller::system(),
        )
        .await
        .expect("user")
        .id();
    World {
        database,
        service,
        tenant,
        ana,
    }
}

impl World {
    /// Starts a sign-in, asks for `step` for Ana, and answers the sign-in's
    /// identifier and secret, and what the message carries.
    async fn asked(
        &self,
        step: &str,
        variable: &str,
    ) -> (hodor_authentication::api::TransactionId, String, String) {
        let started = self
            .service
            .start(
                &self.tenant,
                ClientInfo {
                    address: Some("203.0.113.1".to_owned()),
                    description: None,
                },
            )
            .await
            .expect("start");
        let secret = started.secret.expose().clone();
        self.service
            .challenge(
                &self.tenant,
                started.transaction_id,
                &secret,
                ExternalInput {
                    step: step.to_owned(),
                    fields: vec![("email".to_owned(), Secret::from(ANA.to_owned()))],
                },
            )
            .await
            .expect("asked");
        let sent: String = sqlx::query_scalar(
            "SELECT variables->>$2 FROM notification.message
             WHERE tenant_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1",
        )
        .bind(self.tenant.tenant_id().as_uuid())
        .bind(variable)
        .fetch_one(self.database.owner())
        .await
        .expect("a message");
        (started.transaction_id, secret, sent)
    }

    async fn sessions_of_ana(&self) -> i64 {
        sqlx::query_scalar(
            "SELECT count(*) FROM session.session WHERE tenant_id = $1 AND user_id = $2",
        )
        .bind(self.tenant.tenant_id().as_uuid())
        .bind(self.ana.as_uuid())
        .fetch_one(self.database.owner())
        .await
        .expect("count")
    }

    /// Presents the same input many times at once, and counts how many
    /// signed in; every other answer must be a refusal that changed
    /// nothing.
    async fn many_at_once(
        &self,
        id: hodor_authentication::api::TransactionId,
        secret: &str,
        input: impl Fn() -> StepInput,
    ) -> usize {
        let attempts: Vec<_> = (0..12)
            .map(|_| {
                let (service, tenant, secret, input) = (
                    self.service.clone(),
                    self.tenant.clone(),
                    secret.to_owned(),
                    input(),
                );
                tokio::spawn(async move { service.submit(&tenant, id, &secret, input).await })
            })
            .collect();
        let mut completed = 0;
        for attempt in attempts {
            match attempt.await.expect("task") {
                Ok(SignIn::Completed { session, .. }) => {
                    assert_eq!(session.user_id(), self.ana);
                    completed += 1;
                }
                Ok(other) => panic!("a refusal must change nothing: {other:?}"),
                Err(error) => assert!(
                    [
                        "authentication.transaction_modified_concurrently",
                        "authentication.transaction_not_active",
                        "authentication.too_many_attempts",
                    ]
                    .contains(&error.code()),
                    "{error:?}"
                ),
            }
        }
        completed
    }
}

fn external(step: &str, field: &str, value: &str) -> StepInput {
    StepInput::External(ExternalInput {
        step: step.to_owned(),
        fields: vec![(field.to_owned(), Secret::from(value.to_owned()))],
    })
}

#[tokio::test]
async fn the_postgres_store_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_email_sign_in_contract(EmailSignInPortsUnderTest {
        units_of_work: database.app(),
        sent: &PgEmailSignInStore,
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_same_code_presented_many_times_at_once_signs_in_once() {
    let world = world().await;
    let (id, secret, code) = world.asked("email_code", "code").await;
    let completed = world
        .many_at_once(id, &secret, || external("email_code", "code", &code))
        .await;
    assert_eq!(completed, 1, "exactly one of the twelve signs in");
    assert_eq!(world.sessions_of_ana().await, 1);
    let used: Option<hodor_kernel::Timestamp> = sqlx::query_scalar(
        "SELECT used_at FROM authentication.email_sign_in WHERE transaction_id = $1",
    )
    .bind(id.as_uuid())
    .fetch_one(world.database.owner())
    .await
    .expect("the row");
    assert!(used.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_same_link_opened_many_times_at_once_signs_in_once() {
    let world = world().await;
    let (id, secret, link) = world.asked("email_link", "link").await;
    let token = link.split_once("#token=").expect("token").1.to_owned();
    let completed = world
        .many_at_once(id, &secret, || external("email_link", "token", &token))
        .await;
    assert_eq!(completed, 1, "exactly one of the twelve signs in");
    assert_eq!(world.sessions_of_ana().await, 1);
}

#[tokio::test]
async fn only_hashes_are_stored() {
    let world = world().await;
    let (id, _, code) = world.asked("email_code", "code").await;
    let (hash, key): (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT secret_hash, identifier_key FROM authentication.email_sign_in
         WHERE transaction_id = $1",
    )
    .bind(id.as_uuid())
    .fetch_one(world.database.owner())
    .await
    .expect("the row");
    use hodor_kernel::Digest as _;
    assert_eq!(hash, Sha256Digest.sha256(code.as_bytes()).to_vec());
    assert_eq!(key, Sha256Digest.sha256(b"email:ana@example.com").to_vec());
    let row: String = sqlx::query_scalar(
        "SELECT row_to_json(e)::text FROM authentication.email_sign_in e WHERE transaction_id = $1",
    )
    .bind(id.as_uuid())
    .fetch_one(world.database.owner())
    .await
    .expect("the row");
    assert!(!row.contains(ANA), "no address is stored: {row}");
}
