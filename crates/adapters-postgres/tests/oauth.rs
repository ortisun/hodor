//! The stores of the OAuth context on PostgreSQL.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgApplicationStore, PgAuthorizationCodeStore, PgAuthorizationRequestStore,
    PgClientAssertionStore, PgClientStore, PgGrantStore, PgResourceServerStore,
};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::{Caller, TenantContext, TenantId, Timestamp};
use hodor_oauth::api::ClientAssertionStore;
use hodor_oauth::api::{
    ApplicationPorts, ApplicationService, ApplicationSettings, ClientSettings, ClientType,
    CreateClient, GrantType, RotateSecret,
};
use hodor_oauth::testing::{
    AssertionStorePorts, AuthorizationStorePorts, DistinctRandom, Ports, run_assertion_contract,
    run_authorization_contract, run_contract,
};
use std::sync::Arc;
use time::Duration;

#[tokio::test]
async fn the_postgres_stores_pass_the_contract() {
    let database = TestDatabase::start().await;
    run_contract(Ports {
        units_of_work: database.app(),
        applications: &PgApplicationStore,
        clients: &PgClientStore,
        resource_servers: &PgResourceServerStore,
    })
    .await;
}

#[tokio::test]
async fn the_postgres_authorization_stores_pass_the_contract() {
    let database = TestDatabase::start().await;
    run_authorization_contract(AuthorizationStorePorts {
        units_of_work: database.app(),
        applications: &PgApplicationStore,
        clients: &PgClientStore,
        requests: &PgAuthorizationRequestStore,
        grants: &PgGrantStore,
        codes: &PgAuthorizationCodeStore,
    })
    .await;
}

#[tokio::test]
async fn the_postgres_assertion_store_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_assertion_contract(AssertionStorePorts {
        units_of_work: database.app(),
        applications: &PgApplicationStore,
        clients: &PgClientStore,
        assertions: &PgClientAssertionStore,
    })
    .await;
}

#[tokio::test]
async fn of_two_requests_with_one_assertion_exactly_one_goes_on() {
    let database = TestDatabase::start().await;
    let now = Timestamp::UNIX_EPOCH + Duration::days(20_000);
    let service = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(database.app().clone()),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: Arc::new(FixedClock::at(now)),
    });
    let tenant = TenantContext::assume(TenantId::generate());
    let application = service
        .create_application(
            &tenant,
            ApplicationSettings {
                name: "Payroll".to_owned(),
                first_party: true,
            },
            Caller::system(),
        )
        .await
        .expect("application");
    let (client, _) = service
        .create_client(
            &tenant,
            CreateClient {
                application_id: application.id(),
                client_type: ClientType::Public,
                settings: ClientSettings::new(
                    "Payroll mobile",
                    ClientType::Public,
                    vec![GrantType::AuthorizationCode],
                    vec!["com.example.payroll:/callback".to_owned()],
                ),
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client");
    let remember = || async {
        let mut uow = hodor_kernel::UnitOfWorkFactory::begin(database.app(), &tenant)
            .await
            .expect("begin");
        let first = PgClientAssertionStore
            .remember(
                uow.as_mut(),
                client.id(),
                "the-same",
                now + Duration::minutes(5),
            )
            .await
            .expect("remember");
        uow.commit().await.expect("commit");
        first
    };
    let (one, two) = tokio::join!(remember(), remember());
    assert!(one ^ two, "exactly one is the first: {one} {two}");
}

#[tokio::test]
async fn a_client_and_its_rotated_secret_work_end_to_end_on_postgres() {
    let database = TestDatabase::start().await;
    let now = Timestamp::UNIX_EPOCH + Duration::days(20_000);
    let clock = Arc::new(FixedClock::at(now));
    let service = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(database.app().clone()),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    let tenant = TenantContext::assume(TenantId::generate());
    let application = service
        .create_application(
            &tenant,
            ApplicationSettings {
                name: "Payroll".to_owned(),
                first_party: true,
            },
            Caller::system(),
        )
        .await
        .expect("created");
    let (client, first) = service
        .create_client(
            &tenant,
            CreateClient {
                application_id: application.id(),
                client_type: ClientType::Confidential,
                settings: ClientSettings::new(
                    "Payroll web",
                    ClientType::Confidential,
                    vec![GrantType::AuthorizationCode],
                    vec!["https://payroll.example.com/callback".to_owned()],
                ),
                secret_lifetime: Some(Duration::days(90)),
            },
            Caller::system(),
        )
        .await
        .expect("created");
    let first = first.expect("secret");
    clock.advance(Duration::days(1));
    let second = service
        .rotate_client_secret(
            &tenant,
            client.id(),
            RotateSecret {
                lifetime: Duration::days(90),
                keep_previous_for: Duration::hours(1),
            },
            Caller::system(),
        )
        .await
        .expect("rotated");
    let stored = service.client(&tenant, client.id()).await.expect("stored");
    let today = now + Duration::days(1);
    assert!(stored.accepts_secret(first.expose(), &FakeDigest, today));
    assert!(stored.accepts_secret(second.expose(), &FakeDigest, today));
    assert!(!stored.accepts_secret(first.expose(), &FakeDigest, today + Duration::hours(1)));

    // The table holds hashes only, and the outbox no trace of a secret.
    let rows: Vec<(Vec<u8>,)> =
        sqlx::query_as("SELECT secret_hash FROM oauth.client_secret WHERE client_id = $1")
            .bind(client.id().as_uuid())
            .fetch_all(database.owner())
            .await
            .expect("secrets");
    assert_eq!(rows.len(), 2);
    let payloads: Vec<(String,)> = sqlx::query_as("SELECT payload::text FROM platform.outbox")
        .fetch_all(database.owner())
        .await
        .expect("outbox");
    for (payload,) in payloads {
        assert!(!payload.contains(&first.expose()[9..]), "{payload}");
        assert!(!payload.contains(&second.expose()[9..]), "{payload}");
    }
}

#[tokio::test]
async fn the_database_refuses_a_public_client_with_a_method_or_without_pkce() {
    let database = TestDatabase::start().await;
    let tenant = sqlx::types::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO oauth.application VALUES ($1, $1, 'Payroll', false, 'enabled', now(), now(), 0)",
    )
    .bind(tenant)
    .execute(database.owner())
    .await
    .expect("application");
    for (method, pkce) in [("client_secret_basic", true), ("none", false)] {
        let refused = sqlx::query(
            "INSERT INTO oauth.client VALUES ($1, gen_random_uuid(), $1, 'Mobile', 'public', $2,
                 ARRAY['authorization_code'], ARRAY['com.example.app:/callback'], ARRAY[]::text[],
                 $3, 300, 300, 2592000, 604800, 'enabled', now(), now(), 0)",
        )
        .bind(tenant)
        .bind(method)
        .bind(pkce)
        .execute(database.owner())
        .await;
        assert!(refused.is_err(), "{method} {pkce}");
    }
    let private_key = sqlx::query(
        "INSERT INTO oauth.client VALUES ($1, $1, $1, 'Server', 'confidential', 'private_key_jwt',
             ARRAY['client_credentials'], ARRAY[]::text[], ARRAY[]::text[],
             true, 300, 300, 2592000, 604800, 'enabled', now(), now(), 0)",
    )
    .bind(tenant)
    .execute(database.owner())
    .await;
    assert!(private_key.is_ok(), "{private_key:?}");
    let leaked = sqlx::query(
        "INSERT INTO oauth.client_key VALUES ($1, $1, 'leak', '{\"kty\":\"OKP\",\"d\":\"x\"}', 0, now())",
    )
    .bind(tenant)
    .execute(database.owner())
    .await;
    assert!(
        leaked.is_err(),
        "a private key is refused by the database too"
    );
}

#[tokio::test]
async fn of_two_redemptions_at_the_same_moment_one_wins_and_the_grant_is_revoked() {
    use hodor_kernel::UserId;
    use hodor_oauth::api::{
        AuthorizationCodePorts, AuthorizationCodeService, AuthorizationParameters,
        CodePresentation, GrantStatus, GrantStore as _, SignedInPerson, s256_challenge,
    };
    use hodor_session::api::SessionId;

    let database = TestDatabase::start().await;
    let now = Timestamp::UNIX_EPOCH + Duration::days(20_000);
    let clock = Arc::new(FixedClock::at(now));
    let units = Arc::new(database.app().clone());
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: units.clone(),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    let service = AuthorizationCodeService::new(AuthorizationCodePorts {
        units_of_work: units.clone(),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        requests: Arc::new(PgAuthorizationRequestStore),
        grants: Arc::new(PgGrantStore),
        codes: Arc::new(PgAuthorizationCodeStore),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    let tenant = TenantContext::assume(TenantId::generate());
    let application = applications
        .create_application(
            &tenant,
            ApplicationSettings {
                name: "Payroll".to_owned(),
                first_party: true,
            },
            Caller::system(),
        )
        .await
        .expect("application");
    let mut settings = ClientSettings::new(
        "Payroll mobile",
        ClientType::Public,
        vec![GrantType::AuthorizationCode],
        vec!["com.example.payroll:/callback".to_owned()],
    );
    settings.allowed_scopes = vec!["openid".to_owned()];
    let (client, _) = applications
        .create_client(
            &tenant,
            CreateClient {
                application_id: application.id(),
                client_type: ClientType::Public,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client");
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let parameters = AuthorizationParameters::from_pairs(
        [
            ("response_type", "code".to_owned()),
            ("client_id", client.id().to_string()),
            ("redirect_uri", "com.example.payroll:/callback".to_owned()),
            ("scope", "openid".to_owned()),
            ("code_challenge", s256_challenge(verifier, &FakeDigest)),
            ("code_challenge_method", "S256".to_owned()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v)),
    );
    let request = service
        .check(&tenant, &parameters)
        .await
        .expect("storage")
        .expect("accepted");
    let code = service
        .issue_code(
            &tenant,
            &request,
            &SignedInPerson {
                user_id: UserId::generate(),
                session_id: SessionId::generate(),
                signed_in_at: now,
                methods: vec!["password".to_owned()],
            },
            Caller::system(),
        )
        .await
        .expect("issued");
    let presentation = CodePresentation {
        client_id: client.id(),
        redirect_uri: Some("com.example.payroll:/callback"),
        verifier: Some(verifier),
    };
    let (first, second) = tokio::join!(
        service.redeem_code(&tenant, code.expose(), presentation, Caller::system()),
        service.redeem_code(&tenant, code.expose(), presentation, Caller::system()),
    );
    let (won, lost) = match (first, second) {
        (Ok(won), Err(lost)) | (Err(lost), Ok(won)) => (won, lost),
        (first, second) => panic!("exactly one should win: {first:?} {second:?}"),
    };
    assert_eq!(lost.detail(), Some("already_redeemed"));

    let mut uow = hodor_kernel::UnitOfWorkFactory::begin(database.app(), &tenant)
        .await
        .expect("begin");
    let grant = PgGrantStore
        .get(uow.as_mut(), won.code.grant_id)
        .await
        .expect("get")
        .expect("found");
    assert_eq!(grant.status, GrantStatus::Revoked);

    // The code is in the database only as its hash.
    let everything: String = sqlx::query_scalar(
        "SELECT string_agg(to_jsonb(t)::text, '') FROM oauth.authorization_code t",
    )
    .fetch_one(database.owner())
    .await
    .expect("dump");
    assert!(!everything.contains(code.expose()));
}
