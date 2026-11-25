//! The stores of the OAuth context on PostgreSQL.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgApplicationStore, PgAuthorizationCodeStore, PgAuthorizationRequestStore, PgClaimMapperStore,
    PgClientAssertionStore, PgClientStore, PgConsentStore, PgGrantStore, PgRefreshTokenStore,
    PgResourceServerStore,
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
    AssertionStorePorts, AuthorizationStorePorts, ClaimMapperStorePorts, ConsentStorePorts,
    DistinctRandom, MembershipsOf, Ports, RefreshStorePorts, run_assertion_contract,
    run_authorization_contract, run_claim_mapper_contract, run_consent_contract, run_contract,
    run_refresh_token_contract,
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
async fn the_postgres_claim_mapper_store_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_claim_mapper_contract(ClaimMapperStorePorts {
        units_of_work: database.app(),
        applications: &PgApplicationStore,
        clients: &PgClientStore,
        mappers: &PgClaimMapperStore,
    })
    .await;
}

#[tokio::test]
async fn the_database_keeps_claim_mappers_to_their_shape() {
    let database = TestDatabase::start().await;
    let tenant = sqlx::types::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO oauth.application VALUES ($1, $1, 'Billing', false, 'enabled', now(), now(), 0)",
    )
    .bind(tenant)
    .execute(database.owner())
    .await
    .expect("application");
    sqlx::query(
        "INSERT INTO oauth.client VALUES ($1, $1, $1, 'Web', 'public', 'none',
             ARRAY['authorization_code'], ARRAY['https://billing.example.com/callback'],
             ARRAY[]::text[], true, 300, 300, 2592000, 604800, 'enabled', now(), now(), 0)",
    )
    .bind(tenant)
    .execute(database.owner())
    .await
    .expect("client");
    let insert = "INSERT INTO oauth.claim_mapper
                      (tenant_id, id, client_id, claim, claim_normalized, targets, scope, source,
                       created_at, updated_at)
                  VALUES ($1, gen_random_uuid(), $1, $2, $3, $4, NULL, $5::jsonb, now(), now())";
    sqlx::query(insert)
        .bind(tenant)
        .bind("Team")
        .bind("team")
        .bind(vec!["id_token"])
        .bind(r#"{"kind": "groups"}"#)
        .execute(database.owner())
        .await
        .expect("a mapper that keeps every rule");
    let long = format!(r#"{{"kind": "constant", "value": "{}"}}"#, "x".repeat(2100));
    for (case, claim, normalized, targets, source) in [
        (
            "one mapper per claim, without regard to case",
            "TEAM",
            "team",
            vec!["userinfo"],
            r#"{"kind": "groups"}"#,
        ),
        (
            "the normalized claim is the lowercase",
            "Plan",
            "Plan",
            vec!["userinfo"],
            r#"{"kind": "groups"}"#,
        ),
        (
            "an empty claim",
            "",
            "",
            vec!["userinfo"],
            r#"{"kind": "groups"}"#,
        ),
        ("no target", "plan", "plan", vec![], r#"{"kind": "groups"}"#),
        (
            "an unknown target",
            "plan",
            "plan",
            vec!["logout_token"],
            r#"{"kind": "groups"}"#,
        ),
        (
            "an unknown kind",
            "plan",
            "plan",
            vec!["userinfo"],
            r#"{"kind": "roles"}"#,
        ),
        (
            "a constant that is null",
            "plan",
            "plan",
            vec!["userinfo"],
            r#"{"kind": "constant", "value": null}"#,
        ),
        (
            "a constant too large",
            "plan",
            "plan",
            vec!["userinfo"],
            long.as_str(),
        ),
    ] {
        let refused = sqlx::query(insert)
            .bind(tenant)
            .bind(claim)
            .bind(normalized)
            .bind(targets)
            .bind(source)
            .execute(database.owner())
            .await;
        assert!(refused.is_err(), "{case}");
    }
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
async fn the_postgres_consent_store_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_consent_contract(ConsentStorePorts {
        units_of_work: database.app(),
        applications: &PgApplicationStore,
        clients: &PgClientStore,
        consents: &PgConsentStore,
    })
    .await;
}

#[tokio::test]
async fn the_database_keeps_consent_to_its_rules_and_its_history_unchanged() {
    let database = TestDatabase::start().await;
    let tenant = sqlx::types::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO oauth.application VALUES ($1, $1, 'Billing', false, 'enabled', now(), now(), 0)",
    )
    .bind(tenant)
    .execute(database.owner())
    .await
    .expect("application");
    sqlx::query(
        "INSERT INTO oauth.client VALUES ($1, $1, $1, 'Web', 'public', 'none',
             ARRAY['authorization_code'], ARRAY['https://billing.example.com/callback'],
             ARRAY[]::text[], true, 300, 300, 2592000, 604800, 'enabled', now(), now(), 0)",
    )
    .bind(tenant)
    .execute(database.owner())
    .await
    .expect("client");
    for (case, statement) in [
        (
            "offline access is never kept",
            "INSERT INTO oauth.consent VALUES ($1, gen_random_uuid(), $1,
                 ARRAY['openid', 'offline_access'], ARRAY[]::text[], now(),
                 now() + interval '1 day', NULL, NULL)",
        ),
        (
            "a consent lasts at most 730 days",
            "INSERT INTO oauth.consent VALUES ($1, gen_random_uuid(), $1, ARRAY['openid'],
                 ARRAY[]::text[], now(), now() + interval '731 days', NULL, NULL)",
        ),
        (
            "a withdrawal says who withdrew it",
            "INSERT INTO oauth.consent VALUES ($1, gen_random_uuid(), $1, ARRAY['openid'],
                 ARRAY[]::text[], now(), now() + interval '1 day', now(), 'someone')",
        ),
        (
            "a withdrawal says when",
            "INSERT INTO oauth.consent VALUES ($1, gen_random_uuid(), $1, ARRAY['openid'],
                 ARRAY[]::text[], now(), now() + interval '1 day', NULL, 'person')",
        ),
    ] {
        let refused = sqlx::query(statement)
            .bind(tenant)
            .execute(database.owner())
            .await;
        assert!(refused.is_err(), "{case}");
    }
    let refused = sqlx::query("UPDATE oauth.client SET consent_seconds = 3600 WHERE id = $1")
        .bind(tenant)
        .execute(database.owner())
        .await;
    assert!(refused.is_err(), "a consent lasts at least a day");

    sqlx::query(
        "INSERT INTO oauth.consent_history VALUES ($1, gen_random_uuid(), gen_random_uuid(), $1,
             'given', ARRAY['openid'], ARRAY[]::text[], 'person', now())",
    )
    .bind(tenant)
    .execute(database.owner())
    .await
    .expect("history");
    let context = TenantContext::assume(TenantId::from_uuid(tenant));
    for statement in [
        "UPDATE oauth.consent_history SET action = 'refused'",
        "DELETE FROM oauth.consent_history",
    ] {
        let mut tx = database.app().begin(&context).await.expect("begin");
        let refused = sqlx::query(statement).execute(tx.connection()).await;
        assert!(refused.is_err(), "the application cannot run: {statement}");
    }
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
async fn the_postgres_refresh_token_store_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_refresh_token_contract(RefreshStorePorts {
        units_of_work: database.app(),
        applications: &PgApplicationStore,
        clients: &PgClientStore,
        grants: &PgGrantStore,
        refresh_tokens: &PgRefreshTokenStore,
    })
    .await;
}

#[tokio::test]
async fn of_two_moves_of_one_family_at_the_same_moment_exactly_one_moves_it() {
    use hodor_kernel::{SealedSecret, UnitOfWorkFactory, UserId};
    use hodor_oauth::api::{
        AuthorizationCode, CodeHash, Grant, GrantId, GrantStatus, GrantStore as _, RefreshAsk,
        RefreshFamily, RefreshTokenHash, RefreshTokenStore as _, TokenPolicy,
    };
    use hodor_session::api::SessionId;

    let database = TestDatabase::start().await;
    let now = Timestamp::UNIX_EPOCH + Duration::days(20_000);
    let clock = Arc::new(FixedClock::at(now));
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(database.app().clone()),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock,
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
    let (client, _) = applications
        .create_client(
            &tenant,
            CreateClient {
                application_id: application.id(),
                client_type: ClientType::Public,
                settings: ClientSettings::new(
                    "Payroll mobile",
                    ClientType::Public,
                    vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
                    vec!["com.example.payroll:/callback".to_owned()],
                ),
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client");
    let grant = Grant {
        id: GrantId::generate(),
        client_id: client.id(),
        user_id: UserId::generate(),
        session_id: SessionId::generate(),
        scopes: vec!["openid".to_owned()],
        audiences: Vec::new(),
        organization: None,
        status: GrantStatus::Active,
        created_at: now,
        revoked_at: None,
        revocation_reason: None,
    };
    let code = AuthorizationCode {
        hash: CodeHash::from_stored([1; 32]),
        grant_id: grant.id,
        client_id: client.id(),
        redirect_uri: "com.example.payroll:/callback".to_owned(),
        scopes: grant.scopes.clone(),
        audiences: Vec::new(),
        code_challenge: None,
        nonce: None,
        session_id: grant.session_id,
        user_id: grant.user_id,
        signed_in_at: now,
        methods: vec!["password".to_owned()],
        acr: Some("urn:hodor:acr:mfa".to_owned()),
        issued_at: now,
        expires_at: now + Duration::seconds(60),
        redeemed_at: Some(now),
    };
    let (family, _) = RefreshFamily::start(
        &code,
        &TokenPolicy::default(),
        SealedSecret::from_stored(vec![2; 48]),
        now,
        &DistinctRandom,
        &FakeDigest,
    );
    let mut uow = UnitOfWorkFactory::begin(database.app(), &tenant)
        .await
        .expect("begin");
    PgGrantStore
        .insert(uow.as_mut(), &grant)
        .await
        .expect("grant");
    PgRefreshTokenStore
        .start(uow.as_mut(), &family)
        .await
        .expect("family");
    uow.commit().await.expect("commit");

    let move_to = |byte: u8| {
        let tenant = tenant.clone();
        let database = database.app().clone();
        async move {
            let mut uow = UnitOfWorkFactory::begin(&database, &tenant)
                .await
                .expect("begin");
            let moved = PgRefreshTokenStore
                .advance(
                    uow.as_mut(),
                    family.id,
                    1,
                    &RefreshTokenHash::from_stored([byte; 32]),
                    &RefreshAsk::default(),
                    now + Duration::minutes(1),
                )
                .await
                .expect("advance");
            uow.commit().await.expect("commit");
            moved
        }
    };
    let (one, two) = tokio::join!(move_to(3), move_to(4));
    assert!(one ^ two, "exactly one moves the family: {one} {two}");

    let mut uow = UnitOfWorkFactory::begin(database.app(), &tenant)
        .await
        .expect("begin");
    let (_, newest) = PgRefreshTokenStore
        .find(
            uow.as_mut(),
            &RefreshTokenHash::from_stored(if one { [3; 32] } else { [4; 32] }),
        )
        .await
        .expect("find")
        .expect("the winner's token");
    assert_eq!(newest.generation, 2);
    assert!(
        PgRefreshTokenStore
            .find(
                uow.as_mut(),
                &RefreshTokenHash::from_stored(if one { [4; 32] } else { [3; 32] }),
            )
            .await
            .expect("find")
            .is_none(),
        "the loser left no token"
    );
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
        memberships: Arc::new(MembershipsOf::default()),
        verifier: Arc::new(hodor_oauth::testing::FakeVerifier),
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
        .check(&tenant, "https://hodor.example.com/t/acme", &parameters)
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
                acr: Some("urn:hodor:acr:single-factor".to_owned()),
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

#[tokio::test]
async fn the_postgres_access_token_register_passes_the_contract() {
    use hodor_adapters_postgres::PgAccessTokenRecordStore;
    use hodor_oauth::testing::{AccessTokenRecordStorePorts, run_access_token_record_contract};

    let database = TestDatabase::start().await;
    run_access_token_record_contract(AccessTokenRecordStorePorts {
        units_of_work: database.app(),
        applications: &PgApplicationStore,
        clients: &PgClientStore,
        access_tokens: &PgAccessTokenRecordStore,
    })
    .await;
}

/// A tenant with one public client, made through the application service.
async fn a_tenant_with_a_client(
    database: &TestDatabase,
    now: Timestamp,
) -> (TenantContext, hodor_oauth::api::ClientId) {
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(database.app().clone()),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: Arc::new(FixedClock::at(now)),
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
    let (client, _) = applications
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
    (tenant, client.id())
}

#[tokio::test]
async fn a_record_references_its_grant_and_two_revocations_revoke_once() {
    use hodor_adapters_postgres::PgAccessTokenRecordStore;
    use hodor_kernel::UnitOfWorkFactory;
    use hodor_oauth::api::{AccessTokenRecord, AccessTokenRecordStore as _, GrantId};

    let database = TestDatabase::start().await;
    let now = Timestamp::UNIX_EPOCH + Duration::days(20_000);
    let (tenant, client) = a_tenant_with_a_client(&database, now).await;

    let mut uow = UnitOfWorkFactory::begin(database.app(), &tenant)
        .await
        .expect("begin");
    let error = PgAccessTokenRecordStore
        .record(
            uow.as_mut(),
            &AccessTokenRecord::issued(
                "jti-of-no-grant".to_owned(),
                client,
                Some(GrantId::generate()),
                None,
                now + Duration::minutes(5),
            ),
        )
        .await
        .expect_err("an unknown grant");
    assert_eq!(error.code(), "oauth.grant_not_found");
    drop(uow);

    let mut uow = UnitOfWorkFactory::begin(database.app(), &tenant)
        .await
        .expect("begin");
    PgAccessTokenRecordStore
        .record(
            uow.as_mut(),
            &AccessTokenRecord::issued(
                "jti-raced".to_owned(),
                client,
                None,
                None,
                now + Duration::minutes(5),
            ),
        )
        .await
        .expect("record");
    uow.commit().await.expect("commit");

    let revoke = || {
        let tenant = tenant.clone();
        let database = database.app().clone();
        async move {
            let mut uow = UnitOfWorkFactory::begin(&database, &tenant)
                .await
                .expect("begin");
            let revoked = PgAccessTokenRecordStore
                .revoke(uow.as_mut(), client, "jti-raced", now, "revoked_by_client")
                .await
                .expect("revoke");
            uow.commit().await.expect("commit");
            revoked
        }
    };
    let (one, two) = tokio::join!(revoke(), revoke());
    assert!(one ^ two, "exactly one revokes the record: {one} {two}");
}

#[tokio::test]
async fn expired_access_token_records_are_removed_in_every_tenant_and_no_other_is() {
    use hodor_adapters_postgres::{AccessTokenCleanup, PgAccessTokenRecordStore};
    use hodor_kernel::UnitOfWorkFactory;
    use hodor_oauth::api::{AccessTokenRecord, AccessTokenRecordStore as _};

    let database = TestDatabase::start().await;
    let now = Timestamp::now_utc();
    let mut kept = Vec::new();
    for _ in 0..2 {
        let (tenant, client) = a_tenant_with_a_client(&database, now).await;
        let mut uow = UnitOfWorkFactory::begin(database.app(), &tenant)
            .await
            .expect("begin");
        // Three that expired, one that has not.
        for (index, expires_at) in [
            now - Duration::minutes(30),
            now - Duration::minutes(1),
            now,
            now + Duration::minutes(5),
        ]
        .into_iter()
        .enumerate()
        {
            let token_id = format!("jti-{index}");
            PgAccessTokenRecordStore
                .record(
                    uow.as_mut(),
                    &AccessTokenRecord::issued(token_id.clone(), client, None, None, expires_at),
                )
                .await
                .expect("record");
            if expires_at > now {
                kept.push((tenant.clone(), token_id));
            }
        }
        uow.commit().await.expect("commit");
    }

    let cleanup = AccessTokenCleanup::new(database.platform().clone(), database.app().clone());
    // A batch of two in each tenant, then the rest.
    let first = cleanup.run(now, 2).await.expect("cleanup");
    assert_eq!((first.tenants, first.removed), (2, 4));
    let second = cleanup.run(now, 2).await.expect("cleanup");
    assert_eq!((second.tenants, second.removed), (2, 2));
    let third = cleanup.run(now, 2).await.expect("cleanup");
    assert_eq!(
        (third.tenants, third.removed),
        (0, 0),
        "nothing expired is left"
    );
    for (tenant, token_id) in kept {
        let mut uow = UnitOfWorkFactory::begin(database.app(), &tenant)
            .await
            .expect("begin");
        assert!(
            PgAccessTokenRecordStore
                .find(uow.as_mut(), &token_id)
                .await
                .expect("find")
                .is_some(),
            "a record of a token still in its lifetime stays"
        );
    }
}

#[tokio::test]
async fn the_postgres_pairwise_secret_store_passes_the_contract() {
    use hodor_adapters_postgres::PgPairwiseSecretStore;
    use hodor_oauth::testing::{PairwiseSecretStorePorts, run_pairwise_secret_contract};
    let database = TestDatabase::start().await;
    run_pairwise_secret_contract(PairwiseSecretStorePorts {
        units_of_work: database.app(),
        secrets: &PgPairwiseSecretStore,
    })
    .await;
}

#[tokio::test]
async fn of_many_first_needs_of_a_pairwise_secret_at_once_one_is_kept() {
    use hodor_adapters_postgres::PgPairwiseSecretStore;
    use hodor_oauth::api::SubjectType;
    use hodor_oauth::testing::pairwise_subjects;
    let database = TestDatabase::start().await;
    let tenant = TenantContext::assume(TenantId::generate());
    let pairwise = pairwise_subjects(
        Arc::new(database.app().clone()),
        Arc::new(PgPairwiseSecretStore),
    );
    let mut settings = ClientSettings::new(
        "Payroll web",
        ClientType::Confidential,
        vec![GrantType::AuthorizationCode],
        vec!["https://payroll.example.com/callback".to_owned()],
    );
    settings.subject_type = SubjectType::Pairwise;
    let client = hodor_oauth::api::Client::create(
        hodor_oauth::api::ApplicationId::generate(),
        ClientType::Confidential,
        settings,
        hodor_oauth::api::ClientSecret::DEFAULT_LIFETIME,
        Timestamp::UNIX_EPOCH,
        &DistinctRandom,
        &FakeDigest,
    )
    .expect("client")
    .0;
    let person = hodor_kernel::UserId::generate();
    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let pairwise = pairwise.clone();
            let tenant = tenant.clone();
            let client = client.clone();
            tokio::spawn(async move { pairwise.subject(&tenant, &client, person).await })
        })
        .collect();
    let mut subjects = Vec::new();
    for task in tasks {
        subjects.push(task.await.expect("joined").expect("subject"));
    }
    subjects.dedup();
    assert_eq!(subjects.len(), 1, "every server used the one secret kept");
    let kept: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oauth.pairwise_secret WHERE tenant_id = $1")
            .bind(tenant.tenant_id().as_uuid())
            .fetch_one(database.owner())
            .await
            .expect("count");
    assert_eq!(kept, 1);
}

#[tokio::test]
async fn the_database_keeps_request_object_algorithms_to_those_named() {
    let database = TestDatabase::start().await;
    let tenant = sqlx::types::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO oauth.application VALUES ($1, $1, 'Billing', false, 'enabled', now(), now(), 0)",
    )
    .bind(tenant)
    .execute(database.owner())
    .await
    .expect("application");
    let insert = |algorithm: Option<&str>| {
        sqlx::query(
            "INSERT INTO oauth.client (tenant_id, id, application_id, name, client_type,
                 authentication_method, grant_types, redirect_uris, allowed_scopes, require_pkce,
                 access_token_seconds, id_token_seconds, refresh_token_seconds,
                 refresh_idle_seconds, status, created_at, updated_at, version,
                 request_object_signing_alg)
             VALUES ($1, gen_random_uuid(), $1, 'Web', 'confidential', 'client_secret_basic',
                 ARRAY['authorization_code'], ARRAY['https://billing.example.com/callback'],
                 ARRAY[]::text[], true, 300, 300, 2592000, 604800, 'enabled', now(), now(), 0, $2)",
        )
        .bind(tenant)
        .bind(algorithm.map(str::to_owned))
        .execute(database.owner())
    };
    for accepted in [
        None,
        Some("ES256"),
        Some("RS256"),
        Some("PS256"),
        Some("none"),
    ] {
        insert(accepted)
            .await
            .expect("a known algorithm, or none chosen");
    }
    for refused in ["HS256", "None", "es256", ""] {
        assert!(insert(Some(refused)).await.is_err(), "{refused}");
    }
}

#[tokio::test]
async fn the_database_keeps_subject_types_and_sector_addresses_to_their_rules() {
    let database = TestDatabase::start().await;
    let tenant = sqlx::types::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO oauth.application VALUES ($1, $1, 'Billing', false, 'enabled', now(), now(), 0)",
    )
    .bind(tenant)
    .execute(database.owner())
    .await
    .expect("application");
    let insert = |grants: &str, subject_type: &str, sector: &str| {
        format!(
            "INSERT INTO oauth.client (tenant_id, id, application_id, name, client_type,
                 authentication_method, grant_types, redirect_uris, allowed_scopes, require_pkce,
                 access_token_seconds, id_token_seconds, refresh_token_seconds,
                 refresh_idle_seconds, status, created_at, updated_at, version, subject_type,
                 sector_identifier_uri)
             VALUES ($1, gen_random_uuid(), $1, 'Web', 'confidential', 'client_secret_basic',
                 {grants}, ARRAY['https://billing.example.com/callback'], ARRAY[]::text[], true,
                 300, 300, 2592000, 604800, 'enabled', now(), now(), 0, '{subject_type}', {sector})"
        )
    };
    let code = "ARRAY['authorization_code']";
    // Every piece of the statement is a constant of this test.
    sqlx::query(sqlx::AssertSqlSafe(insert(
        code,
        "pairwise",
        "'https://sector.example.org/uris.json'",
    )))
    .bind(tenant)
    .execute(database.owner())
    .await
    .expect("a pairwise client with an address");
    for (case, statement) in [
        ("an unknown subject type", insert(code, "secret", "NULL")),
        (
            "pairwise without a code",
            insert("ARRAY['client_credentials']", "pairwise", "NULL"),
        ),
        (
            "an address on a public client",
            insert(code, "public", "'https://sector.example.org/uris.json'"),
        ),
        (
            "an address that is not HTTPS",
            insert(code, "pairwise", "'ftp://sector.example.org/uris.json'"),
        ),
    ] {
        let refused = sqlx::query(sqlx::AssertSqlSafe(statement))
            .bind(tenant)
            .execute(database.owner())
            .await;
        assert!(refused.is_err(), "{case}");
    }
    let secret = "INSERT INTO oauth.pairwise_secret VALUES ($1, gen_random_uuid(), '\\x01', now())";
    sqlx::query(secret)
        .bind(tenant)
        .execute(database.owner())
        .await
        .expect("the first secret");
    assert!(
        sqlx::query(secret)
            .bind(tenant)
            .execute(database.owner())
            .await
            .is_err(),
        "a tenant has one secret"
    );
}

#[tokio::test]
async fn the_database_keeps_spiffe_identifiers_to_their_rules() {
    let database = TestDatabase::start().await;
    let tenant = sqlx::types::Uuid::now_v7();
    let twin = sqlx::types::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO oauth.application VALUES ($1, $1, 'Exports', false, 'enabled', now(), now(), 0)",
    )
    .bind(tenant)
    .execute(database.owner())
    .await
    .expect("application");
    for id in [tenant, twin] {
        sqlx::query(
            "INSERT INTO oauth.client VALUES ($1, $2, $1, 'Export', 'confidential',
                 'client_secret_basic', ARRAY['client_credentials'], ARRAY[]::text[],
                 ARRAY[]::text[], true, 300, 300, 2592000, 604800, 'enabled', now(), now(), 0)",
        )
        .bind(tenant)
        .bind(id)
        .execute(database.owner())
        .await
        .expect("client");
    }
    let bind = |id: sqlx::types::Uuid, spiffe_id: &'static str| {
        sqlx::query(
            "UPDATE oauth.client
             SET authentication_method = 'spiffe_jwt', principal_id = $1, spiffe_id = $3
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant)
        .bind(id)
        .bind(spiffe_id)
    };
    bind(tenant, "spiffe://cluster.local/ns/payroll/sa/export")
        .execute(database.owner())
        .await
        .expect("a client bound to an identifier");
    for (case, spiffe_id) in [
        ("a prefix", "spiffe://cluster.local/ns/payroll/*"),
        ("no path", "spiffe://cluster.local"),
        ("a dot segment", "spiffe://cluster.local/ns/../sa"),
        ("an uppercase trust domain", "spiffe://Cluster.local/ns"),
        ("another scheme", "https://cluster.local/ns"),
    ] {
        let refused = bind(twin, spiffe_id).execute(database.owner()).await;
        assert!(refused.is_err(), "{case}");
    }
    // Two clients of one principal may share the identifier (Decision
    // 0058); the client store, under its lock, refuses one of another
    // principal, as the contract of clients checks.
    bind(twin, "spiffe://cluster.local/ns/payroll/sa/export")
        .execute(database.owner())
        .await
        .expect("a second client of the same principal");
    for (case, statement) in [
        (
            "another method keeps no identifier",
            "UPDATE oauth.client SET authentication_method = 'private_key_jwt' WHERE id = $1",
        ),
        (
            "spiffe_jwt needs an identifier",
            "UPDATE oauth.client SET spiffe_id = NULL WHERE id = $1",
        ),
        (
            "an identifier needs a principal",
            "UPDATE oauth.client SET principal_id = NULL WHERE id = $1",
        ),
    ] {
        let refused = sqlx::query(statement)
            .bind(tenant)
            .execute(database.owner())
            .await;
        assert!(refused.is_err(), "{case}");
    }

    // Another tenant binds the same identifier.
    let other = sqlx::types::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO oauth.application VALUES ($1, $1, 'Exports', false, 'enabled', now(), now(), 0)",
    )
    .bind(other)
    .execute(database.owner())
    .await
    .expect("application");
    sqlx::query(
        "INSERT INTO oauth.client VALUES ($1, $1, $1, 'Export', 'confidential', 'spiffe_jwt',
             ARRAY['client_credentials'], ARRAY[]::text[], ARRAY[]::text[], true, 300, 300,
             2592000, 604800, 'enabled', now(), now(), 0)",
    )
    .bind(other)
    .execute(database.owner())
    .await
    .expect_err("the identifier comes with the method");
    sqlx::query(
        "INSERT INTO oauth.client (tenant_id, id, application_id, name, client_type,
             authentication_method, grant_types, redirect_uris, allowed_scopes, require_pkce,
             access_token_seconds, id_token_seconds, refresh_token_seconds,
             refresh_idle_seconds, status, created_at, updated_at, principal_id, spiffe_id)
         VALUES ($1, $1, $1, 'Export', 'confidential', 'spiffe_jwt',
             ARRAY['client_credentials'], ARRAY[]::text[], ARRAY[]::text[], true, 300, 300,
             2592000, 604800, 'enabled', now(), now(), $1,
             'spiffe://cluster.local/ns/payroll/sa/export')",
    )
    .bind(other)
    .execute(database.owner())
    .await
    .expect("the same identifier in another tenant");
}

#[tokio::test]
async fn a_client_of_a_forwarded_identity_keeps_its_identity_on_postgres() {
    use hodor_kernel::UserId;
    use hodor_oauth::api::{AuthenticationMethod, LinkerdIdentity, SpiffeId};

    let database = TestDatabase::start().await;
    let now = Timestamp::UNIX_EPOCH + Duration::days(20_000);
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(database.app().clone()),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: Arc::new(FixedClock::at(now)),
    });
    let tenant = TenantContext::assume(TenantId::generate());
    let application = applications
        .create_application(
            &tenant,
            ApplicationSettings {
                name: "Shop".to_owned(),
                first_party: true,
            },
            Caller::system(),
        )
        .await
        .expect("application");
    let spiffe = |id: &str| (Some(SpiffeId::parse(id).expect("identifier")), None);
    let linkerd = |id: &str| (None, Some(LinkerdIdentity::parse(id).expect("identity")));
    for (method, identity) in [
        (
            AuthenticationMethod::SpiffeX509,
            spiffe("spiffe://cluster.local/ns/shop/sa/web"),
        ),
        (
            AuthenticationMethod::LinkerdIdentity,
            linkerd("web.shop.serviceaccount.identity.linkerd.cluster.local"),
        ),
        (
            AuthenticationMethod::TlsClientAuth,
            linkerd("api.shop.serviceaccount.identity.linkerd.cluster.local"),
        ),
    ] {
        let mut settings = ClientSettings::new(
            "Web",
            ClientType::Confidential,
            vec![GrantType::ClientCredentials],
            Vec::new(),
        );
        settings.authentication_method = method;
        settings.principal = Some(UserId::generate());
        (settings.spiffe_id, settings.linkerd_identity) = identity;
        let (client, secret) = applications
            .create_client(
                &tenant,
                CreateClient {
                    application_id: application.id(),
                    client_type: ClientType::Confidential,
                    settings: settings.clone(),
                    secret_lifetime: None,
                },
                Caller::system(),
            )
            .await
            .expect("client");
        assert!(secret.is_none());
        let read = applications
            .client(&tenant, client.id())
            .await
            .expect("read back");
        assert_eq!(read.snapshot().settings, client.snapshot().settings);
        assert_eq!(read.snapshot().settings.spiffe_id, settings.spiffe_id);
        assert_eq!(
            read.snapshot().settings.linkerd_identity,
            settings.linkerd_identity
        );
    }
    // Changed from one method to another, and back to a secret.
    let mut settings = ClientSettings::new(
        "Api",
        ClientType::Confidential,
        vec![GrantType::ClientCredentials],
        Vec::new(),
    );
    settings.authentication_method = AuthenticationMethod::TlsClientAuth;
    settings.principal = Some(UserId::generate());
    (settings.spiffe_id, settings.linkerd_identity) =
        spiffe("spiffe://cluster.local/ns/shop/sa/api");
    let (client, _) = applications
        .create_client(
            &tenant,
            CreateClient {
                application_id: application.id(),
                client_type: ClientType::Confidential,
                settings: settings.clone(),
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client");
    settings.authentication_method = AuthenticationMethod::LinkerdIdentity;
    (settings.spiffe_id, settings.linkerd_identity) =
        linkerd("api2.shop.serviceaccount.identity.linkerd.cluster.local");
    applications
        .change_client(&tenant, client.id(), settings.clone(), Caller::system())
        .await
        .expect("changed");
    settings.authentication_method = AuthenticationMethod::PrivateKeyJwt;
    (settings.spiffe_id, settings.linkerd_identity) = (None, None);
    applications
        .change_client(&tenant, client.id(), settings, Caller::system())
        .await
        .expect("changed again");
    let read = applications
        .client(&tenant, client.id())
        .await
        .expect("read back");
    assert_eq!(read.snapshot().settings.spiffe_id, None);
    assert_eq!(read.snapshot().settings.linkerd_identity, None);
}

#[tokio::test]
async fn the_database_holds_each_method_to_its_identity() {
    let database = TestDatabase::start().await;
    let tenant = sqlx::types::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO oauth.application VALUES ($1, $1, 'Shop', false, 'enabled', now(), now(), 0)",
    )
    .bind(tenant)
    .execute(database.owner())
    .await
    .expect("application");
    let insert = |method: &'static str,
                  spiffe: Option<&'static str>,
                  linkerd: Option<&'static str>,
                  principal: bool| {
        sqlx::query(
            "INSERT INTO oauth.client
                 (tenant_id, id, application_id, name, client_type, authentication_method,
                  grant_types, redirect_uris, allowed_scopes, require_pkce,
                  access_token_seconds, id_token_seconds, refresh_token_seconds,
                  refresh_idle_seconds, status, created_at, updated_at, spiffe_id,
                  linkerd_identity, principal_id)
             VALUES ($1, gen_random_uuid(), $1, 'Web', 'confidential', $2,
                     ARRAY['client_credentials'], ARRAY[]::text[], ARRAY[]::text[], true,
                     300, 300, 2592000, 604800, 'enabled', now(), now(), $3, $4,
                     CASE WHEN $5 THEN gen_random_uuid() END)",
        )
        .bind(tenant)
        .bind(method)
        .bind(spiffe)
        .bind(linkerd)
        .bind(principal)
        .execute(database.owner())
    };
    let spiffe = |path: &'static str| -> Option<&'static str> { Some(path) };
    for (method, spiffe_id, linkerd_identity) in [
        (
            "spiffe_jwt",
            spiffe("spiffe://cluster.local/ns/shop/sa/jwt"),
            None,
        ),
        (
            "spiffe_x509",
            spiffe("spiffe://cluster.local/ns/shop/sa/web"),
            None,
        ),
        (
            "linkerd_identity",
            None,
            Some("web.shop.serviceaccount.identity.linkerd.cluster.local"),
        ),
        (
            "tls_client_auth",
            spiffe("spiffe://cluster.local/ns/shop/sa/api"),
            None,
        ),
        (
            "tls_client_auth",
            None,
            Some("api.shop.serviceaccount.identity.linkerd.cluster.local"),
        ),
    ] {
        let kept = insert(method, spiffe_id, linkerd_identity, true).await;
        assert!(kept.is_ok(), "{method}: {kept:?}");
    }
    let kept = insert("client_secret_basic", None, None, false).await;
    assert!(kept.is_ok(), "{kept:?}");
    let fresh_spiffe = spiffe("spiffe://cluster.local/ns/shop/sa/fresh");
    let fresh_linkerd = Some("fresh.shop.serviceaccount.identity.linkerd.cluster.local");
    for (method, spiffe_id, linkerd_identity, principal) in [
        ("spiffe_x509", None, None, true),
        ("spiffe_x509", None, fresh_linkerd, true),
        ("spiffe_x509", fresh_spiffe, fresh_linkerd, true),
        ("linkerd_identity", fresh_spiffe, None, true),
        ("tls_client_auth", None, None, true),
        ("tls_client_auth", fresh_spiffe, fresh_linkerd, true),
        ("client_secret_basic", fresh_spiffe, None, true),
        ("private_key_jwt", None, fresh_linkerd, true),
        ("spiffe_x509", Some("https://cluster.local/web"), None, true),
        (
            "linkerd_identity",
            None,
            Some("web.shop.svc.cluster.local"),
            true,
        ),
        ("linkerd_identity", None, fresh_linkerd, false),
        ("unknown", None, None, false),
    ] {
        let refused = insert(method, spiffe_id, linkerd_identity, principal).await;
        assert!(
            refused.is_err(),
            "{method} {spiffe_id:?} {linkerd_identity:?} {principal}"
        );
    }
}

#[tokio::test]
async fn the_database_binds_tokens_only_where_a_certificate_can_come() {
    let database = TestDatabase::start().await;
    let tenant = sqlx::types::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO oauth.application VALUES ($1, $1, 'Shop', false, 'enabled', now(), now(), 0)",
    )
    .bind(tenant)
    .execute(database.owner())
    .await
    .expect("application");
    let insert = |method: &'static str, linkerd: Option<&'static str>, bound: bool| {
        sqlx::query(
            "INSERT INTO oauth.client
                 (tenant_id, id, application_id, name, client_type, authentication_method,
                  grant_types, redirect_uris, allowed_scopes, require_pkce,
                  access_token_seconds, id_token_seconds, refresh_token_seconds,
                  refresh_idle_seconds, status, created_at, updated_at, linkerd_identity,
                  principal_id, certificate_bound_access_tokens)
             VALUES ($1, gen_random_uuid(), $1, 'Web', 'confidential', $2,
                     ARRAY['client_credentials'], ARRAY[]::text[], ARRAY[]::text[], true,
                     300, 300, 2592000, 604800, 'enabled', now(), now(), $3,
                     CASE WHEN $3 IS NOT NULL THEN gen_random_uuid() END, $4)",
        )
        .bind(tenant)
        .bind(method)
        .bind(linkerd)
        .bind(bound)
        .execute(database.owner())
    };
    let kept = insert("client_secret_basic", None, true).await;
    assert!(kept.is_ok(), "{kept:?}");
    let kept = insert(
        "linkerd_identity",
        Some("web.shop.serviceaccount.identity.linkerd.cluster.local"),
        false,
    )
    .await;
    assert!(kept.is_ok(), "{kept:?}");
    let refused = insert(
        "linkerd_identity",
        Some("api.shop.serviceaccount.identity.linkerd.cluster.local"),
        true,
    )
    .await;
    assert!(refused.is_err(), "Linkerd forwards no certificate");

    // A client made before the column is bound to nothing; a family's
    // thumbprint is 32 bytes or none.
    let unbound: bool = sqlx::query_scalar(
        "SELECT column_default = 'false' FROM information_schema.columns
         WHERE table_schema = 'oauth' AND table_name = 'client'
           AND column_name = 'certificate_bound_access_tokens'",
    )
    .fetch_one(database.owner())
    .await
    .expect("column");
    assert!(unbound);
    let shape: String = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint
         WHERE conname = 'refresh_token_family_certificate_thumbprint_shape'",
    )
    .fetch_one(database.owner())
    .await
    .expect("constraint");
    assert!(shape.contains("32"), "{shape}");
}
