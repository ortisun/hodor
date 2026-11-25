//! Client registration on PostgreSQL: the settings of a tenant and its
//! initial access tokens, through the contract, the database's own rules,
//! and a token spent inside the unit of work of a registration.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgApplicationStore, PgClientRegistrationStore, PgClientStore, PgInitialAccessTokenStore,
    PgResourceServerStore,
};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::{Caller, TenantContext, TenantId, Timestamp, UnitOfWorkFactory};
use hodor_oauth::api::{
    AllowedBy, ApplicationPorts, ApplicationService, ApplicationSettings, ClientRegistrationPorts,
    ClientRegistrationService, NewInitialAccessToken, RegistrationSettings, RegistrationWay,
};
use hodor_oauth::testing::{
    ClientRegistrationStorePorts, DistinctRandom, run_client_registration_contract,
};
use std::sync::Arc;
use time::Duration;

#[tokio::test]
async fn the_postgres_registration_stores_pass_the_contract() {
    let database = TestDatabase::start().await;
    run_client_registration_contract(ClientRegistrationStorePorts {
        units_of_work: database.app(),
        applications: &PgApplicationStore,
        registrations: &PgClientRegistrationStore,
        tokens: &PgInitialAccessTokenStore,
    })
    .await;
}

#[tokio::test]
async fn the_database_keeps_settings_and_tokens_to_their_shape() {
    let database = TestDatabase::start().await;
    let tenant = sqlx::types::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO oauth.application VALUES ($1, $1, 'Partners', false, 'enabled', now(), now(), 0)",
    )
    .bind(tenant)
    .execute(database.owner())
    .await
    .expect("application");
    let settings = "INSERT INTO oauth.client_registration
                        (tenant_id, enabled, application_id, ways, max_clients, policy,
                         created_at, updated_at)
                    VALUES ($1, $2, $3, $4, $5, $6::jsonb, now(), now())";
    for (case, enabled, application, ways, max_clients, policy) in [
        (
            "on without an application",
            true,
            None,
            vec!["open"],
            10,
            "{}",
        ),
        ("on without a way", true, Some(tenant), vec![], 10, "{}"),
        ("an unknown way", false, None, vec!["anyone"], 10, "{}"),
        (
            "an application of no tenant",
            true,
            Some(sqlx::types::Uuid::now_v7()),
            vec!["open"],
            10,
            "{}",
        ),
        ("no client", false, None, vec![], 0, "{}"),
        ("more than a thousand", false, None, vec![], 1001, "{}"),
        (
            "a policy that is not an object",
            false,
            None,
            vec![],
            10,
            "[]",
        ),
    ] {
        let refused = sqlx::query(settings)
            .bind(tenant)
            .bind(enabled)
            .bind(application)
            .bind(ways)
            .bind(max_clients)
            .bind(policy)
            .execute(database.owner())
            .await;
        assert!(refused.is_err(), "{case}");
    }
    sqlx::query(settings)
        .bind(tenant)
        .bind(true)
        .bind(Some(tenant))
        .bind(vec!["initial_access_token", "open"])
        .bind(1000)
        .bind("{}")
        .execute(database.owner())
        .await
        .expect("settings that keep every rule");

    let token = "INSERT INTO oauth.initial_access_token
                     (tenant_id, id, token_hash, hint, name, max_registrations, registrations,
                      created_at, expires_at)
                 VALUES ($1, gen_random_uuid(), $2, $3, $4, $5, $6, now(), now() + $7::interval)";
    let mut hash = 0_u8;
    let mut next_hash = || {
        hash += 1;
        vec![hash; 32]
    };
    sqlx::query(token)
        .bind(tenant)
        .bind(next_hash())
        .bind("7c1e")
        .bind("Partner portal team")
        .bind(1000)
        .bind(1000)
        .bind("90 days")
        .execute(database.owner())
        .await
        .expect("a token that keeps every rule");
    for (case, token_hash, hint, name, max, used, lifetime) in [
        (
            "a hash of another length",
            vec![1_u8; 31],
            "7c1e",
            "Team",
            1,
            0,
            "1 day",
        ),
        (
            "a hint of another shape",
            next_hash(),
            "7C1E",
            "Team",
            1,
            0,
            "1 day",
        ),
        ("an empty name", next_hash(), "7c1e", "", 1, 0, "1 day"),
        (
            "no registration",
            next_hash(),
            "7c1e",
            "Team",
            0,
            0,
            "1 day",
        ),
        (
            "more than it allows",
            next_hash(),
            "7c1e",
            "Team",
            1,
            2,
            "1 day",
        ),
        (
            "less than an hour",
            next_hash(),
            "7c1e",
            "Team",
            1,
            0,
            "59 minutes",
        ),
        (
            "more than 90 days",
            next_hash(),
            "7c1e",
            "Team",
            1,
            0,
            "91 days",
        ),
    ] {
        let refused = sqlx::query(token)
            .bind(tenant)
            .bind(token_hash)
            .bind(hint)
            .bind(name)
            .bind(max)
            .bind(used)
            .bind(lifetime)
            .execute(database.owner())
            .await;
        assert!(refused.is_err(), "{case}");
    }
    let refused = sqlx::query(token)
        .bind(tenant)
        .bind(vec![1_u8; 32])
        .bind("7c1e")
        .bind("Same hash")
        .bind(1)
        .bind(0)
        .bind("1 day")
        .execute(database.owner())
        .await;
    assert!(refused.is_err(), "a hash once per tenant");
}

struct Registration {
    units: Arc<dyn UnitOfWorkFactory>,
    service: ClientRegistrationService,
    clock: Arc<FixedClock>,
}

/// A tenant with registration on, allowing initial access tokens, and a
/// token that allows `registrations`.
async fn with_a_token(
    database: &TestDatabase,
    registrations: u32,
) -> (Registration, TenantContext, String) {
    let tenant = TenantContext::assume(TenantId::generate());
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + Duration::days(20_000),
    ));
    let units = database.app().clone();
    let application = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(units.clone()),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    })
    .create_application(
        &tenant,
        ApplicationSettings {
            name: "Partners".to_owned(),
            first_party: false,
        },
        Caller::system(),
    )
    .await
    .expect("application")
    .id();
    let service = ClientRegistrationService::new(ClientRegistrationPorts {
        units_of_work: Arc::new(units.clone()),
        registrations: Arc::new(PgClientRegistrationStore),
        tokens: Arc::new(PgInitialAccessTokenStore),
        applications: Arc::new(PgApplicationStore),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    service
        .replace(
            &tenant,
            RegistrationSettings {
                enabled: true,
                application_id: Some(application),
                ways: vec![RegistrationWay::InitialAccessToken],
                ..RegistrationSettings::default()
            },
            Caller::system(),
        )
        .await
        .expect("on");
    let (_, value) = service
        .issue_token(
            &tenant,
            NewInitialAccessToken {
                name: "Partner portal team".to_owned(),
                lifetime: Duration::days(7),
                max_registrations: registrations,
            },
            Caller::system(),
        )
        .await
        .expect("token");
    (
        Registration {
            units: Arc::new(units),
            service,
            clock,
        },
        tenant,
        value.expose().to_owned(),
    )
}

#[tokio::test]
async fn a_registration_refused_after_its_token_was_accepted_spends_nothing() {
    let database = TestDatabase::start().await;
    let (registration, tenant, token) = with_a_token(&database, 1).await;
    // Accepted, then the unit of work ends without a commit, as when the
    // registration is refused afterwards.
    let mut uow = registration.units.begin(&tenant).await.expect("begin");
    let admission = registration
        .service
        .admit(uow.as_mut(), Some(&token), Caller::system())
        .await
        .expect("accepted");
    assert!(matches!(
        admission.allowed_by,
        AllowedBy::InitialAccessToken(_)
    ));
    drop(uow);
    let listed = registration.service.tokens(&tenant).await.expect("list");
    assert_eq!(listed[0].snapshot().registrations, 0, "nothing spent");

    // Committed, it is spent, and a second registration is refused.
    let mut uow = registration.units.begin(&tenant).await.expect("begin");
    registration
        .service
        .admit(uow.as_mut(), Some(&token), Caller::system())
        .await
        .expect("accepted");
    uow.commit().await.expect("commit");
    let mut uow = registration.units.begin(&tenant).await.expect("begin");
    assert_eq!(
        registration
            .service
            .admit(uow.as_mut(), Some(&token), Caller::system())
            .await
            .expect_err("used up")
            .code(),
        "oauth.initial_access_token_invalid"
    );
    let listed = registration.service.tokens(&tenant).await.expect("list");
    assert_eq!(listed[0].snapshot().registrations, 1);
    assert_eq!(
        listed[0].snapshot().last_used_at,
        Some(Timestamp::UNIX_EPOCH + Duration::days(20_000))
    );
}

#[tokio::test]
async fn two_registrations_at_once_cannot_spend_one_registration_twice() {
    let database = TestDatabase::start().await;
    let (registration, tenant, token) = with_a_token(&database, 1).await;
    // The first holds the token's row until it commits; the second waits
    // for it, then finds the token used up.
    let mut first = registration.units.begin(&tenant).await.expect("begin");
    registration
        .service
        .admit(first.as_mut(), Some(&token), Caller::system())
        .await
        .expect("first");
    let second = {
        let units = registration.units.clone();
        let service = registration.service.clone();
        let tenant = tenant.clone();
        let token = token.clone();
        tokio::spawn(async move {
            let mut uow = units.begin(&tenant).await.expect("begin");
            let answer = service
                .admit(uow.as_mut(), Some(&token), Caller::system())
                .await;
            if answer.is_ok() {
                uow.commit().await.expect("commit");
            }
            answer.map(|admission| admission.allowed_by)
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(!second.is_finished(), "the second waits for the first");
    first.commit().await.expect("commit");
    let error = second.await.expect("joined").expect_err("used up");
    assert_eq!(error.code(), "oauth.initial_access_token_invalid");
    let listed = registration.service.tokens(&tenant).await.expect("list");
    assert_eq!(listed[0].snapshot().registrations, 1);
}

#[tokio::test]
async fn a_token_past_its_expiry_is_refused_and_one_of_another_tenant_is_unknown() {
    let database = TestDatabase::start().await;
    let (registration, tenant, token) = with_a_token(&database, 5).await;
    let (other, other_tenant, _) = with_a_token(&database, 5).await;
    let mut uow = other.units.begin(&other_tenant).await.expect("begin");
    assert_eq!(
        other
            .service
            .admit(uow.as_mut(), Some(&token), Caller::system())
            .await
            .expect_err("unknown")
            .code(),
        "oauth.initial_access_token_invalid"
    );
    drop(uow);
    registration.clock.advance(Duration::days(7));
    let mut uow = registration.units.begin(&tenant).await.expect("begin");
    assert_eq!(
        registration
            .service
            .admit(uow.as_mut(), Some(&token), Caller::system())
            .await
            .expect_err("expired")
            .code(),
        "oauth.initial_access_token_invalid"
    );
}
