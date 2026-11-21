//! The stores of the federation context, on PostgreSQL.

use hodor_adapters_crypto::{OsRandom, SecretKeys};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{PgLinkStore, PgProviderStore, PgTripStore};
use hodor_federation::api::{
    CreateProvider, FederationService, ProviderKind, ProviderSettings, Subject,
};
use hodor_federation::testing::{Ports, run_contract};
use hodor_kernel::{
    Caller, Secret, SystemClock, TenantContext, TenantId, UnitOfWorkFactory, UserId,
};
use std::sync::Arc;

const SECRET: &str = "the-client-secret-of-the-provider";

#[tokio::test]
async fn the_postgres_stores_pass_the_contract() {
    let database = TestDatabase::start().await;
    run_contract(Ports {
        units_of_work: database.app(),
        providers: &PgProviderStore,
        links: &PgLinkStore,
        trips: &PgTripStore,
    })
    .await;
}

fn service(database: &TestDatabase) -> FederationService {
    let key = SecretKeys::generate(&OsRandom);
    let keys = SecretKeys::parse(&Secret::new(format!("test:{}", key.expose()))).expect("keys");
    FederationService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgProviderStore),
        Arc::new(PgLinkStore),
        Arc::new(keys),
        Arc::new(SystemClock),
    )
}

fn create(alias: &str) -> CreateProvider {
    CreateProvider {
        alias: alias.to_owned(),
        kind: ProviderKind::OpenIdConnect,
        settings: ProviderSettings {
            display_name: "Example".to_owned(),
            issuer: "https://accounts.example.com".to_owned(),
            client_id: "hodor".to_owned(),
            scopes: ProviderSettings::default_scopes(),
            creates_users: true,
        },
        client_secret: Secret::from(SECRET.to_owned()),
    }
}

#[tokio::test]
async fn a_client_secret_is_nowhere_in_the_database_and_still_comes_back() {
    let database = TestDatabase::start().await;
    let service = service(&database);
    let tenant = TenantContext::assume(TenantId::generate());

    let provider = service
        .create_provider(&tenant, create("example"), Caller::system())
        .await
        .expect("create");

    // Everything the database holds about providers and their events,
    // read as the owner of the tables. Bytes are written out so that any
    // text among them stays readable, whatever the other bytes are.
    let everything: String = sqlx::query_scalar(
        r#"SELECT concat(
               (SELECT string_agg(to_jsonb(t)::text || encode(t.client_secret, 'escape'), '')
                FROM federation.identity_provider t),
               (SELECT string_agg(to_jsonb(t)::text, '') FROM platform.outbox t))"#,
    )
    .fetch_one(database.owner())
    .await
    .expect("dump");
    assert!(
        everything.contains("accounts.example.com"),
        "the dump saw the provider"
    );
    assert!(
        !everything.contains(SECRET),
        "the secret is stored nowhere in the clear"
    );

    let read = service
        .provider(&tenant, provider.id())
        .await
        .expect("read");
    assert_eq!(
        service
            .client_secret(&tenant, &read)
            .expect("open")
            .expose(),
        SECRET
    );

    // The same bytes under another tenant do not open.
    let elsewhere = TenantContext::assume(TenantId::generate());
    assert!(service.client_secret(&elsewhere, &read).is_err());
}

#[tokio::test]
async fn a_user_and_their_link_are_stored_together_or_not_at_all() {
    let database = TestDatabase::start().await;
    let service = service(&database);
    let tenant = TenantContext::assume(TenantId::generate());
    let provider = service
        .create_provider(&tenant, create("example"), Caller::system())
        .await
        .expect("create");
    let subject = Subject::parse("subject-1").expect("subject");
    let ana = UserId::generate();

    // Linked, then abandoned: as when creating the user fails afterwards.
    let mut uow = UnitOfWorkFactory::begin(database.app(), &tenant)
        .await
        .expect("begin");
    service
        .link(
            uow.as_mut(),
            provider.id(),
            subject.clone(),
            ana,
            Caller::system(),
        )
        .await
        .expect("link");
    drop(uow);

    let mut uow = UnitOfWorkFactory::begin(database.app(), &tenant)
        .await
        .expect("begin");
    assert_eq!(
        service
            .find_user(uow.as_mut(), provider.id(), &subject)
            .await
            .expect("find"),
        None
    );
    service
        .link(
            uow.as_mut(),
            provider.id(),
            subject.clone(),
            ana,
            Caller::system(),
        )
        .await
        .expect("link");
    uow.commit().await.expect("commit");

    let mut uow = UnitOfWorkFactory::begin(database.app(), &tenant)
        .await
        .expect("begin");
    assert_eq!(
        service
            .find_user(uow.as_mut(), provider.id(), &subject)
            .await
            .expect("find"),
        Some(ana)
    );
    drop(uow);
    let announced: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM platform.outbox WHERE event_type = 'federation.identity_linked'",
    )
    .fetch_one(database.owner())
    .await
    .expect("count");
    assert_eq!(announced, 1, "only the committed link was announced");
}

#[tokio::test]
async fn two_links_of_the_same_identity_made_at_once_leave_one() {
    let database = TestDatabase::start().await;
    let service = Arc::new(service(&database));
    let tenant = TenantContext::assume(TenantId::generate());
    let provider = service
        .create_provider(&tenant, create("example"), Caller::system())
        .await
        .expect("create");

    let attempts: Vec<_> = (0..8)
        .map(|_| {
            let (service, tenant, app) = (service.clone(), tenant.clone(), database.app().clone());
            let provider_id = provider.id();
            tokio::spawn(async move {
                let mut uow = UnitOfWorkFactory::begin(&app, &tenant)
                    .await
                    .expect("begin");
                let user = UserId::generate();
                let subject = Subject::parse("the same person").expect("subject");
                service
                    .link(uow.as_mut(), provider_id, subject, user, Caller::system())
                    .await?;
                uow.commit().await.map(|()| user)
            })
        })
        .collect();
    let mut winners = Vec::new();
    for attempt in attempts {
        match attempt.await.expect("task") {
            Ok(user) => winners.push(user),
            Err(error) => assert_eq!(error.code(), "federation.identity_already_linked"),
        }
    }
    assert_eq!(winners.len(), 1, "exactly one link was made");

    let mut uow = UnitOfWorkFactory::begin(database.app(), &tenant)
        .await
        .expect("begin");
    let subject = Subject::parse("the same person").expect("subject");
    assert_eq!(
        service
            .find_user(uow.as_mut(), provider.id(), &subject)
            .await
            .expect("find"),
        Some(winners[0])
    );
}

#[tokio::test]
async fn the_database_itself_refuses_what_the_rules_forbid() {
    let database = TestDatabase::start().await;
    let service = service(&database);
    let tenant = TenantContext::assume(TenantId::generate());
    let provider = service
        .create_provider(&tenant, create("example"), Caller::system())
        .await
        .expect("create");

    for statement in [
        "UPDATE federation.identity_provider SET alias = 'Not An Alias'",
        "UPDATE federation.identity_provider SET kind = 'something_else'",
        "UPDATE federation.identity_provider SET status = 'half'",
        "UPDATE federation.identity_provider SET issuer = 'http://plain.example.com'",
        "UPDATE federation.identity_provider SET client_secret = ''",
    ] {
        let refused = sqlx::query(statement).execute(database.owner()).await;
        assert!(refused.is_err(), "{statement}");
    }
    // A provider that has links cannot be deleted from under them.
    let mut uow = UnitOfWorkFactory::begin(database.app(), &tenant)
        .await
        .expect("begin");
    let subject = Subject::parse("subject-1").expect("subject");
    service
        .link(
            uow.as_mut(),
            provider.id(),
            subject,
            UserId::generate(),
            Caller::system(),
        )
        .await
        .expect("link");
    uow.commit().await.expect("commit");
    let refused = sqlx::query("DELETE FROM federation.identity_provider")
        .execute(database.owner())
        .await;
    assert!(refused.is_err());
}
