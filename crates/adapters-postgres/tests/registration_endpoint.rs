//! The registration endpoint's use case on PostgreSQL: a registered client
//! stored and read back, the bounds counted from the clients stored and
//! under the lock of the tenant's settings, and the database's rules for
//! the new columns of `oauth.client`.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgApplicationStore, PgClientRegistrationStore, PgClientStore, PgInitialAccessTokenStore,
    PgResourceServerStore,
};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::{Caller, DomainError, TenantContext, TenantId, Timestamp};
use hodor_oauth::api::{
    ApplicationId, ApplicationPorts, ApplicationService, ApplicationSettings, ApplicationType,
    Client, ClientRegistrationPorts, ClientRegistrationService, MOST_REGISTRATIONS_PER_ADDRESS,
    NewInitialAccessToken, RegisterClient, RegistrationSettings, RegistrationWay,
};
use hodor_oauth::testing::DistinctRandom;
use serde_json::{Value, json};
use std::sync::Arc;
use time::Duration;

struct World {
    applications: ApplicationService,
    registration: ClientRegistrationService,
    tenant: TenantContext,
    application: ApplicationId,
    token: String,
}

/// A tenant with registration on by initial access token, a token that
/// allows `registrations`, and room for `max_clients`.
async fn world(database: &TestDatabase, registrations: u32, max_clients: u32) -> World {
    let tenant = TenantContext::assume(TenantId::generate());
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + Duration::days(20_000),
    ));
    let units = database.app().clone();
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(units.clone()),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    let application = applications
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
    let registration = ClientRegistrationService::new(ClientRegistrationPorts {
        units_of_work: Arc::new(units),
        registrations: Arc::new(PgClientRegistrationStore),
        tokens: Arc::new(PgInitialAccessTokenStore),
        applications: Arc::new(PgApplicationStore),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock,
    });
    registration
        .replace(
            &tenant,
            RegistrationSettings {
                enabled: true,
                application_id: Some(application),
                ways: vec![RegistrationWay::InitialAccessToken],
                max_clients,
                ..RegistrationSettings::default()
            },
            Caller::system(),
        )
        .await
        .expect("on");
    let (_, token) = registration
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
    World {
        applications,
        registration,
        tenant,
        application,
        token: token.expose().to_owned(),
    }
}

fn body() -> Value {
    json!({ "redirect_uris": ["https://portal.partner.example/callback"] })
}

impl World {
    async fn register(
        &self,
        body: Value,
        address: Option<[u8; 32]>,
    ) -> Result<Client, DomainError> {
        self.applications
            .register_client(
                &self.registration,
                &self.tenant,
                RegisterClient {
                    body,
                    initial_access_token: Some(self.token.clone()),
                    address_hash: address,
                },
                Caller::system(),
            )
            .await
            .map(|(client, _)| client)
    }

    async fn spent(&self) -> u32 {
        self.registration
            .tokens(&self.tenant)
            .await
            .expect("tokens")[0]
            .snapshot()
            .registrations
    }

    async fn clients(&self) -> usize {
        self.applications
            .clients(&self.tenant, self.application)
            .await
            .expect("clients")
            .len()
    }
}

#[tokio::test]
async fn a_registered_client_is_stored_and_read_back_with_what_it_named() {
    let database = TestDatabase::start().await;
    let world = world(&database, 1, 100).await;
    let client = world
        .register(
            json!({
                "redirect_uris": ["https://portal.partner.example/callback"],
                "client_name": "Partner portal",
                "application_type": "web",
                "client_uri": "https://portal.partner.example",
                "logo_uri": "https://portal.partner.example/logo.png",
                "policy_uri": "https://portal.partner.example/privacy",
                "tos_uri": "https://portal.partner.example/terms"
            }),
            Some([9; 32]),
        )
        .await
        .expect("registered");
    let read = world
        .applications
        .client(&world.tenant, client.id())
        .await
        .expect("read back");
    assert_eq!(read, client);
    assert!(read.is_registered());
    assert_eq!(
        read.snapshot()
            .self_registration
            .and_then(|r| r.address_hash),
        Some([9; 32])
    );
    let settings = &read.snapshot().settings;
    assert_eq!(settings.application_type, Some(ApplicationType::Web));
    assert_eq!(
        settings.logo_uri.as_deref(),
        Some("https://portal.partner.example/logo.png")
    );
    assert_eq!(settings.display_uris().len(), 4);
    assert_eq!(world.spent().await, 1);

    // An administrator's change keeps what the registration named.
    let mut changed = settings.clone();
    changed.name = "Renamed by an administrator".to_owned();
    let changed = world
        .applications
        .change_client(&world.tenant, client.id(), changed, Caller::system())
        .await
        .expect("changed");
    assert!(changed.is_registered());
    let read = world
        .applications
        .client(&world.tenant, client.id())
        .await
        .expect("read back");
    assert_eq!(read.snapshot().settings.tos_uri, settings.tos_uri);
    assert!(read.is_registered());
}

#[tokio::test]
async fn the_eleventh_registration_of_a_minute_from_one_address_spends_nothing() {
    let database = TestDatabase::start().await;
    let world = world(&database, 50, 100).await;
    for _ in 0..MOST_REGISTRATIONS_PER_ADDRESS {
        world.register(body(), Some([1; 32])).await.expect("within");
    }
    let error = world
        .register(body(), Some([1; 32]))
        .await
        .expect_err("the eleventh");
    assert_eq!(error.code(), "oauth.too_many_registrations");
    let bound = u32::try_from(MOST_REGISTRATIONS_PER_ADDRESS).expect("small");
    assert_eq!(world.spent().await, bound);
    // Addresses that were not known are counted together, apart from it.
    for _ in 0..MOST_REGISTRATIONS_PER_ADDRESS {
        world.register(body(), None).await.expect("unknown");
    }
    assert_eq!(
        world
            .register(body(), None)
            .await
            .expect_err("unknown, the eleventh")
            .code(),
        "oauth.too_many_registrations"
    );
    assert_eq!(world.spent().await, 2 * bound);
    assert_eq!(world.clients().await, 2 * MOST_REGISTRATIONS_PER_ADDRESS);
}

#[tokio::test]
async fn two_registrations_at_once_cannot_pass_the_bound_together() {
    let database = TestDatabase::start().await;
    let world = Arc::new(world(&database, 10, 2).await);
    world.register(body(), Some([1; 32])).await.expect("first");
    // One place left, asked for twice at the same moment.
    let attempts: Vec<_> = (2_u8..4)
        .map(|address| {
            let world = world.clone();
            tokio::spawn(async move { world.register(body(), Some([address; 32])).await })
        })
        .collect();
    let mut passed = 0;
    for attempt in attempts {
        match attempt.await.expect("joined") {
            Ok(_) => passed += 1,
            Err(error) => assert_eq!(error.code(), "oauth.too_many_registered_clients"),
        }
    }
    assert_eq!(passed, 1);
    assert_eq!(world.clients().await, 2);
    assert_eq!(world.spent().await, 2, "the refused one spent nothing");
}

#[tokio::test]
async fn the_database_keeps_the_new_columns_to_their_shape() {
    let database = TestDatabase::start().await;
    let world = world(&database, 1, 100).await;
    let registered = world
        .register(body(), Some([5; 32]))
        .await
        .expect("registered");
    let by_hand = {
        let mut settings = hodor_oauth::api::ClientSettings::new(
            "Made by hand",
            hodor_oauth::api::ClientType::Confidential,
            vec![hodor_oauth::api::GrantType::AuthorizationCode],
            vec!["https://portal.partner.example/callback".to_owned()],
        );
        settings.allowed_scopes = vec!["openid".to_owned()];
        world
            .applications
            .create_client(
                &world.tenant,
                hodor_oauth::api::CreateClient {
                    application_id: world.application,
                    client_type: hodor_oauth::api::ClientType::Confidential,
                    settings,
                    secret_lifetime: None,
                },
                Caller::system(),
            )
            .await
            .expect("by hand")
            .0
    };
    assert!(!by_hand.is_registered());
    let tenant = world.tenant.tenant_id().as_uuid();
    for (case, client, change) in [
        (
            "an address on a client that did not register itself",
            by_hand.id(),
            "registered_from = decode(repeat('ab', 32), 'hex')",
        ),
        (
            "an address of another length",
            registered.id(),
            "registered_from = decode('abcd', 'hex')",
        ),
        (
            "a logo over plain HTTP",
            registered.id(),
            "logo_uri = 'http://portal.partner.example/logo.png'",
        ),
        (
            "terms of service too long",
            registered.id(),
            "tos_uri = 'https://portal.partner.example/' || repeat('a', 2000)",
        ),
        (
            "an application type Hodor does not know",
            registered.id(),
            "application_type = 'desktop'",
        ),
    ] {
        let refused = sqlx::query(sqlx::AssertSqlSafe(format!(
            "UPDATE oauth.client SET {change} WHERE tenant_id = $1 AND id = $2"
        )))
        .bind(tenant)
        .bind(client.as_uuid())
        .execute(database.owner())
        .await;
        assert!(refused.is_err(), "{case}");
    }
}
