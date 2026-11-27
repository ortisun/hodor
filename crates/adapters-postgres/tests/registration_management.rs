//! Managing a registration on PostgreSQL: the registration access token
//! stored as a hash and replaced at every change, two changes at once with
//! one token under the lock of the client's row, a removal that deletes the
//! client with every row that names it, and the database's rules for the
//! new columns of `oauth.client`.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgApplicationStore, PgClientRegistrationStore, PgClientStore, PgInitialAccessTokenStore,
    PgResourceServerStore,
};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::{Caller, DomainError, ErrorKind, TenantContext, TenantId, Timestamp};
use hodor_oauth::api::{
    ApplicationPorts, ApplicationService, ApplicationSettings, ChangeRegistration,
    ClientRegistrationPorts, ClientRegistrationService, ManageRegistration, RegisterClient,
    RegisteredClient, RegistrationSettings, RegistrationWay,
};
use hodor_oauth::testing::DistinctRandom;
use serde_json::{Value, json};
use std::sync::Arc;
use time::Duration;

struct World {
    applications: ApplicationService,
    registration: ClientRegistrationService,
    tenant: TenantContext,
}

/// A tenant open to registration.
async fn world(database: &TestDatabase) -> World {
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
                ways: vec![RegistrationWay::Open],
                ..RegistrationSettings::default()
            },
            Caller::system(),
        )
        .await
        .expect("on");
    World {
        applications,
        registration,
        tenant,
    }
}

const CALLBACK: &str = "https://portal.partner.example/callback";

impl World {
    async fn register(&self, body: Value) -> RegisteredClient {
        self.applications
            .register_client(
                &self.registration,
                &self.tenant,
                RegisterClient {
                    body,
                    initial_access_token: None,
                    address_hash: Some([3; 32]),
                },
                Caller::system(),
            )
            .await
            .expect("registered")
    }

    async fn change(
        &self,
        registered: &RegisteredClient,
        token: &str,
        name: &str,
    ) -> Result<hodor_oauth::api::ChangedRegistration, DomainError> {
        self.applications
            .change_registration(
                &self.registration,
                &self.tenant,
                ChangeRegistration {
                    registration: manage(registered, token),
                    body: json!({
                        "client_id": registered.client.id().to_string(),
                        "redirect_uris": [CALLBACK],
                        "client_name": name,
                        "initiate_login_uri": "https://portal.partner.example/start"
                    }),
                },
                Caller::system(),
            )
            .await
    }
}

fn manage(registered: &RegisteredClient, token: &str) -> ManageRegistration {
    ManageRegistration {
        client_id: Some(registered.client.id()),
        access_token: Some(token.to_owned()),
    }
}

#[tokio::test]
async fn the_token_is_stored_as_a_hash_and_replaced_at_every_change() {
    let database = TestDatabase::start().await;
    let world = world(&database).await;
    let registered = world
        .register(json!({
            "redirect_uris": [CALLBACK],
            "initiate_login_uri": "https://portal.partner.example/start?from=hodor"
        }))
        .await;
    let first = registered.access_token.expose().to_owned();
    let read = world
        .applications
        .read_registration(
            &world.registration,
            &world.tenant,
            &manage(&registered, &first),
        )
        .await
        .expect("read with the token");
    assert_eq!(read, registered.client);
    assert_eq!(
        read.snapshot().settings.initiate_login_uri.as_deref(),
        Some("https://portal.partner.example/start?from=hodor")
    );
    let stored: Vec<u8> = sqlx::query_scalar(
        "SELECT registration_token_hash FROM oauth.client WHERE tenant_id = $1 AND id = $2",
    )
    .bind(world.tenant.tenant_id().as_uuid())
    .bind(registered.client.id().as_uuid())
    .fetch_one(database.owner())
    .await
    .expect("stored");
    assert_eq!(stored.len(), 32);
    assert!(!String::from_utf8_lossy(&stored).contains("hodor_rat_"));

    let changed = world
        .change(&registered, &first, "Renamed")
        .await
        .expect("changed");
    let second = changed.access_token.expose().to_owned();
    let error = world
        .applications
        .read_registration(
            &world.registration,
            &world.tenant,
            &manage(&registered, &first),
        )
        .await
        .expect_err("the first is old");
    assert_eq!(error.code(), "oauth.registration_access_token_invalid");
    let read = world
        .applications
        .read_registration(
            &world.registration,
            &world.tenant,
            &manage(&registered, &second),
        )
        .await
        .expect("the second");
    assert_eq!(read.snapshot().settings.name, "Renamed");
    assert_eq!(read.snapshot().version, 1);
}

#[tokio::test]
async fn of_two_changes_at_once_with_one_token_one_is_stored() {
    let database = TestDatabase::start().await;
    let world = world(&database).await;
    let registered = world.register(json!({ "redirect_uris": [CALLBACK] })).await;
    let token = registered.access_token.expose().to_owned();
    let (one, other) = tokio::join!(
        world.change(&registered, &token, "One"),
        world.change(&registered, &token, "Other"),
    );
    let stored = match (one, other) {
        (Ok(stored), Err(refused)) | (Err(refused), Ok(stored)) => {
            // The second waited for the first, then found its token old.
            assert_eq!(refused.kind(), ErrorKind::Unauthenticated);
            assert_eq!(refused.code(), "oauth.registration_access_token_invalid");
            stored
        }
        (Ok(_), Ok(_)) => panic!("both changes were stored with one token"),
        (Err(one), Err(other)) => panic!("neither was stored: {one:?}, {other:?}"),
    };
    // Only the token of the change stored works, and it is the one stored.
    let read = world
        .applications
        .read_registration(
            &world.registration,
            &world.tenant,
            &manage(&registered, stored.access_token.expose()),
        )
        .await
        .expect("the token of the change stored");
    assert_eq!(
        read.snapshot().settings.name,
        stored.client.snapshot().settings.name
    );
    assert_eq!(read.snapshot().version, 1, "one change");
}

#[tokio::test]
async fn removing_a_registration_deletes_the_client_with_every_row_that_names_it() {
    let database = TestDatabase::start().await;
    let world = world(&database).await;
    let registered = world
        .register(json!({
            "redirect_uris": [CALLBACK],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": { "keys": [{
                "kty": "EC", "crv": "P-256", "kid": "one",
                "x": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
                "y": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"
            }] }
        }))
        .await;
    let other = world.register(json!({ "redirect_uris": [CALLBACK] })).await;
    let tenant = world.tenant.tenant_id().as_uuid();
    let id = registered.client.id().as_uuid();
    world
        .applications
        .remove_registration(
            &world.registration,
            &world.tenant,
            &manage(&registered, registered.access_token.expose()),
            Caller::system(),
        )
        .await
        .expect("removed");
    for table in ["oauth.client", "oauth.client_key"] {
        let column = if table == "oauth.client" {
            "id"
        } else {
            "client_id"
        };
        let left: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) FROM {table} WHERE tenant_id = $1 AND {column} = $2"
        )))
        .bind(tenant)
        .bind(id)
        .fetch_one(database.owner())
        .await
        .expect("counted");
        assert_eq!(left, 0, "{table}");
    }
    // The other client is untouched.
    world
        .applications
        .read_registration(
            &world.registration,
            &world.tenant,
            &manage(&other, other.access_token.expose()),
        )
        .await
        .expect("the other");

    // Every table that names a client goes with it: a reference that does
    // not cascade would refuse the removal, or leave a row behind.
    let not_cascading: Vec<String> = sqlx::query_scalar(
        "SELECT conrelid::regclass::text || '.' || conname FROM pg_constraint
         WHERE contype = 'f' AND confrelid = 'oauth.client'::regclass AND confdeltype <> 'c'",
    )
    .fetch_all(database.owner())
    .await
    .expect("references");
    assert!(not_cascading.is_empty(), "{not_cascading:?}");
}

#[tokio::test]
async fn the_database_keeps_the_new_columns_to_their_rules() {
    let database = TestDatabase::start().await;
    let world = world(&database).await;
    let registered = world.register(json!({ "redirect_uris": [CALLBACK] })).await;
    let application: sqlx::types::Uuid = sqlx::query_scalar(
        "SELECT application_id FROM oauth.client WHERE tenant_id = $1 AND id = $2",
    )
    .bind(world.tenant.tenant_id().as_uuid())
    .bind(registered.client.id().as_uuid())
    .fetch_one(database.owner())
    .await
    .expect("application");
    let by_hand = world
        .applications
        .create_client(
            &world.tenant,
            hodor_oauth::api::CreateClient {
                application_id: hodor_oauth::api::ApplicationId::from_uuid(application),
                client_type: hodor_oauth::api::ClientType::Confidential,
                settings: hodor_oauth::api::ClientSettings::new(
                    "By hand",
                    hodor_oauth::api::ClientType::Confidential,
                    vec![hodor_oauth::api::GrantType::AuthorizationCode],
                    vec![CALLBACK.to_owned()],
                ),
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("by hand")
        .0;
    let tenant = world.tenant.tenant_id().as_uuid();
    for (case, client, change) in [
        (
            "a token on a client that did not register itself",
            by_hand.id(),
            "registration_token_hash = decode(repeat('ab', 32), 'hex')",
        ),
        (
            "a token hash of another length",
            registered.client.id(),
            "registration_token_hash = decode('abcd', 'hex')",
        ),
        (
            "a login initiation address over plain HTTP",
            registered.client.id(),
            "initiate_login_uri = 'http://portal.partner.example/start'",
        ),
        (
            "a login initiation address too long",
            registered.client.id(),
            "initiate_login_uri = 'https://portal.partner.example/' || repeat('a', 2000)",
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
