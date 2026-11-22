//! The use cases of applications, clients and resource servers, on the
//! in-memory stores.

use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, TenantContext, TenantId, Timestamp};
use hodor_oauth::api::{
    ApplicationPorts, ApplicationService, ApplicationSettings, AuthenticationMethod,
    ClientSettings, ClientType, CreateClient, CreateResourceServer, GrantType,
    ResourceServerSettings, RotateSecret, ScopeDefinition, Status,
};
use hodor_oauth::testing::{DistinctRandom, InMemoryStores, Ports, run_contract};
use std::sync::Arc;
use time::Duration;

const NOW: Timestamp = Timestamp::UNIX_EPOCH;

struct World {
    service: ApplicationService,
    units_of_work: InMemoryUnitOfWorkFactory,
    clock: Arc<FixedClock>,
    tenant: TenantContext,
}

fn world() -> World {
    let stores = InMemoryStores::default();
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let clock = Arc::new(FixedClock::at(NOW));
    let service = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(units_of_work.clone()),
        applications: Arc::new(stores.applications),
        clients: Arc::new(stores.clients),
        resource_servers: Arc::new(stores.resource_servers),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    World {
        service,
        units_of_work,
        clock,
        tenant: TenantContext::assume(TenantId::generate()),
    }
}

fn payroll() -> ApplicationSettings {
    ApplicationSettings {
        name: "Payroll".to_owned(),
        first_party: false,
    }
}

fn web(application: &hodor_oauth::api::Application) -> CreateClient {
    CreateClient {
        application_id: application.id(),
        client_type: ClientType::Confidential,
        settings: ClientSettings::new(
            "Payroll web",
            ClientType::Confidential,
            vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            vec!["https://payroll.example.com/callback".to_owned()],
        ),
        secret_lifetime: None,
    }
}

#[tokio::test]
async fn the_in_memory_stores_pass_the_contract() {
    let stores = InMemoryStores::default();
    run_contract(Ports {
        units_of_work: &InMemoryUnitOfWorkFactory::default(),
        applications: &stores.applications,
        clients: &stores.clients,
        resource_servers: &stores.resource_servers,
    })
    .await;
}

#[tokio::test]
async fn an_application_gets_a_client_whose_secret_is_shown_once() {
    let world = world();
    let application = world
        .service
        .create_application(&world.tenant, payroll(), Caller::system())
        .await
        .expect("created");
    let (client, secret) = world
        .service
        .create_client(&world.tenant, web(&application), Caller::system())
        .await
        .expect("created");
    let secret = secret.expect("a confidential client with a secret method");
    let stored = world
        .service
        .client(&world.tenant, client.id())
        .await
        .expect("stored");
    assert!(stored.accepts_secret(secret.expose(), &FakeDigest, NOW));
    assert_eq!(
        stored.snapshot().secrets[0].expires_at,
        NOW + Duration::days(365)
    );
    assert!(stored.accepts_redirect_uri("https://payroll.example.com/callback"));
    assert_eq!(
        world.units_of_work.committed_event_types(),
        [
            "oauth.application_created",
            "oauth.client_created",
            "oauth.client_secret_issued"
        ]
    );
    let events: String = world
        .units_of_work
        .committed_events()
        .iter()
        .map(|event| event.payload.to_string())
        .collect();
    assert!(!events.contains(&secret.expose()[9..]), "{events}");
    assert_eq!(
        world
            .service
            .clients(&world.tenant, application.id())
            .await
            .expect("listed"),
        vec![stored]
    );
}

#[tokio::test]
async fn a_public_client_has_no_secret_to_rotate() {
    let world = world();
    let application = world
        .service
        .create_application(&world.tenant, payroll(), Caller::system())
        .await
        .expect("created");
    let (client, secret) = world
        .service
        .create_client(
            &world.tenant,
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
        .expect("created");
    assert!(secret.is_none());
    let error = world
        .service
        .rotate_client_secret(
            &world.tenant,
            client.id(),
            RotateSecret {
                lifetime: Duration::days(30),
                keep_previous_for: Duration::ZERO,
            },
            Caller::system(),
        )
        .await
        .expect_err("a public client");
    assert_eq!(error.code(), "oauth.client_secret_not_allowed");
}

#[tokio::test]
async fn a_rotation_hands_over_without_stopping_the_client() {
    let world = world();
    let application = world
        .service
        .create_application(&world.tenant, payroll(), Caller::system())
        .await
        .expect("created");
    let (client, first) = world
        .service
        .create_client(&world.tenant, web(&application), Caller::system())
        .await
        .expect("created");
    let first = first.expect("secret");
    world.clock.advance(Duration::days(10));
    let second = world
        .service
        .rotate_client_secret(
            &world.tenant,
            client.id(),
            RotateSecret {
                lifetime: Duration::days(90),
                keep_previous_for: Duration::days(1),
            },
            Caller::system(),
        )
        .await
        .expect("rotated");
    let stored = world
        .service
        .client(&world.tenant, client.id())
        .await
        .expect("stored");
    let today = NOW + Duration::days(10);
    assert!(stored.accepts_secret(first.expose(), &FakeDigest, today));
    assert!(stored.accepts_secret(second.expose(), &FakeDigest, today));
    assert!(!stored.accepts_secret(first.expose(), &FakeDigest, today + Duration::days(1)));

    let second_id = stored.snapshot().secrets[1].id;
    world
        .service
        .revoke_client_secret(&world.tenant, client.id(), second_id, Caller::system())
        .await
        .expect("revoked");
    let stored = world
        .service
        .client(&world.tenant, client.id())
        .await
        .expect("stored");
    assert!(!stored.accepts_secret(second.expose(), &FakeDigest, today));
    assert!(stored.accepts_secret(first.expose(), &FakeDigest, today));
}

#[tokio::test]
async fn keys_and_settings_change_through_the_use_cases() {
    let world = world();
    let application = world
        .service
        .create_application(&world.tenant, payroll(), Caller::system())
        .await
        .expect("created");
    let mut command = web(&application);
    command.settings.authentication_method = AuthenticationMethod::PrivateKeyJwt;
    let (client, secret) = world
        .service
        .create_client(&world.tenant, command, Caller::system())
        .await
        .expect("created");
    assert!(secret.is_none());
    let jwk = r#"{"kty":"OKP","crv":"Ed25519","kid":"2026","x":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"}"#;
    let keyed = world
        .service
        .add_client_key(&world.tenant, client.id(), jwk, Caller::system())
        .await
        .expect("added");
    assert_eq!(keyed.snapshot().keys[0].key_id, "2026");
    let private = r#"{"kty":"OKP","crv":"Ed25519","kid":"leak","x":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","d":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"}"#;
    assert_eq!(
        world
            .service
            .add_client_key(&world.tenant, client.id(), private, Caller::system())
            .await
            .expect_err("a private key")
            .code(),
        "oauth.client_key_invalid"
    );
    world
        .service
        .remove_client_key(&world.tenant, client.id(), "2026", Caller::system())
        .await
        .expect("removed");

    let mut settings = keyed.snapshot().settings.clone();
    settings.redirect_uris = vec!["https://payroll.example.com/other".to_owned()];
    let changed = world
        .service
        .change_client(
            &world.tenant,
            client.id(),
            settings.clone(),
            Caller::system(),
        )
        .await
        .expect("changed");
    assert!(!changed.accepts_redirect_uri("https://payroll.example.com/callback"));
    let before = world.units_of_work.committed_events().len();
    world
        .service
        .change_client(&world.tenant, client.id(), settings, Caller::system())
        .await
        .expect("same settings");
    assert_eq!(
        world.units_of_work.committed_events().len(),
        before,
        "nothing changed, nothing announced"
    );
    let disabled = world
        .service
        .set_client_status(
            &world.tenant,
            client.id(),
            Status::Disabled,
            Caller::system(),
        )
        .await
        .expect("disabled");
    assert!(!disabled.is_enabled());
}

#[tokio::test]
async fn limits_and_missing_things_are_reported() {
    let world = world();
    let application = world
        .service
        .create_application(&world.tenant, payroll(), Caller::system())
        .await
        .expect("created");
    for _ in 0..20 {
        world
            .service
            .create_client(&world.tenant, web(&application), Caller::system())
            .await
            .expect("created");
    }
    assert_eq!(
        world
            .service
            .create_client(&world.tenant, web(&application), Caller::system())
            .await
            .expect_err("a 21st client")
            .code(),
        "oauth.too_many_clients"
    );
    let missing = hodor_oauth::api::Application::create(payroll(), NOW).expect("not stored");
    assert_eq!(
        world
            .service
            .create_client(&world.tenant, web(&missing), Caller::system())
            .await
            .expect_err("no such application")
            .code(),
        "oauth.application_not_found"
    );
    let elsewhere = TenantContext::assume(TenantId::generate());
    assert_eq!(
        world
            .service
            .application(&elsewhere, application.id())
            .await
            .expect_err("another tenant")
            .code(),
        "oauth.application_not_found"
    );
    assert_eq!(
        world
            .service
            .clients(&elsewhere, application.id())
            .await
            .expect_err("another tenant")
            .code(),
        "oauth.application_not_found"
    );
    for _ in 1..100 {
        world
            .service
            .create_application(&world.tenant, payroll(), Caller::system())
            .await
            .expect("created");
    }
    assert_eq!(
        world
            .service
            .create_application(&world.tenant, payroll(), Caller::system())
            .await
            .expect_err("a 101st application")
            .code(),
        "oauth.too_many_applications"
    );
}

#[tokio::test]
async fn a_resource_server_is_found_by_its_audience() {
    let world = world();
    let application = world
        .service
        .create_application(&world.tenant, payroll(), Caller::system())
        .await
        .expect("created");
    let settings = ResourceServerSettings {
        name: "Payroll interface".to_owned(),
        scopes: vec![ScopeDefinition {
            name: "payroll:read".to_owned(),
            description: "Read pay slips".to_owned(),
        }],
    };
    let server = world
        .service
        .create_resource_server(
            &world.tenant,
            CreateResourceServer {
                application_id: application.id(),
                audience: "https://api.payroll.example.com".to_owned(),
                settings: settings.clone(),
            },
            Caller::system(),
        )
        .await
        .expect("created");
    let found = world
        .service
        .resource_server_by_audience(&world.tenant, "https://api.payroll.example.com")
        .await
        .expect("found");
    assert_eq!(found, server);
    assert!(found.defines("payroll:read"));
    for unknown in ["https://api.payroll.example.com/", "not an audience"] {
        assert_eq!(
            world
                .service
                .resource_server_by_audience(&world.tenant, unknown)
                .await
                .expect_err(unknown)
                .code(),
            "oauth.resource_server_not_found"
        );
    }
    let mut more = settings;
    more.scopes.push(ScopeDefinition {
        name: "payroll:approve".to_owned(),
        description: "Approve pay runs".to_owned(),
    });
    let changed = world
        .service
        .change_resource_server(&world.tenant, server.id(), more, Caller::system())
        .await
        .expect("changed");
    assert!(changed.defines("payroll:approve"));
    assert_eq!(
        world
            .service
            .resource_servers(&world.tenant)
            .await
            .expect("listed")
            .len(),
        1
    );
    assert_eq!(
        world
            .units_of_work
            .committed_event_types()
            .last()
            .map(String::as_str),
        Some("oauth.resource_server_changed")
    );
}

#[tokio::test]
async fn an_application_is_changed_and_disabled() {
    let world = world();
    let application = world
        .service
        .create_application(&world.tenant, payroll(), Caller::system())
        .await
        .expect("created");
    let changed = world
        .service
        .change_application(
            &world.tenant,
            application.id(),
            ApplicationSettings {
                name: "Payroll and pensions".to_owned(),
                first_party: true,
            },
            Caller::system(),
        )
        .await
        .expect("changed");
    assert!(changed.snapshot().settings.first_party);
    let disabled = world
        .service
        .set_application_status(
            &world.tenant,
            application.id(),
            Status::Disabled,
            Caller::system(),
        )
        .await
        .expect("disabled");
    assert!(!disabled.is_enabled());
    assert_eq!(
        world.units_of_work.committed_event_types(),
        [
            "oauth.application_created",
            "oauth.application_changed",
            "oauth.application_disabled"
        ]
    );
    let listed = world
        .service
        .applications(&world.tenant)
        .await
        .expect("listed");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].snapshot().settings, disabled.snapshot().settings);
    assert_eq!(listed[0].snapshot().version, 2, "two stored changes");
}
