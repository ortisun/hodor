//! The use cases of the authorization endpoint, on the in-memory stores.

use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, Clock as _, TenantContext, TenantId, Timestamp, UserId};
use hodor_oauth::api::{
    ApplicationPorts, ApplicationService, ApplicationSettings, AuthorizationCodePorts,
    AuthorizationCodeService, AuthorizationParameters, AuthorizationRefusal, ClientSettings,
    ClientType, CodePresentation, CreateClient, CreateResourceServer, GrantStatus, GrantStore,
    GrantType, ResourceServerSettings, ScopeDefinition, SignedInPerson, s256_challenge,
};
use hodor_oauth::testing::{
    AuthorizationStorePorts, DistinctRandom, InMemoryAuthorizationCodes,
    InMemoryAuthorizationRequests, InMemoryGrants, InMemoryStores, run_authorization_contract,
};
use hodor_session::api::SessionId;
use std::sync::Arc;
use time::Duration;

const REDIRECT: &str = "https://payroll.example.com/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

struct World {
    units: InMemoryUnitOfWorkFactory,
    clock: Arc<FixedClock>,
    grants: InMemoryGrants,
    service: AuthorizationCodeService,
    applications: ApplicationService,
}

fn world() -> World {
    let units = InMemoryUnitOfWorkFactory::default();
    let stores = InMemoryStores::default();
    let requests = InMemoryAuthorizationRequests::new(&stores.clients);
    let grants = InMemoryGrants::new(&stores.clients);
    let codes = InMemoryAuthorizationCodes::new(&grants);
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + Duration::days(20_000),
    ));
    let service = AuthorizationCodeService::new(AuthorizationCodePorts {
        units_of_work: Arc::new(units.clone()),
        applications: Arc::new(stores.applications.clone()),
        clients: Arc::new(stores.clients.clone()),
        resource_servers: Arc::new(stores.resource_servers.clone()),
        requests: Arc::new(requests),
        grants: Arc::new(grants.clone()),
        codes: Arc::new(codes),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(units.clone()),
        applications: Arc::new(stores.applications),
        clients: Arc::new(stores.clients),
        resource_servers: Arc::new(stores.resource_servers),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    World {
        units,
        clock,
        grants,
        service,
        applications,
    }
}

/// A first-party application with a public client and a resource server.
async fn registered(world: &World, tenant: &TenantContext) -> String {
    let application = world
        .applications
        .create_application(
            tenant,
            ApplicationSettings {
                name: "Payroll".to_owned(),
                first_party: true,
            },
            Caller::system(),
        )
        .await
        .expect("application");
    let mut settings = ClientSettings::new(
        "Payroll web",
        ClientType::Public,
        vec![GrantType::AuthorizationCode],
        vec![REDIRECT.to_owned()],
    );
    settings.allowed_scopes = vec!["openid".to_owned(), "read".to_owned()];
    let (client, _) = world
        .applications
        .create_client(
            tenant,
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
    world
        .applications
        .create_resource_server(
            tenant,
            CreateResourceServer {
                application_id: application.id(),
                audience: "https://api.payroll.example.com".to_owned(),
                settings: ResourceServerSettings {
                    name: "Payroll interface".to_owned(),
                    scopes: vec![ScopeDefinition {
                        name: "read".to_owned(),
                        description: "reads payslips".to_owned(),
                    }],
                },
            },
            Caller::system(),
        )
        .await
        .expect("resource server");
    client.id().to_string()
}

fn parameters(client_id: &str) -> AuthorizationParameters {
    AuthorizationParameters::from_pairs(
        [
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", REDIRECT),
            ("scope", "openid read"),
            ("state", "xyz"),
            ("code_challenge", &s256_challenge(VERIFIER, &FakeDigest)),
            ("code_challenge_method", "S256"),
        ]
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
    )
}

fn person(world: &World) -> SignedInPerson {
    SignedInPerson {
        user_id: UserId::generate(),
        session_id: SessionId::generate(),
        signed_in_at: world.clock.now(),
        methods: vec!["password".to_owned()],
        acr: Some("urn:hodor:acr:single-factor".to_owned()),
    }
}

#[tokio::test]
async fn the_in_memory_stores_pass_the_contract() {
    let units = InMemoryUnitOfWorkFactory::default();
    let stores = InMemoryStores::default();
    let requests = InMemoryAuthorizationRequests::new(&stores.clients);
    let grants = InMemoryGrants::new(&stores.clients);
    let codes = InMemoryAuthorizationCodes::new(&grants);
    run_authorization_contract(AuthorizationStorePorts {
        units_of_work: &units,
        applications: &stores.applications,
        clients: &stores.clients,
        requests: &requests,
        grants: &grants,
        codes: &codes,
    })
    .await;
}

#[tokio::test]
async fn a_request_waits_for_its_browser_and_is_resumed_once() {
    let world = world();
    let tenant = TenantContext::assume(TenantId::generate());
    let client_id = registered(&world, &tenant).await;
    let request = world
        .service
        .check(&tenant, &parameters(&client_id))
        .await
        .expect("storage")
        .expect("accepted");
    let (id, secret) = world
        .service
        .hold(&tenant, request.clone())
        .await
        .expect("held");

    // A wrong secret finds nothing and leaves the request for its browser.
    let wrong = "A".repeat(43);
    assert_eq!(
        world
            .service
            .resume(&tenant, id, &wrong)
            .await
            .expect("resume"),
        None
    );
    // Another tenant has no such request.
    let elsewhere = TenantContext::assume(TenantId::generate());
    assert_eq!(
        world
            .service
            .resume(&elsewhere, id, secret.expose())
            .await
            .expect("resume"),
        None
    );
    let resumed = world
        .service
        .resume(&tenant, id, secret.expose())
        .await
        .expect("resume")
        .expect("resumed");
    assert_eq!(resumed.request, request);
    assert_eq!(
        world
            .service
            .resume(&tenant, id, secret.expose())
            .await
            .expect("resume"),
        None,
        "once"
    );

    // After ten minutes it cannot be resumed.
    let (id, secret) = world.service.hold(&tenant, request).await.expect("held");
    world.clock.advance(Duration::minutes(10));
    assert_eq!(
        world
            .service
            .resume(&tenant, id, secret.expose())
            .await
            .expect("resume"),
        None
    );
}

#[tokio::test]
async fn a_client_of_another_tenant_is_unknown() {
    let world = world();
    let tenant = TenantContext::assume(TenantId::generate());
    let client_id = registered(&world, &tenant).await;
    let elsewhere = TenantContext::assume(TenantId::generate());
    assert_eq!(
        world
            .service
            .check(&elsewhere, &parameters(&client_id))
            .await
            .expect("storage"),
        Err(AuthorizationRefusal::NotRedirectable(
            "oauth.authorization_client_unknown"
        ))
    );
}

#[tokio::test]
async fn a_code_is_redeemed_once_and_a_second_redemption_revokes_the_grant() {
    let world = world();
    let tenant = TenantContext::assume(TenantId::generate());
    let client_id = registered(&world, &tenant).await;
    let request = world
        .service
        .check(&tenant, &parameters(&client_id))
        .await
        .expect("storage")
        .expect("accepted");
    let person = person(&world);
    let code = world
        .service
        .issue_code(&tenant, &request, &person, Caller::system())
        .await
        .expect("issued");
    let presentation = CodePresentation {
        client_id: request.client_id,
        redirect_uri: Some(REDIRECT),
        verifier: Some(VERIFIER),
    };

    // Another tenant does not know the code; a wrong verifier is refused
    // and does not use it up.
    let elsewhere = TenantContext::assume(TenantId::generate());
    let refused = world
        .service
        .redeem_code(&elsewhere, code.expose(), presentation, Caller::system())
        .await
        .expect_err("another tenant");
    assert_eq!(
        (refused.code(), refused.detail()),
        ("oauth.code_refused", Some("unknown"))
    );
    let wrong_verifier = "x".repeat(43);
    let wrong = CodePresentation {
        verifier: Some(&wrong_verifier),
        ..presentation
    };
    let refused = world
        .service
        .redeem_code(&tenant, code.expose(), wrong, Caller::system())
        .await
        .expect_err("wrong verifier");
    assert_eq!(refused.detail(), Some("verifier_wrong"));

    let redeemed = world
        .service
        .redeem_code(&tenant, code.expose(), presentation, Caller::system())
        .await
        .expect("redeemed");
    assert_eq!(redeemed.code.user_id, person.user_id);
    assert_eq!(redeemed.code.scopes, ["openid", "read"]);
    assert_eq!(redeemed.code.audiences, ["https://api.payroll.example.com"]);

    let refused = world
        .service
        .redeem_code(&tenant, code.expose(), presentation, Caller::system())
        .await
        .expect_err("second redemption");
    assert_eq!(refused.detail(), Some("already_redeemed"));
    let mut uow = hodor_kernel::UnitOfWorkFactory::begin(&world.units, &tenant)
        .await
        .expect("begin");
    let grant = world
        .grants
        .get(uow.as_mut(), redeemed.code.grant_id)
        .await
        .expect("get")
        .expect("found");
    assert_eq!(grant.status, GrantStatus::Revoked);
    assert_eq!(grant.revocation_reason.as_deref(), Some("code_reused"));
    let types = world.units.committed_event_types();
    assert!(types.contains(&"oauth.authorization_code_issued".to_owned()));
    assert!(types.contains(&"oauth.grant_revoked".to_owned()));

    // No event carries the code.
    for event in world.units.committed_events() {
        assert!(!format!("{event:?}").contains(code.expose()));
    }
}

#[tokio::test]
async fn a_code_lives_sixty_seconds() {
    let world = world();
    let tenant = TenantContext::assume(TenantId::generate());
    let client_id = registered(&world, &tenant).await;
    let request = world
        .service
        .check(&tenant, &parameters(&client_id))
        .await
        .expect("storage")
        .expect("accepted");
    let code = world
        .service
        .issue_code(&tenant, &request, &person(&world), Caller::system())
        .await
        .expect("issued");
    world.clock.advance(Duration::seconds(60));
    let refused = world
        .service
        .redeem_code(
            &tenant,
            code.expose(),
            CodePresentation {
                client_id: request.client_id,
                redirect_uri: Some(REDIRECT),
                verifier: Some(VERIFIER),
            },
            Caller::system(),
        )
        .await
        .expect_err("expired");
    assert_eq!(refused.detail(), Some("expired"));
}
