//! The use cases of consent, on the in-memory stores.

use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, TenantContext, TenantId, Timestamp, UserId};
use hodor_oauth::api::{
    ApplicationPorts, ApplicationService, ApplicationSettings, AskedScope, AuthorizationCodePorts,
    AuthorizationCodeService, AuthorizationParameters, AuthorizationRequest, ClientSettings,
    ClientType, ConsentAction, ConsentActor, ConsentAnswer, ConsentPorts, ConsentService,
    CreateClient, CreateResourceServer, GrantStatus, GrantType, PendingAuthorizationId,
    ResourceServerSettings, ScopeDefinition, SignedInPerson, s256_challenge,
};
use hodor_oauth::testing::{
    ConsentStorePorts, DistinctRandom, InMemoryAuthorizationCodes, InMemoryAuthorizationRequests,
    InMemoryConsents, InMemoryGrants, InMemoryStores, MembershipsOf, run_consent_contract,
};
use hodor_session::api::SessionId;
use std::sync::Arc;
use time::Duration;

const REDIRECT: &str = "https://billing.example.com/callback";
const AUDIENCE: &str = "https://api.billing.example.com";

struct World {
    units: InMemoryUnitOfWorkFactory,
    clock: Arc<FixedClock>,
    grants: InMemoryGrants,
    consents: InMemoryConsents,
    codes: AuthorizationCodeService,
    consent: ConsentService,
    applications: ApplicationService,
    registration: hodor_oauth::api::ClientRegistrationService,
}

fn world() -> World {
    let units = InMemoryUnitOfWorkFactory::default();
    let stores = InMemoryStores::default();
    let requests = InMemoryAuthorizationRequests::new(&stores.clients);
    let grants = InMemoryGrants::new(&stores.clients);
    let codes = InMemoryAuthorizationCodes::new(&grants);
    let consents = InMemoryConsents::new(&stores.clients);
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + Duration::days(20_000),
    ));
    let code_service = AuthorizationCodeService::new(AuthorizationCodePorts {
        units_of_work: Arc::new(units.clone()),
        applications: Arc::new(stores.applications.clone()),
        clients: Arc::new(stores.clients.clone()),
        resource_servers: Arc::new(stores.resource_servers.clone()),
        requests: Arc::new(requests.clone()),
        grants: Arc::new(grants.clone()),
        codes: Arc::new(codes),
        memberships: Arc::new(MembershipsOf::default()),
        verifier: Arc::new(hodor_oauth::testing::FakeVerifier),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    let consent = ConsentService::new(ConsentPorts {
        units_of_work: Arc::new(units.clone()),
        consents: Arc::new(consents.clone()),
        requests: Arc::new(requests),
        grants: Arc::new(grants.clone()),
        clients: Arc::new(stores.clients.clone()),
        applications: Arc::new(stores.applications.clone()),
        resource_servers: Arc::new(stores.resource_servers.clone()),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    let registration = hodor_oauth::testing::client_registration_service(
        Arc::new(units.clone()),
        &stores,
        clock.clone(),
    );
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
        consents,
        codes: code_service,
        consent,
        applications,
        registration,
    }
}

/// A third-party application with a public client allowed `openid`,
/// `offline_access` and `invoices:read`, and its resource server.
async fn registered(world: &World, tenant: &TenantContext) -> String {
    let application = world
        .applications
        .create_application(
            tenant,
            ApplicationSettings {
                name: "Billing".to_owned(),
                first_party: false,
            },
            Caller::system(),
        )
        .await
        .expect("application");
    let mut settings = ClientSettings::new(
        "Billing web",
        ClientType::Public,
        vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        vec![REDIRECT.to_owned()],
    );
    settings.allowed_scopes = vec![
        "openid".to_owned(),
        "offline_access".to_owned(),
        "invoices:read".to_owned(),
    ];
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
                audience: AUDIENCE.to_owned(),
                settings: ResourceServerSettings {
                    name: "Invoices".to_owned(),
                    scopes: vec![ScopeDefinition {
                        name: "invoices:read".to_owned(),
                        description: "Read your invoices".to_owned(),
                    }],
                },
            },
            Caller::system(),
        )
        .await
        .expect("resource server");
    client.id().to_string()
}

async fn checked(
    world: &World,
    tenant: &TenantContext,
    client_id: &str,
    scope: &str,
    extra: &[(&str, &str)],
) -> AuthorizationRequest {
    let challenge = s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", &FakeDigest);
    let mut pairs = vec![
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", REDIRECT),
        ("scope", scope),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ];
    pairs.extend_from_slice(extra);
    let parameters = AuthorizationParameters::from_pairs(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
    );
    world
        .codes
        .check(
            tenant,
            "https://hodor.example.com/t/acme",
            &parameters,
            &hodor_oauth::api::PushedRequestPolicy::default(),
        )
        .await
        .expect("storage")
        .expect("accepted")
}

fn person() -> SignedInPerson {
    SignedInPerson {
        user_id: UserId::generate(),
        session_id: SessionId::generate(),
        signed_in_at: Timestamp::UNIX_EPOCH + Duration::days(20_000),
        methods: vec!["password".to_owned()],
        acr: None,
    }
}

fn a_tenant() -> TenantContext {
    TenantContext::assume(TenantId::generate())
}

/// Holds `request` for `person` and answers it, as the consent page would.
async fn agree(
    world: &World,
    tenant: &TenantContext,
    request: AuthorizationRequest,
    person: &SignedInPerson,
) -> PendingAuthorizationId {
    let (id, secret) = world
        .consent
        .hold(tenant, request, person)
        .await
        .expect("held");
    assert!(
        world
            .consent
            .answer(
                tenant,
                id,
                secret.expose(),
                person,
                ConsentAnswer::Agreed,
                Caller::system()
            )
            .await
            .expect("answered")
    );
    id
}

#[tokio::test]
async fn the_store_contract_holds_in_memory() {
    let stores = InMemoryStores::default();
    let consents = InMemoryConsents::new(&stores.clients);
    let units = InMemoryUnitOfWorkFactory::default();
    run_consent_contract(ConsentStorePorts {
        units_of_work: &units,
        applications: &stores.applications,
        clients: &stores.clients,
        consents: &consents,
    })
    .await;
}

#[tokio::test]
async fn a_scope_not_agreed_to_is_asked_for_and_an_agreed_one_is_not_until_it_runs_out() {
    let world = world();
    let tenant = a_tenant();
    let client = registered(&world, &tenant).await;
    let ana = person();
    let request = checked(&world, &tenant, &client, "openid", &[]).await;
    assert!(!request.first_party);
    assert!(
        world
            .consent
            .must_ask(&tenant, &request, &ana)
            .await
            .expect("decided")
    );

    agree(&world, &tenant, request.clone(), &ana).await;
    assert!(
        !world
            .consent
            .must_ask(&tenant, &request, &ana)
            .await
            .expect("decided")
    );
    let more = checked(&world, &tenant, &client, "openid invoices:read", &[]).await;
    assert!(
        world
            .consent
            .must_ask(&tenant, &more, &ana)
            .await
            .expect("decided"),
        "a scope not agreed to"
    );
    assert!(
        world
            .consent
            .must_ask(&tenant, &request, &person())
            .await
            .expect("decided"),
        "another person agreed to nothing"
    );
    assert!(
        world
            .consent
            .must_ask(&a_tenant(), &request, &ana)
            .await
            .expect("decided"),
        "in another tenant nothing was agreed"
    );

    world.clock.advance(Duration::days(365));
    assert!(
        world
            .consent
            .must_ask(&tenant, &request, &ana)
            .await
            .expect("decided"),
        "the consent ran out"
    );
}

#[tokio::test]
async fn offline_access_and_prompt_consent_ask_again() {
    let world = world();
    let tenant = a_tenant();
    let client = registered(&world, &tenant).await;
    let ana = person();
    let offline = checked(&world, &tenant, &client, "openid offline_access", &[]).await;
    agree(&world, &tenant, offline.clone(), &ana).await;
    assert!(
        world
            .consent
            .must_ask(&tenant, &offline, &ana)
            .await
            .expect("decided"),
        "offline access is asked every time"
    );
    let plain = checked(&world, &tenant, &client, "openid", &[]).await;
    assert!(
        !world
            .consent
            .must_ask(&tenant, &plain, &ana)
            .await
            .expect("decided")
    );
    let again = checked(&world, &tenant, &client, "openid", &[("prompt", "consent")]).await;
    assert!(
        world
            .consent
            .must_ask(&tenant, &again, &ana)
            .await
            .expect("decided")
    );
}

#[tokio::test]
async fn the_question_names_the_application_and_its_scopes_for_the_person_asked_only() {
    let world = world();
    let tenant = a_tenant();
    let client = registered(&world, &tenant).await;
    let ana = person();
    let request = checked(
        &world,
        &tenant,
        &client,
        "openid invoices:read offline_access",
        &[],
    )
    .await;
    let (id, secret) = world
        .consent
        .hold(&tenant, request, &ana)
        .await
        .expect("held");
    let question = world
        .consent
        .describe(&tenant, id, secret.expose(), ana.user_id, ana.session_id)
        .await
        .expect("described")
        .expect("waiting");
    assert_eq!(question.application, "Billing");
    assert!(question.offline_access);
    assert_eq!(
        question.scopes,
        vec![
            AskedScope::OpenId {
                scope: "openid".to_owned()
            },
            AskedScope::Resource {
                scope: "invoices:read".to_owned(),
                description: "Read your invoices".to_owned(),
                resource_server: "Invoices".to_owned(),
            },
        ]
    );

    let other = person();
    assert_eq!(
        world
            .consent
            .describe(
                &tenant,
                id,
                secret.expose(),
                other.user_id,
                other.session_id
            )
            .await
            .expect("described"),
        None,
        "another person"
    );
    assert_eq!(
        world
            .consent
            .describe(
                &tenant,
                id,
                secret.expose(),
                ana.user_id,
                SessionId::generate()
            )
            .await
            .expect("described"),
        None,
        "another session of the same person"
    );
    assert_eq!(
        world
            .consent
            .describe(
                &tenant,
                id,
                "a-wrong-secret-of-the-right-length-0123456789",
                ana.user_id,
                ana.session_id
            )
            .await
            .expect("described"),
        None,
        "another browser"
    );
    assert_eq!(
        world
            .consent
            .describe(
                &a_tenant(),
                id,
                secret.expose(),
                ana.user_id,
                ana.session_id
            )
            .await
            .expect("described"),
        None,
        "another tenant"
    );
    assert!(
        !world
            .consent
            .answer(
                &tenant,
                id,
                secret.expose(),
                &other,
                ConsentAnswer::Agreed,
                Caller::system()
            )
            .await
            .expect("answer"),
        "another person cannot answer it"
    );
}

#[tokio::test]
async fn a_request_is_answered_once_and_a_refusal_is_kept_in_the_history() {
    let world = world();
    let tenant = a_tenant();
    let client = registered(&world, &tenant).await;
    let ana = person();
    let request = checked(&world, &tenant, &client, "openid", &[]).await;
    let (id, secret) = world
        .consent
        .hold(&tenant, request.clone(), &ana)
        .await
        .expect("held");
    assert!(
        world
            .consent
            .answer(
                &tenant,
                id,
                secret.expose(),
                &ana,
                ConsentAnswer::Refused,
                Caller::system()
            )
            .await
            .expect("answered")
    );
    assert!(
        !world
            .consent
            .answer(
                &tenant,
                id,
                secret.expose(),
                &ana,
                ConsentAnswer::Agreed,
                Caller::system()
            )
            .await
            .expect("answer"),
        "answered once"
    );
    assert_eq!(
        world
            .consent
            .describe(&tenant, id, secret.expose(), ana.user_id, ana.session_id)
            .await
            .expect("described"),
        None,
        "an answered request no longer waits"
    );
    let resumed = world
        .codes
        .resume(&tenant, id, secret.expose())
        .await
        .expect("resumed")
        .expect("kept");
    assert_eq!(
        resumed.consent.and_then(|wait| wait.answer),
        Some(ConsentAnswer::Refused)
    );
    assert!(
        world
            .consent
            .must_ask(&tenant, &request, &ana)
            .await
            .expect("decided")
    );
    let history = world.consents.history(tenant.tenant_id());
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].action, ConsentAction::Refused);
    assert!(
        world
            .units
            .committed_events()
            .iter()
            .any(|event| event.event_type == "oauth.consent_refused")
    );
}

#[tokio::test]
async fn withdrawing_a_consent_revokes_its_grants_and_asks_again() {
    let world = world();
    let tenant = a_tenant();
    let client = registered(&world, &tenant).await;
    let ana = person();
    let request = checked(&world, &tenant, &client, "openid invoices:read", &[]).await;
    agree(&world, &tenant, request.clone(), &ana).await;
    world
        .codes
        .issue_code(&tenant, &request, &ana, Caller::system())
        .await
        .expect("code");
    world
        .codes
        .issue_code(&tenant, &request, &ana, Caller::system())
        .await
        .expect("code");
    let listed = world
        .consent
        .list(&tenant, ana.user_id)
        .await
        .expect("listed");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].application, "Billing");
    assert!(
        world
            .consent
            .list(&tenant, person().user_id)
            .await
            .expect("listed")
            .is_empty()
    );

    let client_id = request.client_id;
    assert_eq!(
        world
            .consent
            .withdraw(
                &tenant,
                person().user_id,
                client_id,
                ConsentActor::Person,
                Caller::system()
            )
            .await
            .expect_err("another person's")
            .code(),
        "oauth.consent_not_found"
    );
    world
        .consent
        .withdraw(
            &tenant,
            ana.user_id,
            client_id,
            ConsentActor::Person,
            Caller::system(),
        )
        .await
        .expect("withdrawn");
    let grants = world.grants.all(tenant.tenant_id());
    assert_eq!(grants.len(), 2);
    assert!(
        grants
            .iter()
            .all(|grant| grant.status == GrantStatus::Revoked)
    );
    assert!(
        grants
            .iter()
            .all(|grant| grant.revocation_reason.as_deref() == Some("consent_withdrawn"))
    );
    assert!(
        world
            .consent
            .must_ask(&tenant, &request, &ana)
            .await
            .expect("decided")
    );
    assert!(
        world
            .consent
            .list(&tenant, ana.user_id)
            .await
            .expect("listed")
            .is_empty()
    );
    assert_eq!(
        world
            .consent
            .withdraw(
                &tenant,
                ana.user_id,
                client_id,
                ConsentActor::Person,
                Caller::system()
            )
            .await
            .expect_err("once")
            .code(),
        "oauth.consent_not_found"
    );
    let types: Vec<String> = world
        .units
        .committed_events()
        .iter()
        .map(|event| event.event_type.clone())
        .collect();
    assert!(types.contains(&"oauth.consent_given".to_owned()));
    assert!(types.contains(&"oauth.consent_withdrawn".to_owned()));
    assert_eq!(
        types.iter().filter(|t| *t == "oauth.grant_revoked").count(),
        2
    );
}

#[tokio::test]
async fn a_client_that_registered_itself_is_asked_for_and_shown_in_its_own_words() {
    use hodor_oauth::api::{RegisterClient, RegistrationSettings, RegistrationWay};

    let world = world();
    let tenant = a_tenant();
    let application = world
        .applications
        .create_application(
            &tenant,
            ApplicationSettings {
                name: "Registered clients".to_owned(),
                first_party: false,
            },
            Caller::system(),
        )
        .await
        .expect("application");
    world
        .registration
        .replace(
            &tenant,
            RegistrationSettings {
                enabled: true,
                application_id: Some(application.id()),
                ways: vec![RegistrationWay::Open],
                ..RegistrationSettings::default()
            },
            Caller::system(),
        )
        .await
        .expect("on");
    let (client, _) = world
        .applications
        .register_client(
            &world.registration,
            &tenant,
            RegisterClient {
                body: serde_json::json!({
                    "redirect_uris": [REDIRECT],
                    "client_name": "Partner portal",
                    "logo_uri": "https://billing.example.com/logo.png",
                    "tos_uri": "https://billing.example.com/terms"
                }),
                initial_access_token: None,
                address_hash: None,
            },
            Caller::system(),
        )
        .await
        .expect("registered");
    // The application is made first party afterwards: the registered
    // client still asks.
    world
        .applications
        .change_application(
            &tenant,
            application.id(),
            ApplicationSettings {
                name: "Registered clients".to_owned(),
                first_party: true,
            },
            Caller::system(),
        )
        .await
        .expect("first party");
    let request = checked(&world, &tenant, &client.id().to_string(), "openid", &[]).await;
    assert!(
        !request.first_party,
        "a registered client is never first party"
    );

    let ana = person();
    let (id, secret) = world
        .consent
        .hold(&tenant, request.clone(), &ana)
        .await
        .expect("held");
    let question = world
        .consent
        .describe(&tenant, id, secret.expose(), ana.user_id, ana.session_id)
        .await
        .expect("described")
        .expect("waiting");
    assert_eq!(question.application, "Partner portal");
    let described = question.registered.expect("its own words");
    assert_eq!(
        described.logo_uri.as_deref(),
        Some("https://billing.example.com/logo.png")
    );
    assert_eq!(
        described.tos_uri.as_deref(),
        Some("https://billing.example.com/terms")
    );
    assert_eq!(described.policy_uri, None);
    assert_eq!(described.client_uri, None);

    agree(&world, &tenant, request, &ana).await;
    let listed = world
        .consent
        .list(&tenant, ana.user_id)
        .await
        .expect("listed");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].application, "Partner portal");
}

#[tokio::test]
async fn a_client_an_administrator_made_shows_nothing_it_chose() {
    let world = world();
    let tenant = a_tenant();
    let client = registered(&world, &tenant).await;
    let ana = person();
    let request = checked(&world, &tenant, &client, "openid", &[]).await;
    let (id, secret) = world
        .consent
        .hold(&tenant, request, &ana)
        .await
        .expect("held");
    let question = world
        .consent
        .describe(&tenant, id, secret.expose(), ana.user_id, ana.session_id)
        .await
        .expect("described")
        .expect("waiting");
    assert_eq!(question.application, "Billing");
    assert_eq!(question.registered, None);
}
