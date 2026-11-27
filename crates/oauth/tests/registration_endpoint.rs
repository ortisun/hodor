//! The registration endpoint's use case, on the in-memory stores: a client
//! that registers itself, each way that allows it, each refusal, the
//! bounds, and the addresses Hodor calls only for a caller it admitted.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "The registration
//! endpoint".

use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, Clock as _, DestinationCheck, DomainError, ErrorKind, TenantContext, TenantId,
    Timestamp,
};
use hodor_oauth::api::{
    ApplicationId, ApplicationPorts, ApplicationService, ApplicationSettings, AuthenticationMethod,
    Client, ClientRegistrationService, ClientSecretValue, ClientSettings, ClientType, CreateClient,
    GrantType, IdTokenAlgorithm, InitialAccessTokenId, InitialAccessTokenStatus,
    MOST_REGISTRATIONS_PER_ADDRESS, NewInitialAccessToken, RegisterClient, RegistrationPolicy,
    RegistrationSettings, RegistrationWay,
};
use hodor_oauth::testing::{
    DistinctRandom, FakeDestinations, InMemoryStores, SectorDocuments, client_registration_service,
};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use time::Duration;

/// A destination check that counts how often it is asked.
#[derive(Default)]
struct Counted(AtomicUsize);

impl Counted {
    fn asked(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl DestinationCheck for Counted {
    async fn check(&self, url: &str) -> Result<(), DomainError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        FakeDestinations.check(url).await
    }
}

struct World {
    units: InMemoryUnitOfWorkFactory,
    clock: Arc<FixedClock>,
    applications: ApplicationService,
    registration: ClientRegistrationService,
    destinations: Arc<Counted>,
    sector_documents: SectorDocuments,
}

fn world() -> World {
    let units = InMemoryUnitOfWorkFactory::default();
    let stores = InMemoryStores::default();
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + Duration::days(20_000),
    ));
    let registration = client_registration_service(Arc::new(units.clone()), &stores, clock.clone());
    let destinations = Arc::new(Counted::default());
    let sector_documents = SectorDocuments::default();
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(units.clone()),
        applications: Arc::new(stores.applications),
        clients: Arc::new(stores.clients),
        resource_servers: Arc::new(stores.resource_servers),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    })
    .with_destinations(destinations.clone())
    .with_sector_documents(Arc::new(sector_documents.clone()));
    World {
        units,
        clock,
        applications,
        registration,
        destinations,
        sector_documents,
    }
}

fn tenant() -> TenantContext {
    TenantContext::assume(TenantId::generate())
}

const CALLBACK: &str = "https://portal.partner.example/callback";

fn body() -> Value {
    json!({ "redirect_uris": [CALLBACK], "client_name": "Partner portal" })
}

fn with(member: &str, value: Value) -> Value {
    let mut body = body();
    body[member] = value;
    body
}

impl World {
    async fn application(&self, tenant: &TenantContext, first_party: bool) -> ApplicationId {
        self.applications
            .create_application(
                tenant,
                ApplicationSettings {
                    name: "Partners".to_owned(),
                    first_party,
                },
                Caller::system(),
            )
            .await
            .expect("application")
            .id()
    }

    async fn turned_on_with(
        &self,
        tenant: &TenantContext,
        ways: &[RegistrationWay],
        change: impl FnOnce(&mut RegistrationSettings),
    ) -> ApplicationId {
        let application = self.application(tenant, false).await;
        let mut settings = RegistrationSettings {
            enabled: true,
            application_id: Some(application),
            ways: ways.to_vec(),
            ..RegistrationSettings::default()
        };
        change(&mut settings);
        self.registration
            .replace(tenant, settings, Caller::system())
            .await
            .expect("on");
        application
    }

    async fn turned_on(&self, tenant: &TenantContext, ways: &[RegistrationWay]) -> ApplicationId {
        self.turned_on_with(tenant, ways, |_| {}).await
    }

    async fn token(
        &self,
        tenant: &TenantContext,
        max_registrations: u32,
    ) -> (InitialAccessTokenId, String) {
        let (token, value) = self
            .registration
            .issue_token(
                tenant,
                NewInitialAccessToken {
                    name: "Partner portal team".to_owned(),
                    lifetime: Duration::days(7),
                    max_registrations,
                },
                Caller::system(),
            )
            .await
            .expect("token");
        (token.id(), value.expose().to_owned())
    }

    async fn register_from(
        &self,
        tenant: &TenantContext,
        token: Option<&str>,
        body: Value,
        address: Option<[u8; 32]>,
    ) -> Result<(Client, Option<ClientSecretValue>), DomainError> {
        self.applications
            .register_client(
                &self.registration,
                tenant,
                RegisterClient {
                    body,
                    initial_access_token: token.map(str::to_owned),
                    address_hash: address,
                },
                Caller::system(),
            )
            .await
            .map(|registered| (registered.client, registered.secret))
    }

    async fn register(
        &self,
        tenant: &TenantContext,
        token: Option<&str>,
        body: Value,
    ) -> Result<(Client, Option<ClientSecretValue>), DomainError> {
        self.register_from(tenant, token, body, Some([7; 32])).await
    }

    async fn registrations_of(&self, tenant: &TenantContext, id: InitialAccessTokenId) -> u32 {
        self.registration
            .token(tenant, id)
            .await
            .expect("token")
            .snapshot()
            .registrations
    }

    async fn clients_of(&self, tenant: &TenantContext, application: ApplicationId) -> Vec<Client> {
        self.applications
            .clients(tenant, application)
            .await
            .expect("clients")
    }
}

#[tokio::test]
async fn a_client_registers_itself_with_an_initial_access_token() {
    let world = world();
    let acme = tenant();
    let application = world
        .turned_on(&acme, &[RegistrationWay::InitialAccessToken])
        .await;
    let (token_id, token) = world.token(&acme, 1).await;

    let (client, secret) = world
        .register(&acme, Some(&token), body())
        .await
        .expect("registered");
    let secret = secret.expect("a secret method gets its first secret");
    assert!(client.is_registered());
    assert_eq!(client.application_id(), application);
    assert_eq!(client.client_type(), ClientType::Confidential);
    assert!(client.is_enabled());
    let settings = &client.snapshot().settings;
    assert_eq!(settings.name, "Partner portal");
    assert_eq!(settings.id_token_algorithm, IdTokenAlgorithm::Rs256);
    assert!(
        settings.require_pkce,
        "a registered client always uses PKCE"
    );
    assert_eq!(settings.principal, None);
    assert!(client.accepts_secret(secret.expose(), &FakeDigest, world.clock.now()));
    assert_eq!(
        client
            .snapshot()
            .self_registration
            .and_then(|r| r.address_hash),
        Some([7; 32])
    );

    // Stored in the application of registered clients, and the token spent.
    let stored = world.clients_of(&acme, application).await;
    assert_eq!(stored.len(), 1);
    assert!(stored[0].is_registered());
    assert_eq!(world.registrations_of(&acme, token_id).await, 1);
    let token = world
        .registration
        .token(&acme, token_id)
        .await
        .expect("token");
    assert_eq!(
        token.status(world.clock.now()),
        InitialAccessTokenStatus::UsedUp
    );
    let events = world.units.committed_event_types();
    for event in [
        "oauth.client_created",
        "oauth.client_secret_issued",
        "oauth.initial_access_token_used",
        "oauth.client_registered",
    ] {
        assert!(
            events.iter().any(|kind| kind == event),
            "{event}: {events:?}"
        );
    }
    let registered = world
        .units
        .committed_events()
        .into_iter()
        .find(|event| event.event_type == "oauth.client_registered")
        .expect("recorded");
    assert_eq!(registered.payload["way"], "initial_access_token");
    assert_eq!(registered.payload["token_id"], token_id.to_string());
    assert!(registered.payload.get("address_hash").is_none());
}

#[tokio::test]
async fn an_open_tenant_takes_a_registration_without_a_token_and_never_takes_a_token_for_none() {
    let world = world();
    let acme = tenant();
    let application = world.turned_on(&acme, &[RegistrationWay::Open]).await;
    let error = world
        .register(
            &acme,
            None,
            with("token_endpoint_auth_method", json!("client_secret_post")),
        )
        .await
        .expect_err("the policy does not allow `client_secret_post`");
    assert_eq!(error.code(), "oauth.registration_method_not_allowed");
    let (client, _) = world.register(&acme, None, body()).await.expect("open");
    assert!(client.is_registered());
    let registered = world
        .units
        .committed_events()
        .into_iter()
        .find(|event| event.event_type == "oauth.client_registered")
        .expect("recorded");
    assert_eq!(registered.payload["way"], "open");
    assert!(registered.payload.get("token_id").is_none());
    // A token presented where only open registration is allowed is
    // refused, not taken for an open registration.
    let error = world
        .register(
            &acme,
            Some("hodor_iat_0000000000000000000000000000000000000000000000000000000000000000"),
            body(),
        )
        .await
        .expect_err("a token, where tokens are not allowed");
    assert_eq!(error.code(), "oauth.initial_access_token_invalid");
    assert_eq!(world.clients_of(&acme, application).await.len(), 1);
}

#[tokio::test]
async fn registration_off_is_no_address_and_a_missing_or_bad_token_registers_nothing() {
    let world = world();
    let acme = tenant();
    for token in [None, Some("anything")] {
        let error = world.register(&acme, token, body()).await.expect_err("off");
        assert_eq!(error.code(), "oauth.client_registration_off");
        assert_eq!(error.kind(), ErrorKind::NotFound);
    }

    let application = world
        .turned_on(&acme, &[RegistrationWay::InitialAccessToken])
        .await;
    let error = world
        .register(&acme, None, body())
        .await
        .expect_err("needs one");
    assert_eq!(error.code(), "oauth.initial_access_token_required");
    assert_eq!(error.kind(), ErrorKind::Unauthenticated);
    for token in [
        "",
        "not a token",
        "hodor_iat_0000000000000000000000000000000000000000000000000000000000000000",
    ] {
        let error = world
            .register(&acme, Some(token), body())
            .await
            .expect_err(token);
        assert_eq!(
            error.code(),
            "oauth.initial_access_token_invalid",
            "{token}"
        );
        assert_eq!(error.kind(), ErrorKind::Unauthenticated);
    }
    assert!(world.clients_of(&acme, application).await.is_empty());
    assert!(
        !world
            .units
            .committed_event_types()
            .iter()
            .any(|kind| kind == "oauth.client_registered")
    );
}

#[tokio::test]
async fn a_refused_registration_spends_nothing_and_stores_nothing() {
    let world = world();
    let acme = tenant();
    let application = world
        .turned_on(&acme, &[RegistrationWay::InitialAccessToken])
        .await;
    let (token_id, token) = world.token(&acme, 1).await;
    for (body, code) in [
        (json!(["not an object"]), "oauth.client_metadata_invalid"),
        (
            with("software_statement", json!("eyJhbGciOiJSUzI1NiJ9.e30.c2ln")),
            "oauth.software_statement_unapproved",
        ),
        (
            with("userinfo_encrypted_response_alg", json!("RSA-OAEP")),
            "oauth.registration_member_not_supported",
        ),
        (
            with("jwks_uri", json!("https://portal.partner.example/jwks")),
            "oauth.client_jwks_uri_invalid",
        ),
        (
            json!({ "redirect_uris": ["https://portal.partner.example/cb#fragment"] }),
            "oauth.client_redirect_uri_invalid",
        ),
        (json!({}), "oauth.client_redirect_uri_invalid"),
        (
            with(
                "grant_types",
                json!(["authorization_code", "refresh_token"]),
            ),
            "oauth.registration_grant_not_allowed",
        ),
        (
            // A client without the code grant has no redirect address.
            with("grant_types", json!(["client_credentials"])),
            "oauth.client_redirect_uri_invalid",
        ),
        (
            with("response_types", json!(["code id_token token"])),
            "oauth.client_response_types_invalid",
        ),
        (
            with("scope", json!("openid groups")),
            "oauth.registration_scope_not_allowed",
        ),
        (
            with("token_endpoint_auth_method", json!("none")),
            "oauth.registration_method_not_allowed",
        ),
        (
            // A method of workloads breaks a rule of every client first.
            with("token_endpoint_auth_method", json!("spiffe_jwt")),
            "oauth.client_spiffe_id_invalid",
        ),
        (
            with("subject_type", json!("pairwise")),
            "oauth.registration_subject_type_not_allowed",
        ),
        (
            with("logo_uri", json!("http://portal.partner.example/logo.png")),
            "oauth.client_display_uri_invalid",
        ),
        (
            json!({
                "redirect_uris": ["https://portal.partner.example/callback"],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": { "keys": [{ "kty": "oct", "kid": "one", "k": "c2VjcmV0" }] }
            }),
            "oauth.client_key_invalid",
        ),
        (
            with(
                "initiate_login_uri",
                json!("http://portal.partner.example/start"),
            ),
            "oauth.client_initiate_login_uri_invalid",
        ),
    ] {
        let error = world
            .register(&acme, Some(&token), body.clone())
            .await
            .expect_err(code);
        assert_eq!(error.code(), code, "{body}");
    }
    assert!(world.clients_of(&acme, application).await.is_empty());
    assert_eq!(world.registrations_of(&acme, token_id).await, 0);
    // The token still allows its registration.
    world
        .register(&acme, Some(&token), body())
        .await
        .expect("still good");
    assert_eq!(world.registrations_of(&acme, token_id).await, 1);
}

#[tokio::test]
async fn the_policy_bounds_the_hosts_of_every_address() {
    let world = world();
    let acme = tenant();
    world
        .turned_on_with(&acme, &[RegistrationWay::Open], |settings| {
            settings.policy = RegistrationPolicy {
                hosts: Some(vec!["portal.partner.example".to_owned()]),
                ..RegistrationPolicy::default()
            };
        })
        .await;
    let error = world
        .register(
            &acme,
            None,
            json!({ "redirect_uris": ["https://elsewhere.example/callback"] }),
        )
        .await
        .expect_err("redirect elsewhere");
    assert_eq!(error.code(), "oauth.registration_redirect_host_not_allowed");
    for (member, address) in [
        ("logo_uri", json!("https://cdn.elsewhere.example/logo.png")),
        ("policy_uri", json!("https://elsewhere.example/privacy")),
        ("client_uri", json!("https://sub.portal.partner.example/")),
        (
            "request_uris",
            json!(["https://elsewhere.example/requests/"]),
        ),
    ] {
        let error = world
            .register(&acme, None, with(member, address))
            .await
            .expect_err(member);
        assert_eq!(
            error.code(),
            "oauth.registration_host_not_allowed",
            "{member}"
        );
    }
    world
        .register(
            &acme,
            None,
            with("logo_uri", json!("https://portal.partner.example/logo.png")),
        )
        .await
        .expect("a listed host");
}

#[tokio::test]
async fn an_address_registers_at_most_ten_clients_a_minute() {
    let world = world();
    let acme = tenant();
    let application = world
        .turned_on(&acme, &[RegistrationWay::InitialAccessToken])
        .await;
    let (token_id, token) = world.token(&acme, 50).await;
    let here = Some([1; 32]);
    for _ in 0..MOST_REGISTRATIONS_PER_ADDRESS {
        world
            .register_from(&acme, Some(&token), body(), here)
            .await
            .expect("within the bound");
    }
    let error = world
        .register_from(&acme, Some(&token), body(), here)
        .await
        .expect_err("the eleventh");
    assert_eq!(error.code(), "oauth.too_many_registrations");
    assert_eq!(error.kind(), ErrorKind::RateLimited);
    assert_eq!(error.retry_after_seconds(), Some(60));
    assert_eq!(
        world.registrations_of(&acme, token_id).await,
        u32::try_from(MOST_REGISTRATIONS_PER_ADDRESS).expect("small")
    );

    // Another address, and addresses that are not known, count apart.
    world
        .register_from(&acme, Some(&token), body(), Some([2; 32]))
        .await
        .expect("another address");
    for _ in 0..MOST_REGISTRATIONS_PER_ADDRESS {
        world
            .register_from(&acme, Some(&token), body(), None)
            .await
            .expect("unknown addresses");
    }
    assert_eq!(
        world
            .register_from(&acme, Some(&token), body(), None)
            .await
            .expect_err("unknown addresses are counted together")
            .code(),
        "oauth.too_many_registrations"
    );

    // A minute later the address may register again.
    world.clock.advance(Duration::seconds(61));
    world
        .register_from(&acme, Some(&token), body(), here)
        .await
        .expect("a minute later");
    assert_eq!(world.clients_of(&acme, application).await.len(), 22);
}

#[tokio::test]
async fn the_application_of_registered_clients_holds_at_most_its_bound() {
    let world = world();
    let acme = tenant();
    let application = world
        .turned_on_with(&acme, &[RegistrationWay::Open], |settings| {
            settings.max_clients = 2;
        })
        .await;
    // A client an administrator made there counts too.
    world
        .applications
        .create_client(
            &acme,
            CreateClient {
                application_id: application,
                client_type: ClientType::Confidential,
                settings: ClientSettings::new(
                    "Made by hand",
                    ClientType::Confidential,
                    vec![GrantType::AuthorizationCode],
                    vec![CALLBACK.to_owned()],
                ),
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("by hand");
    world
        .register_from(&acme, None, body(), Some([1; 32]))
        .await
        .expect("the second");
    let error = world
        .register_from(&acme, None, body(), Some([2; 32]))
        .await
        .expect_err("the third");
    assert_eq!(error.code(), "oauth.too_many_registered_clients");
    assert_eq!(error.kind(), ErrorKind::Forbidden);
    assert_eq!(world.clients_of(&acme, application).await.len(), 2);
}

#[tokio::test]
async fn no_address_is_called_for_a_caller_who_may_not_register() {
    let world = world();
    let acme = tenant();
    world
        .turned_on_with(&acme, &[RegistrationWay::InitialAccessToken], |settings| {
            settings.policy.subject_types = vec![
                hodor_oauth::api::SubjectType::Public,
                hodor_oauth::api::SubjectType::Pairwise,
            ];
        })
        .await;
    let (_, token) = world.token(&acme, 5).await;
    let calling = json!({
        "redirect_uris": [CALLBACK],
        "backchannel_logout_uri": "https://portal.partner.example/logout",
        "request_uris": ["https://portal.partner.example/requests/"],
        "require_pushed_authorization_requests": true,
        "subject_type": "pairwise",
        "sector_identifier_uri": "https://portal.partner.example/sector.json"
    });
    world.sector_documents.answer(
        "https://portal.partner.example/sector.json",
        200,
        &json!([CALLBACK]).to_string(),
    );
    for token in [
        None,
        Some("hodor_iat_0000000000000000000000000000000000000000000000000000000000000000"),
    ] {
        world
            .register(&acme, token, calling.clone())
            .await
            .expect_err("not admitted");
    }
    assert_eq!(world.destinations.asked(), 0);
    assert_eq!(world.sector_documents.fetched(), 0);

    let (client, _) = world
        .register(&acme, Some(&token), calling.clone())
        .await
        .expect("admitted");
    assert_eq!(
        client.backchannel_logout_uri(),
        Some("https://portal.partner.example/logout")
    );
    assert_eq!(client.sector().as_deref(), Some("portal.partner.example"));
    assert_eq!(
        client.snapshot().settings.request_uris,
        vec!["https://portal.partner.example/requests/"]
    );
    assert!(client.snapshot().settings.require_pushed_requests);
    // The back-channel logout address, the request object address and the
    // sector identifier address.
    assert_eq!(world.destinations.asked(), 3);
    assert_eq!(world.sector_documents.fetched(), 1);

    // An address that may not be called, and a document that does not list
    // the redirect address, are refused as for an administrator's client.
    let error = world
        .register(
            &acme,
            Some(&token),
            json!({
                "redirect_uris": [CALLBACK],
                "backchannel_logout_uri": "https://169.254.169.254/latest"
            }),
        )
        .await
        .expect_err("inside the network");
    assert_eq!(
        error.code(),
        "oauth.client_backchannel_logout_uri_forbidden"
    );
    let error = world
        .register(
            &acme,
            Some(&token),
            json!({
                "redirect_uris": [CALLBACK],
                "request_uris": ["https://10.0.0.7/requests/"]
            }),
        )
        .await
        .expect_err("inside the network");
    assert_eq!(error.code(), "oauth.client_request_uri_forbidden");
    world.sector_documents.answer(
        "https://portal.partner.example/other.json",
        200,
        &json!(["https://portal.partner.example/other"]).to_string(),
    );
    let mut mismatched = calling;
    mismatched["sector_identifier_uri"] = json!("https://portal.partner.example/other.json");
    let error = world
        .register(&acme, Some(&token), mismatched)
        .await
        .expect_err("not listed");
    assert_eq!(error.code(), "oauth.client_sector_identifier_uri_mismatch");
}

#[tokio::test]
async fn a_client_of_private_key_jwt_registers_with_its_keys_checked_as_an_administrators() {
    let world = world();
    let acme = tenant();
    world.turned_on(&acme, &[RegistrationWay::Open]).await;
    let key = |kid: &str| {
        json!({
            "kty": "EC", "crv": "P-256", "kid": kid,
            "x": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
            "y": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"
        })
    };
    let (client, secret) = world
        .register(
            &acme,
            None,
            json!({
                "redirect_uris": [CALLBACK],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": { "keys": [key("one"), key("two")] }
            }),
        )
        .await
        .expect("registered");
    assert!(secret.is_none());
    assert_eq!(
        client.snapshot().settings.authentication_method,
        AuthenticationMethod::PrivateKeyJwt
    );
    assert_eq!(client.snapshot().keys.len(), 2);
    for (keys, code) in [
        (vec![key("one"), key("one")], "oauth.client_key_taken"),
        (
            (0..6).map(|n| key(&format!("k{n}"))).collect(),
            "oauth.client_too_many_keys",
        ),
        (
            vec![json!({ "kty": "EC", "crv": "P-256", "kid": "private", "d": "AA" })],
            "oauth.client_key_invalid",
        ),
    ] {
        let error = world
            .register(
                &acme,
                None,
                json!({
                    "redirect_uris": [CALLBACK],
                    "token_endpoint_auth_method": "private_key_jwt",
                    "jwks": { "keys": keys }
                }),
            )
            .await
            .expect_err(code);
        assert_eq!(error.code(), code);
    }
}

#[tokio::test]
async fn registration_turned_off_since_admission_registers_nothing() {
    let world = world();
    let acme = tenant();
    let application = world.turned_on(&acme, &[RegistrationWay::Open]).await;
    world
        .registration
        .replace(
            &acme,
            RegistrationSettings {
                enabled: false,
                application_id: Some(application),
                ways: vec![RegistrationWay::Open],
                ..RegistrationSettings::default()
            },
            Caller::system(),
        )
        .await
        .expect("off");
    let error = world.register(&acme, None, body()).await.expect_err("off");
    assert_eq!(error.code(), "oauth.client_registration_off");
    assert!(world.clients_of(&acme, application).await.is_empty());
}

#[tokio::test]
async fn a_registration_of_one_tenant_is_nowhere_in_another() {
    let world = world();
    let (acme, globex) = (tenant(), tenant());
    let acme_partners = world
        .turned_on(&acme, &[RegistrationWay::InitialAccessToken])
        .await;
    let globex_partners = world
        .turned_on(&globex, &[RegistrationWay::InitialAccessToken])
        .await;
    let (acme_token_id, acme_token) = world.token(&acme, 1).await;
    let error = world
        .register(&globex, Some(&acme_token), body())
        .await
        .expect_err("unknown at Globex");
    assert_eq!(error.code(), "oauth.initial_access_token_invalid");
    assert_eq!(world.registrations_of(&acme, acme_token_id).await, 0);

    let (client, _) = world
        .register(&acme, Some(&acme_token), body())
        .await
        .expect("at Acme");
    assert_eq!(
        world
            .applications
            .client(&globex, client.id())
            .await
            .expect_err("not Globex's")
            .code(),
        "oauth.client_not_found"
    );
    assert!(world.clients_of(&globex, globex_partners).await.is_empty());
    assert_eq!(world.clients_of(&acme, acme_partners).await.len(), 1);
}

#[tokio::test]
async fn a_client_of_private_key_jwt_registers_with_its_key_set_address() {
    let world = world();
    let acme = tenant();
    world.turned_on(&acme, &[RegistrationWay::Open]).await;
    let (client, secret) = world
        .register(
            &acme,
            None,
            json!({
                "redirect_uris": [CALLBACK],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks_uri": "https://portal.partner.example/jwks"
            }),
        )
        .await
        .expect("registered");
    assert!(secret.is_none());
    assert!(client.snapshot().keys.is_empty());
    assert_eq!(
        client.jwks_uri(),
        Some("https://portal.partner.example/jwks")
    );
    // Checked by the guarded client's destination check, and not fetched.
    assert_eq!(world.destinations.asked(), 1);
    assert_eq!(world.sector_documents.fetched(), 0);

    for (body, code) in [
        (
            json!({
                "redirect_uris": [CALLBACK],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks_uri": "https://10.0.0.7/jwks"
            }),
            "oauth.client_jwks_uri_forbidden",
        ),
        (
            json!({
                "redirect_uris": [CALLBACK],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks_uri": "https://portal.partner.example/jwks",
                "jwks": { "keys": [{
                    "kty": "EC", "crv": "P-256", "kid": "one",
                    "x": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
                    "y": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"
                }] }
            }),
            "oauth.client_metadata_invalid",
        ),
    ] {
        let error = world.register(&acme, None, body).await.expect_err(code);
        assert_eq!(error.code(), code);
    }
}

#[tokio::test]
async fn response_types_are_kept_within_the_policy() {
    use hodor_oauth::api::ResponseType;
    let world = world();
    let acme = tenant();
    world.turned_on(&acme, &[RegistrationWay::Open]).await;
    let browser = json!({
        "redirect_uris": [CALLBACK],
        "grant_types": ["authorization_code", "implicit"],
        "response_types": ["code", "id_token"]
    });
    // The default policy allows `code` alone.
    let error = world
        .register(&acme, None, browser.clone())
        .await
        .expect_err("not allowed");
    assert_eq!(error.code(), "oauth.registration_response_type_not_allowed");

    let other = tenant();
    world
        .turned_on_with(&other, &[RegistrationWay::Open], |settings| {
            settings.policy.response_types = vec![ResponseType::Code, ResponseType::IdToken];
        })
        .await;
    let (client, _) = world
        .register(&other, None, browser)
        .await
        .expect("registered");
    let settings = &client.snapshot().settings;
    assert_eq!(
        settings.response_types,
        vec![ResponseType::Code, ResponseType::IdToken]
    );
    assert_eq!(settings.grant_types, vec![GrantType::AuthorizationCode]);
    let answer = hodor_oauth::api::registration_answer(&client, None, None);
    assert_eq!(answer["response_types"], json!(["code", "id_token"]));
    assert_eq!(answer["grant_types"], json!(["authorization_code"]));
}
