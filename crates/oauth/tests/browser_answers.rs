//! The answers of the authorization endpoint through the browser, through
//! the use cases on the in-memory stores: what each response type makes,
//! and the ID token that comes through the browser with its hashes and the
//! person's claims. Specified in `docs/architecture/contexts/oauth.md`,
//! "Response types and modes" and "The ID token through the browser".

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_identity::api::{PostalAddress, StandardClaims};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::sealing::testing::FakeSecretBox;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, Clock as _, CorrelationId, TenantContext, TenantId, Timestamp, UnitOfWorkFactory as _,
    UserId,
};
use hodor_keys::api::{KeyAlgorithm, KeyService, RotationPolicy};
use hodor_keys::testing::{FakeKeyProvider, InMemoryKeys};
use hodor_oauth::api::{
    ApplicationId, ApplicationPorts, ApplicationService, ApplicationSettings,
    AuthorizationCodePorts, AuthorizationCodeService, AuthorizationParameters,
    AuthorizationRequest, ClaimMapperPorts, ClaimMapperService, ClaimMapperSettings, ClaimMapping,
    ClaimSource, ClaimTarget, ClientId, ClientSettings, ClientType, ConsentPorts, ConsentService,
    CreateClient, GrantStore as _, GrantType, IdTokenAlgorithm, Issuer, PersonAttributes,
    ResponseMode, ResponseType, SignedInPerson, TokenPorts, TokenRequest, TokenService,
    left_half_hash, s256_challenge,
};
use hodor_oauth::testing::{
    ClaimSourcesOf, DistinctRandom, FakeVerifier, InMemoryAccessTokenRecords,
    InMemoryAuthorizationCodes, InMemoryAuthorizationRequests, InMemoryClaimMappers,
    InMemoryClientAssertions, InMemoryConsents, InMemoryGrants, InMemoryRefreshTokens,
    InMemoryStores, MembershipsOf, StandingOf,
};
use hodor_session::api::SessionId;
use serde_json::{Value, json};
use std::sync::Arc;
use time::Duration;

const REDIRECT: &str = "https://payroll.example.com/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const ISSUER: &str = "https://hodor.example.com/t/acme";
const ENDPOINT: &str = "https://hodor.example.com/t/acme/oauth2/token";
const NONCE: &str = "n-0S6_WzA2Mj";
const STATE: &str = "af0ifjsldkj";

const ISSUER_OF: Issuer<'static> = Issuer {
    issuer: ISSUER,
    token_endpoint: ENDPOINT,
};

struct World {
    units: InMemoryUnitOfWorkFactory,
    clock: Arc<FixedClock>,
    grants: InMemoryGrants,
    sources: ClaimSourcesOf,
    codes: AuthorizationCodeService,
    consent: ConsentService,
    applications: ApplicationService,
    mappers: ClaimMapperService,
    keys: KeyService,
    tokens: TokenService,
}

fn world() -> World {
    let units = InMemoryUnitOfWorkFactory::default();
    let stores = InMemoryStores::default();
    let requests = InMemoryAuthorizationRequests::new(&stores.clients);
    let grants = InMemoryGrants::new(&stores.clients);
    let code_store = InMemoryAuthorizationCodes::new(&grants);
    let families = InMemoryRefreshTokens::new(&grants);
    let mapper_store = InMemoryClaimMappers::new(&stores.clients);
    let memberships = MembershipsOf::default();
    let sources = ClaimSourcesOf::default();
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + Duration::days(20_000),
    ));
    let codes = AuthorizationCodeService::new(AuthorizationCodePorts {
        units_of_work: Arc::new(units.clone()),
        applications: Arc::new(stores.applications.clone()),
        clients: Arc::new(stores.clients.clone()),
        resource_servers: Arc::new(stores.resource_servers.clone()),
        requests: Arc::new(requests.clone()),
        grants: Arc::new(grants.clone()),
        codes: Arc::new(code_store),
        memberships: Arc::new(memberships.clone()),
        verifier: Arc::new(FakeVerifier),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    let consent = ConsentService::new(ConsentPorts {
        units_of_work: Arc::new(units.clone()),
        consents: Arc::new(InMemoryConsents::new(&stores.clients)),
        requests: Arc::new(requests),
        grants: Arc::new(grants.clone()),
        clients: Arc::new(stores.clients.clone()),
        applications: Arc::new(stores.applications.clone()),
        resource_servers: Arc::new(stores.resource_servers.clone()),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    let keys = KeyService::new(
        Arc::new(units.clone()),
        Arc::new(InMemoryKeys::default()),
        Arc::new(FakeKeyProvider),
        clock.clone(),
    );
    let tokens = TokenService::new(TokenPorts {
        units_of_work: Arc::new(units.clone()),
        applications: Arc::new(stores.applications.clone()),
        clients: Arc::new(stores.clients.clone()),
        resource_servers: Arc::new(stores.resource_servers.clone()),
        grants: Arc::new(grants.clone()),
        assertions: Arc::new(InMemoryClientAssertions::new(&stores.clients)),
        refresh_tokens: Arc::new(families),
        access_tokens: Arc::new(InMemoryAccessTokenRecords::new(&stores.clients)),
        standing: Arc::new(StandingOf::default()),
        memberships: Arc::new(memberships.clone()),
        mapping: ClaimMapping::new(
            Arc::new(units.clone()),
            Arc::new(mapper_store.clone()),
            Arc::new(memberships),
            Arc::new(sources.clone()),
        ),
        secrets: Arc::new(FakeSecretBox),
        codes: codes.clone(),
        keys: keys.clone(),
        verifier: Arc::new(FakeVerifier),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    let mappers = ClaimMapperService::new(ClaimMapperPorts {
        units_of_work: Arc::new(units.clone()),
        clients: Arc::new(stores.clients.clone()),
        mappers: Arc::new(mapper_store),
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
        sources,
        codes,
        consent,
        applications,
        mappers,
        keys,
        tokens,
    }
}

/// A tenant with an active signing key and an application, first party or
/// not.
async fn tenant(world: &World, first_party: bool) -> (TenantContext, ApplicationId) {
    let tenant = TenantContext::assume(TenantId::generate());
    world
        .keys
        .rotate_now(
            &tenant,
            KeyAlgorithm::Es256,
            &RotationPolicy::DEFAULT,
            Caller::system(),
        )
        .await
        .expect("a signing key");
    let application = world
        .applications
        .create_application(
            &tenant,
            ApplicationSettings {
                name: "Payroll".to_owned(),
                first_party,
            },
            Caller::system(),
        )
        .await
        .expect("application");
    (tenant, application.id())
}

/// Ana, with every claim the tests read.
fn ana(world: &World, tenant: &TenantContext) -> SignedInPerson {
    let person = SignedInPerson {
        user_id: UserId::generate(),
        session_id: SessionId::generate(),
        signed_in_at: world.clock.now() - Duration::minutes(2),
        methods: vec!["password".to_owned()],
        acr: Some("urn:hodor:acr:single-factor".to_owned()),
    };
    world.sources.set_attributes(
        tenant.tenant_id(),
        person.user_id,
        PersonAttributes {
            display_name: Some("Ana Silva".to_owned()),
            username: Some("ana".to_owned()),
            email: Some(("ana@example.com".to_owned(), true)),
            locale: Some("pt-BR".to_owned()),
            claims: StandardClaims {
                given_name: Some("Ana".to_owned()),
                phone_number: Some("+5511999990000".to_owned()),
                ..StandardClaims::default()
            },
            updated_at: Some(world.clock.now() - Duration::days(1)),
        },
    );
    person
}

/// A public client of every response type that may ask for `scopes`.
async fn client(
    world: &World,
    tenant: &TenantContext,
    application: ApplicationId,
    scopes: &[&str],
) -> ClientId {
    client_signing_with(world, tenant, application, scopes, IdTokenAlgorithm::Es256).await
}

/// The same, whose ID tokens are signed with `algorithm`.
async fn client_signing_with(
    world: &World,
    tenant: &TenantContext,
    application: ApplicationId,
    scopes: &[&str],
    algorithm: IdTokenAlgorithm,
) -> ClientId {
    let mut settings = ClientSettings::new(
        "Payroll in the browser",
        ClientType::Public,
        vec![GrantType::AuthorizationCode],
        vec![REDIRECT.to_owned()],
    );
    settings.response_types = ResponseType::ALL.to_vec();
    settings.id_token_algorithm = algorithm;
    settings.allowed_scopes = scopes.iter().map(|scope| (*scope).to_owned()).collect();
    world
        .applications
        .create_client(
            tenant,
            CreateClient {
                application_id: application,
                client_type: ClientType::Public,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client")
        .0
        .id()
}

/// A request of `response_type` for `scope`, with a nonce, a state, a
/// code challenge and `claims`.
async fn checked(
    world: &World,
    tenant: &TenantContext,
    client: ClientId,
    response_type: &str,
    scope: &str,
    claims: &Value,
) -> AuthorizationRequest {
    let challenge = s256_challenge(VERIFIER, &FakeDigest);
    let id = client.to_string();
    let claims = claims.to_string();
    let pairs = [
        ("response_type", response_type),
        ("client_id", id.as_str()),
        ("redirect_uri", REDIRECT),
        ("scope", scope),
        ("state", STATE),
        ("nonce", NONCE),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("claims", claims.as_str()),
    ];
    let parameters = AuthorizationParameters::from_pairs(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
    );
    world
        .codes
        .check(
            tenant,
            ISSUER,
            &parameters,
            &hodor_oauth::api::PushedRequestPolicy::default(),
        )
        .await
        .expect("storage")
        .expect("a valid request")
}

fn claims_of(token: &str) -> Value {
    let part = token.split('.').nth(1).expect("claims");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("json")
}

/// What the endpoint answers `request` with, for `person`: the code, if
/// any, and the ID token, if any, as their texts.
async fn answered(
    world: &World,
    tenant: &TenantContext,
    request: &AuthorizationRequest,
    person: &SignedInPerson,
) -> (Option<String>, Option<String>) {
    let consented = world
        .consent
        .consented_scopes(tenant, request, person)
        .await
        .expect("consented scopes");
    let answer = world
        .codes
        .answer(tenant, request, person, &consented, Caller::system())
        .await
        .expect("answer");
    let code = answer.code.as_ref().map(|code| code.expose().to_owned());
    let id_token = match &answer.grant {
        Some(grant) if request.response_type.returns_id_token() => Some(
            world
                .tokens
                .browser_id_token(tenant, ISSUER, request, grant, person, code.as_deref())
                .await
                .expect("storage")
                .expect("signed")
                .expose()
                .clone(),
        ),
        _ => None,
    };
    (code, id_token)
}

async fn grants_of(world: &World, tenant: &TenantContext, person: &SignedInPerson) -> usize {
    let mut uow = world.units.begin(tenant).await.expect("unit of work");
    world
        .grants
        .list_active_of(uow.as_mut(), person.user_id)
        .await
        .expect("grants")
        .len()
}

#[tokio::test]
async fn an_id_token_alone_holds_the_claims_of_the_scopes_and_the_hash_of_the_state() {
    let world = world();
    let (tenant, application) = tenant(&world, true).await;
    let payroll = client(
        &world,
        &tenant,
        application,
        &["openid", "profile", "email", "phone", "address", "groups"],
    )
    .await;
    let ana = ana(&world, &tenant);
    let request = checked(
        &world,
        &tenant,
        payroll,
        "id_token",
        "openid profile email phone groups",
        &json!({}),
    )
    .await;
    assert_eq!(request.response_mode, ResponseMode::Fragment);
    let (code, id_token) = answered(&world, &tenant, &request, &ana).await;
    assert!(code.is_none(), "nothing to redeem");
    let claims = claims_of(&id_token.expect("an ID token"));

    // Hodor's own claims, as at the token endpoint.
    assert_eq!(claims["iss"], ISSUER);
    assert_eq!(claims["sub"], ana.user_id.to_string());
    assert_eq!(claims["aud"], payroll.to_string());
    assert_eq!(claims["nonce"], NONCE);
    assert_eq!(claims["auth_time"], ana.signed_in_at.unix_timestamp());
    assert_eq!(claims["acr"], "urn:hodor:acr:single-factor");
    assert_eq!(claims["amr"], json!(["pwd"]));
    assert_eq!(claims["sid"], ana.session_id.to_string());
    assert_eq!(
        claims["s_hash"],
        left_half_hash(STATE, IdTokenAlgorithm::Es256, &FakeDigest)
    );
    for absent in ["c_hash", "at_hash"] {
        assert!(
            claims.get(absent).is_none(),
            "{absent}: nothing came with it"
        );
    }

    // No access token comes with it: the claims of its scopes are here.
    assert_eq!(claims["name"], "Ana Silva");
    assert_eq!(claims["preferred_username"], "ana");
    assert_eq!(claims["given_name"], "Ana");
    assert_eq!(claims["email"], "ana@example.com");
    assert_eq!(claims["email_verified"], true);
    assert_eq!(claims["phone_number"], "+5511999990000");
    assert_eq!(claims["phone_number_verified"], false);
    assert!(
        claims.get("address").is_none(),
        "`address` was not asked for"
    );
    assert!(
        claims.get("groups").is_none(),
        "groups stay out of an ID token"
    );

    // A grant, so that the client hears of the end of the session, and
    // the event of the ID token; never the token itself.
    assert_eq!(grants_of(&world, &tenant, &ana).await, 1);
    let types = world.units.committed_event_types();
    assert!(types.contains(&"oauth.id_token_issued".to_owned()));
    assert!(!types.contains(&"oauth.authorization_code_issued".to_owned()));
}

#[tokio::test]
async fn the_hashes_of_an_eddsa_client_are_the_left_half_of_sha_512() {
    let world = world();
    let (tenant, application) = tenant(&world, true).await;
    let payroll = client_signing_with(
        &world,
        &tenant,
        application,
        &["openid"],
        IdTokenAlgorithm::EdDsa,
    )
    .await;
    let ana = ana(&world, &tenant);
    let request = checked(
        &world,
        &tenant,
        payroll,
        "code id_token",
        "openid",
        &json!({}),
    )
    .await;
    let (code, id_token) = answered(&world, &tenant, &request, &ana).await;
    let code = code.expect("a code");
    let id_token = id_token.expect("an ID token");
    let header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(id_token.split('.').next().expect("header"))
            .expect("base64url"),
    )
    .expect("json");
    assert_eq!(header["alg"], "EdDSA");
    let claims = claims_of(&id_token);
    // The hash of EdDSA is SHA-512, whose left half is 32 bytes: 43
    // characters of base64url, where SHA-256 gives 22.
    for (name, value) in [("c_hash", code.as_str()), ("s_hash", STATE)] {
        let hash = claims[name].as_str().expect(name);
        assert_eq!(
            hash,
            left_half_hash(value, IdTokenAlgorithm::EdDsa, &FakeDigest),
            "{name}"
        );
        assert_eq!(hash.len(), 43, "{name}");
        assert_ne!(
            hash,
            left_half_hash(value, IdTokenAlgorithm::Es256, &FakeDigest),
            "{name}"
        );
    }
}

#[tokio::test]
async fn a_code_and_an_id_token_are_tied_by_c_hash_and_the_code_redeems_for_the_same_person() {
    let world = world();
    let (tenant, application) = tenant(&world, true).await;
    let payroll = client(
        &world,
        &tenant,
        application,
        &["openid", "profile", "email"],
    )
    .await;
    let ana = ana(&world, &tenant);
    let request = checked(
        &world,
        &tenant,
        payroll,
        "code id_token",
        "openid profile",
        &json!({"id_token": {"email": null}}),
    )
    .await;
    let (code, id_token) = answered(&world, &tenant, &request, &ana).await;
    let code = code.expect("a code");
    let claims = claims_of(&id_token.expect("an ID token"));
    assert_eq!(
        claims["c_hash"],
        left_half_hash(&code, IdTokenAlgorithm::Es256, &FakeDigest)
    );
    assert_eq!(
        claims["s_hash"],
        left_half_hash(STATE, IdTokenAlgorithm::Es256, &FakeDigest)
    );
    assert_eq!(claims["nonce"], NONCE);
    // An access token comes from the token endpoint: the claims of the
    // scopes are read at UserInfo, and only those asked for are here.
    assert!(claims.get("name").is_none(), "profile is read at UserInfo");
    assert_eq!(claims["email"], "ana@example.com", "asked through claims");

    let types = world.units.committed_event_types();
    assert!(types.contains(&"oauth.id_token_issued".to_owned()));
    assert!(types.contains(&"oauth.authorization_code_issued".to_owned()));
    for event in world.units.committed_events() {
        assert!(
            !format!("{event:?}").contains(&code),
            "no event carries the code"
        );
    }

    // The code redeems as any code, and the ID token of the token endpoint
    // names the same person for the same nonce.
    let form = vec![
        ("grant_type".to_owned(), "authorization_code".to_owned()),
        ("code".to_owned(), code),
        ("redirect_uri".to_owned(), REDIRECT.to_owned()),
        ("code_verifier".to_owned(), VERIFIER.to_owned()),
        ("client_id".to_owned(), payroll.to_string()),
    ];
    let tokens = world
        .tokens
        .token(
            &tenant,
            ISSUER_OF,
            TokenRequest::parse(None, form).expect("a request"),
            CorrelationId::generate(),
        )
        .await
        .expect("storage")
        .expect("tokens");
    let redeemed = claims_of(tokens.id_token.as_ref().expect("an ID token").expose());
    for same in ["iss", "sub", "nonce", "sid"] {
        assert_eq!(redeemed[same], claims[same], "{same}");
    }
    assert!(redeemed.get("at_hash").is_some());
    assert!(redeemed.get("c_hash").is_none() && redeemed.get("s_hash").is_none());
}

#[tokio::test]
async fn none_makes_nothing_and_records_nothing() {
    let world = world();
    let (tenant, application) = tenant(&world, true).await;
    let payroll = client(&world, &tenant, application, &["openid"]).await;
    let ana = ana(&world, &tenant);
    let request = checked(&world, &tenant, payroll, "none", "openid", &json!({})).await;
    assert_eq!(request.response_mode, ResponseMode::Query);
    let events_before = world.units.committed_event_types().len();
    let (code, id_token) = answered(&world, &tenant, &request, &ana).await;
    assert!(code.is_none() && id_token.is_none());
    assert_eq!(grants_of(&world, &tenant, &ana).await, 0);
    assert_eq!(world.units.committed_event_types().len(), events_before);
}

#[tokio::test]
async fn the_claims_of_the_scopes_share_the_bound_of_the_id_token_with_the_mappers() {
    let world = world();
    let (tenant, application) = tenant(&world, true).await;
    let payroll = client(
        &world,
        &tenant,
        application,
        &["openid", "profile", "email", "address"],
    )
    .await;
    let ana = ana(&world, &tenant);
    world.sources.set_attributes(
        tenant.tenant_id(),
        ana.user_id,
        PersonAttributes {
            display_name: Some("Ana Silva".to_owned()),
            email: Some(("ana@example.com".to_owned(), true)),
            claims: StandardClaims {
                address: Some(PostalAddress {
                    formatted: Some("f".repeat(300)),
                    locality: Some("l".repeat(100)),
                    ..PostalAddress::default()
                }),
                ..StandardClaims::default()
            },
            ..PersonAttributes::default()
        },
    );
    // Mappers of about 3700 bytes in all: the name fits after them, the
    // address does not, and the email address after it fits again.
    for (claim, length) in [
        ("first", 1022),
        ("second", 1022),
        ("third", 1022),
        ("fourth", 600),
    ] {
        world
            .mappers
            .create(
                &tenant,
                payroll,
                ClaimMapperSettings {
                    claim: claim.to_owned(),
                    targets: vec![ClaimTarget::IdToken],
                    scope: None,
                    source: ClaimSource::Constant(json!("x".repeat(length))),
                },
                Caller::system(),
            )
            .await
            .expect("mapper");
    }
    let request = checked(
        &world,
        &tenant,
        payroll,
        "id_token",
        "openid profile address email",
        &json!({}),
    )
    .await;
    let (_, id_token) = answered(&world, &tenant, &request, &ana).await;
    let claims = claims_of(&id_token.expect("an ID token"));
    assert_eq!(claims["fourth"], "x".repeat(600), "the mappers count first");
    assert_eq!(claims["name"], "Ana Silva");
    assert!(
        claims.get("address").is_none(),
        "a claim that would cross the bound is left out whole"
    );
    assert_eq!(claims["email"], "ana@example.com", "one after it that fits");
}
