//! The `claims` parameter through the use cases, on the in-memory stores:
//! what a grant gives, decided by the scopes consented to for the client,
//! and the person's claims added to the ID token within its bound.

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
    ClaimSource, ClaimTarget, ClientId, ClientSettings, ClientType, ConsentAnswer, ConsentPorts,
    ConsentService, CreateClient, GrantStore as _, GrantType, IssuedTokens, Issuer,
    PersonAttributes, SignedInPerson, TokenPorts, TokenRequest, TokenService, s256_challenge,
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

/// A public client that may ask for `scopes`.
async fn client(
    world: &World,
    tenant: &TenantContext,
    application: ApplicationId,
    scopes: &[&str],
) -> ClientId {
    let mut settings = ClientSettings::new(
        "Payroll",
        ClientType::Public,
        vec![GrantType::AuthorizationCode],
        vec![REDIRECT.to_owned()],
    );
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

async fn checked(
    world: &World,
    tenant: &TenantContext,
    client: ClientId,
    scope: &str,
    claims: &Value,
) -> AuthorizationRequest {
    let challenge = s256_challenge(VERIFIER, &FakeDigest);
    let id = client.to_string();
    let claims = claims.to_string();
    let pairs = [
        ("response_type", "code"),
        ("client_id", id.as_str()),
        ("redirect_uri", REDIRECT),
        ("scope", scope),
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

/// Issues a code for `request` as the authorization endpoint does, with
/// the scopes consented to for its client, and redeems it.
async fn redeemed(
    world: &World,
    tenant: &TenantContext,
    request: &AuthorizationRequest,
    person: &SignedInPerson,
) -> IssuedTokens {
    let consented = world
        .consent
        .consented_scopes(tenant, request, person)
        .await
        .expect("consented scopes");
    let code = world
        .codes
        .issue_code_consented(tenant, request, person, &consented, Caller::system())
        .await
        .expect("code");
    let form = vec![
        ("grant_type".to_owned(), "authorization_code".to_owned()),
        ("code".to_owned(), code.expose().to_owned()),
        ("redirect_uri".to_owned(), REDIRECT.to_owned()),
        ("code_verifier".to_owned(), VERIFIER.to_owned()),
        ("client_id".to_owned(), request.client_id.to_string()),
    ];
    world
        .tokens
        .token(
            tenant,
            ISSUER_OF,
            TokenRequest::parse(None, form).expect("a request"),
            CorrelationId::generate(),
        )
        .await
        .expect("storage")
        .expect("tokens")
}

fn id_token(tokens: &IssuedTokens) -> Value {
    let token = tokens.id_token.as_ref().expect("an ID token").expose();
    let part = token.split('.').nth(1).expect("claims");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("json")
}

/// The claims the person's only grant for `client` gives for UserInfo.
async fn userinfo_claims_of_the_grant(
    world: &World,
    tenant: &TenantContext,
    person: &SignedInPerson,
    client: ClientId,
) -> Vec<String> {
    let mut uow = world.units.begin(tenant).await.expect("unit of work");
    let grants = world
        .grants
        .list_active_for(uow.as_mut(), person.user_id, client)
        .await
        .expect("grants");
    assert_eq!(grants.len(), 1);
    grants[0].claims.userinfo.clone()
}

#[tokio::test]
async fn a_first_party_client_gets_the_claims_of_every_scope_it_may_ask_for_and_no_other() {
    let world = world();
    let (tenant, application) = tenant(&world, true).await;
    // It may ask for `openid`, `profile` and `email`, not `phone`.
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
        "openid",
        &json!({
            "id_token": {"name": {"essential": true}, "email": null, "phone_number": null,
                         "updated_at": null},
            "userinfo": {"given_name": null, "phone_number": {"essential": true}}
        }),
    )
    .await;
    let tokens = redeemed(&world, &tenant, &request, &ana).await;
    let claims = id_token(&tokens);
    assert_eq!(claims["name"], "Ana Silva", "under its own name");
    assert_eq!(claims["email"], "ana@example.com");
    assert_eq!(
        claims["updated_at"],
        (world.clock.now() - Duration::days(1)).unix_timestamp()
    );
    assert!(
        claims.get("phone_number").is_none(),
        "the client may not ask for `phone`: nobody consented to it"
    );
    assert!(
        claims.get("given_name").is_none(),
        "asked for UserInfo only"
    );
    assert_eq!(claims["sub"], ana.user_id.to_string(), "Hodor's own stay");
    assert_eq!(
        userinfo_claims_of_the_grant(&world, &tenant, &ana, payroll).await,
        ["given_name"],
        "the grant keeps what it gives UserInfo, never the number"
    );
}

#[tokio::test]
async fn a_third_party_client_gets_only_the_claims_of_what_the_person_agreed_to() {
    let world = world();
    let (tenant, application) = tenant(&world, false).await;
    // It may ask for `openid`, `profile` and `email`, not `phone`.
    let payroll = client(
        &world,
        &tenant,
        application,
        &["openid", "profile", "email"],
    )
    .await;
    let ana = ana(&world, &tenant);
    let asked = json!({"id_token": {"name": null, "email": null}});

    // Ana agrees to `openid` alone: neither her name nor her address.
    let request = checked(&world, &tenant, payroll, "openid", &asked).await;
    agree(&world, &tenant, request.clone(), &ana).await;
    let claims = id_token(&redeemed(&world, &tenant, &request, &ana).await);
    assert!(claims.get("name").is_none(), "a claim never consented to");
    assert!(claims.get("email").is_none(), "a claim never consented to");

    // Once she agrees to `profile`, a later request of `openid` alone gets
    // her name, and still not her address.
    let profile = checked(&world, &tenant, payroll, "openid profile", &json!({})).await;
    agree(&world, &tenant, profile, &ana).await;
    let claims = id_token(&redeemed(&world, &tenant, &request, &ana).await);
    assert_eq!(claims["name"], "Ana Silva");
    assert!(claims.get("email").is_none());
}

/// Holds `request` for `person` and agrees to it, as the consent page does.
async fn agree(
    world: &World,
    tenant: &TenantContext,
    request: AuthorizationRequest,
    person: &SignedInPerson,
) {
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
}

#[tokio::test]
async fn a_claim_that_would_cross_the_bound_of_the_id_token_is_left_out_never_cut() {
    let world = world();
    let (tenant, application) = tenant(&world, true).await;
    // It may ask for `address`, so that only the bound keeps it out.
    let payroll = client(
        &world,
        &tenant,
        application,
        &["openid", "profile", "address"],
    )
    .await;
    let ana = ana(&world, &tenant);
    // Three constants of 1024 bytes leave 1006 bytes of the 4096.
    for claim in ["c1", "c2", "c3"] {
        world
            .mappers
            .create(
                &tenant,
                payroll,
                ClaimMapperSettings {
                    claim: claim.to_owned(),
                    targets: vec![ClaimTarget::IdToken],
                    scope: None,
                    source: ClaimSource::Constant(json!("x".repeat(1022))),
                },
                Caller::system(),
            )
            .await
            .expect("mapper");
    }
    // A postal address of 300 characters of four bytes each: 1200 bytes.
    world.sources.set_attributes(
        tenant.tenant_id(),
        ana.user_id,
        PersonAttributes {
            display_name: Some("Ana Silva".to_owned()),
            claims: StandardClaims {
                address: Some(PostalAddress {
                    formatted: Some("𝔄".repeat(300)),
                    ..PostalAddress::default()
                }),
                ..StandardClaims::default()
            },
            ..PersonAttributes::default()
        },
    );
    let request = checked(
        &world,
        &tenant,
        payroll,
        "openid",
        &json!({"id_token": {"name": null, "address": {"essential": true}}}),
    )
    .await;
    let tokens = redeemed(&world, &tenant, &request, &ana).await;
    let claims = id_token(&tokens);
    assert!(claims.get("address").is_none(), "left out whole");
    assert_eq!(claims["name"], "Ana Silva", "what fits is added");
    for claim in ["c1", "c2", "c3"] {
        assert_eq!(claims[claim], "x".repeat(1022), "the mappers' claims stay");
    }
}
