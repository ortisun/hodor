//! Request objects through the use cases of the authorization endpoint, on
//! the in-memory stores: accepted and kept as the checked request, and
//! refused when signed by another client's key, sent unsigned for a client
//! that signs, or sent to another tenant.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, Clock as _, PublicKey, SignatureAlgorithm, TenantContext, TenantId, Timestamp,
};
use hodor_oauth::api::{
    ApplicationPorts, ApplicationService, ApplicationSettings, AuthenticationMethod,
    AuthorizationCodePorts, AuthorizationCodeService, AuthorizationError, AuthorizationParameters,
    AuthorizationRefusal, ClientId, ClientSettings, ClientType, CreateClient, GrantType,
    RequestObjectAlgorithm, ResponseMode,
};
use hodor_oauth::testing::{
    DistinctRandom, FakeVerifier, InMemoryAuthorizationCodes, InMemoryAuthorizationRequests,
    InMemoryGrants, InMemoryStores, MembershipsOf, fake_signature,
};
use serde_json::{Value, json};
use std::sync::Arc;
use time::Duration;

const ISSUER: &str = "https://hodor.example.com/t/acme";
const REDIRECT: &str = "https://payroll.example.com/callback";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

struct World {
    clock: Arc<FixedClock>,
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
        grants: Arc::new(grants),
        codes: Arc::new(codes),
        memberships: Arc::new(MembershipsOf::default()),
        verifier: Arc::new(FakeVerifier),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(units),
        applications: Arc::new(stores.applications),
        clients: Arc::new(stores.clients),
        resource_servers: Arc::new(stores.resource_servers),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    World {
        clock,
        service,
        applications,
    }
}

fn p256_key(fill: u8) -> (String, PublicKey) {
    let x = vec![fill; 32];
    let y = vec![fill.wrapping_add(1); 32];
    let jwk = json!({
        "kty": "EC", "crv": "P-256", "kid": "signing",
        "x": URL_SAFE_NO_PAD.encode(&x), "y": URL_SAFE_NO_PAD.encode(&y),
    })
    .to_string();
    (jwk, PublicKey::P256 { x, y })
}

/// A confidential client with `private_key_jwt` and one P-256 key made
/// from `fill`, in a first-party application of `tenant`.
async fn signing_client(
    world: &World,
    tenant: &TenantContext,
    fill: u8,
    chosen: Option<RequestObjectAlgorithm>,
) -> (ClientId, PublicKey) {
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
        ClientType::Confidential,
        vec![GrantType::AuthorizationCode],
        vec![REDIRECT.to_owned()],
    );
    settings.authentication_method = AuthenticationMethod::PrivateKeyJwt;
    settings.allowed_scopes = vec!["openid".to_owned()];
    settings.request_object_algorithm = chosen;
    let (client, _) = world
        .applications
        .create_client(
            tenant,
            CreateClient {
                application_id: application.id(),
                client_type: ClientType::Confidential,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client");
    let (jwk, key) = p256_key(fill);
    world
        .applications
        .add_client_key(tenant, client.id(), &jwk, Caller::system())
        .await
        .expect("key");
    (client.id(), key)
}

fn encode(value: &Value) -> String {
    URL_SAFE_NO_PAD.encode(value.to_string())
}

fn claims(world: &World, client: ClientId) -> Value {
    json!({
        "iss": client.to_string(),
        "aud": ISSUER,
        "exp": (world.clock.now() + Duration::minutes(5)).unix_timestamp(),
        "client_id": client.to_string(),
        "response_type": "code",
        "redirect_uri": REDIRECT,
        "scope": "openid",
        "state": "inside",
        "nonce": "n-0S6_WzA2Mj",
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
    })
}

fn signed(key: &PublicKey, claims: &Value) -> String {
    let input = format!(
        "{}.{}",
        encode(&json!({"alg": "ES256", "kid": "signing"})),
        encode(claims)
    );
    let signature = fake_signature(SignatureAlgorithm::Es256, key, input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn unsigned(claims: &Value) -> String {
    format!("{}.{}.", encode(&json!({"alg": "none"})), encode(claims))
}

fn request(client: ClientId, object: &str) -> AuthorizationParameters {
    AuthorizationParameters::from_pairs([
        ("client_id".to_owned(), client.to_string()),
        ("response_type".to_owned(), "code".to_owned()),
        ("scope".to_owned(), "openid".to_owned()),
        ("redirect_uri".to_owned(), REDIRECT.to_owned()),
        ("request".to_owned(), object.to_owned()),
    ])
}

fn refused_object(description: &'static str) -> AuthorizationRefusal {
    AuthorizationRefusal::Redirect(AuthorizationError {
        redirect_uri: REDIRECT.to_owned(),
        error: "invalid_request_object",
        description,
        state: None,
        mode: ResponseMode::Query,
    })
}

#[tokio::test]
async fn a_signed_request_object_is_checked_and_kept_as_the_request() {
    let world = world();
    let tenant = TenantContext::assume(TenantId::generate());
    let (client, key) = signing_client(&world, &tenant, 3, None).await;
    let checked = world
        .service
        .check(
            &tenant,
            ISSUER,
            &request(client, &signed(&key, &claims(&world, client))),
        )
        .await
        .expect("storage")
        .expect("accepted");
    assert_eq!(checked.client_id, client);
    assert_eq!(checked.state.as_deref(), Some("inside"));
    assert_eq!(checked.nonce.as_deref(), Some("n-0S6_WzA2Mj"));

    // What waits for the person is the checked request, not the object.
    let (id, secret) = world
        .service
        .hold(&tenant, checked.clone())
        .await
        .expect("held");
    let resumed = world
        .service
        .resume(&tenant, id, secret.expose())
        .await
        .expect("storage")
        .expect("resumed");
    assert_eq!(resumed.request, checked);
}

#[tokio::test]
async fn an_object_signed_by_another_client_s_key_is_refused() {
    let world = world();
    let tenant = TenantContext::assume(TenantId::generate());
    let (client, _) = signing_client(&world, &tenant, 3, None).await;
    let (_, stranger_key) = signing_client(&world, &tenant, 9, None).await;
    let answer = world
        .service
        .check(
            &tenant,
            ISSUER,
            &request(client, &signed(&stranger_key, &claims(&world, client))),
        )
        .await
        .expect("storage");
    assert_eq!(
        answer,
        Err(refused_object(
            "the request object's signature does not verify"
        ))
    );
}

#[tokio::test]
async fn an_unsigned_object_is_read_only_from_a_client_that_chose_none() {
    let world = world();
    let tenant = TenantContext::assume(TenantId::generate());
    let (signs, _) = signing_client(&world, &tenant, 3, None).await;
    let (names_one, _) =
        signing_client(&world, &tenant, 4, Some(RequestObjectAlgorithm::Es256)).await;
    let (signs_nothing, _) =
        signing_client(&world, &tenant, 5, Some(RequestObjectAlgorithm::None)).await;
    for client in [signs, names_one] {
        let answer = world
            .service
            .check(
                &tenant,
                ISSUER,
                &request(client, &unsigned(&claims(&world, client))),
            )
            .await
            .expect("storage");
        assert_eq!(
            answer,
            Err(refused_object(
                "this client's request objects must be signed"
            ))
        );
    }
    world
        .service
        .check(
            &tenant,
            ISSUER,
            &request(signs_nothing, &unsigned(&claims(&world, signs_nothing))),
        )
        .await
        .expect("storage")
        .expect("accepted");
}

#[tokio::test]
async fn an_object_of_another_tenant_s_client_is_refused() {
    let world = world();
    let tenant = TenantContext::assume(TenantId::generate());
    let elsewhere = TenantContext::assume(TenantId::generate());
    let (client, key) = signing_client(&world, &tenant, 3, None).await;
    let (theirs, _) = signing_client(&world, &elsewhere, 7, None).await;
    let object = signed(&key, &claims(&world, client));

    // Its own client is unknown there: nothing is checked, and nothing is
    // sent to an address.
    let answer = world
        .service
        .check(
            &elsewhere,
            "https://hodor.example.com/t/other",
            &request(client, &object),
        )
        .await
        .expect("storage");
    assert_eq!(
        answer,
        Err(AuthorizationRefusal::NotRedirectable(
            "oauth.authorization_client_unknown"
        ))
    );

    // Named for a client of that tenant, it is signed by a key it does
    // not have.
    let answer = world
        .service
        .check(
            &elsewhere,
            "https://hodor.example.com/t/other",
            &request(theirs, &object),
        )
        .await
        .expect("storage");
    assert!(
        matches!(
            answer,
            Err(AuthorizationRefusal::Redirect(AuthorizationError {
                error: "invalid_request_object",
                ..
            }))
        ),
        "{answer:?}"
    );
}
