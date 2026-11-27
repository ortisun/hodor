//! Pushed authorization requests through the use cases, on the in-memory
//! stores: a client proves who it is and pushes its request, which is
//! checked at once and kept; its reference brings it to the authorization
//! endpoint once, for that client and tenant only, within its life.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::sealing::testing::FakeSecretBox;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, Clock as _, PublicKey, SignatureAlgorithm, TenantContext, TenantId, Timestamp,
};
use hodor_keys::api::KeyService;
use hodor_keys::testing::{FakeKeyProvider, InMemoryKeys};
use hodor_oauth::api::{
    ASSERTION_TYPE, ApplicationId, ApplicationPorts, ApplicationService, ApplicationSettings,
    AuthenticationMethod, AuthorizationCodePorts, AuthorizationCodeService,
    AuthorizationParameters, AuthorizationRefusal, AuthorizationRequest, BasicCredentials,
    ClientId, ClientSecretValue, ClientSettings, ClientType, CreateClient, GrantType, Issuer,
    PushedAnswer, PushedRequest, PushedRequestPolicy, TokenError, TokenPorts, TokenService,
};
use hodor_oauth::testing::{
    DistinctRandom, FakeVerifier, InMemoryAccessTokenRecords, InMemoryAuthorizationCodes,
    InMemoryAuthorizationRequests, InMemoryClientAssertions, InMemoryGrants, InMemoryRefreshTokens,
    InMemoryStores, MembershipsOf, StandingOf, fake_signature,
};
use serde_json::{Value, json};
use std::sync::Arc;
use time::Duration;

const ISSUER: &str = "https://hodor.example.com/t/acme";
const TOKEN_ENDPOINT: &str = "https://hodor.example.com/t/acme/oauth2/token";
const PUSH_ENDPOINT: &str = "https://hodor.example.com/t/acme/oauth2/par";
const REDIRECT: &str = "https://payroll.example.com/callback";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const ISSUER_OF: Issuer<'static> = Issuer {
    issuer: ISSUER,
    token_endpoint: TOKEN_ENDPOINT,
};

struct World {
    clock: Arc<FixedClock>,
    requests: InMemoryAuthorizationRequests,
    codes: AuthorizationCodeService,
    applications: ApplicationService,
    tokens: TokenService,
}

fn world() -> World {
    let units = InMemoryUnitOfWorkFactory::default();
    let stores = InMemoryStores::default();
    let requests = InMemoryAuthorizationRequests::new(&stores.clients);
    let grants = InMemoryGrants::new(&stores.clients);
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
        codes: Arc::new(InMemoryAuthorizationCodes::new(&grants)),
        memberships: Arc::new(MembershipsOf::default()),
        verifier: Arc::new(FakeVerifier),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    let tokens = TokenService::new(TokenPorts {
        units_of_work: Arc::new(units.clone()),
        applications: Arc::new(stores.applications.clone()),
        clients: Arc::new(stores.clients.clone()),
        resource_servers: Arc::new(stores.resource_servers.clone()),
        grants: Arc::new(grants.clone()),
        assertions: Arc::new(InMemoryClientAssertions::new(&stores.clients)),
        refresh_tokens: Arc::new(InMemoryRefreshTokens::new(&grants)),
        access_tokens: Arc::new(InMemoryAccessTokenRecords::new(&stores.clients)),
        standing: Arc::new(StandingOf::default()),
        memberships: Arc::new(MembershipsOf::default()),
        mapping: hodor_oauth::api::ClaimMapping::new(
            Arc::new(units.clone()),
            Arc::new(hodor_oauth::testing::InMemoryClaimMappers::new(
                &stores.clients,
            )),
            Arc::new(MembershipsOf::default()),
            Arc::new(hodor_oauth::testing::ClaimSourcesOf::default()),
        ),
        secrets: Arc::new(FakeSecretBox),
        codes: codes.clone(),
        keys: KeyService::new(
            Arc::new(units.clone()),
            Arc::new(InMemoryKeys::default()),
            Arc::new(FakeKeyProvider),
            clock.clone(),
        ),
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
        requests,
        codes,
        applications,
        tokens,
    }
}

async fn application(world: &World, tenant: &TenantContext) -> ApplicationId {
    world
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
        .expect("application")
        .id()
}

/// A client of a new first-party application of `tenant`, proving who it
/// is with `method`, required to push its requests when `strict`.
async fn make_client(
    world: &World,
    tenant: &TenantContext,
    method: AuthenticationMethod,
    strict: bool,
) -> (ClientId, Option<ClientSecretValue>) {
    let client_type = if method == AuthenticationMethod::None {
        ClientType::Public
    } else {
        ClientType::Confidential
    };
    let mut settings = ClientSettings::new(
        "Payroll",
        client_type,
        vec![GrantType::AuthorizationCode],
        vec![REDIRECT.to_owned()],
    );
    settings.authentication_method = method;
    settings.allowed_scopes = vec!["openid".to_owned()];
    settings.require_pushed_requests = strict;
    let application = application(world, tenant).await;
    let (client, secret) = world
        .applications
        .create_client(
            tenant,
            CreateClient {
                application_id: application,
                client_type,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client");
    (client.id(), secret)
}

/// What a client pushes beside its credentials.
fn request_form(extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut list = vec![
        ("response_type", "code"),
        ("redirect_uri", REDIRECT),
        ("scope", "openid"),
        ("state", "pushed"),
        ("nonce", "n-0S6_WzA2Mj"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ];
    list.extend_from_slice(extra);
    list.iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect()
}

fn basic(client: ClientId, secret: &ClientSecretValue) -> Option<BasicCredentials> {
    Some(BasicCredentials {
        client_id: client.to_string(),
        secret: hodor_kernel::Secret::from(secret.expose().to_owned()),
    })
}

async fn push_as(
    world: &World,
    tenant: &TenantContext,
    basic: Option<BasicCredentials>,
    form: Vec<(String, String)>,
    policy: &PushedRequestPolicy,
) -> Result<PushedAnswer, TokenError> {
    let request = PushedRequest::parse(basic, form)?;
    world
        .tokens
        .push(tenant, ISSUER_OF, PUSH_ENDPOINT, request, policy)
        .await
        .expect("storage")
}

/// Pushes the request of a confidential client with a secret.
async fn push(
    world: &World,
    tenant: &TenantContext,
    client: ClientId,
    secret: &ClientSecretValue,
) -> String {
    push_as(
        world,
        tenant,
        basic(client, secret),
        request_form(&[]),
        &PushedRequestPolicy::default(),
    )
    .await
    .expect("pushed")
    .reference
    .expose()
    .to_owned()
}

async fn bring(
    world: &World,
    tenant: &TenantContext,
    client: ClientId,
    reference: &str,
    outside: &[(&str, &str)],
) -> Result<AuthorizationRequest, AuthorizationRefusal> {
    let mut pairs = vec![
        ("client_id".to_owned(), client.to_string()),
        ("request_uri".to_owned(), reference.to_owned()),
    ];
    pairs.extend(
        outside
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
    );
    world
        .codes
        .check(
            tenant,
            ISSUER,
            &AuthorizationParameters::from_pairs(pairs),
            &PushedRequestPolicy::default(),
        )
        .await
        .expect("storage")
}

fn error_of(result: Result<AuthorizationRequest, AuthorizationRefusal>) -> &'static str {
    match result {
        Err(AuthorizationRefusal::Redirect(error)) => {
            assert_eq!(error.redirect_uri, REDIRECT);
            error.error
        }
        other => panic!("expected an error at the redirect address, got {other:?}"),
    }
}

/// The client's redirect address outside, so that a refusal reaches it.
const OUTSIDE: [(&str, &str); 1] = [("redirect_uri", REDIRECT)];

#[tokio::test]
async fn a_pushed_request_is_kept_and_its_reference_brings_it_once() {
    let world = world();
    let tenant = TenantContext::assume(TenantId::generate());
    let (client, secret) = make_client(
        &world,
        &tenant,
        AuthenticationMethod::ClientSecretBasic,
        false,
    )
    .await;
    let secret = secret.expect("a secret");
    let answer = push_as(
        &world,
        &tenant,
        basic(client, &secret),
        request_form(&[]),
        &PushedRequestPolicy::default(),
    )
    .await
    .expect("pushed");
    assert_eq!(answer.expires_in, 60);
    assert!(
        answer
            .reference
            .expose()
            .starts_with("urn:ietf:params:oauth:request_uri:")
    );
    let kept = world.requests.pushed(tenant.tenant_id());
    assert_eq!(kept.len(), 1, "kept as a pending request");
    assert_eq!(
        kept[0].expires_at,
        world.clock.now() + Duration::seconds(60)
    );
    assert!(
        !format!("{kept:?}").contains(answer.reference.expose()),
        "the reference is stored nowhere"
    );

    let request = bring(&world, &tenant, client, answer.reference.expose(), &[])
        .await
        .expect("the pushed request");
    assert_eq!(request.client_id, client);
    assert_eq!(request.redirect_uri, REDIRECT);
    assert_eq!(request.state.as_deref(), Some("pushed"));
    assert_eq!(request.nonce.as_deref(), Some("n-0S6_WzA2Mj"));
    assert_eq!(request.code_challenge.as_deref(), Some(CHALLENGE));
    assert!(
        world.requests.pushed(tenant.tenant_id()).is_empty(),
        "taken"
    );

    // Used once: a second time, it is unknown.
    assert_eq!(
        error_of(bring(&world, &tenant, client, answer.reference.expose(), &OUTSIDE).await),
        "invalid_request_uri"
    );
    assert_eq!(
        bring(&world, &tenant, client, answer.reference.expose(), &[]).await,
        Err(AuthorizationRefusal::NotRedirectable(
            "oauth.authorization_request_uri_invalid"
        )),
        "without an address of the client's outside, Hodor's own page"
    );
}

#[tokio::test]
async fn a_reference_past_its_life_of_another_client_or_at_another_tenant_is_refused() {
    let world = world();
    let tenant = TenantContext::assume(TenantId::generate());
    let (client, secret) = make_client(
        &world,
        &tenant,
        AuthenticationMethod::ClientSecretBasic,
        false,
    )
    .await;
    let secret = secret.expect("a secret");
    let (stranger, _) = make_client(&world, &tenant, AuthenticationMethod::None, false).await;

    // Past its life, here the ten seconds the tenant chose.
    let short = PushedRequestPolicy {
        lifetime: Duration::seconds(10),
        required: false,
    };
    let answer = push_as(
        &world,
        &tenant,
        basic(client, &secret),
        request_form(&[]),
        &short,
    )
    .await
    .expect("pushed");
    assert_eq!(answer.expires_in, 10);
    world.clock.advance(Duration::seconds(10));
    assert_eq!(
        error_of(bring(&world, &tenant, client, answer.reference.expose(), &OUTSIDE).await),
        "invalid_request_uri"
    );

    // Brought by another client of the tenant: unknown to it, and still
    // its own client's afterwards.
    let reference = push(&world, &tenant, client, &secret).await;
    assert_eq!(
        error_of(bring(&world, &tenant, stranger, &reference, &OUTSIDE).await),
        "invalid_request_uri"
    );

    // At another tenant, its client is unknown: Hodor's own page.
    let elsewhere = TenantContext::assume(TenantId::generate());
    assert_eq!(
        bring(&world, &elsewhere, client, &reference, &OUTSIDE).await,
        Err(AuthorizationRefusal::NotRedirectable(
            "oauth.authorization_client_unknown"
        ))
    );
    assert!(
        bring(&world, &tenant, client, &reference, &[])
            .await
            .is_ok(),
        "neither took it from its client"
    );
}

#[tokio::test]
async fn a_reference_presented_twice_at_once_is_used_once() {
    let world = world();
    let tenant = TenantContext::assume(TenantId::generate());
    let (client, secret) = make_client(
        &world,
        &tenant,
        AuthenticationMethod::ClientSecretBasic,
        false,
    )
    .await;
    let reference = push(&world, &tenant, client, &secret.expect("a secret")).await;
    let (first, second) = tokio::join!(
        bring(&world, &tenant, client, &reference, &OUTSIDE),
        bring(&world, &tenant, client, &reference, &OUTSIDE),
    );
    assert!(
        first.is_ok() != second.is_ok(),
        "exactly one has it: {first:?} {second:?}"
    );
}

#[tokio::test]
async fn a_pushed_request_that_fails_a_check_is_answered_at_once_and_kept_nowhere() {
    let world = world();
    let tenant = TenantContext::assume(TenantId::generate());
    let (client, secret) = make_client(
        &world,
        &tenant,
        AuthenticationMethod::ClientSecretBasic,
        false,
    )
    .await;
    let secret = secret.expect("a secret");
    let policy = PushedRequestPolicy::default();

    let wrong = Some(BasicCredentials {
        client_id: client.to_string(),
        secret: hodor_kernel::Secret::from("not the secret".to_owned()),
    });
    let error = push_as(&world, &tenant, wrong, request_form(&[]), &policy)
        .await
        .expect_err("refused");
    assert_eq!(error.error, "invalid_client");

    for (extra, expected) in [
        (vec![("scope", "openid write")], "invalid_scope"),
        (
            vec![("response_type", "token")],
            "unsupported_response_type",
        ),
        (
            vec![("redirect_uri", "https://elsewhere.example.com/callback")],
            "invalid_request",
        ),
        (
            vec![("request_uri", "urn:ietf:params:oauth:request_uri:abc")],
            "invalid_request",
        ),
        (vec![("request", "not an object")], "invalid_request_object"),
    ] {
        let mut form: Vec<(String, String)> = request_form(&[])
            .into_iter()
            .filter(|(name, _)| !extra.iter().any(|(other, _)| other == name))
            .collect();
        form.extend(
            extra
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
        );
        let error = push_as(&world, &tenant, basic(client, &secret), form, &policy)
            .await
            .expect_err("refused");
        assert_eq!(error.error, expected, "{extra:?}");
    }
    assert!(
        world.requests.pushed(tenant.tenant_id()).is_empty(),
        "nothing refused is kept"
    );

    // A public client pushes with its identifier alone, and is held to
    // PKCE as at the authorization endpoint.
    let (public, _) = make_client(&world, &tenant, AuthenticationMethod::None, false).await;
    let id = public.to_string();
    let mut form = request_form(&[("client_id", &id)]);
    assert!(
        push_as(&world, &tenant, None, form.clone(), &policy)
            .await
            .is_ok()
    );
    form.retain(|(name, _)| !name.starts_with("code_challenge"));
    assert_eq!(
        push_as(&world, &tenant, None, form, &policy)
            .await
            .expect_err("no challenge")
            .error,
        "invalid_request"
    );
}

#[tokio::test]
async fn a_client_keeps_at_most_five_pushed_requests() {
    let world = world();
    let tenant = TenantContext::assume(TenantId::generate());
    let (client, secret) = make_client(
        &world,
        &tenant,
        AuthenticationMethod::ClientSecretBasic,
        false,
    )
    .await;
    let secret = secret.expect("a secret");
    let mut references = Vec::new();
    for _ in 0..6 {
        references.push(push(&world, &tenant, client, &secret).await);
        world.clock.advance(Duration::seconds(1));
    }
    assert_eq!(world.requests.pushed(tenant.tenant_id()).len(), 5);
    assert_eq!(
        error_of(bring(&world, &tenant, client, &references[0], &OUTSIDE).await),
        "invalid_request_uri",
        "the oldest went"
    );
    for reference in &references[1..] {
        assert!(bring(&world, &tenant, client, reference, &[]).await.is_ok());
    }
}

#[tokio::test]
async fn a_client_that_must_push_is_refused_without_a_pushed_request() {
    let world = world();
    let tenant = TenantContext::assume(TenantId::generate());
    let (strict, secret) = make_client(
        &world,
        &tenant,
        AuthenticationMethod::ClientSecretBasic,
        true,
    )
    .await;
    let (lenient, _) = make_client(&world, &tenant, AuthenticationMethod::None, false).await;
    let direct = |client: ClientId| {
        let mut pairs = request_form(&[]);
        pairs.push(("client_id".to_owned(), client.to_string()));
        AuthorizationParameters::from_pairs(pairs)
    };
    let lenient_tenant = PushedRequestPolicy::default();
    let strict_tenant = PushedRequestPolicy {
        required: true,
        ..lenient_tenant
    };
    let check = |client, policy| {
        let parameters = direct(client);
        let world = &world;
        let tenant = &tenant;
        async move {
            world
                .codes
                .check(tenant, ISSUER, &parameters, &policy)
                .await
                .expect("storage")
        }
    };
    assert_eq!(
        error_of(check(strict, lenient_tenant).await),
        "invalid_request"
    );
    assert_eq!(
        error_of(check(lenient, strict_tenant).await),
        "invalid_request"
    );
    assert!(check(lenient, lenient_tenant).await.is_ok());

    // Pushed, it is accepted.
    let reference = push(&world, &tenant, strict, &secret.expect("a secret")).await;
    assert!(
        bring(&world, &tenant, strict, &reference, &[])
            .await
            .is_ok()
    );
}

fn client_key() -> (String, PublicKey) {
    let x = vec![5_u8; 32];
    let y = vec![6_u8; 32];
    let jwk = json!({
        "kty": "EC", "crv": "P-256", "kid": "payroll-1",
        "x": URL_SAFE_NO_PAD.encode(&x), "y": URL_SAFE_NO_PAD.encode(&y),
    })
    .to_string();
    (jwk, PublicKey::P256 { x, y })
}

fn assertion(
    client: ClientId,
    key: &PublicKey,
    audience: &str,
    jti: &str,
    now: Timestamp,
) -> String {
    let encode = |value: &Value| URL_SAFE_NO_PAD.encode(value.to_string());
    let header = encode(&json!({"alg": "ES256", "kid": "payroll-1"}));
    let claims = encode(&json!({
        "iss": client.to_string(),
        "sub": client.to_string(),
        "aud": audience,
        "exp": (now + Duration::minutes(1)).unix_timestamp(),
        "jti": jti,
    }));
    let input = format!("{header}.{claims}");
    let signature = fake_signature(SignatureAlgorithm::Es256, key, input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

#[tokio::test]
async fn an_assertion_may_name_the_pushed_request_endpoint_as_its_audience() {
    let world = world();
    let tenant = TenantContext::assume(TenantId::generate());
    let (client, _) =
        make_client(&world, &tenant, AuthenticationMethod::PrivateKeyJwt, false).await;
    let (jwk, key) = client_key();
    world
        .applications
        .add_client_key(&tenant, client, &jwk, Caller::system())
        .await
        .expect("key");
    let policy = PushedRequestPolicy::default();
    for (audience, jti) in [
        (PUSH_ENDPOINT, "one"),
        (ISSUER, "two"),
        (TOKEN_ENDPOINT, "three"),
    ] {
        let signed = assertion(client, &key, audience, jti, world.clock.now());
        let form = request_form(&[
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", &signed),
        ]);
        assert!(
            push_as(&world, &tenant, None, form, &policy).await.is_ok(),
            "{audience}"
        );
    }
    let signed = assertion(
        client,
        &key,
        "https://hodor.example.com/t/acme/oauth2/introspect",
        "four",
        world.clock.now(),
    );
    let form = request_form(&[
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", &signed),
    ]);
    assert_eq!(
        push_as(&world, &tenant, None, form, &policy)
            .await
            .expect_err("another endpoint's address")
            .error,
        "invalid_client"
    );
}
