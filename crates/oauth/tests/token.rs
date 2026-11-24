//! The use cases of the token endpoint, on the in-memory stores.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::sealing::testing::FakeSecretBox;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, Clock as _, CorrelationId, PublicKey, SignatureAlgorithm, TenantContext, TenantId,
    Timestamp, UserId,
};
use hodor_keys::api::{KeyAlgorithm, KeyService, RotationPolicy};
use hodor_keys::testing::{FakeKeyProvider, InMemoryKeys};
use hodor_oauth::api::{
    ASSERTION_TYPE, ApplicationPorts, ApplicationService, ApplicationSettings,
    AuthenticationMethod, AuthorizationCodePorts, AuthorizationCodeService,
    AuthorizationParameters, BasicCredentials, ClientId, ClientSecretValue, ClientSettings,
    ClientType, CreateClient, CreateResourceServer, GrantStatus, GrantStore, GrantType,
    IssuedTokens, Issuer, ResourceServerSettings, ScopeDefinition, SignedInPerson, Status,
    TokenError, TokenPorts, TokenRequest, TokenService, access_token_hash, s256_challenge,
};
use hodor_oauth::testing::{
    AssertionStorePorts, DistinctRandom, FakeVerifier, InMemoryAccessTokenRecords,
    InMemoryAuthorizationCodes, InMemoryAuthorizationRequests, InMemoryClientAssertions,
    InMemoryGrants, InMemoryRefreshTokens, InMemoryStores, MembershipsOf, StandingOf,
    fake_signature, run_assertion_contract,
};
use hodor_session::api::SessionId;
use serde_json::{Value, json};
use std::sync::Arc;
use time::Duration;

const REDIRECT: &str = "https://payroll.example.com/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const ISSUER: &str = "https://hodor.example.com/t/acme";
const ENDPOINT: &str = "https://hodor.example.com/t/acme/oauth2/token";
const AUDIENCE: &str = "https://api.payroll.example.com";
const OTHER_AUDIENCE: &str = "urn:example:billing";

struct World {
    units: InMemoryUnitOfWorkFactory,
    clock: Arc<FixedClock>,
    grants: InMemoryGrants,
    codes: AuthorizationCodeService,
    applications: ApplicationService,
    keys: KeyService,
    tokens: TokenService,
}

fn world() -> World {
    let units = InMemoryUnitOfWorkFactory::default();
    let stores = InMemoryStores::default();
    let requests = InMemoryAuthorizationRequests::new(&stores.clients);
    let grants = InMemoryGrants::new(&stores.clients);
    let code_store = InMemoryAuthorizationCodes::new(&grants);
    let assertions = InMemoryClientAssertions::new(&stores.clients);
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + Duration::days(20_000),
    ));
    let codes = AuthorizationCodeService::new(AuthorizationCodePorts {
        units_of_work: Arc::new(units.clone()),
        applications: Arc::new(stores.applications.clone()),
        clients: Arc::new(stores.clients.clone()),
        resource_servers: Arc::new(stores.resource_servers.clone()),
        requests: Arc::new(requests),
        grants: Arc::new(grants.clone()),
        codes: Arc::new(code_store),
        memberships: Arc::new(MembershipsOf::default()),
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
        assertions: Arc::new(assertions),
        refresh_tokens: Arc::new(InMemoryRefreshTokens::new(&grants)),
        access_tokens: Arc::new(InMemoryAccessTokenRecords::new(&stores.clients)),
        standing: Arc::new(StandingOf::default()),
        memberships: Arc::new(MembershipsOf::default()),
        secrets: Arc::new(FakeSecretBox),
        codes: codes.clone(),
        keys: keys.clone(),
        verifier: Arc::new(FakeVerifier),
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
        codes,
        applications,
        keys,
        tokens,
    }
}

const ISSUER_OF: Issuer<'static> = Issuer {
    issuer: ISSUER,
    token_endpoint: ENDPOINT,
};

/// A tenant with an active signing key, a first-party application and two
/// resource servers.
async fn tenant(world: &World) -> (TenantContext, hodor_oauth::api::ApplicationId) {
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
                first_party: true,
            },
            Caller::system(),
        )
        .await
        .expect("application");
    world
        .applications
        .create_resource_server(
            &tenant,
            CreateResourceServer {
                application_id: application.id(),
                audience: AUDIENCE.to_owned(),
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
    let billing = world
        .applications
        .create_application(
            &tenant,
            ApplicationSettings {
                name: "Billing".to_owned(),
                first_party: true,
            },
            Caller::system(),
        )
        .await
        .expect("application");
    world
        .applications
        .create_resource_server(
            &tenant,
            CreateResourceServer {
                application_id: billing.id(),
                audience: OTHER_AUDIENCE.to_owned(),
                settings: ResourceServerSettings {
                    name: "Billing interface".to_owned(),
                    scopes: vec![ScopeDefinition {
                        name: "invoices".to_owned(),
                        description: "reads invoices".to_owned(),
                    }],
                },
            },
            Caller::system(),
        )
        .await
        .expect("resource server");
    (tenant, application.id())
}

async fn client(
    world: &World,
    tenant: &TenantContext,
    application: hodor_oauth::api::ApplicationId,
    client_type: ClientType,
    method: AuthenticationMethod,
) -> (ClientId, Option<ClientSecretValue>) {
    let mut settings = ClientSettings::new(
        "Payroll",
        client_type,
        vec![GrantType::AuthorizationCode],
        vec![REDIRECT.to_owned()],
    );
    settings.authentication_method = method;
    settings.allowed_scopes = vec![
        "openid".to_owned(),
        "read".to_owned(),
        "invoices".to_owned(),
    ];
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

fn person(world: &World) -> SignedInPerson {
    SignedInPerson {
        user_id: UserId::generate(),
        session_id: SessionId::generate(),
        signed_in_at: world.clock.now() - Duration::minutes(2),
        methods: vec!["password".to_owned()],
        acr: Some("urn:hodor:acr:single-factor".to_owned()),
    }
}

/// A code for `client`, issued as the authorization endpoint would, for the
/// scopes and resources given.
async fn code_for(
    world: &World,
    tenant: &TenantContext,
    client: ClientId,
    scope: &str,
    resources: &[&str],
) -> String {
    let challenge = s256_challenge(VERIFIER, &FakeDigest);
    let id = client.to_string();
    let mut pairs = vec![
        ("response_type", "code"),
        ("client_id", id.as_str()),
        ("redirect_uri", REDIRECT),
        ("scope", scope),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ];
    for resource in resources {
        pairs.push(("resource", resource));
    }
    let parameters = AuthorizationParameters::from_pairs(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
    );
    let request = world
        .codes
        .check(tenant, &parameters)
        .await
        .expect("storage")
        .expect("a valid request");
    world
        .codes
        .issue_code(tenant, &request, &person(world), Caller::system())
        .await
        .expect("code")
        .expose()
        .to_owned()
}

fn form(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

fn code_form(code: &str, extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut list = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
    ];
    list.extend_from_slice(extra);
    form(&list)
}

async fn ask(
    world: &World,
    tenant: &TenantContext,
    basic: Option<BasicCredentials>,
    pairs: Vec<(String, String)>,
) -> Result<IssuedTokens, TokenError> {
    let request = TokenRequest::parse(basic, pairs)?;
    world
        .tokens
        .token(tenant, ISSUER_OF, request, CorrelationId::generate())
        .await
        .expect("storage")
}

fn decoded(part: &str) -> Value {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("json")
}

#[tokio::test]
async fn a_public_client_exchanges_its_code_for_a_signed_access_token() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    let (client, _) = client(
        &world,
        &tenant,
        application,
        ClientType::Public,
        AuthenticationMethod::None,
    )
    .await;
    let code = code_for(&world, &tenant, client, "openid read", &[AUDIENCE]).await;
    let id = client.to_string();
    let tokens = ask(
        &world,
        &tenant,
        None,
        code_form(&code, &[("client_id", &id)]),
    )
    .await
    .expect("tokens");
    assert_eq!(tokens.token_type, "Bearer");
    assert_eq!(tokens.expires_in, 300);
    assert_eq!(tokens.scope, "openid read");
    assert!(tokens.refresh_token.is_none());

    let token = tokens.access_token.expose();
    let parts: Vec<&str> = token.split('.').collect();
    let [header, claims, signature] = parts.as_slice() else {
        panic!("three parts");
    };
    let header = decoded(header);
    let active = world
        .keys
        .published_keys(&tenant)
        .await
        .expect("keys")
        .into_iter()
        .find(|version| version.state() == hodor_keys::api::KeyState::Active)
        .expect("the active key");
    assert_eq!(
        header,
        json!({"alg": "ES256", "typ": "at+jwt", "kid": active.id().to_string()})
    );
    // The stand-in provider's signature is its label and the message.
    let signed = URL_SAFE_NO_PAD.decode(signature).expect("signature");
    let message = format!("{}.{}", parts[0], parts[1]);
    assert!(signed.ends_with(message.as_bytes()));
    assert!(String::from_utf8_lossy(&signed).starts_with(&format!(
        "fake|{}|{}|ES256|",
        tenant.tenant_id(),
        active.id()
    )));
    let claims = decoded(claims);
    assert_eq!(claims["iss"], ISSUER);
    assert_eq!(
        claims["aud"],
        json!([AUDIENCE, ISSUER]),
        "with openid, the token reads UserInfo too"
    );
    assert_eq!(claims["client_id"], id);
    assert_eq!(claims["scope"], "openid read");
    assert_eq!(
        claims["exp"].as_i64().expect("exp") - claims["iat"].as_i64().expect("iat"),
        300
    );

    // `openid` was asked for: an ID token for the client, signed by the
    // same key, bound to this access token.
    let id_token = tokens.id_token.as_ref().expect("an ID token").expose();
    let id_parts: Vec<&str> = id_token.split('.').collect();
    assert_eq!(
        decoded(id_parts[0]),
        json!({"alg": "ES256", "typ": "JWT", "kid": active.id().to_string()})
    );
    let id_claims = decoded(id_parts[1]);
    assert_eq!(id_claims["iss"], ISSUER);
    assert_eq!(id_claims["aud"], id, "the client alone");
    assert_eq!(id_claims["sub"], claims["sub"]);
    assert_eq!(id_claims["auth_time"], claims["auth_time"]);
    assert_eq!(id_claims["at_hash"], access_token_hash(token, &FakeDigest));
    assert_eq!(id_claims["amr"], json!(["pwd"]));
    assert_eq!(id_claims["acr"], "urn:hodor:acr:single-factor");
    assert!(id_claims.get("nonce").is_none(), "the request had none");
    assert_eq!(
        id_claims["exp"].as_i64().expect("exp") - id_claims["iat"].as_i64().expect("iat"),
        300
    );

    let events = world.units.committed_events();
    let issued = events
        .iter()
        .find(|event| event.event_type == "oauth.access_token_issued")
        .expect("the issue is recorded");
    let payload = issued.payload.to_string();
    assert!(payload.contains(&claims["jti"].as_str().expect("jti").to_owned()));
    assert!(
        !payload.contains(token),
        "the event never carries the token"
    );
}

#[tokio::test]
async fn a_token_carries_only_the_audiences_asked_for() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    let (client, _) = client(
        &world,
        &tenant,
        application,
        ClientType::Public,
        AuthenticationMethod::None,
    )
    .await;
    let id = client.to_string();
    let audience_of = |tokens: IssuedTokens| {
        let token = tokens.access_token.expose().to_owned();
        decoded(token.split('.').nth(1).expect("claims"))["aud"].clone()
    };

    let both = code_for(&world, &tenant, client, "read invoices", &[]).await;
    let tokens = ask(
        &world,
        &tenant,
        None,
        code_form(&both, &[("client_id", &id)]),
    )
    .await
    .expect("tokens");
    assert_eq!(audience_of(tokens), json!([AUDIENCE, OTHER_AUDIENCE]));

    let one = code_for(&world, &tenant, client, "read", &[AUDIENCE]).await;
    let tokens = ask(
        &world,
        &tenant,
        None,
        code_form(&one, &[("client_id", &id)]),
    )
    .await
    .expect("tokens");
    assert!(tokens.id_token.is_none(), "no openid, no ID token");
    assert_eq!(audience_of(tokens), json!(AUDIENCE));

    let none = code_for(&world, &tenant, client, "openid", &[]).await;
    let tokens = ask(
        &world,
        &tenant,
        None,
        code_form(&none, &[("client_id", &id)]),
    )
    .await
    .expect("tokens");
    assert_eq!(audience_of(tokens), json!(ISSUER), "Hodor itself");
}

#[tokio::test]
async fn a_code_is_refused_without_its_verifier_for_another_client_and_twice() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    let (client, _) = client(
        &world,
        &tenant,
        application,
        ClientType::Public,
        AuthenticationMethod::None,
    )
    .await;
    let (other, _) = self::client(
        &world,
        &tenant,
        application,
        ClientType::Public,
        AuthenticationMethod::None,
    )
    .await;
    let id = client.to_string();
    let other_id = other.to_string();
    let code = code_for(&world, &tenant, client, "read", &[]).await;

    let wrong_verifier = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT),
        (
            "code_verifier",
            "a-wrong-verifier-that-is-long-enough-to-be-a-verifier",
        ),
        ("client_id", &id),
    ]);
    let error = ask(&world, &tenant, None, wrong_verifier)
        .await
        .expect_err("refused");
    assert_eq!(error.error, "invalid_grant");

    // The code above was not redeemed by the refusal; another client still
    // cannot use it.
    let code = code_for(&world, &tenant, client, "read", &[]).await;
    let error = ask(
        &world,
        &tenant,
        None,
        code_form(&code, &[("client_id", &other_id)]),
    )
    .await
    .expect_err("another client's code");
    assert_eq!(error.error, "invalid_grant");

    let code = code_for(&world, &tenant, client, "read", &[]).await;
    ask(
        &world,
        &tenant,
        None,
        code_form(&code, &[("client_id", &id)]),
    )
    .await
    .expect("first redemption");
    let error = ask(
        &world,
        &tenant,
        None,
        code_form(&code, &[("client_id", &id)]),
    )
    .await
    .expect_err("second redemption");
    assert_eq!(error.error, "invalid_grant");
    let events = world.units.committed_event_types();
    assert!(events.iter().any(|kind| kind == "oauth.grant_revoked"));
}

#[tokio::test]
async fn a_secret_is_accepted_only_where_the_client_was_registered_to_send_it() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    let (basic_client, secret) = client(
        &world,
        &tenant,
        application,
        ClientType::Confidential,
        AuthenticationMethod::ClientSecretBasic,
    )
    .await;
    let secret = secret.expect("a secret").expose().to_owned();
    let id = basic_client.to_string();
    let credentials = |secret: &str| BasicCredentials {
        client_id: id.clone(),
        secret: hodor_kernel::Secret::from(secret.to_owned()),
    };

    let code = code_for(&world, &tenant, basic_client, "read", &[]).await;
    let error = ask(
        &world,
        &tenant,
        Some(credentials("hodor_cs_wrong")),
        code_form(&code, &[]),
    )
    .await
    .expect_err("wrong secret");
    assert_eq!(
        (error.error, error.reason),
        ("invalid_client", "the secret is wrong")
    );
    let error = ask(
        &world,
        &tenant,
        None,
        code_form(&code, &[("client_id", &id), ("client_secret", &secret)]),
    )
    .await
    .expect_err("the secret in the form");
    assert_eq!(
        (error.error, error.reason),
        (
            "invalid_client",
            "the client used another method than its own"
        )
    );
    let error = ask(
        &world,
        &tenant,
        None,
        code_form(&code, &[("client_id", &id)]),
    )
    .await
    .expect_err("no secret at all");
    assert_eq!(error.error, "invalid_client");
    ask(
        &world,
        &tenant,
        Some(credentials(&secret)),
        code_form(&code, &[]),
    )
    .await
    .expect("the right secret in the right place");

    let (post_client, post_secret) = client(
        &world,
        &tenant,
        application,
        ClientType::Confidential,
        AuthenticationMethod::ClientSecretPost,
    )
    .await;
    let post_id = post_client.to_string();
    let post_secret = post_secret.expect("a secret").expose().to_owned();
    let code = code_for(&world, &tenant, post_client, "read", &[]).await;
    ask(
        &world,
        &tenant,
        None,
        code_form(
            &code,
            &[("client_id", &post_id), ("client_secret", &post_secret)],
        ),
    )
    .await
    .expect("the secret in the form");
}

fn client_key() -> (String, PublicKey) {
    let x = vec![5_u8; 32];
    let y = vec![6_u8; 32];
    let jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "kid": "payroll-1",
        "x": URL_SAFE_NO_PAD.encode(&x),
        "y": URL_SAFE_NO_PAD.encode(&y),
    })
    .to_string();
    (jwk, PublicKey::P256 { x, y })
}

fn assertion(client: ClientId, key: &PublicKey, jti: &str, now: Timestamp) -> String {
    let encode = |value: &Value| URL_SAFE_NO_PAD.encode(value.to_string());
    let header = encode(&json!({"alg": "ES256", "kid": "payroll-1"}));
    let claims = encode(&json!({
        "iss": client.to_string(),
        "sub": client.to_string(),
        "aud": ENDPOINT,
        "exp": (now + Duration::minutes(1)).unix_timestamp(),
        "jti": jti,
    }));
    let input = format!("{header}.{claims}");
    let signature = fake_signature(SignatureAlgorithm::Es256, key, input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

#[tokio::test]
async fn an_assertion_proves_the_client_once() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    let (client, _) = client(
        &world,
        &tenant,
        application,
        ClientType::Confidential,
        AuthenticationMethod::PrivateKeyJwt,
    )
    .await;
    let (jwk, key) = client_key();
    world
        .applications
        .add_client_key(&tenant, client, &jwk, Caller::system())
        .await
        .expect("key");
    let signed = assertion(client, &key, "once", world.clock.now());
    let with = |signed: &str| {
        code_form(
            "",
            &[
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", signed),
            ],
        )
        .into_iter()
        .skip(4)
        .collect::<Vec<_>>()
    };
    let form_with = |code: &str, signed: &str| {
        let mut pairs = code_form(code, &[]);
        pairs.extend(with(signed));
        pairs
    };

    let code = code_for(&world, &tenant, client, "read", &[]).await;
    ask(&world, &tenant, None, form_with(&code, &signed))
        .await
        .expect("tokens");

    let code = code_for(&world, &tenant, client, "read", &[]).await;
    let error = ask(&world, &tenant, None, form_with(&code, &signed))
        .await
        .expect_err("the same assertion again");
    assert_eq!(
        (error.error, error.reason),
        ("invalid_client", "the assertion was used before")
    );

    // An assertion refused after it was remembered stays used: a wrong code
    // with a new assertion, then that assertion again with a good code.
    let fresh = assertion(client, &key, "spent-on-a-wrong-code", world.clock.now());
    let error = ask(
        &world,
        &tenant,
        None,
        form_with("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", &fresh),
    )
    .await
    .expect_err("wrong code");
    assert_eq!(error.error, "invalid_grant");
    let error = ask(&world, &tenant, None, form_with(&code, &fresh))
        .await
        .expect_err("used");
    assert_eq!(error.error, "invalid_client");

    // A secret is not how this client proves who it is.
    let id = client.to_string();
    let error = ask(
        &world,
        &tenant,
        None,
        code_form(&code, &[("client_id", &id)]),
    )
    .await
    .expect_err("no assertion");
    assert_eq!(error.error, "invalid_client");
}

#[tokio::test]
async fn an_unknown_disabled_or_foreign_client_gets_nothing() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    let (elsewhere, other_application) = self::tenant(&world).await;
    let (client, _) = client(
        &world,
        &tenant,
        application,
        ClientType::Public,
        AuthenticationMethod::None,
    )
    .await;
    let id = client.to_string();
    let code = code_for(&world, &tenant, client, "read", &[]).await;

    // The client and its code are of `tenant`: another tenant knows neither.
    let error = ask(
        &world,
        &elsewhere,
        None,
        code_form(&code, &[("client_id", &id)]),
    )
    .await
    .expect_err("another tenant");
    assert_eq!(error.error, "invalid_client");
    let (foreign, _) = self::client(
        &world,
        &elsewhere,
        other_application,
        ClientType::Public,
        AuthenticationMethod::None,
    )
    .await;
    let foreign_id = foreign.to_string();
    let error = ask(
        &world,
        &elsewhere,
        None,
        code_form(&code, &[("client_id", &foreign_id)]),
    )
    .await
    .expect_err("a code of another tenant");
    assert_eq!(error.error, "invalid_grant");

    for unknown in ["not-a-client", &ClientId::generate().to_string()] {
        let error = ask(
            &world,
            &tenant,
            None,
            code_form(&code, &[("client_id", unknown)]),
        )
        .await
        .expect_err("unknown");
        assert_eq!(error.error, "invalid_client");
    }

    world
        .applications
        .set_client_status(&tenant, client, Status::Disabled, Caller::system())
        .await
        .expect("disabled");
    let error = ask(
        &world,
        &tenant,
        None,
        code_form(&code, &[("client_id", &id)]),
    )
    .await
    .expect_err("disabled");
    assert_eq!(error.error, "invalid_client");
    world
        .applications
        .set_client_status(&tenant, client, Status::Enabled, Caller::system())
        .await
        .expect("enabled");
    world
        .applications
        .set_application_status(&tenant, application, Status::Disabled, Caller::system())
        .await
        .expect("application disabled");
    let error = ask(
        &world,
        &tenant,
        None,
        code_form(&code, &[("client_id", &id)]),
    )
    .await
    .expect_err("application disabled");
    assert_eq!(error.error, "invalid_client");
}

#[tokio::test]
async fn a_tenant_whose_key_was_revoked_signs_with_a_new_one_never_the_revoked() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    let (client, _) = client(
        &world,
        &tenant,
        application,
        ClientType::Public,
        AuthenticationMethod::None,
    )
    .await;
    let active = world
        .keys
        .published_keys(&tenant)
        .await
        .expect("keys")
        .remove(0);
    world
        .keys
        .revoke(&tenant, active.id(), "compromised", Caller::system())
        .await
        .expect("revoked");
    let id = client.to_string();
    let code = code_for(&world, &tenant, client, "read", &[]).await;
    let tokens = ask(
        &world,
        &tenant,
        None,
        code_form(&code, &[("client_id", &id)]),
    )
    .await
    .expect("a new key signs");
    let header = decoded(
        tokens
            .access_token
            .expose()
            .split('.')
            .next()
            .expect("header"),
    );
    assert_ne!(
        header["kid"],
        active.id().to_string(),
        "never the revoked key"
    );
    let published = world.keys.published_keys(&tenant).await.expect("keys");
    assert_eq!(
        published.len(),
        1,
        "the new key is published, the revoked one is not"
    );
    assert_eq!(header["kid"], published[0].id().to_string());
}

#[tokio::test]
async fn a_revoked_grant_gives_no_token() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    let (client, _) = client(
        &world,
        &tenant,
        application,
        ClientType::Public,
        AuthenticationMethod::None,
    )
    .await;
    let code = code_for(&world, &tenant, client, "read", &[]).await;
    // Revoke every grant of the tenant behind the code's back.
    let mut uow = hodor_kernel::UnitOfWorkFactory::begin(&world.units, &tenant)
        .await
        .expect("begin");
    for mut grant in world.grants.all(tenant.tenant_id()) {
        if grant.revoke("test", world.clock.now()).is_some() {
            world
                .grants
                .update(uow.as_mut(), &grant)
                .await
                .expect("revoked");
        }
        assert_eq!(grant.status, GrantStatus::Revoked);
    }
    uow.commit().await.expect("commit");
    let id = client.to_string();
    let error = ask(
        &world,
        &tenant,
        None,
        code_form(&code, &[("client_id", &id)]),
    )
    .await
    .expect_err("revoked");
    assert_eq!(
        (error.error, error.reason),
        ("invalid_grant", "the grant was revoked")
    );
}

#[tokio::test]
async fn the_in_memory_store_of_assertions_passes_the_contract() {
    let units = InMemoryUnitOfWorkFactory::default();
    let stores = InMemoryStores::default();
    let assertions = InMemoryClientAssertions::new(&stores.clients);
    run_assertion_contract(AssertionStorePorts {
        units_of_work: &units,
        applications: &stores.applications,
        clients: &stores.clients,
        assertions: &assertions,
    })
    .await;
}
