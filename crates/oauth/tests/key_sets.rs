//! A client's keys at its address, its `jwks_uri`, through the use cases
//! of the token and authorization endpoints, on the in-memory stores: the
//! set fetched when it is needed, kept for an hour at most, fetched again
//! for an unknown `kid` at most once a minute per client, and refused when
//! the address redirects, answers too much or does not answer.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::sealing::testing::FakeSecretBox;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, Clock as _, DomainError, ErrorKind, HttpClient, HttpMethod, HttpRequest, HttpResponse,
    PublicKey, SignatureAlgorithm, TenantContext, TenantId, Timestamp,
};
use hodor_keys::api::KeyService;
use hodor_keys::testing::{FakeKeyProvider, InMemoryKeys};
use hodor_oauth::api::{
    ASSERTION_TYPE, ApplicationId, ApplicationPorts, ApplicationService, ApplicationSettings,
    AuthenticationMethod, AuthorizationCodePorts, AuthorizationCodeService,
    AuthorizationParameters, ClientId, ClientKeySets, ClientSettings, ClientType, CreateClient,
    GrantType, Issuer, KEY_SET_ACCEPT, KEY_SET_TIME_LIMIT, MAX_KEY_SET_BYTES, PushedRequestPolicy,
    TokenPorts, TokenQuery, TokenService,
};
use hodor_oauth::testing::{
    DistinctRandom, FakeDestinations, FakeVerifier, InMemoryAccessTokenRecords,
    InMemoryAuthorizationCodes, InMemoryAuthorizationRequests, InMemoryClientAssertions,
    InMemoryGrants, InMemoryRefreshTokens, InMemoryStores, MembershipsOf, StandingOf,
    fake_signature,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use time::Duration;

const ISSUER: &str = "https://hodor.example.com/t/acme";
const TOKEN_ENDPOINT: &str = "https://hodor.example.com/t/acme/oauth2/token";
const INTROSPECTION: &str = "https://hodor.example.com/t/acme/oauth2/introspect";
const ADDRESS: &str = "https://payroll.example.com/jwks";
const REDIRECT: &str = "https://payroll.example.com/callback";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

const ISSUER_OF: Issuer<'static> = Issuer {
    issuer: ISSUER,
    token_endpoint: TOKEN_ENDPOINT,
};

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What each address answers: its status and its body.
type Answers = HashMap<String, (u16, Vec<u8>)>;

/// Key set addresses and what each answers, in place of the guarded
/// outbound client: an address given no answer does not answer. Every
/// request is kept.
#[derive(Clone, Default)]
struct Addresses {
    answers: Arc<Mutex<Answers>>,
    asked: Arc<Mutex<Vec<HttpRequest>>>,
}

impl Addresses {
    fn answer(&self, url: &str, status: u16, body: Vec<u8>) {
        lock(&self.answers).insert(url.to_owned(), (status, body));
    }

    fn serve(&self, keys: &[Value]) {
        self.answer(
            ADDRESS,
            200,
            json!({ "keys": keys }).to_string().into_bytes(),
        );
    }

    fn stop(&self) {
        lock(&self.answers).remove(ADDRESS);
    }

    fn asked(&self) -> usize {
        lock(&self.asked).len()
    }
}

#[async_trait::async_trait]
impl HttpClient for Addresses {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, DomainError> {
        lock(&self.asked).push(request.clone());
        let answer = lock(&self.answers).get(&request.url).cloned();
        answer
            .map(|(status, body)| HttpResponse {
                status,
                headers: vec![(
                    "location".to_owned(),
                    "https://internal.example/".to_owned(),
                )],
                body,
            })
            .ok_or_else(|| {
                DomainError::new(
                    ErrorKind::Unavailable,
                    "http.unreachable",
                    "the address did not answer",
                )
            })
    }
}

struct World {
    clock: Arc<FixedClock>,
    addresses: Addresses,
    applications: ApplicationService,
    codes: AuthorizationCodeService,
    tokens: TokenService,
}

/// The services of one server, sharing one [`ClientKeySets`], unless
/// `without_sets`.
fn world_with(without_sets: bool) -> World {
    let units = InMemoryUnitOfWorkFactory::default();
    let stores = InMemoryStores::default();
    let grants = InMemoryGrants::new(&stores.clients);
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + Duration::days(20_000),
    ));
    let addresses = Addresses::default();
    let sets = ClientKeySets::new(Arc::new(addresses.clone()), clock.clone());
    let mut codes = AuthorizationCodeService::new(AuthorizationCodePorts {
        units_of_work: Arc::new(units.clone()),
        applications: Arc::new(stores.applications.clone()),
        clients: Arc::new(stores.clients.clone()),
        resource_servers: Arc::new(stores.resource_servers.clone()),
        requests: Arc::new(InMemoryAuthorizationRequests::new(&stores.clients)),
        grants: Arc::new(grants.clone()),
        codes: Arc::new(InMemoryAuthorizationCodes::new(&grants)),
        memberships: Arc::new(MembershipsOf::default()),
        verifier: Arc::new(FakeVerifier),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    codes = codes
        .with_request_object_addresses(Arc::new(FakeDestinations), Arc::new(addresses.clone()));
    if !without_sets {
        codes = codes.with_client_key_sets(sets.clone());
    }
    let keys = KeyService::new(
        Arc::new(units.clone()),
        Arc::new(InMemoryKeys::default()),
        Arc::new(FakeKeyProvider),
        clock.clone(),
    );
    let mut tokens = TokenService::new(TokenPorts {
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
        keys,
        verifier: Arc::new(FakeVerifier),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    if !without_sets {
        tokens = tokens.with_client_key_sets(sets);
    }
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(units),
        applications: Arc::new(stores.applications),
        clients: Arc::new(stores.clients),
        resource_servers: Arc::new(stores.resource_servers),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    })
    .with_destinations(Arc::new(FakeDestinations));
    World {
        clock,
        addresses,
        applications,
        codes,
        tokens,
    }
}

fn world() -> World {
    world_with(false)
}

/// A P-256 key named `kid`, made from `fill`: as it is published, and as
/// the verifier reads it.
fn key(kid: &str, fill: u8) -> (Value, PublicKey) {
    let x = vec![fill; 32];
    let y = vec![fill.wrapping_add(1); 32];
    let jwk = json!({
        "kty": "EC", "crv": "P-256", "kid": kid, "use": "sig",
        "x": URL_SAFE_NO_PAD.encode(&x), "y": URL_SAFE_NO_PAD.encode(&y),
    });
    (jwk, PublicKey::P256 { x, y })
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

fn settings(jwks_uri: Option<&str>) -> ClientSettings {
    let mut settings = ClientSettings::new(
        "Payroll web",
        ClientType::Confidential,
        vec![GrantType::AuthorizationCode],
        vec![REDIRECT.to_owned()],
    );
    settings.authentication_method = AuthenticationMethod::PrivateKeyJwt;
    settings.allowed_scopes = vec!["openid".to_owned()];
    settings.jwks_uri = jwks_uri.map(str::to_owned);
    settings
}

async fn create(
    world: &World,
    tenant: &TenantContext,
    settings: ClientSettings,
) -> Result<ClientId, DomainError> {
    let application = application(world, tenant).await;
    world
        .applications
        .create_client(
            tenant,
            CreateClient {
                application_id: application,
                client_type: ClientType::Confidential,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .map(|(client, _)| client.id())
}

/// A client whose keys are at [`ADDRESS`], in a new tenant.
async fn client_at_address(world: &World) -> (TenantContext, ClientId) {
    let tenant = TenantContext::assume(TenantId::generate());
    let client = create(world, &tenant, settings(Some(ADDRESS)))
        .await
        .expect("client");
    (tenant, client)
}

fn encode(value: &Value) -> String {
    URL_SAFE_NO_PAD.encode(value.to_string())
}

fn signed_with(header: &Value, claims: &Value, key: &PublicKey) -> String {
    let input = format!("{}.{}", encode(header), encode(claims));
    let signature = fake_signature(SignatureAlgorithm::Es256, key, input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

/// An assertion of `client`, signed with `key` and naming `kid`.
fn assertion(world: &World, client: ClientId, kid: &str, key: &PublicKey, jti: &str) -> String {
    signed_with(
        &json!({"alg": "ES256", "kid": kid}),
        &json!({
            "iss": client.to_string(),
            "sub": client.to_string(),
            "aud": TOKEN_ENDPOINT,
            "exp": (world.clock.now() + Duration::minutes(1)).unix_timestamp(),
            "jti": jti,
        }),
        key,
    )
}

/// Whether the client proves who it is with `assertion`, at the
/// introspection endpoint: the answer for a token nobody knows.
async fn proves(world: &World, tenant: &TenantContext, assertion: &str) -> bool {
    let query = TokenQuery::parse(
        None,
        [
            ("token".to_owned(), "unknown".to_owned()),
            (
                "client_assertion_type".to_owned(),
                ASSERTION_TYPE.to_owned(),
            ),
            ("client_assertion".to_owned(), assertion.to_owned()),
        ],
    )
    .expect("a query");
    match world
        .tokens
        .introspect(tenant, ISSUER_OF, INTROSPECTION, query)
        .await
        .expect("storage")
    {
        Ok(answer) => {
            assert_eq!(answer["active"], false);
            true
        }
        Err(refusal) => {
            assert_eq!(refusal.error, "invalid_client");
            false
        }
    }
}

/// Signs an assertion with a new `jti` each time.
struct Signer<'a> {
    world: &'a World,
    tenant: &'a TenantContext,
    client: ClientId,
    count: usize,
}

impl Signer<'_> {
    async fn proves(&mut self, kid: &str, key: &PublicKey) -> bool {
        self.count += 1;
        let assertion = assertion(
            self.world,
            self.client,
            kid,
            key,
            &format!("assertion-{}", self.count),
        );
        proves(self.world, self.tenant, &assertion).await
    }
}

fn signer<'a>(world: &'a World, tenant: &'a TenantContext, client: ClientId) -> Signer<'a> {
    Signer {
        world,
        tenant,
        client,
        count: 0,
    }
}

#[tokio::test]
async fn an_assertion_is_checked_with_the_keys_at_the_clients_address() {
    let world = world();
    let (jwk, published) = key("one", 3);
    world.addresses.serve(&[jwk]);
    let (tenant, client) = client_at_address(&world).await;
    assert_eq!(world.addresses.asked(), 0, "nothing fetched when saved");

    let mut sign = signer(&world, &tenant, client);
    assert!(sign.proves("one", &published).await);
    assert_eq!(world.addresses.asked(), 1);
    let asked = lock(&world.addresses.asked)[0].clone();
    assert_eq!(asked.method, HttpMethod::Get);
    assert_eq!(asked.url, ADDRESS);
    assert_eq!(asked.time_limit, Some(KEY_SET_TIME_LIMIT));
    assert!(
        asked
            .headers
            .contains(&("accept".to_owned(), KEY_SET_ACCEPT.to_owned()))
    );

    // Kept: the next assertions fetch nothing.
    world.clock.advance(Duration::minutes(30));
    assert!(sign.proves("one", &published).await);
    assert!(sign.proves("one", &published).await);
    assert_eq!(world.addresses.asked(), 1);

    // A key the client does not publish proves nothing.
    let (_, other) = key("one", 9);
    assert!(!sign.proves("one", &other).await);
}

#[tokio::test]
async fn a_key_rotated_at_the_address_is_accepted_from_its_first_use() {
    let world = world();
    let (one, first) = key("one", 3);
    let (two, second) = key("two", 5);
    world.addresses.serve(std::slice::from_ref(&one));
    let (tenant, client) = client_at_address(&world).await;
    let mut sign = signer(&world, &tenant, client);
    assert!(sign.proves("one", &first).await);

    // The client publishes its new key, removes the old one, and signs with
    // the new one: its `kid` is unknown, so the address is fetched again.
    world.clock.advance(Duration::minutes(5));
    world.addresses.serve(&[two]);
    assert!(sign.proves("two", &second).await);
    assert_eq!(world.addresses.asked(), 2);
    // The old key is no longer in the set.
    assert!(!sign.proves("one", &first).await);
    assert_eq!(world.addresses.asked(), 2, "fetched less than a minute ago");
}

#[tokio::test]
async fn a_key_removed_from_the_address_stops_being_accepted_within_the_hour() {
    let world = world();
    let (one, first) = key("one", 3);
    world.addresses.serve(&[one]);
    let (tenant, client) = client_at_address(&world).await;
    let mut sign = signer(&world, &tenant, client);
    assert!(sign.proves("one", &first).await);

    // The key leaks and the client removes it. A server that kept the set
    // still accepts it, for the rest of the hour and no longer.
    world.addresses.serve(&[]);
    world.clock.advance(Duration::minutes(59));
    assert!(sign.proves("one", &first).await);
    assert_eq!(world.addresses.asked(), 1);
    world.clock.advance(Duration::minutes(1));
    assert!(!sign.proves("one", &first).await);
    assert_eq!(world.addresses.asked(), 2);

    // Even when the address stops answering: an old set is never used.
    let (one, _) = key("one", 3);
    world.addresses.serve(&[one]);
    world.clock.advance(Duration::minutes(1));
    assert!(sign.proves("one", &first).await, "published again");
    world.addresses.stop();
    world.clock.advance(Duration::hours(1));
    assert!(!sign.proves("one", &first).await);
}

#[tokio::test]
async fn a_burst_of_unknown_keys_causes_one_fetch_a_minute() {
    let world = world();
    let (one, first) = key("one", 3);
    world.addresses.serve(&[one]);
    let (tenant, client) = client_at_address(&world).await;
    let mut sign = signer(&world, &tenant, client);
    assert!(sign.proves("one", &first).await);
    assert_eq!(world.addresses.asked(), 1);

    world.clock.advance(Duration::minutes(1));
    for n in 0..20 {
        let (_, unknown) = key(&format!("unknown-{n}"), 7);
        assert!(!sign.proves(&format!("unknown-{n}"), &unknown).await);
    }
    assert_eq!(world.addresses.asked(), 2, "one fetch for the burst");
    world.clock.advance(Duration::seconds(59));
    for n in 0..20 {
        let (_, unknown) = key(&format!("more-{n}"), 7);
        assert!(!sign.proves(&format!("more-{n}"), &unknown).await);
    }
    assert_eq!(world.addresses.asked(), 2, "still within the minute");
    world.clock.advance(Duration::seconds(1));
    let (_, unknown) = key("after", 7);
    assert!(!sign.proves("after", &unknown).await);
    assert_eq!(world.addresses.asked(), 3);
    // The known key was accepted all along, from the kept set.
    assert!(sign.proves("one", &first).await);
    assert_eq!(world.addresses.asked(), 3);
}

#[tokio::test]
async fn an_address_that_redirects_answers_too_much_or_no_set_gives_no_keys() {
    let world = world();
    let (one, first) = key("one", 3);
    let set = json!({ "keys": [one] }).to_string().into_bytes();
    let (tenant, client) = client_at_address(&world).await;
    let mut sign = signer(&world, &tenant, client);

    // A redirect is not followed, even to an address that would answer.
    world.addresses.answer(ADDRESS, 302, Vec::new());
    world
        .addresses
        .answer("https://internal.example/", 200, set.clone());
    assert!(!sign.proves("one", &first).await);
    assert_eq!(world.addresses.asked(), 1);
    assert!(
        lock(&world.addresses.asked)
            .iter()
            .all(|asked| asked.url == ADDRESS),
        "only the address itself is asked"
    );

    let mut long = set.clone();
    long.truncate(long.len() - 1);
    long.extend(b", \"padding\": \"");
    long.extend(std::iter::repeat_n(b' ', MAX_KEY_SET_BYTES));
    long.extend(b"\"}");
    for (status, body) in [
        (200, long),
        (500, set.clone()),
        (200, b"[]".to_vec()),
        (200, b"not json".to_vec()),
    ] {
        world.clock.advance(Duration::minutes(1));
        world.addresses.answer(ADDRESS, status, body);
        assert!(!sign.proves("one", &first).await, "{status}");
    }

    // A failed fetch keeps a set that is still young enough.
    world.clock.advance(Duration::minutes(1));
    world.addresses.answer(ADDRESS, 200, set);
    assert!(sign.proves("one", &first).await);
    world.addresses.stop();
    world.clock.advance(Duration::minutes(1));
    let (_, unknown) = key("two", 7);
    assert!(!sign.proves("two", &unknown).await);
    assert!(sign.proves("one", &first).await);
}

#[tokio::test]
async fn one_clients_set_is_never_used_for_another_client() {
    let world = world();
    let (one, first) = key("one", 3);
    world.addresses.serve(&[one]);
    let (tenant, client) = client_at_address(&world).await;
    assert!(signer(&world, &tenant, client).proves("one", &first).await);

    // Another client of another tenant at the same address has a set of
    // its own, fetched for it.
    let (theirs, their_client) = client_at_address(&world).await;
    assert!(
        signer(&world, &theirs, their_client)
            .proves("one", &first)
            .await
    );
    assert_eq!(world.addresses.asked(), 2);

    // A client whose keys Hodor keeps is never checked with an address's.
    let own = create(&world, &tenant, settings(None))
        .await
        .expect("client");
    assert!(!signer(&world, &tenant, own).proves("one", &first).await);
    assert_eq!(world.addresses.asked(), 2);
}

#[tokio::test]
async fn without_key_sets_a_client_at_an_address_has_no_keys() {
    let world = world_with(true);
    let (one, first) = key("one", 3);
    world.addresses.serve(&[one]);
    let (tenant, client) = client_at_address(&world).await;
    assert!(!signer(&world, &tenant, client).proves("one", &first).await);
    assert_eq!(world.addresses.asked(), 0);
}

fn request_object(world: &World, client: ClientId, kid: &str, key: &PublicKey) -> String {
    signed_with(
        &json!({"alg": "ES256", "kid": kid}),
        &json!({
            "iss": client.to_string(),
            "aud": ISSUER,
            "exp": (world.clock.now() + Duration::minutes(5)).unix_timestamp(),
            "client_id": client.to_string(),
            "response_type": "code",
            "redirect_uri": REDIRECT,
            "scope": "openid",
            "state": "inside",
            "code_challenge": CHALLENGE,
            "code_challenge_method": "S256",
        }),
        key,
    )
}

async fn checks(world: &World, tenant: &TenantContext, client: ClientId, object: &str) -> bool {
    let parameters = AuthorizationParameters::from_pairs([
        ("client_id".to_owned(), client.to_string()),
        ("response_type".to_owned(), "code".to_owned()),
        ("scope".to_owned(), "openid".to_owned()),
        ("request".to_owned(), object.to_owned()),
    ]);
    world
        .codes
        .check(tenant, ISSUER, &parameters, &PushedRequestPolicy::default())
        .await
        .expect("storage")
        .is_ok()
}

#[tokio::test]
async fn a_request_object_is_checked_with_the_keys_at_the_clients_address() {
    let world = world();
    let (one, first) = key("one", 3);
    let (two, second) = key("two", 5);
    world.addresses.serve(std::slice::from_ref(&one));
    let (tenant, client) = client_at_address(&world).await;

    assert!(
        checks(
            &world,
            &tenant,
            client,
            &request_object(&world, client, "one", &first)
        )
        .await
    );
    // The token endpoint shares the set the authorization endpoint fetched.
    assert!(signer(&world, &tenant, client).proves("one", &first).await);
    assert_eq!(world.addresses.asked(), 1);

    // A rotated key is fetched for, once a minute at most.
    world.addresses.serve(&[one, two]);
    let rotated = request_object(&world, client, "two", &second);
    assert!(!checks(&world, &tenant, client, &rotated).await);
    world.clock.advance(Duration::minutes(1));
    assert!(checks(&world, &tenant, client, &rotated).await);
    assert_eq!(world.addresses.asked(), 2);

    // An object signed by a key the client does not publish is refused.
    let (_, stranger) = key("two", 11);
    assert!(
        !checks(
            &world,
            &tenant,
            client,
            &request_object(&world, client, "two", &stranger)
        )
        .await
    );
}

#[tokio::test]
async fn an_address_is_checked_when_it_is_set_and_never_with_keys() {
    let world = world();
    let tenant = TenantContext::assume(TenantId::generate());
    for (address, code) in [
        (
            "https://internal.example/jwks",
            "oauth.client_jwks_uri_forbidden",
        ),
        (
            "https://nowhere.example/jwks",
            "oauth.client_jwks_uri_unresolvable",
        ),
        (
            "http://payroll.example.com/jwks",
            "oauth.client_jwks_uri_invalid",
        ),
        (
            "https://payroll.example.com/jwks#keys",
            "oauth.client_jwks_uri_invalid",
        ),
    ] {
        let error = create(&world, &tenant, settings(Some(address)))
            .await
            .expect_err(address);
        assert_eq!(error.code(), code, "{address}");
    }
    let mut secret = settings(Some(ADDRESS));
    secret.authentication_method = AuthenticationMethod::ClientSecretBasic;
    assert_eq!(
        create(&world, &tenant, secret)
            .await
            .expect_err("a secret")
            .code(),
        "oauth.client_jwks_uri_invalid"
    );

    // A client at an address takes no key, and a client with keys no
    // address.
    let (jwk, _) = key("one", 3);
    let at_address = create(&world, &tenant, settings(Some(ADDRESS)))
        .await
        .expect("client");
    let error = world
        .applications
        .add_client_key(&tenant, at_address, &jwk.to_string(), Caller::system())
        .await
        .expect_err("an address");
    assert_eq!(error.code(), "oauth.client_keys_at_address");
    let with_keys = create(&world, &tenant, settings(None))
        .await
        .expect("client");
    world
        .applications
        .add_client_key(&tenant, with_keys, &jwk.to_string(), Caller::system())
        .await
        .expect("a key");
    let error = world
        .applications
        .change_client(
            &tenant,
            with_keys,
            settings(Some(ADDRESS)),
            Caller::system(),
        )
        .await
        .expect_err("keys");
    assert_eq!(error.code(), "oauth.client_jwks_uri_with_keys");
    assert_eq!(world.addresses.asked(), 0, "nothing is fetched when saved");
}

/// What the authorization endpoint makes of a request naming `reference`,
/// an address of the client's, as `request_uri`.
async fn by_reference(
    world: &World,
    tenant: &TenantContext,
    client: ClientId,
    reference: &str,
) -> Result<hodor_oauth::api::AuthorizationRequest, hodor_oauth::api::AuthorizationRefusal> {
    let parameters = AuthorizationParameters::from_pairs([
        ("client_id".to_owned(), client.to_string()),
        ("response_type".to_owned(), "code".to_owned()),
        ("request_uri".to_owned(), reference.to_owned()),
    ]);
    world
        .codes
        .check(tenant, ISSUER, &parameters, &PushedRequestPolicy::default())
        .await
        .expect("storage")
}

#[tokio::test]
async fn a_request_object_fetched_at_a_request_object_address_is_checked_with_the_keys_at_the_key_set_address()
 {
    const REQUESTS: &str = "https://payroll.example.com/requests/";
    let world = world();
    let (one, first) = key("one", 3);
    let (two, second) = key("two", 5);
    world.addresses.serve(std::slice::from_ref(&one));
    let tenant = TenantContext::assume(TenantId::generate());
    let mut at_addresses = settings(Some(ADDRESS));
    at_addresses.request_uris = vec![REQUESTS.to_owned()];
    let client = create(&world, &tenant, at_addresses).await.expect("client");
    let object = request_object(&world, client, "one", &first);
    world
        .addresses
        .answer(&format!("{REQUESTS}one"), 200, object.into_bytes());
    let checked = by_reference(&world, &tenant, client, &format!("{REQUESTS}one")).await;
    assert!(checked.is_ok(), "{checked:?}");
    let asked: Vec<String> = lock(&world.addresses.asked)
        .iter()
        .map(|asked| asked.url.clone())
        .collect();
    assert_eq!(asked, [format!("{REQUESTS}one"), ADDRESS.to_owned()]);

    // The client rotates its key and signs its next object with the new
    // one: the key set address is fetched again for it, after the minute.
    world.addresses.serve(&[one, two]);
    world.clock.advance(Duration::minutes(1));
    let rotated = request_object(&world, client, "two", &second);
    world
        .addresses
        .answer(&format!("{REQUESTS}two"), 200, rotated.into_bytes());
    let checked = by_reference(&world, &tenant, client, &format!("{REQUESTS}two")).await;
    assert!(checked.is_ok(), "{checked:?}");
    assert_eq!(world.addresses.asked(), 4);

    // An object signed by a key the client does not publish is refused.
    let (_, stranger) = key("two", 11);
    let forged = request_object(&world, client, "two", &stranger);
    world
        .addresses
        .answer(&format!("{REQUESTS}forged"), 200, forged.into_bytes());
    assert!(
        by_reference(&world, &tenant, client, &format!("{REQUESTS}forged"))
            .await
            .is_err()
    );
}
