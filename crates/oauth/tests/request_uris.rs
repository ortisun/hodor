//! Request objects at a client's address through the use cases of the
//! authorization endpoint, on the in-memory stores, with a stand-in for
//! the guarded outbound client that says what was fetched: only an
//! address the client registered is fetched, only when it may be called,
//! within the bounds, and what it answered is checked as a request object.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, Clock as _, DestinationCheck, Digest as _, DomainError, HttpMethod, PublicKey,
    SignatureAlgorithm, TenantContext, TenantId, Timestamp,
};
use hodor_oauth::api::{
    ApplicationPorts, ApplicationService, ApplicationSettings, AuthenticationMethod,
    AuthorizationCodePorts, AuthorizationCodeService, AuthorizationError, AuthorizationParameters,
    AuthorizationRefusal, ClientId, ClientSettings, ClientType, CreateClient, GrantType,
    MAX_REQUEST_OBJECT_BYTES, PushedRequestPolicy, ResponseMode,
};
use hodor_oauth::testing::{
    AddressAnswer, DistinctRandom, FakeDestinations, FakeVerifier, InMemoryAuthorizationCodes,
    InMemoryAuthorizationRequests, InMemoryGrants, InMemoryStores, MembershipsOf,
    RequestObjectAddresses, fake_signature,
};
use serde_json::{Value, json};
use std::sync::Arc;
use time::Duration;

const ISSUER: &str = "https://hodor.example.com/t/acme";
const REDIRECT: &str = "https://payroll.example.com/callback";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const REGISTERED: &str = "https://payroll.example.com/requests/";

/// Accepts every address: a name that led somewhere public when it was
/// registered, whatever it leads to now.
struct AnyDestination;

#[async_trait::async_trait]
impl DestinationCheck for AnyDestination {
    async fn check(&self, _url: &str) -> Result<(), DomainError> {
        Ok(())
    }
}

struct World {
    clock: Arc<FixedClock>,
    service: AuthorizationCodeService,
    /// The same use cases with no outbound client.
    unable: AuthorizationCodeService,
    applications: ApplicationService,
    /// Registers any address, for addresses that resolve elsewhere since.
    lenient: ApplicationService,
    addresses: RequestObjectAddresses,
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
    let addresses = RequestObjectAddresses::default();
    let unable = AuthorizationCodeService::new(AuthorizationCodePorts {
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
    let service = unable
        .clone()
        .with_request_object_addresses(Arc::new(FakeDestinations), Arc::new(addresses.clone()));
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
        unable,
        lenient: applications
            .clone()
            .with_destinations(Arc::new(AnyDestination)),
        applications: applications.with_destinations(Arc::new(FakeDestinations)),
        addresses,
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

/// A confidential client with `private_key_jwt`, one P-256 key made from
/// `fill`, and the request object addresses `request_uris`, registered
/// through `applications` in a first-party application of `tenant`.
async fn signing_client(
    applications: &ApplicationService,
    tenant: &TenantContext,
    fill: u8,
    request_uris: &[&str],
    pushed_only: bool,
) -> Result<(ClientId, PublicKey), DomainError> {
    let application = applications
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
    settings.request_uris = request_uris.iter().map(|uri| (*uri).to_owned()).collect();
    settings.require_pushed_requests = pushed_only;
    let (client, _) = applications
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
        .await?;
    let (jwk, key) = p256_key(fill);
    applications
        .add_client_key(tenant, client.id(), &jwk, Caller::system())
        .await
        .expect("key");
    Ok((client.id(), key))
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

/// The hash a client writes after `#`: the SHA-256 of the content, in
/// base64url, as the stand-in for SHA-256 computes it.
fn hash_of(content: &str) -> String {
    URL_SAFE_NO_PAD.encode(FakeDigest.sha256(content.as_bytes()))
}

fn by_reference(
    client: ClientId,
    reference: &str,
    more: &[(&str, &str)],
) -> AuthorizationParameters {
    let mut pairs = vec![
        ("client_id".to_owned(), client.to_string()),
        ("request_uri".to_owned(), reference.to_owned()),
        ("redirect_uri".to_owned(), REDIRECT.to_owned()),
        ("state".to_owned(), "outside".to_owned()),
    ];
    pairs.extend(
        more.iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
    );
    AuthorizationParameters::from_pairs(pairs)
}

async fn check(
    service: &AuthorizationCodeService,
    tenant: &TenantContext,
    parameters: &AuthorizationParameters,
) -> Result<hodor_oauth::api::AuthorizationRequest, AuthorizationRefusal> {
    service
        .check(tenant, ISSUER, parameters, &PushedRequestPolicy::default())
        .await
        .expect("storage")
}

fn refused(error: &'static str, description: &'static str) -> AuthorizationRefusal {
    AuthorizationRefusal::Redirect(AuthorizationError {
        redirect_uri: REDIRECT.to_owned(),
        error,
        description,
        state: Some("outside".to_owned()),
        mode: ResponseMode::Query,
    })
}

#[tokio::test]
async fn a_request_object_at_a_registered_address_is_fetched_and_is_the_request() {
    let world = world();
    let tenant = TenantContext::assume(TenantId::generate());
    let (client, key) = signing_client(&world.applications, &tenant, 3, &[REGISTERED], false)
        .await
        .expect("client");
    let object = signed(&key, &claims(&world, client));
    let address = format!("{REGISTERED}one");
    // Served with a line end after it, as a file usually is.
    world.addresses.serve(&address, &format!("{object}\n"));

    let reference = format!("{address}#{}", hash_of(&format!("{object}\n")));
    let checked = check(
        &world.service,
        &tenant,
        &by_reference(client, &reference, &[("response_type", "code")]),
    )
    .await
    .expect("accepted");
    assert_eq!(checked.client_id, client);
    assert_eq!(checked.state.as_deref(), Some("inside"), "the object's");
    assert_eq!(checked.nonce.as_deref(), Some("n-0S6_WzA2Mj"));

    let asked = world.addresses.asked();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].method, HttpMethod::Get);
    assert_eq!(asked[0].url, address, "without its fragment");
    assert_eq!(asked[0].time_limit, Some(std::time::Duration::from_secs(5)));
    assert!(
        asked[0].headers.contains(&(
            "accept".to_owned(),
            "application/oauth-authz-req+jwt, application/jwt".to_owned()
        )),
        "{:?}",
        asked[0].headers
    );

    // Without a fragment it is read without a hash, and it is fetched
    // again: nothing is kept.
    check(
        &world.service,
        &tenant,
        &by_reference(client, &address, &[]),
    )
    .await
    .expect("accepted");
    assert_eq!(world.addresses.fetched(), [address.clone(), address]);
}

#[tokio::test]
async fn an_address_the_client_did_not_register_is_never_fetched() {
    let world = world();
    let tenant = TenantContext::assume(TenantId::generate());
    let (client, key) = signing_client(&world.applications, &tenant, 3, &[REGISTERED], false)
        .await
        .expect("client");
    let (without, _) = signing_client(&world.applications, &tenant, 4, &[], false)
        .await
        .expect("client");
    let object = signed(&key, &claims(&world, client));
    for address in [
        "https://payroll.example.com/other/one",
        "https://payroll.example.com/requests",
        "https://payroll.example.com.example.org/requests/one",
        "https://attacker.example.org/requests/one",
        "http://payroll.example.com/requests/one",
    ] {
        world.addresses.serve(address, &object);
        let answer = check(&world.service, &tenant, &by_reference(client, address, &[])).await;
        assert_eq!(
            answer,
            Err(refused(
                "invalid_request_uri",
                "the request_uri is not at an address the client registered"
            )),
            "{address}"
        );
    }
    // A client with no address has none registered.
    let address = format!("{REGISTERED}one");
    world.addresses.serve(&address, &object);
    let answer = check(
        &world.service,
        &tenant,
        &by_reference(without, &address, &[]),
    )
    .await;
    assert!(
        matches!(
            answer,
            Err(AuthorizationRefusal::Redirect(AuthorizationError {
                error: "invalid_request_uri",
                ..
            }))
        ),
        "{answer:?}"
    );
    assert!(world.addresses.fetched().is_empty(), "nothing was fetched");
}

#[tokio::test]
async fn a_refused_address_is_answered_in_the_response_mode_named_beside_it() {
    let world = world();
    let tenant = TenantContext::assume(TenantId::generate());
    let (client, _) = signing_client(&world.applications, &tenant, 3, &[REGISTERED], false)
        .await
        .expect("client");
    let answer = check(
        &world.service,
        &tenant,
        &by_reference(
            client,
            "https://attacker.example.org/requests/one",
            &[("response_type", "code"), ("response_mode", "form_post")],
        ),
    )
    .await;
    assert_eq!(
        answer,
        Err(AuthorizationRefusal::Redirect(AuthorizationError {
            redirect_uri: REDIRECT.to_owned(),
            error: "invalid_request_uri",
            description: "the request_uri is not at an address the client registered",
            state: Some("outside".to_owned()),
            mode: ResponseMode::FormPost,
        }))
    );
    assert!(world.addresses.fetched().is_empty(), "nothing was fetched");
}

#[tokio::test]
async fn nothing_is_fetched_for_a_request_that_is_refused_anyway() {
    let world = world();
    let tenant = TenantContext::assume(TenantId::generate());
    let elsewhere = TenantContext::assume(TenantId::generate());
    let (client, key) = signing_client(&world.applications, &tenant, 3, &[REGISTERED], false)
        .await
        .expect("client");
    let (pushes, _) = signing_client(&world.applications, &tenant, 4, &[REGISTERED], true)
        .await
        .expect("client");
    let (theirs, _) = signing_client(&world.applications, &elsewhere, 5, &[], false)
        .await
        .expect("client");
    let address = format!("{REGISTERED}one");
    world
        .addresses
        .serve(&address, &signed(&key, &claims(&world, client)));

    // `request` beside it.
    let answer = check(
        &world.service,
        &tenant,
        &by_reference(client, &address, &[("request", "eyJ.eyJ.")]),
    )
    .await;
    assert_eq!(
        answer,
        Err(refused(
            "invalid_request",
            "request and request_uri cannot be given together"
        ))
    );
    // A client that must push, and every client of a tenant that requires
    // it.
    let answer = check(
        &world.service,
        &tenant,
        &by_reference(pushes, &address, &[]),
    )
    .await;
    assert_eq!(
        answer,
        Err(refused(
            "invalid_request",
            "this client must push its authorization requests"
        ))
    );
    let answer = world
        .service
        .check(
            &tenant,
            ISSUER,
            &by_reference(client, &address, &[]),
            &PushedRequestPolicy {
                required: true,
                ..PushedRequestPolicy::default()
            },
        )
        .await
        .expect("storage");
    assert_eq!(
        answer,
        Err(refused(
            "invalid_request",
            "this client must push its authorization requests"
        ))
    );
    // The client at another tenant, unknown there, and that tenant's own
    // client, which registered nothing.
    for named in [client, theirs] {
        let answer = check(
            &world.service,
            &elsewhere,
            &by_reference(named, &address, &[]),
        )
        .await;
        assert!(answer.is_err(), "{answer:?}");
    }
    assert_eq!(
        check(
            &world.service,
            &elsewhere,
            &by_reference(client, &address, &[])
        )
        .await,
        Err(AuthorizationRefusal::NotRedirectable(
            "oauth.authorization_client_unknown"
        ))
    );
    assert!(world.addresses.fetched().is_empty(), "nothing was fetched");
}

#[tokio::test]
async fn an_address_that_leads_to_a_private_network_is_refused() {
    let world = world();
    let tenant = TenantContext::assume(TenantId::generate());

    // Refused when it is registered.
    for (address, code) in [
        (
            "https://10.0.0.7/requests/",
            "oauth.client_request_uri_forbidden",
        ),
        (
            "https://localhost/requests/",
            "oauth.client_request_uri_forbidden",
        ),
        (
            "https://nowhere.example/requests/",
            "oauth.client_request_uri_unresolvable",
        ),
    ] {
        let error = signing_client(&world.applications, &tenant, 3, &[address], false)
            .await
            .expect_err(address);
        assert_eq!(error.code(), code, "{address}");
    }

    // A name that led somewhere public when it was registered and leads
    // inside now is refused when it is to be fetched, and not fetched.
    let private = [
        "https://10.0.0.7/requests/",
        "https://internal.example/requests/",
    ];
    let (client, key) = signing_client(&world.lenient, &tenant, 3, &private, false)
        .await
        .expect("client");
    let object = signed(&key, &claims(&world, client));
    for registered in private {
        let address = format!("{registered}one");
        world.addresses.serve(&address, &object);
        let answer = check(
            &world.service,
            &tenant,
            &by_reference(client, &address, &[]),
        )
        .await;
        assert_eq!(
            answer,
            Err(refused(
                "invalid_request_uri",
                "the request_uri could not be fetched"
            )),
            "{address}"
        );
    }
    assert!(world.addresses.fetched().is_empty(), "nothing was fetched");

    // The guarded client checks again on the resolution it connects with.
    let (client, _) = signing_client(&world.applications, &tenant, 4, &[REGISTERED], false)
        .await
        .expect("client");
    let address = format!("{REGISTERED}one");
    world.addresses.answer(
        &address,
        AddressAnswer::Failure("http.destination_forbidden"),
    );
    let answer = check(
        &world.service,
        &tenant,
        &by_reference(client, &address, &[]),
    )
    .await;
    assert_eq!(
        answer,
        Err(refused(
            "invalid_request_uri",
            "the request_uri could not be fetched"
        ))
    );
}

#[tokio::test]
async fn content_whose_hash_differs_from_the_fragment_is_refused() {
    let world = world();
    let tenant = TenantContext::assume(TenantId::generate());
    let (client, key) = signing_client(&world.applications, &tenant, 3, &[REGISTERED], false)
        .await
        .expect("client");
    let object = signed(&key, &claims(&world, client));
    let address = format!("{REGISTERED}one");
    world.addresses.serve(&address, &object);
    let changed = signed(&key, &json!({"iss": client.to_string(), "scope": "openid"}));
    for fragment in [hash_of(&changed), String::new(), "AAAA".to_owned()] {
        let answer = check(
            &world.service,
            &tenant,
            &by_reference(client, &format!("{address}#{fragment}"), &[]),
        )
        .await;
        assert_eq!(
            answer,
            Err(refused(
                "invalid_request_uri",
                "the content of the request_uri does not have the hash after #"
            )),
            "{fragment}"
        );
    }
    check(
        &world.service,
        &tenant,
        &by_reference(client, &format!("{address}#{}", hash_of(&object)), &[]),
    )
    .await
    .expect("the right hash");
}

#[tokio::test]
async fn an_address_is_read_within_its_bounds_and_never_followed() {
    let world = world();
    let tenant = TenantContext::assume(TenantId::generate());
    let (client, key) = signing_client(&world.applications, &tenant, 3, &[REGISTERED], false)
        .await
        .expect("client");
    let object = signed(&key, &claims(&world, client));
    let good = format!("{REGISTERED}good");
    world.addresses.serve(&good, &object);
    let cases = [
        (
            "large",
            AddressAnswer::Content(200, vec![b'a'; MAX_REQUEST_OBJECT_BYTES + 1]),
            "the request_uri answered more than 16 kibibytes",
        ),
        (
            "cut",
            AddressAnswer::Failure("http.response_too_large"),
            "the request_uri answered more than 16 kibibytes",
        ),
        (
            "slow",
            AddressAnswer::Failure("http.timed_out"),
            "the request_uri could not be fetched",
        ),
        (
            "silent",
            AddressAnswer::Failure("http.unreachable"),
            "the request_uri could not be fetched",
        ),
        (
            "moved",
            AddressAnswer::Redirect(good.clone()),
            "the request_uri did not answer a request object",
        ),
        (
            "missing",
            AddressAnswer::Content(404, object.as_bytes().to_vec()),
            "the request_uri did not answer a request object",
        ),
        (
            "binary",
            AddressAnswer::Content(200, vec![0xff, 0xfe, 0xfd]),
            "the content of the request_uri is not a request object",
        ),
    ];
    for (path, answer, description) in cases {
        let address = format!("{REGISTERED}{path}");
        world.addresses.answer(&address, answer);
        assert_eq!(
            check(
                &world.service,
                &tenant,
                &by_reference(client, &address, &[])
            )
            .await,
            Err(refused("invalid_request_uri", description)),
            "{path}"
        );
    }
    assert!(
        !world.addresses.fetched().contains(&good),
        "a redirect is never followed"
    );
    assert!(
        world
            .addresses
            .asked()
            .iter()
            .all(|request| request.time_limit == Some(std::time::Duration::from_secs(5))),
        "every fetch within 5 seconds"
    );
}

#[tokio::test]
async fn what_was_fetched_is_checked_as_a_request_object() {
    let world = world();
    let tenant = TenantContext::assume(TenantId::generate());
    let (client, _) = signing_client(&world.applications, &tenant, 3, &[REGISTERED], false)
        .await
        .expect("client");
    let (_, stranger_key) = signing_client(&world.applications, &tenant, 9, &[], false)
        .await
        .expect("client");
    let address = format!("{REGISTERED}one");
    world
        .addresses
        .serve(&address, &signed(&stranger_key, &claims(&world, client)));
    let answer = check(
        &world.service,
        &tenant,
        &by_reference(client, &address, &[]),
    )
    .await;
    assert_eq!(
        answer,
        Err(refused(
            "invalid_request_object",
            "the request object's signature does not verify"
        ))
    );
    // What is outside must say what the object says.
    let (client, key) = signing_client(&world.applications, &tenant, 4, &[REGISTERED], false)
        .await
        .expect("client");
    let address = format!("{REGISTERED}two");
    world
        .addresses
        .serve(&address, &signed(&key, &claims(&world, client)));
    let answer = check(
        &world.service,
        &tenant,
        &by_reference(client, &address, &[("scope", "openid email")]),
    )
    .await;
    assert_eq!(
        answer,
        Err(refused(
            "invalid_request",
            "scope outside the request object is not the one inside"
        ))
    );
}

#[tokio::test]
async fn without_an_outbound_client_an_address_is_not_supported() {
    let world = world();
    let tenant = TenantContext::assume(TenantId::generate());
    let (client, _) = signing_client(&world.applications, &tenant, 3, &[REGISTERED], false)
        .await
        .expect("client");
    let answer = check(
        &world.unable,
        &tenant,
        &by_reference(client, &format!("{REGISTERED}one"), &[]),
    )
    .await;
    assert_eq!(
        answer,
        Err(refused(
            "request_uri_not_supported",
            "references at a client's address are not supported"
        ))
    );
    assert!(world.addresses.fetched().is_empty());
}

#[tokio::test]
async fn only_an_address_new_to_a_client_is_checked_again() {
    let world = world();
    let tenant = TenantContext::assume(TenantId::generate());
    let private = "https://10.0.0.7/requests/";
    let (client, _) = signing_client(&world.lenient, &tenant, 3, &[private], false)
        .await
        .expect("client");
    // A change of something else, the address kept, is not refused for it.
    let mut settings = world
        .applications
        .client(&tenant, client)
        .await
        .expect("client")
        .snapshot()
        .settings
        .clone();
    settings.name = "Payroll site".to_owned();
    settings.request_uris.push(REGISTERED.to_owned());
    world
        .applications
        .change_client(&tenant, client, settings.clone(), Caller::system())
        .await
        .expect("only the new address is checked");
    settings
        .request_uris
        .push("https://192.168.1.1/requests/".to_owned());
    assert_eq!(
        world
            .applications
            .change_client(&tenant, client, settings, Caller::system())
            .await
            .expect_err("a new private address")
            .code(),
        "oauth.client_request_uri_forbidden"
    );
}
