//! The parameters of a request completed by Issue-125, through the use
//! cases of the authorization endpoint on the in-memory stores: an
//! `id_token_hint` checked against the tenant's keys and compared with the
//! person as the client knows them, `prompt=create`, `display`, and the
//! client's defaults for a sign-in.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, PublicKey, SignatureAlgorithm, SignatureVerifier, TenantContext, TenantId, Timestamp,
    UserId,
};
use hodor_keys::api::{KeyAlgorithm, KeyService, RotationPolicy};
use hodor_keys::testing::{FakeKeyProvider, InMemoryKeys};
use hodor_oauth::api::{
    ApplicationPorts, ApplicationService, ApplicationSettings, AuthorizationCodePorts,
    AuthorizationCodeService, AuthorizationParameters, AuthorizationRefusal, AuthorizationRequest,
    Client, ClientSettings, ClientType, CreateClient, GrantType, RequestObjectAlgorithm,
    SubjectType, s256_challenge,
};
use hodor_oauth::testing::{
    DistinctRandom, InMemoryAuthorizationCodes, InMemoryAuthorizationRequests, InMemoryGrants,
    InMemoryPairwiseSecrets, InMemoryStores, MembershipsOf, pairwise_subjects,
};
use serde_json::json;
use std::sync::Arc;
use time::Duration;

const ISSUER: &str = "https://hodor.example.com/t/acme";
const OTHER_ISSUER: &str = "https://hodor.example.com/t/globex";
const REDIRECT: &str = "https://payroll.example.com/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

/// Accepts the stand-in signatures the tests below write: `fake|` followed
/// by what is signed. Which key may sign is the tenant's published keys'
/// to say.
#[derive(Debug, Clone, Copy)]
struct StandIn;

impl SignatureVerifier for StandIn {
    fn verify(
        &self,
        _algorithm: SignatureAlgorithm,
        _key: &PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        signature.starts_with(b"fake|") && signature.ends_with(message)
    }
}

struct World {
    keys: KeyService,
    applications: ApplicationService,
    stores: InMemoryStores,
    units: InMemoryUnitOfWorkFactory,
    secrets: InMemoryPairwiseSecrets,
    service: AuthorizationCodeService,
}

fn world() -> World {
    let units = InMemoryUnitOfWorkFactory::default();
    let stores = InMemoryStores::default();
    let grants = InMemoryGrants::new(&stores.clients);
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + Duration::days(20_000),
    ));
    let keys = KeyService::new(
        Arc::new(units.clone()),
        Arc::new(InMemoryKeys::default()),
        Arc::new(FakeKeyProvider),
        clock.clone(),
    );
    let secrets = InMemoryPairwiseSecrets::default();
    let service = AuthorizationCodeService::new(AuthorizationCodePorts {
        units_of_work: Arc::new(units.clone()),
        applications: Arc::new(stores.applications.clone()),
        clients: Arc::new(stores.clients.clone()),
        resource_servers: Arc::new(stores.resource_servers.clone()),
        requests: Arc::new(InMemoryAuthorizationRequests::new(&stores.clients)),
        grants: Arc::new(grants.clone()),
        codes: Arc::new(InMemoryAuthorizationCodes::new(&grants)),
        memberships: Arc::new(MembershipsOf::default()),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
        verifier: Arc::new(StandIn),
    });
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(units.clone()),
        applications: Arc::new(stores.applications.clone()),
        clients: Arc::new(stores.clients.clone()),
        resource_servers: Arc::new(stores.resource_servers.clone()),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock,
    });
    let service = service
        .with_id_token_hints(keys.clone())
        .with_pairwise_subjects(pairwise_subjects(
            Arc::new(units.clone()),
            Arc::new(secrets.clone()),
        ));
    World {
        keys,
        applications,
        stores,
        units,
        secrets,
        service,
    }
}

/// A tenant with a signing key, and the identifier of that key.
async fn tenant(world: &World) -> (TenantContext, String) {
    let context = TenantContext::assume(TenantId::generate());
    world
        .keys
        .rotate_now(
            &context,
            KeyAlgorithm::Es256,
            &RotationPolicy::DEFAULT,
            Caller::system(),
        )
        .await
        .expect("a signing key");
    let kid = world
        .keys
        .published_keys(&context)
        .await
        .expect("keys")
        .first()
        .expect("one key")
        .id()
        .to_string();
    (context, kid)
}

/// A first-party application's public client, changed by `change`.
async fn client(
    world: &World,
    tenant: &TenantContext,
    change: impl FnOnce(&mut ClientSettings),
) -> Client {
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
    settings.allowed_scopes = vec!["openid".to_owned()];
    change(&mut settings);
    world
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
        .expect("client")
        .0
}

fn parameters(client: &Client, extra: &[(&str, &str)]) -> AuthorizationParameters {
    let client_id = client.id().to_string();
    let challenge = s256_challenge(VERIFIER, &FakeDigest);
    let mut pairs = vec![
        ("response_type", "code"),
        ("client_id", client_id.as_str()),
        ("redirect_uri", REDIRECT),
        ("scope", "openid"),
        ("state", "xyz"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ];
    pairs.extend_from_slice(extra);
    AuthorizationParameters::from_pairs(
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
    )
}

/// An ID token as Hodor writes one, signed with the stand-in signature.
fn id_token(kid: &str, issuer: &str, audience: &str, subject: &str) -> String {
    let header = json!({ "alg": "ES256", "typ": "JWT", "kid": kid });
    let claims = json!({
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "sid": "a-session",
        // Long expired: a hint's expiry is not checked.
        "exp": 1,
        "iat": 0,
    });
    let signed = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let mut signature = b"fake|".to_vec();
    signature.extend_from_slice(signed.as_bytes());
    format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature))
}

/// Checks a request as the endpoint does: the checks of the client and
/// the parameters, then the hint.
async fn check(
    world: &World,
    tenant: &TenantContext,
    parameters: &AuthorizationParameters,
) -> Result<AuthorizationRequest, (AuthorizationRefusal, &'static str)> {
    let request = world
        .service
        .check(
            tenant,
            ISSUER,
            parameters,
            &hodor_oauth::api::PushedRequestPolicy::default(),
        )
        .await
        .expect("storage")
        .expect("the request passes its own checks");
    world
        .service
        .check_hint(tenant, ISSUER, request)
        .await
        .expect("storage")
}

fn invalid_request(result: Result<AuthorizationRequest, (AuthorizationRefusal, &'static str)>) {
    match result {
        Err((AuthorizationRefusal::Redirect(error), _)) => {
            assert_eq!(error.error, "invalid_request");
            assert_eq!(error.redirect_uri, REDIRECT);
            assert_eq!(error.state.as_deref(), Some("xyz"));
        }
        other => panic!("expected invalid_request at the redirect address, got {other:?}"),
    }
}

#[tokio::test]
async fn a_hint_of_the_tenant_names_the_person_the_session_must_be() {
    let world = world();
    let (acme, kid) = tenant(&world).await;
    let payroll = client(&world, &acme, |_| {}).await;
    let ana = UserId::generate();
    let bruno = UserId::generate();
    let hint = id_token(&kid, ISSUER, &payroll.id().to_string(), &ana.to_string());

    let request = check(
        &world,
        &acme,
        &parameters(&payroll, &[("id_token_hint", &hint)]),
    )
    .await
    .expect("the client's own hint, expired long ago");
    assert_eq!(request.id_token_hint, Some(ana.to_string()));
    assert!(
        world
            .service
            .hint_names(&acme, &request, ana)
            .await
            .expect("named")
    );
    assert!(
        !world
            .service
            .hint_names(&acme, &request, bruno)
            .await
            .expect("named")
    );

    // Without a hint, anyone answers.
    let plain = check(&world, &acme, &parameters(&payroll, &[]))
        .await
        .expect("plain");
    assert_eq!(plain.id_token_hint, None);
    assert!(
        world
            .service
            .hint_names(&acme, &plain, bruno)
            .await
            .expect("named")
    );
}

#[tokio::test]
async fn a_hint_signed_by_another_tenant_or_for_another_client_is_refused() {
    let world = world();
    let (acme, kid) = tenant(&world).await;
    let (globex, globex_kid) = tenant(&world).await;
    let payroll = client(&world, &acme, |_| {}).await;
    let travel = client(&world, &acme, |_| {}).await;
    let elsewhere = client(&world, &globex, |_| {}).await;
    let ana = UserId::generate().to_string();
    let audience = payroll.id().to_string();

    // Signed by Globex's key, for Globex's issuer or even for Acme's.
    for hint in [
        id_token(&globex_kid, OTHER_ISSUER, &audience, &ana),
        id_token(&globex_kid, ISSUER, &audience, &ana),
        // Acme's key, but Globex's issuer.
        id_token(&kid, OTHER_ISSUER, &audience, &ana),
        // Issued to another client of Acme, or to a client of Globex.
        id_token(&kid, ISSUER, &travel.id().to_string(), &ana),
        id_token(&kid, ISSUER, &elsewhere.id().to_string(), &ana),
        // Not an ID token at all, or one whose signature does not verify.
        "not.a.token".to_owned(),
        format!("{}x", id_token(&kid, ISSUER, &audience, &ana)),
    ] {
        invalid_request(
            check(
                &world,
                &acme,
                &parameters(&payroll, &[("id_token_hint", &hint)]),
            )
            .await,
        );
    }
    // Where it belongs, Globex's hint is good for Globex's client.
    let hint = id_token(&globex_kid, OTHER_ISSUER, &elsewhere.id().to_string(), &ana);
    let request = world
        .service
        .check(
            &globex,
            OTHER_ISSUER,
            &parameters(&elsewhere, &[("id_token_hint", &hint)]),
            &hodor_oauth::api::PushedRequestPolicy::default(),
        )
        .await
        .expect("storage")
        .expect("checked");
    let hinted = world
        .service
        .check_hint(&globex, OTHER_ISSUER, request)
        .await
        .expect("storage")
        .expect("Globex's own");
    assert_eq!(hinted.id_token_hint, Some(ana));
}

#[tokio::test]
async fn the_hint_of_a_request_object_is_the_one_inside_it() {
    let world = world();
    let (acme, kid) = tenant(&world).await;
    let payroll = client(&world, &acme, |settings| {
        settings.request_object_algorithm = Some(RequestObjectAlgorithm::None);
    })
    .await;
    let client_id = payroll.id().to_string();
    let ana = UserId::generate().to_string();
    let hint = id_token(&kid, ISSUER, &client_id, &ana);
    let challenge = s256_challenge(VERIFIER, &FakeDigest);
    // An unsigned object, which this client chose to send.
    let object = |extra: serde_json::Value| {
        let mut claims = json!({
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT,
            "scope": "openid",
            "state": "xyz",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        });
        claims
            .as_object_mut()
            .expect("an object")
            .extend(extra.as_object().expect("an object").clone());
        format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(json!({ "alg": "none" }).to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        )
    };
    let sent = |object: &str, outside: &[(&str, &str)]| {
        let mut pairs = vec![("client_id", client_id.as_str()), ("request", object)];
        pairs.extend_from_slice(outside);
        AuthorizationParameters::from_pairs(
            pairs
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
        )
    };

    // Inside the object, the hint is read and checked.
    let inside = check(
        &world,
        &acme,
        &sent(&object(json!({ "id_token_hint": hint })), &[]),
    )
    .await
    .expect("the hint inside");
    assert_eq!(inside.id_token_hint, Some(ana.clone()));
    let broken = format!("{hint}x");
    invalid_request(
        check(
            &world,
            &acme,
            &sent(&object(json!({ "id_token_hint": broken })), &[]),
        )
        .await,
    );

    // Outside it, ignored as every parameter but `client_id` is, even one
    // that would be refused.
    let outside = check(
        &world,
        &acme,
        &sent(&object(json!({})), &[("id_token_hint", "not.a.token")]),
    )
    .await
    .expect("the hint outside is ignored");
    assert_eq!(outside.id_token_hint, None);
}

#[tokio::test]
async fn a_service_that_cannot_check_a_hint_refuses_it() {
    let world = world();
    let (acme, kid) = tenant(&world).await;
    let payroll = client(&world, &acme, |_| {}).await;
    let grants = InMemoryGrants::new(&world.stores.clients);
    let bare = AuthorizationCodeService::new(AuthorizationCodePorts {
        units_of_work: Arc::new(world.units.clone()),
        applications: Arc::new(world.stores.applications.clone()),
        clients: Arc::new(world.stores.clients.clone()),
        resource_servers: Arc::new(world.stores.resource_servers.clone()),
        requests: Arc::new(InMemoryAuthorizationRequests::new(&world.stores.clients)),
        grants: Arc::new(grants.clone()),
        codes: Arc::new(InMemoryAuthorizationCodes::new(&grants)),
        memberships: Arc::new(MembershipsOf::default()),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH)),
        verifier: Arc::new(StandIn),
    });
    let hint = id_token(
        &kid,
        ISSUER,
        &payroll.id().to_string(),
        &UserId::generate().to_string(),
    );
    let with_hint = parameters(&payroll, &[("id_token_hint", &hint)]);
    let request = bare
        .check(
            &acme,
            ISSUER,
            &with_hint,
            &hodor_oauth::api::PushedRequestPolicy::default(),
        )
        .await
        .expect("storage")
        .expect("checked");
    invalid_request(
        bare.check_hint(&acme, ISSUER, request)
            .await
            .expect("storage"),
    );
}

#[tokio::test]
async fn a_pairwise_client_s_hint_names_the_person_by_its_pairwise_identifier() {
    let world = world();
    let (acme, kid) = tenant(&world).await;
    let pairwise = client(&world, &acme, |settings| {
        settings.subject_type = SubjectType::Pairwise;
    })
    .await;
    let ana = UserId::generate();
    let names = pairwise_subjects(
        Arc::new(world.units.clone()),
        Arc::new(world.secrets.clone()),
    );
    let subject = names.subject(&acme, &pairwise, ana).await.expect("subject");
    assert_ne!(subject, ana.to_string());
    let hint = id_token(&kid, ISSUER, &pairwise.id().to_string(), &subject);
    let request = check(
        &world,
        &acme,
        &parameters(&pairwise, &[("id_token_hint", &hint)]),
    )
    .await
    .expect("checked");
    assert!(
        world
            .service
            .hint_names(&acme, &request, ana)
            .await
            .expect("named")
    );
    assert!(
        !world
            .service
            .hint_names(&acme, &request, UserId::generate())
            .await
            .expect("named")
    );
    // A hint whose `sub` is the user identifier names nobody to a pairwise
    // client.
    let plain = id_token(&kid, ISSUER, &pairwise.id().to_string(), &ana.to_string());
    let request = check(
        &world,
        &acme,
        &parameters(&pairwise, &[("id_token_hint", &plain)]),
    )
    .await
    .expect("checked");
    assert!(
        !world
            .service
            .hint_names(&acme, &request, ana)
            .await
            .expect("named")
    );
}

#[tokio::test]
async fn display_create_and_the_client_s_defaults_reach_the_request() {
    let world = world();
    let (acme, _) = tenant(&world).await;
    let payroll = client(&world, &acme, |settings| {
        settings.default_max_age = Some(300);
        settings.default_acr_values = vec!["urn:hodor:acr:mfa".to_owned()];
        settings.require_auth_time = true;
    })
    .await;

    let request = check(
        &world,
        &acme,
        &parameters(&payroll, &[("display", "popup"), ("prompt", "create")]),
    )
    .await
    .expect("checked");
    assert!(request.asks_to_register());
    assert!(request.registration_refusal(true).is_none());
    assert_eq!(
        request.registration_refusal(false).map(|error| error.error),
        Some("invalid_request")
    );
    assert_eq!(request.max_age, Some(300));
    assert_eq!(request.acr_values.as_deref(), Some("urn:hodor:acr:mfa"));

    let refused = world
        .service
        .check(
            &acme,
            ISSUER,
            &parameters(&payroll, &[("display", "wap")]),
            &hodor_oauth::api::PushedRequestPolicy::default(),
        )
        .await
        .expect("storage");
    assert!(matches!(
        refused,
        Err(AuthorizationRefusal::Redirect(ref error)) if error.error == "invalid_request"
    ));
}
