//! Request objects, case by case: what is accepted from whom, each check,
//! the parameters read and those ignored, and where a refusal goes.

use super::*;
use crate::domain::application::{Application, ApplicationSettings};
use crate::domain::authorization::{AuthorizationRefusal, AuthorizationRequest, check_request};
use crate::domain::client::{AuthenticationMethod, ClientSettings, ClientType, GrantType};
use crate::domain::key::ClientKey;
use crate::domain::resource_server::{
    Audience, ResourceServer, ResourceServerSettings, ScopeDefinition,
};
use crate::domain::secret::ClientSecret;
use crate::testing::{DistinctRandom, FakeVerifier, fake_signature};
use hodor_kernel::PublicKey;
use hodor_kernel::random::testing::FakeDigest;
use serde_json::json;
use time::Duration;

const ISSUER: &str = "https://hodor.example.com/t/acme";
const REDIRECT: &str = "https://payroll.example.com/callback";
const OTHER_REDIRECT: &str = "https://payroll.example.com/other";
const AUDIENCE: &str = "https://api.payroll.example.com";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn now() -> Timestamp {
    Timestamp::UNIX_EPOCH + Duration::days(20_000)
}

fn objects() -> RequestObjectCheck<'static> {
    RequestObjectCheck {
        issuer: ISSUER,
        now: now(),
        verifier: &FakeVerifier,
    }
}

fn p256_key(kid: &str, fill: u8) -> (String, PublicKey) {
    let x = vec![fill; 32];
    let y = vec![fill.wrapping_add(1); 32];
    let jwk = json!({
        "kty": "EC", "crv": "P-256", "kid": kid,
        "x": URL_SAFE_NO_PAD.encode(&x), "y": URL_SAFE_NO_PAD.encode(&y),
    })
    .to_string();
    (jwk, PublicKey::P256 { x, y })
}

fn rsa_key(kid: &str, fill: u8) -> (String, PublicKey) {
    let mut modulus = vec![fill; 256];
    modulus[0] = 0xc1;
    let exponent = vec![1, 0, 1];
    let jwk = json!({
        "kty": "RSA", "kid": kid,
        "n": URL_SAFE_NO_PAD.encode(&modulus), "e": URL_SAFE_NO_PAD.encode(&exponent),
    })
    .to_string();
    (jwk, PublicKey::Rsa { modulus, exponent })
}

struct Keys {
    ec: PublicKey,
    rsa: PublicKey,
}

fn application() -> Application {
    Application::create(
        ApplicationSettings {
            name: "Payroll".to_owned(),
            first_party: true,
        },
        now(),
    )
    .expect("application")
}

/// A confidential client with `private_key_jwt`, a P-256 key `ec` and an
/// RSA key `rsa`, and the request object algorithm `chosen`.
fn client(
    application: &Application,
    chosen: Option<RequestObjectAlgorithm>,
    fill: u8,
) -> (Client, Keys) {
    let mut settings = ClientSettings::new(
        "Payroll web",
        ClientType::Confidential,
        vec![GrantType::AuthorizationCode],
        vec![REDIRECT.to_owned(), OTHER_REDIRECT.to_owned()],
    );
    settings.authentication_method = AuthenticationMethod::PrivateKeyJwt;
    settings.allowed_scopes = vec!["openid".to_owned(), "read".to_owned()];
    settings.request_object_algorithm = chosen;
    let (mut client, _) = Client::create(
        application.id(),
        ClientType::Confidential,
        settings,
        ClientSecret::DEFAULT_LIFETIME,
        now(),
        &DistinctRandom,
        &FakeDigest,
    )
    .expect("client");
    let (ec_jwk, ec) = p256_key("ec", fill);
    let (rsa_jwk, rsa) = rsa_key("rsa", fill);
    for jwk in [ec_jwk, rsa_jwk] {
        client
            .add_key(ClientKey::parse(&jwk, now()).expect("key"), now())
            .expect("added");
    }
    (client, Keys { ec, rsa })
}

fn server(application: &Application) -> ResourceServer {
    ResourceServer::create(
        application.id(),
        Audience::parse(AUDIENCE).expect("audience"),
        ResourceServerSettings {
            name: "Payroll interface".to_owned(),
            scopes: vec![ScopeDefinition {
                name: "read".to_owned(),
                description: String::new(),
            }],
        },
        now(),
    )
    .expect("server")
}

fn encode(value: &Value) -> String {
    URL_SAFE_NO_PAD.encode(value.to_string())
}

fn signed(algorithm: SignatureAlgorithm, kid: &str, key: &PublicKey, claims: &Value) -> String {
    let name = match algorithm {
        SignatureAlgorithm::Es256 => "ES256",
        SignatureAlgorithm::Rs256 => "RS256",
        SignatureAlgorithm::Ps256 => "PS256",
        SignatureAlgorithm::EdDsa => "EdDSA",
    };
    let input = format!(
        "{}.{}",
        encode(&json!({"alg": name, "kid": kid})),
        encode(claims)
    );
    let signature = fake_signature(algorithm, key, input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn unsigned(claims: &Value) -> String {
    format!("{}.{}.", encode(&json!({"alg": "none"})), encode(claims))
}

/// What a client puts in its object: the whole request, and `iss` and
/// `aud` as a signed object should.
fn claims(client: &Client) -> Value {
    let id = client.id().to_string();
    json!({
        "iss": id,
        "aud": ISSUER,
        "exp": (now() + Duration::minutes(5)).unix_timestamp(),
        "nbf": (now() - Duration::seconds(5)).unix_timestamp(),
        "iat": now().unix_timestamp(),
        "jti": "object-1",
        "client_id": id,
        "response_type": "code",
        "redirect_uri": REDIRECT,
        "scope": "openid read",
        "state": "inside",
        "nonce": "n-0S6_WzA2Mj",
        "max_age": 600,
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
    })
}

fn outside(client: &Client, object: &str, more: &[(&str, &str)]) -> AuthorizationParameters {
    let mut pairs = vec![
        ("client_id".to_owned(), client.id().to_string()),
        ("request".to_owned(), object.to_owned()),
    ];
    pairs.extend(
        more.iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
    );
    AuthorizationParameters::from_pairs(pairs)
}

struct Setting {
    application: Application,
    client: Client,
    keys: Keys,
    servers: Vec<ResourceServer>,
}

fn setting(chosen: Option<RequestObjectAlgorithm>) -> Setting {
    let application = application();
    let (client, keys) = client(&application, chosen, 3);
    let servers = vec![server(&application)];
    Setting {
        application,
        client,
        keys,
        servers,
    }
}

fn check(
    setting: &Setting,
    parameters: &AuthorizationParameters,
) -> Result<AuthorizationRequest, AuthorizationRefusal> {
    check_request(
        parameters,
        Some(&setting.client),
        Some(&setting.application),
        &setting.servers,
        objects(),
        false,
    )
}

/// The error at the redirect address, with where it went and its state.
fn redirected(
    result: Result<AuthorizationRequest, AuthorizationRefusal>,
) -> (&'static str, &'static str, String, Option<String>) {
    match result {
        Err(AuthorizationRefusal::Redirect(error)) => (
            error.error,
            error.description,
            error.redirect_uri,
            error.state,
        ),
        other => panic!("expected an error at the redirect address, got {other:?}"),
    }
}

fn refused_with(setting: &Setting, object: &str) -> (&'static str, &'static str) {
    let (error, description, uri, _) = redirected(check(
        setting,
        &outside(&setting.client, object, &[("redirect_uri", REDIRECT)]),
    ));
    assert_eq!(uri, REDIRECT);
    (error, description)
}

#[test]
fn a_signed_object_is_the_request_and_the_parameters_outside_are_ignored() {
    let setting = setting(None);
    let object = signed(
        SignatureAlgorithm::Es256,
        "ec",
        &setting.keys.ec,
        &claims(&setting.client),
    );
    let parameters = outside(
        &setting.client,
        &object,
        &[
            // Repeated as OpenID Connect asks, the scopes in another order.
            ("response_type", "code"),
            ("scope", "read openid"),
            // Ignored, as RFC 9101 says.
            ("redirect_uri", OTHER_REDIRECT),
            ("state", "outside"),
            ("prompt", "login"),
            ("nonce", "other"),
        ],
    );
    let request = check(&setting, &parameters).expect("accepted");
    assert_eq!(request.client_id, setting.client.id());
    assert_eq!(request.redirect_uri, REDIRECT);
    assert_eq!(request.scopes, ["openid", "read"]);
    assert_eq!(request.audiences, [AUDIENCE]);
    assert_eq!(request.state.as_deref(), Some("inside"));
    assert_eq!(request.nonce.as_deref(), Some("n-0S6_WzA2Mj"));
    assert_eq!(request.max_age, Some(600), "a number is read as its text");
    assert!(request.prompt.is_empty(), "prompt outside is ignored");
    assert_eq!(request.code_challenge.as_deref(), Some(CHALLENGE));
}

#[test]
fn without_client_id_outside_the_object_names_its_client() {
    let setting = setting(None);
    let object = signed(
        SignatureAlgorithm::Es256,
        "ec",
        &setting.keys.ec,
        &claims(&setting.client),
    );
    let parameters = AuthorizationParameters::from_pairs([("request".to_owned(), object)]);
    assert_eq!(parameters.client_id(), Some(setting.client.id()));
    check(&setting, &parameters).expect("accepted");

    // A client_id outside wins for finding the client; the object must
    // then name the same one.
    let other = setting.client.id();
    let named_twice = AuthorizationParameters::from_pairs([
        ("client_id".to_owned(), other.to_string()),
        ("client_id".to_owned(), other.to_string()),
        ("request".to_owned(), unsigned(&claims(&setting.client))),
    ]);
    assert_eq!(named_twice.client_id(), None, "given twice names nobody");
}

#[test]
fn what_is_accepted_depends_on_the_client_s_algorithm() {
    let es256 = |setting: &Setting| {
        signed(
            SignatureAlgorithm::Es256,
            "ec",
            &setting.keys.ec,
            &claims(&setting.client),
        )
    };
    let rs256 = |setting: &Setting| {
        signed(
            SignatureAlgorithm::Rs256,
            "rsa",
            &setting.keys.rsa,
            &claims(&setting.client),
        )
    };
    let ps256 = |setting: &Setting| {
        signed(
            SignatureAlgorithm::Ps256,
            "rsa",
            &setting.keys.rsa,
            &claims(&setting.client),
        )
    };
    let none = |setting: &Setting| unsigned(&claims(&setting.client));
    let accepted = |setting: &Setting, object: &str| {
        check(
            setting,
            &outside(&setting.client, object, &[("redirect_uri", REDIRECT)]),
        )
        .is_ok()
    };

    // None chosen: any of the three, never unsigned.
    let open = setting(None);
    assert!(accepted(&open, &es256(&open)));
    assert!(accepted(&open, &rs256(&open)));
    assert!(accepted(&open, &ps256(&open)));
    assert_eq!(
        refused_with(&open, &none(&open)),
        (
            "invalid_request_object",
            "this client's request objects must be signed"
        )
    );

    // One chosen: only that one.
    let strict = setting(Some(RequestObjectAlgorithm::Ps256));
    assert!(accepted(&strict, &ps256(&strict)));
    for object in [es256(&strict), rs256(&strict)] {
        assert_eq!(
            refused_with(&strict, &object),
            (
                "invalid_request_object",
                "the request object is not signed with the client's algorithm"
            )
        );
    }
    assert_eq!(
        refused_with(&strict, &none(&strict)).0,
        "invalid_request_object",
        "a client that names an algorithm is never sent an unsigned object"
    );

    // `none`: unsigned only, with nothing where the signature goes.
    let unsigned_only = setting(Some(RequestObjectAlgorithm::None));
    assert!(accepted(&unsigned_only, &none(&unsigned_only)));
    assert_eq!(
        refused_with(&unsigned_only, &es256(&unsigned_only)),
        (
            "invalid_request_object",
            "the request object is not signed with the client's algorithm"
        )
    );
    assert_eq!(
        refused_with(
            &unsigned_only,
            &format!("{}c2lnbmF0dXJl", none(&unsigned_only))
        ),
        (
            "invalid_request_object",
            "an unsigned request object carries a signature"
        )
    );
    // An unsigned object needs neither iss nor aud.
    let mut bare = claims(&unsigned_only.client);
    for name in ["iss", "aud", "exp", "nbf", "iat", "jti"] {
        bare.as_object_mut().expect("object").remove(name);
    }
    assert!(accepted(&unsigned_only, &unsigned(&bare)));
}

#[test]
fn an_object_signed_by_another_key_or_changed_after_signing_is_refused() {
    let setting = setting(None);
    let application = application();
    let (_, stranger) = client(&application, None, 9);
    let object = signed(
        SignatureAlgorithm::Es256,
        "ec",
        &stranger.ec,
        &claims(&setting.client),
    );
    assert_eq!(
        refused_with(&setting, &object),
        (
            "invalid_request_object",
            "the request object's signature does not verify"
        )
    );

    let genuine = signed(
        SignatureAlgorithm::Es256,
        "ec",
        &setting.keys.ec,
        &claims(&setting.client),
    );
    let parts: Vec<&str> = genuine.split('.').collect();
    let mut changed = claims(&setting.client);
    changed["scope"] = json!("openid");
    let tampered = format!("{}.{}.{}", parts[0], encode(&changed), parts[2]);
    assert_eq!(
        refused_with(&setting, &tampered).1,
        "the request object's signature does not verify"
    );

    let unknown_kid = signed(
        SignatureAlgorithm::Es256,
        "elsewhere",
        &setting.keys.ec,
        &claims(&setting.client),
    );
    assert_eq!(
        refused_with(&setting, &unknown_kid).1,
        "no key of the client fits the request object"
    );
    let shared_secret = format!(
        "{}.{}.c2lnbmF0dXJl",
        encode(&json!({"alg": "HS256"})),
        encode(&claims(&setting.client))
    );
    assert_eq!(
        refused_with(&setting, &shared_secret).1,
        "the request object names an algorithm that is not accepted"
    );
}

#[test]
fn an_object_that_breaks_a_rule_is_refused() {
    let setting = setting(None);
    let sign = |claims: &Value| signed(SignatureAlgorithm::Es256, "ec", &setting.keys.ec, claims);
    let with = |name: &str, value: Option<Value>| {
        let mut claims = claims(&setting.client);
        match value {
            Some(value) => claims[name] = value,
            None => {
                claims.as_object_mut().expect("object").remove(name);
            }
        }
        sign(&claims)
    };
    let late = (now() - Duration::seconds(61)).unix_timestamp();
    let early = (now() + Duration::seconds(61)).unix_timestamp();
    let cases: Vec<(&str, String, &str)> = vec![
        (
            "no iss in a signed object",
            with("iss", None),
            "a signed request object does not name its client as iss",
        ),
        (
            "another iss",
            with("iss", Some(json!("someone-else"))),
            "the request object is not from this client",
        ),
        (
            "another client_id",
            with("client_id", Some(json!("someone-else"))),
            "the request object names another client",
        ),
        (
            "another audience",
            with("aud", Some(json!("https://elsewhere.example.com"))),
            "the request object is not for this server",
        ),
        (
            "an audience that is not text",
            with("aud", Some(json!(7))),
            "the request object is not for this server",
        ),
        (
            "expired beyond the allowance",
            with("exp", Some(json!(late))),
            "the request object has expired",
        ),
        (
            "a time that is not a whole number",
            with("exp", Some(json!("soon"))),
            "the request object has a malformed time",
        ),
        (
            "valid only later",
            with("nbf", Some(json!(early))),
            "the request object is not valid yet",
        ),
        (
            "another request inside",
            with("request_uri", Some(json!("https://payroll.example.com/r"))),
            "a request object cannot hold another request",
        ),
        (
            "a list of numbers",
            with("resource", Some(json!([1, 2]))),
            "a list in the request object holds something other than text",
        ),
        (
            "two parts",
            "eyJhbGciOiJub25lIn0.e30".to_owned(),
            "the request object is not three parts",
        ),
        (
            "a header that is not JSON",
            format!("bm90IGpzb24.{}.", encode(&claims(&setting.client))),
            "the request object's header is malformed",
        ),
        (
            "too large",
            with("padding", Some(json!("x".repeat(MAX_REQUEST_OBJECT_BYTES)))),
            "the request object is larger than 16 kibibytes",
        ),
    ];
    for (case, object, reason) in cases {
        assert_eq!(
            refused_with(&setting, &object),
            ("invalid_request_object", reason),
            "{case}"
        );
    }

    // Within the 60 seconds allowed for clocks, and an audience among
    // several.
    let near = (now() - Duration::seconds(59)).unix_timestamp();
    let soon = (now() + Duration::seconds(59)).unix_timestamp();
    for object in [
        with("exp", Some(json!(near))),
        with("nbf", Some(json!(soon))),
        with(
            "aud",
            Some(json!(["https://elsewhere.example.com", ISSUER])),
        ),
        with("exp", None),
    ] {
        check(
            &setting,
            &outside(&setting.client, &object, &[("redirect_uri", REDIRECT)]),
        )
        .expect("accepted");
    }
}

/// A case: what it is, the parameters outside, and the reason.
type Contradiction<'a> = (&'a str, &'a [(&'a str, &'a str)], &'a str);

#[test]
fn parameters_outside_that_contradict_the_object_are_refused() {
    let setting = setting(None);
    let object = signed(
        SignatureAlgorithm::Es256,
        "ec",
        &setting.keys.ec,
        &claims(&setting.client),
    );
    let cases: [Contradiction<'_>; 4] = [
        (
            "another response type",
            &[("response_type", "token")],
            "response_type outside the request object is not the one inside",
        ),
        (
            "other scopes",
            &[("scope", "openid")],
            "scope outside the request object is not the one inside",
        ),
        (
            "a reference besides",
            &[("request_uri", "https://payroll.example.com/r")],
            "request and request_uri cannot be given together",
        ),
        (
            "the object twice",
            &[("request", "eyJ")],
            "a parameter is given more than once",
        ),
    ];
    for (case, more, reason) in cases {
        let mut given = vec![("redirect_uri", REDIRECT)];
        given.extend_from_slice(more);
        let (error, description, _, _) =
            redirected(check(&setting, &outside(&setting.client, &object, &given)));
        assert_eq!((error, description), ("invalid_request", reason), "{case}");
    }
}

#[test]
fn every_check_of_the_endpoint_applies_to_what_the_object_holds() {
    let setting = setting(None);
    let sign = |claims: &Value| signed(SignatureAlgorithm::Es256, "ec", &setting.keys.ec, claims);
    let outside_with =
        |object: &str| outside(&setting.client, object, &[("redirect_uri", REDIRECT)]);

    // A redirect address inside that is not the client's: Hodor's own
    // page, whatever the one outside says.
    let mut claims_of = claims(&setting.client);
    claims_of["redirect_uri"] = json!("https://evil.example.com/callback");
    assert_eq!(
        check(&setting, &outside_with(&sign(&claims_of))),
        Err(AuthorizationRefusal::NotRedirectable(
            "oauth.authorization_redirect_uri_unregistered"
        ))
    );

    // A scope the client may not ask for.
    let mut claims_of = claims(&setting.client);
    claims_of["scope"] = json!("openid write");
    let (error, _, _, _) = redirected(check(&setting, &outside_with(&sign(&claims_of))));
    assert_eq!(error, "invalid_scope");

    // No code challenge, which this client must send.
    let mut claims_of = claims(&setting.client);
    claims_of
        .as_object_mut()
        .expect("object")
        .remove("code_challenge");
    let (error, _, _, _) = redirected(check(&setting, &outside_with(&sign(&claims_of))));
    assert_eq!(error, "invalid_request");

    // A list for a parameter that may be given once.
    let mut claims_of = claims(&setting.client);
    claims_of["prompt"] = json!(["login", "consent"]);
    let (error, description, _, _) = redirected(check(&setting, &outside_with(&sign(&claims_of))));
    assert_eq!(
        (error, description),
        ("invalid_request", "a parameter is given more than once")
    );

    // A list of resources is the parameter given once for each.
    let mut claims_of = claims(&setting.client);
    claims_of["resource"] = json!([AUDIENCE]);
    let request = check(&setting, &outside_with(&sign(&claims_of))).expect("accepted");
    assert_eq!(request.audiences, [AUDIENCE]);

    // No response type inside: required, though one is outside.
    let mut claims_of = claims(&setting.client);
    claims_of
        .as_object_mut()
        .expect("object")
        .remove("response_type");
    let (error, _, _, _) = redirected(check(
        &setting,
        &outside(
            &setting.client,
            &sign(&claims_of),
            &[("redirect_uri", REDIRECT), ("response_type", "code")],
        ),
    ));
    assert_eq!(error, "invalid_request");
}

#[test]
fn the_parameters_of_an_object_are_read_as_text() {
    let setting = setting(None);
    let claims = json!({
        "iss": "ignored", "aud": "ignored", "exp": 1, "nbf": 1, "iat": 1, "jti": "ignored",
        "client_id": "replaced by the client's own",
        "state": "text",
        "max_age": 60,
        "flag": true,
        "claims": {"userinfo": {"name": null}},
        "resource": ["https://one.example.com", "https://two.example.com"],
        "nothing": null,
        "empty": "",
    });
    let pairs =
        parameters_of(claims.as_object().expect("object"), &setting.client).expect("readable");
    let mut sorted = pairs.clone();
    sorted.sort();
    let id = setting.client.id().to_string();
    let expected = vec![
        ("claims", r#"{"userinfo":{"name":null}}"#),
        ("client_id", id.as_str()),
        ("empty", ""),
        ("flag", "true"),
        ("max_age", "60"),
        ("resource", "https://one.example.com"),
        ("resource", "https://two.example.com"),
        ("state", "text"),
    ];
    let mut expected: Vec<(String, String)> = expected
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect();
    expected.sort();
    assert_eq!(sorted, expected);
}

#[test]
fn a_refused_object_is_answered_only_at_one_of_the_client_s_addresses() {
    let setting = setting(None);
    let mut inside = claims(&setting.client);
    inside["redirect_uri"] = json!(OTHER_REDIRECT);
    let bad = unsigned(&inside);

    // The address outside, when it is the client's, with its state.
    let (error, _, uri, state) = redirected(check(
        &setting,
        &outside(
            &setting.client,
            &bad,
            &[("redirect_uri", REDIRECT), ("state", "outside")],
        ),
    ));
    assert_eq!(error, "invalid_request_object");
    assert_eq!(
        (uri.as_str(), state.as_deref()),
        (REDIRECT, Some("outside"))
    );

    // Otherwise the object's own, read without trusting it, with its state.
    for more in [
        &[][..],
        &[("redirect_uri", "https://evil.example.com/cb")][..],
    ] {
        let (_, _, uri, state) = redirected(check(&setting, &outside(&setting.client, &bad, more)));
        assert_eq!(
            (uri.as_str(), state.as_deref()),
            (OTHER_REDIRECT, Some("inside"))
        );
    }

    // Neither is the client's: Hodor's own page.
    inside["redirect_uri"] = json!("https://evil.example.com/cb");
    assert_eq!(
        check(
            &setting,
            &outside(
                &setting.client,
                &unsigned(&inside),
                &[("redirect_uri", "https://evil.example.com/cb")]
            )
        ),
        Err(AuthorizationRefusal::NotRedirectable(
            "oauth.authorization_request_object_invalid"
        ))
    );
    assert_eq!(
        check(&setting, &outside(&setting.client, "not an object", &[])),
        Err(AuthorizationRefusal::NotRedirectable(
            "oauth.authorization_request_object_invalid"
        ))
    );
}

#[test]
fn a_refused_object_is_answered_in_the_mode_named_beside_its_address() {
    use crate::domain::response::ResponseMode;
    let setting = setting(None);
    let mut inside = claims(&setting.client);
    inside["redirect_uri"] = json!(OTHER_REDIRECT);
    inside["response_mode"] = json!("form_post");
    inside["iss"] = json!("someone else");
    let bad = unsigned(&inside);
    let mode_of = |parameters: &AuthorizationParameters| match check(&setting, parameters) {
        Err(AuthorizationRefusal::Redirect(error)) => (error.redirect_uri, error.mode),
        other => panic!("expected an error at the redirect address, got {other:?}"),
    };

    // Outside: the mode outside, whatever the object says.
    assert_eq!(
        mode_of(&outside(
            &setting.client,
            &bad,
            &[("redirect_uri", REDIRECT), ("response_type", "code")],
        )),
        (REDIRECT.to_owned(), ResponseMode::Query)
    );
    assert_eq!(
        mode_of(&outside(
            &setting.client,
            &bad,
            &[
                ("redirect_uri", REDIRECT),
                ("response_type", "code"),
                ("response_mode", "form_post"),
            ],
        )),
        (REDIRECT.to_owned(), ResponseMode::FormPost)
    );
    // Inside: the object's own mode, read without trusting it.
    assert_eq!(
        mode_of(&outside(&setting.client, &bad, &[])),
        (OTHER_REDIRECT.to_owned(), ResponseMode::FormPost)
    );
}

#[test]
fn the_mode_inside_an_object_is_the_request_s() {
    use crate::domain::response::ResponseMode;
    let setting = setting(Some(RequestObjectAlgorithm::None));
    let mut inside = claims(&setting.client);
    inside["response_mode"] = json!("form_post");
    // Outside, only `client_id` is read: the mode inside wins.
    let request = check(
        &setting,
        &outside(
            &setting.client,
            &unsigned(&inside),
            &[("response_mode", "query")],
        ),
    )
    .expect("accepted");
    assert_eq!(request.response_mode, ResponseMode::FormPost);
}

#[test]
fn an_object_for_an_unknown_client_is_never_checked() {
    let setting = setting(None);
    let object = signed(
        SignatureAlgorithm::Es256,
        "ec",
        &setting.keys.ec,
        &claims(&setting.client),
    );
    // The client is not one of this tenant: nothing to check it with.
    assert_eq!(
        check_request(
            &outside(&setting.client, &object, &[("redirect_uri", REDIRECT)]),
            None,
            None,
            &[],
            objects(),
            false,
        ),
        Err(AuthorizationRefusal::NotRedirectable(
            "oauth.authorization_client_unknown"
        ))
    );
    // The client outside is another one than the object's.
    let application = application();
    let (other, _) = client(&application, None, 5);
    let parameters = outside(&other, &object, &[("redirect_uri", REDIRECT)]);
    assert_eq!(
        check_request(
            &parameters,
            Some(&other),
            Some(&application),
            &[],
            objects(),
            false,
        ),
        Err(AuthorizationRefusal::Redirect(
            crate::domain::authorization::AuthorizationError {
                redirect_uri: REDIRECT.to_owned(),
                error: "invalid_request_object",
                description: "the request object's signature does not verify",
                state: None,
                mode: crate::domain::response::ResponseMode::Query,
            }
        ))
    );
}
