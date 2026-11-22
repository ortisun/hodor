use super::*;
use crate::domain::application::ApplicationId;
use crate::domain::authorization::GrantId;
use crate::domain::client::{ClientSettings, ClientType, GrantType};
use crate::domain::key::ClientKey;
use crate::domain::secret::ClientSecret;
use crate::testing::{DistinctRandom, FakeVerifier, fake_signature};
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::{PublicKey, UserId};
use hodor_session::api::SessionId;

const ISSUER: &str = "https://hodor.example.com/t/acme";
const ENDPOINT: &str = "https://hodor.example.com/t/acme/oauth2/token";

fn now() -> Timestamp {
    Timestamp::UNIX_EPOCH + Duration::days(20_000)
}

fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect()
}

fn code_grant(extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut list = vec![
        ("grant_type", "authorization_code"),
        ("code", "the-code"),
        ("redirect_uri", "https://app.example.com/callback"),
    ];
    list.extend_from_slice(extra);
    pairs(&list)
}

fn basic(client_id: &str) -> BasicCredentials {
    BasicCredentials {
        client_id: client_id.to_owned(),
        secret: Secret::from("hodor_cs_secret".to_owned()),
    }
}

fn refused(result: Result<TokenRequest, TokenError>) -> TokenError {
    result.expect_err("the request is refused")
}

#[test]
fn each_way_of_proving_who_the_client_is_is_read() {
    let request = TokenRequest::parse(Some(basic("one")), code_grant(&[])).expect("basic");
    assert_eq!(
        request.client.method(),
        AuthenticationMethod::ClientSecretBasic
    );
    let request = TokenRequest::parse(
        None,
        code_grant(&[("client_id", "one"), ("client_secret", "s")]),
    )
    .expect("post");
    assert_eq!(
        request.client.method(),
        AuthenticationMethod::ClientSecretPost
    );
    let request = TokenRequest::parse(
        None,
        code_grant(&[
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", "a.b.c"),
        ]),
    )
    .expect("assertion");
    assert_eq!(request.client.method(), AuthenticationMethod::PrivateKeyJwt);
    let request = TokenRequest::parse(None, code_grant(&[("client_id", "one")])).expect("public");
    assert_eq!(request.client.method(), AuthenticationMethod::None);
    assert_eq!(
        request.grant,
        GrantRequest::AuthorizationCode {
            code: "the-code".to_owned(),
            redirect_uri: "https://app.example.com/callback".to_owned(),
            verifier: None,
        }
    );
}

/// The `Basic` credentials and the form of a request, and the error it gets.
type Case = (
    Option<BasicCredentials>,
    Vec<(String, String)>,
    &'static str,
);

#[test]
fn a_malformed_request_is_refused_for_its_own_reason() {
    let cases: Vec<Case> = vec![
        (
            None,
            pairs(&[
                ("grant_type", "authorization_code"),
                ("grant_type", "authorization_code"),
                ("client_id", "one"),
            ]),
            "invalid_request",
        ),
        (None, pairs(&[("client_id", "one")]), "invalid_request"),
        (
            None,
            pairs(&[("grant_type", "password"), ("client_id", "one")]),
            "unsupported_grant_type",
        ),
        (
            None,
            pairs(&[("grant_type", "refresh_token"), ("client_id", "one")]),
            "unsupported_grant_type",
        ),
        (
            None,
            pairs(&[("grant_type", "client_credentials"), ("client_id", "one")]),
            "unsupported_grant_type",
        ),
        (
            Some(basic("one")),
            code_grant(&[("client_secret", "s")]),
            "invalid_request",
        ),
        (
            Some(basic("one")),
            code_grant(&[
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", "a.b.c"),
            ]),
            "invalid_request",
        ),
        (
            None,
            code_grant(&[
                ("client_id", "one"),
                ("client_secret", "s"),
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", "a.b.c"),
            ]),
            "invalid_request",
        ),
        (
            Some(basic("one")),
            code_grant(&[("client_id", "two")]),
            "invalid_request",
        ),
        (
            None,
            code_grant(&[("client_secret", "s")]),
            "invalid_client",
        ),
        (
            None,
            code_grant(&[("client_assertion", "a.b.c")]),
            "invalid_request",
        ),
        (
            None,
            code_grant(&[
                ("client_assertion_type", "urn:other"),
                ("client_assertion", "a.b.c"),
            ]),
            "invalid_request",
        ),
        (
            None,
            code_grant(&[("client_assertion_type", ASSERTION_TYPE)]),
            "invalid_request",
        ),
        (None, code_grant(&[]), "invalid_client"),
        (
            None,
            pairs(&[
                ("grant_type", "authorization_code"),
                ("client_id", "one"),
                ("redirect_uri", "https://app.example.com/callback"),
            ]),
            "invalid_request",
        ),
        (
            None,
            pairs(&[
                ("grant_type", "authorization_code"),
                ("client_id", "one"),
                ("code", "the-code"),
            ]),
            "invalid_request",
        ),
    ];
    for (credentials, form, expected) in cases {
        let described = format!("{form:?}");
        let error = refused(TokenRequest::parse(credentials, form));
        assert_eq!(error.error, expected, "{described}: {}", error.reason);
    }
}

fn p256_key(kid: &str, fill: u8) -> (String, PublicKey) {
    let x = vec![fill; 32];
    let y = vec![fill.wrapping_add(1); 32];
    let jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "kid": kid,
        "x": URL_SAFE_NO_PAD.encode(&x),
        "y": URL_SAFE_NO_PAD.encode(&y),
    })
    .to_string();
    (jwk, PublicKey::P256 { x, y })
}

fn signing_client(keys: &[&str]) -> Client {
    let mut settings = ClientSettings::new(
        "Payroll service",
        ClientType::Confidential,
        vec![GrantType::AuthorizationCode],
        vec!["https://app.example.com/callback".to_owned()],
    );
    settings.authentication_method = AuthenticationMethod::PrivateKeyJwt;
    let (mut client, _) = Client::create(
        ApplicationId::generate(),
        ClientType::Confidential,
        settings,
        ClientSecret::DEFAULT_LIFETIME,
        now(),
        &DistinctRandom,
        &FakeDigest,
    )
    .expect("client");
    for jwk in keys {
        client
            .add_key(ClientKey::parse(jwk, now()).expect("key"), now())
            .expect("added");
    }
    client
}

fn encode(value: &Value) -> String {
    URL_SAFE_NO_PAD.encode(value.to_string())
}

fn sign(header: &Value, claims: &Value, key: &PublicKey) -> String {
    let input = format!("{}.{}", encode(header), encode(claims));
    let signature = fake_signature(SignatureAlgorithm::Es256, key, input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn claims_for(client: &Client) -> Value {
    let id = client.id().to_string();
    json!({
        "iss": id,
        "sub": id,
        "aud": ENDPOINT,
        "exp": (now() + Duration::minutes(2)).unix_timestamp(),
        "iat": now().unix_timestamp(),
        "jti": "assertion-1",
    })
}

fn check(assertion: &str, client: &Client) -> Result<CheckedAssertion, &'static str> {
    check_assertion(
        assertion,
        client,
        AssertionAudience {
            issuer: ISSUER,
            token_endpoint: ENDPOINT,
        },
        now(),
        &FakeVerifier,
    )
}

#[test]
fn a_well_made_assertion_is_accepted_for_the_issuer_or_the_endpoint() {
    let (jwk, key) = p256_key("one", 1);
    let client = signing_client(&[&jwk]);
    let header = json!({"alg": "ES256", "kid": "one"});
    let checked = check(&sign(&header, &claims_for(&client), &key), &client).expect("accepted");
    assert_eq!(checked.assertion_id, "assertion-1");
    assert_eq!(checked.expires_at, now() + Duration::minutes(2));

    let mut claims = claims_for(&client);
    claims["aud"] = json!(["https://elsewhere.example.com", ISSUER]);
    check(&sign(&header, &claims, &key), &client).expect("the issuer is an audience too");

    // Without a kid, the one key that fits is used.
    let assertion = sign(&json!({"alg": "ES256"}), &claims_for(&client), &key);
    check(&assertion, &client).expect("the only key");
    assert_eq!(assertion_issuer(&assertion), Some(client.id().to_string()));
}

#[test]
fn an_assertion_that_breaks_a_rule_is_refused() {
    let (jwk, key) = p256_key("one", 1);
    let (other_jwk, other_key) = p256_key("two", 7);
    let client = signing_client(&[&jwk]);
    let two_keys = signing_client(&[&jwk, &other_jwk]);
    let header = json!({"alg": "ES256", "kid": "one"});
    let claims = claims_for(&client);
    let changed = |name: &str, value: Value| {
        let mut claims = claims_for(&client);
        if value.is_null() {
            claims.as_object_mut().expect("object").remove(name);
        } else {
            claims[name] = value;
        }
        sign(&header, &claims, &key)
    };
    let good = sign(&header, &claims, &key);
    let (head, _) = good.rsplit_once('.').expect("three parts");
    let unsigned = format!("{}.{}.", encode(&json!({"alg": "none"})), encode(&claims));
    let cases: Vec<(String, &Client, &str)> = vec![
        (
            "a".repeat(MAX_ASSERTION_BYTES + 1),
            &client,
            "the assertion is too large",
        ),
        (
            "a.b".to_owned(),
            &client,
            "the assertion is not three parts",
        ),
        (
            "bm90IGpzb24.e30.c2ln".to_owned(),
            &client,
            "the assertion's header is malformed",
        ),
        (
            unsigned,
            &client,
            "the assertion names an algorithm that is not accepted",
        ),
        (
            sign(&json!({"alg": "HS256", "kid": "one"}), &claims, &key),
            &client,
            "the assertion names an algorithm that is not accepted",
        ),
        (
            sign(&json!({"alg": "ES256", "kid": "unknown"}), &claims, &key),
            &client,
            "no key of the client fits the assertion",
        ),
        (
            sign(&json!({"alg": "RS256", "kid": "one"}), &claims, &key),
            &client,
            "no key of the client fits the assertion",
        ),
        (
            sign(&json!({"alg": "ES256"}), &claims, &key),
            &two_keys,
            "the assertion does not say which of the client's keys signed it",
        ),
        (
            sign(&header, &claims, &other_key),
            &client,
            "the assertion's signature does not verify",
        ),
        (
            format!("{head}.{}", URL_SAFE_NO_PAD.encode([0_u8; 64])),
            &client,
            "the assertion's signature does not verify",
        ),
        (
            changed("iss", json!("someone-else")),
            &client,
            "the assertion is not from this client",
        ),
        (
            changed("sub", json!("someone-else")),
            &client,
            "the assertion is not from this client",
        ),
        (
            changed("aud", json!("https://elsewhere.example.com")),
            &client,
            "the assertion is not for this server",
        ),
        (
            changed("aud", Value::Null),
            &client,
            "the assertion is not for this server",
        ),
        (
            changed("exp", Value::Null),
            &client,
            "the assertion does not say when it expires",
        ),
        (
            changed(
                "exp",
                json!((now() - Duration::minutes(2)).unix_timestamp()),
            ),
            &client,
            "the assertion has expired",
        ),
        (
            changed(
                "exp",
                json!((now() + Duration::minutes(10)).unix_timestamp()),
            ),
            &client,
            "the assertion expires too far ahead",
        ),
        (
            changed(
                "nbf",
                json!((now() + Duration::minutes(3)).unix_timestamp()),
            ),
            &client,
            "the assertion is from the future",
        ),
        (
            changed("iat", json!("yesterday")),
            &client,
            "the assertion has a malformed time",
        ),
        (
            changed("jti", Value::Null),
            &client,
            "the assertion has no usable jti",
        ),
        (
            changed("jti", json!("j".repeat(MAX_ASSERTION_ID_LENGTH + 1))),
            &client,
            "the assertion has no usable jti",
        ),
    ];
    for (assertion, client, reason) in cases {
        assert_eq!(check(&assertion, client), Err(reason));
    }
}

#[test]
fn an_assertion_within_the_clock_allowance_is_accepted() {
    let (jwk, key) = p256_key("one", 1);
    let client = signing_client(&[&jwk]);
    let header = json!({"alg": "ES256", "kid": "one"});
    let mut claims = claims_for(&client);
    claims["exp"] = json!((now() - Duration::seconds(30)).unix_timestamp());
    claims["nbf"] = json!((now() + Duration::seconds(30)).unix_timestamp());
    check(&sign(&header, &claims, &key), &client).expect("within the allowance");
}

fn redeemed(audiences: &[&str]) -> AuthorizationCode {
    AuthorizationCode {
        hash: crate::domain::authorization::CodeHash::from_stored([1; 32]),
        grant_id: GrantId::generate(),
        client_id: ClientId::generate(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        scopes: vec!["openid".to_owned(), "orders:read".to_owned()],
        audiences: audiences.iter().map(|a| (*a).to_owned()).collect(),
        code_challenge: None,
        nonce: None,
        session_id: SessionId::generate(),
        user_id: UserId::generate(),
        signed_in_at: now() - Duration::minutes(3),
        methods: vec!["password".to_owned()],
        issued_at: now(),
        expires_at: now() + Duration::seconds(60),
        redeemed_at: Some(now()),
    }
}

#[test]
fn the_access_token_says_who_for_whom_and_until_when() {
    let code = redeemed(&["https://orders.example.com"]);
    let client = ClientId::generate();
    let token = access_token_claims(
        ISSUER,
        &code,
        client,
        Duration::minutes(5),
        now(),
        &DistinctRandom,
    );
    let claims = &token.claims;
    assert_eq!(claims["iss"], ISSUER);
    assert_eq!(claims["sub"], code.user_id.to_string());
    assert_eq!(claims["aud"], "https://orders.example.com");
    assert_eq!(claims["client_id"], client.to_string());
    assert_eq!(claims["scope"], "openid orders:read");
    assert_eq!(claims["iat"], now().unix_timestamp());
    assert_eq!(
        claims["exp"],
        (now() + Duration::minutes(5)).unix_timestamp()
    );
    assert_eq!(claims["auth_time"], code.signed_in_at.unix_timestamp());
    assert_eq!(claims["jti"], token.token_id.as_str());
    assert_eq!(token.token_id.len(), 22, "16 bytes of base64url");
    assert!(claims.get("amr").is_none() && claims.get("acr").is_none());

    let many = access_token_claims(
        ISSUER,
        &redeemed(&["https://orders.example.com", "urn:example:billing"]),
        client,
        Duration::minutes(5),
        now(),
        &DistinctRandom,
    );
    assert_eq!(
        many.claims["aud"],
        json!(["https://orders.example.com", "urn:example:billing"])
    );
    let none = access_token_claims(
        ISSUER,
        &redeemed(&[]),
        client,
        Duration::minutes(5),
        now(),
        &DistinctRandom,
    );
    assert_eq!(none.claims["aud"], ISSUER, "Hodor itself is the audience");
    assert_ne!(none.token_id, many.token_id);
}

#[test]
fn a_signed_token_is_written_as_a_compact_signature() {
    let header = access_token_header("ES256", "key-1");
    assert_eq!(
        header,
        json!({"alg": "ES256", "typ": "at+jwt", "kid": "key-1"})
    );
    let input = signing_input(&header, &json!({"sub": "ana"}));
    let token = compact(input.as_bytes(), &[1, 2, 3]);
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(format!("{}.{}", parts[0], parts[1]), input);
    assert_eq!(parts[2], "AQID");
}
