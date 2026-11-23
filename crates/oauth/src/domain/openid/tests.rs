use super::*;
use crate::domain::authorization::{CodeHash, GrantId};
use crate::domain::token::SUPPORTED_GRANT_TYPES;
use crate::testing::{FakeVerifier, fake_signature};
use hodor_kernel::random::testing::FakeDigest;
use hodor_session::api::SessionId;

const ISSUER: &str = "https://hodor.example.com/t/acme";

fn now() -> Timestamp {
    Timestamp::UNIX_EPOCH + Duration::days(20_000)
}

fn methods(list: &[&str]) -> Vec<String> {
    list.iter().map(|method| (*method).to_owned()).collect()
}

#[test]
fn each_method_is_named_as_rfc_8176_names_it() {
    assert_eq!(authentication_methods(&methods(&["password"])), ["pwd"]);
    assert_eq!(
        authentication_methods(&methods(&["password", "totp"])),
        ["pwd", "otp", "mfa"]
    );
    assert_eq!(
        authentication_methods(&methods(&["password", "webauthn"])),
        ["pwd", "pop", "mfa"]
    );
    assert_eq!(
        authentication_methods(&methods(&["password", "recovery_code"])),
        ["pwd", "otp", "mfa"]
    );
    assert_eq!(
        authentication_methods(&methods(&["passkey"])),
        ["pop", "user", "mfa"],
        "a passkey is two factors in one gesture"
    );
    assert_eq!(
        authentication_methods(&methods(&["password", "totp", "webauthn", "totp"])),
        ["pwd", "otp", "pop", "mfa"],
        "each value once, in a fixed order"
    );
    assert!(
        authentication_methods(&methods(&["external"])).is_empty(),
        "Hodor did not see how a provider signed the person in"
    );
    assert_eq!(
        authentication_methods(&methods(&["external", "totp"])),
        ["otp"],
        "an external sign-in is not counted as something known"
    );
    assert!(authentication_methods(&methods(&["something-new"])).is_empty());
}

const ACR_MULTI_FACTOR: &str = "urn:hodor:acr:mfa";

fn code(nonce: Option<&str>, signed_in: &[&str]) -> AuthorizationCode {
    AuthorizationCode {
        hash: CodeHash::from_stored([1; 32]),
        grant_id: GrantId::generate(),
        client_id: ClientId::generate(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        scopes: vec!["openid".to_owned(), "email".to_owned()],
        audiences: Vec::new(),
        code_challenge: None,
        nonce: nonce.map(str::to_owned),
        session_id: SessionId::generate(),
        user_id: UserId::generate(),
        signed_in_at: now() - Duration::minutes(3),
        methods: methods(signed_in),
        acr: nonce.map(|_| ACR_MULTI_FACTOR.to_owned()),
        issued_at: now(),
        expires_at: now() + Duration::seconds(60),
        redeemed_at: Some(now()),
    }
}

#[test]
fn the_id_token_says_who_signed_in_for_which_client() {
    let code = code(Some("n-0S6_WzA2Mj"), &["password", "totp"]);
    let client = ClientId::generate();
    let claims = id_token_claims(
        ISSUER,
        &code,
        client,
        Duration::minutes(5),
        now(),
        "the-access-token",
        &FakeDigest,
    );
    assert_eq!(claims["iss"], ISSUER);
    assert_eq!(claims["sub"], code.user_id.to_string());
    assert_eq!(claims["aud"], client.to_string(), "the client alone");
    assert_eq!(claims["iat"], now().unix_timestamp());
    assert_eq!(
        claims["exp"],
        (now() + Duration::minutes(5)).unix_timestamp()
    );
    assert_eq!(claims["auth_time"], code.signed_in_at.unix_timestamp());
    assert_eq!(claims["nonce"], "n-0S6_WzA2Mj", "echoed exactly");
    assert_eq!(claims["acr"], ACR_MULTI_FACTOR);
    assert_eq!(claims["amr"], json!(["pwd", "otp", "mfa"]));
    assert_eq!(
        claims["at_hash"],
        access_token_hash("the-access-token", &FakeDigest)
    );
    assert_eq!(
        claims["at_hash"].as_str().map(str::len),
        Some(22),
        "16 bytes of base64url"
    );
    assert_eq!(
        claims["sid"],
        code.session_id.to_string(),
        "the session, for logout"
    );
    for absent in ["azp", "email", "name", "scope", "client_id"] {
        assert!(claims.get(absent).is_none(), "{absent}");
    }
}

#[test]
fn an_id_token_leaves_out_what_the_sign_in_did_not_have() {
    let claims = id_token_claims(
        ISSUER,
        &code(None, &["external"]),
        ClientId::generate(),
        Duration::minutes(5),
        now(),
        "token",
        &FakeDigest,
    );
    assert!(claims.get("nonce").is_none());
    assert!(claims.get("amr").is_none(), "no name in RFC 8176");
    assert!(
        claims.get("acr").is_none(),
        "the code reached no level of the tenant"
    );
}

#[test]
fn at_hash_is_the_left_half_of_the_digest() {
    /// A digest whose bytes are their own positions, so that the half
    /// taken can be seen.
    struct Positions;
    impl Digest for Positions {
        fn sha256(&self, _data: &[u8]) -> [u8; 32] {
            std::array::from_fn(|index| u8::try_from(index).unwrap_or(u8::MAX))
        }
    }
    let left: Vec<u8> = (0_u8..16).collect();
    assert_eq!(
        access_token_hash("any token", &Positions),
        URL_SAFE_NO_PAD.encode(left)
    );
}

const KEY_ID: &str = "0193a0b2-0000-7000-8000-000000000001";

fn key() -> PublicKey {
    PublicKey::P256 {
        x: vec![1; 32],
        y: vec![2; 32],
    }
}

fn published() -> Vec<PublishedKey> {
    vec![PublishedKey {
        key_id: KEY_ID.to_owned(),
        algorithm: SignatureAlgorithm::Es256,
        key: key(),
    }]
}

fn sign(header: &Value, claims: &Value) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature = fake_signature(SignatureAlgorithm::Es256, &key(), input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn good_header() -> Value {
    json!({"alg": "ES256", "typ": "at+jwt", "kid": KEY_ID})
}

fn good_claims(user: UserId) -> Value {
    json!({
        "iss": ISSUER,
        "sub": user.to_string(),
        "aud": ["https://orders.example.com", ISSUER],
        "scope": "openid profile",
        "exp": (now() + Duration::minutes(5)).unix_timestamp(),
        "iat": now().unix_timestamp(),
        "jti": "token-1",
        "client_id": "a-client",
    })
}

fn check(token: &str) -> Result<CheckedAccessToken, BearerRefusal> {
    check_access_token(token, ISSUER, &published(), now(), &FakeVerifier)
}

#[test]
fn a_good_access_token_is_accepted_with_its_scopes() {
    let user = UserId::generate();
    let checked = check(&sign(&good_header(), &good_claims(user))).expect("accepted");
    assert_eq!(checked.user_id, user);
    assert_eq!(checked.scopes, ["openid", "profile"]);
    assert_eq!(checked.token_id, "token-1");
    assert_eq!(checked.client_id, "a-client");
    let mut alone = good_claims(user);
    alone["aud"] = json!(ISSUER);
    check(&sign(&good_header(), &alone)).expect("the issuer alone as audience");
}

#[test]
fn every_bad_access_token_is_refused_for_its_own_reason() {
    let user = UserId::generate();
    let invalid = |reason: &'static str| Err(BearerRefusal::InvalidToken(reason));
    let changed_header = |name: &str, value: Value| {
        let mut header = good_header();
        header[name] = value;
        sign(&header, &good_claims(user))
    };
    let changed_claim = |name: &str, value: Value| {
        let mut claims = good_claims(user);
        claims[name] = value;
        sign(&good_header(), &claims)
    };
    let cases: Vec<(String, Result<CheckedAccessToken, BearerRefusal>)> = vec![
        (
            "not a token".to_owned(),
            invalid("the token is not three parts"),
        ),
        ("a.b.c".to_owned(), invalid("the header is malformed")),
        (
            changed_header("typ", json!("JWT")),
            invalid("the token is not an access token"),
        ),
        (
            changed_header("alg", json!("none")),
            invalid("the token names another algorithm"),
        ),
        (
            changed_header("alg", json!("HS256")),
            invalid("the token names another algorithm"),
        ),
        (
            changed_header("kid", json!("a key of another tenant")),
            invalid("the token's key is not published by this tenant"),
        ),
        (
            changed_claim("iss", json!("https://hodor.example.com/t/globex")),
            invalid("the token is from another issuer"),
        ),
        (
            changed_claim("aud", json!("https://orders.example.com")),
            invalid("the token is not for this server"),
        ),
        (
            changed_claim("exp", json!(now().unix_timestamp())),
            invalid("the token has expired"),
        ),
        (
            changed_claim("exp", Value::Null),
            invalid("the token does not say when it expires"),
        ),
        (
            changed_claim("sub", json!("not-a-user")),
            invalid("the token names no person"),
        ),
        (
            changed_claim("jti", Value::Null),
            invalid("the token has no jti"),
        ),
        (
            changed_claim("client_id", Value::Null),
            invalid("the token names no client"),
        ),
        (
            changed_claim("scope", json!("orders:read")),
            Err(BearerRefusal::InsufficientScope),
        ),
    ];
    for (token, expected) in cases {
        assert_eq!(check(&token), expected, "{token}");
    }

    // A token whose claims were changed after it was signed.
    let good = sign(&good_header(), &good_claims(user));
    let mut parts: Vec<String> = good.split('.').map(str::to_owned).collect();
    let mut forged = good_claims(user);
    forged["scope"] = json!("openid profile email");
    parts[1] = URL_SAFE_NO_PAD.encode(forged.to_string());
    assert_eq!(
        check(&parts.join(".")),
        invalid("the signature does not verify")
    );
}

#[test]
fn userinfo_answers_only_the_claims_of_the_token_s_scopes() {
    let user = UserId::generate();
    let person = PersonClaims {
        name: Some("Ana Lima".to_owned()),
        preferred_username: Some("ana".to_owned()),
        locale: Some("pt-BR".to_owned()),
        updated_at: Some(now()),
        email: Some(("ana@example.com".to_owned(), true)),
    };
    let scopes =
        |list: &[&str]| -> Vec<String> { list.iter().map(|scope| (*scope).to_owned()).collect() };
    assert_eq!(
        userinfo_claims(user, &scopes(&["openid"]), &person),
        json!({"sub": user.to_string()})
    );
    assert_eq!(
        userinfo_claims(user, &scopes(&["openid", "email"]), &person),
        json!({"sub": user.to_string(), "email": "ana@example.com", "email_verified": true})
    );
    assert_eq!(
        userinfo_claims(user, &scopes(&["openid", "profile"]), &person),
        json!({
            "sub": user.to_string(),
            "name": "Ana Lima",
            "preferred_username": "ana",
            "locale": "pt-BR",
            "updated_at": now().unix_timestamp(),
        })
    );
    assert_eq!(
        userinfo_claims(
            user,
            &scopes(&["openid", "profile", "email"]),
            &PersonClaims::default()
        ),
        json!({"sub": user.to_string()}),
        "what the person does not have is left out"
    );
}

#[test]
fn discovery_names_only_what_is_built() {
    let document = discovery_document(ISSUER, &["urn:example:one", "urn:example:two"]);
    assert_eq!(document["issuer"], ISSUER);
    assert_eq!(
        document["acr_values_supported"],
        json!(["urn:example:one", "urn:example:two"]),
        "the tenant's levels, as given"
    );
    assert_eq!(
        document["authorization_endpoint"],
        format!("{ISSUER}/oauth2/authorize")
    );
    assert_eq!(document["token_endpoint"], format!("{ISSUER}/oauth2/token"));
    assert_eq!(
        document["userinfo_endpoint"],
        format!("{ISSUER}/oauth2/userinfo")
    );
    assert_eq!(document["jwks_uri"], format!("{ISSUER}/oauth2/jwks"));
    assert_eq!(
        document["end_session_endpoint"],
        format!("{ISSUER}/oauth2/logout")
    );
    assert_eq!(
        document["grant_types_supported"],
        json!(SUPPORTED_GRANT_TYPES)
    );
    assert_eq!(document["response_types_supported"], json!(["code"]));
    assert_eq!(document["subject_types_supported"], json!(["public"]));
    assert_eq!(
        document["code_challenge_methods_supported"],
        json!(["S256"])
    );
    assert_eq!(
        document["revocation_endpoint"],
        format!("{ISSUER}/oauth2/revoke")
    );
    assert_eq!(
        document["introspection_endpoint"],
        format!("{ISSUER}/oauth2/introspect")
    );
    assert_eq!(
        document["revocation_endpoint_auth_methods_supported"],
        json!([
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
            "none"
        ])
    );
    assert_eq!(
        document["introspection_endpoint_auth_methods_supported"],
        json!([
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt"
        ]),
        "a public client may not introspect"
    );
    for absent in [
        "registration_endpoint",
        "pushed_authorization_request_endpoint",
        "device_authorization_endpoint",
    ] {
        assert!(document.get(absent).is_none(), "{absent} is not built");
    }
}
