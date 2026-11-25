use super::*;
use crate::domain::authorization::{CodeHash, GrantId};
use crate::domain::token::SUPPORTED_GRANT_TYPES;
use crate::testing::{FakeVerifier, fake_signature};
use hodor_kernel::UserId;
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
        ["otp", "mfa"],
        "an external sign-in names nothing, and counts as something known, \
         as it does for the acr"
    );
    assert_eq!(
        authentication_methods(&methods(&["email_code"])),
        ["otp"],
        "a code by email is a one-time password, and one factor"
    );
    assert!(
        authentication_methods(&methods(&["email_link"])).is_empty(),
        "RFC 8176 has no name for a link"
    );
    assert_eq!(
        authentication_methods(&methods(&["email_link", "webauthn"])),
        ["pop", "mfa"],
        "the mailbox counts as something known, as it does for the acr"
    );
    assert_eq!(
        authentication_methods(&methods(&["email_code", "totp"])),
        ["otp", "mfa"]
    );
    assert!(
        authentication_methods(&methods(&["enrollment"])).is_empty(),
        "RFC 8176 has no name for a factor put in use during the sign-in"
    );
    assert_eq!(
        authentication_methods(&methods(&["password", "enrollment"])),
        ["pwd", "mfa"],
        "a factor set up after the password counts as something held, as \
         it does for the acr"
    );
    assert_eq!(
        authentication_methods(&methods(&["external", "enrollment"])),
        ["mfa"]
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
        IdTokenNames {
            subject: "the person as the client knows them",
            session: "the session as the client knows it",
        },
        None,
        client,
        Duration::minutes(5),
        now(),
        "the-access-token",
        IdTokenAlgorithm::Es256,
        &FakeDigest,
    );
    assert_eq!(claims["iss"], ISSUER);
    assert_eq!(claims["sub"], "the person as the client knows them");
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
        access_token_hash("the-access-token", IdTokenAlgorithm::Es256, &FakeDigest)
    );
    assert_eq!(
        claims["at_hash"].as_str().map(str::len),
        Some(22),
        "16 bytes of base64url"
    );
    assert_eq!(
        claims["sid"], "the session as the client knows it",
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
        IdTokenNames {
            subject: "the person as the client knows them",
            session: "the session as the client knows it",
        },
        None,
        ClientId::generate(),
        Duration::minutes(5),
        now(),
        "token",
        IdTokenAlgorithm::Es256,
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
        fn sha512(&self, _data: &[u8]) -> [u8; 64] {
            std::array::from_fn(|index| u8::try_from(100 + index).unwrap_or(u8::MAX))
        }
    }
    // The hash of the ID token's algorithm: SHA-256 for the three named
    // ...256, SHA-512 for EdDSA on Ed25519, and its left half each time.
    let left: Vec<u8> = (0_u8..16).collect();
    for algorithm in [
        IdTokenAlgorithm::Es256,
        IdTokenAlgorithm::Rs256,
        IdTokenAlgorithm::Ps256,
    ] {
        assert_eq!(
            access_token_hash("any token", algorithm, &Positions),
            URL_SAFE_NO_PAD.encode(&left)
        );
    }
    let left: Vec<u8> = (100_u8..132).collect();
    assert_eq!(
        access_token_hash("any token", IdTokenAlgorithm::EdDsa, &Positions),
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
    check_access_token(token, ISSUER, &published(), now(), &FakeVerifier, None)
}

#[test]
fn a_bound_access_token_is_accepted_only_with_its_certificate() {
    use crate::domain::binding::CertificateThumbprint;
    let mine = CertificateThumbprint::from_bytes([1; 32]);
    let other = CertificateThumbprint::from_bytes([2; 32]);
    let mut claims = good_claims(UserId::generate());
    claims["cnf"] = mine.confirmation();
    let token = sign(&good_header(), &claims);
    let with = |presented: Option<&CertificateThumbprint>| {
        check_access_token(
            &token,
            ISSUER,
            &published(),
            now(),
            &FakeVerifier,
            presented,
        )
    };
    with(Some(&mine)).expect("with its certificate");
    assert!(matches!(with(None), Err(BearerRefusal::InvalidToken(_))));
    assert!(matches!(
        with(Some(&other)),
        Err(BearerRefusal::InvalidToken(_))
    ));
    let read = read_access_token(&token, ISSUER, &published(), now(), &FakeVerifier).expect("read");
    assert_eq!(read.confirmation, Some(mine.confirmation()));

    // A `cnf` that cannot be read is never taken for no binding.
    claims["cnf"] = json!("x5t#S256");
    let token = sign(&good_header(), &claims);
    assert!(matches!(
        check_access_token(
            &token,
            ISSUER,
            &published(),
            now(),
            &FakeVerifier,
            Some(&mine)
        ),
        Err(BearerRefusal::InvalidToken(_))
    ));
}

#[test]
fn a_good_access_token_is_accepted_with_its_scopes() {
    let user = UserId::generate();
    let checked = check(&sign(&good_header(), &good_claims(user))).expect("accepted");
    assert_eq!(checked.subject, user.to_string());
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
            // The client acting for itself: client credentials.
            changed_claim("sub", json!("a-client")),
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

/// A person with every standard claim.
pub(crate) fn every_claim() -> StandardClaims {
    StandardClaims {
        given_name: Some("Ana".to_owned()),
        family_name: Some("Lima".to_owned()),
        middle_name: Some("Maria".to_owned()),
        nickname: Some("Aninha".to_owned()),
        profile: Some("https://example.com/ana".to_owned()),
        picture: Some("https://example.com/ana.png".to_owned()),
        website: Some("https://ana.example.org".to_owned()),
        gender: Some("female".to_owned()),
        birthdate: Some("1990-04-12".to_owned()),
        zoneinfo: Some("America/Sao_Paulo".to_owned()),
        phone_number: Some("+5511912345678".to_owned()),
        phone_number_verified: true,
        address: Some(PostalAddress {
            street_address: Some("Rua Augusta, 100".to_owned()),
            locality: Some("São Paulo".to_owned()),
            country: Some("BR".to_owned()),
            ..PostalAddress::default()
        }),
    }
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
        claims: every_claim(),
        groups: vec![GroupId::generate()],
    };
    let scopes =
        |list: &[&str]| -> Vec<String> { list.iter().map(|scope| (*scope).to_owned()).collect() };
    assert_eq!(
        userinfo_claims(&user.to_string(), &scopes(&["openid"]), &person),
        json!({"sub": user.to_string()})
    );
    assert_eq!(
        userinfo_claims(&user.to_string(), &scopes(&["openid", "groups"]), &person),
        json!({"sub": user.to_string(), "groups": [person.groups[0].to_string()]})
    );
    assert_eq!(
        userinfo_claims(&user.to_string(), &scopes(&["openid", "email"]), &person),
        json!({"sub": user.to_string(), "email": "ana@example.com", "email_verified": true})
    );
    assert_eq!(
        userinfo_claims(&user.to_string(), &scopes(&["openid", "profile"]), &person),
        json!({
            "sub": user.to_string(),
            "name": "Ana Lima",
            "preferred_username": "ana",
            "given_name": "Ana",
            "family_name": "Lima",
            "middle_name": "Maria",
            "nickname": "Aninha",
            "profile": "https://example.com/ana",
            "picture": "https://example.com/ana.png",
            "website": "https://ana.example.org",
            "gender": "female",
            "birthdate": "1990-04-12",
            "zoneinfo": "America/Sao_Paulo",
            "locale": "pt-BR",
            "updated_at": now().unix_timestamp(),
        })
    );
    assert_eq!(
        userinfo_claims(&user.to_string(), &scopes(&["openid", "address"]), &person),
        json!({
            "sub": user.to_string(),
            "address": {
                "street_address": "Rua Augusta, 100",
                "locality": "São Paulo",
                "country": "BR",
            },
        })
    );
    assert_eq!(
        userinfo_claims(&user.to_string(), &scopes(&["openid", "phone"]), &person),
        json!({
            "sub": user.to_string(),
            "phone_number": "+5511912345678",
            "phone_number_verified": true,
        })
    );
    assert_eq!(
        userinfo_claims(
            &user.to_string(),
            &scopes(&["openid", "profile", "email", "address", "phone"]),
            &PersonClaims::default()
        ),
        json!({"sub": user.to_string()}),
        "what the person does not have is left out"
    );
}

#[test]
fn discovery_names_only_what_is_built() {
    let document = discovery_document(ISSUER, &["urn:example:one", "urn:example:two"], false);
    assert_eq!(document["issuer"], ISSUER);
    assert_eq!(
        document["pushed_authorization_request_endpoint"],
        format!("{ISSUER}/oauth2/par")
    );
    assert_eq!(
        document["require_pushed_authorization_requests"],
        json!(false)
    );
    assert_eq!(
        discovery_document(ISSUER, &[], true)["require_pushed_authorization_requests"],
        json!(true),
        "the tenant's requirement"
    );
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
    assert_eq!(document["backchannel_logout_supported"], json!(true));
    assert_eq!(
        document["backchannel_logout_session_supported"],
        json!(true)
    );
    assert_eq!(
        document["grant_types_supported"],
        json!(SUPPORTED_GRANT_TYPES)
    );
    assert_eq!(document["response_types_supported"], json!(["code"]));
    assert_eq!(
        document["response_modes_supported"],
        json!(["query", "form_post"])
    );
    assert_eq!(
        document["scopes_supported"],
        json!(["openid", "profile", "email", "address", "phone", "groups"])
    );
    let claims = document["claims_supported"].as_array().expect("a list");
    for claim in [
        "given_name",
        "family_name",
        "middle_name",
        "nickname",
        "profile",
        "picture",
        "website",
        "gender",
        "birthdate",
        "zoneinfo",
        "address",
        "phone_number",
        "phone_number_verified",
    ] {
        assert!(claims.contains(&json!(claim)), "{claim} is supported");
    }
    assert_eq!(
        document["subject_types_supported"],
        json!(["public", "pairwise"])
    );
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
    for endpoint in ["token", "revocation"] {
        assert_eq!(
            document[format!("{endpoint}_endpoint_auth_methods_supported")],
            json!([
                "client_secret_basic",
                "client_secret_post",
                "private_key_jwt",
                "spiffe_jwt",
                "none"
            ]),
            "{endpoint}"
        );
    }
    assert_eq!(
        document["introspection_endpoint_auth_methods_supported"],
        json!([
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
            "spiffe_jwt"
        ]),
        "a public client may not introspect"
    );
    // Every algorithm a client may choose for what Hodor signs for it.
    for member in [
        "id_token_signing_alg_values_supported",
        "userinfo_signing_alg_values_supported",
    ] {
        assert_eq!(
            document[member],
            json!(["ES256", "RS256", "PS256", "EdDSA"]),
            "{member}"
        );
    }
    assert_eq!(document["request_parameter_supported"], json!(true));
    assert_eq!(
        document["request_object_signing_alg_values_supported"],
        json!(["ES256", "RS256", "PS256", "none"])
    );
    assert_eq!(document["request_uri_parameter_supported"], json!(true));
    assert_eq!(document["require_request_uri_registration"], json!(true));
    assert_eq!(document["claims_parameter_supported"], json!(false));
    for absent in ["registration_endpoint", "device_authorization_endpoint"] {
        assert!(document.get(absent).is_none(), "{absent} is not built");
    }
}

#[test]
fn the_id_token_names_the_organization_of_the_sign_in() {
    let organization = OrganizationId::generate();
    let claims = id_token_claims(
        ISSUER,
        &code(None, &["password"]),
        IdTokenNames {
            subject: "the person as the client knows them",
            session: "the session as the client knows it",
        },
        Some(organization),
        ClientId::generate(),
        Duration::minutes(5),
        now(),
        "token",
        IdTokenAlgorithm::Es256,
        &FakeDigest,
    );
    assert_eq!(claims["org_id"], organization.to_string());
    assert!(
        claims.get("groups").is_none(),
        "groups stay out of the ID token"
    );
}

#[test]
fn userinfo_answers_every_group_however_many() {
    let person = PersonClaims {
        name: None,
        preferred_username: None,
        locale: None,
        updated_at: None,
        email: None,
        claims: StandardClaims::default(),
        groups: (0..150).map(|_| GroupId::generate()).collect(),
    };
    let claims = userinfo_claims(
        "the person as the client knows them",
        &["openid".to_owned(), "groups".to_owned()],
        &person,
    );
    assert_eq!(claims["groups"].as_array().map(Vec::len), Some(150));
}

/// The specification of discovery, which the documentation site publishes.
const OAUTH_CONTEXT: &str = include_str!("../../../../../docs/architecture/contexts/oauth.md");

#[test]
fn the_metadata_page_names_the_version_of_the_spiffe_draft() {
    use crate::domain::spiffe::SPIFFE_CLIENT_AUTHENTICATION_DRAFT;
    let discovery = OAUTH_CONTEXT
        .split("\n### Discovery\n")
        .nth(1)
        .and_then(|section| section.split("\n### ").next())
        .expect("the discovery section");
    assert!(
        discovery.contains(&format!(
            "**`spiffe_jwt` follows {SPIFFE_CLIENT_AUTHENTICATION_DRAFT}**"
        )),
        "the metadata page names the version of the draft Hodor follows"
    );
    let document = discovery_document(ISSUER, &[], false);
    assert!(
        document["token_endpoint_auth_methods_supported"]
            .as_array()
            .expect("a list")
            .contains(&json!("spiffe_jwt"))
    );
}

#[test]
fn a_signed_userinfo_answer_holds_the_claims_with_iss_and_aud_and_no_expiry() {
    let claims = json!({"sub": "248289761001", "name": "Ana Lima", "email": "ana@example.com"});
    let signed = signed_userinfo_claims(claims, "https://hodor.example.com/t/acme", "client-1");
    assert_eq!(
        signed,
        json!({
            "sub": "248289761001",
            "name": "Ana Lima",
            "email": "ana@example.com",
            "iss": "https://hodor.example.com/t/acme",
            "aud": "client-1",
        })
    );
    for absent in ["exp", "iat", "nonce", "typ"] {
        assert!(signed.get(absent).is_none(), "{absent}");
    }
    // The header names the algorithm and the key, and is no ID token's.
    let header = userinfo_header("EdDSA", "0193a0b2-0000-7000-8000-000000000001");
    assert_eq!(
        header,
        json!({"alg": "EdDSA", "kid": "0193a0b2-0000-7000-8000-000000000001"})
    );
    assert_ne!(
        header,
        id_token_header("EdDSA", "0193a0b2-0000-7000-8000-000000000001")
    );
}
