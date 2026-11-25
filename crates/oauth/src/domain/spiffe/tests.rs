use super::*;
use crate::domain::client::{AuthenticationMethod, ClientSettings, ClientType, GrantType};
use crate::domain::token::{BasicCredentials, PresentedClient, TokenRequest};
use crate::testing::{FakeVerifier, fake_signature};
use hodor_kernel::UserId;
use hodor_kernel::random::testing::FakeDigest;
use hodor_keys::testing::sample_bundle;
use serde_json::json;

const ISSUER: &str = "https://hodor.example.com/t/acme";
const EXPORT: &str = "spiffe://cluster.local/ns/payroll/sa/export";
const KID: &str = "2026-11";

fn now() -> Timestamp {
    Timestamp::UNIX_EPOCH + Duration::days(20_000)
}

fn export() -> SpiffeId {
    SpiffeId::parse(EXPORT).expect("identifier")
}

fn bundle(key_ids: &[&str]) -> TrustBundle {
    TrustBundle::parse(sample_bundle(Some(1), key_ids).to_string().as_bytes()).expect("bundle")
}

/// A JWT-SVID with `header` and `claims`, signed for [`FakeVerifier`] by
/// the bundle's key `signer`.
fn signed(header: &Value, claims: &Value, signer: &TrustBundle, kid: &str) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let key = verifying_key_of(
        &signer.jwt_key(kid).expect("signer's key").jwk,
        SignatureAlgorithm::Es256,
    )
    .expect("a P-256 key");
    let signature = fake_signature(SignatureAlgorithm::Es256, &key, input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn header() -> Value {
    json!({ "alg": "ES256", "kid": KID, "typ": "JWT" })
}

fn claims() -> Value {
    let at = now().unix_timestamp();
    json!({ "sub": EXPORT, "aud": [ISSUER], "exp": at + 300, "iat": at })
}

fn check(svid: &str, trusted: &TrustBundle) -> Result<CheckedSvid, &'static str> {
    check_svid(
        svid,
        &export(),
        trusted,
        ISSUER,
        now(),
        &FakeVerifier,
        &FakeDigest,
    )
}

#[test]
fn an_identifier_is_written_exactly_as_spiffe_writes_it() {
    let id = export();
    assert_eq!(id.as_str(), EXPORT);
    assert_eq!(id.trust_domain(), "cluster.local");
    assert!(SpiffeId::parse("spiffe://example.org/a/b.c-d_E/9").is_ok());
    for refused in [
        "",
        "spiffe://cluster.local",
        "spiffe://cluster.local/",
        "spiffe://cluster.local/ns/",
        "spiffe://cluster.local//ns",
        "spiffe://cluster.local/ns/payroll/*",
        "spiffe://cluster.local/ns/./sa",
        "spiffe://cluster.local/ns/../sa",
        "spiffe://cluster.local/ns%2Fsa",
        "spiffe://cluster.local/ns?x=1",
        "spiffe://cluster.local/ns#x",
        "spiffe://Cluster.local/ns",
        "SPIFFE://cluster.local/ns",
        "https://cluster.local/ns",
        "spiffe://user@cluster.local/ns",
        "spiffe://cluster.local:8443/ns",
        "spiffe:///ns",
    ] {
        assert_eq!(
            SpiffeId::parse(refused).expect_err(refused).code(),
            "oauth.client_spiffe_id_invalid",
            "{refused}"
        );
    }
    let long = format!(
        "spiffe://cluster.local/{}",
        "a".repeat(MAX_SPIFFE_ID_LENGTH)
    );
    assert!(SpiffeId::parse(&long).is_err());
}

#[test]
fn a_client_using_spiffe_jwt_has_one_identifier_and_a_principal() {
    let workload = |method, spiffe_id: Option<&str>, principal| {
        let mut settings = ClientSettings::new(
            "Nightly export",
            ClientType::Confidential,
            vec![GrantType::ClientCredentials],
            Vec::new(),
        );
        settings.authentication_method = method;
        settings.spiffe_id = spiffe_id.map(|id| SpiffeId::parse(id).expect("identifier"));
        settings.principal = principal;
        settings.checked(ClientType::Confidential)
    };
    let principal = Some(UserId::generate());
    let checked = workload(AuthenticationMethod::SpiffeJwt, Some(EXPORT), principal)
        .expect("bound to one identifier");
    assert_eq!(checked.spiffe_id, Some(export()));
    for (method, spiffe_id, principal) in [
        (AuthenticationMethod::SpiffeJwt, None, principal),
        (AuthenticationMethod::SpiffeJwt, Some(EXPORT), None),
        (AuthenticationMethod::PrivateKeyJwt, Some(EXPORT), principal),
        (AuthenticationMethod::ClientSecretBasic, Some(EXPORT), None),
    ] {
        assert_eq!(
            workload(method, spiffe_id, principal)
                .expect_err("refused")
                .code(),
            "oauth.client_spiffe_id_invalid",
            "{method:?} {spiffe_id:?}"
        );
    }
    assert_eq!(
        AuthenticationMethod::parse("spiffe_jwt").expect("known"),
        AuthenticationMethod::SpiffeJwt
    );
    assert_eq!(AuthenticationMethod::SpiffeJwt.as_str(), "spiffe_jwt");
}

#[test]
fn a_jwt_svid_is_read_as_the_drafts_assertion_type() {
    let form = |list: &[(&str, &str)]| {
        let mut pairs = vec![("grant_type".to_owned(), "client_credentials".to_owned())];
        pairs.extend(
            list.iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
        );
        pairs
    };
    let request = TokenRequest::parse(
        None,
        form(&[
            ("client_id", "one"),
            ("client_assertion_type", SPIFFE_ASSERTION_TYPE),
            ("client_assertion", "a.b.c"),
        ]),
    )
    .expect("a JWT-SVID");
    assert_eq!(request.client.method(), AuthenticationMethod::SpiffeJwt);
    assert!(matches!(
        request.client,
        PresentedClient::Svid { client_id: Some(ref id), .. } if id == "one"
    ));
    let without_id = TokenRequest::parse(
        None,
        form(&[
            ("client_assertion_type", SPIFFE_ASSERTION_TYPE),
            ("client_assertion", "a.b.c"),
        ]),
    )
    .expect("read, refused later");
    assert!(matches!(
        without_id.client,
        PresentedClient::Svid {
            client_id: None,
            ..
        }
    ));
    let error = TokenRequest::parse(
        Some(BasicCredentials {
            client_id: "one".to_owned(),
            secret: hodor_kernel::Secret::from("s".to_owned()),
        }),
        form(&[
            ("client_assertion_type", SPIFFE_ASSERTION_TYPE),
            ("client_assertion", "a.b.c"),
        ]),
    )
    .expect_err("two ways");
    assert_eq!(error.error, "invalid_request");
    let error = TokenRequest::parse(
        None,
        form(&[("client_assertion_type", SPIFFE_ASSERTION_TYPE)]),
    )
    .expect_err("no assertion");
    assert_eq!(error.error, "invalid_request");
}

#[test]
fn a_jwt_svid_signed_by_its_trust_domain_for_the_issuer_alone_passes() {
    let trusted = bundle(&[KID]);
    let svid = signed(&header(), &claims(), &trusted, KID);
    let checked = check(&svid, &trusted).expect("passes");
    assert_eq!(checked.expires_at, now() + Duration::seconds(300));
    let signed_part = svid.rsplit_once('.').expect("three parts").0;
    assert_eq!(
        checked.mark,
        format!(
            "{SVID_MARK_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(FakeDigest.sha256(signed_part.as_bytes()))
        ),
        "the hash of the header and the claims, without the signature"
    );
    assert!(checked.mark.len() <= 255, "fits the register's column");

    // `aud` as one text, `typ` `JOSE` or absent, no `jti`, no `iss`.
    let mut one = claims();
    one["aud"] = json!(ISSUER);
    check(&signed(&header(), &one, &trusted, KID), &trusted).expect("one text");
    let jose = json!({ "alg": "ES256", "kid": KID, "typ": "JOSE" });
    check(&signed(&jose, &claims(), &trusted, KID), &trusted).expect("JOSE");
    let untyped = json!({ "alg": "ES256", "kid": KID });
    check(&signed(&untyped, &claims(), &trusted, KID), &trusted).expect("no typ");
    let mut other_issuer = claims();
    other_issuer["iss"] = json!("https://elsewhere.example.com");
    check(&signed(&header(), &other_issuer, &trusted, KID), &trusted).expect("iss is not read");

    // Within the clocks' allowance.
    let mut just_expired = claims();
    just_expired["exp"] = json!(now().unix_timestamp() - 30);
    check(&signed(&header(), &just_expired, &trusted, KID), &trusted).expect("allowance");
    let mut an_hour = claims();
    an_hour["exp"] = json!(now().unix_timestamp() + 3600);
    check(&signed(&header(), &an_hour, &trusted, KID), &trusted).expect("an hour ahead");
}

#[test]
fn a_jwt_svid_of_another_trust_domain_identifier_or_audience_is_refused() {
    let trusted = bundle(&[KID]);
    // Signed by a key of another trust domain's bundle, under the same kid.
    let elsewhere = TrustBundle::parse(
        json!({ "keys": [{
            "use": "jwt-svid", "kty": "EC", "crv": "P-256", "kid": KID,
            "x": URL_SAFE_NO_PAD.encode([40_u8; 32]),
            "y": URL_SAFE_NO_PAD.encode([41_u8; 32]),
        }] })
        .to_string()
        .as_bytes(),
    )
    .expect("another bundle");
    assert_eq!(
        check(&signed(&header(), &claims(), &elsewhere, KID), &trusted),
        Err("the JWT-SVID's signature does not verify")
    );
    // A kid the bundle does not have.
    let unknown = json!({ "alg": "ES256", "kid": "other", "typ": "JWT" });
    let other = bundle(&["other"]);
    assert_eq!(
        check(&signed(&unknown, &claims(), &other, "other"), &trusted),
        Err("the trust domain's bundle has no key of the JWT-SVID's kid")
    );

    let refused = |claims: Value| check(&signed(&header(), &claims, &trusted, KID), &trusted);
    // Another workload of the same trust domain.
    let mut another = claims();
    another["sub"] = json!("spiffe://cluster.local/ns/payroll/sa/import");
    assert_eq!(
        refused(another),
        Err("the JWT-SVID is not of the client's SPIFFE identifier")
    );
    let mut prefix = claims();
    prefix["sub"] = json!("spiffe://cluster.local/ns/payroll/sa/export/child");
    assert!(refused(prefix).is_err());
    let mut missing = claims();
    missing.as_object_mut().expect("object").remove("sub");
    assert!(refused(missing).is_err());
    // Another tenant's issuer, an endpoint, or more than one audience.
    for audience in [
        json!("https://hodor.example.com/t/globex"),
        json!(["https://hodor.example.com/t/globex"]),
        json!(format!("{ISSUER}/oauth2/token")),
        json!([ISSUER, "https://api.example.com"]),
        json!([]),
        json!(null),
    ] {
        let mut wrong = claims();
        wrong["aud"] = audience.clone();
        assert_eq!(
            refused(wrong),
            Err("the JWT-SVID's audience is not the tenant's issuer alone"),
            "{audience}"
        );
    }
}

#[test]
fn a_jwt_svid_that_breaks_a_rule_of_its_shape_or_time_is_refused() {
    let trusted = bundle(&[KID]);
    let refused = |header: Value, claims: Value| {
        check(&signed(&header, &claims, &trusted, KID), &trusted).expect_err("refused")
    };
    let at = now().unix_timestamp();
    let with = |name: &str, value: Value| {
        let mut changed = claims();
        changed[name] = value;
        changed
    };
    assert_eq!(
        refused(header(), with("exp", json!(at - 61))),
        "the JWT-SVID has expired"
    );
    assert_eq!(
        refused(header(), with("exp", json!(at + 3600 + 61))),
        "the JWT-SVID expires too far ahead"
    );
    let mut no_expiry = claims();
    no_expiry.as_object_mut().expect("object").remove("exp");
    assert_eq!(
        refused(header(), no_expiry),
        "the JWT-SVID does not say when it expires"
    );
    assert_eq!(
        refused(header(), with("iat", json!(at + 120))),
        "the JWT-SVID is from the future"
    );
    assert_eq!(
        refused(header(), with("nbf", json!(at + 120))),
        "the JWT-SVID is from the future"
    );
    assert_eq!(
        refused(json!({ "alg": "none", "kid": KID }), claims()),
        "the JWT-SVID names an algorithm that is not accepted"
    );
    assert_eq!(
        refused(json!({ "alg": "HS256", "kid": KID }), claims()),
        "the JWT-SVID names an algorithm that is not accepted"
    );
    assert_eq!(
        refused(json!({ "alg": "ES256" }), claims()),
        "the JWT-SVID names no kid"
    );
    assert_eq!(
        refused(
            json!({ "alg": "ES256", "kid": KID, "typ": "at+jwt" }),
            claims()
        ),
        "the JWT-SVID's typ is neither JWT nor JOSE"
    );
    // An RSA algorithm with the bundle's P-256 key.
    assert_eq!(
        check(
            &signed(
                &json!({ "alg": "RS256", "kid": KID }),
                &claims(),
                &trusted,
                KID
            ),
            &trusted
        ),
        Err("the bundle's key does not fit the JWT-SVID's algorithm")
    );
    for malformed in [
        "a.b",
        "a.b.c.d",
        "!.!.!",
        &"a".repeat(MAX_ASSERTION_BYTES + 1),
    ] {
        assert!(check(malformed, &trusted).is_err(), "{malformed}");
    }
    // A signature over other claims does not carry over.
    let svid = signed(&header(), &claims(), &trusted, KID);
    let (input, signature) = svid.rsplit_once('.').expect("parts");
    let (head, _) = input.split_once('.').expect("parts");
    let mut forged = claims();
    forged["sub"] = json!("spiffe://cluster.local/ns/payroll/sa/import");
    let tampered = format!(
        "{head}.{}.{signature}",
        URL_SAFE_NO_PAD.encode(forged.to_string())
    );
    assert_eq!(
        check(&tampered, &trusted),
        Err("the JWT-SVID's signature does not verify")
    );
}
