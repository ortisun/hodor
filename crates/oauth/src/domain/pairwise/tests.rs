use super::*;
use crate::testing::FakeHmac;
use hodor_kernel::random::testing::CountingRandom;

fn secret() -> PairwiseSecret {
    PairwiseSecret::generate(&CountingRandom::default())
}

fn uris(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

const PERSON: [u8; 16] = [7; 16];
const OTHER_PERSON: [u8; 16] = [8; 16];

#[test]
fn one_sector_gives_one_person_the_same_identifier_every_time() {
    let tenant = TenantId::generate();
    let secret = secret();
    let first = secret.subject(&FakeHmac, tenant, "app.example.com", &PERSON);
    let again = secret.subject(&FakeHmac, tenant, "app.example.com", &PERSON);
    assert_eq!(first, again);
    // The sector is compared in lowercase.
    assert_eq!(
        first,
        secret.subject(&FakeHmac, tenant, "APP.Example.com", &PERSON)
    );
    // 32 bytes of base64url without padding.
    assert_eq!(first.len(), 43);
    assert!(
        first
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    );
}

#[test]
fn another_sector_another_person_or_another_tenant_gives_another_identifier() {
    let tenant = TenantId::generate();
    let secret = secret();
    let first = secret.subject(&FakeHmac, tenant, "app.example.com", &PERSON);
    assert_ne!(
        first,
        secret.subject(&FakeHmac, tenant, "other.example.net", &PERSON)
    );
    assert_ne!(
        first,
        secret.subject(&FakeHmac, tenant, "app.example.com", &OTHER_PERSON)
    );
    // The same secret in another tenant: the tenant is in the message.
    assert_ne!(
        first,
        secret.subject(&FakeHmac, TenantId::generate(), "app.example.com", &PERSON)
    );
    // Another tenant's own secret.
    let another = PairwiseSecret::from_opened(Secret::new(vec![9; 32])).expect("secret");
    assert_ne!(
        first,
        another.subject(&FakeHmac, tenant, "app.example.com", &PERSON)
    );
    // The user identifier is not in it.
    let written = uuid_text(&PERSON);
    assert!(!first.contains(&written));
}

fn uuid_text(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn a_session_and_a_person_with_the_same_bytes_get_different_identifiers() {
    let tenant = TenantId::generate();
    let secret = secret();
    assert_ne!(
        secret.subject(&FakeHmac, tenant, "app.example.com", &PERSON),
        secret.session(&FakeHmac, tenant, "app.example.com", &PERSON)
    );
    assert_eq!(
        secret.session(&FakeHmac, tenant, "app.example.com", &PERSON),
        secret.session(&FakeHmac, tenant, "app.example.com", &PERSON)
    );
    assert_ne!(
        secret.session(&FakeHmac, tenant, "app.example.com", &PERSON),
        secret.session(&FakeHmac, tenant, "other.example.net", &PERSON)
    );
}

#[test]
fn a_secret_that_is_not_32_bytes_does_not_open() {
    let error = PairwiseSecret::from_opened(Secret::new(vec![1; 31])).expect_err("short");
    assert_eq!(error.code(), "secret.unreadable");
    assert_eq!(format!("{:?}", secret()), "PairwiseSecret(…)");
}

#[test]
fn the_host_of_an_address_is_lowercase_without_its_port() {
    assert_eq!(
        host_of("https://App.Example.com:8443/callback?x=1").as_deref(),
        Some("app.example.com")
    );
    assert_eq!(
        host_of("http://127.0.0.1:4000/callback").as_deref(),
        Some("127.0.0.1")
    );
    assert_eq!(host_of("http://[::1]:4000/").as_deref(), Some("[::1]"));
    assert_eq!(host_of("com.example.app:/callback"), None);
    assert_eq!(host_of("https:///nothing"), None);
}

#[test]
fn the_sector_is_the_address_host_or_the_one_host_of_the_redirect_addresses() {
    let one_host = uris(&[
        "https://app.example.com/callback",
        "https://APP.example.com:8443/other",
    ]);
    assert_eq!(
        sector_of(None, &one_host).as_deref(),
        Some("app.example.com")
    );
    let two_hosts = uris(&[
        "https://app.example.com/callback",
        "https://other.example.net/callback",
    ]);
    assert_eq!(sector_of(None, &two_hosts), None);
    assert_eq!(
        sector_of(Some("https://sector.example.org/uris.json"), &two_hosts).as_deref(),
        Some("sector.example.org")
    );
    assert_eq!(sector_of(None, &uris(&["com.example.app:/callback"])), None);
    assert_eq!(sector_of(None, &[]), None);
}

#[test]
fn a_sector_identifier_address_has_the_form_of_an_address_hodor_calls() {
    check_sector_identifier_uri("https://sector.example.org/uris.json").expect("good");
    for bad in [
        "",
        "ftp://sector.example.org/",
        "https://user:pass@sector.example.org/",
        "https://sector.example.org/#fragment",
        "https://sector.example.org/a b",
        "https:///uris.json",
    ] {
        let error = check_sector_identifier_uri(bad).expect_err(bad);
        assert_eq!(
            error.code(),
            "oauth.client_sector_identifier_uri_invalid",
            "{bad}"
        );
    }
    let long = format!("https://sector.example.org/{}", "a".repeat(2000));
    assert!(check_sector_identifier_uri(&long).is_err());
}

#[test]
fn the_sector_document_lists_every_redirect_address() {
    let redirect = uris(&[
        "https://app.example.com/callback",
        "https://other.example.net/callback",
    ]);
    check_sector_document(
        br#"["https://other.example.net/callback", "https://app.example.com/callback", "https://more.example/"]"#,
        &redirect,
    )
    .expect("listed");
    let missing = check_sector_document(br#"["https://app.example.com/callback"]"#, &redirect)
        .expect_err("missing");
    assert_eq!(
        missing.code(),
        "oauth.client_sector_identifier_uri_mismatch"
    );
    // Compared character for character.
    let changed = check_sector_document(
        br#"["https://app.example.com/callback/", "https://other.example.net/callback"]"#,
        &redirect,
    )
    .expect_err("changed");
    assert_eq!(
        changed.code(),
        "oauth.client_sector_identifier_uri_mismatch"
    );
    for document in [
        &b"{}"[..],
        b"[1, 2]",
        b"not json",
        b"\"https://app.example.com/callback\"",
    ] {
        let error = check_sector_document(document, &redirect).expect_err("not an array");
        assert_eq!(
            error.code(),
            "oauth.client_sector_identifier_uri_document_invalid"
        );
    }
}

#[test]
fn a_subject_type_is_public_or_pairwise() {
    assert_eq!(SubjectType::default(), SubjectType::Public);
    for kind in [SubjectType::Public, SubjectType::Pairwise] {
        assert_eq!(SubjectType::parse(kind.as_str()).expect("parse"), kind);
    }
    let error = SubjectType::parse("PAIRWISE").expect_err("unknown");
    assert_eq!(error.code(), "oauth.client_subject_type_invalid");
}
