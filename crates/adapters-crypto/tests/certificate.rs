//! Checking forwarded certificates against a bundle's authorities, with
//! certificates made for the test.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "An identity
//! forwarded by a proxy".

use hodor_adapters_crypto::X509CertificateCheck;
use hodor_adapters_crypto::testing::certificates::{Leaf, TestAuthority, not_an_authority_element};
use hodor_oauth::api::{CertificateCheck, CertificateNames};
use serde_json::Value;
use time::{Duration, OffsetDateTime};

const WEB: &str = "spiffe://cluster.local/ns/shop/sa/web";

fn chains(certificate: &[u8], chain: &[Vec<u8>], elements: &[Value]) -> bool {
    let written: Vec<String> = elements.iter().map(Value::to_string).collect();
    let authorities: Vec<&str> = written.iter().map(String::as_str).collect();
    X509CertificateCheck.chains_to(
        certificate,
        chain,
        &authorities,
        &[],
        OffsetDateTime::now_utc(),
    )
}

#[test]
fn the_names_of_a_certificate_are_its_uris_and_dns_names() {
    let authority = TestAuthority::root("mesh");
    let leaf = authority.issue(&Leaf {
        uris: vec![WEB.to_owned(), "https://web.example".to_owned()],
        dns_names: vec!["web.shop.serviceaccount.identity.linkerd.cluster.local".to_owned()],
        ..Leaf::default()
    });
    assert_eq!(
        X509CertificateCheck.names(&leaf),
        Some(CertificateNames {
            uris: vec![WEB.to_owned(), "https://web.example".to_owned()],
            dns_names: vec!["web.shop.serviceaccount.identity.linkerd.cluster.local".to_owned()],
        })
    );
    assert_eq!(
        X509CertificateCheck.names(&authority.der()),
        Some(CertificateNames::default()),
        "a certificate without alternative names has none"
    );
    for unreadable in [Vec::new(), b"not a certificate".to_vec(), {
        let mut trailing = leaf.clone();
        trailing.push(0);
        trailing
    }] {
        assert_eq!(X509CertificateCheck.names(&unreadable), None);
    }
}

#[test]
fn a_certificate_signed_by_an_authority_of_the_bundle_chains_to_it() {
    let authority = TestAuthority::root("mesh");
    let leaf = authority.issue(&Leaf::uri(WEB));
    assert!(chains(&leaf, &[], &[authority.bundle_element()]));
    let other = TestAuthority::root("other");
    assert!(
        chains(
            &leaf,
            &[],
            &[other.bundle_element(), authority.bundle_element()]
        ),
        "any authority of the bundle"
    );
}

#[test]
fn a_path_goes_through_the_forwarded_chain_in_any_order() {
    let root = TestAuthority::root("root");
    let first = root.intermediate("first");
    let second = first.intermediate("second");
    let leaf = second.issue(&Leaf::uri(WEB));
    let element = [root.bundle_element()];
    assert!(chains(&leaf, &[second.der(), first.der()], &element));
    assert!(chains(&leaf, &[first.der(), second.der()], &element));
    assert!(
        !chains(&leaf, &[second.der()], &element),
        "a missing link breaks the path"
    );
    assert!(
        !chains(&leaf, &[], &element),
        "intermediates are never fetched"
    );
    assert!(
        chains(&leaf, &[], &[second.bundle_element()]),
        "an intermediate in the bundle is an authority of its own"
    );
}

#[test]
fn a_certificate_of_another_authority_does_not_chain() {
    let authority = TestAuthority::root("mesh");
    let stranger = TestAuthority::root("mesh");
    let leaf = stranger.issue(&Leaf::uri(WEB));
    assert!(!chains(&leaf, &[], &[authority.bundle_element()]));
    assert!(
        !chains(&leaf, &[stranger.der()], &[authority.bundle_element()]),
        "the stranger's own authority in the chain is no anchor"
    );
    assert!(!chains(&leaf, &[], &[]), "an empty bundle trusts nothing");
}

#[test]
fn an_element_that_is_not_an_authority_holding_its_key_trusts_nothing() {
    let authority = TestAuthority::root("mesh");
    let leaf = authority.issue(&Leaf::uri(WEB));
    let impostor = TestAuthority::root("impostor");
    assert!(
        !chains(&leaf, &[], &[authority.element_with_key_of(&impostor)]),
        "the certificate does not hold the element's key"
    );
    assert!(
        chains(
            &leaf,
            &[],
            &[
                authority.element_with_key_of(&impostor),
                not_an_authority_element("careless"),
                authority.bundle_element(),
            ]
        ),
        "such an element is passed over, and the rest of the bundle still trusts"
    );
    let workload = authority.issue(&Leaf::uri("spiffe://cluster.local/ns/shop/sa/api"));
    let element = serde_json::json!({
        "use": "x509-svid",
        "kty": "EC",
        "crv": "P-256",
        "x": "AAAA",
        "y": "AAAA",
        "x5c": [base64_of(&workload)],
    });
    assert!(
        !chains(&leaf, &[], &[element]),
        "a workload's certificate is no authority"
    );
    for unreadable in ["", "{}", "not json", r#"{"x5c":["!!"]}"#, r#"{"x5c":[]}"#] {
        assert!(
            !X509CertificateCheck.chains_to(
                &leaf,
                &[],
                &[unreadable],
                &[],
                OffsetDateTime::now_utc()
            ),
            "{unreadable}"
        );
    }
}

fn base64_of(der: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(der)
}

#[test]
fn a_certificate_out_of_its_time_does_not_chain() {
    let authority = TestAuthority::root("mesh");
    let expired = authority.issue(&Leaf {
        expired: true,
        ..Leaf::uri(WEB)
    });
    assert!(!chains(&expired, &[], &[authority.bundle_element()]));
    let leaf = authority.issue(&Leaf::uri(WEB));
    let element = authority.bundle_element().to_string();
    assert!(
        !X509CertificateCheck.chains_to(
            &leaf,
            &[],
            &[&element],
            &[],
            OffsetDateTime::now_utc() + Duration::days(365 * 3000),
        ),
        "checked at the time given"
    );
}

#[test]
fn a_workload_certificate_must_be_one_for_a_client() {
    let authority = TestAuthority::root("mesh");
    let element = [authority.bundle_element()];
    let is_authority = authority.issue(&Leaf {
        authority: true,
        ..Leaf::uri(WEB)
    });
    assert!(
        !chains(&is_authority, &[], &element),
        "an authority is not a workload"
    );
    let server_only = authority.issue(&Leaf {
        server_only: true,
        ..Leaf::uri(WEB)
    });
    assert!(
        !chains(&server_only, &[], &element),
        "its extended key usages leave out clientAuth"
    );
}

#[test]
fn too_long_a_chain_or_a_certificate_that_does_not_read_is_refused() {
    let authority = TestAuthority::root("mesh");
    let leaf = authority.issue(&Leaf::uri(WEB));
    let element = [authority.bundle_element()];
    let long: Vec<Vec<u8>> = (0..=hodor_oauth::api::MAX_FORWARDED_CHAIN)
        .map(|_| authority.der())
        .collect();
    assert!(!chains(&leaf, &long, &element));
    assert!(!chains(b"not a certificate", &[], &element));
}
