//! Responses shaped as the identity providers of the recipes send them, which
//! must be accepted.
//!
//! None of these is a real response: no real one has been had yet. Each is
//! built here to the shape its identity provider is documented and known to
//! send, which element is signed, the namespace prefixes or a default
//! namespace, the list of namespaces exclusive canonicalization keeps, typed
//! attribute values, line breaks and indentation, and signed by the test with
//! a key it holds. See `docs/security/saml-attack-corpus.md`.

#![allow(clippy::expect_used, reason = "tests")]

use hodor_saml::testing::{ResponseDraft, Signed, TestIdentityProvider, encode};
use hodor_saml::{Assertion, Expected, ServiceProvider, check_response};
use time::OffsetDateTime;

const REQUEST: &str = "_request-0001";

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_795_000_000).expect("a valid instant")
}

fn service_provider() -> ServiceProvider {
    ServiceProvider::new(
        "https://hodor.example/t/acme/interaction/sign-in/providers/corp/saml/metadata",
        "https://hodor.example/t/acme/interaction/sign-in/providers/corp/saml",
    )
}

fn check(provider: &TestIdentityProvider, posted: &str) -> Assertion {
    let service_provider = service_provider();
    let key = provider.key();
    check_response(
        posted,
        &Expected {
            service_provider: &service_provider,
            issuer: provider.entity_id(),
            key: &key,
            request_id: REQUEST,
            now: now(),
        },
    )
    .expect("accepted")
}

fn draft(provider: &TestIdentityProvider, attributes: &[(&str, &str)]) -> ResponseDraft {
    ResponseDraft {
        attributes: attributes
            .iter()
            .map(|(name, value)| ((*name).to_owned(), vec![(*value).to_owned()]))
            .collect(),
        ..ResponseDraft::good(&service_provider(), provider, REQUEST, now())
    }
}

/// The assertion written with a default namespace and no prefix, as Microsoft
/// writes it.
fn assertion_in_default_namespace(xml: &str) -> String {
    let start = xml.find("<saml:Assertion ").expect("the assertion");
    let end = xml.find("</saml:Assertion>").expect("its end") + "</saml:Assertion>".len();
    let assertion = xml[start..end]
        .replace("<saml:", "<")
        .replace("</saml:", "</")
        .replacen(
            "<Assertion ",
            r#"<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" "#,
            1,
        );
    format!("{}{assertion}{}", &xml[..start], &xml[end..])
}

/// Every prefix renamed, as the libraries of some identity providers write them.
fn prefixes(xml: &str, protocol: &str, assertion: &str, signature: &str) -> String {
    xml.replace("samlp:", &format!("{protocol}:"))
        .replace("xmlns:samlp=", &format!("xmlns:{protocol}="))
        .replace("saml:", &format!("{assertion}:"))
        .replace("xmlns:saml=", &format!("xmlns:{assertion}="))
        .replace("ds:", &format!("{signature}:"))
        .replace("xmlns:ds=", &format!("xmlns:{signature}="))
}

/// A line break and indentation between every two tags.
fn indented(xml: &str) -> String {
    xml.replace("><", ">\n    <")
}

#[test]
fn microsoft_entra_id() {
    let provider =
        TestIdentityProvider::rsa("https://sts.windows.net/8d6a2b6e-1c4e-4c39-9f31-3c1d0a9e7f10/");
    let draft = draft(
        &provider,
        &[
            (
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                "ana@example.com",
            ),
            (
                "http://schemas.microsoft.com/identity/claims/displayname",
                "Ana Lima",
            ),
        ],
    );
    let template = assertion_in_default_namespace(&draft.xml(provider.signature_algorithm()));
    let assertion = check(&provider, &encode(&provider.sign(&template)));
    assert_eq!(assertion.name_id(), "ana@example.com");
    assert_eq!(
        assertion.first_value("http://schemas.microsoft.com/identity/claims/displayname"),
        Some("Ana Lima")
    );
}

#[test]
fn okta() {
    let provider = TestIdentityProvider::rsa("http://www.okta.com/exk1a2b3c4d5e6f7g8h9");
    let draft = draft(
        &provider,
        &[("email", "ana@example.com"), ("name", "Ana Lima")],
    );
    let template = prefixes(&draft.xml(provider.signature_algorithm()), "saml2p", "saml2", "ds")
        .replace(
            r#"<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
            concat!(
                r#"<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">"#,
                r#"<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs"/>"#,
                "</ds:Transform>"
            ),
        )
        .replace(
            "<saml2:AttributeValue>",
            concat!(
                r#"<saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema""#,
                r#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">"#
            ),
        );
    let assertion = check(&provider, &encode(&provider.sign(&template)));
    assert_eq!(assertion.first_value("email"), Some("ana@example.com"));
}

#[test]
fn active_directory_federation_services() {
    let provider = TestIdentityProvider::rsa("http://adfs.example.com/adfs/services/trust");
    let draft = draft(
        &provider,
        &[
            (
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                "ana@example.com",
            ),
            (
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
                "Ana Lima",
            ),
        ],
    );
    let template = assertion_in_default_namespace(&draft.xml(provider.signature_algorithm()));
    let assertion = check(&provider, &encode(&provider.sign(&template)));
    assert_eq!(
        assertion.first_value("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"),
        Some("Ana Lima")
    );
}

#[test]
fn keycloak() {
    let provider = TestIdentityProvider::rsa("https://keycloak.example.com/realms/acme");
    let draft = ResponseDraft {
        signed: Signed::Response,
        ..draft(
            &provider,
            &[("email", "ana@example.com"), ("name", "Ana Lima")],
        )
    };
    let template = prefixes(
        &draft.xml(provider.signature_algorithm()),
        "samlp",
        "saml",
        "dsig",
    );
    let assertion = check(&provider, &encode(&provider.sign(&template)));
    assert_eq!(assertion.first_value("name"), Some("Ana Lima"));
}

#[test]
fn shibboleth() {
    let provider = TestIdentityProvider::rsa("https://idp.example.edu/idp/shibboleth");
    let draft = ResponseDraft {
        signed: Signed::Response,
        ..draft(
            &provider,
            &[
                ("urn:oid:0.9.2342.19200300.100.1.3", "ana@example.edu"),
                ("urn:oid:2.16.840.1.113730.3.1.241", "Ana Lima"),
            ],
        )
    };
    let template = indented(&prefixes(
        &draft.xml(provider.signature_algorithm()),
        "saml2p",
        "saml2",
        "ds",
    ));
    let signed = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
        provider.sign(&template)
    );
    let encoded = encode(&signed);
    let wrapped: Vec<&str> = encoded
        .as_bytes()
        .chunks(76)
        .map(|line| std::str::from_utf8(line).expect("base64 is ASCII"))
        .collect();
    let assertion = check(&provider, &wrapped.join("\n"));
    assert_eq!(
        assertion.first_value("urn:oid:0.9.2342.19200300.100.1.3"),
        Some("ana@example.edu")
    );
}

#[test]
fn rsa_pss_signature() {
    let provider = TestIdentityProvider::rsa("https://idp.example/saml");
    let draft = draft(&provider, &[("email", "ana@example.com")]);
    let template = draft.xml("http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1");
    let assertion = check(&provider, &encode(&provider.sign(&template)));
    assert_eq!(assertion.name_id(), "ana@example.com");
}
