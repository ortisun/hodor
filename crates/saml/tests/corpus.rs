//! The SAML attack corpus, `docs/security/saml-attack-corpus.md`: one test
//! per case, named after it, each checking the reason of the refusal.
//!
//! Every case starts from the good response of the control tests at the top.
//! A change is made after signing unless the test says it signs after the
//! change.

#![allow(clippy::expect_used, reason = "tests")]

use std::sync::OnceLock;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hodor_saml::testing::{
    ResponseDraft, Signed, TestIdentityProvider, certificate_with_short_rsa_key, encode,
};
use hodor_saml::{
    Assertion, CertificateError, Expected, IdentityProviderKey, Reason, ServiceProvider,
    check_response,
};
use time::{Duration, OffsetDateTime};

const REQUEST: &str = "_request-0001";
const ISSUER: &str = "https://idp.example/saml";
const ASSERTION_ID: &str = "_assertion-9c2e";

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_795_000_000).expect("a valid instant")
}

fn service_provider() -> ServiceProvider {
    ServiceProvider::new(
        "https://hodor.example/t/acme/interaction/sign-in/providers/corp/saml/metadata",
        "https://hodor.example/t/acme/interaction/sign-in/providers/corp/saml",
    )
}

/// The identity provider Hodor trusts.
fn identity_provider() -> &'static TestIdentityProvider {
    static PROVIDER: OnceLock<TestIdentityProvider> = OnceLock::new();
    PROVIDER.get_or_init(|| TestIdentityProvider::rsa(ISSUER))
}

/// Somebody else, who claims to be the same identity provider.
fn impostor() -> &'static TestIdentityProvider {
    static PROVIDER: OnceLock<TestIdentityProvider> = OnceLock::new();
    PROVIDER.get_or_init(|| TestIdentityProvider::rsa(ISSUER))
}

fn good() -> ResponseDraft {
    ResponseDraft::good(&service_provider(), identity_provider(), REQUEST, now())
}

/// The good response signed on the response instead of the assertion.
fn good_signed_on_the_response() -> ResponseDraft {
    ResponseDraft {
        signed: Signed::Response,
        ..good()
    }
}

fn signed(draft: &ResponseDraft) -> String {
    identity_provider().respond(draft)
}

/// The draft written, changed by `change`, then signed.
fn signed_after(draft: &ResponseDraft, change: impl FnOnce(String) -> String) -> String {
    let provider = identity_provider();
    provider.sign(&change(draft.xml(provider.signature_algorithm())))
}

fn check_with(provider: &TestIdentityProvider, xml: &str) -> Result<Assertion, Reason> {
    let service_provider = service_provider();
    let key = provider.key();
    check_response(
        &encode(xml),
        &Expected {
            service_provider: &service_provider,
            issuer: ISSUER,
            key: &key,
            request_id: REQUEST,
            now: now(),
        },
    )
    .map_err(|refusal| refusal.reason())
}

fn check(xml: &str) -> Result<Assertion, Reason> {
    check_with(identity_provider(), xml)
}

#[track_caller]
fn refused(xml: &str) -> Reason {
    match check(xml) {
        Ok(assertion) => panic!("accepted, for {}", assertion.name_id()),
        Err(reason) => reason,
    }
}

/// Replaces the one occurrence of `from`, and fails if there is not exactly one.
#[track_caller]
fn replace_once(xml: &str, from: &str, to: &str) -> String {
    assert_eq!(
        xml.matches(from).count(),
        1,
        "expected `{from}` once in {xml}"
    );
    xml.replacen(from, to, 1)
}

/// The first element written from `start` to the end of `end`.
#[track_caller]
fn element(xml: &str, start: &str, end: &str) -> String {
    let from = xml.find(start).expect("the element starts");
    let to = from + xml[from..].find(end).expect("the element ends") + end.len();
    xml[from..to].to_owned()
}

fn assertion_of(xml: &str) -> String {
    element(xml, "<saml:Assertion ", "</saml:Assertion>")
}

fn signature_of(xml: &str) -> String {
    element(xml, "<ds:Signature ", "</ds:Signature>")
}

/// An unsigned assertion that names somebody else, with an identifier of its own.
fn forged_assertion() -> String {
    let forged = ResponseDraft {
        assertion_id: "_forged".to_owned(),
        name_id: "eve@example.com".to_owned(),
        signed: Signed::Nothing,
        ..good()
    };
    assertion_of(&signed(&forged))
}

/// Flips one bit of the base64 text between `start` and `end`.
#[track_caller]
fn flip_a_bit(xml: &str, start: &str, end: &str) -> String {
    let from = xml.find(start).expect("the value starts") + start.len();
    let to = from + xml[from..].find(end).expect("the value ends");
    let mut bytes = STANDARD.decode(&xml[from..to]).expect("base64");
    bytes[0] ^= 1;
    format!("{}{}{}", &xml[..from], STANDARD.encode(bytes), &xml[to..])
}

/// Inserts `content` right after the response's own issuer.
fn after_response_issuer(xml: &str, content: &str) -> String {
    let issuer = format!("<saml:Issuer>{ISSUER}</saml:Issuer>");
    let at = xml.find(&issuer).expect("the response's issuer") + issuer.len();
    format!("{}{content}{}", &xml[..at], &xml[at..])
}

// The good response, accepted. Without these the corpus proves nothing.

#[test]
fn good_response_signed_on_the_assertion_is_accepted() {
    let assertion = check(&signed(&good())).expect("accepted");
    assert_eq!(assertion.name_id(), "ana@example.com");
    assert_eq!(
        assertion.name_id_format(),
        Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
    );
    assert_eq!(assertion.session_index(), Some("_session-77"));
    assert_eq!(assertion.first_value("email"), Some("ana@example.com"));
    assert_eq!(assertion.first_value("name"), Some("Ana Lima"));
}

#[test]
fn good_response_signed_on_the_response_is_accepted() {
    let assertion = check(&signed(&good_signed_on_the_response())).expect("accepted");
    assert_eq!(assertion.name_id(), "ana@example.com");
}

#[test]
fn good_response_signed_with_an_elliptic_curve_key_is_accepted() {
    let provider = TestIdentityProvider::ecdsa(ISSUER);
    let draft = ResponseDraft::good(&service_provider(), &provider, REQUEST, now());
    let assertion = check_with(&provider, &provider.respond(&draft)).expect("accepted");
    assert_eq!(assertion.name_id(), "ana@example.com");
}

#[test]
fn good_response_with_a_declaration_and_wrapped_base64_is_accepted() {
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>{}"#,
        signed(&good())
    );
    let encoded = encode(&xml);
    let wrapped: Vec<&str> = encoded
        .as_bytes()
        .chunks(76)
        .map(|line| std::str::from_utf8(line).expect("base64 is ASCII"))
        .collect();
    let service_provider = service_provider();
    let key = identity_provider().key();
    let assertion = check_response(
        &wrapped.join("\r\n"),
        &Expected {
            service_provider: &service_provider,
            issuer: ISSUER,
            key: &key,
            request_id: REQUEST,
            now: now(),
        },
    )
    .expect("accepted");
    assert_eq!(assertion.name_id(), "ana@example.com");
}

#[test]
fn good_response_within_the_clock_tolerance_is_accepted() {
    let draft = ResponseDraft {
        not_before: Some(now() + Duration::seconds(50)),
        not_on_or_after: Some(now() - Duration::seconds(50)),
        confirmation_not_on_or_after: now() - Duration::seconds(50),
        ..good()
    };
    assert!(check(&signed(&draft)).is_ok());
}

// Signature wrapping and parser differentials.

#[test]
fn wrapping_assertion_sibling() {
    let xml = signed(&good());
    let assertion = assertion_of(&xml);
    let xml = replace_once(
        &xml,
        &assertion,
        &format!("{assertion}{}", forged_assertion()),
    );
    assert_eq!(refused(&xml), Reason::Wrapping);
}

#[test]
fn wrapping_assertion_before() {
    let xml = signed(&good());
    let assertion = assertion_of(&xml);
    let xml = replace_once(
        &xml,
        &assertion,
        &format!("{}{assertion}", forged_assertion()),
    );
    assert_eq!(refused(&xml), Reason::Wrapping);
}

#[test]
fn wrapping_in_extensions() {
    let xml = signed(&good());
    let assertion = assertion_of(&xml);
    let xml = replace_once(&xml, &assertion, &forged_assertion());
    let xml = after_response_issuer(
        &xml,
        &format!("<samlp:Extensions>{assertion}</samlp:Extensions>"),
    );
    assert_eq!(refused(&xml), Reason::Wrapping);
}

#[test]
fn wrapping_in_object() {
    let xml = signed(&good_signed_on_the_response());
    let assertion = assertion_of(&xml);
    let xml = replace_once(&xml, &assertion, &forged_assertion());
    let xml = replace_once(
        &xml,
        "</ds:Signature>",
        &format!("<ds:Object>{assertion}</ds:Object></ds:Signature>"),
    );
    assert_eq!(refused(&xml), Reason::Wrapping);
}

#[test]
fn wrapping_response_signature() {
    let xml = signed(&good_signed_on_the_response());
    let assertion = assertion_of(&xml);
    let xml = replace_once(&xml, &assertion, &forged_assertion());
    let xml = replace_once(
        &xml,
        "</samlp:Response>",
        &format!("<samlp:Extensions>{assertion}</samlp:Extensions></samlp:Response>"),
    );
    assert_eq!(refused(&xml), Reason::Wrapping);
}

#[test]
fn two_signatures() {
    let xml = signed(&good());
    let signature = signature_of(&xml);
    let xml = replace_once(&xml, &signature, &format!("{signature}{signature}"));
    assert_eq!(refused(&xml), Reason::Wrapping);
}

#[test]
fn duplicate_id() {
    let xml = signed(&good());
    let xml = after_response_issuer(
        &xml,
        &format!(
            r#"<samlp:Extensions><x:Decoy xmlns:x="urn:decoy" ID="{ASSERTION_ID}"/></samlp:Extensions>"#
        ),
    );
    assert_eq!(refused(&xml), Reason::DuplicateIdentifier);
}

#[test]
fn id_attribute_case() {
    let xml = signed(&good());
    let xml = replace_once(
        &xml,
        &format!(r#"<saml:Assertion ID="{ASSERTION_ID}""#),
        &format!(r#"<saml:Assertion id="{ASSERTION_ID}""#),
    );
    assert_eq!(refused(&xml), Reason::Reference);
}

#[test]
fn reference_empty_uri() {
    let xml = signed(&good());
    let xml = replace_once(&xml, &format!(r##"URI="#{ASSERTION_ID}""##), r#"URI="""#);
    assert_eq!(refused(&xml), Reason::Reference);
}

#[test]
fn reference_xpointer() {
    let xml = signed(&good());
    let xml = replace_once(
        &xml,
        &format!(r##"URI="#{ASSERTION_ID}""##),
        &format!(r##"URI="#xpointer(id('{ASSERTION_ID}'))""##),
    );
    assert_eq!(refused(&xml), Reason::Reference);
}

#[test]
fn two_references() {
    let xml = signed(&good());
    let reference = element(&xml, "<ds:Reference ", "</ds:Reference>");
    let xml = replace_once(&xml, &reference, &format!("{reference}{reference}"));
    assert_eq!(refused(&xml), Reason::Reference);
}

#[test]
fn namespace_redefinition() {
    let xml = signed_after(&good(), |xml| {
        replace_once(
            &xml,
            "<saml:Subject>",
            r#"<saml:Subject xmlns:saml="urn:not-saml">"#,
        )
    });
    assert_eq!(refused(&xml), Reason::Structure);
}

#[test]
fn comment_in_name_id() {
    let xml = signed_after(&good(), |xml| {
        replace_once(
            &xml,
            ">ana@example.com</saml:NameID>",
            ">ana@example.com<!---->.evil.example</saml:NameID>",
        )
    });
    assert_eq!(refused(&xml), Reason::Comment);
}

#[test]
fn entity_in_name_id() {
    // Not refused: a character reference is the same text to the signature
    // and to what is read, because both read the one parsed tree.
    let xml = signed(&good());
    let xml = replace_once(
        &xml,
        ">ana@example.com</saml:NameID>",
        ">ana&#64;example.com</saml:NameID>",
    );
    let assertion = check(&xml).expect("accepted");
    assert_eq!(assertion.name_id(), "ana@example.com");
}

#[test]
fn doctype() {
    let xml = format!("<!DOCTYPE samlp:Response>{}", signed(&good()));
    assert_eq!(refused(&xml), Reason::DocumentType);
}

#[test]
fn external_entity() {
    let xml = signed(&good());
    let xml = replace_once(
        &xml,
        ">ana@example.com</saml:NameID>",
        ">&leak;</saml:NameID>",
    );
    let xml =
        format!(r#"<!DOCTYPE samlp:Response [<!ENTITY leak SYSTEM "file:///etc/passwd">]>{xml}"#);
    assert_eq!(refused(&xml), Reason::DocumentType);
}

#[test]
fn entity_expansion() {
    let mut declarations = String::from(r#"<!ENTITY a0 "laugh">"#);
    for level in 1..10 {
        let previous = format!("&a{};", level - 1).repeat(10);
        declarations.push_str(&format!(r#"<!ENTITY a{level} "{previous}">"#));
    }
    let xml = signed(&good());
    let xml = replace_once(
        &xml,
        ">ana@example.com</saml:NameID>",
        ">&a9;</saml:NameID>",
    );
    let xml = format!("<!DOCTYPE samlp:Response [{declarations}]>{xml}");
    assert_eq!(refused(&xml), Reason::DocumentType);
}

#[test]
fn processing_instruction() {
    let xml = signed(&good());
    let xml = replace_once(&xml, "<saml:Subject>", "<?evil data?><saml:Subject>");
    assert_eq!(refused(&xml), Reason::ProcessingInstruction);
}

#[test]
fn oversized() {
    let xml = signed(&good());
    // Larger than the limit once decoded, and still small enough to post.
    let padding = "a".repeat(257 * 1024);
    let larger = after_response_issuer(
        &xml,
        &format!("<samlp:Extensions>{padding}</samlp:Extensions>"),
    );
    assert_eq!(refused(&larger), Reason::Size);
    // So large that it is refused before it is decoded.
    let padding = "a".repeat(400 * 1024);
    let much_larger = after_response_issuer(
        &xml,
        &format!("<samlp:Extensions>{padding}</samlp:Extensions>"),
    );
    assert_eq!(refused(&much_larger), Reason::Size);
}

#[test]
fn deeply_nested() {
    let xml = signed(&good());
    let nested = format!(
        "{}{}",
        r#"<x:e xmlns:x="urn:deep">"#.repeat(1000),
        "</x:e>".repeat(1000)
    );
    let xml = after_response_issuer(
        &xml,
        &format!("<samlp:Extensions>{nested}</samlp:Extensions>"),
    );
    assert_eq!(refused(&xml), Reason::Depth);
}

#[test]
fn namespace_flood() {
    // Parsing work grows with elements times prefixes in scope: within the
    // size limit this cost seconds before the limit on prefixes.
    let xml = signed(&good());
    let mut opening = String::new();
    for level in 0..20 {
        opening.push_str(&format!(
            r#"<x:e xmlns:a{level}="urn:a" xmlns:b{level}="urn:b" xmlns:c{level}="urn:c" xmlns:x="urn:x">"#
        ));
    }
    let flood = format!("{opening}{}{}", "<x:a/>".repeat(2000), "</x:e>".repeat(20));
    let xml = after_response_issuer(
        &xml,
        &format!("<samlp:Extensions>{flood}</samlp:Extensions>"),
    );
    assert_eq!(refused(&xml), Reason::Size);
}

#[test]
fn node_flood() {
    let xml = signed(&good());
    let flood = r#"<x:a xmlns:x="urn:x"/>"#.repeat(10_000);
    let xml = after_response_issuer(
        &xml,
        &format!("<samlp:Extensions>{flood}</samlp:Extensions>"),
    );
    assert_eq!(refused(&xml), Reason::Size);
}

#[test]
fn percent_encoded_identifier() {
    // xml-sec decodes percent escapes in a reference: `#%5Fresponse-4f1d`
    // would name the response, while Hodor reads it as naming the assertion.
    let draft = ResponseDraft {
        assertion_id: "%5Fresponse-4f1d".to_owned(),
        ..good()
    };
    assert_eq!(refused(&signed(&draft)), Reason::Reference);
}

#[test]
fn id_in_another_namespace() {
    let xml = signed(&good());
    let xml = after_response_issuer(
        &xml,
        &format!(
            r#"<samlp:Extensions><x:Decoy xmlns:x="urn:decoy" x:ID="{ASSERTION_ID}"/></samlp:Extensions>"#
        ),
    );
    assert_eq!(refused(&xml), Reason::DuplicateIdentifier);
}

#[test]
fn not_base64() {
    let service_provider = service_provider();
    let key = identity_provider().key();
    let refusal = check_response(
        "%%% this is not base64 %%%",
        &Expected {
            service_provider: &service_provider,
            issuer: ISSUER,
            key: &key,
            request_id: REQUEST,
            now: now(),
        },
    )
    .expect_err("refused");
    assert_eq!(refusal.reason(), Reason::Malformed);
}

// Signatures that do not hold.

#[test]
fn unsigned() {
    let draft = ResponseDraft {
        signed: Signed::Nothing,
        ..good()
    };
    assert_eq!(refused(&signed(&draft)), Reason::Unsigned);
}

#[test]
fn signature_removed() {
    let xml = signed(&good());
    let xml = replace_once(&xml, &signature_of(&xml), "");
    assert_eq!(refused(&xml), Reason::Unsigned);
}

#[test]
fn signature_value_changed() {
    let xml = flip_a_bit(
        &signed(&good()),
        "<ds:SignatureValue>",
        "</ds:SignatureValue>",
    );
    assert_eq!(refused(&xml), Reason::Signature);
}

#[test]
fn digest_changed() {
    let xml = flip_a_bit(&signed(&good()), "<ds:DigestValue>", "</ds:DigestValue>");
    assert_eq!(refused(&xml), Reason::Signature);
}

#[test]
fn subject_changed() {
    let xml = replace_once(
        &signed(&good()),
        ">ana@example.com</saml:NameID>",
        ">eve@example.com</saml:NameID>",
    );
    assert_eq!(refused(&xml), Reason::Digest);
}

#[test]
fn attribute_added() {
    let xml = replace_once(
        &signed(&good()),
        "<saml:Assertion ID=",
        r#"<saml:Assertion Consent="urn:added" ID="#,
    );
    assert_eq!(refused(&xml), Reason::Digest);
}

#[test]
fn other_key() {
    let draft = ResponseDraft {
        key_info: false,
        ..good()
    };
    assert_eq!(refused(&impostor().respond(&draft)), Reason::Signature);
}

#[test]
fn key_in_message() {
    // The impostor's certificate travels in `KeyInfo`; it is never used.
    let xml = impostor().respond(&good());
    assert!(xml.contains("X509Certificate>MII"), "{xml}");
    assert_eq!(refused(&xml), Reason::Signature);
}

#[test]
fn sha1_digest() {
    let xml = replace_once(
        &signed(&good()),
        "http://www.w3.org/2001/04/xmlenc#sha256",
        "http://www.w3.org/2000/09/xmldsig#sha1",
    );
    assert_eq!(refused(&xml), Reason::Algorithm);
}

#[test]
fn sha1_signature() {
    let xml = replace_once(
        &signed(&good()),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    );
    assert_eq!(refused(&xml), Reason::Algorithm);
}

#[test]
fn hmac_signature() {
    let provider = identity_provider();
    let template = replace_once(
        &good().xml(provider.signature_algorithm()),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
    );
    let template = replace_once(&template, "<ds:KeyInfo/>", "");
    let xml = provider.sign_with_certificate_as_hmac_key(&template);
    assert_eq!(refused(&xml), Reason::Algorithm);
}

#[test]
fn algorithm_key_mismatch() {
    let xml = replace_once(
        &signed(&good()),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
    );
    assert_eq!(refused(&xml), Reason::Algorithm);
}

#[test]
fn unknown_transform() {
    let xml = replace_once(
        &signed(&good()),
        r#"<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
        r#"<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"/>"#,
    );
    assert_eq!(refused(&xml), Reason::Transform);
}

#[test]
fn xslt_transform() {
    let xml = replace_once(
        &signed(&good()),
        r#"<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
        concat!(
            r#"<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116">"#,
            r#"<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"/>"#,
            "</ds:Transform>"
        ),
    );
    assert_eq!(refused(&xml), Reason::Transform);
}

#[test]
fn short_rsa_key() {
    assert_eq!(
        IdentityProviderKey::from_certificate(&certificate_with_short_rsa_key()),
        Err(CertificateError::KeyTooShort)
    );
    assert_eq!(CertificateError::KeyTooShort.reason(), "key_too_short");
}

// Wrong place, wrong time, wrong request.

#[test]
fn audience_other() {
    let draft = ResponseDraft {
        audiences: vec!["https://another-service.example".to_owned()],
        ..good()
    };
    assert_eq!(refused(&signed(&draft)), Reason::Audience);
}

#[test]
fn audience_missing() {
    let draft = ResponseDraft {
        audiences: Vec::new(),
        ..good()
    };
    assert_eq!(refused(&signed(&draft)), Reason::Audience);
}

#[test]
fn destination_other() {
    let draft = ResponseDraft {
        destination: Some("https://another-service.example/saml".to_owned()),
        ..good()
    };
    assert_eq!(refused(&signed(&draft)), Reason::Destination);
}

#[test]
fn destination_missing() {
    let draft = ResponseDraft {
        destination: None,
        ..good()
    };
    assert_eq!(refused(&signed(&draft)), Reason::Destination);
}

#[test]
fn recipient_other() {
    let draft = ResponseDraft {
        recipient: "https://another-service.example/saml".to_owned(),
        ..good()
    };
    assert_eq!(refused(&signed(&draft)), Reason::Recipient);
}

#[test]
fn issuer_other() {
    let draft = ResponseDraft {
        issuer: "https://another-idp.example".to_owned(),
        response_issuer: Some("https://another-idp.example".to_owned()),
        ..good()
    };
    assert_eq!(refused(&signed(&draft)), Reason::Issuer);
}

#[test]
fn in_response_to_unknown() {
    let draft = ResponseDraft {
        in_response_to: Some("_never-asked".to_owned()),
        confirmation_in_response_to: Some("_never-asked".to_owned()),
        ..good()
    };
    assert_eq!(refused(&signed(&draft)), Reason::Request);
}

#[test]
fn unsolicited() {
    let draft = ResponseDraft {
        in_response_to: None,
        confirmation_in_response_to: None,
        ..good()
    };
    assert_eq!(refused(&signed(&draft)), Reason::Unsolicited);
}

#[test]
fn expired() {
    let draft = ResponseDraft {
        not_on_or_after: Some(now() - Duration::minutes(2)),
        ..good()
    };
    assert_eq!(refused(&signed(&draft)), Reason::Time);
}

#[test]
fn not_yet_valid() {
    let draft = ResponseDraft {
        not_before: Some(now() + Duration::minutes(2)),
        ..good()
    };
    assert_eq!(refused(&signed(&draft)), Reason::Time);
}

#[test]
fn confirmation_expired() {
    let draft = ResponseDraft {
        confirmation_not_on_or_after: now() - Duration::minutes(2),
        ..good()
    };
    assert_eq!(refused(&signed(&draft)), Reason::Time);
}

#[test]
fn status_not_success() {
    let draft = ResponseDraft {
        status: "urn:oasis:names:tc:SAML:2.0:status:Responder".to_owned(),
        ..good()
    };
    assert_eq!(refused(&signed(&draft)), Reason::Status);
}

#[test]
fn bearer_missing() {
    let draft = ResponseDraft {
        confirmation_method: "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches".to_owned(),
        ..good()
    };
    assert_eq!(refused(&signed(&draft)), Reason::Confirmation);
}

#[test]
fn transient_name_id() {
    let draft = ResponseDraft {
        name_id_format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:transient".to_owned()),
        ..good()
    };
    assert_eq!(refused(&signed(&draft)), Reason::Subject);
}

// Encrypted assertions.

#[test]
fn encrypted_assertion() {
    let xml = signed(&good());
    let xml = replace_once(
        &xml,
        &assertion_of(&xml),
        concat!(
            "<saml:EncryptedAssertion>",
            r#"<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/>"#,
            "</saml:EncryptedAssertion>"
        ),
    );
    assert_eq!(refused(&xml), Reason::Encrypted);
}
