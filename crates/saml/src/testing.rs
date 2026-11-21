//! An identity provider for tests: keys of its own, a certificate, and real
//! signed responses.
//!
//! Compiled only with the `testing` feature, which is also the only way
//! signing enters the build. Nothing here is used outside tests.

#![allow(
    clippy::expect_used,
    reason = "test support: a failure to make keys or sign is a broken test"
)]

use aws_lc_rs::encoding::AsDer as _;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use time::{Duration, OffsetDateTime};
use xml_sec::xmldsig::{
    EcdsaP256SigningKey, HmacSigningKey, RsaSigningKey, SignContext, SigningKey,
    X509CertificateKeyInfoWriter,
};

use crate::key::IdentityProviderKey;
use crate::names::{
    ASSERTION, BEARER, ECDSA_SHA256, ENVELOPED_SIGNATURE, EXCLUSIVE_CANONICALIZATION, PROTOCOL,
    RSA_SHA256, SHA256, SIGNATURE, SUCCESS,
};
use crate::response::ServiceProvider;
use crate::text::{escape, instant};

/// The public part of an RSA key of 1024 bits, its modulus and exponent,
/// with no private key anywhere. It exists to be refused.
const SHORT_RSA_PUBLIC_KEY: &str = "MIGJAoGBALrbe53MGvxtipHSLG0ztsJwJC3l9UAGLRRy2WiwtbUaYWJdaO9loHqrt7eA/FT9dK0fphbgC8pDus/EPtcXAbJxJer2RDzgHsaMpVG+qPhaChhpyDeF9GWVb33pywkVej2IG7koWpIZ6jc2RxoGNfa+3NQrFps32DU8SqKHPh9xAgMBAAE=";

/// A public key with no private key, for a certificate that names it.
struct PublicOnly(Vec<u8>);

impl rcgen::PublicKeyData for PublicOnly {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }

    fn algorithm(&self) -> &rcgen::SignatureAlgorithm {
        &rcgen::PKCS_RSA_SHA256
    }
}

/// The private key an identity provider signs with.
#[derive(Debug)]
enum PrivateKey {
    Rsa(Vec<u8>),
    EllipticCurve(Vec<u8>),
}

/// An identity provider with a key pair of its own and a self-signed
/// certificate for it.
#[derive(Debug)]
pub struct TestIdentityProvider {
    entity_id: String,
    private_key: PrivateKey,
    certificate_pem: String,
}

impl TestIdentityProvider {
    /// With an RSA key of 2048 bits.
    #[must_use]
    pub fn rsa(entity_id: &str) -> Self {
        let key = RsaKeyPair::generate(KeySize::Rsa2048).expect("an RSA key");
        let pkcs8 = key.as_der().expect("the key in PKCS #8").as_ref().to_vec();
        let certificate_pem = self_signed(&pkcs8, &rcgen::PKCS_RSA_SHA256);
        Self {
            entity_id: entity_id.to_owned(),
            private_key: PrivateKey::Rsa(pkcs8),
            certificate_pem,
        }
    }

    /// With an elliptic curve key on P-256.
    #[must_use]
    pub fn ecdsa(entity_id: &str) -> Self {
        let random = aws_lc_rs::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random)
            .expect("an elliptic curve key")
            .as_ref()
            .to_vec();
        let certificate_pem = self_signed(&pkcs8, &rcgen::PKCS_ECDSA_P256_SHA256);
        Self {
            entity_id: entity_id.to_owned(),
            private_key: PrivateKey::EllipticCurve(pkcs8),
            certificate_pem,
        }
    }

    /// The entity identifier, which is the `Issuer` of what it sends.
    #[must_use]
    pub fn entity_id(&self) -> &str {
        &self.entity_id
    }

    /// Its certificate, in PEM, as an administrator would copy it.
    #[must_use]
    pub fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }

    /// Its key, as Hodor reads it from the certificate.
    #[must_use]
    pub fn key(&self) -> IdentityProviderKey {
        IdentityProviderKey::from_certificate(&self.certificate_pem).expect("its own certificate")
    }

    /// The signature algorithm its key signs with.
    #[must_use]
    pub const fn signature_algorithm(&self) -> &'static str {
        match self.private_key {
            PrivateKey::Rsa(_) => RSA_SHA256,
            PrivateKey::EllipticCurve(_) => ECDSA_SHA256,
        }
    }

    /// Fills the signature template in `xml`: the digest, the signature value
    /// and, when the template has an empty `KeyInfo`, the certificate.
    #[must_use]
    pub fn sign(&self, xml: &str) -> String {
        let rsa;
        let elliptic;
        let key: &dyn SigningKey = match &self.private_key {
            PrivateKey::Rsa(pkcs8) => {
                rsa = RsaSigningKey::from_pkcs8_der(pkcs8).expect("the RSA key");
                &rsa
            }
            PrivateKey::EllipticCurve(pkcs8) => {
                elliptic = EcdsaP256SigningKey::from_pkcs8_der(pkcs8).expect("the curve key");
                &elliptic
            }
        };
        let writer =
            X509CertificateKeyInfoWriter::from_pem(&self.certificate_pem).expect("the certificate");
        let context = SignContext::new(key);
        let context = if xml.contains("<ds:KeyInfo/>") {
            context.key_info_writer(&writer)
        } else {
            context
        };
        context.sign_template(xml).expect("the template signs")
    }

    /// Fills the signature template in `xml` with an HMAC keyed with this
    /// identity provider's certificate, which anyone can read: the attack of
    /// the case `hmac-signature`. The template names `hmac-sha256`.
    #[must_use]
    pub fn sign_with_certificate_as_hmac_key(&self, xml: &str) -> String {
        let (_, pem) = x509_parser::pem::parse_x509_pem(self.certificate_pem.as_bytes())
            .expect("its own certificate");
        let key = HmacSigningKey::new(pem.contents).expect("an HMAC key");
        SignContext::new(&key)
            .sign_template(xml)
            .expect("the template signs")
    }

    /// The response a draft describes, signed as the draft says.
    #[must_use]
    pub fn respond(&self, draft: &ResponseDraft) -> String {
        let xml = draft.xml(self.signature_algorithm());
        match draft.signed {
            Signed::Nothing => xml,
            Signed::Assertion | Signed::Response => self.sign(&xml),
        }
    }
}

/// A certificate in PEM whose key is an RSA key of 1024 bits, signed by an
/// identity provider's key. Only for showing that such a key is refused.
#[must_use]
pub fn certificate_with_short_rsa_key() -> String {
    let issuer_key = RsaKeyPair::generate(KeySize::Rsa2048).expect("an RSA key");
    let issuer_pkcs8 = issuer_key.as_der().expect("the key in PKCS #8");
    let issuer_key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &issuer_pkcs8.as_ref().into(),
        &rcgen::PKCS_RSA_SHA256,
    )
    .expect("the issuer's key");
    let issuer = rcgen::CertificateParams::new(vec!["issuer.example".to_owned()])
        .expect("parameters")
        .self_signed(&issuer_key)
        .expect("the issuer's certificate");
    let short = STANDARD
        .decode(SHORT_RSA_PUBLIC_KEY)
        .expect("the short key");
    let short = PublicOnly(short);
    rcgen::CertificateParams::new(vec!["identity-provider.example".to_owned()])
        .expect("parameters")
        .signed_by(&short, &issuer, &issuer_key)
        .expect("the certificate")
        .pem()
}

/// Encodes a response as it is posted: base64.
#[must_use]
pub fn encode(xml: &str) -> String {
    STANDARD.encode(xml)
}

fn self_signed(pkcs8: &[u8], algorithm: &'static rcgen::SignatureAlgorithm) -> String {
    let key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8.into(), algorithm)
        .expect("the key for the certificate");
    rcgen::CertificateParams::new(vec!["identity-provider.example".to_owned()])
        .expect("parameters")
        .self_signed(&key)
        .expect("the certificate")
        .pem()
}

/// Which element carries the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signed {
    /// The assertion, as most identity providers do.
    Assertion,
    /// The response that contains it.
    Response,
    /// Neither.
    Nothing,
}

/// Everything a response says, to be changed by a test before it is written
/// and signed.
#[derive(Debug, Clone)]
#[allow(
    missing_docs,
    reason = "each field is the SAML element or attribute it is named after"
)]
pub struct ResponseDraft {
    pub response_id: String,
    pub assertion_id: String,
    pub issue_instant: OffsetDateTime,
    pub destination: Option<String>,
    pub in_response_to: Option<String>,
    pub response_issuer: Option<String>,
    pub status: String,
    pub issuer: String,
    pub name_id: String,
    pub name_id_format: Option<String>,
    pub confirmation_method: String,
    pub recipient: String,
    pub confirmation_in_response_to: Option<String>,
    pub confirmation_not_on_or_after: OffsetDateTime,
    pub not_before: Option<OffsetDateTime>,
    pub not_on_or_after: Option<OffsetDateTime>,
    pub audiences: Vec<String>,
    pub session_index: Option<String>,
    pub attributes: Vec<(String, Vec<String>)>,
    pub signed: Signed,
    pub key_info: bool,
}

impl ResponseDraft {
    /// What a well-behaved identity provider sends to this service provider
    /// for this request, now: the assertion signed, every check satisfied.
    #[must_use]
    pub fn good(
        service_provider: &ServiceProvider,
        identity_provider: &TestIdentityProvider,
        request_id: &str,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            response_id: "_response-4f1d".to_owned(),
            assertion_id: "_assertion-9c2e".to_owned(),
            issue_instant: now,
            destination: Some(service_provider.assertion_consumer_address().to_owned()),
            in_response_to: Some(request_id.to_owned()),
            response_issuer: Some(identity_provider.entity_id().to_owned()),
            status: SUCCESS.to_owned(),
            issuer: identity_provider.entity_id().to_owned(),
            name_id: "ana@example.com".to_owned(),
            name_id_format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".to_owned()),
            confirmation_method: BEARER.to_owned(),
            recipient: service_provider.assertion_consumer_address().to_owned(),
            confirmation_in_response_to: Some(request_id.to_owned()),
            confirmation_not_on_or_after: now + Duration::minutes(5),
            not_before: Some(now - Duration::seconds(30)),
            not_on_or_after: Some(now + Duration::minutes(5)),
            audiences: vec![service_provider.entity_id().to_owned()],
            session_index: Some("_session-77".to_owned()),
            attributes: vec![
                ("email".to_owned(), vec!["ana@example.com".to_owned()]),
                ("name".to_owned(), vec!["Ana Lima".to_owned()]),
            ],
            signed: Signed::Assertion,
            key_info: true,
        }
    }

    /// The response as XML, with an empty signature template where the
    /// draft says it is signed.
    #[must_use]
    pub fn xml(&self, signature_algorithm: &str) -> String {
        let template = |id: &str| signature_template(id, signature_algorithm, self.key_info);
        let mut xml = String::new();
        xml.push_str(&format!(
            r#"<samlp:Response xmlns:samlp="{PROTOCOL}" xmlns:saml="{ASSERTION}" ID="{}" Version="2.0" IssueInstant="{}""#,
            escape(&self.response_id),
            instant(self.issue_instant)
        ));
        if let Some(destination) = &self.destination {
            xml.push_str(&format!(r#" Destination="{}""#, escape(destination)));
        }
        if let Some(request) = &self.in_response_to {
            xml.push_str(&format!(r#" InResponseTo="{}""#, escape(request)));
        }
        xml.push('>');
        if let Some(issuer) = &self.response_issuer {
            xml.push_str(&format!("<saml:Issuer>{}</saml:Issuer>", escape(issuer)));
        }
        if self.signed == Signed::Response {
            xml.push_str(&template(&self.response_id));
        }
        xml.push_str(&format!(
            r#"<samlp:Status><samlp:StatusCode Value="{}"/></samlp:Status>"#,
            escape(&self.status)
        ));
        xml.push_str(&self.assertion_xml(&template));
        xml.push_str("</samlp:Response>");
        xml
    }

    fn assertion_xml(&self, template: &dyn Fn(&str) -> String) -> String {
        let mut xml = format!(
            r#"<saml:Assertion ID="{}" Version="2.0" IssueInstant="{}">"#,
            escape(&self.assertion_id),
            instant(self.issue_instant)
        );
        xml.push_str(&format!(
            "<saml:Issuer>{}</saml:Issuer>",
            escape(&self.issuer)
        ));
        if self.signed == Signed::Assertion {
            xml.push_str(&template(&self.assertion_id));
        }
        xml.push_str("<saml:Subject><saml:NameID");
        if let Some(format) = &self.name_id_format {
            xml.push_str(&format!(r#" Format="{}""#, escape(format)));
        }
        xml.push_str(&format!(">{}</saml:NameID>", escape(&self.name_id)));
        xml.push_str(&format!(
            r#"<saml:SubjectConfirmation Method="{}"><saml:SubjectConfirmationData"#,
            escape(&self.confirmation_method)
        ));
        if let Some(request) = &self.confirmation_in_response_to {
            xml.push_str(&format!(r#" InResponseTo="{}""#, escape(request)));
        }
        xml.push_str(&format!(
            r#" NotOnOrAfter="{}" Recipient="{}"/></saml:SubjectConfirmation></saml:Subject>"#,
            instant(self.confirmation_not_on_or_after),
            escape(&self.recipient)
        ));
        xml.push_str("<saml:Conditions");
        if let Some(not_before) = self.not_before {
            xml.push_str(&format!(r#" NotBefore="{}""#, instant(not_before)));
        }
        if let Some(not_on_or_after) = self.not_on_or_after {
            xml.push_str(&format!(r#" NotOnOrAfter="{}""#, instant(not_on_or_after)));
        }
        xml.push('>');
        if !self.audiences.is_empty() {
            xml.push_str("<saml:AudienceRestriction>");
            for audience in &self.audiences {
                xml.push_str(&format!(
                    "<saml:Audience>{}</saml:Audience>",
                    escape(audience)
                ));
            }
            xml.push_str("</saml:AudienceRestriction>");
        }
        xml.push_str("</saml:Conditions>");
        xml.push_str(&format!(
            r#"<saml:AuthnStatement AuthnInstant="{}""#,
            instant(self.issue_instant)
        ));
        if let Some(index) = &self.session_index {
            xml.push_str(&format!(r#" SessionIndex="{}""#, escape(index)));
        }
        xml.push_str(concat!(
            "><saml:AuthnContext><saml:AuthnContextClassRef>",
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
            "</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>"
        ));
        if !self.attributes.is_empty() {
            xml.push_str("<saml:AttributeStatement>");
            for (name, values) in &self.attributes {
                xml.push_str(&format!(r#"<saml:Attribute Name="{}">"#, escape(name)));
                for value in values {
                    xml.push_str(&format!(
                        "<saml:AttributeValue>{}</saml:AttributeValue>",
                        escape(value)
                    ));
                }
                xml.push_str("</saml:Attribute>");
            }
            xml.push_str("</saml:AttributeStatement>");
        }
        xml.push_str("</saml:Assertion>");
        xml
    }
}

/// An empty enveloped signature of the element with this identifier.
#[must_use]
pub fn signature_template(id: &str, signature_algorithm: &str, key_info: bool) -> String {
    format!(
        concat!(
            r#"<ds:Signature xmlns:ds="{signature}"><ds:SignedInfo>"#,
            r#"<ds:CanonicalizationMethod Algorithm="{exclusive}"/>"#,
            r#"<ds:SignatureMethod Algorithm="{algorithm}"/>"#,
            r##"<ds:Reference URI="#{id}"><ds:Transforms>"##,
            r#"<ds:Transform Algorithm="{enveloped}"/>"#,
            r#"<ds:Transform Algorithm="{exclusive}"/>"#,
            r#"</ds:Transforms><ds:DigestMethod Algorithm="{digest}"/><ds:DigestValue/>"#,
            r#"</ds:Reference></ds:SignedInfo><ds:SignatureValue/>{key_info}</ds:Signature>"#
        ),
        signature = SIGNATURE,
        exclusive = EXCLUSIVE_CANONICALIZATION,
        algorithm = signature_algorithm,
        id = escape(id),
        enveloped = ENVELOPED_SIGNATURE,
        digest = SHA256,
        key_info = if key_info { "<ds:KeyInfo/>" } else { "" },
    )
}
