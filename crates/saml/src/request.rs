//! The request that sends a person to the identity provider.

use std::fmt::Write as _;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use time::OffsetDateTime;

use crate::names::{ASSERTION, HTTP_POST, PROTOCOL};
use crate::response::ServiceProvider;
use crate::text::{escape, instant};

/// Makes the identifier of a request from random bytes.
///
/// An identifier must start with a letter or an underscore; it is an
/// underscore and the bytes in hexadecimal.
#[must_use]
pub fn request_id(random: [u8; 20]) -> String {
    let mut id = String::with_capacity(41);
    id.push('_');
    for byte in random {
        let _ = write!(id, "{byte:02x}");
    }
    id
}

/// An `AuthnRequest`, sent with the HTTP-Redirect binding and not signed.
#[derive(Debug, Clone, Copy)]
pub struct AuthenticationRequest<'a> {
    /// The identifier, from [`request_id`]. The response must name it.
    pub id: &'a str,
    /// Hodor, for this identity provider.
    pub service_provider: &'a ServiceProvider,
    /// The identity provider's single sign-on address.
    pub single_sign_on_address: &'a str,
    /// When the request is made.
    pub issue_instant: OffsetDateTime,
}

impl AuthenticationRequest<'_> {
    /// The request as XML.
    #[must_use]
    pub fn xml(&self) -> String {
        format!(
            concat!(
                r#"<samlp:AuthnRequest xmlns:samlp="{protocol}" xmlns:saml="{assertion}""#,
                r#" ID="{id}" Version="2.0" IssueInstant="{instant}" Destination="{destination}""#,
                r#" AssertionConsumerServiceURL="{consumer}" ProtocolBinding="{binding}">"#,
                r#"<saml:Issuer>{issuer}</saml:Issuer>"#,
                r#"<samlp:NameIDPolicy AllowCreate="true"/>"#,
                r#"</samlp:AuthnRequest>"#
            ),
            protocol = PROTOCOL,
            assertion = ASSERTION,
            id = escape(self.id),
            instant = instant(self.issue_instant),
            destination = escape(self.single_sign_on_address),
            consumer = escape(self.service_provider.assertion_consumer_address()),
            binding = HTTP_POST,
            issuer = escape(self.service_provider.entity_id()),
        )
    }

    /// The address the person is sent to: the single sign-on address with the
    /// request, compressed and encoded as the HTTP-Redirect binding says, and
    /// the relay state, which is an opaque reference to the sign-in.
    #[must_use]
    pub fn redirect_address(&self, relay_state: &str) -> String {
        let compressed = miniz_oxide::deflate::compress_to_vec(self.xml().as_bytes(), 6);
        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("SAMLRequest", &STANDARD.encode(compressed))
            .append_pair("RelayState", relay_state)
            .finish();
        let separator = if self.single_sign_on_address.contains('?') {
            '&'
        } else {
            '?'
        };
        format!("{}{separator}{query}", self.single_sign_on_address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service_provider() -> ServiceProvider {
        ServiceProvider::new(
            "https://hodor.example/metadata",
            "https://hodor.example/saml",
        )
    }

    #[test]
    fn identifiers_start_with_an_underscore() {
        let id = request_id([0xab; 20]);
        assert_eq!(id.len(), 41);
        assert!(id.starts_with("_abab"));
    }

    #[test]
    fn the_redirect_carries_the_compressed_request_and_the_state() {
        let service_provider = service_provider();
        let request = AuthenticationRequest {
            id: "_0123",
            service_provider: &service_provider,
            single_sign_on_address: "https://idp.example/sso",
            issue_instant: OffsetDateTime::UNIX_EPOCH,
        };
        let address = request.redirect_address("opaque-state");
        let (base, query) = address.split_once('?').expect("a query");
        assert_eq!(base, "https://idp.example/sso");
        let pairs: Vec<(String, String)> = form_urlencoded::parse(query.as_bytes())
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
        assert_eq!(pairs[0].0, "SAMLRequest");
        assert_eq!(
            pairs[1],
            ("RelayState".to_owned(), "opaque-state".to_owned())
        );
        let compressed = STANDARD.decode(&pairs[0].1).expect("base64");
        let xml = miniz_oxide::inflate::decompress_to_vec(&compressed).expect("deflate");
        let xml = String::from_utf8(xml).expect("UTF-8");
        assert_eq!(xml, request.xml());
        assert!(xml.contains(r#"ID="_0123""#));
        assert!(xml.contains(r#"IssueInstant="1970-01-01T00:00:00Z""#));
        assert!(xml.contains(r#"AssertionConsumerServiceURL="https://hodor.example/saml""#));
        assert!(xml.contains("<saml:Issuer>https://hodor.example/metadata</saml:Issuer>"));
    }

    #[test]
    fn a_single_sign_on_address_with_a_query_keeps_it() {
        let service_provider = service_provider();
        let request = AuthenticationRequest {
            id: "_0123",
            service_provider: &service_provider,
            single_sign_on_address: "https://idp.example/sso?tenant=acme",
            issue_instant: OffsetDateTime::UNIX_EPOCH,
        };
        assert!(
            request
                .redirect_address("s")
                .starts_with("https://idp.example/sso?tenant=acme&SAMLRequest=")
        );
    }
}
