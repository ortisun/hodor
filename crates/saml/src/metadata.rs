//! Hodor's metadata as a service provider.

use crate::names::{HTTP_POST, METADATA, PROTOCOL};
use crate::response::ServiceProvider;
use crate::text::escape;

/// The metadata an administrator gives the identity provider: Hodor's entity
/// identifier and where responses are posted.
///
/// It says nothing about which element must be signed. Identity providers that
/// read `WantAssertionsSigned` from metadata would then sign the response and
/// the assertion both, and Hodor accepts exactly one signature.
#[must_use]
pub fn metadata(service_provider: &ServiceProvider) -> String {
    format!(
        concat!(
            r#"<?xml version="1.0" encoding="UTF-8"?>"#,
            r#"<md:EntityDescriptor xmlns:md="{metadata}" entityID="{entity}">"#,
            r#"<md:SPSSODescriptor AuthnRequestsSigned="false" protocolSupportEnumeration="{protocol}">"#,
            r#"<md:AssertionConsumerService Binding="{binding}" Location="{location}" index="0" isDefault="true"/>"#,
            r#"</md:SPSSODescriptor>"#,
            r#"</md:EntityDescriptor>"#
        ),
        metadata = METADATA,
        entity = escape(service_provider.entity_id()),
        protocol = PROTOCOL,
        binding = HTTP_POST,
        location = escape(service_provider.assertion_consumer_address()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_names_the_entity_and_the_assertion_consumer() {
        let service_provider = ServiceProvider::new(
            "https://hodor.example/t/acme/interaction/sign-in/providers/corp/saml/metadata",
            "https://hodor.example/t/acme/interaction/sign-in/providers/corp/saml",
        );
        let written = metadata(&service_provider);
        assert!(written.contains(r#"entityID="https://hodor.example/t/acme/interaction/sign-in/providers/corp/saml/metadata""#));
        assert!(written.contains(
            r#"Location="https://hodor.example/t/acme/interaction/sign-in/providers/corp/saml""#
        ));
        assert!(written.contains(HTTP_POST));
        assert!(!written.contains("WantAssertionsSigned"));
    }
}
