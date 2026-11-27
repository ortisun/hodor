//! Identities a proxy in front of Hodor forwards, and the identities a
//! client is bound to so that one of them proves who it is.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "An identity
//! forwarded by a proxy", and Decision 0056.

use crate::domain::binding::CertificateThumbprint;
use crate::domain::client::AuthenticationMethod;
use crate::domain::spiffe::SpiffeId;
use hodor_kernel::{Digest, DomainError};
use hodor_keys::api::TrustDomainName;
use serde_json::Value;
use std::fmt;

/// The longest Linkerd identity: the longest DNS name.
pub const MAX_LINKERD_IDENTITY_LENGTH: usize = 253;
/// The largest forwarded certificate, in its DER encoding.
pub const MAX_FORWARDED_CERTIFICATE_BYTES: usize = 16 * 1024;
/// The most certificates a proxy may forward as a chain.
pub const MAX_FORWARDED_CHAIN: usize = 10;

const LINKERD_MARKER: &str = ".serviceaccount.identity.";

pub(crate) fn linkerd_identity_invalid(reason: &'static str) -> DomainError {
    DomainError::invalid(
        "oauth.client_linkerd_identity_invalid",
        "a client using `linkerd_identity`, or `tls_client_auth` without a SPIFFE identifier, is \
         bound to one Linkerd identity, \
         `<service account>.<namespace>.serviceaccount.identity.<control plane namespace>.<trust domain>`, \
         and acts as a service account; only such a client has one",
    )
    .with_detail(reason)
}

/// A Linkerd identity:
/// `<service account>.<namespace>.serviceaccount.identity.<control plane namespace>.<trust domain>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LinkerdIdentity {
    text: String,
    /// Where its trust domain begins in `text`.
    trust_domain_start: usize,
}

impl LinkerdIdentity {
    /// Reads a Linkerd identity: a DNS name in lowercase that holds
    /// `.serviceaccount.identity.`, as Linkerd names a workload.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_linkerd_identity_invalid`.
    pub fn parse(text: &str) -> Result<Self, DomainError> {
        let label_fits = |label: &str| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        };
        if text.is_empty()
            || text.len() > MAX_LINKERD_IDENTITY_LENGTH
            || !text.split('.').all(label_fits)
        {
            return Err(linkerd_identity_invalid(
                "a Linkerd identity is a DNS name of at most 253 characters in lowercase",
            ));
        }
        let shape = || {
            linkerd_identity_invalid(
                "a Linkerd identity is \
                 `<service account>.<namespace>.serviceaccount.identity.<control plane namespace>.<trust domain>`",
            )
        };
        let (workload, after) = text.split_once(LINKERD_MARKER).ok_or_else(shape)?;
        if !workload.contains('.') {
            return Err(shape());
        }
        let (_control_plane, trust_domain) = after.split_once('.').ok_or_else(shape)?;
        TrustDomainName::parse(trust_domain).map_err(|_| shape())?;
        Ok(Self {
            text: text.to_owned(),
            trust_domain_start: text.len() - trust_domain.len(),
        })
    }

    /// The identity, as it was given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The name of its trust domain: what follows the control plane's
    /// namespace.
    #[must_use]
    pub fn trust_domain(&self) -> &str {
        &self.text[self.trust_domain_start..]
    }
}

impl fmt::Display for LinkerdIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// The identity a client of a forwarded identity is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum WorkloadIdentity {
    /// A SPIFFE identifier, matched against a URI of the certificate.
    Spiffe(SpiffeId),
    /// A Linkerd identity, matched against a DNS name of the certificate
    /// or against `l5d-client-id`.
    Linkerd(LinkerdIdentity),
}

impl WorkloadIdentity {
    /// Reads an identity as a client's binding is read: a SPIFFE
    /// identifier when it starts with `spiffe://`, a Linkerd identity
    /// otherwise.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_spiffe_id_invalid` or
    /// `oauth.client_linkerd_identity_invalid`.
    pub fn parse(text: &str) -> Result<Self, DomainError> {
        if text.starts_with("spiffe://") {
            SpiffeId::parse(text).map(Self::Spiffe)
        } else {
            LinkerdIdentity::parse(text).map(Self::Linkerd)
        }
    }

    /// The name of the trust domain it belongs to.
    #[must_use]
    pub fn trust_domain(&self) -> &str {
        match self {
            Self::Spiffe(id) => id.trust_domain(),
            Self::Linkerd(id) => id.trust_domain(),
        }
    }

    /// The identity, as it was given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Spiffe(id) => id.as_str(),
            Self::Linkerd(id) => id.as_str(),
        }
    }

    /// The SPIFFE identifier, if it is one.
    #[must_use]
    pub const fn spiffe_id(&self) -> Option<&SpiffeId> {
        match self {
            Self::Spiffe(id) => Some(id),
            Self::Linkerd(_) => None,
        }
    }

    /// The Linkerd identity, if it is one.
    #[must_use]
    pub const fn linkerd_identity(&self) -> Option<&LinkerdIdentity> {
        match self {
            Self::Spiffe(_) => None,
            Self::Linkerd(id) => Some(id),
        }
    }
}

/// What a trusted proxy forwarded about the caller, read from the nearest
/// element of the one header the operator names.
#[derive(Clone, PartialEq, Eq)]
pub enum ForwardedIdentity {
    /// The certificate the caller presented, in DER, and the certificates
    /// the proxy gave as its chain, in DER, in the order given.
    Certificate {
        /// The caller's certificate.
        certificate: Vec<u8>,
        /// Certificates that may lead from it to an authority.
        chain: Vec<Vec<u8>>,
    },
    /// The names of the caller's certificate, without the certificate.
    Names {
        /// Its URIs.
        uris: Vec<String>,
        /// Its DNS names.
        dns_names: Vec<String>,
        /// Its thumbprint, when the proxy gave it: Envoy's `Hash`.
        hash: Option<CertificateThumbprint>,
    },
    /// The Linkerd identity Linkerd's proxy asserts.
    Linkerd(String),
}

impl fmt::Debug for ForwardedIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Certificate { certificate, chain } => f
                .debug_struct("Certificate")
                .field("bytes", &certificate.len())
                .field("chain", &chain.len())
                .finish(),
            Self::Names {
                uris,
                dns_names,
                hash,
            } => f
                .debug_struct("Names")
                .field("uris", uris)
                .field("dns_names", dns_names)
                .field("hash", hash)
                .finish(),
            Self::Linkerd(identity) => f.debug_tuple("Linkerd").field(identity).finish(),
        }
    }
}

impl ForwardedIdentity {
    /// The thumbprint of the certificate the request came with, which a
    /// bound token must name: the SHA-256 of a forwarded certificate, or
    /// the hash a proxy forwarded with the names alone. A Linkerd identity
    /// has none.
    #[must_use]
    pub fn thumbprint(&self, digest: &dyn Digest) -> Option<CertificateThumbprint> {
        match self {
            Self::Certificate { certificate, .. } => {
                Some(CertificateThumbprint::of_certificate(certificate, digest))
            }
            Self::Names { hash, .. } => *hash,
            Self::Linkerd(_) => None,
        }
    }
}

/// The thumbprint of the certificate a request came with, if a trusted
/// proxy forwarded one.
#[must_use]
pub fn presented_thumbprint(
    forwarded: Option<&ForwardedIdentity>,
    digest: &dyn Digest,
) -> Option<CertificateThumbprint> {
    forwarded.and_then(|identity| identity.thumbprint(digest))
}

/// The names of a certificate that a forwarded identity is matched by.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertificateNames {
    /// Its URIs, from its subject alternative names.
    pub uris: Vec<String>,
    /// Its DNS names, from its subject alternative names.
    pub dns_names: Vec<String>,
}

/// Whether the names of a forwarded certificate, or the names a proxy
/// forwarded, are those of a client of `method` bound to `identity`.
///
/// # Errors
///
/// The reason they are not, for Hodor's log.
pub fn names_match(
    method: AuthenticationMethod,
    identity: &WorkloadIdentity,
    names: &CertificateNames,
) -> Result<(), &'static str> {
    match (method, identity) {
        (AuthenticationMethod::SpiffeX509, WorkloadIdentity::Spiffe(id)) => {
            match names.uris.as_slice() {
                [only] if only == id.as_str() => Ok(()),
                [_] => Err("the certificate's SPIFFE identifier is not the client's"),
                _ => Err("an X509-SVID has exactly one URI"),
            }
        }
        (AuthenticationMethod::TlsClientAuth, WorkloadIdentity::Spiffe(id)) => {
            if names.uris.iter().any(|uri| uri == id.as_str()) {
                Ok(())
            } else {
                Err("no URI of the certificate is the client's SPIFFE identifier")
            }
        }
        (AuthenticationMethod::TlsClientAuth, WorkloadIdentity::Linkerd(id)) => {
            if names.dns_names.iter().any(|name| name == id.as_str()) {
                Ok(())
            } else {
                Err("no DNS name of the certificate is the client's Linkerd identity")
            }
        }
        _ => Err("the method does not take a certificate"),
    }
}

/// Adds `methods` to the methods of client authentication a discovery
/// document names for the token, revocation and introspection endpoints,
/// after the ones it names already. Only the methods an operator made
/// usable, by naming the header a proxy forwards them in, are added.
pub fn advertise_forwarded_methods(document: &mut Value, methods: &[AuthenticationMethod]) {
    for member in [
        "token_endpoint_auth_methods_supported",
        "revocation_endpoint_auth_methods_supported",
        "introspection_endpoint_auth_methods_supported",
    ] {
        if let Some(Value::Array(named)) = document.get_mut(member) {
            for method in methods
                .iter()
                .filter(|method| method.uses_forwarded_identity())
            {
                let name = Value::from(method.as_str());
                if !named.contains(&name) {
                    named.push(name);
                }
            }
        }
    }
}

/// Says in a discovery document that tokens are bound to certificates
/// when the client asks (RFC 8705, section 3.3): for an operator who named
/// a header that forwards them.
pub fn advertise_certificate_bound_tokens(document: &mut Value) {
    if let Value::Object(members) = document {
        members.insert(
            "tls_client_certificate_bound_access_tokens".to_owned(),
            Value::Bool(true),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarded_methods_are_advertised_after_the_others_at_each_endpoint() {
        let mut document = serde_json::json!({
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "none"],
            "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "none"],
            "introspection_endpoint_auth_methods_supported": ["client_secret_basic"],
        });
        advertise_forwarded_methods(
            &mut document,
            &[
                AuthenticationMethod::TlsClientAuth,
                AuthenticationMethod::SpiffeX509,
                AuthenticationMethod::None,
            ],
        );
        advertise_forwarded_methods(&mut document, &[AuthenticationMethod::SpiffeX509]);
        assert_eq!(
            document["token_endpoint_auth_methods_supported"],
            serde_json::json!([
                "client_secret_basic",
                "none",
                "tls_client_auth",
                "spiffe_x509"
            ])
        );
        assert_eq!(
            document["introspection_endpoint_auth_methods_supported"],
            serde_json::json!(["client_secret_basic", "tls_client_auth", "spiffe_x509"])
        );
    }

    #[test]
    fn certificate_bound_tokens_are_advertised_only_when_asked() {
        let mut document = serde_json::json!({ "issuer": "https://hodor.example/t/acme" });
        assert!(
            document
                .get("tls_client_certificate_bound_access_tokens")
                .is_none()
        );
        advertise_certificate_bound_tokens(&mut document);
        assert_eq!(
            document["tls_client_certificate_bound_access_tokens"],
            serde_json::json!(true)
        );
    }

    #[test]
    fn a_certificate_s_thumbprint_or_envoy_s_hash_is_what_binds_a_token() {
        use hodor_kernel::random::testing::FakeDigest;
        let certificate = ForwardedIdentity::Certificate {
            certificate: b"a certificate".to_vec(),
            chain: Vec::new(),
        };
        assert_eq!(
            certificate.thumbprint(&FakeDigest),
            Some(CertificateThumbprint::of_certificate(
                b"a certificate",
                &FakeDigest
            ))
        );
        let hash = CertificateThumbprint::from_bytes([3; 32]);
        let names = ForwardedIdentity::Names {
            uris: vec!["spiffe://td/web".to_owned()],
            dns_names: Vec::new(),
            hash: Some(hash),
        };
        assert_eq!(names.thumbprint(&FakeDigest), Some(hash));
        let bare = ForwardedIdentity::Names {
            uris: vec!["spiffe://td/web".to_owned()],
            dns_names: Vec::new(),
            hash: None,
        };
        assert_eq!(bare.thumbprint(&FakeDigest), None);
        let linkerd =
            ForwardedIdentity::Linkerd("web.shop.serviceaccount.identity.l.td".to_owned());
        assert_eq!(linkerd.thumbprint(&FakeDigest), None);
        assert_eq!(presented_thumbprint(None, &FakeDigest), None);
        assert_eq!(presented_thumbprint(Some(&names), &FakeDigest), Some(hash));
    }

    #[test]
    fn linkerd_identities_name_their_trust_domain_after_the_control_plane() {
        let id = LinkerdIdentity::parse("web.shop.serviceaccount.identity.linkerd.cluster.local")
            .expect("an identity");
        assert_eq!(id.trust_domain(), "cluster.local");
        let other =
            LinkerdIdentity::parse("api.payments.serviceaccount.identity.mesh.prod.example")
                .expect("another control plane namespace");
        assert_eq!(other.trust_domain(), "prod.example");
        for refused in [
            "",
            "web.shop.serviceaccount.identity.linkerd",
            "shop.serviceaccount.identity.linkerd.cluster.local",
            "web.shop.serviceaccount.linkerd.cluster.local",
            "Web.shop.serviceaccount.identity.linkerd.cluster.local",
            "web..shop.serviceaccount.identity.linkerd.cluster.local",
            "-web.shop.serviceaccount.identity.linkerd.cluster.local",
            "web_1.shop.serviceaccount.identity.linkerd.cluster.local",
            "spiffe://cluster.local/ns/shop/sa/web",
        ] {
            assert!(LinkerdIdentity::parse(refused).is_err(), "{refused}");
        }
        let long = format!(
            "{}.shop.serviceaccount.identity.linkerd.cluster.local",
            [
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(63)
            ]
            .join(".")
        );
        assert!(LinkerdIdentity::parse(&long).is_err(), "longer than 253");
    }

    fn names(uris: &[&str], dns_names: &[&str]) -> CertificateNames {
        CertificateNames {
            uris: uris.iter().map(|&uri| uri.to_owned()).collect(),
            dns_names: dns_names.iter().map(|&name| name.to_owned()).collect(),
        }
    }

    #[test]
    fn an_x509_svid_has_exactly_the_clients_one_uri() {
        let id = WorkloadIdentity::Spiffe(SpiffeId::parse("spiffe://td/web").expect("id"));
        let method = AuthenticationMethod::SpiffeX509;
        assert!(names_match(method, &id, &names(&["spiffe://td/web"], &["web.local"])).is_ok());
        assert!(names_match(method, &id, &names(&["spiffe://td/api"], &[])).is_err());
        assert!(
            names_match(
                method,
                &id,
                &names(&["spiffe://td/web", "spiffe://td/api"], &[])
            )
            .is_err(),
            "two URIs make no X509-SVID"
        );
        assert!(names_match(method, &id, &names(&[], &[])).is_err());
    }

    #[test]
    fn tls_client_auth_matches_one_uri_or_one_dns_name() {
        let spiffe = WorkloadIdentity::Spiffe(SpiffeId::parse("spiffe://td/web").expect("id"));
        let linkerd = WorkloadIdentity::Linkerd(
            LinkerdIdentity::parse("web.shop.serviceaccount.identity.linkerd.td").expect("id"),
        );
        let method = AuthenticationMethod::TlsClientAuth;
        let both = names(
            &["https://other.example", "spiffe://td/web"],
            &["web.shop.serviceaccount.identity.linkerd.td"],
        );
        assert!(names_match(method, &spiffe, &both).is_ok());
        assert!(names_match(method, &linkerd, &both).is_ok());
        assert!(
            names_match(
                method,
                &linkerd,
                &names(&["web.shop.serviceaccount.identity.linkerd.td"], &[])
            )
            .is_err(),
            "a Linkerd identity is a DNS name, not a URI"
        );
        assert!(
            names_match(
                method,
                &spiffe,
                &names(&["spiffe://td/web/"], &["spiffe://td/web"])
            )
            .is_err(),
            "compared exactly, and a URI is never matched by a DNS name"
        );
        assert!(
            names_match(AuthenticationMethod::LinkerdIdentity, &linkerd, &both).is_err(),
            "linkerd_identity takes no certificate"
        );
    }
}
