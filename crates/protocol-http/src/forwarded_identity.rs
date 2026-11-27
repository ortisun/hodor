//! The caller's identity, as a trusted proxy forwards it.
//!
//! Specified in `docs/api/api-spec.md`, under "The caller's identity from
//! a proxy". The rules, in short:
//!
//! - only the one header the operator names is read, and none by default;
//! - only on a connection from a trusted proxy, the same proxies as for the
//!   client address;
//! - only its nearest element, the last, which the proxy Hodor is connected
//!   to wrote; nothing a caller wrote before it;
//! - what cannot be read is no identity.

use crate::client_address::split_outside;
use axum::http::{HeaderMap, HeaderName};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hodor_oauth::api::{
    AuthenticationMethod, CertificateThumbprint, ForwardedIdentity,
    MAX_FORWARDED_CERTIFICATE_BYTES, MAX_FORWARDED_CHAIN, MAX_LINKERD_IDENTITY_LENGTH,
};
use std::str::FromStr;

/// The header a trusted proxy writes the caller's identity into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityHeader {
    /// `Client-Cert` and `Client-Cert-Chain` (RFC 9440).
    ClientCert,
    /// `X-Forwarded-Client-Cert`, as Envoy writes it.
    XForwardedClientCert,
    /// `l5d-client-id`, as Linkerd's proxy writes it.
    LinkerdClientId,
}

const CLIENT_CERT: HeaderName = HeaderName::from_static("client-cert");
const CLIENT_CERT_CHAIN: HeaderName = HeaderName::from_static("client-cert-chain");
const X_FORWARDED_CLIENT_CERT: HeaderName = HeaderName::from_static("x-forwarded-client-cert");
const L5D_CLIENT_ID: HeaderName = HeaderName::from_static("l5d-client-id");

impl IdentityHeader {
    /// The header's name, as the setting names it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientCert => "client-cert",
            Self::XForwardedClientCert => "x-forwarded-client-cert",
            Self::LinkerdClientId => "l5d-client-id",
        }
    }

    /// The methods of client authentication this header makes usable,
    /// which the discovery document then names.
    #[must_use]
    pub const fn methods(self) -> &'static [AuthenticationMethod] {
        match self {
            Self::ClientCert | Self::XForwardedClientCert => &[
                AuthenticationMethod::TlsClientAuth,
                AuthenticationMethod::SpiffeX509,
            ],
            Self::LinkerdClientId => &[AuthenticationMethod::LinkerdIdentity],
        }
    }

    /// Whether the header forwards certificates, or their hash, that
    /// tokens can be bound to: Linkerd's forwards none.
    #[must_use]
    pub const fn forwards_certificates(self) -> bool {
        matches!(self, Self::ClientCert | Self::XForwardedClientCert)
    }

    fn name(self) -> HeaderName {
        match self {
            Self::ClientCert => CLIENT_CERT,
            Self::XForwardedClientCert => X_FORWARDED_CLIENT_CERT,
            Self::LinkerdClientId => L5D_CLIENT_ID,
        }
    }
}

impl FromStr for IdentityHeader {
    type Err = String;

    fn from_str(given: &str) -> Result<Self, Self::Err> {
        match given.trim().to_ascii_lowercase().as_str() {
            "client-cert" => Ok(Self::ClientCert),
            "x-forwarded-client-cert" => Ok(Self::XForwardedClientCert),
            "l5d-client-id" => Ok(Self::LinkerdClientId),
            _ => Err(format!(
                "`{given}` is not a header of the caller's identity Hodor reads: `client-cert`, \
                 `x-forwarded-client-cert` or `l5d-client-id`"
            )),
        }
    }
}

/// What the named header said about the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Read {
    /// Nothing: no header named, a connection that is not from a trusted
    /// proxy, no such header, or an element that names nobody.
    Absent,
    /// The nearest element could not be read: no identity.
    Unreadable,
    /// The identity the nearest element holds.
    Identity(ForwardedIdentity),
}

/// The lines of a header, in the order they arrived, or `None` when one
/// is not text.
fn lines(headers: &HeaderMap, name: HeaderName) -> Option<Vec<&str>> {
    headers
        .get_all(name)
        .iter()
        .map(|value| value.to_str().ok())
        .collect()
}

/// The elements of every line of a header, read as one list.
fn elements<'a>(lines: &[&'a str]) -> Vec<&'a str> {
    lines
        .iter()
        .flat_map(|line| split_outside(line, ','))
        .map(str::trim)
        .collect()
}

/// Reads the named header of a request that came from a trusted proxy.
pub(crate) fn read(header: IdentityHeader, headers: &HeaderMap) -> Read {
    let Some(lines) = lines(headers, header.name()) else {
        return Read::Unreadable;
    };
    if lines.is_empty() {
        return Read::Absent;
    }
    let all = elements(&lines);
    let Some(&nearest) = all.last() else {
        return Read::Absent;
    };
    let read = match header {
        IdentityHeader::ClientCert => client_cert(nearest, headers),
        IdentityHeader::XForwardedClientCert => x_forwarded_client_cert(nearest),
        IdentityHeader::LinkerdClientId => linkerd_client_id(nearest),
    };
    read.unwrap_or(Read::Unreadable)
}

/// A structured field's byte sequence, `:base64:` (RFC 8941, section
/// 3.3.5), holding one certificate.
fn byte_sequence(item: &str) -> Option<Vec<u8>> {
    let inside = item.strip_prefix(':')?.strip_suffix(':')?;
    let bytes = STANDARD.decode(inside).ok()?;
    (!bytes.is_empty() && bytes.len() <= MAX_FORWARDED_CERTIFICATE_BYTES).then_some(bytes)
}

fn client_cert(nearest: &str, headers: &HeaderMap) -> Option<Read> {
    let certificate = byte_sequence(nearest)?;
    let chain_lines = lines(headers, CLIENT_CERT_CHAIN)?;
    let chain = elements(&chain_lines)
        .into_iter()
        .map(byte_sequence)
        .collect::<Option<Vec<_>>>()?;
    if chain.len() > MAX_FORWARDED_CHAIN {
        return None;
    }
    Some(Read::Identity(ForwardedIdentity::Certificate {
        certificate,
        chain,
    }))
}

/// A value of `X-Forwarded-Client-Cert`, bare or in double quotes with
/// `\"` and `\\` inside.
fn unquote(value: &str) -> Option<String> {
    let Some(inner) = value.strip_prefix('"') else {
        return (!value.contains('"')).then(|| value.to_owned());
    };
    let inner = inner.strip_suffix('"')?;
    let mut unquoted = String::with_capacity(inner.len());
    let mut characters = inner.chars();
    while let Some(character) = characters.next() {
        match character {
            '\\' => unquoted.push(characters.next()?),
            '"' => return None,
            other => unquoted.push(other),
        }
    }
    Some(unquoted)
}

/// Undoes percent-encoding, leaving `+` as it is: PEM's base64 holds it.
fn percent_decoded(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = value.get(index + 1..index + 3)?;
            decoded.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

/// The certificates of PEM text, in order. Anything but whitespace
/// outside the blocks does not read.
fn pem_certificates(text: &str) -> Option<Vec<Vec<u8>>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut certificates = Vec::new();
    let mut rest = text.trim();
    while !rest.is_empty() {
        let body = rest.strip_prefix(BEGIN)?;
        let (inside, after) = body.split_once(END)?;
        let base64: String = inside.chars().filter(|c| !c.is_whitespace()).collect();
        let der = STANDARD.decode(base64).ok()?;
        if der.is_empty() || der.len() > MAX_FORWARDED_CERTIFICATE_BYTES {
            return None;
        }
        certificates.push(der);
        if certificates.len() > MAX_FORWARDED_CHAIN + 1 {
            return None;
        }
        rest = after.trim_start();
    }
    Some(certificates)
}

fn x_forwarded_client_cert(nearest: &str) -> Option<Read> {
    let (mut cert, mut chain) = (None, None);
    let (mut uris, mut dns_names) = (Vec::new(), Vec::new());
    let mut hashes = Vec::new();
    for pair in split_outside(nearest, ';') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=')?;
        let value = unquote(value.trim())?;
        match key.trim().to_ascii_lowercase().as_str() {
            "cert" if cert.is_none() => cert = Some(value),
            "chain" if chain.is_none() => chain = Some(value),
            "cert" | "chain" => return None,
            "uri" => uris.push(value),
            "dns" => dns_names.push(value),
            "hash" => hashes.push(value),
            _ => {}
        }
    }
    if let Some(cert) = cert {
        let [certificate] =
            <[Vec<u8>; 1]>::try_from(pem_certificates(&percent_decoded(&cert)?)?).ok()?;
        let chain = match chain {
            Some(chain) => pem_certificates(&percent_decoded(&chain)?)?,
            None => Vec::new(),
        };
        // Envoy's chain starts with the certificate itself.
        let chain: Vec<Vec<u8>> = chain
            .into_iter()
            .filter(|der| *der != certificate)
            .collect();
        if chain.len() > MAX_FORWARDED_CHAIN {
            return None;
        }
        return Some(Read::Identity(ForwardedIdentity::Certificate {
            certificate,
            chain,
        }));
    }
    if uris.is_empty() && dns_names.is_empty() {
        return Some(Read::Absent);
    }
    // Without the certificate, its SHA-256 as Envoy writes it, for a bound
    // token. One given twice, or that does not read, gives none.
    let hash = match hashes.as_slice() {
        [only] => CertificateThumbprint::from_hex(only),
        _ => None,
    };
    Some(Read::Identity(ForwardedIdentity::Names {
        uris,
        dns_names,
        hash,
    }))
}

fn linkerd_client_id(nearest: &str) -> Option<Read> {
    let fits = !nearest.is_empty()
        && nearest.len() <= MAX_LINKERD_IDENTITY_LENGTH
        && nearest.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        });
    fits.then(|| Read::Identity(ForwardedIdentity::Linkerd(nearest.to_owned())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                HeaderName::from_bytes(name.as_bytes()).expect("a name"),
                HeaderValue::from_str(value).expect("a value"),
            );
        }
        headers
    }

    fn sequence(bytes: &[u8]) -> String {
        format!(":{}:", STANDARD.encode(bytes))
    }

    fn pem(bytes: &[u8]) -> String {
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD.encode(bytes)
        )
    }

    /// Percent-encodes as Envoy does: everything but unreserved characters.
    fn encoded(text: &str) -> String {
        text.bytes()
            .map(|byte| {
                if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                    char::from(byte).to_string()
                } else {
                    format!("%{byte:02X}")
                }
            })
            .collect()
    }

    fn certificate(certificate: &[u8], chain: &[&[u8]]) -> Read {
        Read::Identity(ForwardedIdentity::Certificate {
            certificate: certificate.to_vec(),
            chain: chain.iter().map(|der| der.to_vec()).collect(),
        })
    }

    #[test]
    fn the_header_is_named_by_the_operator() {
        assert_eq!("Client-Cert".parse(), Ok(IdentityHeader::ClientCert));
        assert_eq!(
            " x-forwarded-client-cert ".parse(),
            Ok(IdentityHeader::XForwardedClientCert)
        );
        assert_eq!("l5d-client-id".parse(), Ok(IdentityHeader::LinkerdClientId));
        for refused in ["", "x-client-cert", "ssl-client-cert", "client-cert-chain"] {
            assert!(refused.parse::<IdentityHeader>().is_err(), "{refused}");
        }
    }

    #[test]
    fn only_the_named_header_is_read() {
        let sent = headers(&[
            ("client-cert", &sequence(b"\x30one")),
            (
                "l5d-client-id",
                "web.shop.serviceaccount.identity.linkerd.td",
            ),
        ]);
        assert_eq!(
            read(IdentityHeader::XForwardedClientCert, &sent),
            Read::Absent
        );
        assert_eq!(
            read(IdentityHeader::LinkerdClientId, &sent),
            Read::Identity(ForwardedIdentity::Linkerd(
                "web.shop.serviceaccount.identity.linkerd.td".to_owned()
            ))
        );
    }

    #[test]
    fn client_cert_is_read_with_its_chain() {
        let sent = headers(&[
            ("client-cert", &sequence(b"\x30leaf")),
            (
                "client-cert-chain",
                &format!("{}, {}", sequence(b"\x30one"), sequence(b"\x30two")),
            ),
        ]);
        assert_eq!(
            read(IdentityHeader::ClientCert, &sent),
            certificate(b"\x30leaf", &[b"\x30one", b"\x30two"])
        );
        let alone = headers(&[("client-cert", &sequence(b"\x30leaf"))]);
        assert_eq!(
            read(IdentityHeader::ClientCert, &alone),
            certificate(b"\x30leaf", &[])
        );
    }

    #[test]
    fn of_client_cert_only_the_nearest_element_is_read() {
        let forged = sequence(b"\x30forged");
        let own = sequence(b"\x30own");
        let in_one_line = headers(&[("client-cert", &format!("{forged}, {own}"))]);
        assert_eq!(
            read(IdentityHeader::ClientCert, &in_one_line),
            certificate(b"\x30own", &[])
        );
        let in_two_lines = headers(&[("client-cert", &forged), ("client-cert", &own)]);
        assert_eq!(
            read(IdentityHeader::ClientCert, &in_two_lines),
            certificate(b"\x30own", &[])
        );
    }

    #[test]
    fn client_cert_that_does_not_read_is_no_identity() {
        let too_large = vec![0x30; MAX_FORWARDED_CERTIFICATE_BYTES + 1];
        let long_chain = vec![sequence(b"\x30c"); MAX_FORWARDED_CHAIN + 1].join(",");
        for (cert, chain) in [
            ("MIIB", None),
            (":not base64!:", None),
            ("::", None),
            (":AAAA:;param=1", None),
            (sequence(&too_large).as_str(), None),
            (sequence(b"\x30leaf").as_str(), Some("not a sequence")),
            (sequence(b"\x30leaf").as_str(), Some(long_chain.as_str())),
        ] {
            let mut pairs = vec![("client-cert", cert)];
            if let Some(chain) = chain {
                pairs.push(("client-cert-chain", chain));
            }
            assert_eq!(
                read(IdentityHeader::ClientCert, &headers(&pairs)),
                Read::Unreadable,
                "{cert:.20} {chain:?}"
            );
        }
    }

    #[test]
    fn envoy_names_are_read_from_the_nearest_element_only() {
        let sent = headers(&[(
            "x-forwarded-client-cert",
            "By=spiffe://td/ns/a/sa/forged;URI=spiffe://td/ns/a/sa/admin,\
             By=spiffe://td/ns/hodor/sa/hodor;Hash=abc;Subject=\"CN=web,O=Shop\";\
             URI=spiffe://td/ns/shop/sa/web;DNS=web.shop.svc;DNS=\"web.local\"",
        )]);
        assert_eq!(
            read(IdentityHeader::XForwardedClientCert, &sent),
            Read::Identity(ForwardedIdentity::Names {
                uris: vec!["spiffe://td/ns/shop/sa/web".to_owned()],
                dns_names: vec!["web.shop.svc".to_owned(), "web.local".to_owned()],
                hash: None,
            }),
            "a Hash that does not read gives no thumbprint"
        );
        let lines = headers(&[
            ("x-forwarded-client-cert", "URI=spiffe://td/forged"),
            ("x-forwarded-client-cert", "By=x;uri=spiffe://td/own"),
        ]);
        assert_eq!(
            read(IdentityHeader::XForwardedClientCert, &lines),
            Read::Identity(ForwardedIdentity::Names {
                uris: vec!["spiffe://td/own".to_owned()],
                dns_names: Vec::new(),
                hash: None,
            }),
            "keys are read whatever their case, from the last line"
        );
    }

    #[test]
    fn envoy_s_hash_is_read_with_the_names_alone() {
        let hash = "9f".repeat(32);
        let element = |hash: &str| {
            headers(&[(
                "x-forwarded-client-cert",
                &format!(
                    "By=spiffe://td/forged;Hash={};URI=spiffe://td/forged,\
                     By=spiffe://td/hodor;Hash={hash};Subject=\"\";URI=spiffe://td/web",
                    "1".repeat(64)
                ),
            )])
        };
        assert_eq!(
            read(IdentityHeader::XForwardedClientCert, &element(&hash)),
            Read::Identity(ForwardedIdentity::Names {
                uris: vec!["spiffe://td/web".to_owned()],
                dns_names: Vec::new(),
                hash: CertificateThumbprint::from_hex(&hash),
            }),
            "the nearest element's Hash, never an earlier one's"
        );
        assert!(CertificateThumbprint::from_hex(&hash).is_some());
        let quoted = headers(&[(
            "x-forwarded-client-cert",
            &format!("Hash=\"{hash}\";URI=spiffe://td/web"),
        )]);
        assert_eq!(
            read(IdentityHeader::XForwardedClientCert, &quoted),
            Read::Identity(ForwardedIdentity::Names {
                uris: vec!["spiffe://td/web".to_owned()],
                dns_names: Vec::new(),
                hash: CertificateThumbprint::from_hex(&hash),
            })
        );
        let twice = headers(&[(
            "x-forwarded-client-cert",
            &format!("Hash={hash};Hash={hash};URI=spiffe://td/web"),
        )]);
        assert_eq!(
            read(IdentityHeader::XForwardedClientCert, &twice),
            Read::Identity(ForwardedIdentity::Names {
                uris: vec!["spiffe://td/web".to_owned()],
                dns_names: Vec::new(),
                hash: None,
            }),
            "a Hash given twice gives none"
        );
    }

    #[test]
    fn an_envoy_certificate_is_read_from_percent_encoded_pem() {
        let leaf = b"\x30leaf+/=".to_vec();
        let intermediate = b"\x30intermediate".to_vec();
        let chain = format!("{}{}", pem(&leaf), pem(&intermediate));
        let element = format!(
            "By=spiffe://td/hodor;Hash=abc;Cert=\"{}\";Chain=\"{}\";URI=spiffe://td/web",
            encoded(&pem(&leaf)),
            encoded(&chain)
        );
        let sent = headers(&[(
            "x-forwarded-client-cert",
            &format!(
                "Cert={};URI=spiffe://td/forged,{element}",
                encoded(&pem(b"\x30x"))
            ),
        )]);
        assert_eq!(
            read(IdentityHeader::XForwardedClientCert, &sent),
            certificate(&leaf, &[&intermediate]),
            "the certificate and the rest of its chain, the leaf left out of it"
        );
    }

    #[test]
    fn an_envoy_element_that_does_not_read_is_no_identity() {
        for element in [
            "URI",
            "URI=\"spiffe://td/a",
            "URI=spiffe://td/\"a\"",
            "Cert=%ZZ",
            "Cert=not-pem",
            "Cert=a;Cert=b",
        ] {
            assert_eq!(
                read(
                    IdentityHeader::XForwardedClientCert,
                    &headers(&[("x-forwarded-client-cert", element)])
                ),
                Read::Unreadable,
                "{element}"
            );
        }
        let two = format!("{}{}", pem(b"\x30a"), pem(b"\x30b"));
        assert_eq!(
            read(
                IdentityHeader::XForwardedClientCert,
                &headers(&[(
                    "x-forwarded-client-cert",
                    &format!("Cert={}", encoded(&two))
                )])
            ),
            Read::Unreadable,
            "Cert holds one certificate"
        );
        assert_eq!(
            read(
                IdentityHeader::XForwardedClientCert,
                &headers(&[("x-forwarded-client-cert", "By=spiffe://td/hodor;Hash=abc")])
            ),
            Read::Absent,
            "an element that names nobody"
        );
    }

    #[test]
    fn a_linkerd_identity_is_the_nearest_element() {
        let sent = headers(&[
            (
                "l5d-client-id",
                "admin.ops.serviceaccount.identity.linkerd.td",
            ),
            (
                "l5d-client-id",
                "web.shop.serviceaccount.identity.linkerd.td",
            ),
        ]);
        assert_eq!(
            read(IdentityHeader::LinkerdClientId, &sent),
            Read::Identity(ForwardedIdentity::Linkerd(
                "web.shop.serviceaccount.identity.linkerd.td".to_owned()
            ))
        );
        for refused in ["", "Web.Shop", "web shop", "spiffe://td/web"] {
            assert_eq!(
                read(
                    IdentityHeader::LinkerdClientId,
                    &headers(&[("l5d-client-id", refused)])
                ),
                Read::Unreadable,
                "{refused}"
            );
        }
    }
}
