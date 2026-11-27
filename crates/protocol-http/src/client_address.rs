//! Which address a request came from: the connection's, or the one a
//! trusted proxy forwarded.
//!
//! Specified in `docs/api/api-spec.md`, under "The client address". The
//! rules, in short:
//!
//! - a forwarded header is read only when the connection comes from a
//!   trusted proxy, and only the one header the operator names;
//! - the list it holds is read from its end, nearest first, passing over
//!   trusted proxies; the first address that is not one is the client;
//! - anything that cannot be read falls back to the connection's address,
//!   which a client cannot choose;
//! - behind the proxy of a service mesh, when the operator names the
//!   ingress gateways, the header is read only from a request whose caller
//!   is one of them, under "Behind the proxy of a service mesh".

use crate::forwarded_identity::{self, IdentityHeader, Read};
use axum::http::{HeaderMap, HeaderName};
use hodor_oauth::api::{
    CertificateCheck, ForwardedIdentity, LinkerdIdentity, SpiffeId, WorkloadIdentity,
};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

/// The most trusted proxies passed over in one forwarded header before
/// the client address is given up on.
pub const MAX_FORWARDED_HOPS: usize = 32;

/// A range of addresses: a network and the length of its prefix, such as
/// `10.0.0.0/8`. A bare address is a range of that address alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressRange {
    network: IpAddr,
    prefix: u8,
}

impl AddressRange {
    /// Whether `address` is inside the range. An IPv4 address held in an
    /// IPv6 one, such as `::ffff:10.0.0.1`, is read as the IPv4 address.
    #[must_use]
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.network, address.to_canonical()) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                prefix_matches(&network.octets(), &address.octets(), self.prefix)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                prefix_matches(&network.octets(), &address.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

/// Whether the first `prefix` bits of `network` and `address` agree.
fn prefix_matches(network: &[u8], address: &[u8], prefix: u8) -> bool {
    let whole = usize::from(prefix / 8);
    let rest = prefix % 8;
    if network[..whole] != address[..whole] {
        return false;
    }
    if rest == 0 {
        return true;
    }
    let mask = 0xff_u8 << (8 - rest);
    network[whole] & mask == address[whole] & mask
}

impl fmt::Display for AddressRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.network, self.prefix)
    }
}

/// Why a range given by the operator was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidRange {
    /// What was given.
    pub given: String,
    /// Why it was refused.
    pub reason: &'static str,
}

impl fmt::Display for InvalidRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "`{}` {}", self.given, self.reason)
    }
}

impl std::error::Error for InvalidRange {}

impl FromStr for AddressRange {
    type Err = InvalidRange;

    fn from_str(given: &str) -> Result<Self, Self::Err> {
        let invalid = |reason| InvalidRange {
            given: given.to_owned(),
            reason,
        };
        let (address, prefix) = match given.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (given, None),
        };
        let network = IpAddr::from_str(address)
            .map_err(|_| invalid("is not an IPv4 or IPv6 address"))?
            .to_canonical();
        // The longest prefix is that of the address as written: an IPv4
        // address held in IPv6 is written with the 128 bits of IPv6.
        let longest: u8 = if address.contains(':') { 128 } else { 32 };
        let prefix = match prefix {
            None if network.is_ipv4() => 32,
            None => 128,
            Some(prefix) => {
                if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(invalid("has a prefix length that is not a number"));
                }
                let prefix: u8 = prefix
                    .parse()
                    .map_err(|_| invalid("has a prefix length that is too long"))?;
                if prefix > longest {
                    return Err(invalid("has a prefix length that is too long"));
                }
                // A range written from an IPv4 address held in IPv6 is
                // counted from the IPv4 address.
                if address.contains(':') && network.is_ipv4() {
                    prefix
                        .checked_sub(96)
                        .ok_or_else(|| invalid("holds more than the IPv4 addresses it names"))?
                } else {
                    prefix
                }
            }
        };
        if prefix == 0 {
            return Err(invalid(
                "holds every address, which would let every client choose its own address",
            ));
        }
        Ok(Self {
            network: truncate(network, prefix),
            prefix,
        })
    }
}

/// The network of `address` with every bit after `prefix` cleared.
fn truncate(address: IpAddr, prefix: u8) -> IpAddr {
    fn clear<const N: usize>(mut octets: [u8; N], prefix: u8) -> [u8; N] {
        for (index, octet) in octets.iter_mut().enumerate() {
            let start = u32::try_from(index).unwrap_or(u32::MAX).saturating_mul(8);
            let kept = u32::from(prefix).saturating_sub(start).min(8);
            *octet &= if kept == 0 { 0 } else { 0xff_u8 << (8 - kept) };
        }
        octets
    }
    match address {
        IpAddr::V4(address) => IpAddr::from(clear(address.octets(), prefix)),
        IpAddr::V6(address) => IpAddr::from(clear(address.octets(), prefix)),
    }
}

/// Reads ranges separated by commas, as `HODOR_TRUSTED_PROXIES` holds
/// them. Spaces around each are ignored, and an empty list is no range.
///
/// # Errors
///
/// The first range that cannot be read.
pub fn parse_ranges(list: &str) -> Result<Vec<AddressRange>, InvalidRange> {
    list.split(',')
        .map(str::trim)
        .filter(|range| !range.is_empty())
        .map(AddressRange::from_str)
        .collect()
}

/// The header a trusted proxy writes the addresses into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ForwardedHeader {
    /// `X-Forwarded-For`: addresses separated by commas.
    #[default]
    XForwardedFor,
    /// `Forwarded` (RFC 7239): elements separated by commas, each with a
    /// `for` parameter.
    Forwarded,
    /// None: the proxies are trusted for the caller's identity alone, and
    /// the client address is always the connection's.
    None,
}

impl ForwardedHeader {
    fn name(self) -> Option<HeaderName> {
        match self {
            Self::XForwardedFor => Some(HeaderName::from_static("x-forwarded-for")),
            Self::Forwarded => Some(HeaderName::from_static("forwarded")),
            Self::None => None,
        }
    }
}

impl FromStr for ForwardedHeader {
    type Err = String;

    fn from_str(given: &str) -> Result<Self, Self::Err> {
        match given.trim().to_ascii_lowercase().as_str() {
            "x-forwarded-for" => Ok(Self::XForwardedFor),
            "forwarded" => Ok(Self::Forwarded),
            "none" => Ok(Self::None),
            _ => Err(format!(
                "`{given}` is not a forwarded header Hodor reads: `x-forwarded-for`, `forwarded` \
                 or `none`"
            )),
        }
    }
}

/// Why an identity given as an ingress gateway was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidGateway {
    /// What was given.
    pub given: String,
    /// Why it was refused.
    pub reason: String,
}

impl fmt::Display for InvalidGateway {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "`{}` {}", self.given, self.reason)
    }
}

impl std::error::Error for InvalidGateway {}

/// Reads the identities of ingress gateways separated by commas, as
/// `HODOR_GATEWAY_IDENTITIES` holds them: a SPIFFE identifier, by the rule
/// of a client's, or a Linkerd identity. Spaces around each are ignored,
/// and an empty list names no gateway.
///
/// # Errors
///
/// The first identity that cannot be read.
pub fn parse_gateways(list: &str) -> Result<Vec<WorkloadIdentity>, InvalidGateway> {
    list.split(',')
        .map(str::trim)
        .filter(|identity| !identity.is_empty())
        .map(|given| {
            let read = if given.starts_with("spiffe://") {
                SpiffeId::parse(given).map(WorkloadIdentity::Spiffe)
            } else {
                LinkerdIdentity::parse(given).map(WorkloadIdentity::Linkerd)
            };
            read.map_err(|error| InvalidGateway {
                given: given.to_owned(),
                reason: format!(
                    "is neither a SPIFFE identifier nor a Linkerd identity: {}",
                    error.detail().unwrap_or_else(|| error.message())
                ),
            })
        })
        .collect()
}

/// The ingress gateways whose forwarded header is read, and what reads the
/// names of a forwarded certificate.
#[derive(Clone)]
struct Gateways {
    identities: Vec<WorkloadIdentity>,
    certificates: Arc<dyn CertificateCheck>,
}

impl Gateways {
    /// Whether the caller a trusted proxy forwarded is one of the gateways.
    fn holds(&self, caller: &ForwardedIdentity) -> bool {
        match caller {
            ForwardedIdentity::Linkerd(asserted) => self.identities.iter().any(|gateway| {
                matches!(gateway, WorkloadIdentity::Linkerd(id) if id.as_str() == asserted)
            }),
            ForwardedIdentity::Names {
                uris, dns_names, ..
            } => self.named(uris, dns_names),
            ForwardedIdentity::Certificate { certificate, .. } => self
                .certificates
                .names(certificate)
                .is_some_and(|names| self.named(&names.uris, &names.dns_names)),
        }
    }

    /// Whether a SPIFFE identifier of a gateway is among `uris`, or a Linkerd
    /// identity of one among `dns_names`.
    fn named(&self, uris: &[String], dns_names: &[String]) -> bool {
        self.identities.iter().any(|gateway| match gateway {
            WorkloadIdentity::Spiffe(id) => uris.iter().any(|uri| uri == id.as_str()),
            WorkloadIdentity::Linkerd(id) => dns_names.iter().any(|name| name == id.as_str()),
        })
    }
}

/// The proxies whose forwarded header is believed, which header that is,
/// which header of the caller's identity they write, if any, and the
/// ingress gateways the forwarded header is read from, if named. With no
/// range, which is the default, no header is ever read.
#[derive(Clone, Default)]
pub struct TrustedProxies {
    ranges: Vec<AddressRange>,
    header: ForwardedHeader,
    identity: Option<IdentityHeader>,
    gateways: Option<Gateways>,
}

impl fmt::Debug for TrustedProxies {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedProxies")
            .field("ranges", &self.ranges)
            .field("header", &self.header)
            .field("identity", &self.identity)
            .field(
                "gateways",
                &self.gateways.as_ref().map(|gateways| &gateways.identities),
            )
            .finish()
    }
}

/// Why the forwarded header of a trusted proxy was not read although it was
/// there: the caller is not one of the ingress gateways.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ignored {
    /// No identity was forwarded, or it could not be read.
    NoIdentity,
    /// The identity forwarded is not one of the gateways.
    NotAGateway,
}

impl Ignored {
    /// The value of the `reason` label of the counter.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoIdentity => "no_identity",
            Self::NotAGateway => "not_a_gateway",
        }
    }
}

/// Why a forwarded header was given up on, and the connection's address
/// used instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreadable {
    /// An entry that is not an address was reached before the client.
    Unreadable,
    /// More trusted proxies were passed over than [`MAX_FORWARDED_HOPS`].
    TooLong,
}

impl Unreadable {
    /// The value of the `reason` label of the counter.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unreadable => "unreadable",
            Self::TooLong => "too_long",
        }
    }
}

/// The address a request came from, and whether a forwarded header had to
/// be given up on to find it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolved {
    /// The client address, if the connection's address is known.
    pub address: Option<IpAddr>,
    /// Set when the header of a trusted proxy could not be read.
    pub unreadable: Option<Unreadable>,
    /// Set when the header of a trusted proxy was there and not read,
    /// because the caller is not one of the ingress gateways.
    pub ignored: Option<Ignored>,
}

impl TrustedProxies {
    /// Trusts the proxies in `ranges`, whose header is `header`.
    #[must_use]
    pub const fn new(ranges: Vec<AddressRange>, header: ForwardedHeader) -> Self {
        Self {
            ranges,
            header,
            identity: None,
            gateways: None,
        }
    }

    /// The same proxies, whose forwarded header is read only from a request
    /// whose caller is one of `identities`, the ingress gateways; the names
    /// of a forwarded certificate are read by `certificates`. With no
    /// identity, the header is read from every caller, the default.
    #[must_use]
    pub fn with_gateways(
        mut self,
        identities: Vec<WorkloadIdentity>,
        certificates: Arc<dyn CertificateCheck>,
    ) -> Self {
        self.gateways = (!identities.is_empty()).then_some(Gateways {
            identities,
            certificates,
        });
        self
    }

    /// The ingress gateways the forwarded header is read from, if named.
    #[must_use]
    pub fn gateways(&self) -> &[WorkloadIdentity] {
        self.gateways
            .as_ref()
            .map_or(&[], |gateways| gateways.identities.as_slice())
    }

    /// The same proxies, whose header of the caller's identity is
    /// `identity`; none is read when it is `None`, the default.
    #[must_use]
    pub const fn with_identity_header(mut self, identity: Option<IdentityHeader>) -> Self {
        self.identity = identity;
        self
    }

    /// The header of the caller's identity that is read, if any.
    #[must_use]
    pub const fn identity_header(&self) -> Option<IdentityHeader> {
        self.identity
    }

    /// What the header of the caller's identity says, for a request whose
    /// connection came from `peer`: nothing unless a header is named and
    /// `peer` is a trusted proxy.
    pub(crate) fn forwarded_identity(&self, peer: Option<IpAddr>, headers: &HeaderMap) -> Read {
        match (self.identity, peer) {
            (Some(header), Some(peer)) if self.trusts(peer.to_canonical()) => {
                forwarded_identity::read(header, headers)
            }
            _ => Read::Absent,
        }
    }

    /// Trusts no proxy: the client address is always the connection's.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    fn trusts(&self, address: IpAddr) -> bool {
        self.ranges.iter().any(|range| range.contains(address))
    }

    /// The client address of a request whose connection came from `peer`.
    #[must_use]
    pub fn resolve(&self, peer: Option<IpAddr>, headers: &HeaderMap) -> Resolved {
        let caller = if self.gateways.is_some() {
            self.forwarded_identity(peer, headers)
        } else {
            Read::Absent
        };
        self.resolve_with(peer, headers, &caller)
    }

    /// The client address of a request whose connection came from `peer`,
    /// whose caller's identity was already read as `caller`.
    pub(crate) fn resolve_with(
        &self,
        peer: Option<IpAddr>,
        headers: &HeaderMap,
        caller: &Read,
    ) -> Resolved {
        let Some(peer) = peer.map(|peer| peer.to_canonical()) else {
            return Resolved {
                address: None,
                unreadable: None,
                ignored: None,
            };
        };
        let direct = |unreadable| Resolved {
            address: Some(peer),
            unreadable,
            ignored: None,
        };
        if !self.trusts(peer) {
            return direct(None);
        }
        let Some(name) = self.header.name() else {
            return direct(None);
        };
        if let Some(gateways) = &self.gateways {
            let ignored = match caller {
                Read::Identity(identity) if gateways.holds(identity) => None,
                Read::Identity(_) => Some(Ignored::NotAGateway),
                Read::Absent | Read::Unreadable => Some(Ignored::NoIdentity),
            };
            if let Some(ignored) = ignored {
                return Resolved {
                    address: Some(peer),
                    unreadable: None,
                    ignored: headers.contains_key(&name).then_some(ignored),
                };
            }
        }

        // Every line of the header, read as one list in the order the
        // lines arrived. A line that is not text cannot be read.
        let mut lines = Vec::new();
        for value in headers.get_all(name) {
            match value.to_str() {
                Ok(line) => lines.push(line),
                Err(_) => return direct(Some(Unreadable::Unreadable)),
            }
        }
        if lines.is_empty() {
            return direct(None);
        }
        let mut entries = Vec::new();
        for line in &lines {
            entries.extend(split_outside(line, ','));
        }

        let mut farthest = peer;
        for (hops, entry) in entries.iter().rev().enumerate() {
            if hops >= MAX_FORWARDED_HOPS {
                return direct(Some(Unreadable::TooLong));
            }
            let address = match self.header {
                ForwardedHeader::XForwardedFor => parse_node(entry.trim()),
                ForwardedHeader::Forwarded => forwarded_for(entry),
                ForwardedHeader::None => None,
            };
            let Some(address) = address.map(|address| address.to_canonical()) else {
                return direct(Some(Unreadable::Unreadable));
            };
            if !self.trusts(address) {
                return Resolved {
                    address: Some(address),
                    unreadable: None,
                    ignored: None,
                };
            }
            farthest = address;
        }
        // Every address was a trusted proxy: the first is the client.
        Resolved {
            address: Some(farthest),
            unreadable: None,
            ignored: None,
        }
    }
}

/// Splits a header line on `separator` where it is not inside a quoted
/// string.
pub(crate) fn split_outside(line: &str, separator: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            found if found == separator && !quoted => {
                parts.push(&line[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&line[start..]);
    parts
}

/// The address of the `for` parameter of one element of `Forwarded`, such
/// as `for=192.0.2.60;proto=https` or `for="[2001:db8::1]:4711"`.
fn forwarded_for(element: &str) -> Option<IpAddr> {
    let mut found = None;
    for pair in element.split(';') {
        let (name, value) = pair.trim().split_once('=')?;
        if !name.trim().eq_ignore_ascii_case("for") {
            continue;
        }
        if found.is_some() {
            // An element names one client, never two.
            return None;
        }
        let value = value.trim();
        let value = match value.strip_prefix('"') {
            Some(quoted) => {
                let inner = quoted.strip_suffix('"')?;
                if inner.contains(['"', '\\']) {
                    return None;
                }
                inner
            }
            None => value,
        };
        found = Some(parse_node(value)?);
    }
    found
}

/// An address with or without its port: `203.0.113.7`, `203.0.113.7:80`,
/// `2001:db8::7`, `[2001:db8::7]` or `[2001:db8::7]:80`.
fn parse_node(node: &str) -> Option<IpAddr> {
    if let Some(bracketed) = node.strip_prefix('[') {
        let (inside, after) = bracketed.split_once(']')?;
        if !(after.is_empty() || is_port(after.strip_prefix(':')?)) {
            return None;
        }
        return inside.parse::<std::net::Ipv6Addr>().ok().map(IpAddr::V6);
    }
    if let Ok(address) = node.parse::<IpAddr>() {
        return Some(address);
    }
    let (host, port) = node.rsplit_once(':')?;
    if !is_port(port) {
        return None;
    }
    host.parse::<std::net::Ipv4Addr>().ok().map(IpAddr::V4)
}

fn is_port(port: &str) -> bool {
    !port.is_empty() && port.len() <= 5 && port.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn address(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    fn proxies(ranges: &str, header: ForwardedHeader) -> TrustedProxies {
        TrustedProxies::new(parse_ranges(ranges).expect("ranges"), header)
    }

    fn headers(name: &str, lines: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for line in lines {
            headers.append(
                HeaderName::from_bytes(name.as_bytes()).expect("a name"),
                HeaderValue::from_str(line).expect("a value"),
            );
        }
        headers
    }

    fn resolve(proxies: &TrustedProxies, peer: &str, headers: &HeaderMap) -> Resolved {
        proxies.resolve(Some(address(peer)), headers)
    }

    fn client(resolved: Resolved) -> String {
        resolved.address.expect("an address").to_string()
    }

    #[test]
    fn ranges_are_read_as_written_and_cleared_past_their_prefix() {
        let ranges = parse_ranges(" 10.0.0.5/8, 2001:db8::/32 ,192.0.2.1,, ::1").expect("ranges");
        let written: Vec<String> = ranges.iter().map(ToString::to_string).collect();
        assert_eq!(
            written,
            ["10.0.0.0/8", "2001:db8::/32", "192.0.2.1/32", "::1/128"]
        );
        assert!(parse_ranges("").expect("nothing").is_empty());
    }

    #[test]
    fn a_range_that_cannot_be_read_or_holds_everything_is_refused() {
        for given in [
            "10.0.0.0/33",
            "2001:db8::/129",
            "10.0.0.0/",
            "10.0.0.0/eight",
            "10.0.0.0/+8",
            "not-an-address",
            "10.0.0.0/8/8",
            "0.0.0.0/0",
            "::/0",
            "::ffff:10.0.0.0/64",
        ] {
            assert!(
                AddressRange::from_str(given).is_err(),
                "{given} was accepted"
            );
        }
    }

    #[test]
    fn a_range_contains_the_addresses_of_its_prefix_only() {
        let range = AddressRange::from_str("10.1.0.0/20").expect("range");
        assert!(range.contains(address("10.1.15.255")));
        assert!(!range.contains(address("10.1.16.0")));
        assert!(!range.contains(address("2001:db8::1")));
        assert!(
            range.contains(address("::ffff:10.1.0.9")),
            "IPv4 held in IPv6"
        );

        let range = AddressRange::from_str("2001:db8:abcd::/47").expect("range");
        assert!(range.contains(address("2001:db8:abcd:1::1")));
        assert!(!range.contains(address("2001:db8:abce::1")));

        let held = AddressRange::from_str("::ffff:192.0.2.0/120").expect("range");
        assert_eq!(held.to_string(), "192.0.2.0/24");
    }

    #[test]
    fn a_header_from_a_connection_that_is_not_a_trusted_proxy_is_ignored() {
        let proxies = proxies("10.0.0.0/8", ForwardedHeader::XForwardedFor);
        let forged = headers("x-forwarded-for", &["198.51.100.1"]);
        assert_eq!(
            resolve(&proxies, "203.0.113.7", &forged),
            Resolved {
                address: Some(address("203.0.113.7")),
                unreadable: None,
                ignored: None
            }
        );
        let nobody = TrustedProxies::none();
        assert_eq!(client(resolve(&nobody, "10.0.0.1", &forged)), "10.0.0.1");
    }

    #[test]
    fn the_nearest_address_that_is_not_a_trusted_proxy_is_the_client() {
        let proxies = proxies("10.0.0.0/16", ForwardedHeader::XForwardedFor);
        let chain = headers("x-forwarded-for", &["198.51.100.1, 203.0.113.7, 10.0.0.5"]);
        assert_eq!(client(resolve(&proxies, "10.0.1.9", &chain)), "203.0.113.7");
    }

    #[test]
    fn a_chain_of_trusted_proxies_alone_yields_its_first_address() {
        let proxies = proxies("10.0.0.0/8", ForwardedHeader::XForwardedFor);
        let chain = headers("x-forwarded-for", &["10.9.9.9, 10.0.0.5"]);
        assert_eq!(client(resolve(&proxies, "10.0.1.9", &chain)), "10.9.9.9");
    }

    #[test]
    fn without_the_header_the_connection_is_the_client() {
        let proxies = proxies("10.0.0.0/8", ForwardedHeader::XForwardedFor);
        let other = headers("forwarded", &["for=203.0.113.7"]);
        assert_eq!(
            resolve(&proxies, "10.0.0.1", &other),
            Resolved {
                address: Some(address("10.0.0.1")),
                unreadable: None,
                ignored: None
            },
            "only the named header is read"
        );
    }

    #[test]
    fn lines_of_the_header_are_read_as_one_list_in_order() {
        let proxies = proxies("10.0.0.0/8", ForwardedHeader::XForwardedFor);
        let lines = headers("x-forwarded-for", &["203.0.113.7", "10.0.0.5"]);
        assert_eq!(client(resolve(&proxies, "10.0.0.1", &lines)), "203.0.113.7");
    }

    #[test]
    fn ports_brackets_and_ipv4_held_in_ipv6_are_read() {
        let proxies = proxies("10.0.0.0/8,fd00::/8", ForwardedHeader::XForwardedFor);
        for (entry, expected) in [
            ("203.0.113.7:4711", "203.0.113.7"),
            ("[2001:db8::7]:4711", "2001:db8::7"),
            ("[2001:db8::7]", "2001:db8::7"),
            ("2001:db8::7", "2001:db8::7"),
            ("::ffff:203.0.113.7", "203.0.113.7"),
        ] {
            let header = headers("x-forwarded-for", &[entry]);
            assert_eq!(
                client(resolve(&proxies, "10.0.0.1", &header)),
                expected,
                "{entry}"
            );
        }
        let mapped_peer = headers("x-forwarded-for", &["203.0.113.7"]);
        assert_eq!(
            client(resolve(&proxies, "::ffff:10.0.0.1", &mapped_peer)),
            "203.0.113.7",
            "a proxy connecting over IPv6 with its IPv4 address is still trusted"
        );
    }

    #[test]
    fn forwarded_elements_are_read_by_their_for_parameter() {
        let proxies = proxies("10.0.0.0/8", ForwardedHeader::Forwarded);
        let header = headers(
            "forwarded",
            &[
                r#"for=198.51.100.1, For="[2001:db8::7]:4711";proto=https, for=10.0.0.5;by=10.0.0.6"#,
            ],
        );
        assert_eq!(
            client(resolve(&proxies, "10.0.1.9", &header)),
            "2001:db8::7"
        );
    }

    #[test]
    fn what_cannot_be_read_falls_back_to_the_connection_and_says_so() {
        let x_forwarded_for = proxies("10.0.0.0/8", ForwardedHeader::XForwardedFor);
        for entry in [
            "unknown",
            "",
            "203.0.113.7:port",
            "203.0.113.7:123456",
            "[2001:db8::7",
        ] {
            let header = headers("x-forwarded-for", &[&format!("{entry}, 10.0.0.5")]);
            assert_eq!(
                resolve(&x_forwarded_for, "10.0.0.1", &header),
                Resolved {
                    address: Some(address("10.0.0.1")),
                    unreadable: Some(Unreadable::Unreadable),
                    ignored: None
                },
                "{entry:?}"
            );
        }
        let forwarded = proxies("10.0.0.0/8", ForwardedHeader::Forwarded);
        for element in [
            "for=_hidden",
            "for=unknown",
            "proto=https",
            "for=203.0.113.7;for=198.51.100.1",
            r#"for="203.0.113.7"#,
            r#"for="203\.0.113.7""#,
        ] {
            let header = headers("forwarded", &[element]);
            assert_eq!(
                resolve(&forwarded, "10.0.0.1", &header).unreadable,
                Some(Unreadable::Unreadable),
                "{element}"
            );
        }
    }

    #[test]
    fn a_quoted_comma_does_not_split_an_element() {
        let proxies = proxies("10.0.0.0/8", ForwardedHeader::Forwarded);
        let header = headers(
            "forwarded",
            &[r#"for="198.51.100.1, for=10.0.0.9", for=10.0.0.5"#],
        );
        assert_eq!(
            resolve(&proxies, "10.0.0.1", &header).unreadable,
            Some(Unreadable::Unreadable),
            "the forged element is read whole, and does not read"
        );
    }

    #[test]
    fn garbage_written_by_a_client_is_never_reached() {
        let proxies = proxies("10.0.0.0/8", ForwardedHeader::XForwardedFor);
        let header = headers("x-forwarded-for", &["not an address, 203.0.113.7"]);
        assert_eq!(
            resolve(&proxies, "10.0.0.1", &header),
            Resolved {
                address: Some(address("203.0.113.7")),
                unreadable: None,
                ignored: None
            }
        );
    }

    #[test]
    fn a_long_list_written_by_a_client_does_not_move_it_onto_the_proxy() {
        let proxies = proxies("10.0.0.0/8", ForwardedHeader::XForwardedFor);
        let mut list: Vec<String> = (0..100).map(|n| format!("198.51.100.{n}")).collect();
        list.push("203.0.113.7".to_owned());
        let header = headers("x-forwarded-for", &[&list.join(", ")]);
        assert_eq!(
            client(resolve(&proxies, "10.0.0.1", &header)),
            "203.0.113.7"
        );
    }

    #[test]
    fn too_many_trusted_proxies_fall_back_to_the_connection() {
        let proxies = proxies("10.0.0.0/8", ForwardedHeader::XForwardedFor);
        let list: Vec<String> = (0..=MAX_FORWARDED_HOPS)
            .map(|n| format!("10.0.0.{n}"))
            .collect();
        let header = headers("x-forwarded-for", &[&list.join(",")]);
        assert_eq!(
            resolve(&proxies, "10.0.1.1", &header),
            Resolved {
                address: Some(address("10.0.1.1")),
                unreadable: Some(Unreadable::TooLong),
                ignored: None
            }
        );
        let fits: Vec<String> = (0..MAX_FORWARDED_HOPS)
            .map(|n| format!("10.0.0.{n}"))
            .collect();
        let header = headers("x-forwarded-for", &[&fits.join(",")]);
        assert_eq!(client(resolve(&proxies, "10.0.1.1", &header)), "10.0.0.0");
    }

    #[test]
    fn without_a_connection_there_is_no_address() {
        let proxies = proxies("10.0.0.0/8", ForwardedHeader::XForwardedFor);
        let header = headers("x-forwarded-for", &["203.0.113.7"]);
        assert_eq!(
            proxies.resolve(None, &header),
            Resolved {
                address: None,
                unreadable: None,
                ignored: None
            }
        );
    }

    #[test]
    fn the_header_is_named_by_the_operator() {
        assert_eq!(
            "X-Forwarded-For".parse(),
            Ok(ForwardedHeader::XForwardedFor)
        );
        assert_eq!(" forwarded ".parse(), Ok(ForwardedHeader::Forwarded));
        assert_eq!("None".parse(), Ok(ForwardedHeader::None));
        assert!("x-real-ip".parse::<ForwardedHeader>().is_err());
    }

    #[test]
    fn with_no_forwarded_header_the_connection_is_the_client() {
        let proxies = proxies("10.0.0.0/8", ForwardedHeader::None);
        let sent = headers("x-forwarded-for", &["203.0.113.7"]);
        assert_eq!(
            resolve(&proxies, "10.0.0.1", &sent),
            Resolved {
                address: Some(address("10.0.0.1")),
                unreadable: None,
                ignored: None
            }
        );
    }

    #[test]
    fn the_callers_identity_is_read_only_from_a_trusted_proxy_and_only_when_named() {
        let identity = "web.shop.serviceaccount.identity.linkerd.td";
        let sent = headers("l5d-client-id", &[identity]);
        let named = proxies("10.0.0.0/8", ForwardedHeader::None)
            .with_identity_header(Some(IdentityHeader::LinkerdClientId));
        assert_eq!(
            named.forwarded_identity(Some(address("10.0.0.1")), &sent),
            Read::Identity(hodor_oauth::api::ForwardedIdentity::Linkerd(
                identity.to_owned()
            ))
        );
        assert_eq!(
            named.forwarded_identity(Some(address("::ffff:10.0.0.1")), &sent),
            Read::Identity(hodor_oauth::api::ForwardedIdentity::Linkerd(
                identity.to_owned()
            )),
            "a proxy connecting over IPv6 with its IPv4 address is still trusted"
        );
        assert_eq!(
            named.forwarded_identity(Some(address("203.0.113.7")), &sent),
            Read::Absent,
            "from a peer that is not a trusted proxy"
        );
        assert_eq!(named.forwarded_identity(None, &sent), Read::Absent);
        let unnamed = proxies("10.0.0.0/8", ForwardedHeader::None);
        assert_eq!(unnamed.identity_header(), None);
        assert_eq!(
            unnamed.forwarded_identity(Some(address("10.0.0.1")), &sent),
            Read::Absent,
            "no header is read when none is named"
        );
        let nobody =
            TrustedProxies::none().with_identity_header(Some(IdentityHeader::LinkerdClientId));
        assert_eq!(
            nobody.forwarded_identity(Some(address("10.0.0.1")), &sent),
            Read::Absent,
            "a header named with no trusted proxy is never read"
        );
    }

    const GATEWAY: &str =
        "spiffe://cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account";
    const LINKERD_GATEWAY: &str = "gateway.edge.serviceaccount.identity.linkerd.cluster.local";
    const WORKLOAD: &str = "spiffe://cluster.local/ns/shop/sa/web";

    /// A sidecar at 127.0.0.6, trusted, whose identity header is `header`,
    /// in front of the gateways `named`.
    fn behind_sidecar(header: IdentityHeader, named: &str) -> TrustedProxies {
        proxies("127.0.0.6", ForwardedHeader::XForwardedFor)
            .with_identity_header(Some(header))
            .with_gateways(
                parse_gateways(named).expect("gateways"),
                Arc::new(hodor_adapters_crypto::X509CertificateCheck),
            )
    }

    fn request(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                HeaderName::from_bytes(name.as_bytes()).expect("a name"),
                HeaderValue::from_str(value).expect("a value"),
            );
        }
        headers
    }

    /// The element Istio's sidecar adds, naming the caller by its URI.
    fn sidecar_element(caller: &str) -> String {
        format!("By=spiffe://cluster.local/ns/hodor/sa/hodor;Hash=00;Subject=\"\";URI={caller}")
    }

    #[test]
    fn gateways_are_read_as_spiffe_identifiers_or_linkerd_identities() {
        let gateways = parse_gateways(&format!(" {GATEWAY} ,, {LINKERD_GATEWAY}")).expect("read");
        let written: Vec<&str> = gateways.iter().map(WorkloadIdentity::as_str).collect();
        assert_eq!(written, [GATEWAY, LINKERD_GATEWAY]);
        assert!(matches!(gateways[0], WorkloadIdentity::Spiffe(_)));
        assert!(matches!(gateways[1], WorkloadIdentity::Linkerd(_)));
        assert!(parse_gateways("").expect("nothing").is_empty());
        for given in [
            "spiffe://cluster.local/ns/istio-system/sa/*",
            "spiffe://",
            "https://gateway.example",
            "gateway.edge.svc.cluster.local",
            "Gateway.Edge.serviceaccount.identity.linkerd.cluster.local",
        ] {
            let refused = parse_gateways(&format!("{GATEWAY},{given}"))
                .expect_err("an identity that does not read");
            assert_eq!(refused.given, given);
        }
        let none = behind_sidecar(IdentityHeader::XForwardedClientCert, "");
        assert!(none.gateways().is_empty(), "an empty list names no gateway");
    }

    #[test]
    fn behind_a_gateway_the_forwarded_address_is_read() {
        let proxies = behind_sidecar(IdentityHeader::XForwardedClientCert, GATEWAY);
        let through_gateway = request(&[
            ("x-forwarded-for", "198.51.100.1, 203.0.113.7"),
            ("x-forwarded-client-cert", &sidecar_element(GATEWAY)),
        ]);
        assert_eq!(
            resolve(&proxies, "127.0.0.6", &through_gateway),
            Resolved {
                address: Some(address("203.0.113.7")),
                unreadable: None,
                ignored: None
            }
        );
    }

    #[test]
    fn the_forwarded_address_of_any_other_workload_is_ignored_and_counted() {
        let proxies = behind_sidecar(IdentityHeader::XForwardedClientCert, GATEWAY);
        let forged = request(&[
            ("x-forwarded-for", "198.51.100.1"),
            ("x-forwarded-client-cert", &sidecar_element(WORKLOAD)),
        ]);
        assert_eq!(
            resolve(&proxies, "127.0.0.6", &forged),
            Resolved {
                address: Some(address("127.0.0.6")),
                unreadable: None,
                ignored: Some(Ignored::NotAGateway)
            }
        );
        // An element naming the gateway, written by the caller before the
        // sidecar's own, is never read.
        let before = request(&[
            ("x-forwarded-for", "198.51.100.1"),
            (
                "x-forwarded-client-cert",
                &format!("URI={GATEWAY},{}", sidecar_element(WORKLOAD)),
            ),
        ]);
        assert_eq!(
            resolve(&proxies, "127.0.0.6", &before).ignored,
            Some(Ignored::NotAGateway)
        );
        // Hodor's own identity, in By, is not the caller's.
        let own = behind_sidecar(
            IdentityHeader::XForwardedClientCert,
            "spiffe://cluster.local/ns/hodor/sa/hodor",
        );
        assert_eq!(
            resolve(&own, "127.0.0.6", &forged).ignored,
            Some(Ignored::NotAGateway)
        );
    }

    #[test]
    fn without_an_identity_the_forwarded_address_is_ignored() {
        let proxies = behind_sidecar(IdentityHeader::XForwardedClientCert, GATEWAY);
        let absent = request(&[("x-forwarded-for", "198.51.100.1")]);
        assert_eq!(
            resolve(&proxies, "127.0.0.6", &absent),
            Resolved {
                address: Some(address("127.0.0.6")),
                unreadable: None,
                ignored: Some(Ignored::NoIdentity)
            }
        );
        let unreadable = request(&[
            ("x-forwarded-for", "198.51.100.1"),
            ("x-forwarded-client-cert", "Cert=\"not a certificate\""),
        ]);
        assert_eq!(
            resolve(&proxies, "127.0.0.6", &unreadable).ignored,
            Some(Ignored::NoIdentity)
        );
        // Another header of identity than the one named is not read.
        let other = request(&[
            ("x-forwarded-for", "198.51.100.1"),
            ("l5d-client-id", LINKERD_GATEWAY),
        ]);
        let both = behind_sidecar(
            IdentityHeader::XForwardedClientCert,
            &format!("{GATEWAY},{LINKERD_GATEWAY}"),
        );
        assert_eq!(
            resolve(&both, "127.0.0.6", &other).ignored,
            Some(Ignored::NoIdentity)
        );
        // With no forwarded header, nothing is ignored.
        let quiet = request(&[("x-forwarded-client-cert", &sidecar_element(WORKLOAD))]);
        assert_eq!(
            resolve(&proxies, "127.0.0.6", &quiet),
            Resolved {
                address: Some(address("127.0.0.6")),
                unreadable: None,
                ignored: None
            }
        );
    }

    #[test]
    fn a_connection_that_is_not_a_trusted_proxy_is_its_own_address_even_as_a_gateway() {
        let proxies = behind_sidecar(IdentityHeader::XForwardedClientCert, GATEWAY);
        let forged = request(&[
            ("x-forwarded-for", "198.51.100.1"),
            ("x-forwarded-client-cert", &sidecar_element(GATEWAY)),
        ]);
        assert_eq!(
            resolve(&proxies, "10.0.0.9", &forged),
            Resolved {
                address: Some(address("10.0.0.9")),
                unreadable: None,
                ignored: None
            }
        );
    }

    #[test]
    fn a_linkerd_gateway_is_the_identity_its_proxy_asserts() {
        let proxies = behind_sidecar(IdentityHeader::LinkerdClientId, LINKERD_GATEWAY);
        let gateway = request(&[
            ("x-forwarded-for", "203.0.113.7"),
            ("l5d-client-id", LINKERD_GATEWAY),
        ]);
        assert_eq!(
            client(resolve(&proxies, "127.0.0.6", &gateway)),
            "203.0.113.7"
        );
        let workload = request(&[
            ("x-forwarded-for", "203.0.113.7"),
            (
                "l5d-client-id",
                "web.shop.serviceaccount.identity.linkerd.cluster.local",
            ),
        ]);
        assert_eq!(
            resolve(&proxies, "127.0.0.6", &workload).ignored,
            Some(Ignored::NotAGateway)
        );
        // A SPIFFE identifier names no Linkerd caller.
        let spiffe = behind_sidecar(IdentityHeader::LinkerdClientId, GATEWAY);
        assert_eq!(
            resolve(&spiffe, "127.0.0.6", &gateway).ignored,
            Some(Ignored::NotAGateway)
        );
    }

    #[test]
    fn a_forwarded_certificate_is_a_gateway_by_its_names() {
        use base64::Engine as _;
        use hodor_adapters_crypto::testing::certificates::{Leaf, TestAuthority};
        let mesh = TestAuthority::root("mesh");
        let encoded = |pem: &str| {
            pem.bytes()
                .map(|byte| {
                    if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                        char::from(byte).to_string()
                    } else {
                        format!("%{byte:02X}")
                    }
                })
                .collect::<String>()
        };
        let with_cert = |leaf: &Leaf| {
            request(&[
                ("x-forwarded-for", "203.0.113.7"),
                (
                    "x-forwarded-client-cert",
                    &format!("By=x;Cert=\"{}\"", encoded(&mesh.issue_pem(leaf))),
                ),
            ])
        };
        let proxies = behind_sidecar(
            IdentityHeader::XForwardedClientCert,
            &format!("{GATEWAY},{LINKERD_GATEWAY}"),
        );
        assert_eq!(
            client(resolve(
                &proxies,
                "127.0.0.6",
                &with_cert(&Leaf::uri(GATEWAY))
            )),
            "203.0.113.7"
        );
        assert_eq!(
            client(resolve(
                &proxies,
                "127.0.0.6",
                &with_cert(&Leaf::dns(LINKERD_GATEWAY))
            )),
            "203.0.113.7",
            "a Linkerd identity among the certificate's DNS names"
        );
        assert_eq!(
            resolve(&proxies, "127.0.0.6", &with_cert(&Leaf::uri(WORKLOAD))).ignored,
            Some(Ignored::NotAGateway)
        );

        let client_cert = behind_sidecar(IdentityHeader::ClientCert, GATEWAY);
        let sequence = format!(
            ":{}:",
            base64::engine::general_purpose::STANDARD.encode(mesh.issue(&Leaf::uri(GATEWAY)))
        );
        let rfc = request(&[
            ("x-forwarded-for", "203.0.113.7"),
            ("client-cert", &sequence),
        ]);
        assert_eq!(
            client(resolve(&client_cert, "127.0.0.6", &rfc)),
            "203.0.113.7"
        );
    }
}
