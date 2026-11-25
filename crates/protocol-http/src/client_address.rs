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
//!   which a client cannot choose.

use crate::forwarded_identity::{self, IdentityHeader, Read};
use axum::http::{HeaderMap, HeaderName};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

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

/// The proxies whose forwarded header is believed, which header that is,
/// and which header of the caller's identity they write, if any. With no
/// range, which is the default, no header is ever read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxies {
    ranges: Vec<AddressRange>,
    header: ForwardedHeader,
    identity: Option<IdentityHeader>,
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
}

impl TrustedProxies {
    /// Trusts the proxies in `ranges`, whose header is `header`.
    #[must_use]
    pub const fn new(ranges: Vec<AddressRange>, header: ForwardedHeader) -> Self {
        Self {
            ranges,
            header,
            identity: None,
        }
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
        let Some(peer) = peer.map(|peer| peer.to_canonical()) else {
            return Resolved {
                address: None,
                unreadable: None,
            };
        };
        let direct = |unreadable| Resolved {
            address: Some(peer),
            unreadable,
        };
        if !self.trusts(peer) {
            return direct(None);
        }
        let Some(name) = self.header.name() else {
            return direct(None);
        };

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
                };
            }
            farthest = address;
        }
        // Every address was a trusted proxy: the first is the client.
        Resolved {
            address: Some(farthest),
            unreadable: None,
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
                unreadable: None
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
                unreadable: None
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
                    unreadable: Some(Unreadable::Unreadable)
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
                unreadable: None
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
                unreadable: Some(Unreadable::TooLong)
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
                unreadable: None
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
                unreadable: None
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
}
