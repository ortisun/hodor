//! Which addresses may be called.
//!
//! The ranges are listed in `docs/security/outbound-http.md`. Anything
//! not known to be public is refused.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn is_public_v4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    let refused = a == 0                                    // "this network"
        || a == 10                                          // private
        || (a == 100 && (64..=127).contains(&b))            // shared address space
        || a == 127                                         // the machine itself
        || (a == 169 && b == 254)                           // link-local, metadata services
        || (a == 172 && (16..=31).contains(&b))             // private
        || (a == 192 && b == 0 && c == 0)                   // protocol assignments
        || (a == 192 && b == 0 && c == 2)                   // documentation
        || (a == 192 && b == 88 && c == 99)                 // former relay anycast
        || (a == 192 && b == 168)                           // private
        || (a == 198 && (18..=19).contains(&b))             // benchmarks
        || (a == 198 && b == 51 && c == 100)                // documentation
        || (a == 203 && b == 0 && c == 113)                 // documentation
        || a >= 224; // multicast, reserved, broadcast
    !refused
}

fn is_public_v6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    let embedded = |high: u16, low: u16| {
        let [a, b] = high.to_be_bytes();
        let [c, d] = low.to_be_bytes();
        Ipv4Addr::new(a, b, c, d)
    };
    match segments {
        // An IPv4 address carried inside an IPv6 one: the address inside
        // is what would be reached.
        [0, 0, 0, 0, 0, 0xffff, high, low] | [0x64, 0xff9b, 0, 0, 0, 0, high, low] => {
            is_public_v4(embedded(high, low))
        }
        [0x2002, high, low, ..] => is_public_v4(embedded(high, low)),
        // Unspecified, loopback and the rest of the lowest block, which
        // also holds the deprecated "compatible" form of IPv4 addresses.
        [0, 0, 0, 0, 0, 0, _, _] => false,
        // Teredo and documentation.
        [0x2001, 0 | 0xdb8, ..] => false,
        [first, ..] => {
            let unique_local = first & 0xfe00 == 0xfc00;
            let link_local = first & 0xffc0 == 0xfe80;
            let multicast = first & 0xff00 == 0xff00;
            !(unique_local || link_local || multicast)
        }
    }
}

/// Whether `address` is one the server may call on someone else's word.
#[must_use]
pub fn is_public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_v4(address),
        IpAddr::V6(address) => is_public_v6(address),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public(text: &str) -> bool {
        is_public(text.parse().expect("an address"))
    }

    #[test]
    fn ordinary_addresses_are_public() {
        for address in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "172.15.255.255",
            "172.32.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "169.253.0.1",
            "192.0.1.1",
            "198.17.255.255",
            "198.20.0.0",
            "223.255.255.255",
            "2606:4700:4700::1111",
            "2a00:1450:4001:81b::200e",
            "64:ff9b::8.8.8.8",
            "::ffff:8.8.8.8",
            "2002:0808:0808::1",
        ] {
            assert!(public(address), "{address}");
        }
    }

    #[test]
    fn everything_else_is_refused() {
        for address in [
            // The machine itself.
            "127.0.0.1",
            "127.255.255.254",
            "::1",
            // Unspecified.
            "0.0.0.0",
            "0.1.2.3",
            "::",
            // Private networks.
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.255.255",
            "fc00::1",
            "fd12:3456:789a::1",
            // Shared address space.
            "100.64.0.1",
            "100.127.255.255",
            // Link-local, where metadata services live.
            "169.254.169.254",
            "169.254.0.1",
            "fe80::1",
            "febf::1",
            // Reserved, documentation, benchmarks.
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.1",
            "203.0.113.1",
            "2001:db8::1",
            "2001::1",
            // Multicast, reserved, broadcast.
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
            "ff02::1",
            // An IPv4 address inside an IPv6 one.
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::127.0.0.1",
            "64:ff9b::192.168.1.1",
            "2002:7f00:0001::1",
            "2002:c0a8:0101::1",
            "2002:a9fe:a9fe::1",
            "::127.0.0.1",
            "::10.0.0.1",
        ] {
            assert!(!public(address), "{address}");
        }
    }
}
