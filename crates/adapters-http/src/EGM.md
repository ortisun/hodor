# hodor-adapters-http source

## Overview

The outbound HTTP adapter. It is the one implementation of the kernel's `HttpClient` port, and the one place in Hodor that opens a connection to an address somebody else chose. It decides whether a destination may be called at all (`lib.rs` crate documentation, which points to `docs/security/outbound-http.md`). The modules `address` and `client` are private, and three items are re-exported (`lib.rs`).

## Interface

- `impl HttpClient for GuardedHttpClient` (`client.rs:199`, under `#[async_trait::async_trait]`) implements the kernel port `hodor_kernel::HttpClient` (see [the kernel source contract](../../kernel/src/EGM.md)). Its one method is `send(&self, request: HttpRequest) -> Result<HttpResponse, DomainError>` (`client.rs:GuardedHttpClient::send`).
- `GuardedHttpClient::new(policy: OutboundPolicy) -> Result<Self, DomainError>` builds two `reqwest` clients (`client.rs:GuardedHttpClient::new`):
  - a guarded client that allows HTTPS only and resolves names through a resolver that accepts only public addresses;
  - a development client, used only for the hosts listed in `development_hosts`.

  A build failure returns `http.client_unavailable`.
- `OutboundPolicy { timeout, connect_timeout, max_response_bytes, development_hosts }` (`client.rs:OutboundPolicy`). `Default` gives 10 seconds, 5 seconds, 1,048,576 bytes and no development hosts (`client.rs:OutboundPolicy::default`).
- `is_public(address: IpAddr) -> bool` returns whether an address may be called on someone else's word (`address.rs:is_public`).
- Internal: `impl Resolve for PublicOnly` (`client.rs:48`) implements the `reqwest::dns::Resolve` trait for the private resolver.

## Invariants

- IPv4 addresses that are refused (`address.rs:is_public_v4`): 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, and every address whose first octet is 224 or higher.
- IPv6 addresses (`address.rs:is_public_v6`):
  - Addresses that embed an IPv4 address are checked by the IPv4 rules: mapped addresses (`::ffff:a.b.c.d`), the 64:ff9b::/96 translation prefix and 2002::/16.
  - Refused outright are addresses whose first six segments are zero (including `::` and `::1`), 2001:0::/32, 2001:db8::/32, fc00::/7, fe80::/10 and ff00::/8.
- The resolver pins the connection to the checked addresses. `PublicOnly` resolves through `tokio::net::lookup_host` and refuses the name if the answer is empty or if any address is not public. Otherwise it returns exactly the addresses it checked (`client.rs:PublicOnly::resolve`).
- A literal IP address that is not public is refused as `http.destination_forbidden` before any connection is made (`client.rs:GuardedHttpClient::client_for`).
- An address is refused as `http.url_invalid` in five cases: it does not parse; it carries a user name or password; its scheme is neither `http` nor `https`; it has no host; or it uses a scheme other than `https` without being a development host (`client.rs:GuardedHttpClient::client_for`, `client.rs:GuardedHttpClient::send`).
- A development host matches when its `host:port` equals an entry exactly, ignoring ASCII case. Such a host skips the address check and may use plain HTTP, but the credential, scheme and host checks still run first (`client.rs:GuardedHttpClient::is_development`, `client.rs:GuardedHttpClient::client_for`).
- Both clients follow no redirects (`Policy::none()`), use no proxy, send the user agent `hodor`, and apply the policy's timeouts (`client.rs:GuardedHttpClient::new`).
- Errors from `send` are mapped as follows (`client.rs:GuardedHttpClient::send`, `client.rs:was_forbidden`):
  - a refusal by the resolver becomes `http.destination_forbidden`;
  - a request that cannot be built becomes `http.url_invalid`;
  - any other transport failure becomes `http.unreachable` (`Unavailable`).
- The body is read chunk by chunk. Once it would pass `max_response_bytes`, the request fails with `http.response_too_large`, whatever length the server announced. Response headers whose values are not visible text are dropped (`client.rs:GuardedHttpClient::send`).

## Side Effects

- Name lookups through `tokio::net::lookup_host` for every host the guarded client connects to (`client.rs:PublicOnly::resolve`).
- Outbound HTTP and HTTPS requests (GET or POST) through `reqwest` (`client.rs:GuardedHttpClient::send`).
- Warnings through `tracing::warn!` in these cases (`client.rs`):
  - a refused host or address;
  - a failed or truncated exchange, with the address removed through `without_url()`;
  - construction with a non-empty `development_hosts` list.
- `GuardedHttpClient::new` sets up the TLS library (rustls, through `reqwest`) when it builds the clients (`client.rs:GuardedHttpClient::new`).

## Verification

- Run: `cargo test -p hodor-adapters-http`
