# Outbound HTTP

Hodor calls addresses that administrators of tenants type in: where an identity provider publishes its configuration and its keys, later where a webhook is delivered. An address chosen by someone else is a way to make the server call something it should never call: the cloud's metadata service, a database's administration port, another tenant's internal system. This is server-side request forgery, Threat-General-13 and Threat-Federation-08 in [the threat model](threat-model.md).

There is therefore one way out. Every outbound HTTP request of every context goes through the `HttpClient` port of the kernel, and `hodor-adapters-http` is its only implementation. A context cannot make a request any other way: [the architecture test](../architecture/crates.md#automated-checks) keeps HTTP libraries out of context crates.

## The port

| Part | Contents |
|---|---|
| Request | `GET` or `POST`, an address, headers, an optional body |
| Response | The status, the headers and the body, whatever the status is. A redirect is a response like any other |

The caller decides what a status means. The client decides whether the request may be made at all.

## The rules

| Rule | Why |
|---|---|
| **HTTPS only** | What comes back is trusted to configure a sign-in. It must come from who the address names |
| **No name and password in the address** | `https://user:password@host/` is how a secret ends up in a log, and how a host name is disguised |
| **The address the name resolves to must be public** | See the table below. A name that resolves to several addresses is refused if any one of them is not public |
| **The address that was checked is the address that is connected to** | The check and the connection use the same resolution. A name cannot answer one address for the check and another for the connection |
| **An address written as numbers is checked the same way** | In every spelling: `127.0.0.1`, `2130706433`, `0x7f.1`, `[::ffff:127.0.0.1]` |
| **Redirects are not followed** | A public address may redirect to a private one. A caller that expects a redirect reads it and asks again, and the new address goes through every rule |
| **No proxy from the environment** | A proxy would connect on Hodor's behalf to an address Hodor did not check |
| **The whole exchange has a time limit**, ten seconds by default, five to connect | A slow answer must not hold a sign-in |
| **The answer has a size limit**, one mebibyte by default | An endless answer must not fill memory. The limit applies to the bytes received, whatever length the server announced |

### Addresses that are not public

| Range | What it is |
|---|---|
| `0.0.0.0/8`, `::` | "This network", unspecified |
| `127.0.0.0/8`, `::1` | The machine itself |
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7` | Private networks |
| `100.64.0.0/10` | Shared address space of carriers |
| `169.254.0.0/16`, `fe80::/10` | Link-local, where cloud metadata services live |
| `192.0.0.0/24`, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`, `198.18.0.0/15` | Reserved for protocols, documentation and benchmarks |
| `224.0.0.0/4`, `ff00::/8`, `240.0.0.0/4` | Multicast, reserved, broadcast |
| `::ffff:0:0/96`, `64:ff9b::/96`, `2002::/16`, `2001::/32` | An IPv4 address carried inside an IPv6 one. The address inside is checked; `2001::/32` is refused whole |

## The exception for development

A stack on one machine has an identity provider at a private address, over plain HTTP. For that, and for nothing else, the client takes a list of hosts with their ports, `HODOR_OUTBOUND_DEVELOPMENT_HOSTS`, for example `provider:8080`.

- A request to exactly that host and port is made without the address check and may use plain HTTP. Every other rule still applies.
- The list is empty by default. A server started with a non-empty list says so in its log at startup, at the warning level, naming every host.
- It must be empty anywhere real. It is the one setting that turns the protection off for a destination.
- The same list is what lets an identity provider have a plain HTTP issuer and plain HTTP endpoints: only when their host and port are on it. Everywhere else an issuer that is not HTTPS is refused when the provider is added, whatever the list says about other hosts.

## What does not go through this client

Connections to [LDAP directories](../architecture/contexts/federation.md#which-directories-may-be-used). Directories live on private networks, so the rule about public addresses cannot hold for them; they have a rule of their own, a list of allowed hosts kept by whoever operates the installation.

## Errors

| Code | When |
|---|---|
| `http.url_invalid` | The address cannot be read, is not HTTPS, or carries a name and password |
| `http.destination_forbidden` | The address is not public |
| `http.unreachable` | No connection, a failed TLS handshake, or the time limit |
| `http.response_too_large` | The answer passed the size limit |

None of them repeats the address in its message: the message may reach a person who should not learn what an internal name resolves to. The log has it.

## Not built yet

| Item | Planned in |
|---|---|
| A test of the TLS path against a server with a real certificate. The tests use the development exception | Hardening pass |
| An allow-list of destinations per tenant | With webhooks, Phase 5 |
| Limits on how many requests a tenant may cause | With webhooks, Phase 5 |
