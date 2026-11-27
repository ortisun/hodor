# Outbound HTTP

Hodor calls addresses that administrators of tenants type in: where an identity provider publishes its configuration and its keys, where a webhook is delivered, where a client is sent a logout token, where a pairwise client's sector identifier document is read, the same, its request object addresses and its key set address for a client that [registered itself](../architecture/contexts/oauth.md#the-registration-endpoint), which anyone may do in a tenant open to registration, or [changed its registration](../architecture/contexts/oauth.md#managing-a-registration), where a client publishes its keys, where a trust domain's bundle is fetched, and where a client keeps a request object it names by its address. An address chosen by someone else is a way to make the server call something it should never call: the cloud's metadata service, a database's administration port, another tenant's internal system. This is server-side request forgery, Threat-General-13 and Threat-Federation-08 in [the threat model](threat-model.md).

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

## The authorities it trusts

An HTTPS address is called only if its certificate chains to an authority Hodor trusts, for the name in the address. Those are the authorities of the system Hodor runs on: in the image, the public authorities its Debian base ships. `SSL_CERT_FILE`, the variable OpenSSL reads, names a file of certificates in PEM that **replaces** them, for the server, the worker and the command-line tool alike: for an identity provider or a trust domain's bundle endpoint served under an authority of the installation's own. Since it replaces them, the file holds the public authorities too when Hodor also calls public addresses. The chart's `outboundAuthorities` mounts such a file from a ConfigMap and sets the variable ([installing on Kubernetes](../operations/install-on-kubernetes.md#settings)). It changes no other rule: the address is still checked as the tables above say.

## The exception for development

A stack on one machine has an identity provider at a private address, over plain HTTP. For that, and for nothing else, the client takes a list of hosts with their ports, `HODOR_OUTBOUND_DEVELOPMENT_HOSTS`, for example `provider:8080`.

- A request to exactly that host and port is made without the address check and may use plain HTTP. Every other rule still applies.
- The list is empty by default. A server started with a non-empty list says so in its log at startup, at the warning level, naming every host.
- It must be empty anywhere real. It is the one setting that turns the protection off for a destination.
- The same list is what lets an identity provider have a plain HTTP issuer and plain HTTP endpoints: only when their host and port are on it. Everywhere else an issuer that is not HTTPS is refused when the provider is added, whatever the list says about other hosts.

## Checking an address without calling it

The guarded client also answers whether an address could be called now, without calling it: the `DestinationCheck` port of the kernel. It applies the rules above to the address as written, then resolves the name and refuses it unless every address it resolves to is public. A development host is accepted as it is, without resolving it.

It is for telling an administrator at once that an address will be refused, when the address is saved. It is never a reason to skip the check when the address is called: a name can resolve to something else between the two, so the client checks again on the resolution it connects with. [Webhook endpoints](../architecture/contexts/webhooks.md#endpoints) and [back-channel logout addresses](../architecture/contexts/oauth.md#the-back-channel-logout-address) are checked both ways, and so is a [sector identifier address](../architecture/contexts/oauth.md#the-sector-identifier-address), which is checked and then fetched once when it is saved. The registration endpoint checks these only for a request it has admitted, by its initial access token or because the tenant is open, and at most 10 times a minute for one address ([what a registration goes through](../architecture/contexts/oauth.md#what-a-registration-goes-through)). A [bundle endpoint](../architecture/contexts/keys.md#fetching-a-bundle) is checked and fetched when its trust domain is saved, and fetched again by the worker, the client checking the address at every fetch. A client's [request object addresses](../architecture/contexts/oauth.md#request-object-addresses) are checked when they are saved, and a [request object at one of them](../architecture/contexts/oauth.md#request-objects-at-a-clients-address) is checked again and fetched at the authorization endpoint, for each request that names it. A client's [key set address](../architecture/contexts/oauth.md#keys-at-the-clients-address) is checked when it is saved, and fetched when the client's keys are needed, at most once a minute per client.

| Code | When |
|---|---|
| `http.url_invalid` | The address cannot be read, is not HTTPS, or carries a name and password |
| `http.destination_forbidden` | The address, or one the name resolves to, is not public |
| `http.unreachable` | The name resolves to nothing |

## A time limit per request

A caller may give one request a shorter time limit than the client's, such as the 200 milliseconds an authorization decision may take. The shorter of the two applies. A request that runs out of time fails with `http.timed_out`, so that a caller can tell a slow answer from no connection.

## What does not go through this client

Connections to [LDAP directories](../architecture/contexts/federation.md#which-directories-may-be-used). Directories live on private networks, so the rule about public addresses cannot hold for them; they have a rule of their own, a list of allowed hosts kept by whoever operates the installation.

Requests to [Open Policy Agent](../architecture/contexts/authorization.md#open-policy-agent-as-an-engine), which also lives on a private network, often on the same machine, and to [OpenBao](../operations/keys-in-openbao.md), where the signing keys may be kept. They go through a second client of the same crate, `ServiceHttpClient`, which reverses the rule: instead of every public address, it calls **only the origins the operator configured**, exactly, and refuses any other address whatever it resolves to. No tenant and no caller can add to that list; the engine and the key provider build the path themselves. Every other rule above stays: no name and password in the address, no redirects, no proxy, a limit on time and on the size of the answer. Plain HTTP is accepted for these origins, for a sidecar on the same machine. OpenBao has a client of its own, which can trust only the certificate authority the operator names (`HODOR_OPENBAO_CA_FILE`) instead of the system's.

## Errors

| Code | When |
|---|---|
| `http.url_invalid` | The address cannot be read, is not HTTPS, or carries a name and password |
| `http.destination_forbidden` | The address is not public |
| `http.destination_not_configured` | `ServiceHttpClient` only: the origin is not one the operator configured |
| `http.unreachable` | No connection, or a failed TLS handshake |
| `http.timed_out` | The time limit, of the client or of the request, ran out |
| `http.response_too_large` | The answer passed the size limit |

None of them repeats the address in its message: the message may reach a person who should not learn what an internal name resolves to. The log has it.

## Not built yet

| Item | Planned in |
|---|---|
| A test of the TLS path against a server with a real certificate. The tests use the development exception | Hardening pass |
| An allow-list of destinations per tenant | Not scheduled |
| Limits on how many requests a tenant may cause, beyond those of [webhooks](../architecture/contexts/webhooks.md#bounds) | Not scheduled |
