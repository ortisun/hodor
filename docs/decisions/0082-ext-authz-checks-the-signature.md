# Decision 0082: `hodor-ext-authz` checks the signature of the bearer token itself, against the tenant's published key set, before it asks Hodor anything

Status: Proposed

## Context

[Decision 0058](0058-hodor-ext-authz.md#what-hodor-ext-authz-does) has `hodor-ext-authz` take the subject from the claims of the token the proxy checked: from the request's metadata, where Envoy's JWT filter writes them, or from a header the proxy writes, believed only when it equals the claims part of the bearer token in `Authorization`. It never checks a signature: the proxy does, and [Decision 0077](0077-ext-authz-checks-the-audience.md) added the audience to what the adapter checks of the claims, `iss`, `exp` and `sub`.

The demonstration of Milestone 11 found that the proxy does not always check first:

- **Istio's sidecar asks external authorization before it checks a token.** Istio 1.30 puts the filter of an `AuthorizationPolicy` of action `CUSTOM` ahead of the one of `RequestAuthentication`. A request that comes through the ingress gateway has its token checked there, and the gateway writes the claims; a workload that calls an application directly, inside the mesh, reaches the application's sidecar, whose `CUSTOM` check runs before any `RequestAuthentication`. It can send a token it made itself, with claims that look right, and the header of those claims beside it: the header equals the token's claims, so the adapter believes it.
- **Envoy Gateway does the same in its own order of filters**, until the operator puts the JWT check first with the `filterOrder` of the `EnvoyProxy`. It also hands the adapter neither the metadata nor a header of the claims it checked, so the caller sends the claims itself.

Two things follow when the adapter believes claims nobody checked:

- **Hodor records a decision about a forged subject.** The adapter asks `evaluate` as the application's client about whoever the token names, and the record of decisions holds a question nobody could ask.
- **The answer tells the caller what Hodor decided.** When Hodor denies, the adapter answers `403`. When Hodor allows, the request goes on to the application's `RequestAuthentication`, which refuses the forged token with `401`. A workload of the mesh learns, for any person and any route, whether that person holds the role.

Checking tokens at the ingress gateway, as the service mesh guide asks while this is missing, protects only the requests that come through it. The proxy's own order is not the adapter's to choose, and differs from one proxy to the next.

Hodor publishes the keys that sign a tenant's tokens: its discovery document names `<issuer>/oauth2/jwks` as `jwks_uri`, a set of the pending, active and retiring versions of every signing algorithm, answered with `Cache-Control: public, max-age=300` so that a revoked version disappears for everyone within five minutes ([the published key set](../architecture/contexts/keys.md#the-published-key-set)). The server already fetches and keeps the keys a client publishes at its address, in each server's memory, fetching again for a `kid` it does not know ([Decision 0079](0079-keys-at-a-client-s-address-kept-in-memory.md)). `hodor-ext-authz` cannot reuse that code: it depends on no crate of the workspace but `hodor-observability` ([Decision 0058](0058-hodor-ext-authz.md#what-hodor-ext-authz-does)), and `ClientKeySets` lives in the OAuth context. The pattern carries over.

## Decision

- **When the configuration reads tokens, the token is the bearer token in `Authorization`, and `hodor-ext-authz` checks its signature itself.** The claims it decides on are that token's own, read after the signature holds; then `iss`, `aud`, `exp` and `sub` are checked as before. Whatever the proxy checked, or did not check yet, changes nothing.
- **The keys are the tenant's published key set, read at Hodor's own address.** The set is the one discovery names, `<issuer>/oauth2/jwks`, fetched at `hodor.url` followed by `/t/<slug>/oauth2/jwks`, the address the adapter already uses for the token endpoint and `evaluate`: inside a mesh, the issuer's public address may not be reachable from the adapter's pod, or reachable only through the ingress gateway. Discovery itself is not read, since its `jwks_uri` names the public address, and the path is fixed by Hodor.
- **The set is kept in the adapter's memory, bounded, and fetched again for an unknown key**, as Decision 0079 does for a client's keys:
  - a set is used for **five minutes** after it was fetched, and never after, the time Hodor's answer allows it to be kept, so that a revoked key stops being accepted within five minutes;
  - a token whose `kid` the kept set lacks fetches the set again, and so does the first token after the five minutes, but **at most once every ten seconds**, counted when a fetch starts, whether it answers or not. Requests that arrive while a fetch runs wait for it and use what it answered, and do not fetch again;
  - a fetch takes at most `hodor.timeout_milliseconds`, reads at most 64 kibibytes, follows no redirect, and keeps at most 32 keys; a fetch that fails keeps the set that was kept, until its own five minutes end;
  - only keys Hodor publishes are read: `kid`, `alg` and the public parts of an EC key on P-256, an RSA key of at least 2048 bits, or an Ed25519 key; a key with a private part, another `use` than `sig`, or a type that does not fit its algorithm is left out.
- **Only the algorithms Hodor signs with are accepted: `ES256`, `RS256`, `PS256` and `EdDSA`**, named exactly. The header must name a `kid`, and the key of that `kid` must have the header's algorithm. `none`, every HMAC algorithm, and anything else are refused before a key is looked for, so a public key is never used as a secret. A header with `crit` is refused, since the adapter understands no extension.
- **A token whose signature fails is denied before Hodor is asked anything.** No access token is asked for and `evaluate` is not called, so Hodor records no decision about it.
- **Every failure is the same denial.** A token that is not a JSON Web Token, an algorithm refused, a `kid` not in the set, a set that cannot be fetched, a signature that does not hold, and claims that fail are answered as every other denial: `PERMISSION_DENIED` with an HTTP `403` and no body. The reason is logged, never sent.
- **The configuration's `token` names that tokens are read: `"bearer"`.** The two forms written before stay readable, and mean the same, with one more rule each:
  - **`{"header": "<name>"}`**: the named header is no longer where the claims come from and is not needed. A request that still carries it is denied unless it holds exactly the token's claims part, as before, and when it comes without a bearer token.
  - **`{"metadata": {…}}`**: the metadata is no longer read for claims. A request whose metadata holds claims without a bearer token is denied: the proxy checked a token and did not forward it, as Envoy's JWT filter does without `forward: true`, and deciding on the caller's identity instead would act for someone else.
  - A request with no bearer token and nothing in those places is decided on the caller's identity, as before.

## Consequences

- A workload inside the mesh that sends a token it made, directly to an application, is denied with `403` by the adapter, before Hodor is asked: nothing is recorded, and the answer is the one every other denial gets, so it tells nothing. Checking tokens at the ingress gateway, and putting Envoy Gateway's JWT check first, are no longer needed for `hodor-ext-authz`; they remain good practice, since a proxy that refuses a token first spares the check.
- The claims header becomes unnecessary. Istio's `outputPayloadToHeader` is not needed for the adapter, and behind Envoy Gateway the caller no longer sends its claims beside its token. A configuration that names a header keeps working, with the header checked when it is present.
- The proxy must pass the `Authorization` header to the check. Istio's sidecar does, since it asks before its own JWT filter; a proxy whose JWT filter runs first must forward the token: `forward: true` in Envoy, `forwardOriginalToken: true` in Istio. A configuration that read claims from the metadata of a JWT filter that removed the token now denies those requests, and says why in its log.
- Each replica of the adapter fetches the set from Hodor at most once every ten seconds, and once every five minutes in a steady state. A burst of unknown `kid` values reaches Hodor as one fetch per replica every ten seconds; each fetch asks Hodor to make sure every signing algorithm has an active key, which Hodor does on every read of the set.
- A key Hodor revokes is accepted by the adapter for up to five minutes after the last fetch, as by any relying party that keeps the set as long as Hodor allows. A key Hodor rotates in at once, without publishing it first, is accepted from its first token, or within ten seconds when another fetch came just before.
- The adapter depends on `aws-lc-rs` for the signatures, the library Hodor signs with, already in its tree through `rustls`. It reads its own small part of JSON Web Signatures; no library of JSON Web Tokens is added.
- `hodor-ext-authz` was not released before this, so no running configuration of a release breaks; one built from the development branch with `token.metadata` must forward the token.
- Threat-Mesh-19 records the threat and its control; Threat-Mesh-14 now names the signature.

## Alternatives considered

- **Keeping the proxy's check, and asking operators to check tokens at the ingress gateway.** Nothing to build. Set aside: it protects only requests through the gateway, depends on each proxy's order of filters, and the demonstration showed that Istio and Envoy Gateway both ask before they check by default.
- **Asking Hodor to introspect each token.** Hodor would check the signature, the register of access tokens and revocation. Set aside here: it adds a call to every check, needs the adapter's clients to be allowed to introspect, which widens what a compromised adapter can do (Threat-Mesh-07), and introspection is a decision of its own, which a cache of decisions would have to consider too.
- **Reading discovery at start, and the `jwks_uri` it names.** It follows the issuer exactly. Set aside: the address it names is the public one, and the adapter reaches Hodor only at `hodor.url`; the path is Hodor's own and does not change.
- **A setting for the key set's address.** It would let the set be read elsewhere. Set aside until someone needs it: the set is Hodor's, and Hodor is at `hodor.url`.
- **Reusing `ClientKeySets` of the OAuth context.** One implementation. Set aside: the adapter depends on no context crate, and the rules differ: one set for one tenant, kept five minutes as Hodor's answer allows, not an hour as OpenID Connect expects of a client's keys.
- **Keeping the set for an hour, and fetching it again at most once a minute, as Decision 0079 does.** Fewer fetches. Set aside: Hodor promises that a revoked key disappears within five minutes, and the address is Hodor's own, inside the cluster, so ten seconds between fetches costs little and accepts a key rotated at once sooner.
- **Accepting `ES256` alone**, the algorithm of every access token Hodor issues. Narrower. Set aside: the four are the algorithms Hodor signs with and publishes, each key is bound to its own algorithm, and the audience already refuses an ID token signed with another.
- **Requiring `typ` `at+jwt`.** It would refuse an ID token by its type as well as by its audience. Set aside for now: the audience refuses it already ([Decision 0077](0077-ext-authz-checks-the-audience.md)), and the tokens Hodor issues through every grant would have to be checked to carry it first.
- **Dropping `token.metadata` and `token.header`, and refusing a file that names them.** One form only. Set aside: configurations written before keep working, the header still catches a caller that sends claims that are not its token's, and the metadata form catches a proxy that removed the token.
