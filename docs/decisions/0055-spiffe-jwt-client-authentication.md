# Decision 0055: A client of a service account is bound to one SPIFFE identifier, and its JWT-SVID is used once, remembered by the hash of what it signs

Status: Accepted

## Context

[Issue-106](../product/epics.md#slice-trust-domains-and-spiffe-epic-31) lets a workload prove who it is at the token, introspection and revocation endpoints with a JWT-SVID, as [draft-ietf-oauth-spiffe-client-auth-03](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-spiffe-client-auth-03) writes it. [Decision 0029](0029-hodor-in-a-service-mesh.md#a-workload-proves-who-it-is-in-one-of-three-ways) says what is checked: the signature by a key of the trust domain's bundle, `sub` the client's SPIFFE identifier, `aud` exactly the tenant's issuer, the expiry, and a JWT-SVID never presented twice, remembered by its hash since `jti` may be absent. [Decision 0042](0042-trust-domains.md) keeps trust domains and their bundles in the keys context. Neither says where the binding of a client to an identifier lives, how it is set, what the draft's optional `client_id` means for Hodor, which hash is remembered, nor how long a JWT-SVID may live.

What the draft leaves open, or allows and Hodor does not take:

- **The client identifier.** `client_id` is optional. Without it, the draft makes the SPIFFE identifier the client identifier, and the client the one whose `client_id` is that identifier. Hodor's client identifiers are UUIDs it makes.
- **The hash.** A JSON Web Signature in ECDSA can be changed into another that verifies too, by replacing the signature's `s` with its opposite modulo the curve's order. A hash of the whole token would see two tokens where there is one assertion.
- **The lifetime.** The draft does not bound it. SPIRE gives JWT-SVIDs five minutes unless configured otherwise, and caches one for a workload until half of its life has passed.
- **The registration metadata**, `spiffe_id` and `spiffe_bundle_endpoint`, for clients that register themselves or publish a Client ID Metadata Document. Hodor has neither.
- **Prefix matches** of identifiers ending in `/*`, which Decision 0029 already set aside.

## Decision

- **The binding is a setting of the client**, its SPIFFE identifier, kept in the OAuth context with the client's other settings. It is set and changed through the client's own operations of the administration interface, `POST /applications/{application_id}/clients` and `PATCH /clients/{client_id}`, as `spiffe_id`. No operation is added; the command-line tool and the console stay with Issue-109.
- **Only a client of a service account is bound**, and only with the method `spiffe_jwt`. A client with that method has an identifier and a principal; a client with any other method has no identifier. The administration interface checks, through the identity context, that the principal is a service account: an agent acts on a person's behalf and proves who it is with its own credentials ([Decision 0031](0031-workloads-are-users.md)).
- **The identifier is exact and unique in the tenant.** One identifier, written as the SPIFFE identifier specification writes it, with a path, without `*`; compared byte for byte. Two clients of one tenant are never bound to the same identifier, so that an identifier names one client, and a certificate forwarded by a proxy (Issue-107) or a caller's identity in a mesh (Issue-110) will name one too. Two tenants may each bind the same identifier, as each may trust a `cluster.local` of its own.
- **The trust domain is the one the identifier names, in the client's tenant**, found when the request comes, by its name. Binding a client does not need the trust domain to exist yet; until it does, or while it is checked by the mesh and has no bundle, the client cannot prove who it is with a JWT-SVID.
- **`client_id` is needed in practice.** The request without it is read as the draft says: the SPIFFE identifier would be the client identifier, no client of Hodor has such an identifier, and the answer is `invalid_client`, as the draft requires in that case.
- **`aud` holds the tenant's issuer and nothing else**, as one text or an array of one. Not the address of an endpoint, unlike a `private_key_jwt` assertion: the draft names only the issuer, and the issuer already tells one tenant from another.
- **A JWT-SVID is used once.** As soon as it has been checked, the SHA-256 of its first two parts, the header and the claims as they arrived, is remembered with the client until the JWT-SVID expires, in the register of client assertions, marked as a JWT-SVID's. The signature is left out of the hash, so that a JWT-SVID whose signature was rewritten is the same JWT-SVID. `jti` is neither needed nor used.
- **A JWT-SVID lives at most an hour ahead**, so that the register holds nothing for longer. One that expires further ahead is refused.
- **`iss` is not used.** The draft makes it optional and warns against finding keys through it. The keys are the bundle's, chosen by the client's identifier.
- **The algorithms are those Hodor already checks**: `ES256`, `RS256` and `PS256`. A bundle's key on P-384 or P-521 is kept by the keys context and cannot yet check a JWT-SVID.
- **The metadata names `spiffe_jwt`** among the methods of the token, revocation and introspection endpoints, and the [discovery section of the OAuth context](../architecture/contexts/oauth.md#discovery) names the version of the draft Hodor follows. A change of the draft is a change to Hodor, written in the changelog.

## Consequences

- A workload under SPIRE gets a token with no secret of its own. It sends a new JWT-SVID with each request to Hodor: SPIRE's cache can hand it the same one twice, and the second is refused. Keeping its access token until it expires, five minutes by default, keeps the number of requests low.
- An attacker who reads a JWT-SVID before it reaches Hodor can use it once, in its place, until it expires; the audience keeps it to one tenant of one Hodor. Decision 0029 accepts this; a workload that cannot accept it proves who it is with its certificate (Issue-107).
- `spiffe_x509` (Issue-107) binds a client the same way and reads the same setting; the rules above that name `spiffe_jwt` then name both methods.
- The register of client assertions holds rows of two kinds. They are removed by the same cleanup, once expired.

## Alternatives considered

- **Finding the client by its SPIFFE identifier when `client_id` is absent.** Simpler for a workload. Set aside: the draft says the client is then the one whose identifier is the SPIFFE identifier, and refusing what the draft refuses keeps Hodor from accepting requests another authorization server would not.
- **A table of bindings of its own**, beside the clients, so that one client could be bound to several identifiers. Set aside: Decision 0029 binds each client to exactly one identity, and a setting is checked with the client's other settings in one place.
- **Remembering the hash of the whole JWT-SVID.** Simpler to explain. Set aside for the reason above: an ECDSA signature can be rewritten.
- **Requiring `jti`**, as RFC 7523 does. Set aside: SPIFFE does not require it, and SPIRE does not always put one.
- **Accepting the token endpoint's address in `aud`**, as for `private_key_jwt`. Set aside: the draft names the issuer as the sole value.
- **Letting an agent's client use `spiffe_jwt` too.** Set aside for 0.4.0, as the issue binds a service account; it can be allowed later without breaking anything.
