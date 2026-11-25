# Decision 0062: The certificate authority of a tenant lives in the keys context, is switched on by one setting, and writes name constraints that Hodor's own chain checking reads

Status: Accepted

## Context

[Decision 0030](0030-optional-certificate-authority.md) says what the certificate authority of a tenant is for and what protects its key. Issue-116 builds the authority itself, and has to settle what that decision leaves open:

- how an installation turns the authority on, and what "nothing of it is reachable" means when it is off;
- where the authority's key lives in the keys context, which already holds key sets whose signing keys are published and rotated;
- how the name constraints are written, so that a verifier honoring them refuses a certificate for a name outside the tenant's trust domains;
- how Hodor's own trust domains trust the authority's bundle "without anyone uploading it" ([Decision 0042](0042-trust-domains.md#consequences));
- who may act on it, and what the audit log records of each signature.

One constraint comes from the library Hodor checks certificate paths with. Issue-107 checks a certificate a proxy forwards with `rustls-webpki`, and `rustls-webpki` does not read name constraints on URIs: when an authority of the path constrains URIs and a certificate below it names a URI, it refuses the certificate, whatever the URI. A SPIFFE identity is a URI. An authority whose constraints the meshes honor, as Decision 0030 asks, would therefore make Hodor refuse every workload certificate under it.

## Decision

### One setting turns the authority on for an installation

`HODOR_CERTIFICATE_AUTHORITY` is `off` (the default), `on` or `development`.

- **`off`**: the authority does not exist. The administration interface has no route for it and its OpenAPI document does not name one, no bundle endpoint is served, no discovery document mentions it, and the console does not list its permissions among what a person may do. An installation that turns it off after tenants made authorities keeps their rows and their keys, and the trust domains they added stay trusted until an administrator removes them.
- **`on`**: an administrator of a tenant may create the tenant's authority, on a key provider that signs inside itself (below).
- **`development`**: the same, and the local key provider is accepted. Every answer about the authority then says `development: true`, and the authority's certificate names itself as one for development.

The authority needs the keys context, so the server refuses to start with `on` or `development` and no `HODOR_SECRET_KEYS`.

A tenant turns its authority on by creating it and off by removing it. No tenant setting is added: a tenant without an authority sees no change, as Decision 0030 asks.

### The authority is an aggregate of the keys context, with a key of its own

The authority sits beside the key provider and the trust domains it needs, as [Decision 0042](0042-trust-domains.md) planned. A tenant has at most one. Its key is not a version of a key set: it is never published in the tenant's key set, never signs a token, and is never rotated. It is made by the key provider for the authority's own identifier, kept with the authority, and used by the provider that made it, as every version is.

- **The provider.** The authority's key is made by OpenBao whenever OpenBao is configured, whatever `HODOR_KEY_PROVIDER` says of token signing keys, since an operator may keep those local and still want the authority. Without OpenBao, it would be made by the local provider, which keeps keys under the installation's root keys: creating an authority is then refused with `keys.authority_provider_unsuitable`, except under `development`. The rule asks whether the provider signs inside itself, a property each provider declares, not for OpenBao by name, so that a cloud key management service fits later.
- **A root or an intermediate.** A root is signed by its own key at once. An intermediate starts awaiting its certificate: Hodor answers a certificate signing request made with the authority's key, the tenant's own root signs it outside Hodor, and an administrator installs the certificate, which Hodor checks before taking it. Either is an authority with a path length of one, so that it can sign the intermediates of the tenant's meshes, which sign workloads, and nothing deeper.
- **Lifetimes.** A root lives 5 years unless the administrator says otherwise, at most 10. The bound on the intermediates it will sign (Issue-117) is kept on the authority: 30 days unless set, at most 365.

### Name constraints are written for URIs, DNS names and addresses

The authority's certificate, or the request for it, carries a critical name constraints extension (RFC 5280, section 4.2.1.10):

- **permitted**, for each trust domain of the authority, the URI host `<trust domain>`, which a SPIFFE identity `spiffe://<trust domain>/…` must have exactly, and the DNS name `<trust domain>`, under which Linkerd builds its identities;
- **excluded**, every IPv4 and IPv6 address, `0.0.0.0/0` and `::/0`, so that no certificate below it names an address.

A trust domain of an authority must therefore be a DNS name: labels of lowercase letters, digits and `-`, separated by `.`. The SPIFFE rule also allows `_`, which a DNS constraint cannot hold.

A verifier that honors URI constraints, as Go's (Istio, Linkerd, SPIRE) and OpenSSL's do, refuses any certificate below the authority for a URI, a DNS name or an address outside them. Go reads a URI constraint without a leading `.` as the host and its subdomains, OpenSSL and Hodor as the host alone; both refuse every name outside the tenant's trust domains.

### Hodor's own chain checking reads the URI constraints itself

`rustls-webpki` fails closed on URI constraints, so Hodor does not hand them to it:

- **The anchor.** When Hodor checks a path that ends at a certificate whose name constraints include URIs, it gives `rustls-webpki` that certificate as a trust anchor whose constraints leave the URI subtrees out, and keeps them aside. `rustls-webpki` checks the signatures, the validity, the authorities and path lengths, the usages and the DNS and address constraints. Hodor then checks every URI of every certificate below the anchor against the URI subtrees it kept: each must have a host that a permitted subtree allows and that no excluded subtree names. `hodor-adapters-crypto` holds this check, `UriConstraints`, and `check_path`, which does both; the check of a certificate a trusted proxy forwards ([Decision 0056](0056-forwarded-client-identity.md)) goes through it.
- **The intermediates below it.** Decision 0030 copies the authority's name constraints into each intermediate it signs. This decision narrows that for URIs: Issue-117 copies the DNS and address constraints, narrowed if asked, and writes no URI constraint into an intermediate. The authority's own URI constraints already bind every certificate below it, since constraints of every authority of a path apply; copying them into an intermediate would make `rustls-webpki` refuse every workload under that intermediate. An intermediate is therefore not narrowed to fewer of the tenant's trust domains by URI; it is by DNS name.

The authority's own certificate is the anchor its bundle publishes, so every path Hodor checks under it ends at a certificate whose constraints Hodor reads this way.

### The bundle is published, and Hodor's trust domains hold it

- **The bundle endpoint** is `GET /t/{tenant}/certificate-authority/bundle`, under the tenant's issuer, without authentication: a SPIFFE bundle (the `https_web` profile) with one `x509-svid` element, the authority's certificate and its key; `spiffe_sequence`, the moment the authority became active in seconds since 1970, so that a bundle of an authority made later never goes back; and a refresh hint of 300 seconds. It answers `404` when the tenant has no active authority. It is the same bundle for each of the authority's trust domains.
- **Hodor trusts it through a fourth source of trust domain, `authority`.** When the authority becomes active, a trust domain of source `authority` is added for each of its trust domains, holding the authority's bundle. Every check that reads a trust domain's bundle, the forwarded certificates of Issue-107 among them, trusts the authority without anyone uploading anything. Such a trust domain cannot be replaced through the trust domains' operations, `keys.trust_domain_of_authority`, and the worker never fetches it; it can be removed, which stops Hodor trusting that trust domain, and it is removed with the authority.
- **A name already trusted is refused.** Creating an authority for a trust domain the tenant already has, from another source, is refused with `keys.authority_trust_domain_taken`, and so is installing an intermediate's certificate when one has been added since. The administrator removes that trust domain first: two sources for one trust domain would let one change what the other means.

### Permissions of its own, and every signature audited

- `certificate-authority:read` sees the authority, its certificate, its request and its name constraints; the tenant auditor holds it. `certificate-authority:write` creates it, installs its certificate and removes it. The administrator holds both. Signing intermediates, and the scope a signing client holds, come with Issue-117.
- Every signature the authority's key makes is an audit event, `keys.authority_signed`, in the same transaction that keeps what was signed: who asked, what was signed (`certificate` or `certificate_signing_request`), the SHA-256 of the signed part, the serial number of a certificate, and the trust domains it was signed for. Creating, activating and removing the authority are events too. No event carries a key, a certificate or a request.

## Consequences

- An installation that never sets `HODOR_CERTIFICATE_AUTHORITY` serves nothing new: the cross-tenant suite and the operation counts see the same interface as before.
- The authority's key stays in OpenBao when the authority is removed: Hodor's policy cannot delete a key. An operator who wants it gone deletes it in OpenBao.
- Turning the authority off on an installation does not stop Hodor trusting what the trust domains of source `authority` hold. An administrator removes those trust domains to stop it.
- An intermediate under the authority cannot be narrowed by URI. A mesh intermediate may sign for any of the tenant's trust domains of the authority; the URI constraints of the authority still keep it within them.
- Hodor's chain checking has a part of its own for URI constraints. It is small, and it runs only after `rustls-webpki` has checked everything else.

## Alternatives considered

- **No URI constraints, DNS constraints only.** Every verifier would accept them. Set aside: a DNS constraint says nothing of a URI, and a SPIFFE identity is a URI, so the authority would not be limited to the tenant's trust domains for SPIFFE at all.
- **Hodor's own path checking in place of `rustls-webpki`.** It could read URI constraints anywhere in a path, intermediates included. Set aside: signatures, path building and validity are what an audited library is for, and the part Hodor adds is only the matching of hosts against subtrees.
- **The authority's key as a version of the signing key set.** It would reuse the storage and the lifecycle. Set aside: the signing key set is published as the tenant's JSON Web Key Set and rotated on a schedule, and the authority's key must be neither.
- **Adding the authority's certificate to the bundle of an existing trust domain of the same name.** No refusal. Set aside: a fetched bundle replaces the one in force, so the authority would disappear at the next refresh, or be kept through rules a fetch does not have.
- **A tenant setting beside the authority.** Set aside: creating the authority is the tenant's choice, and a setting that says "on" with no authority behind it means nothing.
