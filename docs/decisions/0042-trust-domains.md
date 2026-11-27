# Decision 0042: Trust domains are kept by the keys context, under its permissions, and a bundle replaces the one in force only when it reads and does not go back

Status: Accepted

## Context

[Issue-105](../product/epics.md#slice-trust-domains-and-spiffe-epic-31) gives a tenant its trust domains: a name and a bundle, uploaded by an administrator or fetched from a SPIFFE bundle endpoint through the guarded outbound client and refreshed by the worker, or marked as checked by the mesh. [Decision 0029](0029-hodor-in-a-service-mesh.md#a-workload-proves-who-it-is-in-one-of-three-ways) says what a trust domain is for and that it belongs to a tenant. It does not say which context keeps it, nor how a bundle is read, nor what happens when a fetched one is wrong.

Three contexts will read trust domains:

- the OAuth context checks a JWT-SVID against a bundle (Issue-106) and a forwarded certificate against one (Issue-107), at the token, introspection and revocation endpoints;
- the certificate authority of [Decision 0030](0030-optional-certificate-authority.md) signs only within the tenant's trust domains, and Hodor's own trust domains trust its bundle without anyone uploading it (Issue-116); its key lives in the key provider of the keys context;
- the administration interface manages them.

The SPIFFE specifications say how a bundle is written, what an element of an unknown kind is (ignored), and that a client of a bundle endpoint should poll at the bundle's refresh hint, five minutes when it has none. They say nothing of a bundle that does not read, of a fetch that fails, or of a bundle older than the one in force.

## Decision

- **The keys context keeps trust domains.** It already answers which keys a signature may be checked against, for the tenant's own keys; a bundle is the same answer for keys the tenant trusts. It is a base context: the OAuth context depends on it already, and the authority of Milestone 12 will sit beside the key provider it needs, in the same context, so that its bundle reaches the tenant's trust domains without a dependency between two contexts of one layer. It is specified in [the keys context](../architecture/contexts/keys.md#trust-domains).
- **The permissions are those of keys**: `keys:read` to see trust domains and their bundles, `keys:write` to add, replace and remove them. A bundle is public, and an auditor who reads the tenant's key versions reads what it trusts as well. No permission is added.
- **A trust domain has exactly one of three sources**: a bundle an administrator uploads, a bundle endpoint, or the mesh. A trust domain checked by the mesh has no bundle, so nothing can be checked against it but a forwarded identity (Issue-107).
- **A bundle is read whole, or refused whole.** Elements of an unknown `use` or key type are ignored, as SPIFFE requires. An element of a known kind that breaks a rule, such as a private part, an `x509-svid` element with a `kid` or with two certificates, or a `jwt-svid` element without a `kid`, refuses the whole bundle. Keeping part of a bundle would let what an administrator reads back differ from what the sender meant.
- **What is not right keeps what was.** A bundle that does not read, a fetch that fails, an endpoint at an address that may not be called, and a fetched bundle whose sequence number goes back or stays the same with other contents all leave the bundle in force as it is, and are recorded on the trust domain. Saving a trust domain fetches its bundle once and is refused, storing nothing, when that fails.
- **Bundle endpoints are fetched through the guarded outbound client**, checked by `DestinationCheck` when they are saved and by the client at every fetch, HTTPS only, ten seconds and 64 kibibytes at most, **without following redirects**, as for every address a tenant names ([outbound HTTP](../security/outbound-http.md)).
- **The worker fetches on leases**, as it sends webhooks and logout tokens: a short transaction leases a due trust domain, the fetch happens outside any transaction, and a second short transaction records it only if the trust domain is still as it was leased. The refresh hint is bounded between one minute and one day.
- **Every change is an audit event**: adding, replacing and removing by an administrator, every bundle the worker puts in force, and the first failure of a run of failed fetches. Events name the bundle by its SHA-256 and count its authorities, never the keys or the address.
- **The administration interface gets five operations in this issue**: listing, adding, reading, replacing and removing trust domains. The cross-tenant suite and the worker's tests need them. Issue-109 keeps the command-line tool, the console and the clients bound to identities.

## Consequences

- A tenant's trust domains change only through the administration interface and the worker. A trust domain of one tenant is never read for another, whatever its name: two tenants can both trust a `cluster.local` of their own.
- An endpoint that keeps failing leaves its trust domain on its last good bundle. The mesh's authorities rotate in days; a bundle that stops following them for longer shows in the trust domain's `failing_since` and in the audit log.
- A bundle endpoint that redirects cannot be used as it is. The administrator names the address it leads to.
- Whether an `x509-svid` element's certificate is an authority that holds the element's key is checked only when certificates are checked against the bundle (Issue-107). Until then a bundle with a wrong certificate is kept, and trusts no certificate that does not chain to it.
- When the authority of Milestone 12 is built, it adds its bundle to the tenant's trust domains in the same context, through the same storage.

## Alternatives considered

- **The OAuth context.** It is the first to check an SVID. Set aside: the authority of Milestone 12 belongs beside the key provider, and could not reach trust domains kept by the OAuth context without a dependency the layers forbid.
- **A context of its own for workloads in a mesh.** It would hold trust domains, and later the identities bound to clients. Set aside: one aggregate does not need a crate, and the identities bound to clients are the OAuth context's, with its clients.
- **New permissions, `trust-domains:read` and `trust-domains:write`.** Finer. Set aside: trusting an authority is the same kind of decision as rotating or revoking a key, and every role that holds one holds the other.
- **Following temporary redirects**, as the `https_web` profile suggests. Set aside: a public address could redirect Hodor to a private one, and the guarded client follows none for any context.
- **Keeping the readable part of a bundle that breaks a rule.** More forgiving of a careless endpoint. Set aside for the reason above.
- **Accepting any fetched bundle that reads, whatever its sequence.** Simpler. Set aside: an older bundle replayed would bring back an authority the trust domain had stopped trusting.
