# Decision 0071: An intermediate is signed from what its request asks, within the authority; withdrawing it stops Hodor trusting its key; signing has a permission, a role and a scope of its own

Status: Accepted

## Context

[Decision 0030](0030-optional-certificate-authority.md) lists what a certificate signing request must meet before the tenant's certificate authority signs it: an authority with a path length of zero, names within the trust domains, name constraints copied in and never widened, a key of a known kind and size, a lifetime within the tenant's bound. [Decision 0062](0062-the-certificate-authority-of-a-tenant.md) narrows the name constraints to DNS names and addresses. Issue-117 builds the signing, and has to settle what those decisions leave open:

- what a request has to say, and what Hodor writes whatever it says, since the meshes' tools write requests in their own ways: cert-manager asks for an authority without a path length, OpenSSL writes whatever its configuration says;
- where an administrator asks to narrow the name constraints;
- what "withdrawn" means to Hodor, which keeps no revocation list and whose trust in the authority comes from one bundle that never names an intermediate;
- who may sign, now and for `hodor-cert-manager-issuer` (Issue-118), whose client must hold "only the scope to ask for signatures".

## Decision

### A request asks; Hodor checks it and writes the rest itself

A request is a PKCS#10 certificate signing request in PEM, signed by the key it asks a certificate for. It is signed only if it meets every rule below, each refused with a code of its own and the reason as its detail ([signing intermediates](../architecture/contexts/keys.md#signing-intermediates)):

- **It reads and proves its key.** Its signature is checked with its own public key, so that nobody gets a certificate for a key they do not hold. Its subject is not empty.
- **It asks for an authority.** Its basic constraints say `cA`. A path length of zero is accepted, and so is none, which is how cert-manager asks; a path length above zero is refused. Hodor writes zero in every certificate it signs, whatever was asked.
- **Its names are within the authority's trust domains.** Every URI has the host of one of them, every DNS name is one of them or under one, and nothing of another kind is named.
- **Its name constraints narrow and never widen.** The narrowing is asked in the request itself, in its own name constraints extension, as cert-manager writes it from a `Certificate`: permitted DNS names that are trust domains of the authority or names under them, and excluded DNS names. A permitted name outside the trust domains, or a permitted subtree of another kind, widens and is refused; a URI subtree is refused too, since an intermediate never carries one (Decision 0062). Without a narrowing, the intermediate is permitted the authority's trust domains as DNS names. Every address stays excluded.
- **Its key** is ECDSA on P-256 or P-384, or RSA of 3072 to 8192 bits, and is not the authority's own key.
- **Its lifetime**, which the administrator gives in days or leaves to the bound, is at most the authority's bound on intermediates and ends no later than the authority's own certificate.

Of the request, Hodor copies the subject, the public key and the subject alternative names, as they were written. Everything else it writes itself: the issuer, a serial number of its own, the validity, critical basic constraints with a path length of zero, critical `keyCertSign` and `cRLSign`, the key identifiers, and the critical name constraints. Other extensions a request asks for are not copied.

### Withdrawing an intermediate stops Hodor trusting its key, at once

Hodor's trust in what the authority signed comes from the trust domains of source `authority`, which hold the authority's certificate alone. A withdrawn intermediate cannot be taken out of them, so Hodor keeps a list beside them: the keys of the intermediates withdrawn in the tenant, named by the SHA-256 of their subject public key info. Every certificate path Hodor checks in that tenant, under any trust domain, is refused when one of its intermediates holds such a key. The next request of a workload under a withdrawn intermediate is refused.

Withdrawal is of the key, not of one certificate:

- withdrawing one intermediate withdraws every intermediate signed for the same key, which a mesh may have had signed again on renewal;
- a request for a key that was ever withdrawn is refused, so that signing it again cannot bring it back;
- a key leaves the list Hodor checks paths against when the last intermediate withdrawn for it expires, since an expired certificate is refused anyway; the intermediates are kept, so that it is still refused for signing;
- removing the authority keeps its intermediates and their withdrawals, so that a key withdrawn under one authority stays refused under the next.

The meshes keep using a withdrawn intermediate they hold until it expires: Hodor publishes no revocation list (Decision 0030). Short lifetimes are what limits that.

### One permission, one role and one scope sign

- **`certificate-authority:sign`** signs intermediates, and nothing else. It is a permission of its own, so that whoever only renews intermediates holds no permission to create, change or remove the authority, and whoever runs the authority can be kept from signing. The tenant administrator holds it; the auditor does not. Withdrawing an intermediate changes what Hodor trusts, so it needs `certificate-authority:write`; reading intermediates needs `certificate-authority:read`.
- **`certificate_signer`** is a third built-in role of Hodor's administration, holding `certificate-authority:sign` alone. It is the role of the workload that signs, so that the service account of `hodor-cert-manager-issuer` holds nothing else.
- **`certificate-authority:sign` is also a scope.** An API key of that workload holding it, and only it, signs and does nothing else ([API keys](0033-api-keys.md)); this works from Issue-117. The issuer of Issue-118 proves who it is with its mesh identity or a signed assertion, as Decision 0030 says, through a client of that service account that asks for an access token with the audience `urn:hodor:certificate-authority` and the scope `certificate-authority:sign`, as a client of the Authorization API asks for `authz:evaluate`. Issue-118 builds that: the signing operation takes such a token, and no other operation does.

`hodor-cli authority sign` signs as Hodor itself, as the other commands of the tool act: whoever runs it can read the database and use the key provider already.

## Consequences

- The meshes' tools need not agree on how they write a request: cert-manager's, Istio's and OpenSSL's are all signed as long as they ask for an authority within the trust domains, and every certificate Hodor signs says the same things.
- An administrator cannot narrow an intermediate by naming DNS names in the operation; the narrowing is in the request, signed by the key it is for, and the audit record keeps the hash of that request.
- A tenant whose intermediate leaked withdraws it once, and the key is refused for good in Hodor, whatever certificates were signed for it.
- Every check of a forwarded certificate reads the list of withdrawn keys of its tenant: one more read of the database per check, of a list that holds only keys whose last intermediate has not expired.
- A role is added to the two built-in roles of the administration, and the database's rule on built-in roles names it.

## Alternatives considered

- **Requiring a path length of zero in the request.** Set aside: cert-manager asks for an authority without one, and what matters is what the certificate says, which Hodor writes.
- **Narrowing named in the operation, by the administrator.** Set aside: the request is what the mesh asked for and signed, and two places to narrow would need a rule for when they disagree.
- **Withdrawing a certificate, by its serial number or its hash.** Set aside: a mesh that renews with the same key would bring the withdrawn key back with its next certificate.
- **Trusting only the intermediates Hodor signed and has not withdrawn**, a list of what is allowed rather than of what is refused. Set aside for now: only the authority's key can sign below it, and a list of what is allowed would refuse every workload for a moment after each renewal until the list is read again. It is the stronger rule if the authority's key is ever thought exposed, and then the authority is replaced instead.
- **A revocation list, or certificate status answered online, for the meshes.** Set aside, as Decision 0030 did: meshes check neither for their own intermediates.
- **Giving the signing workload `tenant_administrator` and a key of one scope.** It works with what exists. Set aside: the workload would hold every permission, and only its keys' scopes would stand between it and the whole tenant.
