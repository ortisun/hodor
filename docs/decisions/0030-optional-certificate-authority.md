# Decision 0030: An optional certificate authority per tenant signs the intermediates of the tenant's meshes, only within its trust domains, and never a workload's own certificate

Status: Proposed (requested by the project owner)

## Context

Every service mesh runs a certificate authority of its own, and so does SPIRE. Two meshes of one tenant, such as an Istio cluster and a Linkerd cluster, trust each other only when an operator gives both the same root by hand. Each mesh also expects to keep issuing its workloads' certificates itself, and each accepts an authority *above* it:

| Mesh | How it takes an authority above its own |
|---|---|
| Istio | An intermediate in the `cacerts` secret, the plug-in authority. A cert-manager `Certificate` can keep that secret current |
| Linkerd | Its trust anchor is the root. Its identity issuer, an intermediate, is kept by cert-manager (`identity.externalCA`), typically for 48 hours, renewed 25 hours before it expires |
| SPIRE | An upstream authority plugin: `disk`, `certmanager`, `vault`, `awspca`, `gcpcas`, `ejbca`, `spire` |
| Consul | Providers: its own, HashiCorp Vault, Amazon Web Services Private Certificate Authority. None of them takes an intermediate from another authority |

cert-manager takes outside issuers: a controller signs the `CertificateRequest`s addressed to its own kind, and must sign only those that have been approved. istio-csr is the other route into Istio, but it signs every workload's certificate through cert-manager, which is the path Decision 0028 leaves out.

The owner asked for the authority to be planned, as a feature a tenant turns on ([Decision 0028](0028-what-0.4.0-holds.md)). Neither Keycloak nor Ory Hydra has one.

Today Hodor's only key provider is the local one: keys are wrapped under the installation's root keys and used inside the server ([the keys context](../architecture/contexts/keys.md#the-local-provider)). Anyone who holds the database and the server's configuration holds every key. The providers of key management services are planned for Phase 9 (Requirement-Key-03). For the owner, the authority's key goes into OpenBao, and the cloud's key management services stay possible.

## Decision

### It is off unless both the installation and the tenant turn it on

- An installation offers the authority only when its operator turns it on. Otherwise no route exists, nothing is published and nothing appears in any metadata. The installation pages say what turning it on means for the protection of keys.
- A tenant has no authority until an administrator creates one. A tenant without one sees no change.
- Nothing else depends on it. Accepting certificates and JWT-SVIDs ([Decision 0029](0029-hodor-in-a-service-mesh.md)) works the same with or without it.

### What it is

- **One authority per tenant: a root certificate and its key.** The key is generated in Hodor's [key provider](../architecture/contexts/keys.md#the-key-provider) as ECDSA P-256 ([Decision 0008](0008-cryptography.md)), by a provider that signs inside itself, and never leaves it (see [what protects the key](#what-protects-the-key)). Instead of being its own root, the authority can be an intermediate under a root the tenant already has: Hodor makes the request, and the tenant's own root signs it outside Hodor.
- **It is limited to the tenant's trust domains.** Its certificate carries name constraints that permit only the trust domains an administrator names for it: the URI `spiffe://<trust domain>` for SPIFFE identities, and the DNS names Linkerd builds under its own trust domain. A certificate below it for any other name is not valid for any verifier that honors name constraints.
- **It signs intermediate certificates only.** A request is signed only when:
  - it asks for an authority with a path length of zero;
  - its names are within the authority's trust domains, and the name constraints are copied into it, narrowed if asked, never widened;
  - its key is ECDSA P-256 or P-384, or RSA of 3072 bits or more;
  - its lifetime is within the tenant's bound, 30 days by default and never more than one year.

  It never signs a certificate that is not an authority, so a workload's own certificate always comes from its mesh.
- **Its bundle is published per tenant**, as a SPIFFE bundle endpoint (the `https_web` profile) under the tenant's issuer. Meshes, trust-manager and federated SPIRE servers read it. Hodor's own trust domains of [Decision 0029](0029-hodor-in-a-service-mesh.md) trust it without anyone uploading it.
- **Withdrawing an intermediate takes effect in Hodor at once and in the meshes as it expires.** It is removed from Hodor's own trust immediately. A mesh that holds a copy keeps using it until it expires, which is why lifetimes are short. Revocation lists and OCSP are not published.
- **Every signature is an audit record**, with who asked, the request's hash, the serial number and the names signed for.

### How a mesh gets its intermediate

1. **By hand, through the administration interface or `hodor-cli authority sign`.** An administrator sends a certificate signing request (PKCS#10) and gets the certificate back. This serves Istio's `cacerts`, and SPIRE's `disk` plugin, and it requires someone to repeat it before the certificate expires.
2. **Through `hodor-cert-manager-issuer`, an outside issuer for cert-manager.** A controller, a binary of the workspace written with the Kubernetes client for Rust, signs through Hodor the approved `CertificateRequest`s addressed to it, and only requests for an authority. It proves who it is to Hodor with its own mesh identity or a signed assertion, through a client holding only the scope to ask for signatures. This keeps Linkerd's identity issuer, SPIRE's `certmanager` plugin and Istio's `cacerts` current without anyone repeating anything.

Consul is not served in 0.4.0: none of its providers takes an intermediate from another authority.

### What protects the key

- **The authority needs a key provider that signs inside itself and never exports a key.** The local provider does not, so an authority cannot be created on it. The one exception is an installation whose operator sets a setting of its own saying the authority is for development; the authority's page then says so on every screen.
- **OpenBao is that provider in 0.4.0** (Requirement-Key-06). Milestone 12 pulls it forward from Phase 9, in `hodor-adapters-kms`:
  - Keys are made in OpenBao's Transit secrets engine as ECDSA P-256, not exportable and with no plaintext backup. Hodor asks OpenBao to sign and gets the signature back: in the DER encoding for certificates, and in the JOSE encoding for tokens.
  - Each key is named for its tenant and its version, and Hodor's policy in OpenBao allows signing and reading public keys under Hodor's own mount, nothing else. Hodor signs in to OpenBao with Kubernetes authentication or an AppRole.
  - The provider serves every key of the key provider, not only the authority's: an operator can put the tenants' token signing keys in OpenBao too. The root keys of [secrets at rest](../security/secrets-at-rest.md) stay as they are in 0.4.0.
- **The cloud's key management services fit the same port.** The authority asks for a provider that signs inside itself, not for OpenBao by name. Amazon Web Services key management service, Google Cloud key management service and Azure Key Vault (Requirement-Key-03) are such providers when they are built, in Phase 9 or earlier if the owner pulls one forward. Until then, OpenBao can itself be unsealed by a cloud key management service, so that its own keys rest on the cloud's.
- **Who may act.** Only administrators with a permission of their own can create the authority, sign, or change its bound. The signing client of `hodor-cert-manager-issuer` holds only the scope to ask for signatures, not to change anything.

## Consequences

- A tenant with the authority on has one root for all its meshes. An Istio cluster and a Linkerd cluster of that tenant trust each other's workloads without anyone copying a root by hand, and Hodor trusts both.
- Hodor becomes something that can make workloads trusted. Taking the authority's key is worth more to an attacker than taking a tenant's token signing key, since it reaches every workload of the tenant's meshes. The [threat model](../security/threat-model.md#service-meshes-and-certificates) lists what this adds.
- Hodor is on the path of an intermediate's renewal, not of a workload's. If Hodor is down, meshes keep issuing workload certificates until their intermediate expires: days with the defaults, not minutes.
- Turning the authority on means running OpenBao, with its own availability, upgrades and backups. If OpenBao is down, nothing new is signed, and with it holding the tenants' token signing keys, no token is issued either. Intermediates in use keep working until they expire.
- A cloud key management service can replace OpenBao for a tenant once its provider is built, without changing the authority.
- `hodor-cert-manager-issuer` is a Kubernetes controller, the first Hodor ships, with its own permissions in the cluster.

## Alternatives considered

- **Issuing every workload's certificate**, as istio-csr or a SPIRE server would. Set aside: Hodor would be on the path of every workload's start and every rotation, every few hours, and would compete with the mesh for a job the mesh already does.
- **An ACME or EST server.** Standard enrollment. Set aside: ACME proves control of a name, not a workload's identity, and cert-manager's outside issuer reaches the meshes with less.
- **Allowing the local provider for production authorities**, with the gap stated. Nothing more to run. Set aside: anyone holding the database and the configuration would hold every tenant's authority.
- **A cloud key management service first, instead of OpenBao.** Set aside because the owner chose OpenBao, which runs in any cluster and in development. The cloud's services keep the same port.
- **Revocation lists and OCSP for intermediates.** Set aside: meshes check neither for their own intermediates, and short lifetimes do the work.
- **No authority, only accepting certificates.** Set aside because the owner asked for it, as a feature a tenant turns on.
