# Architecture Decision Records

Format: context, decision, consequences, alternatives considered. A decision record is immutable once accepted; a change of mind is a new decision record that supersedes the old one.

All records below are **Proposed** unless marked otherwise: they become Accepted when the design review signs them off.

| # | Decision |
|---|---|
| [0001](0001-modular-monolith-clean-architecture.md) | Modular monolith with clean architecture per bounded context |
| [0002](0002-crate-consolidation.md) | Consolidate the proposed workspace from 26 to 24 crates |
| [0003](0003-context-communication.md) | Contexts talk through facades, service provider interfaces and outbox events |
| [0004](0004-token-formats.md) | JWT access tokens, opaque hashed refresh tokens and codes |
| [0005](0005-tenant-and-organization.md) | Tenant is the isolation boundary; organizations live inside it |
| [0006](0006-tenant-isolation.md) | Shared schema with `tenant_id` and forced row-level security |
| [0007](0007-postgres-required-redis-optional.md) | PostgreSQL is required; Redis is optional |
| [0008](0008-cryptography.md) | Cryptographic primitives and key handling |
| [0009](0009-authorization-engine-contract.md) | Authorization engine contract and one engine per namespace |
| [0010](0010-opa-integration.md) | Open Policy Agent through its official APIs; dedicated instances for tenant-authored Rego |
| [0011](0011-frontends-bff.md) | Hosted user interface on an interaction API; consoles behind a backend-for-frontend |
| [0012](0012-extension-strategy.md) | Traits first, webhooks second, WebAssembly plugins last |
| [0013](0013-auth-flow-as-data.md) | Authentication flows are versioned data interpreted by one engine |
| [0014](0014-saml-deferred-with-spike.md) | SAML is deferred to Phase 6 and gated by a security spike |
| [0015](0015-observability-stack.md) | OpenTelemetry for instrumentation, VictoriaMetrics for metrics (Accepted) |
| [0016](0016-design-system.md) | One token-based design system for the three frontends, with security patterns built in (how it is built is changed by 0018) |
| [0017](0017-external-identities-before-oauth.md) | Signing in with external identities comes before OAuth (Accepted) |
| [0018](0018-astryx-component-foundation.md) | Astryx is the foundation of the design system (Accepted) |
| [0019](0019-saml-signature-verification.md) | SAML signatures are verified with `xml-sec` behind a narrow profile (Accepted) |
| [0020](0020-console-on-the-hodor-session.md) | Until Hodor issues tokens, the admin console rides the administrator's Hodor session (Accepted) |
| [0021](0021-documentation-site.md) | The documentation site is built from `docs/` with MkDocs and Material, and published on GitHub Pages from `develop` |
| [0022](0022-installation-packages.md) | Hodor is installed from two packages kept apart from the development stack, and neither holds a secret |
| [0023](0023-what-0.2.0-holds.md) | 0.2.0 holds the OAuth server, strong authentication and the authorization engine, each cut to what makes it whole (Accepted) |
| [0024](0024-webauthn-checks.md) | WebAuthn is checked by Hodor's own code, over the cryptography it already has (Accepted) |
| [0025](0025-condition-language.md) | Conditions are Common Expression Language, interpreted by the `cel` crate in a crate of their own (Accepted) |
| [0026](0026-policy-checks-in-a-sandbox.md) | Policies are checked by the `opa` binary, run by the worker as a child process with nothing of its own (Accepted) |
| [0027](0027-what-0.3.0-holds.md) | 0.3.0 holds operations, groups and organizations with SCIM, workloads with webhooks, and what 0.2.0 left out (Accepted) |
| [0028](0028-what-0.4.0-holds.md) | 0.4.0 holds workloads proven by their certificates, Hodor in a service mesh, and an optional certificate authority per tenant |
| [0029](0029-hodor-in-a-service-mesh.md) | Hodor accepts the mesh's certificates and issues none to workloads; proxies check its tokens and ask its decisions through `hodor-ext-authz`; Linkerd gets policies written from Hodor's roles |
| [0030](0030-optional-certificate-authority.md) | An optional certificate authority per tenant signs the intermediates of the tenant's meshes, only within its trust domains, and never a workload's own certificate |
| [0031](0031-workloads-are-users.md) | Service accounts and agents are users of the identity context, and a client of the client credentials grant acts as one (Accepted) |
| [0032](0032-webhooks.md) | Webhooks are a context of their own, signed as Standard Webhooks say, and sent on leases outside any transaction (Accepted) |
| [0033](0033-api-keys.md) | API keys are credentials of workloads, recognized by their prefix, and never do more than their holder (Accepted) |
| [0034](0034-token-exchange.md) | An agent acts for a person through token exchange, with a bounded `act` chain, a policy of audiences per client and scopes that only narrow (Accepted) |
| [0035](0035-access-control-lists.md) | Access control lists are entries that only allow, read at every decision beside the roles (Accepted) |
| [0036](0036-codes-and-links-by-email.md) | A code or a link by email is an alternative of the flow, kept apart from the sign-in that asked for it, and counted as the first factor (Accepted) |
| [0037](0037-back-channel-logout.md) | Back-channel logout is made by the OAuth context from the end of a session, and sent by the worker on leases as webhooks are (Accepted) |
| [0038](0038-the-license.md) | Hodor is licensed under the MIT License; what it bundles keeps its own license (Accepted) |
| [0039](0039-enrolling-during-a-sign-in.md) | A second factor is enrolled during a sign-in at the last step of the flow, only by a person the policy holds back, and counts as that sign-in's second factor (Accepted) |
| [0040](0040-pairwise-subjects.md) | A pairwise client knows a person by an identifier of its sector alone, in every token, answer and logout it is given (Accepted) |
| [0041](0041-claim-mappers.md) | Claim mappers name their tokens, never a claim Hodor sets, and are bounded when they are saved (Accepted) |
| [0042](0042-trust-domains.md) | Trust domains are kept by the keys context, under its permissions, and a bundle replaces the one in force only when it reads and does not go back (Accepted) |
| [0044](0044-what-0.5.0-and-0.6.0-hold.md) | OpenID certification is two versions: 0.5.0 holds every OpenID Connect profile, 0.6.0 holds FAPI 1.0 Advanced, FAPI 2.0 and FAPI-CIBA |
| [0045](0045-request-objects-and-pushed-requests.md) | A request object and a pushed authorization request become the same pending request, kept per tenant by the hash of its reference, used once |
| [0046](0046-responses-through-the-browser.md) | Every response type and mode of OpenID Connect is offered per client; an access token through the browser only for a client an administrator marks so |
| [0047](0047-claims-and-the-person-s-claims.md) | The `claims` parameter asks only for claims the scopes and consent already allow, and a person keeps the standard claims of OpenID Connect |
| [0048](0048-encryption.md) | JSON Web Encryption with Hodor's own code over `aws-lc-rs`, for a short list of algorithms, with encryption keys per tenant |
| [0049](0049-dynamic-client-registration.md) | Dynamic client registration is off in every tenant until an administrator chooses initial access tokens, software statements or open registration, under a policy |
| [0050](0050-logout-and-session-state-in-the-browser.md) | Front-channel logout is a page of Hodor's that loads each client's address in a frame; session management reads a browser state that is not the session |
| [0051](0051-conformance-runs-and-certification.md) | Every certification plan runs in continuous integration, a core set on each pull request and all of them nightly; certification is asked for per version, in one batch per specification |
| [0052](0052-security-profiles.md) | A client is held to a FAPI security profile, checked when it is saved and at every request; under FAPI 2.0 its refresh tokens are not rotated |
| [0053](0053-dpop.md) | DPoP nonces are derived from a secret of the tenant, proofs are remembered by their `jti`, and access tokens and public clients' refresh tokens are bound |
| [0054](0054-backchannel-authentication.md) | A backchannel authentication request reaches the person on the account page, by email, and through the tenant's own authentication device service; poll, ping, and push outside FAPI |
| [0055](0055-spiffe-jwt-client-authentication.md) | A client of a service account is bound to one SPIFFE identifier, and its JWT-SVID is used once, remembered by the hash of what it signs (Accepted) |
| [0056](0056-forwarded-client-identity.md) | A forwarded identity is read from the one header the operator names, bound to a client by its SPIFFE identifier or its Linkerd identity, and checked with `rustls-webpki` in the cryptography adapter (Accepted) |
| [0057](0057-certificate-bound-access-tokens.md) | A token is bound to the certificate the proxy forwards when its client asks, and checked wherever Hodor accepts it as a credential (Accepted) |
| [0058](0058-hodor-ext-authz.md) | `hodor-ext-authz` asks `evaluate` as one client per application, all bound to its one mesh identity; an identity binds the clients of one service account; the Authorization API names a workload by its identity (Accepted) |
| [0059](0059-linkerd-policies-from-roles.md) | Linkerd policies are written from the roles in force into one file that is also the memory of the last run, in JSON documents, with an identity no workload has when nobody holds a role (Accepted) |
| [0061](0061-gateway-identities.md) | Behind a mesh's proxy, the forwarded address is read only from the ingress gateways the operator names by their identity, and the chart puts Hodor in Istio or Linkerd with one value (Accepted) |
| [0062](0062-the-certificate-authority-of-a-tenant.md) | The certificate authority of a tenant lives in the keys context, is switched on by one setting, and writes name constraints that Hodor's own chain checking reads (Accepted) |
| [0065](0065-where-the-standard-claims-come-from.md) | The identity context keeps a person's standard claims, and each source writes only what it can vouch for |
| [0068](0068-claims-of-every-consented-scope.md) | The `claims` parameter gives a claim of any scope consented to for the client, not only of the scopes of the request |
| [0071](0071-signing-intermediates.md) | An intermediate is signed from what its request asks, within the authority; withdrawing it stops Hodor trusting its key; signing has a permission, a role and a scope of its own (Accepted) |
| [0072](0072-the-state-hash-and-the-response-types-of-a-client.md) | An ID token through the browser carries `s_hash` whenever the request had `state`, and only a client of the authorization code has response types |
| [0074](0074-hodor-cert-manager-issuer.md) | `hodor-cert-manager-issuer` signs approved requests for an authority through the signing operation, which takes an access token for the audience of the certificate authority (Accepted) |
| [0075](0075-the-registration-settings-of-a-tenant.md) | A tenant has one registration policy for every way and one list of hosts for every address; an initial access token is spent under a lock of its row (Accepted) |
| [0076](0076-names-an-authority-leaves-to-its-meshes.md) | A tenant's certificate authority may leave URIs unconstrained and permit DNS names besides its trust domains, so that Istio and Linkerd run under it together (Accepted) |
| [0077](0077-ext-authz-checks-the-audience.md) | `hodor-ext-authz` denies claims whose audience is not the one its configuration names for the application |
| [0078](0078-every-pod-of-the-release-in-the-mesh.md) | `mesh.provider` puts every pod of the release in the mesh, `hodor-ext-authz` and `hodor-cert-manager-issuer` among them, and the network policy opens each one's ports, Linkerd's 4143 included, to its own callers (Accepted) |
| [0079](0079-keys-at-a-client-s-address-kept-in-memory.md) | The keys at a client's address are kept in the memory of each server, for an hour at most, and fetched again at most once a minute per client |
