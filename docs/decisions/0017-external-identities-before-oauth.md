# Decision 0017: Signing in with external identities comes before OAuth

Status: Accepted (requested by the project owner)

## Context

The [roadmap](../product/roadmap.md) placed social login and OpenID Connect federation in Phase 3, after Hodor's own OAuth 2.0 and OpenID Connect server, and LDAP and SAML in Phase 6. With Milestone 1 done, the project owner asked for SAML, LDAP and social logins next.

Signing in *with* an external identity does not need Hodor to issue tokens: the person still ends with a Hodor session in a tenant. What it does need are three things the roadmap had placed later:

- a way to keep a provider's secret encrypted at rest (planned with key management, Phase 2);
- one guarded client for outbound HTTP (planned with federation, Phase 3);
- a sign-in that can be completed by something other than an identifier and a password (alternative steps, planned for Phase 4).

[Decision 0014](0014-saml-deferred-with-spike.md) deferred SAML to Phase 6 and put a security spike in front of it, because a mistake in XML Signature handling is an authentication bypass.

## Decision

- **Milestone 2 is signing in with external identities**: OpenID Connect and OAuth 2.0 providers (the social logins), LDAP directories, and SAML identity providers. It is planned in [the epics](../product/epics.md#milestone-2-signing-in-with-external-identities).
- **The three prerequisites are built first, each as small as this milestone needs.** Secret encryption is one key from configuration with a key identifier, not the key domain of Phase 2. The outbound client and the alternative step are built as designed.
- **Order inside the milestone: OpenID Connect first, then LDAP, then SAML.** OpenID Connect establishes everything the other two reuse: providers, links between a user and an external identity, just-in-time creation and the rules against account takeover. SAML is last because it is the riskiest and gains most from the others being settled.
- **Only one direction of SAML is in this milestone: Hodor as the service provider**, the side that receives an assertion and signs a person in. Hodor as a SAML identity provider gives other applications a sign-in, which needs applications; it stays with the OAuth server.
- **The gate of Decision 0014 stays in full.** SAML still starts with the spike, the attack corpus is still written before the feature code, the fixed rules of the `saml` crate still hold, and the external security review is still a condition for calling SAML ready for production. Only the moment changes.
- **Synchronizing users and groups from LDAP, SCIM, routing by email domain and linking from an account page are not in this milestone.** A person signs in through a directory and is created on first sign-in; bulk synchronization stays in Phase 6, and the rest waits for the consoles.

## Consequences

- Tenants can let people in with the accounts they already have before Hodor can issue a token to an application.
- Phase 2 inherits a secret encryption that it must grow into the key domain, moving existing ciphertexts under managed keys. The key identifier stored with every ciphertext is what makes that possible.
- SAML ships in this milestone as "built and tested against the attack corpus, not yet externally reviewed". The progress page says so until the review happens.
- The roadmap's Phase 3 and half of Phase 6 are done out of order; Phase 2 is next after this milestone.

## Alternatives considered

- **Keep the order: OAuth server first.** Sound, and the original plan; set aside by the project owner's request.
- **SAML first, as asked.** It would be built on nothing: no providers, no links, no outbound client. Every rule about linking would be decided inside the riskiest protocol.
- **Skip the SAML spike to go faster.** Rejected: the spike exists because the fast path is how SAML implementations get bypassed.
