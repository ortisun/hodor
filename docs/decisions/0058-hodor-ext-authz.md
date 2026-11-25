# Decision 0058: `hodor-ext-authz` asks `evaluate` as one client per application, all bound to its one mesh identity; an identity binds the clients of one service account; the Authorization API names a workload by its identity

Status: Accepted

## Context

[Decision 0029](0029-hodor-in-a-service-mesh.md#decisions-are-asked-through-hodor-ext-authz-a-binary-of-its-own) makes `hodor-ext-authz` a binary of its own that maps Envoy's external authorization to [the Authorization API](../api/api-spec.md#authorization-api). It holds one client per protected application, because the API answers only about the resource server of the caller's own application, and it proves who it is to Hodor with its own mesh identity. With no token, the subject is the caller's identity, which Hodor resolves to the service account bound to it.

Three things stand in the way as Issues 106 and 107 built them:

- **An identity binds one client of a tenant at most** ([Decision 0055](0055-spiffe-jwt-client-authentication.md#decision)). `hodor-ext-authz` runs as one workload with one identity, so it could be one client, of one application, and no more.
- **The Authorization API names a subject only as a user or a client**, by Hodor's identifier. A caller that knows only the mesh identity of the workload in front of it cannot name the service account.
- **What `hodor-ext-authz` reads from Envoy, and how it fails, was not written down**: where the token's claims come from, how a route becomes a resource and an action, what is answered when anything is missing.

## Decision

### An identity binds the clients of one service account

- **Several clients of a tenant may be bound to one SPIFFE identifier or one Linkerd identity, as long as they all act as the same service account.** A client bound to an identity that a client of another principal already holds is refused, with `oauth.client_spiffe_id_taken` or `oauth.client_linkerd_identity_taken` as before.
- **Each client is still bound to exactly one identity**, and still names its `client_id` when it proves who it is ([Decision 0056](0056-forwarded-client-identity.md#decision)), so the client is never guessed from the identity.
- **An identity therefore names one service account of the tenant.** That is what resolving a caller's identity needs, and what Decision 0055 kept identifiers unique for.
- **PostgreSQL keeps the rule under a lock.** The unique indexes of migrations 0078 and 0080 are replaced by plain ones (migration 0084), and the client store, before it writes a bound client, takes a transaction-scoped advisory lock on the tenant and the identity and refuses the write if a client of another principal holds it. Two administrators binding one identity to two service accounts at once cannot both succeed.

### The Authorization API names a workload by its identity

- **A subject may be `{"type": "workload_identity", "id": "<a SPIFFE identifier or a Linkerd identity>"}`.** The identity is read as a client's binding is: `spiffe://` makes it a SPIFFE identifier, anything else a Linkerd identity. One that reads as neither is refused with `422` `authorization.workload_identity_invalid`.
- **Hodor resolves it, in the tenant, to the service account of the enabled clients bound to it**, and the request is then about that user, as if the caller had named it with `{"type": "user"}`. The engine, the record of decisions and the answer see a user; the identity is not kept.
- **An identity that no enabled client of the tenant binds is a subject Hodor does not know**: the request is about a user whose identifier is the identity itself, which has no attributes and holds no role, as for any identifier that is not Hodor's. It is decided and recorded, never refused.
- **Resolving is the protocol layer's**, through the OAuth context, as the API key's application is. The authorization context and its engines are unchanged.

### What `hodor-ext-authz` does

- **It depends on no crate of the workspace but `hodor-observability`.** It talks to Hodor only over HTTP, through the token endpoint and `evaluate`, so it holds no decision of its own and can be released, scaled and upgraded apart. The architecture test keeps that rule.
- **Its configuration is a JSON file**, named by `HODOR_EXT_AUTHZ_CONFIG`: Hodor's address, the tenant, the tenant's issuer, where the checked token's claims are found, and one entry per protected application with its destination identity, its client and its route rules. JSON needs no new library, and the chart writes it from its values. The file is read once at start; a file that does not read stops the process before it listens.
- **The application is chosen by `destination.principal`**, exactly. A destination with no entry is denied.
- **The subject is the checked token's, else the caller's identity.**
  - The claims are read from the request's metadata, where Envoy's JWT filter writes them with `payload_in_metadata`, under a namespace and a key the configuration names; or from a header the proxy writes them into, Istio's `outputPayloadToHeader`, believed only when it equals the claims of the bearer token in `Authorization`, which the proxy then forwards and has checked.
  - `iss` must be exactly the tenant's issuer, so a token of another tenant is denied; `exp`, when present, must be in the future. `sub` is the subject: a `client` when it equals `client_id`, as for a client acting for itself, otherwise a `user`.
  - Claims that are present but do not read, or fail these checks, are denied; the caller's identity is never used in their place.
  - With no claims, the subject is `source.principal` as a `workload_identity`. With neither, the request is denied.
- **The resource and the action come from route rules**: a list of methods and a path pattern give a resource type, an action and, from the segment `{id}`, the resource's identifier. The first rule that matches decides; with none, the request is denied. Where the proxy sends context per route, `context_extensions` naming `hodor_resource_type` and `hodor_action`, and optionally `hodor_resource_id`, take the place of the rules; one without the other is denied.
- **It proves who it is with its mesh identity alone.** It asks the token endpoint for `client_credentials` with `client_id`, `resource=urn:hodor:authorization` and `scope=authz:evaluate` and nothing secret; its sidecar presents its certificate and Hodor reads the identity the proxy in front of Hodor forwards (`tls_client_auth`, `spiffe_x509` or `linkerd_identity`). A JWT-SVID is not supported: each is used once, and one workload asking for several clients' tokens would need a fresh one each time.
- **It keeps each client's access token until 30 seconds before it expires**, and asks for a new one when `evaluate` answers `401`, once. It keeps no decision: every request is asked.
- **It answers denied on every failure**: Hodor unreachable or slow past the timeout, an answer that does not read, any status but `200`, a decision other than `ALLOW`, a missing destination, rule or subject. The answer to Envoy is always a well-formed `CheckResponse`, `PERMISSION_DENIED` with an HTTP `403`, never a gRPC error, so Envoy's own failure mode is never reached. The reason is logged, never sent to the caller.

## Consequences

- A tenant sets `hodor-ext-authz` up with one service account bound to the adapter's identity, and one client per protected application, each with that service account as principal and that identity as binding, in the application, holding `authz:evaluate` on the tenant's Authorization API resource server. [The `hodor-ext-authz` page](../operations/hodor-ext-authz.md) shows each step.
- A workload's clients in several applications no longer need several identities, which Kubernetes could not give one pod anyway.
- Any application can ask about the caller its own Linkerd proxy names in `l5d-client-id`, the third path of Decision 0029 for Linkerd, with the same subject type.
- The rule is no longer one index in PostgreSQL but a check under a lock in the store. The contract suite of the client store checks it on memory and on PostgreSQL.
- The proxy's JWT filter must be set to put the claims where the configuration says; a proxy that checks no token still lets workloads through, by their identity.

## Alternatives considered

- **One client for `hodor-ext-authz`, and an Authorization API that lets it name the application asked about.** Simpler to set up. Set aside: the API's rule that a caller asks only about its own resources is what bounds a compromised caller (Threat-Mesh-07), and one client allowed to name any application would ask about all of them.
- **An API key per application.** Keys already name an application. Set aside: a key is a secret, and Decision 0029 wants the adapter to hold none.
- **A table of bound identities, each with its principal, referenced by the clients.** The database would keep the rule by itself. Set aside: rows left behind when the last client lets an identity go would need removing, for a rule a lock keeps as well.
- **An exclusion constraint.** One line. Set aside: it needs the `btree_gist` extension, which the owner of the schema may not be allowed to create.
- **Refusing a request about an identity no client binds.** It would tell the caller at once. Set aside: it would not be a decision, so it would not be recorded, and an identifier Hodor does not know is already answered as a subject without attributes.
- **Vendoring Envoy's `.proto` files and compiling them at build time.** No crate between Envoy and Hodor. Set aside: it needs `protoc` on every build machine and in the image's build. `envoy-types` ships the generated types under the Apache License 2.0, built on `tonic` and `prost`, already in the dependency tree for the tests' containers.
