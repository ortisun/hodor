# ADR-0003: Contexts talk through facades, SPIs and outbox events

Status: Proposed

## Context

Contexts must collaborate without circular dependencies. Three collaborations are especially cyclic by nature: authentication ↔ federation (an external IdP is a login step, and its callback completes a login), OAuth ↔ authentication (the authorization endpoint needs a login, and login returns to it), and everything ↔ audit.

## Decision

Three mechanisms, chosen by the shape of the collaboration:

1. **Facade call (synchronous, downstream → upstream).** A context may call the public `api` of a context it is allowed to depend on. Used when the caller needs an answer inside its transaction or request (authentication asks identity for a user).
2. **SPI (inversion).** When an upstream context needs behavior supplied by a downstream one, the upstream defines a trait and the downstream implements it. `authentication::Authenticator` is implemented by `federation`; `authorization::SubjectAttributeSource` is implemented by a small adapter wired in the composition root.
3. **Domain events through a transactional outbox (asynchronous).** A context writes events in the same transaction as its state change. The worker dispatches them to handlers at least once; handlers are idempotent on `event_id`. Used for reactions that need not be atomic with the cause: audit, session revocation cascading to grants, cache invalidation, webhooks.

OAuth and authentication have no code dependency in either direction. They meet over HTTP: `oauth` decides from the session's facts (`auth_time`, `acr`, `amr`) whether interaction is needed and redirects with an opaque interaction reference; the hosted UI drives `authentication`; the browser returns to `oauth`.

## Consequences

- The dependency graph stays acyclic and small.
- Event-driven reactions are eventually consistent. Where a security property needs immediacy (a revoked session must stop refreshing tokens now), the check is done synchronously at use time (the token endpoint reads the session state) and the event only cleans up.
- At-least-once delivery requires idempotent handlers and an outbox lag alert.

## Alternatives considered

- **Every context defines its own ports for everything it needs, wired in the composition root**: maximal decoupling, but the composition root fills with glue adapters and simple calls become indirection.
- **In-process event bus without an outbox**: loses events on crash and breaks the audit guarantee.
- **External message broker**: an extra mandatory dependency with no need yet; the outbox can feed one later.
