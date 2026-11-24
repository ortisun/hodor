# Decision 0032: Webhooks are a context of their own, signed as Standard Webhooks say, and sent on leases outside any transaction

Status: Accepted (made for Issue-96; the project owner asked for webhooks, not for these choices)

## Context

[Milestone 8](../product/epics.md#milestone-8-workloads-agents-and-webhooks) asks for webhooks: endpoints a tenant registers and subscribes to types of event, events taken from the outbox, a signature with a secret shown once and rotated with an overlap, delivery by the worker through the guarded outbound client with growing waits, deliveries set aside after a bound and delivered again on request. An endpoint at a private address must be refused, a delivery that keeps failing must not hold up the others, and the signature must check with a library that is not Hodor's.

Four questions had to be answered before the code:

1. Which context owns webhooks.
2. How a delivery is signed.
3. How the worker sends deliveries without one endpoint holding up the others.
4. How the address of an endpoint is checked, and when.

What already existed shaped the answers. The outbox dispatcher hands each event to its handlers inside one transaction of the event's tenant ([Decision 0003](0003-context-communication.md)); the audit handler writes its record there. The notification context sends mail by holding a message locked while it talks to the mail server, whose adapter gives up after 30 seconds. The guarded outbound client refuses private addresses when it connects, and checks the address it connects to, not one resolved earlier ([outbound HTTP](../security/outbound-http.md)).

## Decision

- **A new base context, `hodor-webhooks`, depends on the kernel alone.**
  - It is not part of the notification context. Notification writes messages to people: a recipient, a template, a language, a link that expires with it. A webhook is an event sent to a system, as it is, with a secret of its own and an address someone else chose. The two share the idea of a queue that is retried and nothing of their rules.
  - It hears events the way the audit context does: its handler is given to the outbox dispatcher, and no context depends on it. Like audit, it reads only the type, the metadata and the stored fields of an event, so it needs no other context's types.
  - Its HMAC is a port implemented by `hodor-adapters-crypto`, as the HMAC of authenticator applications is. The check of an address is a new port of the kernel, `DestinationCheck`, next to `HttpClient`, implemented by the same guarded client: the rule of which addresses may be called stays in one place.
- **Events are published from a catalog.** A fixed list of event types in the context; nothing outside it can be subscribed to. The body is an envelope of Hodor's own, `id`, `type`, `timestamp`, `tenant_id`, `actor` and `data`, with `data` the event's stored fields unchanged. Every context already promises that its events carry identifiers and no secret; the catalog leaves out configuration changes, events about tokens, and the context's own events, so a webhook never announces a change to webhooks.
- **The signature is Standard Webhooks**: `webhook-id`, `webhook-timestamp` and `webhook-signature` with `v1,` and the HMAC-SHA256 of `id.timestamp.body` in Base64; the secret is 32 random bytes written `whsec_` and Base64. During a rotation both secrets sign and the header carries both values, which every library of the scheme accepts. The secret is sealed with the secret box, not hashed, because signing needs it.
- **Fan-out and delivery are two steps.** The handler writes one delivery per subscribed endpoint inside the dispatcher's transaction, so an event makes its deliveries exactly once. A separate loop of the worker sends them.
- **The worker sends on leases, never inside a transaction.** A short transaction leases a due delivery, after counting under a lock of its endpoint how many of the endpoint's deliveries are leased already; the request is made with no transaction open; another short transaction records the result if the delivery is still as it was leased. Each worker sends up to 32 deliveries at once, and an endpoint never has more than 4 in flight, whichever worker sends them.
- **The address is checked when it is registered and at every delivery.** At registration the name is resolved and every address it leads to must be public, so a mistake is told to the administrator at once. At delivery the guarded client checks again, on the resolution it connects with, since a name can lead elsewhere later. A refused delivery is a failed attempt, retried and in the end set aside, like an endpoint that does not answer.
- **Delivering again puts the same delivery back**, with the same body and the same `webhook-id`, so that a receiver that did handle it after all recognizes it.

## Consequences

- One slow or dead endpoint costs at most four leases of ten seconds at a time; the deliveries of other endpoints and other tenants keep flowing, and a set-aside delivery holds nothing up.
- No database connection is held while an endpoint answers, so the pool does not run out because receivers are slow. The price is a third, short transaction per attempt, and the lease: a worker that stops in the middle of a request leaves its deliveries until the lease ends, about a minute later.
- Delivery is at least once, and not in order. Receivers deduplicate on `webhook-id` and order by `timestamp`; the context page says so.
- Any receiver can check a delivery with a published library in its own language. A test checks Hodor's signature with the Rust `standardwebhooks` crate, whose HMAC is not the one Hodor uses.
- The envelope is a compatibility surface ([the plugin architecture](../architecture/plugins.md#compatibility)): fields may be added to version 1, never removed or renamed.
- Without `HODOR_SECRET_KEYS` there are no webhooks: the server does not offer their operations and the worker sends nothing. Fan-out still runs, so nothing is lost when keys are configured later, but an installation without keys has no endpoints to fan out to.
- Adding an event type to the catalog is a change to this context, reviewed like any other, with a look at what the event carries.

## Alternatives considered

- **Webhooks inside the notification context.** Fewer crates. Set aside: two kinds of message with different rules, recipients and secrets in one context, and the notification context would have to learn the outbox, which it does not hear today.
- **A handler that sends the request itself, inside the outbox transaction.** No table of deliveries. Set aside: one endpoint that takes ten seconds would hold every event of every tenant behind it, a failed request would roll back the audit record with it, and a set-aside delivery would have nowhere to be.
- **Holding the delivery locked during the request, as messages are.** Simpler, and it works for mail, which goes to one server the operator chose. Set aside: endpoints are chosen by tenants, many at once may be slow, and each would hold a connection of the pool for its whole time limit.
- **A signature of Hodor's own, or the scheme of a particular vendor.** Set aside: receivers would have to write the check themselves. Standard Webhooks is an open specification with libraries in many languages, and its multiple signatures make rotation with an overlap work without a second header.
- **Keeping only a hash of the secret.** Set aside: an HMAC cannot be computed from a hash of its key.
- **Checking the address only at delivery.** Set aside: an administrator would learn that an address is refused only from a dead letter, hours later. Checking only at registration was never an option, since a name can be changed to point inside afterwards.
