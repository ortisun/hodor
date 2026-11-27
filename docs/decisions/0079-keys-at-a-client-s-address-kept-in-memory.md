# Decision 0079: The keys at a client's address are kept in the memory of each server, for an hour at most, and fetched again at most once a minute per client

Status: Proposed

## Context

[Decision 0049](0049-dynamic-client-registration.md#the-clients-keys-may-live-at-its-jwks_uri) lets a client name `jwks_uri` instead of keys, an address where it publishes its keys itself, and fixes four rules: the set is fetched through the guarded outbound client, kept for an hour at most, fetched again for a `kid` Hodor does not know at most once a minute per client, and no redirect is followed. The OpenID conformance suite needs it: its test `oidcc-refresh-token-rp-key-rotation` rotates the client's key at its address and expects the next assertion, signed with the new key, to be accepted.

Two things the decision leaves open, and which Issue-136 has to settle:

- **Where the fetched set is kept.** Hodor runs as several servers behind a load balancer ([Milestone 6](../product/epics.md#milestone-6-hodor-runs-behind-a-load-balancer-and-cleans-up-after-itself)), and every server checks assertions and request objects. A set kept by one server is not seen by another unless it is kept somewhere they share, the database or Redis.
- **What "at most once a minute" counts.** Fetches caused by an unknown `kid` only, or every fetch of the address; and what a request does while a fetch it would have caused is not allowed.

The trust domains of [the keys context](../architecture/contexts/keys.md#fetching-a-bundle) answer the same question for SPIFFE bundles the other way: the worker fetches the bundle on a schedule and stores it in the database. A bundle changes on the authority's schedule, and a workload never signs with a key before the bundle names it. A client rotating its own key does exactly that: it publishes the key and signs with it at once, and Hodor must fetch when it sees the new `kid`, inside the request that names it.

## Decision

- **Each server keeps the sets it fetched in its own memory**, for the tenant, the client and the address together. Nothing fetched is written to the database or to Redis, and nothing is shown to an administrator. A server that restarts starts with none.
- **A set is used for one hour after it was fetched, and never after.** The first request that needs it after the hour fetches it again.
- **At most one fetch a minute per client and per server, whatever caused it**: the first use, the end of the hour, or a `kid` the kept set does not have. A fetch counts from the moment it starts, before it answers, so requests that arrive while it runs check against the set that is kept, or against no key, and do not fetch again. A failed fetch counts too.
- **An unknown key is a header that names a `kid` none of the kept keys has, or names none while none fits its algorithm.** Only then does a request fetch before the hour ends. A header Hodor would refuse in any case, for an algorithm it does not accept or a `kid` that is not text, fetches nothing.
- **A failed fetch keeps what was kept**, until its own hour ends. A set that answered is the set, even with no usable key in it: an address that answers no key is a client with no key, not an address that failed.
- **The number of sets kept is bounded**: at most 10 000 clients per server. When a new client would pass it, the sets past their hour go first, then the one fetched longest ago.

## Consequences

- A key a client removes from its address stops being accepted within the hour on every server, and a new key is accepted from its first use, or within a minute when another fetch of that client came just before.
- An installation of several servers fetches a client's address once a minute per server at most, not once a minute in all. A burst of unknown `kid` values reaches the address as many times a minute as there are servers. The number of servers is the operator's, so the bound holds; the residual risk is in [the threat model](../security/threat-model.md#residual-risks).
- An administrator who must stop a key at once, because it leaked, changes the client's address or disables the client. Every server reads the client at every request, and a set is kept for the address it was fetched from, so either takes effect at the next request.
- The first request of a client after a server starts, or after the hour, waits for the fetch, five seconds at most. A client that signs a request every few minutes waits once an hour per server.
- Nothing new is stored, so there is no migration of fetched keys, no cleanup job, and nothing of a client's keys for a backup to hold.

## Alternatives considered

- **Keeping the sets in the database, shared by every server.** One fetch a minute for the whole installation, and one set seen by all. Set aside: a fetch would write a row from inside the token endpoint, and the rule "at most once a minute" would need a lock across servers on the client, held while the address answers; the gain is a factor of the number of servers on a bound that already holds.
- **Keeping them in Redis.** Shared without touching the database. Set aside: Redis is optional ([Decision 0007](0007-postgres-required-redis-optional.md)), and an installation without it would need the memory of each server anyway.
- **Fetching on a schedule by the worker**, as a trust domain's bundle is. No fetch inside a request. Set aside: a client that publishes a key and signs with it at once would be refused until the next pass, which is what the suite's rotation test checks.
- **Fetching once when the client is saved, and keeping the keys as if an administrator had given them.** No outbound request at a sign-in. Set aside: a client would have to be saved again for every rotation, which is what `jwks_uri` is there to avoid, and a key it removed would be accepted until then.
- **Counting only the fetches an unknown `kid` causes.** A client whose address does not answer would then be fetched at every request after its hour, as often as anyone sends an assertion naming it. Set aside: the bound would not hold where it matters most, an address that is slow or down.
