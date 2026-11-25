# Decision 0034: An agent acts for a person through token exchange, and the token says so

Status: Accepted

## Context

[Issue-95](../product/epics.md#slice-y--workloads-and-agents-epic-22) asks for token exchange ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)): a subject token and an actor token, the `act` chain with a bounded depth, a policy per client of what may be exchanged for which audience, scopes that may only narrow, and the chain in the audit log. [Decision 0031](0031-workloads-are-users.md) said that only an agent may act on a person's behalf, and that an agent proves who it is through a client of the client credentials grant bound to it.

RFC 8693 leaves most of the semantics to the server: which tokens may be exchanged, by whom, for what, and what the new token says. Five questions had to be answered: who may exchange, what the policy says, what the new token is about, how long it lives, and when it stops.

## Decision

- **Only an agent exchanges, for itself, with its own client.** The client asking is a confidential client bound to an agent, allowed the token exchange grant besides client credentials. The actor token is an access token of that agent, issued to that client; the subject token is a person's access token, or a token an earlier exchange made for a person.
- **The policy is a list of rules on the client**, each a pair: the audience a subject token must hold, and the audience the new token may be for. A request names one audience; it is refused unless a rule pairs one of the subject token's audiences with it. An administrator says, for each agent's client, which tokens it may turn into which: a token a person gave to the agent's own interface, say, into one for the invoices interface.
- **The new token is the person's, held by the agent.** Its `sub` is the person, `client_id` the agent's client, `aud` the one audience asked for, and `act` the agent, written `{"sub": "<agent>", "principal_kind": "agent"}`, with the subject token's own `act`, if any, inside it. Its scopes are those asked for, or all those the subject token holds that the audience's resource server defines; each must be one the subject token holds, one the client is allowed and one the resource server defines. A scope can only narrow.
- **The chain is bounded: at most three actors.** A subject token whose chain already holds three is refused, so that a token never hides how many hands it passed through.
- **The new token never outlives what it came from.** It lives the client's access token lifetime, or until the subject token expires if that comes first. It is recorded in the register with the subject token as its parent, the grant and the refresh token family of the subject token, and the agent as its principal: it is in force only while its parent is, the person's grant is active, and the agent may act. Revoking the person's token, the person's deprovisioning, and disabling the agent all stop it at once.
- **Every exchange is audited with its chain**: the client, the person, every actor from the newest to the oldest, the audience and the new token's `jti`, with the agent as the actor of the record.

## Consequences

- A resource server reads `act` to know that an agent acts, and which, and decides for itself whether it lets an agent do what it lets the person do. The Authorization API is asked about the person, the token's `sub`.
- Token exchange needs nothing new to be stored but the policy and the parent of a token. The register checks a chain one record at a time, at most four records deep.
- A service account never exchanges and is never an actor. A workload is never a subject.
- The grant appears in discovery's `grant_types_supported`. A client of OpenID Connect that does not know it ignores it.

## Alternatives considered

- **The client as the actor, without an actor token.** RFC 8693 allows it. Set aside because the issue asks for both tokens, and an actor token lets the agent's standing be checked through the same register as every token.
- **Impersonation, where the new token carries no `act`.** Set aside: a token that hides that an agent holds it is the thing the milestone wants to prevent.
- **Policy as one list of allowed audiences, whatever the subject token.** Set aside because an agent could then turn any token a person gave anyone into one for any of those audiences.
- **An unbounded chain.** Set aside: each hop is a party a resource server must trust, and a token must stay small.
