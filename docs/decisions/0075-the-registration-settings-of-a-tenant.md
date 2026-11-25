# Decision 0075: A tenant has one registration policy for every way, one list of hosts for every address, and initial access tokens counted and spent under a lock

Status: Accepted

## Context

[Decision 0049](0049-dynamic-client-registration.md) says that dynamic client registration is off in every tenant until an administrator turns it on, names an application for the registered clients, chooses among three ways to allow a registration (an initial access token, a software statement, open registration), and writes a policy that bounds every registration. Its table of ways says that a token allows "what the token's policy allows" and open registration "what the tenant's policy for open registration allows", while its section on the policy speaks of one policy "checked against every registration and every change, whichever way allowed it". It lets the policy decide, for each kind of address, whether any host or only listed ones may be named. [Issue-132](../product/epics.md#slice-registration-epic-19) builds the settings, the policy and initial access tokens, so these had to be settled before the registration endpoint of Issue-133 can check anything against them.

Five questions were open: how many policies a tenant has, how hosts are limited, where the settings live, how an initial access token is counted when two registrations present it at once, and what a token of a tenant whose registration is off does.

## Decision

- **One policy per tenant, the same for every way.** The policy is part of the tenant's registration settings, and every registration and change is checked against it whether a token, a statement or nobody allowed it. A token allows a number of registrations within that policy, and carries no policy of its own; open registration has none of its own either. What differs between the ways is who may register, never what they may register.
- **One list of hosts for every address.** The policy allows any host, or a list of up to 50 hosts, and then every address a registration names, whatever its member, redirect addresses, `jwks_uri`, `request_uris`, `sector_identifier_uri`, the logout addresses, `initiate_login_uri`, `logo_uri`, `policy_uri`, `tos_uri` and `client_uri` alike, must have one of them as its host, compared exactly, with no subdomain matching. An address without a host, such as a private-use scheme of a native application, is allowed only where any host is.
- **The settings are the OAuth context's**, in a table of their own, `oauth.client_registration`, not among the tenant context's settings: they name an application, grants, response types, scopes and methods, which are the OAuth context's words, and the application is referenced with the tenant so that the database refuses an application of another tenant. A tenant without a row reads as off.
- **The settings are replaced as a whole**, with optimistic locking. Being off is one of them, so a tenant may keep a policy while registration is off, and turning it on again does not ask for the policy again; the command-line tool turns registration off that way.
- **An initial access token is spent under a lock of its row**, in the unit of work of the registration it allows: it is found by its hash with `SELECT … FOR UPDATE`, checked, its count raised and the registration stored, then committed together. Two registrations at the same moment cannot spend one registration twice, and a registration refused after its token was accepted spends nothing.
- **While registration is off, tokens are kept and refused**, without being spent, and none can be made. Turning registration on again makes each token that has not expired, been revoked or been used up work again; an administrator who wants them gone revokes them.
- **Making a token takes `applications:write`**, the permission that makes clients: a token lets its holder make a client, so making one is as much as making a client, and no permission is added.
- **Every refusal of a presented token is one code**, `oauth.initial_access_token_invalid`, whatever the reason, as for API keys: an unknown token, one of another tenant, an expired, revoked or used-up one look the same to whoever presents them.

## Consequences

- Issue-133 asks one question of one policy. A conformance tenant that runs the Dynamic plan with an initial access token writes one policy that allows what the plan registers.
- A tenant that wants open registration to allow less than its tokens do cannot say so yet: it allows open registration under the same policy, or not at all. A token or an open registration with a narrower policy can be added later without changing the stored settings, as a second policy beside the first.
- A tenant whose developers keep their logos on another host than their redirect addresses lists both hosts. Limits per kind of address can be added later as more lists beside the first.
- The tokens of a tenant that turned registration off stay in the table until revoked, or until a cleanup job removes them after they end, which is not built yet.

## Alternatives considered

- **A policy per token and one for open registration**, as the table of Decision 0049 reads. Set aside for now: three places to look for what a registration may be, a policy to write for every token handed out, and no case yet that needs a token to allow less than the tenant does.
- **Hosts listed per member.** Closer to the wording of Decision 0049. Set aside for now: seven lists that are the same list in every tenant known so far, and an administrator who forgets one leaves that member open.
- **The settings among the tenant context's settings**, as the email sign-in policy is. Set aside: the tenant context would have to know applications, grants and methods, and could not have the database check that the application is the tenant's.
- **Counting uses with a conditional update alone**, `UPDATE … SET registrations = registrations + 1 WHERE registrations < max_registrations`. Equally safe, and one round trip fewer. Set aside: the rules of a token, its expiry, its revocation and its count, would be written in SQL as well as in the domain; with the lock, the domain decides and the database only keeps the row still.
- **Revoking every token when registration is turned off.** Set aside: turning registration off for an hour, to look into something, would undo every token handed out, and the developers holding them would have to ask again.
