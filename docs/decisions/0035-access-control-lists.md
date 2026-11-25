# Decision 0035: Access control lists are entries that only allow, read at every decision beside the roles

Status: Accepted (made for Issue-102; the project owner asked for access control lists, not for these choices)

## Context

[Milestone 9](../product/epics.md#milestone-9-what-020-left-out) asks for per-resource access control lists in the native engine: entries naming a user, a group, a client or a service account, a permission and one resource of a resource server, evaluated with roles, and managed through the administration interface and the command-line tool. An entry must allow only on its resource; taking a person out of a group that an entry names must stop allowing on the next decision; and an entry of another tenant must never be read. The demonstration shares one document with a group and asks for a member and for someone else.

What already existed shaped the answer:

- The native engine answers from roles ([native role-based access control](../architecture/contexts/authorization.md#native-role-based-access-control)). It keeps, per principal, what the principal's assignments come to, and reads everything again when the tenant's role revision changes. Every change of a permission, a role or an assignment raises that revision.
- A user's groups, the nested ones included, come with the subject: they are resolved at every decision by the subject attribute source, so taking someone out of a group already takes effect at once for roles given to the group (Issue-89).
- A service account or an agent is a user ([Decision 0031](0031-workloads-are-users.md)).
- The design of the engine ([authorization](../architecture/authorization.md#native-engine)) puts an access control list before roles and an explicit deny before both. Explicit deny was never built, and no role denies.

Five questions had to be answered: what an entry names, whether an entry can deny, where entries are read in a decision, whether they are cached, and who may manage them.

## Decision

- **An entry names one principal, one permission of a resource server and one resource identifier.** The permission is one the tenant declared for the resource server, written `resource:action`; its first half is the kind of the resource. `document:read` on `d-42` for the group `finance` lets every member of `finance` read the document `d-42`, and nothing else. Naming a declared permission, rather than any action, keeps one vocabulary for roles and entries, and removing a permission removes the entries that name it, as it removes it from every role.
- **A principal is a user, a client or a group.** A service account and an agent are named as users, as they are when they are given roles. A group's members are not written into its entries: the engine compares the entry's group with the groups resolved for the subject at the decision.
- **An entry only allows.** There are no deny entries. A deny entry would have to win over every role, and over every other entry, which is the explicit deny the design left for later; nothing asks for it yet.
- **An entry has no scope, no start, no end and no condition.** It holds for its resource until it is removed. Conditions on entries stay out ([Decision 0025](0025-condition-language.md)).
- **Entries are read first, then roles.** When a request names a resource identifier, the engine reads the entries of that resource server, permission and resource whose principal is the subject or one of its groups, in one query. One of them allows with the reason `matching_entry`, naming the entries as `entry:<identifier>`. Otherwise the roles decide as before. A request without a resource identifier is answered by roles alone, and a deny keeps the reason `no_matching_role`, so that a refusal reveals no more than before.
- **Entries are not cached and do not raise the role revision.** They are read at every decision that names a resource, so a new or removed entry takes effect on the next decision, in every instance of Hodor. The query is answered from an index of the tenant, the resource server, the resource kind, the resource and the principal.
- **An entry has an identifier of its own.** It is removed by that identifier. Granting the same principal the same permission on the same resource again answers the entry that exists and announces nothing.
- **Two permissions of their own, `access-entries:read` and `access-entries:write`.** A program that shares documents on behalf of people needs to write entries, not to define roles: the permissions are apart from `roles:read` and `roles:write`. The auditor holds the read.

## Consequences

- Sharing one resource is one row, written in one short transaction, and is in force at the next decision. It does not throw away what the engine keeps for the roles of every principal of the tenant, which raising the role revision would.
- A decision about one resource costs one more indexed query, even when a role would allow. It is bounded: the principals are the subject and its resolved groups, and the number of groups is bounded by the tenant's group policy.
- Removing a person from a group stops every entry naming the group from allowing them on the next decision, because groups come with the subject and nothing about the entry changes.
- An entry that names a user, a client or a group that is later removed stays, and allows nothing: identifiers are not reused. The administration interface checks that the principal exists when the entry is granted.
- The revision an allow by an entry reports is the role revision, which does not count entries. It says which roles were in force, not which entries.
- The answer of an entry names it, so that an explanation says which entry allowed. Only callers allowed explanations see it ([the Authorization API](../architecture/contexts/authorization.md#who-may-ask)).

## Alternatives considered

- **A role given on one resource**, an assignment scoped to a resource instead of an application. Set aside: every share would be an assignment, kept in the cache of every principal and raising the role revision, and a role per resource mixes two questions, what someone may do in general and to what they were given access.
- **Caching entries per resource, invalidated by a revision of their own.** Set aside: a revision per resource is a write per share and a read per decision anyway; a revision per tenant is thrown away by every share. One indexed query is simpler and always current.
- **Writing a group's members into its entries.** Set aside: the members would have to be rewritten at every change of the group, and a removal would take effect only when the rewrite finished.
- **Deny entries**, to take a resource away from someone a role allows. Set aside for now: it is the explicit deny of the design, which changes the meaning of every allow, and nobody has asked for it.
- **Any action, without declaring a permission.** Fewer steps for a tenant. Set aside: an entry for a misspelled action would be accepted and never allow, and removing a permission would leave entries that no role can explain.
- **Relationship-based access control**, tuples with relations between resources. Set aside: it is planned on its own ([the authorization architecture](../architecture/authorization.md#native-engine)) and out of Milestone 9. An entry is the simplest case of a tuple, a subject related to one resource by one permission, and can become one later.
