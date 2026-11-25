# Decision 0031: Service accounts and agents are users, and a client acts as one

Status: Accepted

## Context

[Milestone 8](../product/epics.md#milestone-8-workloads-agents-and-webhooks) adds principals of a tenant that are not people: service accounts, for programs that act on their own, and agents, for artificial intelligence agents that will also act on a person's behalf through token exchange ([Issue-95](../product/epics.md#slice-y--workloads-and-agents-epic-22)). Issue-93 asks that they have a lifecycle and owners, hold clients of the client credentials grant, are assigned roles like users, can never sign in, and that disabling one stops its tokens at once.

Three things were already in place:

- The identity context's users have a kind, `human`, `service_account` or `agent`, since Milestone 1 ([the identity context](../architecture/contexts/identity.md#what-a-user-is)), and nothing used the two kinds that are not people.
- A client of the client credentials grant gets tokens for itself: their `sub` is the client's identifier, and roles can be assigned to a client as a principal of its own ([native role-based access control](../architecture/contexts/authorization.md#assignments)).
- Issue-91 ends a person's access at once when a directory deprovisions them, in the same transaction, through a port that the composition root implements with the session and OAuth contexts ([deprovisioning](../architecture/contexts/provisioning.md#deprovisioning)).

Two questions had to be answered: where a workload lives, and how a token says that a workload acted.

## Decision

- **A service account or an agent is a user of the identity context**, of its kind. Role assignments, group memberships, the audit log and the subject attributes of the Authorization API already name users, so they work for workloads with no change. What only a workload has, its owners, is kept beside the user, in `identity.workload_owner`.
- **A workload never signs in.** It has no login identifier, so nobody can type a name that finds it, and the rule that says whether a user may sign in answers no for any kind but `human`, so that no step, alternative or completion of a sign-in can make a session for one. It authenticates as a client.
- **A client of the client credentials grant may be bound to one workload**, its **principal**, chosen by an administrator. A bound client is allowed that grant only. Its access tokens have the principal's identifier as `sub`, so that the roles assigned to the principal are the ones a resource server finds when it asks about the token's subject, and they carry `principal_kind`, `service_account` or `agent`, so that a resource server tells a workload from a person without asking Hodor. A client without a principal is answered exactly as before: its tokens are about itself, and carry no `principal_kind`.
- **A workload's standing is checked wherever a token of it is used.** The token endpoint refuses a bound client whose principal is not an active workload, and the register of access tokens counts a token as in force only while its principal is an active workload. Introspection, UserInfo, the Authorization API and the SCIM server all ask the register, so they all stop at once.
- **Disabling or deleting a workload also revokes its access tokens**, in the same transaction, through the port Issue-91 built for deprovisioning, which the composition root implements once for both. Enabling it again does not bring a revoked token back.
- **The OAuth context does not learn what a workload is.** It keeps the principal as a user identifier and asks a port of its own whether it may act. The administration interface and the command-line tool check, through the identity context, that a principal names a workload of the tenant.

## Consequences

- An agent and a service account differ only in their kind until Issue-95: only an agent may then be the actor of a token exchange.
- A resource server that reads tokens by itself tells the three kinds of subject apart: `principal_kind` names a workload; `sub` equal to `client_id` names a client acting for itself; any other `sub` names a person.
- A workload never holds a token of the administration interface, which belongs to a person who signs in. Workloads reach that interface with the API keys of Issue-94.
- The register of access tokens reads the identity context once more for a workload's token, through the composition root. A resource server that checks tokens by itself still accepts a token until it expires, as [Decision 0004](0004-token-formats.md) accepts.

## Alternatives considered

- **A context of its own for workloads.** It would duplicate the users' lifecycle, and every reader of a subject (role assignments, groups, the audit log, the Authorization API) would learn a second kind of principal. Set aside because a workload is a principal of the tenant like a user, and the identity context already says so.
- **The client as the workload.** A client is a credential of an application: it has secrets and keys that rotate, and a workload may need several, one per place it runs. Roles given to the client would be lost with it. Set aside so that rotating or replacing a client keeps the workload's roles.
- **No claim for the kind, only `sub`.** A resource server would have to ask Hodor who a subject is before trusting a token for anything a person may do. Set aside because the token is where a resource server looks first.
- **The kind in every token, `human` for a person and `client` for a client acting for itself.** It would change the tokens of every client, which the issue asks to keep as they are.
