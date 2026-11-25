# Decision 0059: Linkerd policies are written from the roles in force into one file that is also the memory of the last run, in JSON documents, with an identity no workload has when nobody holds a role

Status: Accepted

## Context

[Decision 0029](0029-hodor-in-a-service-mesh.md#linkerd-gets-three-paths-since-it-can-ask-no-outside-decision) gives Linkerd policies written from Hodor's roles: `hodor-cli mesh linkerd-policy` writes, for one application, the `MeshTLSAuthentication` and the `AuthorizationPolicy` that let in only the Linkerd identities of the service accounts that hold a role on the application's resource server. It writes them and does not apply them, and says what changed since the last run ([Issue-111](../product/epics.md#slice-linkerd-epic-32)). It leaves open:

- what "holds a role on the resource server" means, when roles include other roles, are given to groups, and are scoped to an application or an organization and bounded in time;
- which clients say what a service account's Linkerd identity is;
- where the last run is remembered, since Hodor applies nothing and so cannot read what the cluster holds;
- the format of what is written, which the command must read back;
- what to write when nobody holds a role, since Linkerd refuses a `MeshTLSAuthentication` with no identity (`minItems: 1` in its custom resource definition, as of `edge-26.11.2`).

## Decision

- **A service account holds a role on the resource server when the native engine could allow it something there for a request made for the application.** An assignment of the service account, or of a group it is in, counts when it is in force at the moment of the run, its role is of the resource server's namespace or includes one as far as inclusion goes, and it is for the whole tenant, for this application, or for an organization the service account is a member of. Which permissions the role holds, and their conditions, are not looked at: the policy is coarse, and the application decides the rest.
- **The Linkerd identities are those of the clients bound to one**, through `linkerd_identity` ([Decision 0056](0056-forwarded-client-identity.md)): enabled clients of enabled applications whose principal is an active service account. A disabled client or service account stops being let in, as it stops getting tokens. Several clients of one service account may share an identity, one in each application ([Decision 0058](0058-hodor-ext-authz.md#an-identity-binds-the-clients-of-one-service-account)); the identity is written once, and stays while any one of them is enabled. Since an identity binds the clients of one service account alone, it is let in for that service account's roles and no other's.
- **The last run is remembered by its own file.** `--output` names the file; the command reads it before replacing it and prints each identity added and removed, and each change of namespace, name or target. Nothing is kept in Hodor's database, and nothing is read from a cluster. The file is what the operator applies and, usually, keeps under version control, so what changed is what will change in the cluster when it is applied.
- **The file is YAML whose documents are JSON**, after a comment that names the application. JSON is YAML, so `kubectl` and the tools that deploy clusters read it as any manifest; and the command reads its own file back with the JSON reader the workspace already has, exactly, without a YAML library. The output is the same bytes for the same policy, so an unchanged run writes nothing.
- **When nobody holds a role, the one identity written is `nobody.hodor.serviceaccount.identity.linkerd.invalid`.** It has the shape of a Linkerd identity, so Linkerd accepts it, and its trust domain is `invalid`, which RFC 6761 reserves and no mesh uses, so no workload has it. Applying the file then takes away what an earlier run let in.
- **A file that is not one the command wrote, or that was written for another application, is never replaced.** The command refuses, so that a mistyped path cannot overwrite something else.

## Consequences

- The policy trails the roles until the command runs again and its file is applied. Decision 0029 accepted this; the [authorization context](../architecture/contexts/authorization.md#written-never-applied) says so where the command is specified.
- An operator who keeps one file per application in version control sees each change of access in the history of their repository.
- A service account with a role in an organization it is a member of is let in for every request, though the role applies only to requests made in that organization. Linkerd cannot tell organizations apart; the application can.
- Removing a whole policy, or moving it to another namespace, is the operator's: the command prints the change, and the resources the last run wrote stay in the cluster until they are deleted.
- The format is unusual for a Kubernetes manifest, which is written in block YAML more often than in JSON. It is read the same way by every tool, and diffs line by line as block YAML does.

## Alternatives considered

- **Remembering the last run in Hodor's database.** Set aside: it would say what the command last wrote, not what the operator applied, and two operators writing for two clusters would overwrite each other's memory.
- **Reading the cluster to compare.** The most accurate. Set aside for the same reason Decision 0029 set aside a controller: Hodor would need rights in every cluster, if only to read.
- **A separate `--previous` file.** More flexible, for a pipeline that writes elsewhere each time. Set aside for one file that is both, which is how a file under version control is used; a pipeline can copy the last file to the path first.
- **Block YAML, read back with a YAML library.** More usual. Set aside: no YAML library is in the workspace, those for Rust are forks of one that is no longer maintained, and reading back a format written by hand is where small differences hide.
- **Leaving both resources out when nobody holds a role.** Linkerd then refuses every caller of a `Server` with no policy. Set aside: applying the file would not remove what an earlier run applied, so the last identities would stay let in.
- **Naming service accounts through `identityRefs`** instead of identities. Set aside: a reference to a service account says nothing of the trust domain, while the identity bound to the client is exact.
