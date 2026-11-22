# The authorization context

The `authorization` context answers one question: may this user do this? Other parts of Hodor ask it and obey the answer; none of them decides for itself.

The whole design, with policies, several engines and Open Policy Agent, is in [authorization](../authorization.md). This page specifies what is built:

- the fixed roles that protect Hodor's own administration interface, from Milestone 1;
- the engine contract of [Decision 0009](../../decisions/0009-authorization-engine-contract.md), from Milestone 5 (Issue-72): the request, the decision, engines and the binding that says which engine answers for a resource server;
- native role-based access control, from Milestone 5 (Issue-73): permissions and roles a tenant defines for its resource servers, who holds them, and the native engine that answers from them. The fixed roles above are its built-in roles for Hodor's administration.

## Permissions

A permission names something that can be done: a kind of resource and an action on it, written `resource:action`.

| Permission | Allows |
|---|---|
| `users:read` | Seeing users and their login identifiers |
| `users:write` | Creating users and suspending them |
| `sessions:read` | Seeing a user's sessions |
| `sessions:revoke` | Ending a session |
| `audit:read` | Reading the audit log |
| `identity-providers:read` | Seeing the tenant's identity providers, without their secrets |
| `identity-providers:write` | Adding, changing, enabling and disabling identity providers, and replacing their secrets |
| `keys:read` | Listing a tenant's key versions |
| `keys:write` | Rotating a tenant's signing key and revoking key versions |
| `applications:read` | Seeing the tenant's applications, their clients and resource servers, without any secret |
| `applications:write` | Registering and changing applications, clients and resource servers, giving clients secrets and keys, and enabling and disabling them |

## Roles

A role is a named set of permissions. The roles of Hodor's administration are fixed: they are part of Hodor and cannot be changed or added to. They are the **built-in roles** of the namespace `hodor:admin` in [native role-based access control](#native-role-based-access-control); roles a tenant defines for its own resource servers are described there.

| Role | Permissions | Meant for |
|---|---|---|
| `tenant_administrator` | All of the above | The people who run a tenant |
| `tenant_auditor` | `users:read`, `sessions:read`, `audit:read`, `identity-providers:read`, `keys:read`, `applications:read` | People who must be able to see everything and change nothing |

A user holds a role in one tenant. Holding a role in one tenant means nothing in another: an assignment is a row of its tenant, like everything else.

## The check

```mermaid
flowchart LR
    ask["May this user do this?"] --> roles["The user's roles in the tenant"]
    roles --> any{"Does any role hold the permission?"}
    any -- yes --> allow["Allow"]
    any -- no --> deny["Deny"]
```

- **Deny is the default.** A user with no role, a role that lacks the permission and a user that does not exist all get the same answer: deny, with the reason `no_matching_role`.
- **The tenant comes from the caller's credential and the address of the request**, never from anything the caller sends in a body.
- **Nothing is cached.** Every check reads the user's roles. Taking a role away takes effect on the next request.
- **It is the native engine's answer for `hodor:admin`.** The check and the native engine read the same assignments and the same built-in role definitions, and give the same reason: the first role, in the fixed order, that holds the permission.

The check says whether a user may do something. Whether the user is who they claim to be, and whether they may sign in at all, is decided before it is asked, by whoever asks.

## Operations

| Use case | What it does |
|---|---|
| Assign role | Gives a user a role in the tenant. Giving a role the user already holds changes nothing and announces nothing |
| Revoke role | Takes a role away. Taking away a role the user does not hold changes nothing |
| Roles of a user | Lists the roles a user holds in the tenant |
| Check | Answers allow or deny for a user and a permission |

### Events

| Event type | When |
|---|---|
| `authorization.role_assigned` | A user was given a role; carries the user and the role |
| `authorization.role_revoked` | A role was taken away; carries the user and the role |

### Port

| Port | Purpose |
|---|---|
| `RoleAssignmentStore` | Store, remove and list a user's role assignments |

## Storage

### `authorization.role_assignment`

Who holds which role, for the built-in roles and for the roles a tenant defines. Since Issue-73 it holds both; the rows written before it became assignments of the built-in roles of `hodor:admin` to users, for the whole tenant, without an end.

| Column | Type | Notes |
|---|---|---|
| `tenant_id`, `principal_kind`, `principal_id`, `namespace`, `role`, `application` | `uuid`, `text`, `text`, `text`, `text`, `text` | Primary key. `principal_kind` is `user` or `client`. `application` is empty for an assignment to the whole tenant |
| `valid_from`, `valid_until` | `timestamptz` | Both optional; when both are given, the end comes after the start |
| `assigned_at` | `timestamptz` | |
| `role_namespace` | `text` | Generated: the namespace, or nothing for `hodor:admin`. It carries the reference to `authorization.role`, so that an assignment of a tenant's role names a role that exists and goes when the role goes |

A tenant table under row-level security. In `hodor:admin` the role is one of the built-in roles, the principal is a user, the assignment covers the whole tenant and has no start or end; the database refuses anything else there. `principal_id` refers to a user of the identity context or a client of the OAuth context but is deliberately not a foreign key: contexts do not reference each other's tables.

### `authorization.engine_binding`

| Column | Type | Notes |
|---|---|---|
| `tenant_id`, `namespace` | `uuid`, `text` | Primary key. The namespace is compared byte for byte; `hodor:admin` is refused |
| `engine` | `text` | The registered engine's name |
| `timeout_milliseconds` | `integer` | 1 to 5000 |
| `sensitive` | `boolean` | |
| `fail_open_actions` | `text[]` | Empty when `sensitive` |
| `trust_asserted` | `boolean` | |
| `created_at`, `updated_at` | `timestamptz` | |

A tenant table under row-level security. The namespace is a resource server's audience but not a foreign key, for the same reason as above.

## The engine contract

Applications ask about their own resources: whether a subject may do an action to a resource of one of their resource servers. The question goes to one **engine**, the one the tenant **bound** to that resource server. The context owns the question, the answer and the binding; an engine only decides.

### The request

| Part | What it is | Rules |
|---|---|---|
| Namespace | The resource server asked about, by its audience (`https://…` or `urn:…`, as in [the OAuth context](oauth.md#resource-servers)), or `hodor:admin` for Hodor's own administration | At most 255 characters, no fragment, no space |
| Subject | Who wants to act: a kind, `user` or `client`, and an identifier | The identifier has 1 to 255 characters and no control character |
| Asserted attributes | What the caller claims about the subject, such as roles it keeps itself | Kept apart from what Hodor resolves; **not given to the engine** unless the binding trusts them |
| Resource | A kind (`document`), an optional identifier and attributes | A kind is 1 to 64 characters of lower-case letters, digits, `-`, `_` and `.`, starting with a letter |
| Action | What is to be done (`read`) | Same characters as a kind |
| Context | Attributes of the moment, such as the address the request came from, an optional correlation identifier, and the application the request is made for, when there is one | The application is an identifier of 1 to 255 characters without a control character. It is what an assignment scoped to an application is compared with |

Attributes are names with JSON values. A set holds at most 64 names of at most 64 characters each.

**The request never names a tenant.** The tenant is the one of the caller's credential, passed beside the request as `TenantContext`; nothing in the request can point at another tenant.

### The answer

| Field | What it is |
|---|---|
| `decision_id` | A new identifier for every decision |
| `effect` | `allow`, `deny` or `indeterminate` |
| `evaluated_at` | When the decision was made, by Hodor's clock |
| `engine` | The engine that answered; absent when no engine was reached |
| `policy_version` | The revision of the policies the engine used, when it has one |
| `reason` | A stable code, safe to show to the caller, such as `no_matching_role` |
| `matched_policies` | The policies that decided. Only callers allowed to see explanations receive them ([the Authorization API](../../api/api-spec.md#authorization-api), Issue-75) |
| `metadata` | How long the evaluation took, whether it came from a cache, and whether asserted attributes were given to the engine |

**`indeterminate` means the engine could not decide**: it failed, timed out, was not available, or said so itself. Whoever enforces the answer treats it as deny: only `allow` permits. It exists so that logs and metrics tell "denied by policy" from "could not evaluate".

An engine does not write the whole answer. It returns its part (the effect, the reason, the revision and the matched policies), and the context adds the identifier, the time, the engine's name and the duration. No engine can claim another's name or another moment.

### Engines

An engine has a name (`native`, `open_policy_agent`, …), says what it can do beyond deciding (simulation, explanation), and answers one request or a batch, one answer per request in the same order. An engine that does not answer a batch in one call answers its requests one after the other.

Simulation is a separate ability of the engines that have it: the same request evaluated against a draft, a chosen revision or what is published. A simulated answer is never taken as a real decision.

Engines are registered when a binary starts. A binding names an engine; a binding cannot name an engine that is not registered.

### Bindings

A binding says which engine answers for one resource server in a tenant, and how failure is handled.

| Setting | Meaning | Default and bounds |
|---|---|---|
| Namespace | The resource server's audience | Unique in the tenant; never `hodor:admin` |
| Engine | The registered engine that answers | |
| Time limit | How long the engine may take | 200 milliseconds; 1 to 5000 |
| Sensitive | Whether a failure may ever allow | `false` |
| Actions that fail open | The actions for which a failure allows instead of being indeterminate | None. Must be empty when the namespace is sensitive. At most 50 |
| Trust asserted attributes | Whether the engine receives what the caller claims | `false` |

One request is answered by exactly one engine. Decisions of several engines are not combined.

**A resource server without a binding is denied everything**, with the reason `no_engine_bound`.

**Hodor's administration namespace, `hodor:admin`, is never bound and never rebound.** It is always answered by the native engine inside this context, from the built-in roles above, with nothing outside the context involved: an outage of Open Policy Agent can never lock administrators out of the system that fixes it. Its binding is fixed: sensitive, nothing fails open, asserted attributes are never trusted.

### Evaluating

```mermaid
flowchart TD
    request["Request and the caller's tenant"] --> binding{"Binding for the namespace?"}
    binding -- "none" --> unbound["deny: no_engine_bound"]
    binding -- "cannot be read" --> failure
    binding -- "found" --> engine{"Engine registered?"}
    engine -- "no" --> failure
    engine -- "yes" --> subject["Resolve the subject's attributes"]
    subject -- "cannot be resolved" --> failure
    subject --> ask["Ask the engine within the time limit"]
    ask -- "answers allow or deny in time" --> answer["The engine's answer"]
    ask -- "fails, times out or answers indeterminate" --> failure{"Does this action fail open?"}
    failure -- "no" --> indeterminate["indeterminate, with the cause"]
    failure -- "yes" --> recorded{"Failure recorded in the audit log?"}
    recorded -- "yes" --> open["allow: fail_open"]
    recorded -- "no" --> indeterminate
```

1. **The binding.** The administration namespace has its fixed one. Any other is read from storage; none means deny with `no_engine_bound`.
2. **The subject's attributes** are resolved by Hodor through a `SubjectAttributeSource`. A subject Hodor does not know has no attributes; it is not told apart from one that has none, so the answer does not reveal who exists.
3. **The engine decides.** The time limit is given to the engine, which stops waiting when it is reached (an engine that talks to another service sets it on its connection). If the answer arrives after the limit anyway, by Hodor's clock, it is not used.
4. **A failure is indeterminate, unless the binding lets that action fail open.** Then the answer is allow with the reason `fail_open`, and only if the event `authorization.failed_open` was stored with it; when it cannot be stored, the answer stays indeterminate.

The causes of failure have their own reasons:

| Reason | Cause |
|---|---|
| `binding_unavailable` | The binding could not be read |
| `engine_unavailable` | The binding names an engine that is not registered in this binary |
| `subject_unavailable` | The subject's attributes could not be resolved |
| `engine_failed` | The engine returned an error, or a batch answer of the wrong length |
| `engine_timed_out` | The engine answered after the time limit |

A batch holds at most 100 requests and gives one answer per request, in order; a failure of one does not fail the others. Requests bound to the same engine are sent to it together.

### Ports of the engine contract

| Port | Purpose |
|---|---|
| `AuthorizationEngine` | Decides one request or a batch |
| `PolicySimulator` | Evaluates a request against a chosen set of policies, for the engines that can |
| `EngineBindingStore` | Store, read, list and remove a tenant's bindings |
| `SubjectAttributeSource` | Resolve what Hodor knows about a user or a client |

### Events of the engine contract

| Event type | When |
|---|---|
| `authorization.engine_bound` | A binding was made or changed; carries the namespace and the engine |
| `authorization.engine_unbound` | A binding was removed; carries the namespace |
| `authorization.failed_open` | A failure allowed because the binding lets the action fail open; carries the namespace, the action, the engine and the cause |

## Native role-based access control

The native engine answers for the resource servers a tenant binds to it, `native`, and always for `hodor:admin`. It answers from **permissions**, **roles** and **assignments** kept in this context, and needs nothing outside it.

```mermaid
flowchart LR
    principal["User or client"] -- "assignment: whole tenant or one application, with an optional start and end" --> role["Role"]
    role -- "includes" --> included["Other roles"]
    role -- "holds" --> permission["Permissions of its resource server"]
    included -- "hold" --> more["Their permissions"]
```

### Permissions of a resource server

A tenant declares the permissions of each of its resource servers. A permission is written `resource:action`, the resource kind and the action of a [request](#the-request): `document:read` allows the action `read` on resources of the kind `document`. Both halves follow the rules of a kind and an action. A permission has a description of at most 500 characters.

Permissions cannot be declared for `hodor:admin`: its permissions are [the fixed ones](#permissions). Removing a permission removes it from every role that held it.

### Roles

A role belongs to one resource server, its namespace, and has a name, unique in that namespace: a lower-case letter followed by lower-case letters, digits, `-`, `_` and `.`, at most 64 characters. It holds permissions of its own namespace only, at most 200, and may **include** other roles, at most 50.

- **A role holds what the roles it includes hold.** A role that includes another of its own namespace is a **hierarchy**: a senior role (`editor`) includes a junior one (`viewer`) and holds everything the junior holds. A role that includes roles of other namespaces is a **composite role**: `support` may include `viewer` of the documents server and `reader` of the billing server, and holding it is holding both. Inclusion is followed as far as it goes.
- **Inclusion never makes a cycle.** A role that would include itself, directly or through other roles, is refused with `authorization.role_cycle`. Inclusion is at most 10 roles deep; a deeper chain is refused with `authorization.role_inclusion_too_deep`.
- **A role cannot include a built-in role**, and no role can be defined in `hodor:admin`: what a tenant defines never reaches Hodor's administration.
- **A role holds only permissions declared for its namespace.** An undeclared permission or an included role that does not exist is refused when the role is defined.
- **Defining a role again replaces it**: its description, its permissions and what it includes. **A role that another role includes cannot be removed** (`authorization.role_in_use`); removing a role removes its assignments.

### Assignments

An assignment gives a role to a **principal**, a user or a client (an application acting for itself). There are no groups or organizations yet, so roles are given to them only ([Decision 0023](../../decisions/0023-what-0.2.0-holds.md)).

| Part | Meaning |
|---|---|
| Principal | A user, by its identifier, or a client, by its client identifier |
| Role | The role, by namespace and name. It must exist |
| Scope | The whole tenant, or one application. An assignment to an application applies only to requests made for that application, those whose context names it |
| Start and end | Both optional. Before the start and from the end on, the assignment allows nothing. The end must come after the start |

Assigning the same role to the same principal with the same scope again replaces its start and end; with nothing changed, it changes nothing and announces nothing. Built-in roles are not given this way: they are given by [the bootstrap command](../../api/admin-api.md#the-first-administrator), as before.

### How the native engine decides

For a request about the resource server `namespace`, with the resource kind `kind` and the action `action`:

1. The principal is the request's subject. Its assignments in the tenant are read.
2. An assignment counts when it is in force at the moment of the decision and its scope is the whole tenant or the application named by the request's context.
3. From each assignment that counts, the role and every role it includes are followed. Every permission of `namespace` they hold is collected.
4. If `kind:action` is among them, the answer is **allow** with the reason `matching_role`. It names the assigned roles that led there, written `namespace#role`, and reports the tenant's role revision.
5. Otherwise the answer is **deny** with the reason `no_matching_role`. An undeclared permission, an unknown subject and a subject with no assignment get the same answer, so the answer does not reveal what exists.

For `hodor:admin` the built-in roles are used, the subject must be a user, and the answer is the one of [the check](#the-check): the reason is the name of the first role that allows, and the revision is `fixed_roles`.

Conditions on attributes come with Issue-74; then a role's permission may carry a condition that must also hold.

### Caching and the role revision

The native engine keeps, per tenant and principal, what the principal's assignments come to: the permissions, with the role, the scope, the start and the end of each assignment that gives them. Every change to a tenant's permissions, roles or assignments raises **the tenant's role revision** in the same transaction. Before using what it keeps, the engine reads the revision: when it has changed, it reads everything again. So **a change takes effect on the next decision**, whichever instance of Hodor answers it. The start and end of assignments are checked at every decision, so time passing needs no change. `hodor:admin` is not cached.

### Operations of native role-based access control

| Use case | What it does |
|---|---|
| Declare permission | Declares, or describes again, a permission of a resource server |
| Remove permission | Removes it, and removes it from every role |
| Permissions | Lists the permissions of a resource server |
| Define role | Creates a role or replaces it, after the checks above |
| Remove role | Removes a role no other role includes, with its assignments |
| Roles | Lists the tenant's roles, or one role |
| Assign | Gives a role to a principal, for the tenant or an application, with an optional start and end |
| Revoke | Takes it away |
| Assignments of a principal | Lists a principal's assignments |

They are not reachable through the administration interface, the command-line tool or the console yet; that is Issue-80.

### Events of native role-based access control

| Event type | When |
|---|---|
| `authorization.permission_declared` | A permission was declared or described again; carries the namespace and the permission |
| `authorization.permission_removed` | A permission was removed |
| `authorization.role_defined` | A role was created or replaced; carries the namespace and the name |
| `authorization.role_removed` | A role was removed |
| `authorization.principal_role_assigned` | A role was given to a principal, or its start and end changed; carries the principal, the role and the scope |
| `authorization.principal_role_revoked` | A role was taken away from a principal |

### Port of native role-based access control

| Port | Purpose |
|---|---|
| `NativeRoleStore` | Store, read and remove a tenant's permissions, roles and assignments, and read and raise its role revision |

### Storage of native role-based access control

| Table | Primary key | What it holds |
|---|---|---|
| `authorization.permission` | `tenant_id`, `namespace`, `name` | The declared permissions, with a description |
| `authorization.role` | `tenant_id`, `namespace`, `name` | The roles, with a description |
| `authorization.role_permission` | `tenant_id`, `namespace`, `role`, `permission` | What each role holds. Goes with its role and with its permission |
| `authorization.role_inclusion` | `tenant_id`, `namespace`, `role`, `included_namespace`, `included_role` | What each role includes. Goes with the including role; the included role cannot be removed while it is there |
| `authorization.role_revision` | `tenant_id` | The tenant's role revision |
| `authorization.role_assignment` | See [above](#authorizationrole_assignment) | Who holds which role |

All are tenant tables under row-level security. None of them may name `hodor:admin` except the assignments of the built-in roles.

## Open Policy Agent as an engine

The engine `open_policy_agent` asks an Open Policy Agent instance through its Data API. It lives in its own crate, `hodor-authorization-opa`, which depends on this context and the kernel only. Nothing in this context knows that Open Policy Agent exists ([Decision 0010](../../decisions/0010-opa-integration.md)). The integration as a whole, with bundles and the policy lifecycle, is in [the authorization architecture](../authorization.md#open-policy-agent-integration). This section is what the engine does with one request.

### Which instance answers

Instances are named by whoever operates the installation, in the server's configuration, never by a tenant, a binding or a request:

| Setting | Meaning |
|---|---|
| `HODOR_OPEN_POLICY_AGENT_ADDRESS` | The shared instance. It runs only policy written by the operator, parameterized by each tenant's data |
| `HODOR_OPEN_POLICY_AGENT_TENANT_ADDRESSES` | Instances dedicated to one tenant each, as `tenant-identifier=address` pairs separated by commas. Policy written by a tenant runs only in an instance of its own |
| `HODOR_OPEN_POLICY_AGENT_TOKEN` | The bearer token Hodor presents to every instance. Open Policy Agent's own interface must require it, and be reachable only from Hodor |

A tenant with an instance of its own is answered by it; any other tenant by the shared instance. With neither, the engine is still registered and answers `indeterminate` with `policy_engine_not_configured`, so that a binding to it fails closed instead of being refused.

An address is an origin, `http://` or `https://`, a host and an optional port, with no path, query, fragment, name or password. Plain HTTP is accepted because the default deployment is a sidecar on `localhost`; the server warns at startup about a plain HTTP address that is not on the machine itself.

### How the instance is reached

Not through the guarded client of [outbound HTTP](../../security/outbound-http.md): that client refuses private addresses, which is where Open Policy Agent lives. The engine has a client of its own, which **calls only the configured origins, exactly**, and refuses everything else, whatever the address resolves to. The addresses come from the operator, and the path is built by the engine, so no input of a tenant or a caller can steer a request anywhere else. The rules that are not about addresses stay: no redirects, no proxy, a limit on the size of the answer (64 kibibytes) and on time.

### The decision path

```text
POST /v1/data/hodor/tenants/t<tenant>/resource_servers/r<namespace>/decision
```

- `<tenant>` is the tenant's identifier, from the caller's credential, as 32 hexadecimal digits.
- `<namespace>` is the first 32 hexadecimal digits of the SHA-256 of the binding's namespace, the resource server's audience. An audience is an address or a name that cannot be a segment of a Rego package; its digest can.

Both come from the `TenantContext` and the binding. **Nothing in the request is part of the path**: an attribute, a resource kind or an identifier that names another tenant or another path is only input that the policy sees.

The policy that answers a tenant's resource server is therefore the rule `decision` of the package `hodor.tenants.t<tenant>.resource_servers.r<namespace>`. The bundles of Issue-78 write it; a person writing Rego does not have to.

### The input

```json
{
  "input": {
    "namespace": "https://api.example.com",
    "subject": { "kind": "user", "id": "…", "attributes": { … } },
    "asserted": { … },
    "resource": { "kind": "document", "id": "…", "attributes": { … } },
    "action": "read",
    "context": { … }
  }
}
```

`subject.attributes` are those Hodor resolved. `asserted` is empty unless the binding trusts what the caller asserts.

### The answer

The only answer taken is a result that is an object with a boolean `allow`:

```json
{ "result": { "allow": true, "reason": "owner_may_read", "policies": ["documents/owner"] } }
```

| What came back | Effect | Reason |
|---|---|---|
| `allow` is `true` | `allow` | `reason` if given, otherwise `policy_allowed` |
| `allow` is `false` | `deny` | `reason` if given, otherwise `policy_denied` |
| No `result`: the rule is not defined for this input, or no policy exists at the path | `indeterminate` | `policy_undefined` |
| Anything else: `allow` missing or not a boolean, a `reason` that is not a code of lower-case letters, digits and `_`, `policies` that are not at most 64 strings, a body that is not JSON | `indeterminate` | `policy_answer_malformed` |

`policies` become the decision's matched policies. A revision is not read yet; it comes with the bundles (Issue-78).

### Failures

Every failure is `indeterminate`, with its own reason. The evaluation then treats it like any other failure of an engine: it denies, unless the binding lets that action fail open.

| Reason | Cause |
|---|---|
| `policy_engine_timed_out` | No answer within the binding's time limit |
| `policy_engine_unreachable` | No connection, twice |
| `policy_engine_error` | An answer with a status other than 200 |
| `policy_engine_unavailable` | The instance's circuit is open |
| `policy_engine_not_configured` | No instance answers this tenant |

- **Time.** The binding's time limit is the whole budget. Each attempt is given what is left of it as its own limit on the connection.
- **One retry**, only when the first attempt could not connect and time is left. It is made at once: a context has no timer, so there is no wait and no jitter. There is never a retry after a time-out or an error status, which would only double the load on an instance that is already struggling.
- **A circuit breaker per instance.** It opens after 5 failures in a row, or when at least half of the last 10 seconds' requests failed and there were at least 10 of them. While it is open the instance is not called, and the answer is `policy_engine_unavailable` at once. After 5 seconds one request is let through as a probe: if it succeeds the circuit closes, if not it opens again for another 5 seconds. Only the instance's failures count (time-outs, connections, error statuses); an undefined or malformed answer is a fault of the policy, not of the instance.

### How policies reach an instance

In production, only as signed bundles that the instance pulls from Hodor (Issue-78). Hodor never sends a policy through Open Policy Agent's Policy API. The tests of this engine do, into a container of their own, because the bundles do not exist yet.

### The capabilities file

`deploy/open-policy-agent/capabilities.json` lists the built-in functions a policy may use. It is the list of Open Policy Agent 1.10.1 without:

| Built-in | Why it is removed |
|---|---|
| `http.send` | Calls any address from inside a decision |
| `net.lookup_ip_addr` | Resolves names: a lookup is a request, and its answer leaks what the network looks like |
| `opa.runtime` | Reads the instance's configuration and environment, where its credentials are |
| `providers.aws.sign_req` | Signs requests to a cloud with credentials of the instance |

Its `allow_net` is empty, so no built-in may reach the network even if one were added back. The functions that only compute on addresses (`net.cidr_contains` and the others of `net.cidr_*`) stay: they read nothing outside the policy.

Open Policy Agent has no setting that limits the built-ins of a running instance. The file is enforced when a policy is checked and built (`opa check --capabilities`, `opa build --capabilities`, Issue-79), so no bundle using a removed built-in is ever published. An instance should run without a route out of its network as well.

## Not built yet

| Item | Planned in |
|---|---|
| Roles given through groups and organizations | When groups and organizations exist ([Decision 0023](../../decisions/0023-what-0.2.0-holds.md)) |
| Assigning and revoking roles through the administration interface. Today the only way to give a role is [the bootstrap command](../../api/admin-api.md#the-first-administrator), and there is no way to take one away | Phase 2 |
| Conditions on attributes in Common Expression Language | Issue-74 |
| The authorization interface for applications, which calls the evaluation; and an implementation of `SubjectAttributeSource`. Until then no binary evaluates through the engine contract, and the administration interface still asks the check above | Issue-75 |
| The record of decisions | Issue-76 |
| Bundles, the revision a decision was made with and the lag of an instance behind what is published | Issue-78 |
| The policy lifecycle, with checks and builds against the capabilities file | Issue-79 |
| A health check of each instance every 5 seconds. Today an instance's health is known only from the decisions it answers, through its circuit | Issue-78, with the status each instance reports |
| Instances and their credentials managed through the administration interface, one token per instance, and mutual TLS | Issue-80 |
| A cache of decisions | When a binding declares its policy deterministic |
| Managing bindings, permissions, roles and assignments through the administration interface, the command-line tool and the console | Issue-80 |
| Access control lists and relationships | Later phase ([Decision 0023](../../decisions/0023-what-0.2.0-holds.md)) |
