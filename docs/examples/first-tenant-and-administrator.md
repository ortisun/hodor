# A tenant and its first administrator

A company that runs Hodor for its customers gives each customer a tenant. Most of those tenants do not let strangers register: an administrator of the tenant adds its people. This example creates such a tenant, `globex`, makes its first administrator with the command-line tool, lets the administrator choose a password, and opens the admin console as them.

You need the [development stack](../operations/quick-start.md#1-start-the-stack) running. Nothing else.

```mermaid
sequenceDiagram
    autonumber
    participant Operator as Operator, with hodor-cli
    participant Hodor
    participant Mailbox as Development mail server
    participant Carla as Carla, in a browser
    Operator->>Hodor: tenant create --slug globex
    Operator->>Hodor: admin bootstrap --tenant globex --email carla@example.com
    Hodor-->>Operator: Carla is created, with the role tenant_administrator, and an access token
    Carla->>Hodor: Recover a password for carla@example.com
    Hodor->>Mailbox: A link to choose a password
    Carla->>Hodor: Follow the link, choose a password, sign in
    Carla->>Hodor: Open the admin console
```

## 1. Create the tenant

```bash
docker compose -f deploy/docker/compose.yaml run --rm --no-deps --entrypoint /usr/local/bin/hodor-cli -e HODOR_DATABASE_URL=postgres://hodor_server:dev-server@postgres:5432/hodor server tenant create --slug globex --name "Globex"
```

It answers with the slug and the tenant's identifier:

```text
created globex 01a20106-9e7a-75f4-8d49-b65408716f3c
```

Without `--open-registration`, the tenant accepts no registrations: its registration page is there, and sending it an address is refused with `403` and `authentication.registration_closed`. People get in only once an administrator has added them, or through an [identity provider](signing-in-through-identity-providers.md) that is allowed to create users.

`tenant list` shows every tenant of the installation, with the system tenant that the stack creates when it starts:

```bash
docker compose -f deploy/docker/compose.yaml run --rm --no-deps --entrypoint /usr/local/bin/hodor-cli -e HODOR_DATABASE_URL=postgres://hodor_server:dev-server@postgres:5432/hodor server tenant list
```

## 2. Make the first administrator

Nobody can be given a role through the administration interface yet, so the first administrator is made by someone who can run commands against the installation:

```bash
docker compose -f deploy/docker/compose.yaml run --rm --no-deps --entrypoint /usr/local/bin/hodor-cli -e HODOR_DATABASE_URL=postgres://hodor_server:dev-server@postgres:5432/hodor server admin bootstrap --tenant globex --email carla@example.com
```

```text
user 01a20106-a4f6-769c-80ad-29f8a9cee02c carla@example.com
role tenant_administrator
token hodor_at_…
expires 2026-11-22T03:12:22Z
```

The command finds the user with that address in the tenant or creates one, active and without a password; gives them the role `tenant_administrator`; and prints an access token for [the administration interface](../api/admin-api.md#the-first-administrator), once. The token lives an hour; running the command again gives a new one. What the command did is in the tenant's audit log, with Hodor itself as the actor.

To keep the token in a shell variable instead of copying it, take the line that starts with `token`:

```bash
TOKEN=$(docker compose -f deploy/docker/compose.yaml run --rm --no-deps --entrypoint /usr/local/bin/hodor-cli -e HODOR_DATABASE_URL=postgres://hodor_server:dev-server@postgres:5432/hodor server admin bootstrap --tenant globex --email carla@example.com | awk '/^token/ {print $2}')
```

and ask the administration interface who is in the tenant:

```bash
curl -s http://localhost:8080/t/globex/api/v1/admin/users -H "Authorization: Bearer $TOKEN"
```

The answer holds one user, Carla, whose address is not verified yet:

```json
{
  "items": [
    {
      "id": "01a20106-a4f6-769c-80ad-29f8a9cee02c",
      "kind": "human",
      "status": "active",
      "status_reason": null,
      "display_name": null,
      "locale": null,
      "identifiers": [
        { "id": "01a20106-a4f6-769c-80ad-29f9f4aa3811", "kind": "email", "value": "carla@example.com", "verified": false, "primary": true }
      ],
      "created_at": "2026-11-22T02:12:22.390079Z",
      "updated_at": "2026-11-22T02:12:22.390079Z"
    }
  ]
}
```

## 3. Let the administrator choose a password

Nobody, administrators included, ever sets or knows another person's password. Carla chooses hers the way anyone recovers a forgotten one, which also proves that the mailbox is hers:

1. Open <http://localhost:8080/t/globex/account/recover> and give `carla@example.com`.
2. Open the development mail server at <http://localhost:8025> and read the message *Choose a new password for Globex*. Follow its link.
3. Choose a password of 12 characters or more. The page then asks you to sign in with it.

## 4. Sign in and open the console

1. Sign in at <http://localhost:8080/t/globex/account/sign-in> with `carla@example.com` and the new password.
2. Open <http://localhost:8080/t/globex/console>. The console recognizes the session of the hosted pages and opens on the users of the tenant.

![The admin console: the users screen, with the users of a tenant, their status, email addresses and whether each address is verified](../images/admin-console.png)

From the console Carla can create users, suspend them, end their sessions, read the audit log and add identity providers. A person she creates chooses a password the same way she did, in step 3. [The admin console](../architecture/admin-console.md) describes every screen.

## What to read next

- [Calling the administration interface](administration-interface.md) does with `curl` what the console does.
- [The tenant context](../architecture/contexts/tenant.md) has the rules of tenants: slugs, statuses, suspension, the system tenant.
- [Multi-tenant isolation](../architecture/multi-tenancy.md) explains why a token, a cookie or a password of one tenant means nothing in another.
