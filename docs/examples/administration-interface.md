# Calling the administration interface

The administration interface is how the people who run a tenant, and the programs they write, manage it over HTTP: users, sessions, the audit log and identity providers. This example calls every part of it with `curl`. The admin console does the same through [the console interface](../api/console-interface.md); this is the way for scripts.

You need the stack running, the tenant `acme` and its administrator from the [quick-start](../operations/quick-start.md#4-make-an-administrator), and Python 3, which the commands below use to read values out of the answers. [The administration interface](../api/admin-api.md) specifies everything shown here, and [its OpenAPI document](../api/admin-reference.md) describes every operation.

## 1. Get a token

Every request carries an access token of a user who holds a role in the tenant. `hodor-cli admin bootstrap` makes such a user and prints a token for them, which lives an hour. Keep it in a variable, with the address of the interface:

```bash
TOKEN=$(docker compose -f deploy/docker/compose.yaml run --rm --no-deps --entrypoint /usr/local/bin/hodor-cli -e HODOR_DATABASE_URL=postgres://hodor_server:dev-server@postgres:5432/hodor server admin bootstrap --tenant acme --email ana@example.com | awk '/^token/ {print $2}')
```

```bash
ADMIN=http://localhost:8080/t/acme/api/v1/admin
```

Every path below is relative to the tenant: the same token in another tenant is unknown there.

## 2. Users

List the users, oldest first:

```bash
curl -s $ADMIN/users -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

```json
{
    "items": [
        {
            "id": "01a200ff-de31-7597-ab93-59632abfc2ce",
            "kind": "human",
            "status": "active",
            "status_reason": null,
            "display_name": "Ana",
            "locale": "en",
            "identifiers": [
                {
                    "id": "01a200ff-de31-7597-ab93-5964b1d8188d",
                    "kind": "email",
                    "value": "ana@example.com",
                    "verified": true,
                    "primary": true
                }
            ],
            "created_at": "2026-11-22T02:04:58.289178Z",
            "updated_at": "2026-11-22T02:04:58.292845Z"
        }
    ]
}
```

Create one. `display_name` and `locale` are optional; the locale chooses the language of the messages the person receives, English or Brazilian Portuguese (`pt-BR`). The answer is `201` with the user, and the command keeps their identifier:

```bash
BRUNO=$(curl -s -X POST $ADMIN/users -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"email": "bruno@example.com", "display_name": "Bruno Costa", "locale": "pt-BR"}' | python3 -c 'import json, sys; print(json.load(sys.stdin)["id"])')
```

Read them back:

```bash
curl -s $ADMIN/users/$BRUNO -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

Bruno is active, without a password, and his address is not verified. Nobody sets a password for him: he chooses one by recovering it at <http://localhost:8080/t/acme/account/recover>, and the message, *Escolha uma nova senha para Acme*, arrives in Portuguese because of his locale. Following its link verifies his address.

Creating the same address again is refused, and the answer says why, as every error of the interface does, in a problem document:

```bash
curl -s -X POST $ADMIN/users -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"email": "bruno@example.com"}'
```

```json
{"type":"urn:hodor:error:identity.identifier_taken","title":"Conflict","status":409,"detail":"this login identifier is already in use","code":"identity.identifier_taken","request_id":"01a20102-e2e9-74b2-9b3a-bac8fd57c2a0"}
```

Lists come a page at a time. `limit` is 50 unless given, and at most 200; while there are more, the answer has `next_cursor`, which is passed back as `cursor`:

```bash
curl -s "$ADMIN/users?limit=1" -H "Authorization: Bearer $TOKEN" | python3 -c 'import json, sys; print(json.load(sys.stdin)["next_cursor"])'
```

```bash
curl -s "$ADMIN/users?limit=1&cursor=<the cursor>" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

## 3. Sessions

Sign in as Ana in a browser, at <http://localhost:8080/t/acme/account/sign-in>, if you are not signed in already. Then list her sessions:

```bash
ANA=$(curl -s "$ADMIN/users?limit=1" -H "Authorization: Bearer $TOKEN" | python3 -c 'import json, sys; print(json.load(sys.stdin)["items"][0]["id"])')
```

```bash
curl -s $ADMIN/users/$ANA/sessions -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

```json
{
    "items": [
        {
            "session_id": "01a20101-af59-738d-b319-7a1df40fd9c7",
            "started_at": "2026-11-22T02:06:57.369684Z",
            "last_activity_at": "2026-11-22T02:07:59.76075Z",
            "expires_at": "2026-11-22T02:37:59.76075Z",
            "address": "192.168.112.1",
            "description": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 …"
        }
    ]
}
```

The address is the one Hodor saw the browser connect from; on the development stack it is an address of Docker's own network. End the session:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X DELETE $ADMIN/sessions/<the session_id> -H "Authorization: Bearer $TOKEN"
```

It answers `204`, and so does ending a session that has already ended. Reload the page in the browser: Ana is no longer signed in.

## 4. Suspending a user

A suspended user cannot sign in, and their sessions end with the next request each one makes. A reason is required:

```bash
curl -s -X POST "$ADMIN/users/${BRUNO}:suspend" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"reason": "left the company"}' | python3 -m json.tool
```

The answer is the user, with `"status": "suspended"` and `"status_reason": "left the company"`. The interface cannot reactivate a user yet; that comes in Phase 2.

## 5. The audit log

Everything above was recorded: the registration, the sign-ins, the token issued by the command-line tool, the user created and suspended, the session ended. Read the log, oldest first:

```bash
curl -s "$ADMIN/audit-records?limit=200" -H "Authorization: Bearer $TOKEN" | python3 -c 'import json, sys; [print(record["sequence"], record["action"], record["actor"]["kind"]) for record in json.load(sys.stdin)["items"]]'
```

```text
1 tenant.created system
2 tenant.settings_changed system
3 tenant.activated system
4 notification.message_sent system
5 identity.user_created anonymous
…
14 identity.user_created user
15 identity.identifier_added user
…
```

Each record carries the hash of the one before it and its own, in hexadecimal, so that anyone can check the chain. `hodor-cli` checks it whole:

```bash
docker compose -f deploy/docker/compose.yaml run --rm --no-deps --entrypoint /usr/local/bin/hodor-cli -e HODOR_DATABASE_URL=postgres://hodor_server:dev-server@postgres:5432/hodor server audit verify --tenant acme
```

```text
intact: 41 records
```

The number is how many records the tenant has. It exits with an error if a record was changed, removed or inserted. [The audit context](../architecture/contexts/audit.md) explains the chain.

## 6. Identity providers

The interface manages the same providers as `hodor-cli provider`. Add the development OpenID Connect provider a second time, under another alias. The client secret goes in the request and never comes back out:

```bash
PROVIDER=$(curl -s -X POST $ADMIN/identity-providers -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"alias": "development-again", "display_name": "Development provider, added through the interface", "issuer": "http://provider:9400", "client_id": "hodor", "client_secret": "development-client-secret"}' | python3 -c 'import json, sys; print(json.load(sys.stdin)["id"])')
```

List the tenant's providers. The answer has, for each, the `callback_address` to register at the provider, or for a SAML provider the `metadata_address` to give it:

```bash
curl -s $ADMIN/identity-providers -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

Change its name on the sign-in page, then stop it from signing anyone in:

```bash
curl -s -X PATCH $ADMIN/identity-providers/$PROVIDER -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"display_name": "Development provider, renamed"}' | python3 -m json.tool
```

```bash
curl -s -X POST "$ADMIN/identity-providers/${PROVIDER}:disable" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

The answer has `"status": "disabled"`, and the sign-in page no longer offers it. `:enable` turns it back on. A GitHub provider, a directory or a SAML provider is added the same way, with `kind` and the fields of its kind; [the identity providers section](../api/admin-api.md#identity-providers) lists them.

## 7. When the token is missing or wrong

A request without a token, with an expired one, or with another tenant's, gets the same answer, which says nothing about what was asked for:

```bash
curl -s -i $ADMIN/users
```

```text
HTTP/1.1 401 Unauthorized
content-type: application/problem+json
www-authenticate: Bearer
…
```

A good token whose user lacks the permission gets `403` and `admin.forbidden`. [Who may call it](../api/admin-api.md#who-may-call-it) has the order of the checks.

## 8. The OpenAPI document

The server describes the interface in an OpenAPI document, served without a token:

```bash
curl -s $ADMIN/openapi.json | python3 -c 'import json, sys; document = json.load(sys.stdin); print(document["info"]["title"], document["info"]["version"]); [print(path) for path in document["paths"]]'
```

Give it to a client generator, or read it on [this site](../api/admin-reference.md).
