# Examples

Worked examples on the development stack: each one starts from a running stack and ends with something you can see in a browser or in an answer. They use only what Hodor does today, and every command in them is run as written against the code on `develop`.

Start the stack first, as the [quick-start](../operations/quick-start.md#1-start-the-stack) says:

```bash
docker compose -f deploy/docker/compose.yaml up --build --wait
```

| Example | What you do | What you need first |
|---|---|---|
| [A tenant and its first administrator](first-tenant-and-administrator.md) | Create a tenant where only administrators add people, make its first administrator with `hodor-cli`, let them choose a password, and open the admin console | The stack |
| [Signing in through identity providers](signing-in-through-identity-providers.md) | Add an OpenID Connect provider, an LDAP directory and a SAML identity provider to a tenant, sign in through each, and add GitHub | The tenant `acme` of the [quick-start](../operations/quick-start.md#2-create-a-tenant) |
| [Calling the administration interface](administration-interface.md) | Get an access token and use `curl` to list, create and suspend users, end a session, read the audit log, and manage identity providers | The tenant `acme` and its administrator from the [quick-start](../operations/quick-start.md#4-make-an-administrator) |

## Running the command-line tool

`hodor-cli` is in the image. Every example runs it through Compose, as one more container of the stack, so nothing is installed on your machine:

```bash
docker compose -f deploy/docker/compose.yaml run --rm --no-deps --entrypoint /usr/local/bin/hodor-cli -e HODOR_DATABASE_URL=postgres://hodor_server:dev-server@postgres:5432/hodor server tenant list
```

The container is a copy of the `server` service with `hodor-cli` in place of the server. It has the server's settings, such as `HODOR_SECRET_KEYS` and the hosts the development providers live at, so the identity provider commands need nothing more. `--no-deps` keeps Compose from restarting the services the server depends on. [Local setup](../development/local-setup.md#hodor-cli) lists every command and the variables it reads, and `--help` after any command describes it.

## If the stack is on other ports

If a port of the stack was taken on your machine and you chose others, as [local setup](../development/local-setup.md#running-the-development-stack) says, set the same variables for every `docker compose` command, and use your port in place of `8080` in the addresses.

The development stack's passwords and keys are written in the repository. Nothing in these examples belongs anywhere real.
