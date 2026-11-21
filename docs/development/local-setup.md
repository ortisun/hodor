# Local setup

How to build Hodor, run its checks and start it on your machine. To only run Hodor and see what it does, the [quick-start](../operations/quick-start.md) is shorter.

## What you need

| Tool | Why |
|---|---|
| Rust, the version pinned in `rust-toolchain.toml` | `rustup` installs it automatically on the first `cargo` command |
| Docker | Integration tests start PostgreSQL and VictoriaMetrics in containers; the development stack runs on Compose |
| `cargo-deny`, `cargo-machete` | License, advisory and unused-dependency checks |
| Node.js 24 or newer, with `npm` | Only to work on [the hosted pages](../architecture/hosted-pages.md) or to run the browser tests. Building and testing the Rust workspace does not need it, and neither does the development stack, which builds the pages inside the image |

```bash
cargo install cargo-deny cargo-machete
```

## The checks

These are the commands continuous integration runs. Run them before opening a pull request.

```bash
cargo fmt --all --check
```

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

```bash
cargo test --workspace
```

```bash
cargo deny check
```

```bash
cargo machete
```

The integration tests need Docker running. Each test that touches the database starts its own PostgreSQL container, so the suite needs no setup and leaves nothing behind.

The hosted pages have checks of their own, run from `frontend/auth-ui` after `npm ci`:

```bash
npm run theme-check && npm run lint && npm run typecheck && npm test && npm run build
```

### Running the browser tests

The browser tests drive Chromium against a running stack: they register, read the message in the development mail server, sign in and sign out, as a person would. Start [the development stack](#running-the-development-stack), create the tenant `acme` with open registration ([creating your first tenant](#creating-your-first-tenant)), then, from `frontend/auth-ui`:

```bash
npx playwright install chromium
```

```bash
npm run browser-tests
```

`HODOR_URL`, `HODOR_MAIL_URL` and `HODOR_TENANT` point the tests at a stack on other ports or at another tenant; they default to `http://localhost:8080`, `http://localhost:8025` and `acme`. The tests create new people on every run and remove nothing.

Every run asks for about ten links, and a tenant limits how many may be asked for from one address: fifty in fifteen minutes by default, with waits that grow. After several runs in a row the tests stop before they start and say so. Wait, or create another tenant with open registration and name it in `HODOR_TENANT`.

## Running the development stack

The Compose file in `deploy/docker` builds the image and starts everything Hodor needs:

```bash
docker compose -f deploy/docker/compose.yaml up --build --wait
```

| Service | What it is | Where |
|---|---|---|
| `postgres` | PostgreSQL 17, with the database roles created on first start | internal only |
| `migrate` | Runs `hodor-cli migrate` once and exits | — |
| `system-tenant` | Runs `hodor-cli tenant create-system` once and exits. It creates the system tenant unless it exists | — |
| `server` | `hodor-server`, with the hosted pages | <http://localhost:8080>, health on <http://localhost:9090/readyz> |
| `worker` | `hodor-worker`, writing the audit log and delivering email | internal only |
| `mail` | A mail server for development. It accepts every message and delivers none: what Hodor sends can be read in its web page | <http://localhost:8025> |
| `victoriametrics` | Metrics backend; the server and the worker push to it over OTLP | <http://localhost:8428/vmui> |
| `victoriatraces` | Traces backend; the server and the worker push to it over OTLP | <http://localhost:10428/select/vmui> |

If one of those ports is taken on your machine, choose others:

```bash
HODOR_HTTP_PORT=18080 HODOR_OPS_PORT=19090 HODOR_VM_PORT=18428 HODOR_TRACES_PORT=20428 HODOR_MAIL_PORT=18025 docker compose -f deploy/docker/compose.yaml up --build --wait
```

Set the same variables for every later `docker compose` command on that stack. The commands on this page pass `--no-deps` to `run`, so that running the command-line tool never restarts a service of the stack.

Stop the stack and delete its data:

```bash
docker compose -f deploy/docker/compose.yaml down -v
```

The credentials in the Compose file and in `deploy/docker/postgres-init.sql` are placeholders for local use. They must never be used anywhere else.

### What works today

A person can register, sign in, sign out and recover a forgotten password, in a browser. With the stack running and a tenant created with open registration (see [creating your first tenant](#creating-your-first-tenant)), `hodor-server` serves [the hosted pages](../architecture/hosted-pages.md) under `/t/{slug}/account` and [the interaction interface](../api/interaction-api.md) they call under `/t/{slug}/interaction`. The worker delivers the messages to the development mail server, where they can be read at <http://localhost:8025>.

What is still missing around it:

- The pages cover registering, signing in, signing out and recovering a password. Seeing and ending one's sessions is in the interaction interface but has no page yet.
- [The administration interface](../api/admin-api.md) is served under `/t/{slug}/api/v1/admin`. Its first administrator and their access token come from `hodor-cli admin bootstrap`; see [the first administrator](#the-first-administrator).
- The session cookie is marked `Secure`. Chromium and Firefox accept that on `http://localhost`; Safari does not, and over plain HTTP on any other host name no browser does. Use `localhost` throughout, not `127.0.0.1`: the links in messages point at `localhost`, and a browser keeps the cookies of the two apart.

See [progress](../product/progress.md) for the full picture.

## Configuration

Every setting is a command-line flag with an environment variable of the same meaning. `--help` on each binary lists them.

### `hodor-server`

| Variable | Default | Meaning |
|---|---|---|
| `HODOR_LISTEN_ADDR` | `0.0.0.0:8080` | Public listener |
| `HODOR_OPS_ADDR` | `127.0.0.1:9090` | Operations listener (health). Keep it off the internet |
| `HODOR_DATABASE_URL` | — (required) | Connection URL of a login role that is a member of `hodor_app` |
| `HODOR_DATABASE_MAX_CONNECTIONS` | `10` | Pool size |
| `HODOR_LOG_FORMAT` | `json` | `json` or `pretty` |
| `HODOR_LOG_FILTER` | `info` | `tracing` filter, for example `info,hodor_oauth=debug` |
| `HODOR_OTLP_TRACES_ENDPOINT` | unset | Full URL of the OTLP/HTTP traces endpoint; unset disables export. For VictoriaTraces: `http://<host>:10428/insert/opentelemetry/v1/traces` |
| `HODOR_OTLP_METRICS_ENDPOINT` | unset | Full URL of the OTLP/HTTP metrics endpoint. For VictoriaMetrics: `http://<host>:8428/opentelemetry/v1/metrics` |
| `HODOR_SHUTDOWN_DRAIN_SECONDS` | `5` | How long to keep serving after a stop signal while readiness fails |
| `HODOR_PUBLIC_URL` | `http://localhost:8080` | The address people reach this installation at, without a path. Links in messages start with it |
| `HODOR_SECRET_KEYS` | unset | The keys that keep secrets [encrypted at rest](../security/secrets-at-rest.md#keys). Unset: no identity provider can be used, and none is offered |
| `HODOR_OUTBOUND_DEVELOPMENT_HOSTS` | empty | Hosts with ports, separated by commas, that [outbound requests](../security/outbound-http.md#the-exception-for-development) may reach at a private address and over plain HTTP. Never set it anywhere real |
| `HODOR_PAGES_DIRECTORY` | unset; the image sets `/usr/share/hodor/auth-ui` | The directory holding the built [hosted pages](../architecture/hosted-pages.md#how-the-pages-are-served). Unset: no pages are served. Set to a directory without `index.html`: the server does not start |
| `HODOR_CONSOLE_DIRECTORY` | unset; the image sets `/usr/share/hodor/admin-console` | The directory holding the built [admin console](../architecture/admin-console.md#how-it-is-served). Unset: no console page is served; the console interface is still answered. Set to a directory without `index.html`: the server does not start |
| `HODOR_PASSWORD_HASH_MEMORY_KIBIBYTES` | `19456` | Memory one password hash uses. Raising it makes every password harder to guess offline; existing passwords are re-hashed as their owners sign in |
| `HODOR_PASSWORD_HASH_PASSES` | `2` | Passes over that memory |
| `HODOR_PASSWORD_HASH_LANES` | `1` | Lanes computed in parallel within one hash |
| `HODOR_PASSWORD_HASH_CONCURRENCY` | one per processor core | Password hashes computed at the same time. The memory the server needs for hashing is this number times the memory of one hash |
| `HODOR_PASSWORD_HASH_QUEUE` | four times the concurrency | Requests allowed to wait for a hash. One more is answered "busy, try again" |

### `hodor-worker`

The worker connects to the database twice, with different roles: as a member of `hodor_platform` to find pending work across tenants, and as a member of `hodor_app` to handle each piece of work inside its tenant.

| Variable | Default | Meaning |
|---|---|---|
| `HODOR_DATABASE_URL` | — (required) | Connection URL of a login role that is a member of `hodor_app` |
| `HODOR_PLATFORM_DATABASE_URL` | — (required) | Connection URL of a login role that is a member of `hodor_platform` |
| `HODOR_DATABASE_MAX_CONNECTIONS` | `5` | Size of each of the two pools |
| `HODOR_OPS_ADDR` | `127.0.0.1:9091` | Operations listener (health) |
| `HODOR_OUTBOX_BATCH_SIZE` | `100` | Most events handled per pass |
| `HODOR_OUTBOX_POLL_INTERVAL_MS` | `500` | Pause between passes when there is nothing to deliver |
| `HODOR_SMTP_URL` | unset | Where to send mail: `smtps://user:password@host:465` for an encrypted connection, `smtp://user:password@host:587?tls=required` to encrypt after connecting. Plain `smtp://host:25` does not encrypt and is for development only. Unset: no mail is delivered and messages wait |
| `HODOR_MAIL_FROM` | — (required with `HODOR_SMTP_URL`) | The address messages are sent from, for example `Hodor <no-reply@example.com>` |
| `HODOR_MAIL_BATCH_SIZE` | `50` | Most messages handled per pass |
| `HODOR_MAIL_POLL_INTERVAL_MS` | `1000` | Pause between passes when there is no message to deliver |
| `HODOR_LOG_FORMAT`, `HODOR_LOG_FILTER`, `HODOR_OTLP_TRACES_ENDPOINT`, `HODOR_OTLP_METRICS_ENDPOINT` | as for the server | Telemetry |

### `hodor-cli`

| Command | Variable | Meaning |
|---|---|---|
| `migrate` | `HODOR_DATABASE_OWNER_URL` (required) | Applies pending migrations as the role that owns the schema |
| `tenant create`, `tenant create-system`, `tenant list`, `tenant suspend`, `tenant reactivate` | `HODOR_DATABASE_URL` (required) | Manage tenants as a member of `hodor_app`. See [the tenant context](../architecture/contexts/tenant.md#command-line-tool) |
| `admin bootstrap --tenant <slug> --email <address>` | `HODOR_DATABASE_URL` (required) | Makes a user an administrator of a tenant, creating the user if needed, and prints an access token for [the administration interface](../api/admin-api.md#the-first-administrator) |
| `audit verify --tenant <slug>` | `HODOR_DATABASE_URL` (required) | Checks a tenant's whole chain of audit records and exits non-zero if a record was changed, removed or inserted. See [the audit context](../architecture/contexts/audit.md#verifying) |
| `provider add`, `provider list`, `provider disable`, `provider enable` | `HODOR_DATABASE_URL` and `HODOR_SECRET_KEYS` (required) | Manage a tenant's [identity providers](../architecture/contexts/federation.md#identity-providers). `provider add` reads the client secret from `HODOR_PROVIDER_CLIENT_SECRET`, never from an argument, so that it does not show in the list of processes or in the history of a shell |
| `secrets generate-key` | — | Prints a new key for `HODOR_SECRET_KEYS`. See [secrets at rest](../security/secrets-at-rest.md#keys) |
| `probe` | — | Requests a health endpoint (`--addr`, `--path`) and exits non-zero unless it answers 200. Used by container health checks, since the image has no shell |

### Creating your first tenant

With the development stack running:

```bash
docker compose -f deploy/docker/compose.yaml run --rm --no-deps --entrypoint /usr/local/bin/hodor-cli -e HODOR_DATABASE_URL=postgres://hodor_server:dev-server@postgres:5432/hodor server tenant create --slug acme --name "Acme" --open-registration
```

The tenant's pages are then at <http://localhost:8080/t/acme/account>. `--open-registration` lets anyone register in it; without it only administrators create users, through [the administration interface](../api/admin-api.md).

### Registering your first person

1. Open <http://localhost:8080/t/acme/account/register> and give an address, for example `ana@example.com`.
2. Open the development mail server at <http://localhost:8025>, read the message and follow its link.
3. Choose a password of 12 characters or more.
4. Sign in with the address and the password.

The same can be done without a browser, with the requests of [the interaction interface](../api/interaction-api.md#registering-and-recovering-a-password).

### The first administrator

Make someone an administrator of the tenant and get an access token for them:

```bash
docker compose -f deploy/docker/compose.yaml run --rm --no-deps --entrypoint /usr/local/bin/hodor-cli -e HODOR_DATABASE_URL=postgres://hodor_server:dev-server@postgres:5432/hodor server admin bootstrap --tenant acme --email ana@example.com
```

Use the token it prints to call the administration interface, for example to list the tenant's users:

```bash
curl -s http://localhost:8080/t/acme/api/v1/admin/users -H 'Authorization: Bearer <the token>'
```

The token lives for an hour. Running the command again gives a new one.

## Database roles

Hodor never connects as the owner of its tables. See [multi-tenancy](../architecture/multi-tenancy.md#isolation-by-layer) for why.

| Role | Kind | Used by |
|---|---|---|
| Schema owner | Login | `hodor-cli migrate` only |
| `hodor_app` | Group, no login | Row-level security applies; sees one tenant at a time |
| `hodor_platform` | Group, no login | Cross-tenant jobs; sees all tenants |
| A login role in `hodor_app` | Login | `hodor-server`, and `hodor-worker` when it handles an event |
| A login role in `hodor_platform` | Login | `hodor-worker` when it looks for pending work |

The migrations create the two group roles if they are missing. Login roles are created by whoever operates the database; `deploy/docker/postgres-init.sql` shows how.
