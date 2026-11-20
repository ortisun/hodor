# Local setup

How to build Hodor, run its checks and start it on your machine.

## What you need

| Tool | Why |
|---|---|
| Rust, the version pinned in `rust-toolchain.toml` | `rustup` installs it automatically on the first `cargo` command |
| Docker | Integration tests start PostgreSQL and VictoriaMetrics in containers; the development stack runs on Compose |
| `cargo-deny`, `cargo-machete` | License, advisory and unused-dependency checks |

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

## Running the development stack

The Compose file in `deploy/docker` builds the image and starts everything Hodor needs:

```bash
docker compose -f deploy/docker/compose.yaml up --build --wait
```

| Service | What it is | Where |
|---|---|---|
| `postgres` | PostgreSQL 17, with the database roles created on first start | internal only |
| `migrate` | Runs `hodor-cli migrate` once and exits | — |
| `server` | `hodor-server` | <http://localhost:8080>, health on <http://localhost:9090/readyz> |
| `worker` | `hodor-worker`, delivering outbox events | internal only |
| `victoriametrics` | Metrics backend; the server pushes to it over OTLP | <http://localhost:8428/vmui> |

If one of those ports is taken on your machine, choose others:

```bash
HODOR_HTTP_PORT=18080 HODOR_OPS_PORT=19090 HODOR_VM_PORT=18428 docker compose -f deploy/docker/compose.yaml up --build --wait
```

Stop the stack and delete its data:

```bash
docker compose -f deploy/docker/compose.yaml down -v
```

The credentials in the Compose file and in `deploy/docker/postgres-init.sql` are placeholders for local use. They must never be used anywhere else.

### What works today

The server starts, connects to the database and answers its health endpoints. There are no tenants yet, so every path under `/t/{slug}` answers `404` with a problem document. See [progress](../product/progress.md) for what has been built.

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
| `HODOR_OTLP_TRACES_ENDPOINT` | unset | Full URL of the OTLP/HTTP traces endpoint; unset disables export |
| `HODOR_OTLP_METRICS_ENDPOINT` | unset | Full URL of the OTLP/HTTP metrics endpoint. For VictoriaMetrics: `http://<host>:8428/opentelemetry/v1/metrics` |
| `HODOR_SHUTDOWN_DRAIN_SECONDS` | `5` | How long to keep serving after a stop signal while readiness fails |

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
| `HODOR_LOG_FORMAT`, `HODOR_LOG_FILTER`, `HODOR_OTLP_TRACES_ENDPOINT`, `HODOR_OTLP_METRICS_ENDPOINT` | as for the server | Telemetry |

### `hodor-cli`

| Command | Variable | Meaning |
|---|---|---|
| `migrate` | `HODOR_DATABASE_OWNER_URL` (required) | Applies pending migrations as the role that owns the schema |
| `probe` | — | Requests a health endpoint (`--addr`, `--path`) and exits non-zero unless it answers 200. Used by container health checks, since the image has no shell |

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
