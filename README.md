# Hodor

Identity, authentication and authorization platform written in Rust: identity provider, OAuth 2.x authorization server, OpenID Provider, federation broker and policy decision point, multi-tenant from the start.

Milestone 1, the walking skeleton, is built: a person registers, verifies an email address, signs in with a password and gets a session in a tenant, with tenant isolation, an audit log and telemetry. OAuth, OpenID Connect, federation and policies come in the phases that follow. [Progress](docs/product/progress.md) says what exists and what does not.

## Try it

The [quick-start](docs/operations/quick-start.md) goes from a clean checkout to a tenant people sign in to, with Docker and nothing else:

```bash
docker compose -f deploy/docker/compose.yaml up --build --wait
```

```bash
python3 deploy/demo/demo.py
```

The second command is the demonstration of the milestone: it creates two tenants and shows, checking every answer, that they are kept apart.

## Layout

| Path | Contents |
|---|---|
| `crates/` | One crate per bounded context, plus adapters |
| `apps/` | `hodor-server`, `hodor-worker`, `hodor-cli` |
| `frontend/` | The hosted pages and the showcase of the design system, both built on Astryx with the Hodor theme |
| `migrations/` | The database schema |
| `deploy/` | The container image, the development stack and the demonstration |
| `docs/` | Product, architecture, protocol, security and operations documentation, and the decision records. The design lives there; start with the [index](docs/README.md) |

## Development

[Local setup](docs/development/local-setup.md) says how to build Hodor, run its checks and work on it; the [conventions](docs/development/conventions.md) say how changes are made.

## Contributing

- Commits follow [Conventional Commits](https://www.conventionalcommits.org/).
- Branching follows Gitflow: feature branches are cut from `develop` and merged back through pull requests; `main` holds releases.
