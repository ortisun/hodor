# Holdor

Identity, authentication and authorization platform written in Rust: identity provider, OAuth 2.x authorization server, OpenID Provider, federation broker and policy decision point, multi-tenant from the start.

The project is at the beginning of Milestone 1. The design lives in [docs/](docs/README.md); start with the [critical review](docs/architecture/critical-review.md).

## Layout

| Path | Contents |
|---|---|
| `crates/` | One crate per bounded context, plus adapters |
| `apps/` | `holdor-server`, `holdor-worker`, `holdor-cli` |
| `docs/` | Product, architecture, protocol, security and operations documentation, ADRs |

## Development

Requires the Rust toolchain pinned in `rust-toolchain.toml`, plus `cargo-deny` and `cargo-machete`.

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
cargo machete
```

## Contributing

- Commits follow [Conventional Commits](https://www.conventionalcommits.org/).
- Branching follows Gitflow: feature branches are cut from `develop` and merged back through pull requests; `main` holds releases.
