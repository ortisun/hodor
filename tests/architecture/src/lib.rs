//! Dependency rules of the Holdor workspace.
//!
//! The rules mirror `docs/architecture/crates.md`. They are data, so a new
//! crate or a new edge between crates is a visible, reviewed change to this
//! file rather than an accident in a `Cargo.toml`.
//!
//! Only normal and build dependencies are checked. Dev-dependencies are
//! exempt so that tests may use fakes and harnesses from other crates.

// The crate exists only for its tests.
#![cfg(test)]

/// Which workspace crates a crate may depend on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Allowed {
    /// Composition roots may depend on any workspace crate.
    Any,
    /// Only the listed workspace crates.
    Only(&'static [&'static str]),
}

/// One workspace crate and what it may depend on.
#[derive(Debug, Clone, Copy)]
struct Rule {
    name: &'static str,
    /// Workspace crates this crate may depend on.
    workspace: Allowed,
    /// Whether the crate is domain or application code (layers 0 to 3), which
    /// must stay free of infrastructure libraries.
    infrastructure_free: bool,
}

const fn context(name: &'static str, deps: &'static [&'static str]) -> Rule {
    Rule {
        name,
        workspace: Allowed::Only(deps),
        infrastructure_free: true,
    }
}

const fn adapter(name: &'static str, deps: &'static [&'static str]) -> Rule {
    Rule {
        name,
        workspace: Allowed::Only(deps),
        infrastructure_free: false,
    }
}

const fn app(name: &'static str) -> Rule {
    Rule {
        name,
        workspace: Allowed::Any,
        infrastructure_free: false,
    }
}

/// Every crate the workspace may contain. Crates appear here before they
/// exist; a crate that exists without an entry fails the check.
const RULES: &[Rule] = &[
    // Layer 0: kernel.
    context("holdor-kernel", &[]),
    // Layer 1: base contexts.
    context("holdor-tenant", &["holdor-kernel"]),
    context("holdor-identity", &["holdor-kernel"]),
    context("holdor-credential", &["holdor-kernel"]),
    context("holdor-session", &["holdor-kernel"]),
    context("holdor-keys", &["holdor-kernel"]),
    context("holdor-audit", &["holdor-kernel"]),
    context("holdor-notification", &["holdor-kernel"]),
    context("holdor-authorization", &["holdor-kernel"]),
    // Layer 2: orchestrating contexts.
    context(
        "holdor-authentication",
        &[
            "holdor-kernel",
            "holdor-identity",
            "holdor-credential",
            "holdor-session",
            "holdor-tenant",
            "holdor-notification",
        ],
    ),
    context(
        "holdor-oauth",
        &[
            "holdor-kernel",
            "holdor-identity",
            "holdor-session",
            "holdor-keys",
            "holdor-tenant",
        ],
    ),
    context(
        "holdor-saml",
        &[
            "holdor-kernel",
            "holdor-identity",
            "holdor-session",
            "holdor-keys",
        ],
    ),
    context("holdor-provisioning", &["holdor-kernel", "holdor-identity"]),
    // Layer 3: context extensions.
    context(
        "holdor-federation",
        &["holdor-kernel", "holdor-authentication", "holdor-identity"],
    ),
    context(
        "holdor-authorization-native",
        &["holdor-kernel", "holdor-authorization"],
    ),
    context(
        "holdor-authorization-opa",
        &["holdor-kernel", "holdor-authorization"],
    ),
    context(
        "holdor-plugin-runtime",
        &["holdor-kernel", "holdor-authentication", "holdor-oauth"],
    ),
    // Layer 4: adapters. An adapter never depends on another adapter.
    adapter(
        "holdor-adapters-postgres",
        &[
            "holdor-kernel",
            "holdor-tenant",
            "holdor-identity",
            "holdor-credential",
            "holdor-session",
            "holdor-keys",
            "holdor-authentication",
            "holdor-federation",
            "holdor-oauth",
            "holdor-authorization",
            "holdor-audit",
        ],
    ),
    adapter(
        "holdor-adapters-redis",
        &[
            "holdor-kernel",
            "holdor-session",
            "holdor-authentication",
            "holdor-oauth",
            "holdor-authorization",
        ],
    ),
    adapter(
        "holdor-adapters-crypto",
        &[
            "holdor-kernel",
            "holdor-credential",
            "holdor-keys",
            "holdor-oauth",
        ],
    ),
    adapter("holdor-adapters-kms", &["holdor-kernel", "holdor-keys"]),
    adapter("holdor-adapters-http", &["holdor-kernel"]),
    adapter("holdor-observability", &["holdor-kernel"]),
    adapter(
        "holdor-protocol-http",
        &[
            "holdor-kernel",
            "holdor-tenant",
            "holdor-identity",
            "holdor-credential",
            "holdor-session",
            "holdor-authentication",
            "holdor-federation",
            "holdor-oauth",
            "holdor-authorization",
            "holdor-audit",
            "holdor-keys",
        ],
    ),
    // Layer 5: composition roots.
    app("holdor-server"),
    app("holdor-worker"),
    app("holdor-cli"),
    // Test support.
    adapter("holdor-architecture-tests", &[]),
];

/// Libraries that domain and application crates must not depend on.
const INFRASTRUCTURE: &[&str] = &[
    "axum", "hyper", "redis", "reqwest", "sqlx", "tokio", "tower",
];

/// A workspace crate and its direct normal and build dependencies.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CrateDeps {
    name: String,
    dependencies: Vec<String>,
}

/// Returns one message per rule violation; empty means the workspace conforms.
fn violations(workspace: &[CrateDeps]) -> Vec<String> {
    let members: Vec<&str> = workspace.iter().map(|c| c.name.as_str()).collect();
    let mut found = Vec::new();

    for krate in workspace {
        let Some(rule) = RULES.iter().find(|r| r.name == krate.name) else {
            found.push(format!(
                "`{}` has no dependency rule; add it to RULES and to docs/architecture/crates.md",
                krate.name
            ));
            continue;
        };

        for dep in &krate.dependencies {
            let is_member = members.contains(&dep.as_str());
            if is_member {
                if let Allowed::Only(allowed) = rule.workspace
                    && !allowed.contains(&dep.as_str())
                {
                    found.push(format!("`{}` must not depend on `{dep}`", krate.name));
                }
            } else if rule.infrastructure_free && INFRASTRUCTURE.contains(&dep.as_str()) {
                found.push(format!(
                    "`{}` is domain or application code and must not depend on `{dep}`",
                    krate.name
                ));
            }
        }
    }

    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use cargo_metadata::{DependencyKind, MetadataCommand};

    fn krate(name: &str, dependencies: &[&str]) -> CrateDeps {
        CrateDeps {
            name: name.to_owned(),
            dependencies: dependencies.iter().map(|d| (*d).to_owned()).collect(),
        }
    }

    #[test]
    fn workspace_follows_the_dependency_rules() {
        let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml");
        let metadata = MetadataCommand::new()
            .manifest_path(manifest)
            .no_deps()
            .exec()
            .expect("cargo metadata should run");

        let workspace: Vec<CrateDeps> = metadata
            .workspace_packages()
            .into_iter()
            .map(|package| CrateDeps {
                name: package.name.to_string(),
                dependencies: package
                    .dependencies
                    .iter()
                    .filter(|d| d.kind != DependencyKind::Development)
                    .map(|d| d.name.clone())
                    .collect(),
            })
            .collect();

        assert!(!workspace.is_empty(), "no workspace crates were found");
        let found = violations(&workspace);
        assert!(
            found.is_empty(),
            "dependency rules violated:\n{}",
            found.join("\n")
        );
    }

    #[test]
    fn allowed_edges_pass() {
        let workspace = [
            krate("holdor-kernel", &["uuid"]),
            krate("holdor-identity", &["holdor-kernel", "serde"]),
            krate(
                "holdor-authentication",
                &["holdor-kernel", "holdor-identity"],
            ),
        ];
        assert_eq!(violations(&workspace), Vec::<String>::new());
    }

    #[test]
    fn a_context_cannot_depend_on_infrastructure() {
        let workspace = [krate("holdor-identity", &["holdor-kernel", "sqlx"])];
        let found = violations(&workspace);
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("`sqlx`"), "{found:?}");
    }

    #[test]
    fn an_adapter_may_depend_on_infrastructure() {
        let workspace = [krate(
            "holdor-adapters-postgres",
            &["holdor-kernel", "sqlx"],
        )];
        assert_eq!(violations(&workspace), Vec::<String>::new());
    }

    #[test]
    fn oauth_and_authentication_stay_independent() {
        let workspace = [
            krate("holdor-authentication", &["holdor-oauth"]),
            krate("holdor-oauth", &["holdor-authentication"]),
        ];
        assert_eq!(violations(&workspace).len(), 2);
    }

    #[test]
    fn no_context_depends_on_audit() {
        let workspace = [
            krate("holdor-audit", &["holdor-kernel"]),
            krate("holdor-identity", &["holdor-audit"]),
        ];
        assert_eq!(violations(&workspace).len(), 1);
    }

    #[test]
    fn an_adapter_cannot_depend_on_another_adapter() {
        let workspace = [
            krate("holdor-adapters-postgres", &[]),
            krate("holdor-protocol-http", &["holdor-adapters-postgres"]),
        ];
        assert_eq!(violations(&workspace).len(), 1);
    }

    #[test]
    fn an_unknown_crate_is_rejected() {
        let workspace = [krate("holdor-surprise", &[])];
        let found = violations(&workspace);
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("no dependency rule"), "{found:?}");
    }

    #[test]
    fn apps_may_depend_on_anything() {
        let workspace = [
            krate("holdor-adapters-postgres", &[]),
            krate(
                "holdor-server",
                &["holdor-adapters-postgres", "axum", "tokio"],
            ),
        ];
        assert_eq!(violations(&workspace), Vec::<String>::new());
    }

    #[test]
    fn every_rule_refers_to_known_crates() {
        for rule in RULES {
            if let Allowed::Only(allowed) = rule.workspace {
                for dep in allowed {
                    assert!(
                        RULES.iter().any(|r| r.name == *dep),
                        "`{}` allows unknown crate `{dep}`",
                        rule.name
                    );
                    assert_ne!(*dep, rule.name, "`{}` lists itself", rule.name);
                }
            }
        }
    }
}
