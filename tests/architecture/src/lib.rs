//! Dependency rules of the Hodor workspace.
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
    context("hodor-kernel", &[]),
    // Layer 1: base contexts.
    context("hodor-tenant", &["hodor-kernel"]),
    context("hodor-identity", &["hodor-kernel"]),
    context("hodor-credential", &["hodor-kernel"]),
    context("hodor-session", &["hodor-kernel"]),
    context("hodor-keys", &["hodor-kernel"]),
    context("hodor-audit", &["hodor-kernel"]),
    context("hodor-notification", &["hodor-kernel"]),
    context("hodor-authorization", &["hodor-kernel"]),
    // Layer 2: orchestrating contexts.
    context(
        "hodor-authentication",
        &[
            "hodor-kernel",
            "hodor-identity",
            "hodor-credential",
            "hodor-session",
            "hodor-tenant",
            "hodor-notification",
        ],
    ),
    context(
        "hodor-oauth",
        &[
            "hodor-kernel",
            "hodor-identity",
            "hodor-session",
            "hodor-keys",
            "hodor-tenant",
        ],
    ),
    context("hodor-saml", &["hodor-kernel"]),
    context("hodor-provisioning", &["hodor-kernel", "hodor-identity"]),
    // Layer 3: context extensions.
    context(
        "hodor-federation",
        &[
            "hodor-kernel",
            "hodor-authentication",
            "hodor-identity",
            "hodor-saml",
        ],
    ),
    context(
        "hodor-authorization-native",
        &["hodor-kernel", "hodor-authorization"],
    ),
    context(
        "hodor-authorization-opa",
        &["hodor-kernel", "hodor-authorization"],
    ),
    context(
        "hodor-plugin-runtime",
        &["hodor-kernel", "hodor-authentication", "hodor-oauth"],
    ),
    // Layer 4: adapters. An adapter never depends on another adapter.
    adapter(
        "hodor-adapters-postgres",
        &[
            "hodor-kernel",
            "hodor-tenant",
            "hodor-identity",
            "hodor-credential",
            "hodor-session",
            "hodor-keys",
            "hodor-authentication",
            "hodor-federation",
            "hodor-oauth",
            "hodor-authorization",
            "hodor-authorization-opa",
            "hodor-audit",
            "hodor-notification",
        ],
    ),
    adapter(
        "hodor-adapters-redis",
        &[
            "hodor-kernel",
            "hodor-session",
            "hodor-authentication",
            "hodor-oauth",
            "hodor-authorization",
        ],
    ),
    adapter(
        "hodor-adapters-crypto",
        &[
            "hodor-kernel",
            "hodor-credential",
            "hodor-keys",
            "hodor-oauth",
            "hodor-authorization-opa",
        ],
    ),
    adapter("hodor-adapters-kms", &["hodor-kernel", "hodor-keys"]),
    adapter("hodor-adapters-http", &["hodor-kernel"]),
    adapter(
        "hodor-adapters-policy-check",
        &["hodor-kernel", "hodor-authorization-opa"],
    ),
    adapter("hodor-adapters-ldap", &["hodor-kernel", "hodor-federation"]),
    adapter(
        "hodor-adapters-smtp",
        &["hodor-kernel", "hodor-notification"],
    ),
    adapter("hodor-observability", &["hodor-kernel"]),
    adapter(
        "hodor-protocol-http",
        &[
            "hodor-kernel",
            "hodor-tenant",
            "hodor-identity",
            "hodor-credential",
            "hodor-session",
            "hodor-authentication",
            "hodor-federation",
            "hodor-oauth",
            "hodor-authorization",
            "hodor-authorization-opa",
            "hodor-audit",
            "hodor-keys",
        ],
    ),
    // Layer 5: composition roots.
    app("hodor-server"),
    app("hodor-worker"),
    app("hodor-cli"),
    // Test support.
    adapter("hodor-architecture-tests", &[]),
];

/// Libraries that domain and application crates must not depend on.
const INFRASTRUCTURE: &[&str] = &[
    "axum", "hyper", "redis", "reqwest", "sqlx", "tokio", "tower",
];

/// XML libraries. Only `hodor-saml` may depend on one (Decision 0019): one
/// crate, one parser, one place where XML is read.
const XML: &[&str] = &[
    "xml-sec",
    "roxmltree",
    "quick-xml",
    "xml-rs",
    "xmltree",
    "sxd-document",
    "libxml",
    "xmlsec",
    "samael",
];

/// The one crate allowed to depend on an XML library.
const XML_CRATE: &str = "hodor-saml";

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
            if XML.contains(&dep.as_str()) && krate.name != XML_CRATE {
                found.push(format!(
                    "`{}` must not depend on the XML library `{dep}`; only `{XML_CRATE}` reads XML",
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
            krate("hodor-kernel", &["uuid"]),
            krate("hodor-identity", &["hodor-kernel", "serde"]),
            krate("hodor-authentication", &["hodor-kernel", "hodor-identity"]),
        ];
        assert_eq!(violations(&workspace), Vec::<String>::new());
    }

    #[test]
    fn a_context_cannot_depend_on_infrastructure() {
        let workspace = [krate("hodor-identity", &["hodor-kernel", "sqlx"])];
        let found = violations(&workspace);
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("`sqlx`"), "{found:?}");
    }

    #[test]
    fn an_adapter_may_depend_on_infrastructure() {
        let workspace = [krate("hodor-adapters-postgres", &["hodor-kernel", "sqlx"])];
        assert_eq!(violations(&workspace), Vec::<String>::new());
    }

    #[test]
    fn oauth_and_authentication_stay_independent() {
        let workspace = [
            krate("hodor-authentication", &["hodor-oauth"]),
            krate("hodor-oauth", &["hodor-authentication"]),
        ];
        assert_eq!(violations(&workspace).len(), 2);
    }

    #[test]
    fn no_context_depends_on_audit() {
        let workspace = [
            krate("hodor-audit", &["hodor-kernel"]),
            krate("hodor-identity", &["hodor-audit"]),
        ];
        assert_eq!(violations(&workspace).len(), 1);
    }

    #[test]
    fn an_adapter_cannot_depend_on_another_adapter() {
        let workspace = [
            krate("hodor-adapters-postgres", &[]),
            krate("hodor-protocol-http", &["hodor-adapters-postgres"]),
        ];
        assert_eq!(violations(&workspace).len(), 1);
    }

    #[test]
    fn only_the_saml_crate_reads_xml() {
        let workspace = [
            krate("hodor-saml", &["xml-sec"]),
            krate("hodor-adapters-http", &["hodor-kernel", "quick-xml"]),
        ];
        let found = violations(&workspace);
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("`quick-xml`"), "{found:?}");
    }

    #[test]
    fn an_unknown_crate_is_rejected() {
        let workspace = [krate("hodor-surprise", &[])];
        let found = violations(&workspace);
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("no dependency rule"), "{found:?}");
    }

    #[test]
    fn apps_may_depend_on_anything() {
        let workspace = [
            krate("hodor-adapters-postgres", &[]),
            krate(
                "hodor-server",
                &["hodor-adapters-postgres", "axum", "tokio"],
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
