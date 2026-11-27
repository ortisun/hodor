//! `hodor-cli mesh linkerd-policy`, run as the real binary against a real
//! database with roles, and what it writes checked against the schemas of
//! Linkerd's custom resource definitions.
//!
//! `linkerd_policy_crds.json` holds the `openAPIV3Schema` of the
//! `v1alpha1` version of `MeshTLSAuthentication` and `AuthorizationPolicy`,
//! as Linkerd's chart `linkerd-crds` defines them at the tag
//! `edge-26.11.2`, converted from YAML to JSON and otherwise unchanged.

use hodor_adapters_crypto::{OsRandom, Sha256Digest};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{Database, PgApplicationStore, PgClientStore, PgResourceServerStore};
use hodor_kernel::{Caller, DomainError, Secret, SystemClock, TenantContext, TenantId, UserId};
use hodor_oauth::api::{
    ApplicationId, ApplicationPorts, ApplicationService, AuthenticationMethod, ClientSettings,
    ClientType, CreateClient, GrantType, LinkerdIdentity,
};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

const SHOP: &str = "https://api.shop.example.com";
const OTHER: &str = "https://api.other.example.com";
const NOBODY: &str = "nobody.hodor.serviceaccount.identity.linkerd.invalid";

fn run(database: &TestDatabase, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hodor-cli"))
        .args(arguments)
        .env("HODOR_DATABASE_URL", database.app_url())
        .output()
        .expect("the command-line tool should run")
}

fn said(output: &Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn refused(output: &Output, code: &str) {
    assert!(!output.status.success(), "refused");
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains(code), "{error}");
}

/// The word at `position` of what a command said.
fn word(output: &Output, position: usize) -> String {
    said(output)
        .split_whitespace()
        .nth(position)
        .expect("a word")
        .to_owned()
}

fn identity(service_account: &str) -> String {
    format!("{service_account}.shop.serviceaccount.identity.linkerd.cluster.local")
}

/// A tenant with its first administrator, whose identifier is returned:
/// service accounts need an owner.
async fn tenant(database: &TestDatabase, slug: &str) -> String {
    said(&run(
        database,
        &["tenant", "create", "--slug", slug, "--name", slug],
    ));
    let email = format!("owner@{slug}.example.com");
    said(&run(
        database,
        &["admin", "bootstrap", "--tenant", slug, "--email", &email],
    ));
    let (owner,): (sqlx::types::Uuid,) =
        sqlx::query_as("SELECT user_id FROM identity.user_identifier WHERE value_normalized = $1")
            .bind(&email)
            .fetch_one(database.owner())
            .await
            .expect("the owner");
    owner.to_string()
}

/// An application of `slug` with a resource server of `audience`, if one
/// is given.
fn application(database: &TestDatabase, slug: &str, name: &str, audience: Option<&str>) -> String {
    let id = word(
        &run(
            database,
            &["application", "add", "--tenant", slug, "--name", name],
        ),
        1,
    );
    if let Some(audience) = audience {
        said(&run(
            database,
            &[
                "resource-server",
                "add",
                "--tenant",
                slug,
                "--application",
                &id,
                "--audience",
                audience,
                "--name",
                name,
            ],
        ));
    }
    id
}

/// A role of `namespace` holding `permission`, including `includes`.
fn role(
    database: &TestDatabase,
    slug: &str,
    namespace: &str,
    name: &str,
    permission: &str,
    includes: &[&str],
) {
    said(&run(
        database,
        &[
            "authorization",
            "permission",
            "declare",
            "--tenant",
            slug,
            "--namespace",
            namespace,
            "--name",
            permission,
            "--description",
            "",
        ],
    ));
    let mut arguments = vec![
        "authorization",
        "role",
        "define",
        "--tenant",
        slug,
        "--namespace",
        namespace,
        "--name",
        name,
        "--permission",
        permission,
    ];
    for included in includes {
        arguments.extend(["--include", included]);
    }
    said(&run(database, &arguments));
}

fn service_account(database: &TestDatabase, slug: &str, name: &str, owner: &str) -> String {
    word(
        &run(
            database,
            &[
                "service-account",
                "create",
                "--tenant",
                slug,
                "--name",
                name,
                "--owner",
                owner,
            ],
        ),
        1,
    )
}

/// Gives `role` to `principal`, `--user <id>` or `--group <id>`, with
/// `more` arguments, or takes it away.
fn assignment(
    database: &TestDatabase,
    giving: bool,
    slug: &str,
    principal: [&str; 2],
    role: &str,
    more: &[&str],
) {
    let mut arguments = vec![
        "authorization",
        if giving { "assign" } else { "revoke" },
        "--tenant",
        slug,
        principal[0],
        principal[1],
        "--role",
        role,
    ];
    arguments.extend(more);
    said(&run(database, &arguments));
}

/// A client of `application` acting as `principal`, bound to its Linkerd
/// identity.
async fn bound_client(
    database: &TestDatabase,
    slug: &str,
    application: &str,
    principal: &str,
    linkerd_identity: &str,
) -> String {
    try_bound_client(database, slug, application, principal, linkerd_identity)
        .await
        .expect("the client")
}

/// A client of `application` acting as `principal`, bound to its Linkerd
/// identity, or why the OAuth context refused it. The command-line tool
/// does not bind identities yet, so the client is made through the OAuth
/// context.
async fn try_bound_client(
    database: &TestDatabase,
    slug: &str,
    application: &str,
    principal: &str,
    linkerd_identity: &str,
) -> Result<String, DomainError> {
    let (tenant_id,): (sqlx::types::Uuid,) =
        sqlx::query_as("SELECT tenant_id FROM platform.tenant_directory WHERE slug = $1")
            .bind(slug)
            .fetch_one(database.owner())
            .await
            .expect("the tenant");
    let tenant = TenantContext::assume(tenant_id.to_string().parse::<TenantId>().expect("id"));
    let connection = Database::connect(&Secret::from(database.app_url().to_owned()), 1)
        .await
        .expect("connected");
    let service = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(connection.clone()),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        digest: Arc::new(Sha256Digest),
        random: Arc::new(OsRandom),
        clock: Arc::new(SystemClock),
    });
    let mut settings = ClientSettings::new(
        "Mesh",
        ClientType::Confidential,
        vec![GrantType::ClientCredentials],
        Vec::new(),
    );
    settings.authentication_method = AuthenticationMethod::LinkerdIdentity;
    settings.principal = Some(principal.parse::<UserId>().expect("principal"));
    settings.linkerd_identity = Some(LinkerdIdentity::parse(linkerd_identity).expect("identity"));
    let client = service
        .create_client(
            &tenant,
            CreateClient {
                application_id: application.parse::<ApplicationId>().expect("application"),
                client_type: ClientType::Confidential,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await;
    // A refused write drops its transaction, whose rollback, and the
    // release of its advisory lock on the identity, waits for the runtime;
    // the commands run next block it. Closing the pool ends the session.
    connection.pool().close().await;
    Ok(client?.0.snapshot().id.to_string())
}

/// The policy of `application` written to `output`.
fn policy(
    database: &TestDatabase,
    slug: &str,
    application: &str,
    output: &Path,
    more: &[&str],
) -> Output {
    let output = output.to_str().expect("a path");
    let mut arguments = vec![
        "mesh",
        "linkerd-policy",
        "--tenant",
        slug,
        "--application",
        application,
        "--namespace",
        "shop",
        "--server",
        "shop-http",
        "--output",
        output,
    ];
    arguments.extend(more);
    run(database, &arguments)
}

/// The documents of a file the command wrote, read as `kubectl` splits a
/// YAML stream: comments left out, documents separated by `---`. Each
/// document is JSON, which is YAML.
fn documents(path: &Path) -> Vec<Value> {
    let text = std::fs::read_to_string(path).expect("written");
    text.split("\n---\n")
        .map(|part| {
            part.lines()
                .filter(|line| !line.starts_with('#'))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .filter(|part| !part.trim().is_empty())
        .map(|part| serde_json::from_str(&part).expect("each document is JSON"))
        .collect()
}

fn identities_in(path: &Path) -> Vec<String> {
    let documents = documents(path);
    documents[0]["spec"]["identities"]
        .as_array()
        .expect("identities")
        .iter()
        .map(|identity| identity.as_str().expect("a text").to_owned())
        .collect()
}

/// The errors of `value` against an OpenAPI schema of a custom resource
/// definition, for the keywords Linkerd's schemas use. A keyword this
/// check does not know fails the test, so that a newer schema is not
/// checked only in part. As the API server does, a field the schema does
/// not declare is an error.
fn schema_errors(value: &Value, schema: &Value, at: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let schema = schema.as_object().expect("a schema is an object");
    for keyword in schema.keys() {
        assert!(
            [
                "type",
                "description",
                "required",
                "properties",
                "items",
                "minItems",
                "maxLength",
                "minLength",
                "pattern",
                "oneOf",
            ]
            .contains(&keyword.as_str()),
            "{at}: the check does not know `{keyword}`"
        );
    }
    let fits = match schema.get("type").and_then(Value::as_str) {
        Some("object") => value.is_object(),
        Some("array") => value.is_array(),
        Some("string") => value.is_string(),
        Some(other) => panic!("{at}: the check does not know the type {other}"),
        None => true,
    };
    if !fits {
        errors.push(format!("{at}: not of the type {:?}", schema["type"]));
        return errors;
    }
    if let Some(object) = value.as_object() {
        for required in schema
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let required = required.as_str().expect("a field");
            if !object.contains_key(required) {
                errors.push(format!("{at}: `{required}` is missing"));
            }
        }
        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            for (field, inner) in object {
                match properties.get(field) {
                    Some(declared) => {
                        errors.extend(schema_errors(inner, declared, &format!("{at}.{field}")));
                    }
                    None => errors.push(format!("{at}: `{field}` is not declared")),
                }
            }
        }
    }
    if let Some(items) = value.as_array() {
        if let Some(least) = schema.get("minItems").and_then(Value::as_u64)
            && (items.len() as u64) < least
        {
            errors.push(format!("{at}: fewer than {least} items"));
        }
        if let Some(each) = schema.get("items") {
            for (position, item) in items.iter().enumerate() {
                errors.extend(schema_errors(item, each, &format!("{at}[{position}]")));
            }
        }
    }
    if let Some(text) = value.as_str() {
        let length = text.chars().count() as u64;
        if let Some(most) = schema.get("maxLength").and_then(Value::as_u64)
            && length > most
        {
            errors.push(format!("{at}: longer than {most}"));
        }
        if let Some(least) = schema.get("minLength").and_then(Value::as_u64)
            && length < least
        {
            errors.push(format!("{at}: shorter than {least}"));
        }
        if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
            let pattern = regex::Regex::new(pattern).expect("a pattern");
            if !pattern.is_match(text) {
                errors.push(format!("{at}: does not match {pattern}"));
            }
        }
    }
    if let Some(choices) = schema.get("oneOf").and_then(Value::as_array) {
        let matching = choices
            .iter()
            .filter(|choice| schema_errors(value, choice, at).is_empty())
            .count();
        if matching != 1 {
            errors.push(format!("{at}: matches {matching} of oneOf, not one"));
        }
    }
    errors
}

/// Checks each document of `path` as the API server would check it against
/// Linkerd's definitions: its group, version and kind, its metadata, and
/// the rest against the definition's schema.
fn check_against_linkerd(path: &Path) {
    let definitions: Value =
        serde_json::from_str(include_str!("linkerd_policy_crds.json")).expect("the definitions");
    let label = regex::Regex::new("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$").expect("a pattern");
    let documents = documents(path);
    assert_eq!(documents.len(), 2);
    for (document, kind) in documents
        .iter()
        .zip(["MeshTLSAuthentication", "AuthorizationPolicy"])
    {
        let definition = &definitions[kind];
        assert_eq!(document["kind"], kind);
        assert_eq!(
            document["apiVersion"],
            format!(
                "{}/{}",
                definition["group"].as_str().expect("group"),
                definition["version"].as_str().expect("version")
            )
        );
        let metadata = &document["metadata"];
        let name = metadata["name"].as_str().expect("a name");
        assert!(
            name.len() <= 253 && name.split('.').all(|part| label.is_match(part)),
            "{name}"
        );
        assert!(label.is_match(metadata["namespace"].as_str().expect("a namespace")));
        let mut rest = document.clone();
        let fields = rest.as_object_mut().expect("an object");
        for implicit in ["apiVersion", "kind", "metadata"] {
            fields.remove(implicit);
        }
        let errors = schema_errors(&rest, &definition["schema"], kind);
        assert!(errors.is_empty(), "{errors:#?}");
    }
}

fn scratch(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("hodor-mesh-commands-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("a directory");
    directory
}

#[tokio::test]
async fn the_linkerd_policy_lets_in_only_the_service_accounts_holding_a_role() {
    let database = TestDatabase::start().await;
    let owner = tenant(&database, "acme").await;
    let shop = application(&database, "acme", "Shop", Some(SHOP));
    let other = application(&database, "acme", "Other", Some(OTHER));
    role(&database, "acme", SHOP, "viewer", "order:read", &[]);
    role(&database, "acme", OTHER, "reader", "report:read", &[]);
    let viewer = format!("{SHOP}#viewer");
    let reader = format!("{OTHER}#reader");
    let support = format!("{OTHER}#support");
    said(&run(
        &database,
        &[
            "authorization",
            "role",
            "define",
            "--tenant",
            "acme",
            "--namespace",
            OTHER,
            "--name",
            "support",
            "--include",
            &viewer,
        ],
    ));

    // Let in: a role of the resource server for the tenant, one for this
    // application, one through a group inside a group, and a role of
    // another resource server that includes one of this one.
    let mut accounts = std::collections::BTreeMap::new();
    for name in [
        "direct",
        "scoped",
        "grouped",
        "composite",
        "roleless",
        "elsewhere",
        "wrongapp",
        "disabled",
        "unbound",
    ] {
        let id = service_account(&database, "acme", name, &owner);
        let client = bound_client(&database, "acme", &shop, &id, &identity(name)).await;
        accounts.insert(name, (id, client));
    }
    let user = |name: &str| ["--user", accounts[name].0.as_str()].map(str::to_owned);
    let give = |name: &str, role: &str, more: &[&str]| {
        let principal = user(name);
        assignment(
            &database,
            true,
            "acme",
            [&principal[0], &principal[1]],
            role,
            more,
        );
    };
    give("direct", &viewer, &[]);
    give("scoped", &viewer, &["--application", &shop]);
    give("composite", &support, &[]);
    let outer = word(
        &run(
            &database,
            &["group", "create", "--tenant", "acme", "--name", "Outer"],
        ),
        1,
    );
    let inner = word(
        &run(
            &database,
            &["group", "create", "--tenant", "acme", "--name", "Inner"],
        ),
        1,
    );
    said(&run(
        &database,
        &[
            "group",
            "add",
            "--tenant",
            "acme",
            "--group",
            &outer,
            "--member-group",
            &inner,
        ],
    ));
    said(&run(
        &database,
        &[
            "group",
            "add",
            "--tenant",
            "acme",
            "--group",
            &inner,
            "--user",
            &accounts["grouped"].0,
        ],
    ));
    assignment(&database, true, "acme", ["--group", &outer], &viewer, &[]);

    // Never let in: no role, a role of another resource server, a role for
    // another application, a disabled service account, a disabled client.
    give("elsewhere", &reader, &[]);
    give("wrongapp", &viewer, &["--application", &other]);
    give("disabled", &viewer, &[]);
    said(&run(
        &database,
        &[
            "service-account",
            "disable",
            "--tenant",
            "acme",
            "--id",
            &accounts["disabled"].0,
        ],
    ));
    give("unbound", &viewer, &[]);
    said(&run(
        &database,
        &[
            "client",
            "disable",
            "--tenant",
            "acme",
            "--id",
            &accounts["unbound"].1,
        ],
    ));

    // Another tenant has a resource server of the same audience, a service
    // account holding a role there, and binds the same Linkerd identity as
    // acme's service account without a role.
    let globex_owner = tenant(&database, "globex").await;
    let globex_shop = application(&database, "globex", "Shop", Some(SHOP));
    role(&database, "globex", SHOP, "viewer", "order:read", &[]);
    for name in ["foreign", "roleless"] {
        let id = service_account(&database, "globex", name, &globex_owner);
        bound_client(&database, "globex", &globex_shop, &id, &identity(name)).await;
        assignment(&database, true, "globex", ["--user", &id], &viewer, &[]);
    }

    let directory = scratch("roles");
    let path = directory.join("shop.yaml");
    let first = said(&policy(&database, "acme", &shop, &path, &[]));
    let mut expected: Vec<String> = ["composite", "direct", "grouped", "scoped"]
        .map(identity)
        .to_vec();
    expected.sort();
    let mut lines: Vec<String> = expected
        .iter()
        .map(|identity| format!("added {identity}"))
        .collect();
    lines.push(format!("wrote {}", path.display()));
    assert_eq!(first, lines.join("\n"));
    assert_eq!(identities_in(&path), expected);
    let text = std::fs::read_to_string(&path).expect("written");
    for absent in [
        "roleless",
        "elsewhere",
        "wrongapp",
        "disabled",
        "unbound",
        "foreign",
    ] {
        assert!(!text.contains(&identity(absent)), "{absent} is let in");
    }
    assert!(text.starts_with(&format!(
        "# Written by hodor-cli mesh linkerd-policy for the application {shop} of the tenant acme.\n"
    )));
    let documents = documents(&path);
    assert_eq!(documents[0]["metadata"]["name"], format!("hodor-{shop}"));
    assert_eq!(documents[1]["spec"]["targetRef"]["name"], "shop-http");
    check_against_linkerd(&path);

    // The other tenant's policy holds its own service accounts only.
    let globex_path = directory.join("globex.yaml");
    said(&policy(
        &database,
        "globex",
        &globex_shop,
        &globex_path,
        &[],
    ));
    assert_eq!(
        identities_in(&globex_path),
        [identity("foreign"), identity("roleless")]
    );

    // Run again with nothing changed: nothing is written.
    let modified = std::fs::metadata(&path).expect("written").modified().ok();
    assert_eq!(
        said(&policy(&database, "acme", &shop, &path, &[])),
        format!("unchanged {}", path.display())
    );
    assert_eq!(
        std::fs::metadata(&path).expect("kept").modified().ok(),
        modified
    );

    // A role taken away disappears from the next run, which says so.
    let principal = user("direct");
    assignment(
        &database,
        false,
        "acme",
        [&principal[0], &principal[1]],
        &viewer,
        &[],
    );
    assert_eq!(
        said(&policy(&database, "acme", &shop, &path, &[])),
        format!("removed {}\nwrote {}", identity("direct"), path.display())
    );
    assert!(!identities_in(&path).contains(&identity("direct")));

    // When the last one is taken away, nobody is let in.
    assignment(&database, false, "acme", ["--group", &outer], &viewer, &[]);
    let principal = user("scoped");
    assignment(
        &database,
        false,
        "acme",
        [&principal[0], &principal[1]],
        &viewer,
        &["--application", &shop],
    );
    let principal = user("composite");
    assignment(
        &database,
        false,
        "acme",
        [&principal[0], &principal[1]],
        &support,
        &[],
    );
    let mut lines: Vec<String> = ["composite", "grouped", "scoped"]
        .map(|name| format!("removed {}", identity(name)))
        .to_vec();
    lines.push(format!("no service account holds a role on {SHOP}"));
    lines.push(format!("wrote {}", path.display()));
    assert_eq!(
        said(&policy(&database, "acme", &shop, &path, &[])),
        lines.join("\n")
    );
    assert_eq!(identities_in(&path), [NOBODY]);
    check_against_linkerd(&path);

    // Moving the resources is said too.
    let moved = said(&policy(
        &database,
        "acme",
        &shop,
        &path,
        &["--name", "shop-callers"],
    ));
    assert_eq!(
        moved,
        format!(
            "changed name hodor-{shop} shop-callers\n\
             no service account holds a role on {SHOP}\nwrote {}",
            path.display()
        )
    );
    std::fs::remove_dir_all(&directory).expect("removed");
}

/// Several clients of one service account share its Linkerd identity, one
/// in each application, as `hodor-ext-authz`'s do: the identity is written
/// once, and stays while any of them is enabled. A client of another
/// service account cannot take that identity, so one service account's
/// role never lets in another's workload.
#[tokio::test]
async fn an_identity_shared_by_the_clients_of_one_service_account_is_written_once() {
    let database = TestDatabase::start().await;
    let owner = tenant(&database, "acme").await;
    let shop = application(&database, "acme", "Shop", Some(SHOP));
    let other = application(&database, "acme", "Other", Some(OTHER));
    let bare = application(&database, "acme", "Bare", None);
    role(&database, "acme", SHOP, "viewer", "order:read", &[]);
    let viewer = format!("{SHOP}#viewer");

    // The gateway holds a role on the shop and has a client in each
    // application, all bound to its one identity.
    let gateway = service_account(&database, "acme", "gateway", &owner);
    let mut clients = Vec::new();
    for application in [&shop, &other, &bare] {
        clients.push(
            bound_client(
                &database,
                "acme",
                application,
                &gateway,
                &identity("gateway"),
            )
            .await,
        );
    }
    assignment(&database, true, "acme", ["--user", &gateway], &viewer, &[]);
    // Another service account holds no role, with an identity of its own.
    let roleless = service_account(&database, "acme", "roleless", &owner);
    bound_client(&database, "acme", &shop, &roleless, &identity("roleless")).await;

    // Neither can bind a client to the other's identity: the gateway's role
    // would let the other workload in, or the other's client would act as
    // the gateway's workload.
    for (principal, taken) in [(&gateway, "roleless"), (&roleless, "gateway")] {
        let error = try_bound_client(&database, "acme", &other, principal, &identity(taken))
            .await
            .expect_err("an identity of another service account");
        assert_eq!(error.code(), "oauth.client_linkerd_identity_taken");
    }

    let directory = scratch("shared");
    let path = directory.join("shop.yaml");
    assert_eq!(
        said(&policy(&database, "acme", &shop, &path, &[])),
        format!("added {}\nwrote {}", identity("gateway"), path.display())
    );
    assert_eq!(identities_in(&path), [identity("gateway")]);
    let text = std::fs::read_to_string(&path).expect("written");
    assert_eq!(text.matches(&identity("gateway")).count(), 1, "listed once");
    assert!(!text.contains(&identity("roleless")), "no role, not let in");
    check_against_linkerd(&path);

    // Two of its three clients disabled, the gateway still gets tokens
    // through the third, and is still let in.
    for client in &clients[..2] {
        said(&run(
            &database,
            &["client", "disable", "--tenant", "acme", "--id", client],
        ));
    }
    assert_eq!(
        said(&policy(&database, "acme", &shop, &path, &[])),
        format!("unchanged {}", path.display())
    );
    // The last one disabled, it is not.
    said(&run(
        &database,
        &["client", "disable", "--tenant", "acme", "--id", &clients[2]],
    ));
    assert_eq!(
        said(&policy(&database, "acme", &shop, &path, &[])),
        format!(
            "removed {}\nno service account holds a role on {SHOP}\nwrote {}",
            identity("gateway"),
            path.display()
        )
    );
    assert_eq!(identities_in(&path), [NOBODY]);
    std::fs::remove_dir_all(&directory).expect("removed");
}

#[tokio::test]
async fn the_linkerd_policy_refuses_and_writes_nothing() {
    let database = TestDatabase::start().await;
    tenant(&database, "acme").await;
    let shop = application(&database, "acme", "Shop", Some(SHOP));
    let other = application(&database, "acme", "Other", Some(OTHER));
    let bare = application(&database, "acme", "Bare", None);
    let directory = scratch("refusals");
    let path = directory.join("shop.yaml");
    said(&policy(&database, "acme", &shop, &path, &[]));
    let written = std::fs::read_to_string(&path).expect("written");

    // The file of another application is left as it is.
    refused(
        &policy(&database, "acme", &other, &path, &[]),
        "authorization.linkerd_policy_of_another_application",
    );
    // So is a file this command did not write.
    let foreign = directory.join("foreign.yaml");
    std::fs::write(&foreign, "apiVersion: v1\nkind: ConfigMap\n").expect("written");
    refused(
        &policy(&database, "acme", &shop, &foreign, &[]),
        "authorization.linkerd_policy_unreadable",
    );
    assert_eq!(
        std::fs::read_to_string(&foreign).expect("kept"),
        "apiVersion: v1\nkind: ConfigMap\n"
    );
    // Names Kubernetes would refuse.
    let fresh = directory.join("fresh.yaml");
    refused(
        &policy(&database, "acme", &shop, &fresh, &["--name", "Shop"]),
        "authorization.linkerd_name_invalid",
    );
    for (namespace, server) in [("Shop", "shop-http"), ("shop", "shop_http")] {
        refused(
            &run(
                &database,
                &[
                    "mesh",
                    "linkerd-policy",
                    "--tenant",
                    "acme",
                    "--application",
                    &shop,
                    "--namespace",
                    namespace,
                    "--server",
                    server,
                    "--output",
                    fresh.to_str().expect("a path"),
                ],
            ),
            "authorization.linkerd_name_invalid",
        );
    }
    // An application without a resource server, one that does not exist,
    // and a tenant that does not exist.
    refused(
        &policy(&database, "acme", &bare, &fresh, &[]),
        "oauth.resource_server_not_found",
    );
    refused(
        &policy(&database, "acme", "not-an-identifier", &fresh, &[]),
        "oauth.application_not_found",
    );
    refused(
        &policy(&database, "globex", &shop, &fresh, &[]),
        "tenant.not_found",
    );
    assert!(!fresh.exists(), "nothing written");
    assert_eq!(std::fs::read_to_string(&path).expect("kept"), written);
    std::fs::remove_dir_all(&directory).expect("removed");
}

#[test]
fn the_schema_check_finds_what_linkerd_refuses() {
    let definitions: Value =
        serde_json::from_str(include_str!("linkerd_policy_crds.json")).expect("the definitions");
    let authentication = &definitions["MeshTLSAuthentication"]["schema"];
    let authorization = &definitions["AuthorizationPolicy"]["schema"];
    let errors = |value: Value, schema: &Value| schema_errors(&value, schema, "document");
    assert!(
        errors(
            serde_json::json!({"spec": {"identities": ["a.b"]}}),
            authentication
        )
        .is_empty()
    );
    for refused in [
        serde_json::json!({"spec": {"identities": []}}),
        serde_json::json!({"spec": {}}),
        serde_json::json!({"spec": {"identities": ["a.b"], "identityRefs": [{"kind": "ServiceAccount"}]}}),
        serde_json::json!({"spec": {"identities": ["a.b"], "extra": true}}),
        serde_json::json!({"spec": {"identities": [1]}}),
    ] {
        assert!(
            !errors(refused.clone(), authentication).is_empty(),
            "{refused}"
        );
    }
    let good = serde_json::json!({"spec": {
        "requiredAuthenticationRefs": [{"group": "policy.linkerd.io", "kind": "MeshTLSAuthentication", "name": "a"}],
        "targetRef": {"group": "policy.linkerd.io", "kind": "Server", "name": "s"}
    }});
    assert!(errors(good, authorization).is_empty());
    for refused in [
        serde_json::json!({"spec": {"targetRef": {"kind": "Server", "name": "s"}}}),
        serde_json::json!({"spec": {"requiredAuthenticationRefs": [], "targetRef": {"kind": "Server"}}}),
        serde_json::json!({"spec": {"requiredAuthenticationRefs": [], "targetRef": {"kind": "-Server", "name": "s"}}}),
        serde_json::json!({"spec": {"requiredAuthenticationRefs": [], "targetRef": {"group": "Policy", "kind": "Server", "name": "s"}}}),
    ] {
        assert!(
            !errors(refused.clone(), authorization).is_empty(),
            "{refused}"
        );
    }
}
