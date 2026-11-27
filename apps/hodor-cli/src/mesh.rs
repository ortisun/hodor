//! `hodor-cli mesh linkerd-policy`: the Linkerd policies of an application,
//! written from the roles held on its resource server.
//!
//! Specified in `docs/architecture/contexts/authorization.md`, "Linkerd
//! policies from roles", with the choices of
//! `docs/decisions/0059-linkerd-policies-from-roles.md`. The command reads
//! the database and writes a file; it talks to no cluster.

use crate::{applications, memberships, workloads};
use clap::Subcommand;
use hodor_adapters_postgres::{Database, PgNativeRoleStore};
use hodor_authorization::api::{
    ApplicationReference, Namespace, OrganizationReference, RoleService, Subject, SubjectKind,
};
use hodor_identity::api::{UserKind, UserStatus};
use hodor_kernel::{DomainError, ErrorKind, SystemClock, TenantContext, UserId};
use hodor_oauth::api::{ApplicationId, ApplicationService, Status};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Subcommand)]
pub(crate) enum MeshCommand {
    /// Write the Linkerd policies that let in only the service accounts
    /// holding a role on an application's resource server, and say what
    /// changed since the file was last written. Nothing is applied.
    LinkerdPolicy {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// Identifier of the application.
        #[arg(long)]
        application: String,
        /// The Kubernetes namespace of the application's workload.
        #[arg(long)]
        namespace: String,
        /// The name of the Linkerd `Server` the policy is for.
        #[arg(long)]
        server: String,
        /// The file to write, read first as the last run.
        #[arg(long)]
        output: PathBuf,
        /// The name of both resources; `hodor-<application identifier>`
        /// unless given.
        #[arg(long)]
        name: Option<String>,
    },
}

/// The API version of both resources.
const API_VERSION: &str = "policy.linkerd.io/v1alpha1";

/// The group of Linkerd's policy resources.
const GROUP: &str = "policy.linkerd.io";

/// The one identity written when nobody holds a role: Linkerd refuses an
/// empty list, and `invalid` is a name RFC 6761 reserves, so no workload
/// has it.
const NOBODY: &str = "nobody.hodor.serviceaccount.identity.linkerd.invalid";

/// What the command writes, and what it reads back from the last run.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Policy {
    application: String,
    tenant: String,
    namespace: String,
    name: String,
    server: String,
    /// The identities let in; never [`NOBODY`].
    identities: BTreeSet<String>,
}

fn name_invalid(what: &str) -> DomainError {
    DomainError::invalid(
        "authorization.linkerd_name_invalid",
        "a Kubernetes namespace is 1 to 63 lower-case letters, digits and `-`, starting and \
         ending with a letter or a digit; a name is such parts separated by `.`, 253 characters \
         at most",
    )
    .with_detail(what.to_owned())
}

/// Whether `value` is a Kubernetes label: what a namespace is named.
fn is_label(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=63).contains(&bytes.len())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
}

/// Whether `value` is a Kubernetes name: labels separated by `.`.
fn is_name(value: &str) -> bool {
    value.len() <= 253 && value.split('.').all(is_label)
}

fn unreadable(detail: impl Into<String>) -> DomainError {
    DomainError::invalid(
        "authorization.linkerd_policy_unreadable",
        "the file is not a policy this command wrote; it is left as it is",
    )
    .with_detail(detail)
}

fn header(policy: &Policy) -> String {
    format!(
        "# Written by hodor-cli mesh linkerd-policy for the application {} of the tenant {}.\n\
         # Apply it as it is and do not edit it: the next run reads it back to say what changed.\n",
        policy.application, policy.tenant
    )
}

fn metadata(policy: &Policy) -> Value {
    json!({
        "labels": {
            "app.kubernetes.io/managed-by": "hodor-cli",
            "app.kubernetes.io/part-of": "hodor"
        },
        "name": policy.name,
        "namespace": policy.namespace
    })
}

/// The file of `policy`: the same bytes for the same policy.
fn render(policy: &Policy) -> String {
    let identities: Vec<&str> = if policy.identities.is_empty() {
        vec![NOBODY]
    } else {
        policy.identities.iter().map(String::as_str).collect()
    };
    let authentication = json!({
        "apiVersion": API_VERSION,
        "kind": "MeshTLSAuthentication",
        "metadata": metadata(policy),
        "spec": { "identities": identities }
    });
    let authorization = json!({
        "apiVersion": API_VERSION,
        "kind": "AuthorizationPolicy",
        "metadata": metadata(policy),
        "spec": {
            "requiredAuthenticationRefs": [{
                "group": GROUP,
                "kind": "MeshTLSAuthentication",
                "name": policy.name
            }],
            "targetRef": {
                "group": GROUP,
                "kind": "Server",
                "name": policy.server
            }
        }
    });
    let mut text = header(policy);
    for document in [authentication, authorization] {
        let written = serde_json::to_string_pretty(&document).unwrap_or_default();
        let _ = write!(text, "---\n{written}\n");
    }
    text
}

fn text_at<'a>(document: &'a Value, path: &[&str]) -> Result<&'a str, DomainError> {
    let mut value = document;
    for step in path {
        value = value
            .get(step)
            .ok_or_else(|| unreadable(format!("no {}", path.join("."))))?;
    }
    value
        .as_str()
        .ok_or_else(|| unreadable(format!("{} is not a text", path.join("."))))
}

/// Reads back a file [`render`] wrote.
fn read_back(text: &str) -> Result<Policy, DomainError> {
    let first = text.lines().next().unwrap_or_default();
    let (application, tenant) = first
        .strip_prefix("# Written by hodor-cli mesh linkerd-policy for the application ")
        .and_then(|rest| rest.strip_suffix('.'))
        .and_then(|rest| rest.split_once(" of the tenant "))
        .ok_or_else(|| unreadable("it does not start with the comment the command writes"))?;
    let mut documents = Vec::new();
    let mut current = String::new();
    for line in text.lines().filter(|line| !line.starts_with('#')) {
        if line == "---" {
            documents.push(std::mem::take(&mut current));
        } else {
            current.push_str(line);
            current.push('\n');
        }
    }
    documents.push(current);
    let documents: Vec<Value> = documents
        .iter()
        .filter(|document| !document.trim().is_empty())
        .map(|document| serde_json::from_str(document).map_err(|e| unreadable(e.to_string())))
        .collect::<Result<_, _>>()?;
    let [authentication, authorization] = documents.as_slice() else {
        return Err(unreadable("it does not hold exactly two documents"));
    };
    for (document, kind) in [
        (authentication, "MeshTLSAuthentication"),
        (authorization, "AuthorizationPolicy"),
    ] {
        if text_at(document, &["apiVersion"])? != API_VERSION
            || text_at(document, &["kind"])? != kind
            || text_at(
                document,
                &["metadata", "labels", "app.kubernetes.io/managed-by"],
            )? != "hodor-cli"
        {
            return Err(unreadable(format!("no {kind} written by hodor-cli")));
        }
    }
    let identities = authentication
        .pointer("/spec/identities")
        .and_then(Value::as_array)
        .ok_or_else(|| unreadable("no spec.identities"))?
        .iter()
        .map(|identity| {
            identity
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| unreadable("an identity is not a text"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    Ok(Policy {
        application: application.to_owned(),
        tenant: tenant.to_owned(),
        namespace: text_at(authentication, &["metadata", "namespace"])?.to_owned(),
        name: text_at(authentication, &["metadata", "name"])?.to_owned(),
        server: text_at(authorization, &["spec", "targetRef", "name"])?.to_owned(),
        identities: identities
            .into_iter()
            .filter(|identity| identity != NOBODY)
            .collect(),
    })
}

/// What changed from `before`, the last run if there was one, to `after`,
/// one line each.
fn changes(before: Option<&Policy>, after: &Policy, audience: &str) -> Vec<String> {
    let empty = BTreeSet::new();
    let earlier = before.map_or(&empty, |policy| &policy.identities);
    let mut lines: Vec<String> = after
        .identities
        .difference(earlier)
        .map(|identity| format!("added {identity}"))
        .collect();
    lines.extend(
        earlier
            .difference(&after.identities)
            .map(|identity| format!("removed {identity}")),
    );
    if let Some(before) = before {
        for (what, was, is) in [
            ("namespace", &before.namespace, &after.namespace),
            ("name", &before.name, &after.name),
            ("server", &before.server, &after.server),
        ] {
            if was != is {
                lines.push(format!("changed {what} {was} {is}"));
            }
        }
    }
    if after.identities.is_empty() {
        lines.push(format!("no service account holds a role on {audience}"));
    }
    lines
}

/// The file at `path`, if there is one.
fn last_run(path: &Path) -> Result<Option<String>, DomainError> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(unreadable(error.to_string())),
    }
}

/// Writes `text` beside `path` and renames it over it, so that a failure
/// leaves the last run as it was.
fn replace(path: &Path, text: &str) -> Result<(), DomainError> {
    let unwritable = |error: std::io::Error| {
        DomainError::invalid(
            "authorization.linkerd_policy_unwritable",
            "the file could not be written",
        )
        .with_detail(error.to_string())
    };
    let file_name = path
        .file_name()
        .ok_or_else(|| unwritable(std::io::Error::other("the path names no file")))?;
    let mut beside = path.to_path_buf();
    beside.set_file_name(format!(
        ".{}.{}.hodor-cli",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    std::fs::write(&beside, text).map_err(unwritable)?;
    std::fs::rename(&beside, path).map_err(|error| {
        let _ = std::fs::remove_file(&beside);
        unwritable(error)
    })
}

/// The Linkerd identities of the clients of the tenant bound to one, by
/// the principal they act as: enabled clients of enabled applications.
async fn bound_identities(
    tenant: &TenantContext,
    applications: &ApplicationService,
) -> Result<BTreeMap<UserId, BTreeSet<String>>, DomainError> {
    let mut bound: BTreeMap<UserId, BTreeSet<String>> = BTreeMap::new();
    for application in applications.applications(tenant).await? {
        let application = application.snapshot();
        if application.status != Status::Enabled {
            continue;
        }
        for client in applications.clients(tenant, application.id).await? {
            let client = client.snapshot();
            if client.status != Status::Enabled {
                continue;
            }
            if let (Some(principal), Some(identity)) =
                (client.settings.principal, &client.settings.linkerd_identity)
            {
                bound
                    .entry(principal)
                    .or_default()
                    .insert(identity.as_str().to_owned());
            }
        }
    }
    Ok(bound)
}

/// The Linkerd identities of the active service accounts of the tenant
/// that hold a role on `namespace` for requests made for `application`.
async fn identities_let_in(
    database: &Database,
    tenant: &TenantContext,
    applications: &ApplicationService,
    application: ApplicationId,
    namespace: &Namespace,
) -> Result<BTreeSet<String>, DomainError> {
    let identity = workloads::identity(database);
    let groups = memberships::groups(database);
    let organizations = memberships::organizations(database);
    let roles = RoleService::new(
        Arc::new(database.clone()),
        Arc::new(PgNativeRoleStore),
        Arc::new(SystemClock),
    );
    let application = ApplicationReference::parse(&application.to_string())?;
    let mut let_in = BTreeSet::new();
    for (principal, identities) in bound_identities(tenant, applications).await? {
        let user = match identity.get(tenant, principal).await {
            Ok(user) => user,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if user.kind() != UserKind::ServiceAccount || user.status() != UserStatus::Active {
            continue;
        }
        let mut principals = vec![Subject::user(principal)];
        for group in groups.effective_groups(tenant, principal).await? {
            principals.push(Subject::new(SubjectKind::Group, &group.to_string())?);
        }
        let member_of = organizations
            .organizations_of(tenant, principal)
            .await?
            .iter()
            .map(|membership| OrganizationReference::parse(&membership.organization.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        let held = roles
            .assignments_on(tenant, &principals, namespace, &application, &member_of)
            .await?;
        if !held.is_empty() {
            let_in.extend(identities);
        }
    }
    Ok(let_in)
}

/// Runs a command of the mesh.
pub(crate) async fn run(database: &Database, command: MeshCommand) -> Result<String, DomainError> {
    let MeshCommand::LinkerdPolicy {
        tenant: slug,
        application,
        namespace,
        server,
        output,
        name,
    } = command;
    let application = applications::application_id(&application)?;
    let name = name.unwrap_or_else(|| format!("hodor-{application}"));
    if !is_label(&namespace) {
        return Err(name_invalid("the namespace"));
    }
    if !is_name(&name) {
        return Err(name_invalid("the name"));
    }
    if !is_name(&server) {
        return Err(name_invalid("the server"));
    }
    let previous = last_run(&output)?;
    let before = previous.as_deref().map(read_back).transpose()?;
    if let Some(before) = &before
        && before.application != application.to_string()
    {
        return Err(DomainError::invalid(
            "authorization.linkerd_policy_of_another_application",
            "the file was written for another application; it is left as it is",
        )
        .with_detail(before.application.clone()));
    }
    let (tenant, service) = applications::open(database, &slug).await?;
    service.application(&tenant, application).await?;
    let resource_server = service
        .resource_server_of(&tenant, application)
        .await?
        .ok_or_else(|| {
            DomainError::not_found(
                "oauth.resource_server_not_found",
                "the application has no resource server",
            )
        })?;
    let audience = resource_server.snapshot().audience.as_str().to_owned();
    let identities = identities_let_in(
        database,
        &tenant,
        &service,
        application,
        &Namespace::parse(&audience)?,
    )
    .await?;
    let after = Policy {
        application: application.to_string(),
        tenant: slug,
        namespace,
        name,
        server,
        identities,
    };
    let text = render(&after);
    let mut lines = changes(before.as_ref(), &after, &audience);
    if previous.as_deref() == Some(text.as_str()) {
        lines.push(format!("unchanged {}", output.display()));
    } else {
        replace(&output, &text)?;
        lines.push(format!("wrote {}", output.display()));
    }
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: &str = "web.shop.serviceaccount.identity.linkerd.cluster.local";
    const TWO: &str = "api.shop.serviceaccount.identity.linkerd.cluster.local";

    fn policy(identities: &[&str]) -> Policy {
        Policy {
            application: "0193f1c4-0000-7000-8000-00000000000a".to_owned(),
            tenant: "acme".to_owned(),
            namespace: "shop".to_owned(),
            name: "hodor-0193f1c4-0000-7000-8000-00000000000a".to_owned(),
            server: "shop-http".to_owned(),
            identities: identities
                .iter()
                .map(|&identity| identity.to_owned())
                .collect(),
        }
    }

    #[test]
    fn kubernetes_names_follow_kubernetes_rules() {
        for good in ["shop", "a", "a-1", "0", &"a".repeat(63)] {
            assert!(is_label(good), "{good}");
        }
        for bad in [
            "",
            "Shop",
            "-shop",
            "shop-",
            "sh_op",
            "sh.op",
            &"a".repeat(64),
        ] {
            assert!(!is_label(bad), "{bad}");
        }
        assert!(is_name("hodor-0193f1c4-0000-7000-8000-00000000000a"));
        assert!(is_name("shop.http"));
        for bad in ["shop..http", ".shop", "shop.", "Shop", &"a.".repeat(127)] {
            assert!(!is_name(bad), "{bad}");
        }
    }

    #[test]
    fn what_is_written_is_read_back_exactly() {
        let written = policy(&[TWO, ONE]);
        let text = render(&written);
        assert!(text.starts_with(
            "# Written by hodor-cli mesh linkerd-policy for the application \
             0193f1c4-0000-7000-8000-00000000000a of the tenant acme.\n"
        ));
        assert_eq!(render(&written), text, "the same bytes every time");
        assert_eq!(read_back(&text).expect("read back"), written);
        let position = |identity: &str| text.find(identity).expect("written");
        assert!(position(TWO) < position(ONE), "in order");
    }

    #[test]
    fn nobody_is_written_as_an_identity_no_workload_has_and_read_back_as_nobody() {
        let text = render(&policy(&[]));
        assert!(text.contains(&format!("\"{NOBODY}\"")));
        assert!(read_back(&text).expect("read back").identities.is_empty());
    }

    #[test]
    fn the_documents_are_json_after_a_comment() {
        let text = render(&policy(&[ONE]));
        let documents: Vec<&str> = text.split("---\n").skip(1).collect();
        assert_eq!(documents.len(), 2);
        let authentication: Value = serde_json::from_str(documents[0]).expect("json");
        assert_eq!(authentication["kind"], "MeshTLSAuthentication");
        assert_eq!(authentication["spec"]["identities"], json!([ONE]));
        let authorization: Value = serde_json::from_str(documents[1]).expect("json");
        assert_eq!(authorization["kind"], "AuthorizationPolicy");
        assert_eq!(authorization["spec"]["targetRef"]["kind"], "Server");
        assert_eq!(authorization["spec"]["targetRef"]["name"], "shop-http");
        assert_eq!(
            authorization["spec"]["requiredAuthenticationRefs"][0]["name"],
            authentication["metadata"]["name"]
        );
    }

    #[test]
    fn a_file_the_command_did_not_write_is_not_read() {
        let good = render(&policy(&[ONE]));
        let without_header = good.lines().skip(2).collect::<Vec<_>>().join("\n");
        let one_document = good
            .split("---\n")
            .take(2)
            .collect::<Vec<_>>()
            .join("---\n");
        let not_ours = good.replace("\"hodor-cli\"", "\"someone-else\"");
        let not_json = good.replace(
            "\"kind\": \"AuthorizationPolicy\",",
            "kind: AuthorizationPolicy",
        );
        for bad in [
            String::new(),
            "apiVersion: v1\nkind: ConfigMap\n".to_owned(),
            without_header,
            one_document,
            not_ours,
            not_json,
        ] {
            assert_eq!(
                read_back(&bad).map(|_| ()).map_err(|e| e.code().to_owned()),
                Err("authorization.linkerd_policy_unreadable".to_owned()),
                "{bad}"
            );
        }
    }

    #[test]
    fn the_changes_name_each_identity_and_each_move() {
        let audience = "https://api.shop.example.com";
        assert_eq!(
            changes(None, &policy(&[ONE, TWO]), audience),
            [format!("added {TWO}"), format!("added {ONE}")]
        );
        let before = policy(&[ONE]);
        assert!(changes(Some(&before), &policy(&[ONE]), audience).is_empty());
        assert_eq!(
            changes(Some(&before), &policy(&[TWO]), audience),
            [format!("added {TWO}"), format!("removed {ONE}")]
        );
        let mut moved = policy(&[ONE]);
        moved.namespace = "store".to_owned();
        moved.server = "store-http".to_owned();
        assert_eq!(
            changes(Some(&before), &moved, audience),
            [
                "changed namespace shop store",
                "changed server shop-http store-http"
            ]
        );
        assert_eq!(
            changes(Some(&before), &policy(&[]), audience),
            [
                format!("removed {ONE}"),
                format!("no service account holds a role on {audience}")
            ]
        );
    }

    #[test]
    fn a_file_is_replaced_whole() {
        let directory = std::env::temp_dir().join(format!("hodor-mesh-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("directory");
        let path = directory.join("policy.yaml");
        replace(&path, "first").expect("written");
        replace(&path, "second").expect("replaced");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "second");
        assert_eq!(
            std::fs::read_dir(&directory).expect("listed").count(),
            1,
            "nothing left beside it"
        );
        assert_eq!(
            replace(&directory.join("absent").join("policy.yaml"), "x")
                .map_err(|e| e.code().to_owned()),
            Err("authorization.linkerd_policy_unwritable".to_owned())
        );
        std::fs::remove_dir_all(&directory).expect("removed");
    }
}
