//! The commands for permissions, roles, assignments and bindings.
//!
//! Specified in `docs/architecture/contexts/authorization.md`, "Native
//! role-based access control" and "Bindings". The rules are the
//! authorization context's, so a value the administration interface
//! refuses is refused here with the same code. A resource server is named
//! by its audience, which is the namespace of its permissions and roles.

use crate::{caller, existing};
use clap::{Subcommand, ValueEnum};
use hodor_adapters_postgres::{
    Database, PgEngineBindingStore, PgNativeRoleStore, PgRoleAssignmentStore, PgTenantDirectory,
    PgTenantRepository,
};
use hodor_authorization::api::{
    Action, ApplicationReference, AssignmentScope, Attributes, AuthorizationEngine,
    BindingSettings, Condition, EngineAnswer, EngineCapabilities, EngineId, EngineRegistry,
    EvaluationInput, EvaluationService, Namespace, NativeEngine, OrganizationReference,
    PermissionName, RoleContents, RoleKey, RoleName, RoleService, Subject, SubjectAttributeSource,
    SubjectKind, Validity,
};
use hodor_authorization_native::CelConditionLanguage;
use hodor_kernel::{DomainError, SystemClock, TenantContext};
use hodor_tenant::api::TenantService;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

#[derive(Subcommand)]
pub(crate) enum ManageCommand {
    /// Declare, remove or list the permissions of a resource server.
    Permission {
        #[command(subcommand)]
        command: PermissionCommand,
    },
    /// Define, remove or list roles.
    Role {
        #[command(subcommand)]
        command: RoleCommand,
    },
    /// Give a role to a user or a client.
    Assign {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        #[command(flatten)]
        principal: PrincipalArgs,
        /// The role, written `namespace#name`.
        #[arg(long)]
        role: String,
        /// Only for requests made for this application.
        #[arg(long)]
        application: Option<String>,
        /// Only for requests made in this organization, by its members.
        #[arg(long)]
        organization: Option<String>,
        /// From when it allows, an RFC 3339 time.
        #[arg(long)]
        from: Option<String>,
        /// Until when it allows, an RFC 3339 time.
        #[arg(long)]
        until: Option<String>,
    },
    /// Take a role away.
    Revoke {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        #[command(flatten)]
        principal: PrincipalArgs,
        /// The role, written `namespace#name`.
        #[arg(long)]
        role: String,
        /// The application it was given for, if it was.
        #[arg(long)]
        application: Option<String>,
        /// The organization it was given for, if it was.
        #[arg(long)]
        organization: Option<String>,
    },
    /// Bind a resource server to an engine, or change the binding.
    Bind {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The resource server's audience.
        #[arg(long)]
        namespace: String,
        /// The engine that answers for it.
        #[arg(long, value_enum)]
        engine: EngineArg,
        /// How long the engine may take, in milliseconds.
        #[arg(long)]
        time_limit_milliseconds: Option<u64>,
        /// Mark the resource server as sensitive: no action may fail open.
        #[arg(long)]
        sensitive: bool,
        /// An action allowed when the engine fails; repeat for more.
        #[arg(long = "fail-open")]
        fail_open: Vec<String>,
        /// Let a policy read what the caller asserts.
        #[arg(long)]
        trust_asserted: bool,
    },
    /// Remove a resource server's binding: it is denied everything.
    Unbind {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The resource server's audience.
        #[arg(long)]
        namespace: String,
    },
    /// Print the tenant's bindings, one per line.
    Bindings {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum PermissionCommand {
    /// Declare a permission, or describe it again.
    Declare {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The resource server's audience.
        #[arg(long)]
        namespace: String,
        /// The permission, written `resource:action`.
        #[arg(long)]
        name: String,
        /// What it allows.
        #[arg(long, default_value = "")]
        description: String,
    },
    /// Remove a permission, and remove it from every role.
    Remove {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The resource server's audience.
        #[arg(long)]
        namespace: String,
        /// The permission, written `resource:action`.
        #[arg(long)]
        name: String,
    },
    /// Print the permissions of a resource server, one per line.
    List {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The resource server's audience.
        #[arg(long)]
        namespace: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum RoleCommand {
    /// Define a role, or replace it whole.
    Define {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The resource server's audience.
        #[arg(long)]
        namespace: String,
        /// The role's name.
        #[arg(long)]
        name: String,
        /// What it is for.
        #[arg(long, default_value = "")]
        description: String,
        /// A permission it holds; repeat for more.
        #[arg(long = "permission")]
        permissions: Vec<String>,
        /// A condition on one of its permissions, written
        /// `permission=expression`; repeat for more.
        #[arg(long = "condition")]
        conditions: Vec<String>,
        /// A role it includes, written `namespace#name`; repeat for more.
        #[arg(long = "include")]
        includes: Vec<String>,
    },
    /// Remove a role that no other role includes.
    Remove {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The role, written `namespace#name`.
        #[arg(long)]
        role: String,
    },
    /// Print the tenant's roles, one per line.
    List {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
    },
}

#[derive(clap::Args)]
#[group(required = true, multiple = false)]
pub(crate) struct PrincipalArgs {
    /// The user's identifier.
    #[arg(long)]
    user: Option<String>,
    /// The client's identifier.
    #[arg(long)]
    client: Option<String>,
    /// The group's identifier: the role is held by everyone in the group.
    #[arg(long)]
    group: Option<String>,
}

impl PrincipalArgs {
    fn subject(&self) -> Result<Subject, DomainError> {
        match (&self.user, &self.client, &self.group) {
            (Some(user), None, None) => Subject::new(SubjectKind::User, user),
            (None, Some(client), None) => Subject::new(SubjectKind::Client, client),
            (None, None, Some(group)) => Subject::new(SubjectKind::Group, group),
            _ => Err(DomainError::invalid(
                "authorization.subject_invalid",
                "give one of --user, --client or --group",
            )),
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum EngineArg {
    Native,
    OpenPolicyAgent,
}

/// An engine that is only a name. The command line binds resource servers
/// and never evaluates; the registry only has to know the names.
struct Named(EngineId);

#[async_trait::async_trait]
impl AuthorizationEngine for Named {
    fn id(&self) -> EngineId {
        self.0.clone()
    }

    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities::default()
    }

    async fn evaluate(
        &self,
        _tenant: &TenantContext,
        _input: &EvaluationInput,
    ) -> Result<EngineAnswer, DomainError> {
        Err(DomainError::internal(
            "authorization.engine_unavailable",
            "the command line does not evaluate",
        ))
    }
}

/// Knows nothing about subjects: the command line never evaluates.
struct NoSubjects;

#[async_trait::async_trait]
impl SubjectAttributeSource for NoSubjects {
    async fn attributes_of(
        &self,
        _tenant: &TenantContext,
        _subject: &Subject,
    ) -> Result<Attributes, DomainError> {
        Ok(Attributes::none())
    }
}

struct Services {
    tenant: TenantContext,
    roles: RoleService,
    evaluation: EvaluationService,
}

async fn services(database: &Database, slug: &str) -> Result<Services, DomainError> {
    let tenants = TenantService::new(
        Arc::new(database.clone()),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.clone())),
        Arc::new(SystemClock),
    );
    let entry = existing(&tenants, slug).await?;
    let units = || -> Arc<dyn hodor_kernel::UnitOfWorkFactory> { Arc::new(database.clone()) };
    let mut registry = EngineRegistry::new();
    registry.register(Arc::new(NativeEngine::new(
        units(),
        Arc::new(PgRoleAssignmentStore),
        Arc::new(PgNativeRoleStore),
        Arc::new(SystemClock),
    )))?;
    registry.register(Arc::new(Named(EngineId::parse("open_policy_agent")?)))?;
    Ok(Services {
        tenant: TenantContext::assume(entry.tenant_id),
        roles: RoleService::new(units(), Arc::new(PgNativeRoleStore), Arc::new(SystemClock))
            .with_condition_language(Arc::new(CelConditionLanguage::new())),
        evaluation: EvaluationService::new(
            units(),
            Arc::new(PgRoleAssignmentStore),
            Arc::new(PgEngineBindingStore),
            Arc::new(NoSubjects),
            registry,
            Arc::new(SystemClock),
        ),
    })
}

fn role_key(reference: &str) -> Result<RoleKey, DomainError> {
    let (namespace, name) = reference.rsplit_once('#').ok_or_else(|| {
        DomainError::invalid(
            "authorization.role_name_invalid",
            "a role is written namespace#name",
        )
    })?;
    Ok(RoleKey::new(
        Namespace::parse(namespace)?,
        RoleName::parse(name)?,
    ))
}

fn scope(
    application: Option<&str>,
    organization: Option<&str>,
) -> Result<AssignmentScope, DomainError> {
    Ok(match (application, organization) {
        (None, None) => AssignmentScope::Tenant,
        (Some(id), None) => AssignmentScope::Application(ApplicationReference::parse(id)?),
        (None, Some(id)) => AssignmentScope::Organization(OrganizationReference::parse(id)?),
        (Some(_), Some(_)) => {
            return Err(DomainError::invalid(
                "authorization.scope_invalid",
                "an assignment is scoped to an application or to an organization, not both",
            ));
        }
    })
}

fn time_of(value: Option<&str>) -> Result<Option<OffsetDateTime>, DomainError> {
    value
        .map(|text| {
            OffsetDateTime::parse(text, &Rfc3339).map_err(|_| {
                DomainError::invalid(
                    "authorization.validity_invalid",
                    "a time is written in RFC 3339",
                )
            })
        })
        .transpose()
}

/// Runs a command on permissions, roles, assignments or bindings.
#[allow(clippy::too_many_lines)]
pub(crate) async fn run_manage(
    database: &Database,
    command: ManageCommand,
) -> Result<String, DomainError> {
    match command {
        ManageCommand::Permission { command } => match command {
            PermissionCommand::Declare {
                tenant,
                namespace,
                name,
                description,
            } => {
                let s = services(database, &tenant).await?;
                let permission = s
                    .roles
                    .declare_permission(
                        &s.tenant,
                        Namespace::parse(&namespace)?,
                        PermissionName::parse(&name)?,
                        &description,
                        caller(),
                    )
                    .await?;
                Ok(format!(
                    "declared {}#{}",
                    permission.namespace().as_str(),
                    permission.name().as_str()
                ))
            }
            PermissionCommand::Remove {
                tenant,
                namespace,
                name,
            } => {
                let s = services(database, &tenant).await?;
                let removed = s
                    .roles
                    .remove_permission(
                        &s.tenant,
                        &Namespace::parse(&namespace)?,
                        &PermissionName::parse(&name)?,
                        caller(),
                    )
                    .await?;
                Ok(if removed { "removed" } else { "not declared" }.to_owned())
            }
            PermissionCommand::List { tenant, namespace } => {
                let s = services(database, &tenant).await?;
                let permissions = s
                    .roles
                    .permissions(&s.tenant, &Namespace::parse(&namespace)?)
                    .await?;
                Ok(permissions
                    .iter()
                    .map(|p| format!("{}\t{}", p.name().as_str(), p.description()))
                    .collect::<Vec<_>>()
                    .join("\n"))
            }
        },
        ManageCommand::Role { command } => match command {
            RoleCommand::Define {
                tenant,
                namespace,
                name,
                description,
                permissions,
                conditions,
                includes,
            } => {
                let s = services(database, &tenant).await?;
                let mut conditions_of = BTreeMap::new();
                for written in &conditions {
                    let (permission, expression) = written.split_once('=').ok_or_else(|| {
                        DomainError::invalid(
                            "authorization.condition_invalid",
                            "a condition is written permission=expression",
                        )
                    })?;
                    conditions_of.insert(
                        PermissionName::parse(permission)?,
                        Condition::parse(expression)?,
                    );
                }
                let contents = RoleContents {
                    description,
                    permissions: permissions
                        .iter()
                        .map(|p| PermissionName::parse(p))
                        .collect::<Result<BTreeSet<_>, _>>()?,
                    includes: includes
                        .iter()
                        .map(|r| role_key(r))
                        .collect::<Result<BTreeSet<_>, _>>()?,
                    conditions: conditions_of,
                };
                let key = RoleKey::new(Namespace::parse(&namespace)?, RoleName::parse(&name)?);
                let role = s
                    .roles
                    .define_role(&s.tenant, key, contents, caller())
                    .await?;
                Ok(format!("defined {}", role.key().reference()))
            }
            RoleCommand::Remove { tenant, role } => {
                let s = services(database, &tenant).await?;
                let removed = s
                    .roles
                    .remove_role(&s.tenant, &role_key(&role)?, caller())
                    .await?;
                Ok(if removed { "removed" } else { "no such role" }.to_owned())
            }
            RoleCommand::List { tenant } => {
                let s = services(database, &tenant).await?;
                let mut out = String::new();
                for role in s.roles.roles(&s.tenant).await? {
                    let contents = role.contents();
                    let held: Vec<&str> = contents
                        .permissions
                        .iter()
                        .map(PermissionName::as_str)
                        .collect();
                    let _ = writeln!(
                        out,
                        "{}\t{}\tconditions={}",
                        role.key().reference(),
                        held.join(","),
                        contents.conditions.len()
                    );
                }
                Ok(out.trim_end().to_owned())
            }
        },
        ManageCommand::Assign {
            tenant,
            principal,
            role,
            application,
            organization,
            from,
            until,
        } => {
            let s = services(database, &tenant).await?;
            let assignment = s
                .roles
                .assign(
                    &s.tenant,
                    principal.subject()?,
                    role_key(&role)?,
                    scope(application.as_deref(), organization.as_deref())?,
                    Validity {
                        from: time_of(from.as_deref())?,
                        until: time_of(until.as_deref())?,
                    },
                    caller(),
                )
                .await?;
            Ok(format!(
                "assigned {} to {}:{}",
                assignment.role().reference(),
                assignment.principal().kind().as_str(),
                assignment.principal().id()
            ))
        }
        ManageCommand::Revoke {
            tenant,
            principal,
            role,
            application,
            organization,
        } => {
            let s = services(database, &tenant).await?;
            let taken = s
                .roles
                .revoke(
                    &s.tenant,
                    &principal.subject()?,
                    &role_key(&role)?,
                    &scope(application.as_deref(), organization.as_deref())?,
                    caller(),
                )
                .await?;
            Ok(if taken { "revoked" } else { "not held" }.to_owned())
        }
        ManageCommand::Bind {
            tenant,
            namespace,
            engine,
            time_limit_milliseconds,
            sensitive,
            fail_open,
            trust_asserted,
        } => {
            let s = services(database, &tenant).await?;
            let engine = match engine {
                EngineArg::Native => EngineId::native(),
                EngineArg::OpenPolicyAgent => EngineId::parse("open_policy_agent")?,
            };
            let mut settings = BindingSettings::new(Namespace::parse(&namespace)?, engine);
            if let Some(milliseconds) = time_limit_milliseconds {
                settings.time_limit = std::time::Duration::from_millis(milliseconds);
            }
            settings.sensitive = sensitive;
            settings.trust_asserted = trust_asserted;
            settings.fail_open_actions = fail_open
                .iter()
                .map(|a| Action::parse(a))
                .collect::<Result<_, _>>()?;
            let binding = s.evaluation.bind(&s.tenant, settings, caller()).await?;
            Ok(format!(
                "bound {} to {}",
                binding.namespace().as_str(),
                binding.engine().as_str()
            ))
        }
        ManageCommand::Unbind { tenant, namespace } => {
            let s = services(database, &tenant).await?;
            let removed = s
                .evaluation
                .unbind(&s.tenant, &Namespace::parse(&namespace)?, caller())
                .await?;
            Ok(if removed { "unbound" } else { "not bound" }.to_owned())
        }
        ManageCommand::Bindings { tenant } => {
            let s = services(database, &tenant).await?;
            Ok(s.evaluation
                .bindings(&s.tenant)
                .await?
                .iter()
                .map(|b| {
                    format!(
                        "{}\t{}\t{}ms",
                        b.namespace().as_str(),
                        b.engine().as_str(),
                        b.settings().time_limit.as_millis()
                    )
                })
                .collect::<Vec<_>>()
                .join("\n"))
        }
    }
}
