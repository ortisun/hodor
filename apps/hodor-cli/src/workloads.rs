//! The commands for service accounts and agents.
//!
//! Specified in `docs/architecture/contexts/identity.md`, "Command-line
//! tool". The rules are the identity context's, so a value the
//! administration interface refuses is refused here with the same code.

use crate::{caller, existing};
use clap::Subcommand;
use hodor_adapters_crypto::{OsRandom, Sha256Digest};
use hodor_adapters_postgres::{
    Database, PgAccessTokenRecordStore, PgApiKeyStore, PgApplicationStore, PgClientStore,
    PgGroupRepository, PgOrganizationRepository, PgResourceServerStore, PgTenantDirectory,
    PgTenantRepository, PgUserRepository, PgWorkloadRepository,
};
use hodor_authorization::api::check_key_scopes;
use hodor_credential::api::{
    ApiKey, ApiKeyId, ApiKeySecret, ApiKeyService, ApiKeySettings, KeyApplicationId,
    REVOKED_BY_ADMINISTRATOR,
};
use hodor_identity::api::{
    CreateWorkload, IdentityService, UserKind, UserStatus, WORKLOAD_DELETED, Workload,
    WorkloadAccess, WorkloadService,
};
use hodor_kernel::{
    Caller, DomainError, ErrorKind, PageRequest, SystemClock, TenantContext, UnitOfWork, UserId,
};
use hodor_oauth::api::{ApplicationId, ApplicationPorts, ApplicationService, WorkloadTokens};
use hodor_tenant::api::TenantService;
use std::sync::Arc;
use time::Duration;

#[derive(Subcommand)]
pub(crate) enum WorkloadCommand {
    /// Create one, active, with its owners.
    Create {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// Its name, 1 to 200 characters.
        #[arg(long)]
        name: String,
        /// A person responsible for it; given once for each, 1 to 10.
        #[arg(long = "owner", required = true)]
        owners: Vec<UserId>,
    },
    /// List the tenant's, except the deleted ones.
    List {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
    },
    /// Disable one: its clients get no tokens, and its tokens stop at once.
    Disable(TargetArgs),
    /// Enable one again.
    Enable(TargetArgs),
    /// Delete one: its name is erased, its owners forgotten and its tokens
    /// and API keys revoked.
    Delete(TargetArgs),
    /// Manage one's API keys.
    #[command(subcommand)]
    Key(KeyCommand),
}

#[derive(Subcommand)]
pub(crate) enum KeyCommand {
    /// Make an API key, and print it once.
    Create {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The workload's identifier.
        #[arg(long)]
        id: UserId,
        /// For administrators, 1 to 100 characters.
        #[arg(long)]
        name: String,
        /// A permission of the administration interface or a scope of the
        /// Authorization API; given once for each.
        #[arg(long = "scope", required = true)]
        scopes: Vec<String>,
        /// The application the key asks the Authorization API for.
        #[arg(long)]
        application: Option<String>,
        /// How long the key lives, 1 to 365 days.
        #[arg(long, default_value_t = 90)]
        lifetime_days: u32,
    },
    /// List the workload's keys, newest first.
    List(TargetArgs),
    /// Replace a key with a new one, and print it once.
    Rotate {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The workload's identifier.
        #[arg(long)]
        id: UserId,
        /// The key's identifier.
        #[arg(long)]
        key: ApiKeyId,
        /// How long the new key lives, 1 to 365 days.
        #[arg(long, default_value_t = 90)]
        lifetime_days: u32,
        /// How long the old key keeps working, 0 to 30 days.
        #[arg(long, default_value_t = 7)]
        keep_previous_days: u32,
    },
    /// Revoke a key at once.
    Revoke {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The workload's identifier.
        #[arg(long)]
        id: UserId,
        /// The key's identifier.
        #[arg(long)]
        key: ApiKeyId,
    },
}

#[derive(clap::Args)]
pub(crate) struct TargetArgs {
    /// Slug of the tenant.
    #[arg(long)]
    tenant: String,
    /// Its identifier.
    #[arg(long)]
    id: UserId,
}

/// Ends what a workload holds when the command-line tool disables or
/// deletes it: its access tokens. A workload never signs in and is never
/// granted anything by a person, so it holds no session and no grant.
struct CommandLineAccess {
    tokens: WorkloadTokens,
    keys: ApiKeyService,
}

#[async_trait::async_trait]
impl WorkloadAccess for CommandLineAccess {
    async fn revoke_access(
        &self,
        uow: &mut dyn UnitOfWork,
        workload: UserId,
        reason: &'static str,
        caller: Caller,
    ) -> Result<(), DomainError> {
        self.tokens.revoke_in(uow, workload, reason, caller).await?;
        Ok(())
    }

    async fn revoke_credentials(
        &self,
        uow: &mut dyn UnitOfWork,
        workload: UserId,
        caller: Caller,
    ) -> Result<(), DomainError> {
        self.keys
            .revoke_all_of_in(uow, workload, WORKLOAD_DELETED, caller)
            .await?;
        Ok(())
    }
}

fn identity(database: &Database) -> IdentityService {
    IdentityService::new(
        Arc::new(database.clone()),
        Arc::new(PgUserRepository),
        Arc::new(SystemClock),
    )
    .with_groups(Arc::new(PgGroupRepository))
    .with_organizations(Arc::new(PgOrganizationRepository))
}

fn service(database: &Database) -> WorkloadService {
    WorkloadService::new(
        Arc::new(database.clone()),
        identity(database),
        Arc::new(PgWorkloadRepository),
        Arc::new(CommandLineAccess {
            tokens: WorkloadTokens::new(Arc::new(PgAccessTokenRecordStore), Arc::new(SystemClock)),
            keys: keys(database),
        }),
        Arc::new(SystemClock),
    )
}

async fn tenant_of(database: &Database, slug: &str) -> Result<TenantContext, DomainError> {
    let tenants = TenantService::new(
        Arc::new(database.clone()),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.clone())),
        Arc::new(SystemClock),
    );
    Ok(TenantContext::assume(
        existing(&tenants, slug).await?.tenant_id,
    ))
}

/// `principal` if it is a service account or an agent of the tenant that
/// is not deleted, as a client's principal must be: the OAuth context does
/// not know what a principal is, so the command asks the identity context.
pub(crate) async fn principal_of(
    database: &Database,
    tenant: &TenantContext,
    principal: UserId,
    kind: Option<UserKind>,
) -> Result<UserId, DomainError> {
    let refused = || {
        DomainError::invalid(
            "oauth.client_principal_invalid",
            "a client's principal is a service account or an agent of the tenant; an agent \
             with the token exchange grant, a service account with `spiffe_jwt`, \
             `tls_client_auth`, `spiffe_x509` or `linkerd_identity`",
        )
    };
    match identity(database).get(tenant, principal).await {
        Ok(user)
            if user.kind().is_workload()
                && user.status() != UserStatus::Deleted
                && kind.is_none_or(|kind| user.kind() == kind) =>
        {
            Ok(principal)
        }
        Ok(_) => Err(refused()),
        Err(error) if error.kind() == ErrorKind::NotFound => Err(refused()),
        Err(error) => Err(error),
    }
}

fn line(workload: &Workload) -> String {
    format!(
        "{} {} {}",
        workload.id(),
        workload.status().as_str(),
        workload.name()
    )
}

/// Runs a command on the workloads of `kind`.
pub(crate) async fn run(
    database: &Database,
    kind: UserKind,
    command: WorkloadCommand,
) -> Result<String, DomainError> {
    let service = service(database);
    match command {
        WorkloadCommand::Create {
            tenant,
            name,
            owners,
        } => {
            let tenant = tenant_of(database, &tenant).await?;
            let workload = service
                .create(&tenant, CreateWorkload { kind, name, owners }, caller())
                .await?;
            Ok(format!("created {} {}", workload.id(), workload.name()))
        }
        WorkloadCommand::List { tenant } => {
            let tenant = tenant_of(database, &tenant).await?;
            let mut lines = Vec::new();
            let mut page = PageRequest::new(Some(200), None);
            loop {
                let found = service.list(&tenant, kind, &page).await?;
                lines.extend(found.items.iter().map(line));
                match found.next_cursor {
                    Some(cursor) => page = PageRequest::new(Some(200), Some(cursor)),
                    None => break,
                }
            }
            Ok(lines.join("\n"))
        }
        WorkloadCommand::Disable(target) => {
            let tenant = tenant_of(database, &target.tenant).await?;
            let workload = service.disable(&tenant, kind, target.id, caller()).await?;
            Ok(format!("{} {}", workload.status().as_str(), workload.id()))
        }
        WorkloadCommand::Enable(target) => {
            let tenant = tenant_of(database, &target.tenant).await?;
            let workload = service.enable(&tenant, kind, target.id, caller()).await?;
            Ok(format!("{} {}", workload.status().as_str(), workload.id()))
        }
        WorkloadCommand::Delete(target) => {
            let tenant = tenant_of(database, &target.tenant).await?;
            service.delete(&tenant, kind, target.id, caller()).await?;
            Ok(format!("deleted {}", target.id))
        }
        WorkloadCommand::Key(command) => run_key(database, &service, kind, command).await,
    }
}

fn keys(database: &Database) -> ApiKeyService {
    ApiKeyService::new(
        Arc::new(database.clone()),
        Arc::new(PgApiKeyStore),
        Arc::new(Sha256Digest),
        Arc::new(OsRandom),
        Arc::new(SystemClock),
    )
}

fn days(days: u32) -> Duration {
    // More than any lifetime accepted, so that a large number is refused
    // by its rule instead of overflowing.
    Duration::days(i64::from(days.min(100_000)))
}

fn made(key: &ApiKey, secret: &ApiKeySecret) -> String {
    let expires = key
        .snapshot()
        .expires_at
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    format!(
        "key {}\napi-key {}\nexpires {expires}",
        key.id(),
        secret.expose()
    )
}

/// The application `given` names, if it is one of the tenant: the
/// credential context does not know applications.
async fn application_of(
    database: &Database,
    tenant: &TenantContext,
    given: &str,
) -> Result<KeyApplicationId, DomainError> {
    let refused = || {
        DomainError::invalid(
            "credential.api_key_application_invalid",
            "the application is not one of the tenant",
        )
    };
    let id: ApplicationId = given.parse().map_err(|_| refused())?;
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(database.clone()),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        digest: Arc::new(Sha256Digest),
        random: Arc::new(OsRandom),
        clock: Arc::new(SystemClock),
    });
    match applications.application(tenant, id).await {
        Ok(_) => Ok(KeyApplicationId::from_uuid(id.as_uuid())),
        Err(error) if error.kind() == ErrorKind::NotFound => Err(refused()),
        Err(error) => Err(error),
    }
}

async fn run_key(
    database: &Database,
    workloads: &WorkloadService,
    kind: UserKind,
    command: KeyCommand,
) -> Result<String, DomainError> {
    let keys = keys(database);
    match command {
        KeyCommand::Create {
            tenant,
            id,
            name,
            scopes,
            application,
            lifetime_days,
        } => {
            let tenant = tenant_of(database, &tenant).await?;
            let holder = workloads.get(&tenant, kind, id).await?;
            check_key_scopes(&scopes, application.is_some())?;
            let application = match &application {
                Some(given) => Some(application_of(database, &tenant, given).await?),
                None => None,
            };
            let (key, secret) = keys
                .create(
                    &tenant,
                    holder.id(),
                    ApiKeySettings {
                        name,
                        scopes,
                        application,
                    },
                    days(lifetime_days),
                    caller(),
                )
                .await?;
            Ok(made(&key, &secret))
        }
        KeyCommand::List(target) => {
            let tenant = tenant_of(database, &target.tenant).await?;
            let holder = workloads.get(&tenant, kind, target.id).await?;
            let now = keys.now();
            Ok(keys
                .list(&tenant, holder.id())
                .await?
                .iter()
                .map(|key| {
                    format!(
                        "{} {} {} {}",
                        key.id(),
                        key.status_at(now).as_str(),
                        key.snapshot().hint,
                        key.snapshot().settings.name
                    )
                })
                .collect::<Vec<_>>()
                .join("\n"))
        }
        KeyCommand::Rotate {
            tenant,
            id,
            key,
            lifetime_days,
            keep_previous_days,
        } => {
            let tenant = tenant_of(database, &tenant).await?;
            let holder = workloads.get(&tenant, kind, id).await?;
            let (next, secret) = keys
                .rotate(
                    &tenant,
                    holder.id(),
                    key,
                    days(lifetime_days),
                    days(keep_previous_days),
                    caller(),
                )
                .await?;
            Ok(made(&next, &secret))
        }
        KeyCommand::Revoke { tenant, id, key } => {
            let tenant = tenant_of(database, &tenant).await?;
            let holder = workloads.get(&tenant, kind, id).await?;
            keys.revoke(
                &tenant,
                holder.id(),
                key,
                REVOKED_BY_ADMINISTRATOR,
                caller(),
            )
            .await?;
            Ok(format!("revoked {key}"))
        }
    }
}
