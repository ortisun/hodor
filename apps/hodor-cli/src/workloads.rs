//! The commands for service accounts and agents.
//!
//! Specified in `docs/architecture/contexts/identity.md`, "Command-line
//! tool". The rules are the identity context's, so a value the
//! administration interface refuses is refused here with the same code.

use crate::{caller, existing};
use clap::Subcommand;
use hodor_adapters_postgres::{
    Database, PgAccessTokenRecordStore, PgGroupRepository, PgOrganizationRepository,
    PgTenantDirectory, PgTenantRepository, PgUserRepository, PgWorkloadRepository,
};
use hodor_identity::api::{
    CreateWorkload, IdentityService, UserKind, UserStatus, Workload, WorkloadAccess,
    WorkloadService,
};
use hodor_kernel::{
    Caller, DomainError, ErrorKind, PageRequest, SystemClock, TenantContext, UnitOfWork, UserId,
};
use hodor_oauth::api::WorkloadTokens;
use hodor_tenant::api::TenantService;
use std::sync::Arc;

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
    /// revoked.
    Delete(TargetArgs),
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
) -> Result<UserId, DomainError> {
    let refused = || {
        DomainError::invalid(
            "oauth.client_principal_invalid",
            "a client's principal is a service account or an agent of the tenant",
        )
    };
    match identity(database).get(tenant, principal).await {
        Ok(user) if user.kind().is_workload() && user.status() != UserStatus::Deleted => {
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
    }
}
