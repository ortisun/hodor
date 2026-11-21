//! Operations tool: migrations, tenant management and checking the audit
//! log.

use clap::{Parser, Subcommand};
use hodor_adapters_crypto::Sha256Digest;
use hodor_adapters_postgres::{
    Database, PgAuditLog, PgPool, PgTenantDirectory, PgTenantRepository,
};
use hodor_audit::api::AuditService;
use hodor_kernel::{Actor, CorrelationId, DomainError, Secret, SystemClock, TenantContext};
use hodor_tenant::api::{Caller, CreateTenant, DirectoryEntry, TenantService};
use std::error::Error;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

/// Operate a Hodor installation.
#[derive(Parser)]
#[command(name = "hodor-cli", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Apply pending database migrations.
    ///
    /// Connects as the role that owns the schema. The server and worker use
    /// a different, less privileged role and never run migrations.
    Migrate {
        /// Connection URL of the schema owner.
        #[arg(long, env = "HODOR_DATABASE_OWNER_URL", hide_env_values = true)]
        database_url: String,
    },

    /// Manage tenants.
    ///
    /// Connects as a member of `hodor_app`; no cross-tenant role is needed.
    Tenant {
        /// Connection URL of the application role.
        #[arg(
            long,
            env = "HODOR_DATABASE_URL",
            hide_env_values = true,
            global = true
        )]
        database_url: Option<String>,
        #[command(subcommand)]
        command: TenantCommand,
    },

    /// Check the audit log.
    Audit {
        /// Connection URL of the application role.
        #[arg(
            long,
            env = "HODOR_DATABASE_URL",
            hide_env_values = true,
            global = true
        )]
        database_url: Option<String>,
        #[command(subcommand)]
        command: AuditCommand,
    },

    /// Check a health endpoint and exit non-zero unless it answers 200.
    ///
    /// For container health checks: the runtime image has no shell or HTTP
    /// client of its own.
    Probe {
        /// Address of the operations listener.
        #[arg(long, default_value = "127.0.0.1:9090")]
        addr: SocketAddr,
        /// Path to request.
        #[arg(long, default_value = "/readyz")]
        path: String,
    },
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Check a tenant's whole chain of audit records and exit non-zero if
    /// a record was changed, removed or inserted.
    Verify {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
    },
}

#[derive(Subcommand)]
enum TenantCommand {
    /// Create and activate a tenant.
    Create {
        /// The name used in addresses: `/t/<slug>`.
        #[arg(long)]
        slug: String,
        /// A human-readable name.
        #[arg(long)]
        name: String,
        /// Let anyone register in the tenant.
        #[arg(long)]
        open_registration: bool,
    },
    /// Create the system tenant, unless it already exists.
    CreateSystem,
    /// List every tenant.
    List,
    /// Suspend a tenant.
    Suspend {
        /// The tenant's slug.
        #[arg(long)]
        slug: String,
        /// Why the tenant is suspended.
        #[arg(long)]
        reason: String,
    },
    /// Reactivate a suspended tenant.
    Reactivate {
        /// The tenant's slug.
        #[arg(long)]
        slug: String,
    },
}

/// The command-line tool acts as the system: no authenticated
/// administrator exists yet at this stage.
fn caller() -> Caller {
    Caller {
        actor: Actor::System,
        correlation_id: CorrelationId::generate(),
    }
}

async fn existing(service: &TenantService, slug: &str) -> Result<DirectoryEntry, DomainError> {
    service.find_by_slug(slug).await?.ok_or_else(|| {
        DomainError::not_found(
            "tenant.not_found",
            format!("no tenant has the slug `{slug}`"),
        )
    })
}

async fn run_tenant(
    service: &TenantService,
    command: TenantCommand,
) -> Result<String, DomainError> {
    match command {
        TenantCommand::Create {
            slug,
            name,
            open_registration,
        } => {
            let tenant = service
                .create(
                    CreateTenant {
                        slug,
                        display_name: name,
                        open_registration,
                        system: false,
                    },
                    caller(),
                )
                .await?;
            Ok(format!(
                "created {} {}",
                tenant.snapshot().slug,
                tenant.id()
            ))
        }
        TenantCommand::CreateSystem => {
            if let Some(entry) = service.find_by_slug("system").await? {
                return Ok(format!("exists {} {}", entry.slug, entry.tenant_id));
            }
            let tenant = service
                .create(
                    CreateTenant {
                        slug: String::new(),
                        display_name: "System".to_owned(),
                        open_registration: false,
                        system: true,
                    },
                    caller(),
                )
                .await?;
            Ok(format!(
                "created {} {}",
                tenant.snapshot().slug,
                tenant.id()
            ))
        }
        TenantCommand::List => {
            let lines: Vec<String> = service
                .list()
                .await?
                .into_iter()
                .map(|entry| {
                    format!(
                        "{} {} {}",
                        entry.slug,
                        entry.tenant_id,
                        entry.status.as_str()
                    )
                })
                .collect();
            Ok(lines.join("\n"))
        }
        TenantCommand::Suspend { slug, reason } => {
            let entry = existing(service, &slug).await?;
            let tenant = service
                .suspend(&TenantContext::assume(entry.tenant_id), &reason, caller())
                .await?;
            Ok(format!("{} {}", entry.slug, tenant.status().as_str()))
        }
        TenantCommand::Reactivate { slug } => {
            let entry = existing(service, &slug).await?;
            let tenant = service
                .reactivate(&TenantContext::assume(entry.tenant_id), caller())
                .await?;
            Ok(format!("{} {}", entry.slug, tenant.status().as_str()))
        }
    }
}

/// Checks a tenant's chain of audit records. The outer error is a failure
/// to check; the inner one is a chain that is broken.
async fn verify_audit(
    database: &Database,
    slug: &str,
) -> Result<Result<String, String>, DomainError> {
    let tenants = TenantService::new(
        Arc::new(database.clone()),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.clone())),
        Arc::new(SystemClock),
    );
    let entry = tenants.find_by_slug(slug).await?.ok_or_else(|| {
        DomainError::not_found("tenant.not_found", "there is no tenant with this slug")
    })?;
    let audit = AuditService::new(
        Arc::new(database.clone()),
        Arc::new(PgAuditLog),
        Arc::new(Sha256Digest),
        Arc::new(SystemClock),
    );
    // The command-line tool is one of the places allowed to establish a
    // tenant context: the operator names the tenant.
    let verification = audit
        .verify(&TenantContext::assume(entry.tenant_id))
        .await?;
    Ok(match verification.broken {
        None => Ok(format!("intact: {} records", verification.records)),
        Some((sequence, problem)) => Err(format!(
            "the audit chain of {slug} is broken at record {sequence}: {}; {} records before it are in order",
            problem.description(),
            verification.records
        )),
    })
}

/// Performs a minimal HTTP/1.1 GET and reports whether the status is 200.
fn probe(addr: SocketAddr, path: &str) -> Result<bool, std::io::Error> {
    let timeout = Duration::from_secs(3);
    let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )?;
    let mut status_line = [0_u8; 12];
    stream.read_exact(&mut status_line)?;
    Ok(&status_line == b"HTTP/1.1 200")
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    match Cli::parse().command {
        Command::Migrate { database_url } => {
            let pool = PgPool::connect(&database_url).await?;
            hodor_adapters_postgres::migrate(&pool).await?;
            writeln!(std::io::stdout(), "migrations applied")?;
        }
        Command::Tenant {
            database_url,
            command,
        } => {
            let url = database_url.ok_or("HODOR_DATABASE_URL or --database-url is required")?;
            let database = Database::connect(&Secret::from(url), 2).await?;
            let service = TenantService::new(
                Arc::new(database.clone()),
                Arc::new(PgTenantRepository),
                Arc::new(PgTenantDirectory::new(database)),
                Arc::new(SystemClock),
            );
            match run_tenant(&service, command).await {
                Ok(output) if output.is_empty() => {}
                Ok(output) => writeln!(std::io::stdout(), "{output}")?,
                Err(error) => {
                    return Err(format!("{}: {}", error.code(), error.message()).into());
                }
            }
        }
        Command::Audit {
            database_url,
            command: AuditCommand::Verify { tenant },
        } => {
            let url = database_url.ok_or("HODOR_DATABASE_URL or --database-url is required")?;
            let database = Database::connect(&Secret::from(url), 2).await?;
            let output = verify_audit(&database, &tenant)
                .await
                .map_err(|error| format!("{}: {}", error.code(), error.message()))??;
            writeln!(std::io::stdout(), "{output}")?;
        }
        Command::Probe { addr, path } => {
            if !probe(addr, &path)? {
                return Err(format!("{addr}{path} did not answer 200").into());
            }
        }
    }
    Ok(())
}
