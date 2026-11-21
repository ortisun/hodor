//! Operations tool: migrations, tenant management, the first
//! administrator and checking the audit log.

use clap::{Parser, Subcommand, ValueEnum};
use hodor_adapters_crypto::{OsRandom, SecretKeys, Sha256Digest};
use hodor_adapters_postgres::{
    Database, PgAccessTokenStore, PgAuditLog, PgLinkStore, PgPool, PgProviderStore,
    PgRoleAssignmentStore, PgTenantDirectory, PgTenantRepository, PgUserRepository,
};
use hodor_audit::api::AuditService;
use hodor_authorization::api::{AuthorizationService, Role};
use hodor_credential::api::AccessTokenService;
use hodor_federation::api::{
    CreateProvider, DirectorySettings, FederationService, IdentityProvider, ProviderKind,
    ProviderSettings, ProviderStatus, callback_address,
};
use hodor_identity::api::{
    CreateUser, IdentifierKind, IdentityService, NormalizedIdentifier, Profile, UserKind,
};
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

#[allow(
    clippy::large_enum_variant,
    reason = "parsed once when the tool starts; its size does not matter"
)]
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

    /// Manage administrators.
    Admin {
        /// Connection URL of the application role.
        #[arg(
            long,
            env = "HODOR_DATABASE_URL",
            hide_env_values = true,
            global = true
        )]
        database_url: Option<String>,
        #[command(subcommand)]
        command: AdminCommand,
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

    /// Manage a tenant's identity providers.
    Provider {
        /// Connection URL of the application role.
        #[arg(
            long,
            env = "HODOR_DATABASE_URL",
            hide_env_values = true,
            global = true
        )]
        database_url: Option<String>,
        /// The keys that keep secrets encrypted at rest, as the server
        /// has them.
        #[arg(long, env = "HODOR_SECRET_KEYS", hide_env_values = true, global = true)]
        secret_keys: Option<String>,
        /// Hosts with their ports whose issuer may be plain HTTP,
        /// separated by commas, as the server has them. For a development
        /// stack; never set it anywhere real.
        #[arg(
            long,
            env = "HODOR_OUTBOUND_DEVELOPMENT_HOSTS",
            value_delimiter = ',',
            global = true
        )]
        development_hosts: Vec<String>,
        /// The LDAP directories providers may name, as `host:port`
        /// separated by commas, as the server has them.
        #[arg(
            long,
            env = "HODOR_DIRECTORY_HOSTS",
            value_delimiter = ',',
            global = true
        )]
        directory_hosts: Vec<String>,
        /// The address people reach this installation at, without a path.
        #[arg(
            long,
            env = "HODOR_PUBLIC_URL",
            default_value = "http://localhost:8080",
            global = true
        )]
        public_url: String,
        #[command(subcommand)]
        command: ProviderCommand,
    },

    /// Work with the keys that keep secrets encrypted at rest.
    Secrets {
        #[command(subcommand)]
        command: SecretsCommand,
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
enum AdminCommand {
    /// Make a user an administrator of a tenant, creating the user if
    /// needed, and print an access token for the administration interface.
    ///
    /// The token is printed once. Running the command again issues a new
    /// one and leaves earlier ones as they are.
    Bootstrap {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
        /// The administrator's email address.
        #[arg(long)]
        email: String,
        /// How long the token lives, in minutes: 1 to 43200 (30 days).
        #[arg(long, default_value_t = 60)]
        token_minutes: u32,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum ProviderKindArg {
    OpenidConnect,
    Github,
    Ldap,
}

#[allow(
    clippy::large_enum_variant,
    reason = "parsed once when the tool starts; its size does not matter"
)]
#[derive(Subcommand)]
enum ProviderCommand {
    /// Add an OpenID Connect provider to a tenant, enabled.
    ///
    /// The client secret is read from the environment variable
    /// `HODOR_PROVIDER_CLIENT_SECRET`, never from an argument, so that it
    /// shows neither in the list of processes nor in a shell's history.
    Add {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
        /// The provider's name in addresses, such as `google`. It never
        /// changes.
        #[arg(long)]
        alias: String,
        /// What a person reads on the sign-in page.
        #[arg(long)]
        name: String,
        /// How Hodor talks to the provider.
        #[arg(long, value_enum, default_value = "openid-connect")]
        kind: ProviderKindArg,
        /// The address that identifies the provider. May be left out for
        /// GitHub.
        #[arg(long)]
        issuer: Option<String>,
        /// Who Hodor is to the provider.
        #[arg(long)]
        client_id: String,
        /// What to ask the provider for. May be given several times;
        /// `openid email profile` unless given.
        #[arg(long = "scope")]
        scopes: Vec<String>,
        /// Do not create a person nobody knows yet on first sign-in.
        #[arg(long)]
        no_create_users: bool,
        /// For a directory: where people are searched for.
        #[arg(long)]
        base: Option<String>,
        /// For a directory: how a person is found, with `{identifier}`
        /// where what they type goes, such as `(uid={identifier})`.
        #[arg(long)]
        filter: Option<String>,
        /// For a directory: the attribute that never changes for a person.
        #[arg(long, default_value = "entryUUID")]
        subject_attribute: String,
        /// For a directory: the attribute holding the address.
        #[arg(long, default_value = "mail")]
        email_attribute: String,
        /// For a directory: the attribute holding the name.
        #[arg(long, default_value = "cn")]
        name_attribute: String,
        /// Take every address this provider gives as vouched for, even
        /// when the provider does not say so. Only for a provider whose
        /// addresses the organization itself hands out.
        #[arg(long)]
        trust_email: bool,
    },
    /// List a tenant's providers.
    List {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
    },
    /// Stop a provider from signing people in.
    Disable {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
        /// The provider's alias.
        #[arg(long)]
        alias: String,
    },
    /// Let a provider sign people in again.
    Enable {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
        /// The provider's alias.
        #[arg(long)]
        alias: String,
    },
}

#[derive(Subcommand)]
enum SecretsCommand {
    /// Print a new key for `HODOR_SECRET_KEYS`: 32 random bytes in Base64.
    ///
    /// The key is printed once and stored nowhere. Give it an identifier
    /// and put the pair first in the setting.
    GenerateKey,
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

/// Makes a user an administrator of a tenant and issues an access token
/// for them. See `docs/api/admin-api.md`, "The first administrator".
/// One line about a provider: its alias, status, issuer and the address
/// to register at the provider.
fn provider_line(provider: &IdentityProvider, public_url: &str, slug: &str) -> String {
    let state = provider.snapshot();
    let back = if state.kind == ProviderKind::Ldap {
        // Nobody leaves for a directory.
        "-".to_owned()
    } else {
        callback_address(public_url, slug, state.alias.as_str())
    };
    format!(
        "{} {} {} {back}",
        state.alias.as_str(),
        state.status.as_str(),
        state.settings.issuer,
    )
}

/// Runs a provider command against a tenant named by its slug.
async fn run_provider(
    database: &Database,
    secret_keys: Option<String>,
    development_hosts: &[String],
    directory_hosts: &[String],
    public_url: &str,
    command: ProviderCommand,
) -> Result<String, DomainError> {
    let setting = secret_keys.ok_or_else(|| {
        DomainError::invalid(
            "secret.keys_missing",
            "HODOR_SECRET_KEYS or --secret-keys is required: provider secrets are kept encrypted",
        )
    })?;
    let units = || Arc::new(database.clone());
    let clock = Arc::new(SystemClock);
    let tenants = TenantService::new(
        units(),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.clone())),
        clock.clone(),
    );
    let federation = FederationService::new(
        units(),
        Arc::new(PgProviderStore),
        Arc::new(PgLinkStore),
        Arc::new(SecretKeys::parse(&Secret::from(setting))?),
        clock,
    )
    .allowing_development_hosts(development_hosts)
    .allowing_directory_hosts(directory_hosts);
    let slug = match &command {
        ProviderCommand::Add { tenant, .. }
        | ProviderCommand::List { tenant }
        | ProviderCommand::Disable { tenant, .. }
        | ProviderCommand::Enable { tenant, .. } => tenant.clone(),
    };
    let entry = existing(&tenants, &slug).await?;
    // The command-line tool is one of the places allowed to establish a
    // tenant context: the operator names the tenant.
    let tenant = TenantContext::assume(entry.tenant_id);

    match command {
        ProviderCommand::Add {
            alias,
            name,
            kind,
            issuer,
            client_id,
            scopes,
            no_create_users,
            trust_email,
            base,
            filter,
            subject_attribute,
            email_attribute,
            name_attribute,
            ..
        } => {
            let kind = match kind {
                ProviderKindArg::OpenidConnect => ProviderKind::OpenIdConnect,
                ProviderKindArg::Github => ProviderKind::GitHub,
                ProviderKindArg::Ldap => ProviderKind::Ldap,
            };
            // A directory's settings, given for a directory; any other
            // kind that is given them is refused by the federation context.
            let directory = match (base, filter) {
                (None, None) => None,
                (base, filter) => Some(DirectorySettings {
                    base: base.unwrap_or_default(),
                    filter: filter.unwrap_or_default(),
                    subject_attribute,
                    email_attribute,
                    name_attribute,
                }),
            };
            let client_secret = std::env::var("HODOR_PROVIDER_CLIENT_SECRET").map_err(|_| {
                DomainError::invalid(
                    "federation.client_secret_invalid",
                    "the client secret is read from HODOR_PROVIDER_CLIENT_SECRET, which is not set",
                )
            })?;
            let provider = federation
                .create_provider(
                    &tenant,
                    CreateProvider {
                        alias,
                        kind,
                        settings: ProviderSettings {
                            saml: None,
                            display_name: name,
                            issuer: issuer
                                .or_else(|| {
                                    ProviderSettings::default_issuer_for(kind).map(str::to_owned)
                                })
                                .unwrap_or_default(),
                            client_id,
                            scopes: if scopes.is_empty() {
                                ProviderSettings::default_scopes_for(kind)
                            } else {
                                scopes
                            },
                            creates_users: !no_create_users,
                            trusts_email: trust_email,
                            directory,
                        },
                        client_secret: Secret::from(client_secret),
                    },
                    caller(),
                )
                .await?;
            let created = format!("created {}", provider_line(&provider, public_url, &slug));
            Ok(if kind == ProviderKind::Ldap {
                created
            } else {
                format!(
                    "{created}\nregister this address at the provider: {}",
                    callback_address(public_url, &slug, provider.alias().as_str())
                )
            })
        }
        ProviderCommand::List { .. } => Ok(federation
            .providers(&tenant)
            .await?
            .iter()
            .map(|provider| provider_line(provider, public_url, &slug))
            .collect::<Vec<_>>()
            .join("\n")),
        ProviderCommand::Disable { alias, .. } => {
            let provider = federation.provider_by_alias(&tenant, &alias).await?;
            let provider = federation
                .set_provider_status(&tenant, provider.id(), ProviderStatus::Disabled, caller())
                .await?;
            Ok(provider_line(&provider, public_url, &slug))
        }
        ProviderCommand::Enable { alias, .. } => {
            let provider = federation.provider_by_alias(&tenant, &alias).await?;
            let provider = federation
                .set_provider_status(&tenant, provider.id(), ProviderStatus::Enabled, caller())
                .await?;
            Ok(provider_line(&provider, public_url, &slug))
        }
    }
}

async fn bootstrap_administrator(
    database: &Database,
    slug: &str,
    email: &str,
    token_minutes: u32,
) -> Result<String, DomainError> {
    let units = || Arc::new(database.clone());
    let clock = Arc::new(SystemClock);
    let tenants = TenantService::new(
        units(),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.clone())),
        clock.clone(),
    );
    let entry = tenants.find_by_slug(slug).await?.ok_or_else(|| {
        DomainError::not_found("tenant.not_found", "there is no tenant with this slug")
    })?;
    // The command-line tool is one of the places allowed to establish a
    // tenant context: the operator names the tenant.
    let tenant = TenantContext::assume(entry.tenant_id);

    let identity = IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone());
    let address = NormalizedIdentifier::parse(IdentifierKind::Email, email)?;
    let user = match identity
        .find_by_login(&tenant, address.normalized())
        .await?
    {
        Some(user) => user,
        None => {
            let command = CreateUser {
                kind: UserKind::Human,
                identifiers: vec![(IdentifierKind::Email, email.to_owned())],
                profile: Profile::default(),
                confirmed: true,
            };
            identity.create(&tenant, command, caller()).await?
        }
    };
    if !user.may_sign_in() {
        return Err(DomainError::conflict(
            "identity.user_may_not_sign_in",
            "this user may not sign in, so a token for them would not work",
        ));
    }

    let role = Role::TenantAdministrator;
    AuthorizationService::new(units(), Arc::new(PgRoleAssignmentStore), clock.clone())
        .assign(&tenant, user.id(), role, caller())
        .await?;
    let (token, secret) = AccessTokenService::new(
        units(),
        Arc::new(PgAccessTokenStore),
        Arc::new(Sha256Digest),
        Arc::new(OsRandom),
        clock,
    )
    .issue(
        &tenant,
        user.id(),
        "bootstrap administrator",
        time::Duration::minutes(i64::from(token_minutes)),
        caller(),
    )
    .await?;

    // Written to the second: nobody plans around less.
    let expires_at = token.snapshot().expires_at;
    let expires = expires_at
        .replace_nanosecond(0)
        .unwrap_or(expires_at)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    Ok(format!(
        "user {} {}\nrole {}\ntoken {}\nexpires {expires}",
        user.id(),
        address.display(),
        role.as_str(),
        secret.expose()
    ))
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
        Command::Admin {
            database_url,
            command:
                AdminCommand::Bootstrap {
                    tenant,
                    email,
                    token_minutes,
                },
        } => {
            let url = database_url.ok_or("HODOR_DATABASE_URL or --database-url is required")?;
            let database = Database::connect(&Secret::from(url), 2).await?;
            let output = bootstrap_administrator(&database, &tenant, &email, token_minutes)
                .await
                .map_err(|error| format!("{}: {}", error.code(), error.message()))?;
            writeln!(std::io::stdout(), "{output}")?;
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
        Command::Provider {
            database_url,
            secret_keys,
            development_hosts,
            directory_hosts,
            public_url,
            command,
        } => {
            let url = database_url.ok_or("HODOR_DATABASE_URL or --database-url is required")?;
            let database = Database::connect(&Secret::from(url), 2).await?;
            let output = run_provider(
                &database,
                secret_keys,
                &development_hosts,
                &directory_hosts,
                &public_url,
                command,
            )
            .await
            .map_err(|error| format!("{}: {}", error.code(), error.message()))?;
            if !output.is_empty() {
                writeln!(std::io::stdout(), "{output}")?;
            }
        }
        Command::Secrets {
            command: SecretsCommand::GenerateKey,
        } => {
            let key = SecretKeys::generate(&OsRandom);
            writeln!(std::io::stdout(), "{}", key.expose())?;
        }
        Command::Probe { addr, path } => {
            if !probe(addr, &path)? {
                return Err(format!("{addr}{path} did not answer 200").into());
            }
        }
    }
    Ok(())
}
