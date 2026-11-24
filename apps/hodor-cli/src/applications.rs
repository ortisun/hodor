//! The commands for applications, clients and resource servers.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "The command-line
//! tool". The values are given as the administration interface takes
//! them and checked by the OAuth context, so that a value refused there
//! is refused here with the same code.

use crate::{caller, existing};
use clap::Subcommand;
use hodor_adapters_crypto::{OsRandom, Sha256Digest};
use hodor_adapters_postgres::{
    Database, PgApplicationStore, PgClientStore, PgResourceServerStore, PgTenantDirectory,
    PgTenantRepository,
};
use hodor_kernel::{DomainError, SystemClock, TenantContext, UserId};
use hodor_oauth::api::{
    Application, ApplicationId, ApplicationPorts, ApplicationService, ApplicationSettings,
    AuthenticationMethod, Client, ClientId, ClientSettings, ClientType, CreateClient,
    CreateResourceServer, GrantType, IdTokenAlgorithm, ResourceServerSettings, RotateSecret,
    ScopeDefinition, Status,
};
use hodor_tenant::api::TenantService;
use std::fmt::Write as _;
use std::sync::Arc;
use time::Duration;
use time::format_description::well_known::Rfc3339;

#[derive(Subcommand)]
pub(crate) enum ApplicationCommand {
    /// Register an application, enabled.
    Add {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// Its name, shown to people.
        #[arg(long)]
        name: String,
        /// Whether it belongs to whoever runs the tenant. A person is not
        /// asked for consent for a first-party application.
        #[arg(long)]
        first_party: bool,
    },
    /// List the tenant's applications.
    List {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
    },
    /// Stop an application's clients from getting tokens.
    Disable {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The application's identifier.
        #[arg(long)]
        id: String,
    },
    /// Let an application's clients get tokens again.
    Enable {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The application's identifier.
        #[arg(long)]
        id: String,
    },
}

#[derive(Subcommand)]
#[allow(
    clippy::large_enum_variant,
    reason = "a command is read once from the command line; its size does not matter"
)]
pub(crate) enum ClientCommand {
    /// Create a client of an application, enabled. A client with a secret
    /// method gets its first secret, printed once.
    Add {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The application's identifier.
        #[arg(long)]
        application: String,
        /// Its name, for administrators.
        #[arg(long)]
        name: String,
        /// `confidential` or `public`. Never changes.
        #[arg(long = "type")]
        client_type: String,
        /// A grant it may use; given once per grant.
        #[arg(long = "grant", required = true)]
        grants: Vec<String>,
        /// A redirect address, compared by exact equality; given once per
        /// address.
        #[arg(long = "redirect-uri")]
        redirect_uris: Vec<String>,
        /// Where logout may send a person back to, compared by exact
        /// equality; given once per address.
        #[arg(long = "post-logout-redirect-uri")]
        post_logout_redirect_uris: Vec<String>,
        /// A scope it may ask for; given once per scope.
        #[arg(long = "scope")]
        scopes: Vec<String>,
        /// How it proves who it is; `client_secret_basic` for a
        /// confidential client and `none` for a public one unless given.
        #[arg(long)]
        method: Option<String>,
        /// How many days its first secret lives.
        #[arg(long, default_value_t = 365)]
        secret_days: u32,
        /// Let a confidential client redeem a code without PKCE. Every
        /// client uses PKCE unless this is given; a public client always
        /// does.
        #[arg(long)]
        without_pkce: bool,
        /// How its ID tokens are signed: `ES256` unless given, or `RS256`.
        #[arg(long)]
        id_token_algorithm: Option<String>,
        /// The service account or agent it acts as; only with the
        /// `client_credentials` grant alone.
        #[arg(long)]
        principal: Option<UserId>,
    },
    /// List an application's clients.
    List {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The application's identifier.
        #[arg(long)]
        application: String,
    },
    /// Give a client a new secret, printed once.
    RotateSecret {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The `client_id`.
        #[arg(long)]
        id: String,
        /// How many days the new secret lives.
        #[arg(long, default_value_t = 365)]
        lifetime_days: u32,
        /// How many more days the newest previous secret works; 0 ends it
        /// at once.
        #[arg(long, default_value_t = 7)]
        keep_previous_days: u32,
    },
    /// Stop a client from getting tokens.
    Disable {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The `client_id`.
        #[arg(long)]
        id: String,
    },
    /// Let a client get tokens again.
    Enable {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The `client_id`.
        #[arg(long)]
        id: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum ResourceServerCommand {
    /// Register the resource server of an application.
    Add {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The application's identifier.
        #[arg(long)]
        application: String,
        /// The audience of its tokens. Never changes.
        #[arg(long)]
        audience: String,
        /// Its name, for administrators and the consent page.
        #[arg(long)]
        name: String,
        /// A scope it defines, as `name=description`; given once per scope.
        #[arg(long = "scope")]
        scopes: Vec<String>,
    },
    /// List the tenant's resource servers.
    List {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
    },
}

/// More days than any lifetime the OAuth context accepts, so that a large
/// number is refused by its rule instead of overflowing.
const MOST_DAYS: u32 = 100_000;

fn days(given: u32) -> Duration {
    Duration::days(i64::from(given.min(MOST_DAYS)))
}

fn written(moment: time::OffsetDateTime) -> String {
    moment.format(&Rfc3339).unwrap_or_default()
}

fn application_id(value: &str) -> Result<ApplicationId, DomainError> {
    value.parse().map_err(|_| {
        DomainError::not_found(
            "oauth.application_not_found",
            "there is no such application",
        )
    })
}

fn client_id(value: &str) -> Result<ClientId, DomainError> {
    value
        .parse()
        .map_err(|_| DomainError::not_found("oauth.client_not_found", "there is no such client"))
}

/// The tenant a command names, and the use cases to run it with.
async fn open(
    database: &Database,
    slug: &str,
) -> Result<(TenantContext, ApplicationService), DomainError> {
    let units = || Arc::new(database.clone());
    let clock = Arc::new(SystemClock);
    let tenants = TenantService::new(
        units(),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.clone())),
        clock.clone(),
    );
    let entry = existing(&tenants, slug).await?;
    let service = ApplicationService::new(ApplicationPorts {
        units_of_work: units(),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        digest: Arc::new(Sha256Digest),
        random: Arc::new(OsRandom),
        clock,
    });
    // The command-line tool is one of the places allowed to establish a
    // tenant context: the operator names the tenant.
    Ok((TenantContext::assume(entry.tenant_id), service))
}

fn application_line(application: &Application) -> String {
    let state = application.snapshot();
    format!(
        "{} {} {} {}",
        state.id,
        state.status.as_str(),
        if state.settings.first_party {
            "first-party"
        } else {
            "third-party"
        },
        state.settings.name,
    )
}

fn client_line(client: &Client) -> String {
    let state = client.snapshot();
    format!(
        "{} {} {} {} {}",
        state.id,
        state.status.as_str(),
        state.client_type.as_str(),
        state.settings.authentication_method.as_str(),
        state.settings.name,
    )
}

/// Runs an application command.
pub(crate) async fn run_application(
    database: &Database,
    command: ApplicationCommand,
) -> Result<String, DomainError> {
    match command {
        ApplicationCommand::Add {
            tenant,
            name,
            first_party,
        } => {
            let (tenant, service) = open(database, &tenant).await?;
            let application = service
                .create_application(&tenant, ApplicationSettings { name, first_party }, caller())
                .await?;
            Ok(format!(
                "application {} {}",
                application.id(),
                application.name()
            ))
        }
        ApplicationCommand::List { tenant } => {
            let (tenant, service) = open(database, &tenant).await?;
            Ok(service
                .applications(&tenant)
                .await?
                .iter()
                .map(application_line)
                .collect::<Vec<_>>()
                .join("\n"))
        }
        ApplicationCommand::Disable { tenant, id } => {
            set_application(database, &tenant, &id, Status::Disabled).await
        }
        ApplicationCommand::Enable { tenant, id } => {
            set_application(database, &tenant, &id, Status::Enabled).await
        }
    }
}

async fn set_application(
    database: &Database,
    slug: &str,
    id: &str,
    status: Status,
) -> Result<String, DomainError> {
    let (tenant, service) = open(database, slug).await?;
    let application = service
        .set_application_status(&tenant, application_id(id)?, status, caller())
        .await?;
    Ok(format!(
        "application {} {}",
        application.id(),
        application.snapshot().status.as_str()
    ))
}

fn client_type(value: &str) -> Result<ClientType, DomainError> {
    match value {
        "confidential" => Ok(ClientType::Confidential),
        "public" => Ok(ClientType::Public),
        _ => Err(DomainError::invalid(
            "oauth.client_type_invalid",
            "a client is `confidential` or `public`",
        )),
    }
}

/// Runs a client command.
pub(crate) async fn run_client(
    database: &Database,
    command: ClientCommand,
) -> Result<String, DomainError> {
    match command {
        ClientCommand::Add {
            tenant,
            application,
            name,
            client_type: kind,
            grants,
            redirect_uris,
            post_logout_redirect_uris,
            scopes,
            method,
            secret_days,
            without_pkce,
            id_token_algorithm,
            principal,
        } => {
            let (tenant, service) = open(database, &tenant).await?;
            let kind = client_type(&kind)?;
            let grants = grants
                .iter()
                .map(|grant| GrantType::parse(grant))
                .collect::<Result<Vec<_>, _>>()?;
            let mut settings = ClientSettings::new(&name, kind, grants, redirect_uris);
            if let Some(method) = method {
                settings.authentication_method = AuthenticationMethod::parse(&method)?;
            }
            settings.post_logout_redirect_uris = post_logout_redirect_uris;
            settings.allowed_scopes = scopes;
            settings.require_pkce = !without_pkce;
            if let Some(algorithm) = id_token_algorithm {
                settings.id_token_algorithm = IdTokenAlgorithm::parse(&algorithm)?;
            }
            if let Some(principal) = principal {
                settings.principal =
                    Some(crate::workloads::principal_of(database, &tenant, principal).await?);
            }
            let (client, secret) = service
                .create_client(
                    &tenant,
                    CreateClient {
                        application_id: application_id(&application)?,
                        client_type: kind,
                        settings,
                        secret_lifetime: Some(days(secret_days)),
                    },
                    caller(),
                )
                .await?;
            let mut output = format!("client {}", client.id());
            if let Some(secret) = secret {
                let expires = client
                    .snapshot()
                    .secrets
                    .iter()
                    .map(|kept| kept.expires_at)
                    .max();
                let _ = write!(output, "\nsecret {}", secret.expose());
                if let Some(expires) = expires {
                    let _ = write!(output, "\nexpires {}", written(expires));
                }
            }
            Ok(output)
        }
        ClientCommand::List {
            tenant,
            application,
        } => {
            let (tenant, service) = open(database, &tenant).await?;
            Ok(service
                .clients(&tenant, application_id(&application)?)
                .await?
                .iter()
                .map(client_line)
                .collect::<Vec<_>>()
                .join("\n"))
        }
        ClientCommand::RotateSecret {
            tenant,
            id,
            lifetime_days,
            keep_previous_days,
        } => {
            let (tenant, service) = open(database, &tenant).await?;
            let id = client_id(&id)?;
            let secret = service
                .rotate_client_secret(
                    &tenant,
                    id,
                    RotateSecret {
                        lifetime: days(lifetime_days),
                        keep_previous_for: days(keep_previous_days),
                    },
                    caller(),
                )
                .await?;
            let client = service.client(&tenant, id).await?;
            let newest = client
                .snapshot()
                .secrets
                .iter()
                .max_by_key(|kept| kept.created_at)
                .map(|kept| written(kept.expires_at))
                .unwrap_or_default();
            Ok(format!("secret {}\nexpires {newest}", secret.expose()))
        }
        ClientCommand::Disable { tenant, id } => {
            set_client(database, &tenant, &id, Status::Disabled).await
        }
        ClientCommand::Enable { tenant, id } => {
            set_client(database, &tenant, &id, Status::Enabled).await
        }
    }
}

async fn set_client(
    database: &Database,
    slug: &str,
    id: &str,
    status: Status,
) -> Result<String, DomainError> {
    let (tenant, service) = open(database, slug).await?;
    let client = service
        .set_client_status(&tenant, client_id(id)?, status, caller())
        .await?;
    Ok(format!(
        "client {} {}",
        client.id(),
        client.snapshot().status.as_str()
    ))
}

/// Runs a resource server command.
pub(crate) async fn run_resource_server(
    database: &Database,
    command: ResourceServerCommand,
) -> Result<String, DomainError> {
    match command {
        ResourceServerCommand::Add {
            tenant,
            application,
            audience,
            name,
            scopes,
        } => {
            let (tenant, service) = open(database, &tenant).await?;
            let scopes = scopes
                .iter()
                .map(|given| {
                    let (name, description) = given.split_once('=').unwrap_or((given, ""));
                    ScopeDefinition {
                        name: name.to_owned(),
                        description: description.to_owned(),
                    }
                })
                .collect();
            let server = service
                .create_resource_server(
                    &tenant,
                    CreateResourceServer {
                        application_id: application_id(&application)?,
                        audience,
                        settings: ResourceServerSettings { name, scopes },
                    },
                    caller(),
                )
                .await?;
            Ok(format!(
                "resource-server {} {}",
                server.id(),
                server.audience().as_str()
            ))
        }
        ResourceServerCommand::List { tenant } => {
            let (tenant, service) = open(database, &tenant).await?;
            Ok(service
                .resource_servers(&tenant)
                .await?
                .iter()
                .map(|server| {
                    let state = server.snapshot();
                    let scopes: Vec<&str> = state
                        .settings
                        .scopes
                        .iter()
                        .map(|scope| scope.name.as_str())
                        .collect();
                    format!(
                        "{} {} {} [{}]",
                        state.id,
                        state.audience.as_str(),
                        state.settings.name,
                        scopes.join(" ")
                    )
                })
                .collect::<Vec<_>>()
                .join("\n"))
        }
    }
}
