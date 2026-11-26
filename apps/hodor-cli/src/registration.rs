//! The commands for client registration: the settings of a tenant and its
//! initial access tokens.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Client
//! registration". The values are given as the administration interface
//! takes them and checked by the OAuth context, so that a value refused
//! there is refused here with the same code.

use crate::{caller, existing};
use clap::Subcommand;
use hodor_adapters_crypto::{OsRandom, Sha256Digest};
use hodor_adapters_postgres::{
    Database, PgApplicationStore, PgClientRegistrationStore, PgInitialAccessTokenStore,
    PgTenantDirectory, PgTenantRepository,
};
use hodor_kernel::{DomainError, SystemClock, TenantContext};
use hodor_oauth::api::{
    ApplicationId, ClientRegistrationPorts, ClientRegistrationService, InitialAccessToken,
    InitialAccessTokenId, NewInitialAccessToken, RegistrationPolicy, RegistrationSettings,
    RegistrationWay,
};
use hodor_tenant::api::TenantService;
use std::sync::Arc;
use time::Duration;
use time::format_description::well_known::Rfc3339;

#[derive(Subcommand)]
pub(crate) enum RegistrationCommand {
    /// Show whether clients may register themselves, and under which
    /// settings and policy.
    Show {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
    },
    /// Turn client registration on with these settings. A value left out
    /// takes its default.
    On {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The application registered clients belong to; never first
        /// party.
        #[arg(long)]
        application: String,
        /// A way a registration may be allowed: `initial_access_token`,
        /// `software_statement` or `open`. Once per way;
        /// `initial_access_token` unless given.
        #[arg(long = "way")]
        ways: Vec<String>,
        /// How many clients the application of registered clients may hold,
        /// 1 to 1000.
        #[arg(long, default_value_t = 100)]
        most_clients: u32,
        /// A grant a registration may name. Once per grant.
        #[arg(long = "grant")]
        grants: Vec<String>,
        /// A response type a registration may name, as OpenID Connect
        /// writes it, such as `code id_token`. Once per type.
        #[arg(long = "response-type")]
        response_types: Vec<String>,
        /// A scope a registration may ask for. Once per scope.
        #[arg(long = "scope")]
        scopes: Vec<String>,
        /// An authentication method a registration may name. Once per
        /// method.
        #[arg(long = "method")]
        methods: Vec<String>,
        /// A subject type a registration may name. Once per type.
        #[arg(long = "subject-type")]
        subject_types: Vec<String>,
        /// A host every address of a registration must name. Once per host;
        /// any host unless given.
        #[arg(long = "host")]
        hosts: Vec<String>,
    },
    /// Turn client registration off, keeping the settings and the tokens.
    Off {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
    },
    /// Make, list and revoke initial access tokens.
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
}

#[derive(Subcommand)]
pub(crate) enum TokenCommand {
    /// Make an initial access token, and print it once.
    Add {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// For administrators: whom it is handed to.
        #[arg(long)]
        name: String,
        /// How long it lives, in hours, 1 to 2160.
        #[arg(long, default_value_t = 168)]
        hours: i64,
        /// How many registrations it allows, 1 to 1000.
        #[arg(long, default_value_t = 1)]
        registrations: u32,
    },
    /// List the tenant's initial access tokens, newest first.
    List {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
    },
    /// Revoke an initial access token at once.
    Revoke {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The token's identifier.
        #[arg(long)]
        id: String,
    },
}

fn written(at: time::OffsetDateTime) -> String {
    at.format(&Rfc3339).unwrap_or_else(|_| at.to_string())
}

/// The settings, one fact a line.
fn described(settings: &RegistrationSettings) -> String {
    let policy = &settings.policy;
    let joined = |values: Vec<&str>| values.join(",");
    let mut lines = vec![
        format!(
            "registration {}",
            if settings.enabled { "on" } else { "off" }
        ),
        format!(
            "application {}",
            settings
                .application_id
                .map_or_else(|| "-".to_owned(), |id| id.to_string())
        ),
        format!("ways {}", joined(settings.way_names())),
        format!("most-clients {}", settings.max_clients),
        format!(
            "grants {}",
            joined(
                policy
                    .grant_types
                    .iter()
                    .map(|grant| grant.as_str())
                    .collect()
            )
        ),
        format!(
            "response-types {}",
            joined(
                policy
                    .response_types
                    .iter()
                    .map(|kind| kind.as_str())
                    .collect()
            )
        ),
        format!(
            "scopes {}",
            joined(policy.scopes.iter().map(String::as_str).collect())
        ),
        format!(
            "methods {}",
            joined(
                policy
                    .authentication_methods
                    .iter()
                    .map(|method| method.as_str())
                    .collect()
            )
        ),
        format!(
            "subject-types {}",
            joined(
                policy
                    .subject_types
                    .iter()
                    .map(|subject| subject.as_str())
                    .collect()
            )
        ),
    ];
    lines.push(match &policy.hosts {
        None => "hosts any".to_owned(),
        Some(hosts) => format!(
            "hosts {}",
            joined(hosts.iter().map(String::as_str).collect())
        ),
    });
    lines.join("\n")
}

/// One line of `token list`.
fn line(token: &InitialAccessToken, now: hodor_kernel::Timestamp) -> String {
    let state = token.snapshot();
    format!(
        "{} {} {}/{} {} …{} {}",
        state.id,
        token.status(now).as_str(),
        state.registrations,
        state.max_registrations,
        written(state.expires_at),
        state.hint,
        state.name
    )
}

/// The policy the arguments give, read as the administration interface
/// reads its document, so that the same values are refused the same way.
fn policy_of(
    grants: Vec<String>,
    response_types: Vec<String>,
    scopes: Vec<String>,
    methods: Vec<String>,
    subject_types: Vec<String>,
    hosts: Vec<String>,
) -> Result<RegistrationPolicy, DomainError> {
    let mut document = serde_json::Map::new();
    for (name, values) in [
        ("grant_types", grants),
        ("response_types", response_types),
        ("scopes", scopes),
        ("token_endpoint_auth_methods", methods),
        ("subject_types", subject_types),
        ("hosts", hosts),
    ] {
        if !values.is_empty() {
            document.insert(name.to_owned(), serde_json::json!(values));
        }
    }
    RegistrationPolicy::from_json(&serde_json::Value::Object(document))
}

/// Runs one command against the tenant it names.
pub(crate) async fn run(
    database: &Database,
    command: RegistrationCommand,
) -> Result<String, DomainError> {
    let tenant = match &command {
        RegistrationCommand::Show { tenant }
        | RegistrationCommand::On { tenant, .. }
        | RegistrationCommand::Off { tenant }
        | RegistrationCommand::Token {
            command:
                TokenCommand::Add { tenant, .. }
                | TokenCommand::List { tenant }
                | TokenCommand::Revoke { tenant, .. },
        } => tenant.clone(),
    };
    let tenants = TenantService::new(
        Arc::new(database.clone()),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.clone())),
        Arc::new(SystemClock),
    );
    // The command-line tool is one of the places allowed to establish a
    // tenant context: the operator names the tenant.
    let context = TenantContext::assume(existing(&tenants, &tenant).await?.tenant_id);
    let service = ClientRegistrationService::new(ClientRegistrationPorts {
        units_of_work: Arc::new(database.clone()),
        registrations: Arc::new(PgClientRegistrationStore),
        tokens: Arc::new(PgInitialAccessTokenStore),
        applications: Arc::new(PgApplicationStore),
        digest: Arc::new(Sha256Digest),
        random: Arc::new(OsRandom),
        clock: Arc::new(SystemClock),
    });

    match command {
        RegistrationCommand::Show { .. } => {
            Ok(described(&service.settings(&context).await?.settings))
        }
        RegistrationCommand::On {
            application,
            ways,
            most_clients,
            grants,
            response_types,
            scopes,
            methods,
            subject_types,
            hosts,
            ..
        } => {
            let application_id = application.parse::<ApplicationId>().map_err(|_| {
                DomainError::invalid(
                    "oauth.client_registration_application_invalid",
                    "registered clients belong to one application of the tenant",
                )
            })?;
            let ways = if ways.is_empty() {
                RegistrationSettings::default().ways
            } else {
                ways.iter()
                    .map(|way| RegistrationWay::parse(way))
                    .collect::<Result<_, _>>()?
            };
            let policy = policy_of(
                grants,
                response_types,
                scopes,
                methods,
                subject_types,
                hosts,
            )?;
            let in_force = service
                .replace(
                    &context,
                    RegistrationSettings {
                        enabled: true,
                        application_id: Some(application_id),
                        ways,
                        max_clients: most_clients,
                        policy,
                    },
                    caller(),
                )
                .await?;
            Ok(described(&in_force.settings))
        }
        RegistrationCommand::Off { .. } => {
            let current = service.settings(&context).await?.settings;
            let in_force = service
                .replace(
                    &context,
                    RegistrationSettings {
                        enabled: false,
                        ..current
                    },
                    caller(),
                )
                .await?;
            Ok(described(&in_force.settings))
        }
        RegistrationCommand::Token {
            command:
                TokenCommand::Add {
                    name,
                    hours,
                    registrations,
                    ..
                },
        } => {
            let (token, value) = service
                .issue_token(
                    &context,
                    NewInitialAccessToken {
                        name,
                        // Held far from overflow; the rule of a lifetime
                        // refuses anything past 90 days.
                        lifetime: Duration::hours(hours.clamp(-1_000_000, 1_000_000)),
                        max_registrations: registrations,
                    },
                    caller(),
                )
                .await?;
            Ok(format!(
                "token {}\ninitial-access-token {}\nexpires {}",
                token.id(),
                value.expose(),
                written(token.snapshot().expires_at)
            ))
        }
        RegistrationCommand::Token {
            command: TokenCommand::List { .. },
        } => {
            let now = service.now();
            let tokens = service.tokens(&context).await?;
            Ok(tokens
                .iter()
                .map(|token| line(token, now))
                .collect::<Vec<_>>()
                .join("\n"))
        }
        RegistrationCommand::Token {
            command: TokenCommand::Revoke { id, .. },
        } => {
            let id = id.parse::<InitialAccessTokenId>().map_err(|_| {
                DomainError::not_found(
                    "oauth.initial_access_token_not_found",
                    "there is no such initial access token",
                )
            })?;
            service.revoke_token(&context, id, caller()).await?;
            Ok(format!("revoked {id}"))
        }
    }
}
