//! The commands for applications, clients and resource servers.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "The command-line
//! tool". The values are given as the administration interface takes
//! them and checked by the OAuth context, so that a value refused there
//! is refused here with the same code.

use crate::{caller, existing};
use clap::Subcommand;
use hodor_adapters_crypto::{OsRandom, Sha256Digest};
use hodor_adapters_http::{GuardedHttpClient, OutboundPolicy};
use hodor_adapters_postgres::{
    Database, PgApplicationStore, PgClaimMapperStore, PgClientStore, PgResourceServerStore,
    PgTenantDirectory, PgTenantRepository,
};
use hodor_identity::api::UserKind;
use hodor_kernel::{DomainError, ErrorKind, SystemClock, TenantContext, UserId};
use hodor_oauth::api::{
    Application, ApplicationId, ApplicationPorts, ApplicationService, ApplicationSettings,
    AuthenticationMethod, ClaimMapper, ClaimMapperId, ClaimMapperPorts, ClaimMapperService,
    ClaimMapperSettings, ClaimSource, ClaimTarget, Client, ClientId, ClientSettings, ClientType,
    CreateClient, CreateResourceServer, ExchangeRule, GrantType, IdTokenAlgorithm, LinkerdIdentity,
    RequestObjectAlgorithm, ResourceServerSettings, RotateSecret, ScopeDefinition, SpiffeId,
    Status, SubjectType,
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
        /// How its ID tokens are signed: `ES256` unless given, or `RS256`,
        /// `PS256` or `EdDSA`.
        #[arg(long)]
        id_token_algorithm: Option<String>,
        /// How its UserInfo answers are signed: `ES256`, `RS256`, `PS256`
        /// or `EdDSA`. Answered in JSON, unsigned, unless given.
        #[arg(long)]
        userinfo_signed_response_alg: Option<String>,
        /// How it signs its request objects: `ES256`, `RS256` or `PS256`,
        /// which accepts only that one, or `none`, which accepts only
        /// unsigned objects. Any of the three unless given.
        #[arg(long)]
        request_object_signing_alg: Option<String>,
        /// Has every request of it pushed to the pushed authorization
        /// request endpoint first, and refuses any other.
        #[arg(long)]
        require_pushed_authorization_requests: bool,
        /// An address where it keeps request objects; a `request_uri` is
        /// fetched only when it starts with one. Given once per address,
        /// and checked as the server checks it: the name must lead to
        /// public addresses only.
        #[arg(long = "request-uri")]
        request_uris: Vec<String>,
        /// Where its logout tokens are sent when a session it signed a
        /// person in with ends. Checked as the server checks it: the name
        /// must lead to public addresses only.
        #[arg(long)]
        backchannel_logout_uri: Option<String>,
        /// Record that it needs `sid` in its logout tokens; only with a
        /// back-channel logout address.
        #[arg(long)]
        backchannel_logout_session_required: bool,
        /// How it knows a person: `public` unless given, or `pairwise`, by
        /// an identifier of its sector alone.
        #[arg(long)]
        subject_type: Option<String>,
        /// For a pairwise client: the address whose host is its sector,
        /// which must answer a JSON array of every redirect address.
        /// Fetched now, as the server fetches it.
        #[arg(long)]
        sector_identifier_uri: Option<String>,
        /// The service account or agent it acts as; only with the
        /// `client_credentials` grant alone.
        #[arg(long)]
        principal: Option<UserId>,
        /// An exchange rule of an agent's client, written
        /// `<subject audience>=><audience>`; given once for each.
        #[arg(long = "exchange-rule")]
        exchange_rules: Vec<String>,
        /// The one SPIFFE identifier of a service account's client, such as
        /// `spiffe://cluster.local/ns/payroll/sa/export`: required with the
        /// methods `spiffe_jwt` and `spiffe_x509`, allowed with
        /// `tls_client_auth`.
        #[arg(long)]
        spiffe_id: Option<String>,
        /// The one Linkerd identity of a service account's client:
        /// required with the method `linkerd_identity`, allowed with
        /// `tls_client_auth`.
        #[arg(long)]
        linkerd_identity: Option<String>,
        /// Bind every access token of the client to the certificate its
        /// request comes with, and a public client's refresh tokens too:
        /// `tls_client_certificate_bound_access_tokens` of RFC 8705.
        #[arg(long)]
        bound_tokens: bool,
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
    /// Manage the claim mappers of a client.
    #[command(subcommand)]
    Mapper(MapperCommand),
}

#[derive(Subcommand)]
pub(crate) enum MapperCommand {
    /// Add a claim mapper to a client.
    Add {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The `client_id`.
        #[arg(long)]
        client: String,
        /// The name of the claim.
        #[arg(long)]
        claim: String,
        /// A token it writes into: `id_token`, `access_token` or
        /// `userinfo`; given once per target.
        #[arg(long = "target", required = true)]
        targets: Vec<String>,
        /// Where the value comes from: `attribute`, `groups`,
        /// `group_member`, `organization` or `constant`.
        #[arg(long)]
        source: String,
        /// The attribute of an `attribute` or `organization` source.
        #[arg(long)]
        attribute: Option<String>,
        /// The group of a `group_member` source.
        #[arg(long)]
        group: Option<String>,
        /// The value of a `constant` source, written as JSON.
        #[arg(long)]
        value: Option<String>,
        /// The scope a token must hold for the claim to be added.
        #[arg(long)]
        scope: Option<String>,
    },
    /// List a client's claim mappers, by claim name.
    List {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The `client_id`.
        #[arg(long)]
        client: String,
    },
    /// Delete a claim mapper.
    Remove {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The `client_id`.
        #[arg(long)]
        client: String,
        /// The mapper's identifier.
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

pub(crate) fn application_id(value: &str) -> Result<ApplicationId, DomainError> {
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
pub(crate) async fn open(
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

/// An exchange rule written `<subject audience>=><audience>`.
fn exchange_rule(written: &str) -> Result<ExchangeRule, DomainError> {
    let (subject_audience, audience) = written.split_once("=>").ok_or_else(|| {
        DomainError::invalid(
            "oauth.client_exchange_rules_invalid",
            "an exchange rule is written `<subject audience>=><audience>`",
        )
    })?;
    Ok(ExchangeRule {
        subject_audience: subject_audience.trim().to_owned(),
        audience: audience.trim().to_owned(),
    })
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
    development_hosts: &[String],
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
            userinfo_signed_response_alg,
            request_object_signing_alg,
            require_pushed_authorization_requests,
            request_uris,
            backchannel_logout_uri,
            backchannel_logout_session_required,
            subject_type,
            sector_identifier_uri,
            principal,
            exchange_rules,
            spiffe_id,
            linkerd_identity,
            bound_tokens,
        } => {
            let (tenant, service) = open(database, &tenant).await?;
            // The addresses are checked, and a sector identifier address
            // fetched, by the guarded outbound client, with the
            // development exception the server has.
            let guarded = || {
                GuardedHttpClient::new(OutboundPolicy {
                    development_hosts: development_hosts
                        .iter()
                        .map(|host| host.trim().to_owned())
                        .filter(|host| !host.is_empty())
                        .collect(),
                    ..OutboundPolicy::default()
                })
            };
            let service = service
                .with_destinations(Arc::new(guarded()?))
                .with_sector_documents(Arc::new(guarded()?));
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
            settings.require_pushed_requests = require_pushed_authorization_requests;
            settings.request_uris = request_uris;
            if let Some(algorithm) = id_token_algorithm {
                settings.id_token_algorithm = IdTokenAlgorithm::parse(&algorithm)?;
            }
            if let Some(algorithm) = userinfo_signed_response_alg {
                settings.userinfo_algorithm =
                    Some(IdTokenAlgorithm::parse_for_userinfo(&algorithm)?);
            }
            if let Some(algorithm) = request_object_signing_alg {
                settings.request_object_algorithm =
                    Some(RequestObjectAlgorithm::parse(&algorithm)?);
            }
            settings.exchange_rules = exchange_rules
                .iter()
                .map(|rule| exchange_rule(rule))
                .collect::<Result<_, _>>()?;
            settings.backchannel_logout_uri = backchannel_logout_uri;
            settings.backchannel_logout_session_required = backchannel_logout_session_required;
            if let Some(subject_type) = subject_type {
                settings.subject_type = SubjectType::parse(&subject_type)?;
            }
            settings.sector_identifier_uri = sector_identifier_uri;
            settings.spiffe_id = spiffe_id.as_deref().map(SpiffeId::parse).transpose()?;
            settings.linkerd_identity = linkerd_identity
                .as_deref()
                .map(LinkerdIdentity::parse)
                .transpose()?;
            settings.certificate_bound_access_tokens = bound_tokens;
            if let Some(principal) = principal {
                // Only an agent acts on a person's behalf, and only a
                // service account proves who it is with its identity.
                let kind = if settings.grant_types.contains(&GrantType::TokenExchange) {
                    Some(UserKind::Agent)
                } else if settings.authentication_method.uses_workload_identity() {
                    Some(UserKind::ServiceAccount)
                } else {
                    None
                };
                settings.principal =
                    Some(crate::workloads::principal_of(database, &tenant, principal, kind).await?);
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
        ClientCommand::Mapper(command) => run_mapper(database, command).await,
    }
}

fn mapper_service(database: &Database) -> ClaimMapperService {
    ClaimMapperService::new(ClaimMapperPorts {
        units_of_work: Arc::new(database.clone()),
        clients: Arc::new(PgClientStore),
        mappers: Arc::new(PgClaimMapperStore),
        clock: Arc::new(SystemClock),
    })
}

fn source_invalid() -> DomainError {
    DomainError::invalid(
        "oauth.claim_mapper_source_invalid",
        "a constant is written as JSON",
    )
}

/// The source the options of `mapper add` give, written as the
/// administration interface takes it.
fn source_of(
    kind: &str,
    attribute: Option<String>,
    group: Option<String>,
    value: Option<String>,
) -> Result<ClaimSource, DomainError> {
    let mut written = serde_json::Map::new();
    written.insert("kind".to_owned(), serde_json::json!(kind));
    if let Some(attribute) = attribute {
        written.insert("attribute".to_owned(), serde_json::json!(attribute));
    }
    if let Some(group) = group {
        written.insert("group_id".to_owned(), serde_json::json!(group));
    }
    if let Some(value) = value {
        let value: serde_json::Value =
            serde_json::from_str(&value).map_err(|_| source_invalid())?;
        written.insert("value".to_owned(), value);
    }
    ClaimSource::from_json(&serde_json::Value::Object(written))
}

fn source_line(source: &ClaimSource) -> String {
    let written = source.to_json();
    match source {
        ClaimSource::Attribute(_) | ClaimSource::Organization(_) => format!(
            "{}:{}",
            source.kind(),
            written["attribute"].as_str().unwrap_or_default()
        ),
        ClaimSource::GroupMember(group) => format!("{}:{group}", source.kind()),
        ClaimSource::Groups | ClaimSource::Constant(_) => source.kind().to_owned(),
    }
}

fn mapper_line(mapper: &ClaimMapper) -> String {
    let settings = mapper.settings();
    let targets: Vec<&str> = settings
        .targets
        .iter()
        .map(|target| target.as_str())
        .collect();
    format!(
        "{} {} {} {} {}",
        mapper.id(),
        settings.claim,
        targets.join(","),
        source_line(&settings.source),
        settings.scope.as_deref().unwrap_or("-"),
    )
}

/// Runs a claim mapper command.
async fn run_mapper(database: &Database, command: MapperCommand) -> Result<String, DomainError> {
    match command {
        MapperCommand::Add {
            tenant,
            client,
            claim,
            targets,
            source,
            attribute,
            group,
            value,
            scope,
        } => {
            let (tenant, _) = open(database, &tenant).await?;
            let targets = targets
                .iter()
                .map(|target| ClaimTarget::parse(target))
                .collect::<Result<Vec<_>, _>>()?;
            let source = source_of(&source, attribute, group, value)?;
            // The group must be one of the tenant's, as the administration
            // interface asks.
            if let ClaimSource::GroupMember(group) = &source {
                match crate::memberships::groups(database)
                    .get(&tenant, *group)
                    .await
                {
                    Ok(_) => {}
                    Err(error) if error.kind() == ErrorKind::NotFound => {
                        return Err(DomainError::invalid(
                            "oauth.claim_mapper_group_unknown",
                            "a mapper names a group of the tenant",
                        ));
                    }
                    Err(error) => return Err(error),
                }
            }
            let mapper = mapper_service(database)
                .create(
                    &tenant,
                    client_id(&client)?,
                    ClaimMapperSettings {
                        claim,
                        targets,
                        scope,
                        source,
                    },
                    caller(),
                )
                .await?;
            Ok(format!("mapper {}", mapper.id()))
        }
        MapperCommand::List { tenant, client } => {
            let (tenant, _) = open(database, &tenant).await?;
            Ok(mapper_service(database)
                .mappers(&tenant, client_id(&client)?)
                .await?
                .iter()
                .map(mapper_line)
                .collect::<Vec<_>>()
                .join("\n"))
        }
        MapperCommand::Remove { tenant, client, id } => {
            let (tenant, _) = open(database, &tenant).await?;
            let id: ClaimMapperId = id.parse().map_err(|_| {
                DomainError::not_found(
                    "oauth.claim_mapper_not_found",
                    "the client has no such claim mapper",
                )
            })?;
            mapper_service(database)
                .delete(&tenant, client_id(&client)?, id, caller())
                .await?;
            Ok(format!("removed {id}"))
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
