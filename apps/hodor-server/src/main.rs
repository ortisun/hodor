//! HTTP composition root: protocols, APIs and the console BFF.
//!
//! This is the only place that knows concrete adapter types. It reads the
//! configuration, builds the adapters, hands them to the HTTP layer as
//! trait objects and runs the listeners until asked to stop.

use clap::{Parser, ValueEnum};
use hodor_adapters_crypto::{
    Argon2Parameters, Argon2idHasher, AwsLcHmacSha1, AwsLcVerifier, HashingLimits,
    LocalKeyProvider, OsRandom, SecretKeys, Sha256Digest,
};
use hodor_adapters_http::{GuardedHttpClient, OutboundPolicy, ServiceHttpClient};
use hodor_adapters_ldap::LdapDirectoryClient;
use hodor_adapters_postgres::{
    Database, PgAccessTokenStore, PgApplicationStore, PgAttemptStore, PgAuditLog,
    PgAuthorizationCodeStore, PgAuthorizationRequestStore, PgClientAssertionStore, PgClientStore,
    PgGrantStore, PgKeyStore, PgLinkStore, PgMessageQueue, PgNativeRoleStore, PgPasswordStore,
    PgPendingAuthorizationStore, PgProviderStore, PgRecoveryCodeStore, PgResourceServerStore,
    PgRoleAssignmentStore, PgSealingStateStore, PgSessionStore, PgTenantDirectory,
    PgTenantRepository, PgTotpStore, PgTransactionStore, PgUserRepository,
    PgVerificationTokenStore, PgWebAuthnStore,
};
use hodor_audit::api::AuditService;
use hodor_authentication::api::{
    AccountService, AttemptGuard, AuthFlow, AuthenticationService, Condition, FactorService,
    FlowEngine, IdentifierAuthenticator, LockoutRules, PasskeyAuthenticator, PasswordAuthenticator,
    RecoveryCodeAuthenticator, Requirement, TotpAuthenticator, WebAuthnAuthenticator,
};
use hodor_authorization::api::{AuthorizationService, EngineRegistry, NativeEngine};
use hodor_authorization_opa::api::{Instances, OpenPolicyAgentEngine};
use hodor_credential::api::{
    AccessTokenService, CredentialService, RecoveryCodeService, RelyingParty, TotpService,
    WebAuthnService,
};
use hodor_federation::api::{
    EXTERNAL_STEP, ExternalIdentityAuthenticator, ExternalSignIn, FederationService, GitHubClient,
    LockoutPolicy, OpenIdClient, SamlClient,
};
use hodor_identity::api::IdentityService;
use hodor_kernel::{DomainError, Secret, SecretBox, SystemClock, TenantContext};
use hodor_keys::api::{KeyService, RotationPolicy, TenantSecretBox};
use hodor_notification::api::Notifier;
use hodor_oauth::api::{
    ApplicationPorts, ApplicationService, AuthorizationCodePorts, AuthorizationCodeService,
    TokenPorts, TokenService, UserInfoPorts, UserInfoService,
};
use hodor_observability::{LogFormat, Telemetry};
use hodor_protocol_http::{
    AdminState, AuthorizationState, ConsoleState, Health, InteractionState, Limits, Pages,
    ReadinessCheck, ResolvedTenant, TenantResolver, TenantStatus as HttpTenantStatus, TokenState,
    UserInfoState, admin_routes, authorization_routes, console_routes, discovery_routes,
    interaction_routes, key_set_routes, ops_router, public_router, serve, token_routes,
    userinfo_routes,
};
use hodor_session::api::SessionService;
use hodor_tenant::api::{TenantDirectory as _, TenantService, TenantStatus};
use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;

#[derive(Clone, Copy, ValueEnum)]
enum LogFormatArg {
    Json,
    Pretty,
}

/// Hodor identity server.
#[derive(Parser)]
#[command(name = "hodor-server", version, about)]
struct Config {
    /// Address of the public listener.
    #[arg(long, env = "HODOR_LISTEN_ADDR", default_value = "0.0.0.0:8080")]
    listen_addr: SocketAddr,

    /// Address of the operations listener (health endpoints). Keep it off
    /// the internet.
    #[arg(long, env = "HODOR_OPS_ADDR", default_value = "127.0.0.1:9090")]
    ops_addr: SocketAddr,

    /// Database URL of the application role (a member of `hodor_app`).
    #[arg(long, env = "HODOR_DATABASE_URL", hide_env_values = true)]
    database_url: String,

    /// Size of the database connection pool.
    #[arg(long, env = "HODOR_DATABASE_MAX_CONNECTIONS", default_value_t = 10)]
    database_max_connections: u32,

    /// Log rendering.
    #[arg(long, env = "HODOR_LOG_FORMAT", value_enum, default_value = "json")]
    log_format: LogFormatArg,

    /// Log filter, such as `info` or `info,hodor_oauth=debug`.
    #[arg(long, env = "HODOR_LOG_FILTER", default_value = "info")]
    log_filter: String,

    /// Full URL of the OTLP/HTTP traces endpoint. Unset disables export.
    #[arg(long, env = "HODOR_OTLP_TRACES_ENDPOINT")]
    otlp_traces_endpoint: Option<String>,

    /// Full URL of the OTLP/HTTP metrics endpoint. For VictoriaMetrics:
    /// `http://<host>:8428/opentelemetry/v1/metrics`. Unset disables export.
    #[arg(long, env = "HODOR_OTLP_METRICS_ENDPOINT")]
    otlp_metrics_endpoint: Option<String>,

    /// Seconds to keep serving after a stop signal while readiness fails,
    /// so the load balancer can take the instance out of rotation.
    #[arg(long, env = "HODOR_SHUTDOWN_DRAIN_SECONDS", default_value_t = 5)]
    shutdown_drain_seconds: u64,

    /// The address people reach this installation at, without a path.
    /// Links in messages start with it.
    #[arg(
        long,
        env = "HODOR_PUBLIC_URL",
        default_value = "http://localhost:8080"
    )]
    public_url: String,

    /// Directory holding the built hosted pages (`index.html` and
    /// `assets`). Unset: no pages are served.
    #[arg(long, env = "HODOR_PAGES_DIRECTORY")]
    pages_directory: Option<PathBuf>,

    /// Directory holding the built admin console (`index.html` and
    /// `assets`). Unset: no console page is served.
    #[arg(long, env = "HODOR_CONSOLE_DIRECTORY")]
    console_directory: Option<PathBuf>,

    /// The keys that keep secrets encrypted at rest: `identifier:key`
    /// pairs separated by commas, the first one sealing. Unset: no
    /// identity provider can be used.
    #[arg(long, env = "HODOR_SECRET_KEYS", hide_env_values = true)]
    secret_keys: Option<String>,

    /// How long a signing key replaced by hand stays published, in hours.
    /// The worker's rotation reads the same setting.
    #[arg(long, env = "HODOR_KEY_OVERLAP_HOURS", default_value_t = 24)]
    key_overlap_hours: i64,

    /// Hosts with their ports that outbound requests may reach without
    /// the address check and over plain HTTP, separated by commas. For a
    /// development stack on one machine; never set it anywhere real.
    #[arg(long, env = "HODOR_OUTBOUND_DEVELOPMENT_HOSTS", value_delimiter = ',')]
    outbound_development_hosts: Vec<String>,

    /// The shared Open Policy Agent instance, an origin such as
    /// `http://localhost:8181`, for policy written by the operator.
    #[arg(long, env = "HODOR_OPEN_POLICY_AGENT_ADDRESS")]
    open_policy_agent_address: Option<String>,

    /// Open Policy Agent instances dedicated to one tenant each, as
    /// `tenant-identifier=origin` pairs separated by commas.
    #[arg(
        long,
        env = "HODOR_OPEN_POLICY_AGENT_TENANT_ADDRESSES",
        default_value = ""
    )]
    open_policy_agent_tenant_addresses: String,

    /// The bearer token presented to every Open Policy Agent instance.
    #[arg(long, env = "HODOR_OPEN_POLICY_AGENT_TOKEN", hide_env_values = true)]
    open_policy_agent_token: Option<String>,

    /// The LDAP directories identity providers may name, as `host:port`
    /// separated by commas. Empty: no directory can be used.
    #[arg(long, env = "HODOR_DIRECTORY_HOSTS", value_delimiter = ',')]
    directory_hosts: Vec<String>,

    /// Memory one password hash uses, in kibibytes.
    #[arg(long, env = "HODOR_PASSWORD_HASH_MEMORY_KIBIBYTES", default_value_t = 19 * 1024)]
    password_hash_memory_kibibytes: u32,

    /// Passes over that memory.
    #[arg(long, env = "HODOR_PASSWORD_HASH_PASSES", default_value_t = 2)]
    password_hash_passes: u32,

    /// Lanes computed in parallel within one hash.
    #[arg(long, env = "HODOR_PASSWORD_HASH_LANES", default_value_t = 1)]
    password_hash_lanes: u32,

    /// Password hashes computed at the same time. Defaults to one per
    /// processor core.
    #[arg(long, env = "HODOR_PASSWORD_HASH_CONCURRENCY")]
    password_hash_concurrency: Option<usize>,

    /// Requests allowed to wait for a hash. Defaults to four times the
    /// concurrency.
    #[arg(long, env = "HODOR_PASSWORD_HASH_QUEUE")]
    password_hash_queue: Option<usize>,
}

/// Resolves tenants through the directory, answering by status as
/// specified in `docs/architecture/contexts/tenant.md`, "Lifecycle".
struct DirectoryResolver(PgTenantDirectory);

#[async_trait::async_trait]
impl TenantResolver for DirectoryResolver {
    async fn resolve(&self, slug: &str) -> Result<Option<ResolvedTenant>, DomainError> {
        let Some(entry) = self.0.find_by_slug(slug).await? else {
            return Ok(None);
        };
        let status = match entry.status {
            TenantStatus::Active => HttpTenantStatus::Active,
            TenantStatus::Suspended | TenantStatus::PendingDeletion => HttpTenantStatus::Suspended,
            // Not there yet, or not there any more: indistinguishable from
            // a tenant that never existed.
            TenantStatus::Provisioning | TenantStatus::Deleted => return Ok(None),
        };
        Ok(Some(ResolvedTenant {
            // The request path named this tenant and the directory
            // confirmed it: this is where its context is established.
            context: TenantContext::assume(entry.tenant_id),
            status,
        }))
    }
}

struct DatabaseCheck(Database);

#[async_trait::async_trait]
impl ReadinessCheck for DatabaseCheck {
    fn name(&self) -> &'static str {
        "database"
    }

    async fn check(&self) -> Result<(), String> {
        self.0.ping().await.map_err(|error| error.to_string())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::parse();

    // Telemetry starts before the async runtime: its exporters use a
    // blocking HTTP client on their own threads.
    let mut telemetry_config =
        hodor_observability::Config::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    telemetry_config.log_format = match config.log_format {
        LogFormatArg::Json => LogFormat::Json,
        LogFormatArg::Pretty => LogFormat::Pretty,
    };
    telemetry_config.log_filter.clone_from(&config.log_filter);
    telemetry_config
        .traces_endpoint
        .clone_from(&config.otlp_traces_endpoint);
    telemetry_config
        .metrics_endpoint
        .clone_from(&config.otlp_metrics_endpoint);
    let telemetry = Telemetry::init(&telemetry_config)?;

    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(config));

    if let Err(error) = &result {
        tracing::error!(%error, "server stopped with an error");
    }
    telemetry.shutdown();
    result
}

async fn run(config: Config) -> Result<(), Box<dyn Error>> {
    let database = Database::connect(
        &Secret::from(config.database_url.clone()),
        config.database_max_connections,
    )
    .await?;
    let health = Health::new(vec![Arc::new(DatabaseCheck(database.clone()))]);
    // Checked now, so that a wrong address stops the server at startup.
    // The Authorization API (Issue-75) evaluates through these engines.
    let _engines = authorization_engines(&config, &database)?;

    let keys = keys(&config, &database)?;
    let authorization = authorization(&config, &database);
    let mut oauth2 = authorization_routes(authorization.clone());
    if let Some(keys) = &keys {
        oauth2 = oauth2.merge(token_routes(token(
            &config,
            &database,
            keys.clone(),
            authorization.authorization,
        )));
        oauth2 = oauth2.merge(userinfo_routes(userinfo(&config, &database, keys.clone())));
    }
    let mut tenant_routes = axum::Router::new()
        .nest(
            "/interaction",
            interaction_routes(interaction(&config, &database)?),
        )
        .nest("/oauth2", oauth2)
        .nest(
            "/api/v1/admin",
            admin_routes(administration(&config, &database)?),
        )
        .nest(
            "/console/api",
            console_routes(ConsoleState {
                administration: administration(&config, &database)?,
                digest: Arc::new(Sha256Digest),
                clock: Arc::new(SystemClock),
            }),
        );
    match keys {
        Some(keys) => {
            tenant_routes = tenant_routes
                .merge(key_set_routes(keys))
                .merge(discovery_routes(config.public_url.clone()));
        }
        None => tracing::warn!(
            "HODOR_SECRET_KEYS is not set: no key set is published, keys cannot be managed and \
             no token is issued"
        ),
    }
    let mut site_routes = axum::Router::new();
    match &config.pages_directory {
        Some(directory) => {
            let pages = Pages::load(directory)?;
            tenant_routes = tenant_routes.merge(pages.page_routes());
            site_routes = site_routes.merge(pages.asset_routes());
            tracing::info!(directory = %directory.display(), "serving the hosted pages");
        }
        None => tracing::warn!("HODOR_PAGES_DIRECTORY is not set: no pages are served"),
    }
    match &config.console_directory {
        Some(directory) => {
            let console = Pages::load_console(directory)?;
            tenant_routes = tenant_routes.merge(console.page_routes());
            site_routes = site_routes.merge(console.asset_routes());
            tracing::info!(directory = %directory.display(), "serving the admin console");
        }
        None => tracing::warn!("HODOR_CONSOLE_DIRECTORY is not set: no console is served"),
    }
    let public = public_router(
        Arc::new(DirectoryResolver(PgTenantDirectory::new(database.clone()))),
        tenant_routes,
        site_routes,
        Limits::default(),
    );
    let ops = ops_router(health.clone());

    let public_listener = TcpListener::bind(config.listen_addr).await?;
    let ops_listener = TcpListener::bind(config.ops_addr).await?;
    tracing::info!(
        listen = %public_listener.local_addr()?,
        ops = %ops_listener.local_addr()?,
        "hodor-server started"
    );

    // One signal stops both listeners, after the drain delay.
    let (stop, stopped) = watch::channel(false);
    let drain = Duration::from_secs(config.shutdown_drain_seconds);
    tokio::spawn(async move {
        stop_signal().await;
        tracing::info!(
            drain_seconds = drain.as_secs(),
            "stop signal received, draining"
        );
        health.begin_draining();
        tokio::time::sleep(drain).await;
        let _ = stop.send(true);
    });

    let public_server = serve(public_listener, public, wait_for(stopped.clone()));
    let ops_server = serve(ops_listener, ops, wait_for(stopped));
    let (public_result, ops_result) = tokio::join!(public_server, ops_server);
    public_result?;
    ops_result?;
    tracing::info!("hodor-server stopped");
    Ok(())
}

/// Builds everything the interaction interface needs. This is the composition root: the
/// one place that knows which adapter stands behind each port.
fn interaction(config: &Config, database: &Database) -> Result<InteractionState, DomainError> {
    let units = || Arc::new(database.clone());
    let clock = Arc::new(SystemClock);
    let digest = Arc::new(Sha256Digest);
    let random = Arc::new(OsRandom);

    let defaults = HashingLimits::for_this_machine();
    let concurrent = config
        .password_hash_concurrency
        .unwrap_or(defaults.concurrent);
    let hasher = Arc::new(Argon2idHasher::new(
        Argon2Parameters {
            memory_kibibytes: config.password_hash_memory_kibibytes,
            passes: config.password_hash_passes,
            lanes: config.password_hash_lanes,
        },
        HashingLimits {
            concurrent,
            queued: config.password_hash_queue.unwrap_or(concurrent * 4),
        },
        random.clone(),
    )?);

    let tenants = TenantService::new(
        units(),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.clone())),
        clock.clone(),
    );
    let identity = IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone());
    let credentials =
        CredentialService::new(units(), Arc::new(PgPasswordStore), hasher, clock.clone());
    let sessions = SessionService::new(
        units(),
        Arc::new(PgSessionStore),
        digest.clone(),
        random.clone(),
        clock.clone(),
    );
    let guard = AttemptGuard::new(
        units(),
        Arc::new(PgAttemptStore),
        digest.clone(),
        clock.clone(),
    );
    let webauthn = WebAuthnService::new(
        units(),
        Arc::new(PgWebAuthnStore),
        RelyingParty::from_public_address(&config.public_url)?,
        digest.clone(),
        Arc::new(AwsLcVerifier),
        random.clone(),
        clock.clone(),
    );
    let mut engine = FlowEngine::new()
        .with(Arc::new(IdentifierAuthenticator::new(
            identity.clone(),
            digest.clone(),
        )))
        .with(Arc::new(PasswordAuthenticator::new(
            credentials.clone(),
            identity.clone(),
            tenants.clone(),
            guard.clone(),
        )))
        .with(Arc::new(WebAuthnAuthenticator::new(webauthn.clone())))
        .with(Arc::new(RecoveryCodeAuthenticator::new(
            RecoveryCodeService::new(
                units(),
                Arc::new(PgRecoveryCodeStore),
                digest.clone(),
                random.clone(),
                clock.clone(),
            ),
            tenants.clone(),
            guard.clone(),
        )))
        .with(Arc::new(PasskeyAuthenticator::new(
            webauthn.clone(),
            identity.clone(),
            tenants.clone(),
            guard.clone(),
        )));
    // A person who registered a security key is asked for it after the
    // first factor, unless the sign-in is multi-factor already. A passkey
    // is an alternative of the flow, which is multi-factor by itself.
    // Signing in through an identity provider is another alternative, and
    // a code of an authenticator application one more step, both offered
    // only by an installation that can keep secrets. A recovery code
    // stands in for either second factor.
    let second_factor = Requirement::Conditional(Condition::MultiFactorNotReached);
    let mut flow = AuthFlow::built_in()
        .with_step(
            WebAuthnAuthenticator::KIND,
            WebAuthnAuthenticator::KIND,
            second_factor,
        )
        .with_substitute(WebAuthnAuthenticator::KIND, RecoveryCodeAuthenticator::KIND)
        .with_alternative(PasskeyAuthenticator::KIND, PasskeyAuthenticator::KIND);
    if let Some(totp) = totp_service(config, database, random.clone())? {
        engine = engine.with(Arc::new(TotpAuthenticator::new(
            totp,
            tenants.clone(),
            guard.clone(),
        )));
        flow = flow
            .with_step(
                TotpAuthenticator::KIND,
                TotpAuthenticator::KIND,
                second_factor,
            )
            .with_substitute(TotpAuthenticator::KIND, RecoveryCodeAuthenticator::KIND);
    }
    let external = external_sign_in(config, database, &identity, &tenants, &guard)?;
    if let Some(external) = &external {
        engine = engine.with(Arc::new(ExternalIdentityAuthenticator::new(
            external.clone(),
        )));
        flow = flow.with_alternative(EXTERNAL_STEP, EXTERNAL_STEP);
    }
    // The server only queues messages; the worker delivers them.
    let accounts = AccountService::new(
        units(),
        Arc::new(PgVerificationTokenStore),
        identity.clone(),
        credentials,
        sessions.clone(),
        tenants.clone(),
        Notifier::new(Arc::new(PgMessageQueue), clock.clone()),
        guard,
        digest.clone(),
        random.clone(),
        clock.clone(),
        &config.public_url,
    );
    let factors = FactorService::new(identity.clone(), tenants.clone(), webauthn);
    let authentication = AuthenticationService::new(
        units(),
        Arc::new(PgTransactionStore),
        engine,
        flow,
        identity,
        sessions.clone(),
        tenants,
        digest.clone(),
        random,
        clock.clone(),
    )?;
    Ok(InteractionState {
        authentication,
        accounts,
        sessions,
        factors,
        external,
        digest,
        clock,
    })
}

/// Builds everything the authorization endpoint needs.
fn authorization(config: &Config, database: &Database) -> AuthorizationState {
    let units = Arc::new(database.clone());
    let clock = Arc::new(SystemClock);
    let digest = Arc::new(Sha256Digest);
    let random = Arc::new(OsRandom);
    AuthorizationState {
        authorization: AuthorizationCodeService::new(AuthorizationCodePorts {
            units_of_work: units.clone(),
            applications: Arc::new(PgApplicationStore),
            clients: Arc::new(PgClientStore),
            resource_servers: Arc::new(PgResourceServerStore),
            requests: Arc::new(PgAuthorizationRequestStore),
            grants: Arc::new(PgGrantStore),
            codes: Arc::new(PgAuthorizationCodeStore),
            digest: digest.clone(),
            random: random.clone(),
            clock: clock.clone(),
        }),
        sessions: SessionService::new(units, Arc::new(PgSessionStore), digest, random, clock),
        public_url: config.public_url.clone(),
    }
}

/// Builds everything the token endpoint needs. Tokens are signed with the
/// tenants' keys, so there is no token endpoint without them.
fn token(
    config: &Config,
    database: &Database,
    keys: KeyService,
    codes: AuthorizationCodeService,
) -> TokenState {
    TokenState {
        tokens: TokenService::new(TokenPorts {
            units_of_work: Arc::new(database.clone()),
            applications: Arc::new(PgApplicationStore),
            clients: Arc::new(PgClientStore),
            grants: Arc::new(PgGrantStore),
            assertions: Arc::new(PgClientAssertionStore),
            codes,
            keys,
            verifier: Arc::new(AwsLcVerifier),
            digest: Arc::new(Sha256Digest),
            random: Arc::new(OsRandom),
            clock: Arc::new(SystemClock),
        }),
        public_url: config.public_url.clone(),
    }
}

/// Builds everything UserInfo needs. It checks access tokens against the
/// tenants' keys, so there is no UserInfo without them.
fn userinfo(config: &Config, database: &Database, keys: KeyService) -> UserInfoState {
    let clock = Arc::new(SystemClock);
    UserInfoState {
        userinfo: UserInfoService::new(UserInfoPorts {
            keys,
            verifier: Arc::new(AwsLcVerifier),
            identity: IdentityService::new(
                Arc::new(database.clone()),
                Arc::new(PgUserRepository),
                clock.clone(),
            ),
            clock,
        }),
        public_url: config.public_url.clone(),
    }
}

/// The hosts that may be reached at a private address and over plain
/// HTTP: empty anywhere real.
fn development_hosts(config: &Config) -> Vec<String> {
    config
        .outbound_development_hosts
        .iter()
        .map(|host| host.trim().to_owned())
        .filter(|host| !host.is_empty())
        .collect()
}

/// The engines that answer for resource servers, beside the native engine
/// the authorization context keeps for Hodor's administration: the native
/// engine over the tenant's own roles, and Open Policy Agent. Open Policy
/// Agent is always registered, so that a binding to it fails closed when no
/// instance is configured instead of being refused.
fn authorization_engines(
    config: &Config,
    database: &Database,
) -> Result<EngineRegistry, DomainError> {
    let instances = Instances::parse(
        config.open_policy_agent_address.as_deref(),
        &config.open_policy_agent_tenant_addresses,
    )?;
    let addresses = instances.addresses();
    let http = ServiceHttpClient::new(
        &addresses,
        OutboundPolicy {
            max_response_bytes: 64 * 1024,
            ..OutboundPolicy::default()
        },
    )?;
    if addresses.is_empty() {
        tracing::info!("no Open Policy Agent instance is configured");
    } else {
        tracing::info!(
            instances = addresses.len(),
            "Open Policy Agent instances configured"
        );
    }
    let mut engine = OpenPolicyAgentEngine::new(
        Arc::new(http),
        Arc::new(Sha256Digest),
        Arc::new(SystemClock),
        instances,
    );
    if let Some(token) = &config.open_policy_agent_token {
        engine = engine.with_token(Secret::from(token.clone()));
    }
    let mut registry = EngineRegistry::new();
    registry.register(Arc::new(NativeEngine::new(
        Arc::new(database.clone()),
        Arc::new(PgRoleAssignmentStore),
        Arc::new(PgNativeRoleStore),
        Arc::new(SystemClock),
    )))?;
    registry.register(Arc::new(engine))?;
    Ok(registry)
}

/// The directories that may be connected to: empty unless set.
fn directory_hosts(config: &Config) -> Vec<String> {
    config
        .directory_hosts
        .iter()
        .map(|host| host.trim().to_ascii_lowercase())
        .filter(|host| !host.is_empty())
        .collect()
}

/// The tenant's lockout rules, read from the tenant context, for the
/// federation context's directories.
struct TenantLockout(TenantService);

#[async_trait::async_trait]
impl LockoutPolicy for TenantLockout {
    async fn rules(&self, tenant: &TenantContext) -> Result<LockoutRules, DomainError> {
        let settings = self
            .0
            .get(tenant)
            .await?
            .snapshot()
            .settings
            .lockout
            .clone();
        let seconds = |value: u32| time::Duration::seconds(i64::from(value));
        Ok(LockoutRules {
            max_failures: u32::from(settings.max_failures),
            window: seconds(settings.window_seconds),
            first_lockout: seconds(settings.first_lockout_seconds),
            longest_lockout: seconds(settings.longest_lockout_seconds),
        })
    }
}

/// Builds what signing in through an identity provider needs, if this
/// installation has keys to keep secrets with.
/// Authenticator applications, whose secrets are kept sealed: none
/// without `HODOR_SECRET_KEYS`.
fn totp_service(
    config: &Config,
    database: &Database,
    random: Arc<OsRandom>,
) -> Result<Option<TotpService>, DomainError> {
    let Some(setting) = &config.secret_keys else {
        return Ok(None);
    };
    Ok(Some(TotpService::new(
        Arc::new(database.clone()),
        Arc::new(PgTotpStore),
        secret_box(setting, database)?,
        Arc::new(AwsLcHmacSha1),
        random,
        Arc::new(SystemClock),
    )))
}

fn external_sign_in(
    config: &Config,
    database: &Database,
    identity: &IdentityService,
    tenants: &TenantService,
    guard: &AttemptGuard,
) -> Result<Option<ExternalSignIn>, DomainError> {
    let Some(setting) = &config.secret_keys else {
        tracing::warn!("HODOR_SECRET_KEYS is not set: no identity provider can be used");
        return Ok(None);
    };
    let secrets = secret_box(setting, database)?;
    let units = || Arc::new(database.clone());
    let clock = Arc::new(SystemClock);
    let digest = Arc::new(Sha256Digest);
    let development_hosts = development_hosts(config);
    let http = Arc::new(GuardedHttpClient::new(OutboundPolicy {
        development_hosts: development_hosts.clone(),
        ..OutboundPolicy::default()
    })?);
    let federation = FederationService::new(
        units(),
        Arc::new(PgProviderStore),
        Arc::new(PgLinkStore),
        secrets.clone(),
        clock.clone(),
    )
    .allowing_development_hosts(&development_hosts)
    .allowing_directory_hosts(&directory_hosts(config));
    let openid = OpenIdClient::new(
        http.clone(),
        Arc::new(AwsLcVerifier),
        digest.clone(),
        Arc::new(OsRandom),
        clock.clone(),
    )
    .allowing_development_hosts(&development_hosts);
    let github = GitHubClient::new(http.clone(), Arc::new(OsRandom));
    let sign_in = ExternalSignIn::new(
        federation,
        openid,
        github,
        SamlClient::new(Arc::new(OsRandom)),
        identity.clone(),
        Arc::new(PgPendingAuthorizationStore),
        units(),
        secrets,
        digest,
        clock,
        &config.public_url,
    )
    .with_directories(
        Arc::new(LdapDirectoryClient::new(&directory_hosts(config))),
        guard.clone(),
        Arc::new(TenantLockout(tenants.clone())),
    );
    Ok(Some(sign_in))
}

/// The rotation policy as far as the server uses it: the overlap of a
/// rotation by hand.
fn key_rotation(config: &Config) -> Result<RotationPolicy, DomainError> {
    let default = RotationPolicy::DEFAULT;
    RotationPolicy::new(
        default.period(),
        default.publication(),
        time::Duration::hours(config.key_overlap_hours),
    )
}

/// The keys context, when there are root keys to wrap the tenants' keys
/// with.
fn keys(config: &Config, database: &Database) -> Result<Option<KeyService>, DomainError> {
    let Some(setting) = &config.secret_keys else {
        return Ok(None);
    };
    let root = Arc::new(SecretKeys::parse(&Secret::from(setting.clone()))?);
    Ok(Some(KeyService::new(
        Arc::new(database.clone()),
        Arc::new(PgKeyStore),
        Arc::new(LocalKeyProvider::new(root)),
        Arc::new(SystemClock),
    )))
}

/// Where secrets at rest are sealed: under the tenant's data keys, with
/// the root keys of `HODOR_SECRET_KEYS` wrapping those keys and still
/// opening secrets of the first format until the tenant refuses them
/// (`docs/security/secrets-at-rest.md`).
fn secret_box(setting: &str, database: &Database) -> Result<Arc<dyn SecretBox>, DomainError> {
    let root = Arc::new(SecretKeys::parse(&Secret::from(setting.to_owned()))?);
    Ok(Arc::new(TenantSecretBox::new(
        Arc::new(database.clone()),
        Arc::new(PgKeyStore),
        Arc::new(LocalKeyProvider::new(root.clone())),
        Arc::new(PgSealingStateStore),
        Some(root),
        Arc::new(SystemClock),
    )))
}

/// Builds everything the administration interface needs.
fn administration(config: &Config, database: &Database) -> Result<AdminState, DomainError> {
    let units = || Arc::new(database.clone());
    let clock = Arc::new(SystemClock);
    let digest = Arc::new(Sha256Digest);
    let random = Arc::new(OsRandom);
    // Without keys to keep secrets with there are no identity providers
    // to manage; the routes say so.
    let federation = match &config.secret_keys {
        Some(setting) => Some(
            FederationService::new(
                units(),
                Arc::new(PgProviderStore),
                Arc::new(PgLinkStore),
                secret_box(setting, database)?,
                clock.clone(),
            )
            .allowing_development_hosts(&development_hosts(config))
            .allowing_directory_hosts(&directory_hosts(config)),
        ),
        None => None,
    };
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: units(),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        digest: digest.clone(),
        random: random.clone(),
        clock: clock.clone(),
    });
    Ok(AdminState {
        tokens: AccessTokenService::new(
            units(),
            Arc::new(PgAccessTokenStore),
            digest.clone(),
            random.clone(),
            clock.clone(),
        ),
        authorization: AuthorizationService::new(
            units(),
            Arc::new(PgRoleAssignmentStore),
            clock.clone(),
        ),
        identity: IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone()),
        sessions: SessionService::new(
            units(),
            Arc::new(PgSessionStore),
            digest.clone(),
            random,
            clock.clone(),
        ),
        // The server reads the audit log; the worker writes it.
        audit: AuditService::new(units(), Arc::new(PgAuditLog), digest, clock),
        federation,
        keys: keys(config, database)?,
        key_rotation: key_rotation(config)?,
        applications,
        public_url: config.public_url.clone(),
    })
}

async fn wait_for(mut stopped: watch::Receiver<bool>) {
    // An error means the sender is gone, which also means: stop.
    let _ = stopped.wait_for(|stop| *stop).await;
}

/// Resolves on SIGTERM (orchestrators) or Ctrl-C (terminals).
async fn stop_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = terminate.recv() => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
            }
            Err(error) => {
                tracing::warn!(%error, "cannot listen for SIGTERM, only Ctrl-C will stop the server");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
