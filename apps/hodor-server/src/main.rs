//! HTTP composition root: protocols, APIs and the console BFF.
//!
//! This is the only place that knows concrete adapter types. It reads the
//! configuration, builds the adapters, hands them to the HTTP layer as
//! trait objects and runs the listeners until asked to stop.

use clap::{Parser, ValueEnum};
use hodor_adapters_crypto::{
    Argon2Parameters, Argon2idHasher, AwsLcHmacSha1, AwsLcHmacSha256, AwsLcVerifier, HashingLimits,
    LocalKeyProvider, OsRandom, SecretKeys, Sha256Digest,
};
use hodor_adapters_http::{GuardedHttpClient, OutboundPolicy, ServiceHttpClient};
use hodor_adapters_ldap::LdapDirectoryClient;
use hodor_adapters_postgres::{
    Database, PgAccessListStore, PgAccessTokenRecordStore, PgAccessTokenStore, PgApiKeyStore,
    PgApplicationStore, PgAttemptStore, PgAuditLog, PgAuthorizationCodeStore,
    PgAuthorizationRequestStore, PgBundleStore, PgClaimMapperStore, PgClientAssertionStore,
    PgClientStore, PgConsentStore, PgDecisionLogStore, PgDeliveryStore, PgDeprovisioningPolicy,
    PgEmailSignInStore, PgEndpointStore, PgEngineBindingStore, PgGrantStore, PgGroupPolicy,
    PgGroupRepository, PgInstanceStatusStore, PgInstanceStore, PgInvitationRepository, PgKeyStore,
    PgLinkStore, PgMessageQueue, PgNativeRoleStore, PgOrganizationRepository,
    PgPairwiseSecretStore, PgPasswordStore, PgPendingAuthorizationStore, PgPolicyVersionStore,
    PgProviderStore, PgProvisionedGroupRepository, PgProvisionedUserRepository, PgPublicationStore,
    PgRecoveryCodeStore, PgRefreshTokenStore, PgResourceServerStore, PgRoleAssignmentStore,
    PgSealingStateStore, PgSessionStore, PgSimulationStore, PgTenantDirectory, PgTenantRepository,
    PgTotpStore, PgTransactionStore, PgTrustDomainStore, PgUploadedDecisionStore, PgUserRepository,
    PgVerificationTokenStore, PgWebAuthnStore, PgWorkloadRepository,
};
use hodor_audit::api::AuditService;
use hodor_authentication::api::{
    AccountService, AttemptGuard, AuthFlow, AuthenticationService, Condition, EmailAuthenticator,
    EmailSignInPorts, EnrollmentAuthenticator, FactorService, FlowEngine, IdentifierAuthenticator,
    InvitationContexts, InvitationService, LockoutRules, PasskeyAuthenticator,
    PasswordAuthenticator, RecoveryCodeAuthenticator, Requirement, TotpAuthenticator,
    WebAuthnAuthenticator,
};
use hodor_authorization::api::{
    AccessListService, AuthorizationService, DecisionLog, EngineRegistry, EvaluationService,
    NativeEngine, RoleService,
};
use hodor_authorization_native::CelConditionLanguage;
use hodor_authorization_opa::api::{
    BundleService, Instances, OpenPolicyAgentEngine, PolicyService, StoredRevisions,
};
use hodor_credential::api::{
    AccessTokenService, ApiKeyService, CredentialService, RecoveryCodeService, RelyingParty,
    TotpService, WebAuthnService,
};
use hodor_federation::api::{
    EXTERNAL_STEP, ExternalIdentityAuthenticator, ExternalSignIn, FederationService, GitHubClient,
    LockoutPolicy, OpenIdClient, SamlClient,
};
use hodor_identity::api::{GroupService, IdentityService, OrganizationService, WorkloadService};
use hodor_kernel::{DomainError, Secret, SecretBox, SystemClock, TenantContext};
use hodor_keys::api::{
    KeyService, RotationPolicy, TenantSecretBox, TrustDomainPorts, TrustDomainService,
};
use hodor_notification::api::Notifier;
use hodor_oauth::api::{
    AccessTokenRegister, ApplicationPorts, ApplicationService, AuthorizationCodePorts,
    AuthorizationCodeService, ClaimMapperPorts, ClaimMapperService, ClaimMapping, ConsentPorts,
    ConsentService, LogoutPorts, LogoutService, PairwisePorts, PairwiseSubjects,
    ResourceAccessPorts, ResourceAccessService, TokenPorts, TokenService, UserInfoPorts,
    UserInfoService, WorkloadTokens,
};
use hodor_observability::{LogFormat, Telemetry};
use hodor_protocol_http::{
    AdminState, ApiKeyAccess, AuthorizationApiState, AuthorizationState, ConsentState,
    ConsoleState, DiscoveryState, ForwardedHeader, Health, InteractionState, InvitationState,
    Limits, LogoutState, Pages, ReadinessCheck, ResolvedTenant, ScimState, TenantResolver,
    TenantStatus as HttpTenantStatus, TokenState, TrustedProxies, UserInfoState, admin_routes,
    authorization_api_routes, authorization_routes, consent_routes, console_routes,
    discovery_routes, interaction_routes, invitation_routes, key_set_routes, logout_routes,
    ops_router, parse_ranges, policy_agent_routes, public_router_behind, scim_routes, serve,
    token_routes, userinfo_routes,
};
use hodor_provisioning::api::{ProvisioningPorts, ProvisioningService};
use hodor_session::api::SessionService;
use hodor_tenant::api::{TenantDirectory as _, TenantService, TenantStatus};
use hodor_webhooks::api::WebhookService;
use standing::{ServerMemberships, ServerStanding};
use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;

mod deprovisioning;
mod standing;
mod subjects;

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

    /// How long a refresh token one generation old is answered again with
    /// the same next token, in seconds: 0 to 60. 0 turns retries off.
    #[arg(long, env = "HODOR_REFRESH_RETRY_SECONDS", default_value_t = 10)]
    refresh_retry_seconds: i64,

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

    /// How long after a tenant publishes a revision an instance may still
    /// answer with an older one, in seconds. After that its decisions are
    /// indeterminate.
    #[arg(
        long,
        env = "HODOR_OPEN_POLICY_AGENT_REVISION_LAG_SECONDS",
        default_value_t = 300
    )]
    open_policy_agent_revision_lag_seconds: u32,

    /// Address ranges of the load balancers and web servers whose
    /// forwarded header is read, such as `10.0.0.0/8,fd00::/8`. Empty: the
    /// client address is always the connection's.
    #[arg(long, env = "HODOR_TRUSTED_PROXIES", default_value = "")]
    trusted_proxies: String,

    /// The header trusted proxies write the client address into:
    /// `x-forwarded-for` or `forwarded`.
    #[arg(
        long,
        env = "HODOR_FORWARDED_HEADER",
        default_value = "x-forwarded-for"
    )]
    forwarded_header: String,

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
    // Checked first, so that a wrong range stops the server before anything
    // else is started.
    let proxies = trusted_proxies(&config)?;
    let database = Database::connect(
        &Secret::from(config.database_url.clone()),
        config.database_max_connections,
    )
    .await?;
    let health = Health::new(vec![Arc::new(DatabaseCheck(database.clone()))]);
    // Checked now, so that a wrong address stops the server at startup.
    // The Authorization API evaluates through these engines.
    let engines = authorization_engines(&config, &database)?;

    let keys = keys(&config, &database)?;
    let (interaction, invitations) = interaction(&config, &database)?;
    let authorization = authorization(&config, &database, interaction.authentication.clone());
    // SCIM ends a deprovisioned person's sessions and grants with these.
    let revoker = access_revoker(&database);
    let mut oauth2 = authorization_routes(authorization.clone());
    if let (Some(keys), Some(setting)) = (&keys, &config.secret_keys) {
        oauth2 = oauth2.merge(token_routes(token(
            &config,
            &database,
            keys.clone(),
            authorization.authorization,
            secret_box(setting, &database)?,
        )?));
        oauth2 = oauth2.merge(userinfo_routes(userinfo(&config, &database, keys.clone())));
        oauth2 = oauth2.merge(logout_routes(logout(
            &config,
            &database,
            keys.clone(),
            authorization.sessions.clone(),
            pairwise_subjects(&database, secret_box(setting, &database)?),
        )));
    }
    let mut tenant_routes = axum::Router::new()
        .nest(
            "/interaction",
            interaction_routes(interaction)
                .merge(consent_routes(ConsentState {
                    consents: authorization.consents.clone(),
                    sessions: authorization.sessions.clone(),
                    digest: Arc::new(Sha256Digest),
                }))
                .merge(invitation_routes(InvitationState {
                    invitations: invitations.clone(),
                    sessions: authorization.sessions.clone(),
                    digest: Arc::new(Sha256Digest),
                })),
        )
        .nest("/oauth2", oauth2)
        .nest(
            "/api/v1/admin",
            admin_routes(administration(
                &config,
                &database,
                &engines,
                invitations.clone(),
            )?),
        )
        .nest(
            "/console/api",
            console_routes(ConsoleState {
                administration: administration(&config, &database, &engines, invitations.clone())?,
                digest: Arc::new(Sha256Digest),
                clock: Arc::new(SystemClock),
            }),
        );
    match keys {
        Some(keys) => {
            tenant_routes = tenant_routes
                .nest(
                    "/api/v1/authorization",
                    authorization_api_routes(authorization_api(
                        &config,
                        &database,
                        keys.clone(),
                        engines,
                    )),
                )
                .nest(
                    "/scim/v2",
                    scim_routes(scim(&config, &database, keys.clone(), revoker)),
                )
                .merge(key_set_routes(keys))
                .merge(discovery_routes(DiscoveryState {
                    public_url: config.public_url.clone(),
                    tenants: tenant_service(&database),
                }));
        }
        None => tracing::warn!(
            "HODOR_SECRET_KEYS is not set: no key set is published, keys cannot be managed and \
             no token is issued"
        ),
    }
    // Open Policy Agent instances pull their bundles and report here,
    // each by its own credential.
    let mut site_routes = axum::Router::new().merge(policy_agent_routes(BundleService::new(
        Arc::new(PgInstanceStore::new(database.clone())),
        Arc::new(PgBundleStore),
        Arc::new(PgInstanceStatusStore),
        Arc::new(PgUploadedDecisionStore),
        Arc::new(database.clone()),
        Arc::new(Sha256Digest),
        Arc::new(OsRandom),
        Arc::new(SystemClock),
    )));
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
    let public = public_router_behind(
        Arc::new(DirectoryResolver(PgTenantDirectory::new(database.clone()))),
        tenant_routes,
        site_routes,
        Limits::default(),
        proxies,
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
/// The interaction use cases, and the invitations, which share their
/// password hasher.
fn interaction(
    config: &Config,
    database: &Database,
) -> Result<(InteractionState, InvitationService), DomainError> {
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
    let identity = IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone())
        .with_groups(Arc::new(PgGroupRepository))
        .with_organizations(Arc::new(PgOrganizationRepository));
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
    // A code or a link by email: two more alternatives, each offered only
    // where the tenant turned it on. The server queues the message; the
    // worker delivers it.
    let by_email = EmailSignInPorts {
        units_of_work: units(),
        sent: Arc::new(PgEmailSignInStore),
        identity: identity.clone(),
        tenants: tenants.clone(),
        notifier: Notifier::new(Arc::new(PgMessageQueue), clock.clone()),
        guard: guard.clone(),
        digest: digest.clone(),
        random: random.clone(),
        clock: clock.clone(),
        public_url: config.public_url.clone(),
    };
    engine = engine
        .with(Arc::new(EmailAuthenticator::code(by_email.clone())))
        .with(Arc::new(EmailAuthenticator::link(by_email)));
    // A person who registered a security key is asked for it after the
    // first factor, unless the sign-in is multi-factor already. A passkey
    // is an alternative of the flow, which is multi-factor by itself.
    // Signing in through an identity provider is another alternative, and
    // a code of an authenticator application one more step, both offered
    // only by an installation that can keep secrets. A recovery code
    // stands in for either second factor. The security key is also asked
    // for when an application asked a step-up for more than multi-factor:
    // it is the step that makes a sign-in phishing-resistant.
    let second_factor = Requirement::Conditional(Condition::MultiFactorNotReached);
    let stronger = Requirement::Conditional(Condition::StrongerAssuranceNeeded);
    let mut flow = AuthFlow::built_in()
        .with_step(
            WebAuthnAuthenticator::KIND,
            WebAuthnAuthenticator::KIND,
            stronger,
        )
        .with_substitute(WebAuthnAuthenticator::KIND, RecoveryCodeAuthenticator::KIND)
        .with_alternative(PasskeyAuthenticator::KIND, PasskeyAuthenticator::KIND)
        .with_alternative(EmailAuthenticator::CODE_KIND, EmailAuthenticator::CODE_KIND)
        .with_alternative(EmailAuthenticator::LINK_KIND, EmailAuthenticator::LINK_KIND);
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
    // A person whose tenant requires a second factor and who has none sets
    // one up at the last step, after the first factor, through the use
    // cases of their own pages. Never in a step-up, never for a person who
    // has a factor: they are asked for it by the steps before.
    let factors = factor_service(config, database, &identity, &tenants, webauthn)?;
    engine = engine.with(Arc::new(EnrollmentAuthenticator::new(
        factors.clone(),
        identity.clone(),
    )));
    flow = flow.with_step(
        EnrollmentAuthenticator::KIND,
        EnrollmentAuthenticator::KIND,
        Requirement::Conditional(Condition::AssuranceNotReached),
    );
    let external = external_sign_in(config, database, &identity, &tenants, &guard)?;
    if let Some(external) = &external {
        engine = engine.with(Arc::new(ExternalIdentityAuthenticator::new(
            external.clone(),
        )));
        flow = flow.with_alternative(EXTERNAL_STEP, EXTERNAL_STEP);
    }
    // The server only queues messages; the worker delivers them.
    let invitations = InvitationService::new(
        units(),
        InvitationContexts {
            organizations: OrganizationService::new(
                units(),
                Arc::new(PgOrganizationRepository),
                Arc::new(PgInvitationRepository),
                Arc::new(PgUserRepository),
                clock.clone(),
            ),
            identity: identity.clone(),
            credentials: credentials.clone(),
            tenants: tenants.clone(),
            notifier: Notifier::new(Arc::new(PgMessageQueue), clock.clone()),
        },
        digest.clone(),
        random.clone(),
        &config.public_url,
    );
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
    Ok((
        InteractionState {
            authentication,
            accounts,
            sessions,
            factors,
            external,
            digest,
            clock,
        },
        invitations,
    ))
}

/// The tenant use cases, for the settings other routes read.
fn tenant_service(database: &Database) -> TenantService {
    TenantService::new(
        Arc::new(database.clone()),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.clone())),
        Arc::new(SystemClock),
    )
}

/// Builds the use cases of consent.
fn consents(database: &Database) -> ConsentService {
    ConsentService::new(ConsentPorts {
        units_of_work: Arc::new(database.clone()),
        consents: Arc::new(PgConsentStore),
        requests: Arc::new(PgAuthorizationRequestStore),
        grants: Arc::new(PgGrantStore),
        clients: Arc::new(PgClientStore),
        applications: Arc::new(PgApplicationStore),
        resource_servers: Arc::new(PgResourceServerStore),
        digest: Arc::new(Sha256Digest),
        random: Arc::new(OsRandom),
        clock: Arc::new(SystemClock),
    })
}

/// Builds everything the authorization endpoint needs.
fn authorization(
    config: &Config,
    database: &Database,
    authentication: AuthenticationService,
) -> AuthorizationState {
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
            memberships: Arc::new(ServerMemberships::over(database, clock.clone())),
            codes: Arc::new(PgAuthorizationCodeStore),
            digest: digest.clone(),
            random: random.clone(),
            clock: clock.clone(),
        }),
        consents: consents(database),
        sessions: SessionService::new(units, Arc::new(PgSessionStore), digest, random, clock),
        authentication,
        tenants: tenant_service(database),
        public_url: config.public_url.clone(),
    }
}

/// Builds everything the token endpoint needs. Tokens are signed with the
/// tenants' keys, so there is no token endpoint without them; the secrets
/// of refresh token families are sealed with the same keys.
fn token(
    config: &Config,
    database: &Database,
    keys: KeyService,
    codes: AuthorizationCodeService,
    secrets: Arc<dyn SecretBox>,
) -> Result<TokenState, DomainError> {
    let units = Arc::new(database.clone());
    let clock = Arc::new(SystemClock);
    let digest = Arc::new(Sha256Digest);
    let random = Arc::new(OsRandom);
    let standing = standing(database);
    let pairwise = pairwise_subjects(database, secrets.clone());
    let tokens = TokenService::new(TokenPorts {
        units_of_work: units,
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        grants: Arc::new(PgGrantStore),
        assertions: Arc::new(PgClientAssertionStore),
        refresh_tokens: Arc::new(PgRefreshTokenStore),
        access_tokens: Arc::new(PgAccessTokenRecordStore),
        standing: Arc::new(standing),
        memberships: Arc::new(ServerMemberships::over(database, clock.clone())),
        mapping: claim_mapping(database, clock.clone()),
        secrets,
        codes,
        keys,
        verifier: Arc::new(AwsLcVerifier),
        digest,
        random,
        clock,
    })
    .with_retry_window(time::Duration::seconds(config.refresh_retry_seconds))?
    .with_pairwise_subjects(pairwise);
    Ok(TokenState {
        tokens,
        public_url: config.public_url.clone(),
    })
}

/// Names people to pairwise clients, with the tenants' pairwise secrets
/// sealed by `secrets`.
fn pairwise_subjects(database: &Database, secrets: Arc<dyn SecretBox>) -> PairwiseSubjects {
    PairwiseSubjects::new(PairwisePorts {
        units_of_work: Arc::new(database.clone()),
        secrets: Arc::new(PgPairwiseSecretStore),
        secret_box: secrets,
        mac: Arc::new(AwsLcHmacSha256),
        random: Arc::new(OsRandom),
        clock: Arc::new(SystemClock),
    })
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
            )
            .with_groups(Arc::new(PgGroupRepository))
            .with_organizations(Arc::new(PgOrganizationRepository)),
            register: AccessTokenRegister::new(
                Arc::new(database.clone()),
                Arc::new(PgAccessTokenRecordStore),
                Arc::new(PgGrantStore),
                Arc::new(PgRefreshTokenStore),
                Arc::new(standing(database)),
            ),
            memberships: Arc::new(ServerMemberships::over(database, clock.clone())),
            mapping: claim_mapping(database, clock.clone()),
            clock,
        }),
        public_url: config.public_url.clone(),
    }
}

/// What the claim mappers of clients add to tokens and to UserInfo, read
/// from the identity context.
fn claim_mapping(database: &Database, clock: Arc<SystemClock>) -> ClaimMapping {
    ClaimMapping::new(
        Arc::new(database.clone()),
        Arc::new(PgClaimMapperStore),
        Arc::new(ServerMemberships::over(database, clock.clone())),
        Arc::new(standing::ServerClaimSources::over(database, clock)),
    )
}

/// Builds everything the Authorization API needs. It checks access tokens
/// against the tenants' keys, so there is no Authorization API without
/// them.
fn authorization_api(
    config: &Config,
    database: &Database,
    keys: KeyService,
    engines: EngineRegistry,
) -> AuthorizationApiState {
    let clock = Arc::new(SystemClock);
    let units = || -> Arc<dyn hodor_kernel::UnitOfWorkFactory> { Arc::new(database.clone()) };
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: units(),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        digest: Arc::new(Sha256Digest),
        random: Arc::new(OsRandom),
        clock: clock.clone(),
    });
    AuthorizationApiState {
        access: resource_access(database, keys, applications.clone()),
        keys: ApiKeyAccess {
            keys: api_keys(database),
            identity: IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone()),
            applications: applications.clone(),
        },
        evaluation: EvaluationService::new(
            units(),
            Arc::new(PgRoleAssignmentStore),
            Arc::new(PgEngineBindingStore),
            Arc::new(subjects::ServerSubjects {
                units_of_work: units(),
                identity: IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone())
                    .with_groups(Arc::new(PgGroupRepository))
                    .with_organizations(Arc::new(PgOrganizationRepository)),
                applications,
                groups: GroupService::new(
                    units(),
                    Arc::new(PgGroupRepository),
                    Arc::new(PgUserRepository),
                    Arc::new(PgGroupPolicy),
                    clock.clone(),
                ),
                organizations: OrganizationService::new(
                    units(),
                    Arc::new(PgOrganizationRepository),
                    Arc::new(PgInvitationRepository),
                    Arc::new(PgUserRepository),
                    clock.clone(),
                ),
            }),
            engines,
            clock,
        )
        .with_decision_log(decision_log(database)),
        public_url: config.public_url.clone(),
    }
}

/// Checks the access tokens presented to Hodor's own resource servers, the
/// Authorization API and the SCIM server, against the tenants' keys and
/// the register of access tokens.
fn resource_access(
    database: &Database,
    keys: KeyService,
    applications: ApplicationService,
) -> ResourceAccessService {
    let units = || -> Arc<dyn hodor_kernel::UnitOfWorkFactory> { Arc::new(database.clone()) };
    ResourceAccessService::new(ResourceAccessPorts {
        keys,
        verifier: Arc::new(AwsLcVerifier),
        register: AccessTokenRegister::new(
            units(),
            Arc::new(PgAccessTokenRecordStore),
            Arc::new(PgGrantStore),
            Arc::new(PgRefreshTokenStore),
            Arc::new(standing(database)),
        ),
        applications,
        clock: Arc::new(SystemClock),
    })
}

/// Builds everything the SCIM server needs. Like the Authorization API, it
/// checks access tokens against the tenants' keys.
fn scim(
    config: &Config,
    database: &Database,
    keys: KeyService,
    revoker: deprovisioning::ServerAccessRevoker,
) -> ScimState {
    let clock = Arc::new(SystemClock);
    let units = || -> Arc<dyn hodor_kernel::UnitOfWorkFactory> { Arc::new(database.clone()) };
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: units(),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        digest: Arc::new(Sha256Digest),
        random: Arc::new(OsRandom),
        clock: clock.clone(),
    });
    ScimState {
        access: resource_access(database, keys, applications),
        provisioning: ProvisioningService::new(ProvisioningPorts {
            units_of_work: units(),
            identity: IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone())
                .with_groups(Arc::new(PgGroupRepository))
                .with_organizations(Arc::new(PgOrganizationRepository)),
            groups: GroupService::new(
                units(),
                Arc::new(PgGroupRepository),
                Arc::new(PgUserRepository),
                Arc::new(PgGroupPolicy),
                clock.clone(),
            ),
            users: Arc::new(PgProvisionedUserRepository),
            provisioned_groups: Arc::new(PgProvisionedGroupRepository),
            deprovisioning: Arc::new(PgDeprovisioningPolicy),
            access: Arc::new(revoker),
            clock,
        }),
        public_url: config.public_url.clone(),
    }
}

/// The record of decisions, written by the Authorization API and read by
/// the administration interface.
fn decision_log(database: &Database) -> DecisionLog {
    DecisionLog::new(
        Arc::new(database.clone()),
        Arc::new(PgDecisionLogStore),
        Arc::new(OsRandom),
        Arc::new(SystemClock),
    )
}

/// Builds everything the end-session endpoint needs. A hint is checked
/// against the tenant's keys, so there is no end-session endpoint without
/// them, as there is no ID token.
fn logout(
    config: &Config,
    database: &Database,
    keys: KeyService,
    sessions: SessionService,
    pairwise: PairwiseSubjects,
) -> LogoutState {
    LogoutState {
        logout: LogoutService::new(LogoutPorts {
            units_of_work: Arc::new(database.clone()),
            applications: Arc::new(PgApplicationStore),
            clients: Arc::new(PgClientStore),
            keys,
            verifier: Arc::new(AwsLcVerifier),
        })
        .with_pairwise_subjects(pairwise),
        sessions,
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
    let engine = engine.with_revisions(
        Arc::new(StoredRevisions::new(
            Arc::new(database.clone()),
            Arc::new(PgBundleStore),
            Arc::new(SystemClock),
        )),
        time::Duration::seconds(i64::from(config.open_policy_agent_revision_lag_seconds)),
    );
    let mut registry = EngineRegistry::new();
    let native = Arc::new(
        NativeEngine::new(
            Arc::new(database.clone()),
            Arc::new(PgRoleAssignmentStore),
            Arc::new(PgNativeRoleStore),
            Arc::new(SystemClock),
        )
        .with_condition_language(Arc::new(CelConditionLanguage::new()))
        .with_access_lists(Arc::new(PgAccessListStore)),
    );
    registry.register_with_simulator(native.clone(), native)?;
    registry.register(Arc::new(engine))?;
    Ok(registry)
}

/// The directories that may be connected to: empty unless set.
/// The proxies whose forwarded header is read. A range that cannot be read,
/// or one that holds every address, stops the server from starting.
fn trusted_proxies(config: &Config) -> Result<TrustedProxies, Box<dyn Error>> {
    let ranges = parse_ranges(&config.trusted_proxies)
        .map_err(|invalid| format!("HODOR_TRUSTED_PROXIES: {invalid}"))?;
    let header: ForwardedHeader = config
        .forwarded_header
        .parse()
        .map_err(|invalid| format!("HODOR_FORWARDED_HEADER: {invalid}"))?;
    if ranges.is_empty() {
        tracing::info!("no proxy is trusted: the client address is the connection's");
    } else {
        let named: Vec<String> = ranges.iter().map(ToString::to_string).collect();
        tracing::info!(
            ranges = %named.join(","),
            header = %config.forwarded_header.to_ascii_lowercase(),
            "the client address is read from the forwarded header of trusted proxies"
        );
    }
    Ok(TrustedProxies::new(ranges, header))
}

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

/// People's own factors, with authenticator applications when the
/// installation can keep secrets.
fn factor_service(
    config: &Config,
    database: &Database,
    identity: &IdentityService,
    tenants: &TenantService,
    webauthn: WebAuthnService,
) -> Result<FactorService, DomainError> {
    let factors = FactorService::new(
        identity.clone(),
        tenants.clone(),
        webauthn,
        RecoveryCodeService::new(
            Arc::new(database.clone()),
            Arc::new(PgRecoveryCodeStore),
            Arc::new(Sha256Digest),
            Arc::new(OsRandom),
            Arc::new(SystemClock),
        ),
    );
    Ok(match totp_service(config, database, Arc::new(OsRandom))? {
        Some(totp) => factors.with_totp(totp),
        None => factors,
    })
}

/// What the OAuth context asks of a person or a workload, over the session
/// and identity contexts.
fn standing(database: &Database) -> ServerStanding {
    let units = || Arc::new(database.clone());
    let clock = Arc::new(SystemClock);
    ServerStanding {
        sessions: SessionService::new(
            units(),
            Arc::new(PgSessionStore),
            Arc::new(Sha256Digest),
            Arc::new(OsRandom),
            clock.clone(),
        ),
        identity: IdentityService::new(units(), Arc::new(PgUserRepository), clock)
            .with_groups(Arc::new(PgGroupRepository))
            .with_organizations(Arc::new(PgOrganizationRepository)),
    }
}

/// Ends a deprovisioned person's access, and a disabled or deleted
/// workload's, in the asking context's unit of work.
fn access_revoker(database: &Database) -> deprovisioning::ServerAccessRevoker {
    let units = || Arc::new(database.clone());
    let clock = Arc::new(SystemClock);
    deprovisioning::ServerAccessRevoker {
        sessions: SessionService::new(
            units(),
            Arc::new(PgSessionStore),
            Arc::new(Sha256Digest),
            Arc::new(OsRandom),
            clock.clone(),
        ),
        grants: AuthorizationCodeService::new(AuthorizationCodePorts {
            units_of_work: units(),
            applications: Arc::new(PgApplicationStore),
            clients: Arc::new(PgClientStore),
            resource_servers: Arc::new(PgResourceServerStore),
            requests: Arc::new(PgAuthorizationRequestStore),
            grants: Arc::new(PgGrantStore),
            codes: Arc::new(PgAuthorizationCodeStore),
            memberships: Arc::new(ServerMemberships::over(database, clock.clone())),
            digest: Arc::new(Sha256Digest),
            random: Arc::new(OsRandom),
            clock: clock.clone(),
        }),
        tokens: WorkloadTokens::new(Arc::new(PgAccessTokenRecordStore), clock),
        keys: api_keys(database),
    }
}

/// The API keys of service accounts and agents.
fn api_keys(database: &Database) -> ApiKeyService {
    ApiKeyService::new(
        Arc::new(database.clone()),
        Arc::new(PgApiKeyStore),
        Arc::new(Sha256Digest),
        Arc::new(OsRandom),
        Arc::new(SystemClock),
    )
}

/// Builds everything the administration interface needs.
fn administration(
    config: &Config,
    database: &Database,
    engines: &EngineRegistry,
    invitations: InvitationService,
) -> Result<AdminState, DomainError> {
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
    })
    // Back-channel logout addresses are checked as webhook endpoints are,
    // and sector identifier addresses checked and fetched, with this
    // installation's development exception.
    .with_destinations(Arc::new(GuardedHttpClient::new(OutboundPolicy {
        development_hosts: development_hosts(config),
        ..OutboundPolicy::default()
    })?))
    .with_sector_documents(Arc::new(GuardedHttpClient::new(OutboundPolicy {
        development_hosts: development_hosts(config),
        ..OutboundPolicy::default()
    })?));
    let applications_for_subjects = applications.clone();
    Ok(AdminState {
        claim_mappers: ClaimMapperService::new(ClaimMapperPorts {
            units_of_work: units(),
            clients: Arc::new(PgClientStore),
            mappers: Arc::new(PgClaimMapperStore),
            clock: clock.clone(),
        }),
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
        identity: IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone())
            .with_groups(Arc::new(PgGroupRepository))
            .with_organizations(Arc::new(PgOrganizationRepository)),
        workloads: WorkloadService::new(
            units(),
            IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone())
                .with_groups(Arc::new(PgGroupRepository))
                .with_organizations(Arc::new(PgOrganizationRepository)),
            Arc::new(PgWorkloadRepository),
            Arc::new(access_revoker(database)),
            clock.clone(),
        ),
        api_keys: api_keys(database),
        sessions: SessionService::new(
            units(),
            Arc::new(PgSessionStore),
            digest.clone(),
            random,
            clock.clone(),
        ),
        // The server reads the audit log; the worker writes it.
        audit: AuditService::new(units(), Arc::new(PgAuditLog), digest, clock.clone()),
        federation,
        keys: keys(config, database)?,
        key_rotation: key_rotation(config)?,
        trust_domains: trust_domains(config, database)?,
        applications,
        tenants: tenant_service(database),
        factors: {
            let identity = IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone())
                .with_groups(Arc::new(PgGroupRepository))
                .with_organizations(Arc::new(PgOrganizationRepository));
            let tenants = TenantService::new(
                units(),
                Arc::new(PgTenantRepository),
                Arc::new(PgTenantDirectory::new(database.clone())),
                clock.clone(),
            );
            let webauthn = WebAuthnService::new(
                units(),
                Arc::new(PgWebAuthnStore),
                RelyingParty::from_public_address(&config.public_url)?,
                Arc::new(Sha256Digest),
                Arc::new(AwsLcVerifier),
                Arc::new(OsRandom),
                Arc::new(SystemClock),
            );
            factor_service(config, database, &identity, &tenants, webauthn)?
        },
        consents: consents(database),
        decisions: decision_log(database),
        roles: RoleService::new(units(), Arc::new(PgNativeRoleStore), clock.clone())
            .with_condition_language(Arc::new(CelConditionLanguage::new())),
        access_lists: AccessListService::new(
            units(),
            Arc::new(PgAccessListStore),
            Arc::new(PgNativeRoleStore),
            clock.clone(),
        ),
        evaluation: EvaluationService::new(
            units(),
            Arc::new(PgRoleAssignmentStore),
            Arc::new(PgEngineBindingStore),
            Arc::new(subjects::ServerSubjects {
                units_of_work: units(),
                identity: IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone())
                    .with_groups(Arc::new(PgGroupRepository))
                    .with_organizations(Arc::new(PgOrganizationRepository)),
                applications: applications_for_subjects,
                groups: GroupService::new(
                    units(),
                    Arc::new(PgGroupRepository),
                    Arc::new(PgUserRepository),
                    Arc::new(PgGroupPolicy),
                    clock.clone(),
                ),
                organizations: OrganizationService::new(
                    units(),
                    Arc::new(PgOrganizationRepository),
                    Arc::new(PgInvitationRepository),
                    Arc::new(PgUserRepository),
                    clock.clone(),
                ),
            }),
            engines.clone(),
            clock.clone(),
        ),
        policies: Some(PolicyService::new(
            Arc::new(PgPolicyVersionStore),
            Arc::new(PgPublicationStore),
            Arc::new(PgSimulationStore),
            BundleService::new(
                Arc::new(PgInstanceStore::new(database.clone())),
                Arc::new(PgBundleStore),
                Arc::new(PgInstanceStatusStore),
                Arc::new(PgUploadedDecisionStore),
                Arc::new(database.clone()),
                Arc::new(Sha256Digest),
                Arc::new(OsRandom),
                Arc::new(SystemClock),
            ),
            Arc::new(database.clone()),
            Arc::new(Sha256Digest),
            Arc::new(SystemClock),
        )),
        public_url: config.public_url.clone(),
        groups: GroupService::new(
            units(),
            Arc::new(PgGroupRepository),
            Arc::new(PgUserRepository),
            Arc::new(PgGroupPolicy),
            clock.clone(),
        ),
        organizations: OrganizationService::new(
            units(),
            Arc::new(PgOrganizationRepository),
            Arc::new(PgInvitationRepository),
            Arc::new(PgUserRepository),
            clock.clone(),
        ),
        invitations,
        webhooks: webhooks(config, database)?,
    })
}

/// The trust domains an administrator manages. Bundle endpoints are checked
/// and fetched by the guarded outbound client, with the development
/// exception of this installation; nothing of a bundle is secret, so no
/// keys are needed.
fn trust_domains(config: &Config, database: &Database) -> Result<TrustDomainService, DomainError> {
    let guarded = || {
        GuardedHttpClient::new(OutboundPolicy {
            development_hosts: development_hosts(config),
            max_response_bytes: hodor_keys::api::MAX_BUNDLE_BYTES + 1,
            ..OutboundPolicy::default()
        })
    };
    Ok(TrustDomainService::new(TrustDomainPorts {
        units_of_work: Arc::new(database.clone()),
        store: Arc::new(PgTrustDomainStore),
        destinations: Arc::new(guarded()?),
        http: Arc::new(guarded()?),
        digest: Arc::new(Sha256Digest),
        clock: Arc::new(SystemClock),
    }))
}

/// The webhooks an administrator manages, when there are keys to seal
/// their secrets with. Addresses are checked by the guarded outbound
/// client, with the development exception of this installation.
fn webhooks(config: &Config, database: &Database) -> Result<Option<WebhookService>, DomainError> {
    let Some(setting) = &config.secret_keys else {
        return Ok(None);
    };
    let destinations = GuardedHttpClient::new(OutboundPolicy {
        development_hosts: development_hosts(config),
        ..OutboundPolicy::default()
    })?;
    Ok(Some(WebhookService::new(
        Arc::new(database.clone()),
        Arc::new(PgEndpointStore),
        Arc::new(PgDeliveryStore),
        secret_box(setting, database)?,
        Arc::new(destinations),
        Arc::new(OsRandom),
        Arc::new(SystemClock),
    )))
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
