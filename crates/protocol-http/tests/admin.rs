//! The administration interface, exercised over HTTP against the real
//! contexts running on their in-memory ports.
//!
//! The refusals are generated from the OpenAPI document: every operation
//! it lists is tried without a token, with tokens that are not good, with
//! a role that lacks the permission and with another tenant's token.

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use hodor_audit::api::{AuditHandler, AuditService};
use hodor_audit::testing::InMemoryAuditLog;
use hodor_authorization::api::{AuthorizationService, Permission, Role};
use hodor_authorization::testing::InMemoryRoleAssignments;
use hodor_credential::api::AccessTokenService;
use hodor_credential::testing::InMemoryAccessTokens;
use hodor_federation::api::FederationService;
use hodor_federation::testing::InMemoryFederation;
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_identity::testing::InMemoryUsers;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::sealing::testing::FakeSecretBox;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, DomainError, EventHandler, TenantContext, Timestamp, UnitOfWorkFactory, UserId,
};
use hodor_keys::api::{KeyService, RotationPolicy};
use hodor_keys::testing::{FakeKeyProvider, InMemoryKeys};
use hodor_protocol_http::{
    ADMIN_OPENAPI, ADMIN_OPERATIONS, AdminState, Limits, ResolvedTenant, TenantResolver,
    TenantStatus, admin_routes, public_router,
};
use hodor_session::api::{
    Assurance, ClientInfo, SessionService, SessionTimeouts, SessionToken, StartSession,
};
use hodor_session::testing::{InMemorySessions, SequentialRandom};
use hodor_tenant::api::{CreateTenant, TenantService};
use hodor_tenant::testing::InMemoryTenants;
use http_body_util::BodyExt as _;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use time::Duration;
use tower::ServiceExt as _;

struct Tenants {
    acme: TenantContext,
    globex: TenantContext,
}

#[async_trait::async_trait]
impl TenantResolver for Tenants {
    async fn resolve(&self, slug: &str) -> Result<Option<ResolvedTenant>, DomainError> {
        let context = match slug {
            "acme" => self.acme.clone(),
            "globex" => self.globex.clone(),
            _ => return Ok(None),
        };
        Ok(Some(ResolvedTenant {
            context,
            status: TenantStatus::Active,
        }))
    }
}

struct World {
    router: Router,
    clock: Arc<FixedClock>,
    units_of_work: InMemoryUnitOfWorkFactory,
    identity: IdentityService,
    tokens: AccessTokenService,
    authorization: AuthorizationService,
    sessions: SessionService,
    consents: hodor_oauth::api::ConsentService,
    audit: AuditHandler,
    recorded: AtomicUsize,
    acme: TenantContext,
    globex: TenantContext,
    /// The tenants, for changing their policy.
    tenants: hodor_tenant::api::TenantService,
    /// People's keys, given as a finished registration would.
    keys_of_people: hodor_credential::testing::InMemoryWebAuthn,
    /// People's authenticator applications.
    totp: hodor_credential::api::TotpService,
    /// The record of decisions.
    decisions: hodor_authorization::testing::InMemoryDecisionLog,
    /// The webhooks of every tenant, and the outbound client their
    /// deliveries go through.
    webhooks: hodor_webhooks::testing::InMemoryWebhooks,
    endpoints: hodor_webhooks::testing::RecordingEndpoints,
    /// How many committed events were handed to the webhooks fan-out.
    fanned_out: AtomicUsize,
    /// The bundle endpoints trust domains are fetched from.
    bundle_endpoints: hodor_keys::testing::FakeBundleEndpoints,
    /// The administrator of Acme and their token.
    administrator: UserId,
    administrator_token: String,
}

/// The applications use cases on in-memory stores.
fn applications(
    units_of_work: &InMemoryUnitOfWorkFactory,
    clock: Arc<FixedClock>,
) -> (
    hodor_oauth::api::ApplicationService,
    hodor_oauth::api::ConsentService,
    hodor_oauth::api::ClaimMapperService,
) {
    let stores = hodor_oauth::testing::InMemoryStores::default();
    let claim_mappers =
        hodor_oauth::api::ClaimMapperService::new(hodor_oauth::api::ClaimMapperPorts {
            units_of_work: Arc::new(units_of_work.clone()),
            clients: Arc::new(stores.clients.clone()),
            mappers: Arc::new(hodor_oauth::testing::InMemoryClaimMappers::new(
                &stores.clients,
            )),
            clock: clock.clone(),
        });
    let consents = hodor_oauth::testing::consent_service(
        Arc::new(units_of_work.clone()),
        &stores,
        clock.clone(),
    );
    let applications =
        hodor_oauth::api::ApplicationService::new(hodor_oauth::api::ApplicationPorts {
            units_of_work: Arc::new(units_of_work.clone()),
            applications: Arc::new(stores.applications),
            clients: Arc::new(stores.clients),
            resource_servers: Arc::new(stores.resource_servers),
            digest: Arc::new(FakeDigest),
            random: Arc::new(hodor_oauth::testing::DistinctRandom),
            clock,
        })
        .with_destinations(Arc::new(hodor_oauth::testing::FakeDestinations))
        .with_sector_documents(Arc::new(sector_documents()));
    (applications, consents, claim_mappers)
}

/// The use cases of roles, bindings and policy versions on in-memory
/// stores, with the native engine registered.
fn authorization_services(
    units_of_work: &InMemoryUnitOfWorkFactory,
    clock: Arc<FixedClock>,
) -> (
    hodor_authorization::api::RoleService,
    hodor_authorization::api::EvaluationService,
    hodor_authorization_opa::api::PolicyService,
    hodor_authorization::api::AccessListService,
) {
    use hodor_authorization::testing::{
        InMemoryEngineBindings, InMemoryNativeRoles, StaticSubjectAttributes,
    };
    use hodor_authorization_opa::testing::{
        InMemoryBundles, InMemoryInstances, InMemoryPolicyVersions, InMemoryPublications,
        InMemorySimulations, InMemoryStatuses, InMemoryUploadedDecisions,
    };
    let units = || -> Arc<dyn hodor_kernel::UnitOfWorkFactory> { Arc::new(units_of_work.clone()) };
    let assignments = hodor_authorization::testing::InMemoryRoleAssignments::default();
    let roles = InMemoryNativeRoles::default();
    let engine = hodor_authorization::api::NativeEngine::new(
        units(),
        Arc::new(assignments.clone()),
        Arc::new(roles.clone()),
        clock.clone(),
    )
    .with_access_lists(Arc::new(roles.clone()));
    let mut registry = hodor_authorization::api::EngineRegistry::new();
    registry.register(Arc::new(engine)).expect("register");
    let evaluation = hodor_authorization::api::EvaluationService::new(
        units(),
        Arc::new(assignments),
        Arc::new(InMemoryEngineBindings::default()),
        Arc::new(StaticSubjectAttributes::default()),
        registry,
        clock.clone(),
    );
    let bundles = hodor_authorization_opa::api::BundleService::new(
        Arc::new(InMemoryInstances::default()),
        Arc::new(InMemoryBundles::default()),
        Arc::new(InMemoryStatuses::default()),
        Arc::new(InMemoryUploadedDecisions::default()),
        units(),
        Arc::new(hodor_adapters_crypto::Sha256Digest),
        Arc::new(SequentialRandom::default()),
        clock.clone(),
    );
    let policies = hodor_authorization_opa::api::PolicyService::new(
        Arc::new(InMemoryPolicyVersions::default()),
        Arc::new(InMemoryPublications::default()),
        Arc::new(InMemorySimulations::default()),
        bundles,
        units(),
        Arc::new(hodor_adapters_crypto::Sha256Digest),
        clock.clone(),
    );
    (
        hodor_authorization::api::RoleService::new(units(), Arc::new(roles.clone()), clock.clone()),
        evaluation,
        policies,
        hodor_authorization::api::AccessListService::new(
            units(),
            Arc::new(roles.clone()),
            Arc::new(roles),
            clock,
        ),
    )
}

/// The use cases of people's factors on in-memory stores, with
/// authenticator applications. Returns the key store too, for a test to
/// give someone a key as a finished registration would.
fn factors(
    units_of_work: &InMemoryUnitOfWorkFactory,
    clock: Arc<FixedClock>,
    identity: &IdentityService,
    tenants: &hodor_tenant::api::TenantService,
) -> (
    hodor_authentication::api::FactorService,
    hodor_credential::testing::InMemoryWebAuthn,
    hodor_credential::api::TotpService,
) {
    let units = || Arc::new(units_of_work.clone());
    let keys = hodor_credential::testing::InMemoryWebAuthn::default();
    let webauthn = hodor_credential::api::WebAuthnService::new(
        units(),
        Arc::new(keys.clone()),
        hodor_credential::api::RelyingParty::from_public_address("https://auth.example")
            .expect("valid"),
        Arc::new(hodor_adapters_crypto::Sha256Digest),
        Arc::new(hodor_adapters_crypto::AwsLcVerifier),
        Arc::new(hodor_adapters_crypto::OsRandom),
        clock.clone(),
    );
    let recovery_codes = hodor_credential::api::RecoveryCodeService::new(
        units(),
        Arc::new(hodor_credential::testing::InMemoryRecoveryCodes::default()),
        Arc::new(hodor_adapters_crypto::Sha256Digest),
        Arc::new(hodor_adapters_crypto::OsRandom),
        clock.clone(),
    );
    let totp = hodor_credential::api::TotpService::new(
        units(),
        Arc::new(hodor_credential::testing::InMemoryTotps::default()),
        Arc::new(FakeSecretBox),
        Arc::new(hodor_credential::testing::FakeHmacSha1),
        Arc::new(hodor_adapters_crypto::OsRandom),
        clock,
    );
    let service = hodor_authentication::api::FactorService::new(
        identity.clone(),
        tenants.clone(),
        webauthn,
        recovery_codes,
    )
    .with_totp(totp.clone());
    (service, keys, totp)
}

async fn world() -> World {
    world_with_keys(true).await
}

async fn world_with_keys(with_keys: bool) -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let clock = Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH));
    let digest = Arc::new(FakeDigest);
    let units = || Arc::new(units_of_work.clone());

    let users = Arc::new(InMemoryUsers::default());
    let identity = IdentityService::new(units(), users.clone(), clock.clone());
    let tokens = AccessTokenService::new(
        units(),
        Arc::new(InMemoryAccessTokens::default()),
        digest.clone(),
        Arc::new(SequentialRandom::default()),
        clock.clone(),
    );
    let authorization = AuthorizationService::new(
        units(),
        Arc::new(InMemoryRoleAssignments::default()),
        clock.clone(),
    );
    let sessions = SessionService::new(
        units(),
        Arc::new(InMemorySessions::default()),
        digest.clone(),
        Arc::new(SequentialRandom::default()),
        clock.clone(),
    );
    let audit = AuditService::new(
        units(),
        Arc::new(InMemoryAuditLog::default()),
        digest,
        clock.clone(),
    );

    let providers = InMemoryFederation::default();
    let federation = FederationService::new(
        units(),
        Arc::new(providers.clone()),
        Arc::new(providers),
        Arc::new(FakeSecretBox),
        clock.clone(),
    )
    .allowing_directory_hosts(&["ldap.example.com:636".to_owned()]);

    let keys = with_keys.then(|| {
        KeyService::new(
            units(),
            Arc::new(InMemoryKeys::default()),
            Arc::new(FakeKeyProvider),
            clock.clone(),
        )
    });

    let tenant_rows = InMemoryTenants::default();
    let tenants = TenantService::new(
        units(),
        Arc::new(tenant_rows.clone()),
        Arc::new(tenant_rows),
        clock.clone(),
    );
    let mut contexts = Vec::new();
    for slug in ["acme", "globex"] {
        let created = tenants
            .create(
                CreateTenant {
                    slug: slug.to_owned(),
                    display_name: slug.to_uppercase(),
                    open_registration: false,
                    system: false,
                },
                Caller::system(),
            )
            .await
            .expect("tenant");
        contexts.push(TenantContext::assume(created.id()));
    }
    let (acme, globex) = (contexts[0].clone(), contexts[1].clone());
    let (factor_service, keys_of_people, totp) =
        factors(&units_of_work, clock.clone(), &identity, &tenants);
    let oauth = applications(&units_of_work, clock.clone());
    let decision_store = hodor_authorization::testing::InMemoryDecisionLog::default();
    let authorization_parts = authorization_services(&units_of_work, clock.clone());
    let groups_and_organizations = memberships(
        &units_of_work,
        clock.clone(),
        users.clone(),
        &identity,
        &tenants,
    );
    let webhook_rows = hodor_webhooks::testing::InMemoryWebhooks::default();
    let webhooks = with_keys.then(|| {
        hodor_webhooks::api::WebhookService::new(
            units(),
            Arc::new(webhook_rows.clone()),
            Arc::new(webhook_rows.clone()),
            Arc::new(FakeSecretBox),
            Arc::new(hodor_webhooks::testing::FakeDestinations),
            Arc::new(SequentialRandom::default()),
            clock.clone(),
        )
    });
    let bundle_endpoints = hodor_keys::testing::FakeBundleEndpoints::default();
    let trust_domain_rows = hodor_keys::testing::InMemoryTrustDomains::default();
    // The certificate authority is on, for development, wherever the
    // installation has keys: its key is made by the local provider.
    let authority = with_keys.then(|| {
        let root = hodor_adapters_crypto::SecretKeys::generate(&hodor_adapters_crypto::OsRandom);
        let root = hodor_adapters_crypto::SecretKeys::parse(&hodor_kernel::Secret::new(format!(
            "root:{}",
            root.expose()
        )))
        .expect("root keys");
        let provider = Arc::new(hodor_adapters_crypto::LocalKeyProvider::new(Arc::new(root)));
        hodor_keys::api::AuthorityService::new(
            hodor_keys::api::AuthorityPorts {
                units_of_work: units(),
                store: Arc::new(hodor_keys::testing::InMemoryAuthorities::default()),
                trust_domains: Arc::new(trust_domain_rows.clone()),
                maker: provider.clone(),
                signer: provider,
                certificates: Arc::new(hodor_adapters_crypto::X509Certificates),
                digest: Arc::new(FakeDigest),
                clock: clock.clone(),
            },
            true,
        )
    });
    let trust_domains =
        hodor_keys::api::TrustDomainService::new(hodor_keys::api::TrustDomainPorts {
            units_of_work: units(),
            store: Arc::new(trust_domain_rows),
            destinations: Arc::new(bundle_endpoints.clone()),
            http: Arc::new(bundle_endpoints.clone()),
            digest: Arc::new(FakeDigest),
            clock: clock.clone(),
        });
    let state = AdminState {
        tokens: tokens.clone(),
        authorization: authorization.clone(),
        identity: identity.clone(),
        sessions: sessions.clone(),
        audit: audit.clone(),
        federation: Some(federation),
        keys,
        key_rotation: RotationPolicy::DEFAULT,
        trust_domains,
        authority,
        applications: oauth.0,
        claim_mappers: oauth.2.clone(),
        consents: oauth.1.clone(),
        tenants: tenants.clone(),
        factors: factor_service,
        decisions: hodor_authorization::api::DecisionLog::new(
            units(),
            Arc::new(decision_store.clone()),
            Arc::new(SequentialRandom::default()),
            clock.clone(),
        ),
        roles: authorization_parts.0,
        access_lists: authorization_parts.3,
        evaluation: authorization_parts.1,
        policies: Some(authorization_parts.2),
        public_url: "https://auth.example".to_owned(),
        groups: groups_and_organizations.0,
        organizations: groups_and_organizations.1,
        invitations: groups_and_organizations.2,
        workloads: hodor_identity::api::WorkloadService::new(
            units(),
            identity.clone(),
            Arc::new(hodor_identity::testing::InMemoryWorkloads::over(
                (*users).clone(),
            )),
            Arc::new(hodor_identity::testing::RecordingWorkloadAccess::default()),
            clock.clone(),
        ),
        webhooks,
        api_keys: hodor_credential::api::ApiKeyService::new(
            units(),
            Arc::new(hodor_credential::testing::InMemoryApiKeys::default()),
            Arc::new(FakeDigest),
            Arc::new(SequentialRandom::default()),
            clock.clone(),
        ),
    };
    let router = public_router(
        Arc::new(Tenants {
            acme: acme.clone(),
            globex: globex.clone(),
        }),
        Router::new().nest("/api/v1/admin", admin_routes(state)),
        Router::new(),
        Limits::default(),
    );

    let mut world = World {
        router,
        clock,
        units_of_work,
        identity,
        tokens,
        authorization,
        sessions,
        consents: oauth.1,
        audit: AuditHandler::new(audit),
        recorded: AtomicUsize::new(0),
        acme,
        globex,
        tenants,
        keys_of_people,
        totp,
        decisions: decision_store,
        webhooks: webhook_rows,
        endpoints: hodor_webhooks::testing::RecordingEndpoints::default(),
        fanned_out: AtomicUsize::new(0),
        bundle_endpoints,
        administrator: UserId::generate(),
        administrator_token: String::new(),
    };
    let acme = world.acme.clone();
    let (administrator, token) = world
        .person(&acme, "root@example.com", &[Role::TenantAdministrator])
        .await;
    world.administrator = administrator;
    world.administrator_token = token;
    world
}

impl World {
    /// Creates a user in a tenant with the given roles and a token.
    async fn person(
        &self,
        tenant: &TenantContext,
        email: &str,
        roles: &[Role],
    ) -> (UserId, String) {
        let user = self
            .identity
            .create(
                tenant,
                CreateUser {
                    kind: UserKind::Human,
                    identifiers: vec![(IdentifierKind::Email, email.to_owned())],
                    profile: Profile::default(),
                    confirmed: true,
                },
                Caller::system(),
            )
            .await
            .expect("user")
            .id();
        for role in roles {
            self.authorization
                .assign(tenant, user, *role, Caller::system())
                .await
                .expect("role");
        }
        (user, self.token_for(tenant, user, Duration::hours(1)).await)
    }

    async fn token_for(&self, tenant: &TenantContext, user: UserId, lifetime: Duration) -> String {
        let (_, secret) = self
            .tokens
            .issue(tenant, user, "test", lifetime, Caller::system())
            .await
            .expect("token");
        secret.expose().to_owned()
    }

    async fn start_session(&self, user: UserId) -> SessionToken {
        self.sessions
            .start(
                &self.acme,
                StartSession {
                    user_id: user,
                    assurance: Assurance::SingleFactor,
                    methods: vec!["password".to_owned()],
                    timeouts: SessionTimeouts {
                        idle: Duration::minutes(30),
                        absolute: Duration::hours(12),
                    },
                    client: ClientInfo {
                        address: Some("203.0.113.9".to_owned()),
                        description: Some("Example Browser".to_owned()),
                    },
                },
                Caller::system(),
            )
            .await
            .expect("session")
            .1
    }

    /// Does the worker's part: turns the events announced so far into
    /// audit records.
    async fn record_audit(&self) {
        let events = self.units_of_work.committed_events();
        let from = self.recorded.swap(events.len(), Ordering::SeqCst);
        for event in &events[from..] {
            let tenant = TenantContext::assume(event.metadata.tenant_id);
            let mut uow = self.units_of_work.begin(&tenant).await.expect("begin");
            self.audit
                .handle(uow.as_mut(), event)
                .await
                .expect("recorded");
            uow.commit().await.expect("commit");
        }
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        authorization: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> Reply {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, "auth.example");
        if let Some(value) = authorization {
            request = request.header(header::AUTHORIZATION, value);
        }
        let request = match body {
            Some(body) => request
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        }
        .expect("request");
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("response");
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.expect("body").to_bytes();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        }
    }

    /// A request to Acme's interface as its administrator.
    async fn as_administrator(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Reply {
        self.send(
            method,
            &format!("/t/acme/api/v1/admin{path}"),
            Some(&format!("Bearer {}", self.administrator_token)),
            body,
        )
        .await
    }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: serde_json::Value,
}

impl Reply {
    fn code(&self) -> &str {
        self.body["code"].as_str().unwrap_or_default()
    }
}

/// One operation of the OpenAPI document.
struct Operation {
    method: Method,
    /// The path as the document writes it.
    template: String,
    permission: Permission,
}

impl Operation {
    /// A path that fits the template, naming things that do not exist.
    fn path(&self) -> String {
        format!(
            "/t/acme/api/v1/admin{}",
            self.template
                .replace("{user_id}", &UserId::generate().to_string())
                .replace("{session_id}", &UserId::generate().to_string())
                .replace("{provider_id}", &UserId::generate().to_string())
                .replace("{key_set}", "sig")
                .replace("{version_id}", &UserId::generate().to_string())
                .replace("{application_id}", &UserId::generate().to_string())
                .replace("{client_id}", &UserId::generate().to_string())
                .replace("{claim_mapper_id}", &UserId::generate().to_string())
                .replace("{secret_id}", &UserId::generate().to_string())
                .replace("{key_id}", "a-key")
                .replace("{resource_server_id}", &UserId::generate().to_string())
                .replace("{permission}", "document:read")
                .replace("{role}", "editor")
                .replace("{number}", "7")
                .replace("{simulation_id}", &UserId::generate().to_string())
                .replace("{endpoint_id}", &UserId::generate().to_string())
                .replace("{delivery_id}", &UserId::generate().to_string())
                .replace("{entry_id}", &UserId::generate().to_string())
                .replace("{trust_domain_id}", &UserId::generate().to_string())
        )
    }
}

fn documented_operations() -> Vec<Operation> {
    let document: serde_json::Value = serde_json::from_str(ADMIN_OPENAPI).expect("valid JSON");
    let mut operations = Vec::new();
    for (template, methods) in document["paths"].as_object().expect("paths") {
        for (method, operation) in methods.as_object().expect("operations") {
            let permission = operation["x-hodor-permission"]
                .as_str()
                .and_then(Permission::from_name)
                .unwrap_or_else(|| panic!("{method} {template} names no known permission"));
            operations.push(Operation {
                method: method.to_uppercase().parse().expect("method"),
                template: template.clone(),
                permission,
            });
        }
    }
    operations
}

#[test]
fn the_document_and_the_routes_list_the_same_operations_and_permissions() {
    let documented: BTreeSet<(String, String, &str)> = documented_operations()
        .iter()
        .map(|o| {
            (
                o.method.to_string(),
                o.template.clone(),
                o.permission.as_str(),
            )
        })
        .collect();
    let served: BTreeSet<(String, String, &str)> = ADMIN_OPERATIONS
        .iter()
        .map(|(method, path, permission)| {
            (
                (*method).to_owned(),
                (*path).to_owned(),
                permission.as_str(),
            )
        })
        .collect();
    assert_eq!(documented, served);
    assert_eq!(served.len(), 150);

    // Every operation says how it refuses.
    let document: serde_json::Value = serde_json::from_str(ADMIN_OPENAPI).expect("valid JSON");
    for (template, methods) in document["paths"].as_object().expect("paths") {
        for (method, operation) in methods.as_object().expect("operations") {
            for status in ["401", "403"] {
                assert!(
                    operation["responses"][status].is_object(),
                    "{method} {template} does not document {status}"
                );
            }
        }
    }
}

#[tokio::test]
async fn the_document_is_served_without_a_token() {
    let world = world().await;
    let reply = world
        .send(Method::GET, "/t/acme/api/v1/admin/openapi.json", None, None)
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.body,
        serde_json::from_str::<serde_json::Value>(ADMIN_OPENAPI).expect("valid JSON")
    );
}

#[tokio::test]
async fn with_the_authority_off_the_document_does_not_name_it() {
    // Without keys there is no authority.
    let world = world_with_keys(false).await;
    let reply = world
        .send(Method::GET, "/t/acme/api/v1/admin/openapi.json", None, None)
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body["openapi"], "3.1.0");
    // The certificate authority is off in this world: the document is the
    // whole one without its operations and the schemas only they use.
    let mut whole: serde_json::Value = serde_json::from_str(ADMIN_OPENAPI).expect("valid JSON");
    let paths = whole["paths"].as_object_mut().expect("paths");
    assert!(paths.remove("/certificate-authority").is_some());
    assert!(paths.remove("/certificate-authority:install").is_some());
    let schemas = whole["components"]["schemas"]
        .as_object_mut()
        .expect("schemas");
    for schema in [
        "CertificateAuthority",
        "NewCertificateAuthority",
        "CertificateAuthorityCertificate",
    ] {
        assert!(schemas.remove(schema).is_some(), "{schema}");
    }
    assert_eq!(reply.body, whole);
    assert!(
        !reply.body["paths"]
            .to_string()
            .contains("certificate-authority")
    );
}

#[tokio::test]
async fn with_the_authority_off_its_operations_are_not_routed() {
    let world = world_with_keys(false).await;
    let (_, token) = world
        .person(
            &world.acme,
            "root@acme.example",
            &[Role::TenantAdministrator],
        )
        .await;
    let bearer = format!("Bearer {token}");
    for (method, path) in [
        (Method::GET, "/certificate-authority"),
        (Method::POST, "/certificate-authority"),
        (Method::POST, "/certificate-authority:install"),
        (Method::DELETE, "/certificate-authority"),
    ] {
        let reply = world
            .send(
                method.clone(),
                &format!("/t/acme/api/v1/admin{path}"),
                Some(&bearer),
                Some(serde_json::json!({ "kind": "root", "trust_domains": ["a.example"] })),
            )
            .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{method} {path}");
    }
}

#[tokio::test]
async fn every_operation_refuses_a_request_that_is_not_authenticated_in_one_way() {
    let world = world().await;
    let (globex_administrator, globex_token) = world
        .person(
            &world.globex,
            "root@globex.example",
            &[Role::TenantAdministrator],
        )
        .await;
    let acme = world.acme.clone();
    // An administrator who was suspended, one whose token expired and one
    // whose token was revoked.
    let (suspended, suspended_token) = world
        .person(&acme, "gone@example.com", &[Role::TenantAdministrator])
        .await;
    world
        .identity
        .suspend(&acme, suspended, "left", Caller::system())
        .await
        .expect("suspended");
    let expired_token = world
        .token_for(&acme, world.administrator, Duration::minutes(1))
        .await;
    let (revoked, revoked_secret) = world
        .tokens
        .issue(
            &acme,
            world.administrator,
            "test",
            Duration::hours(1),
            Caller::system(),
        )
        .await
        .expect("token");
    world
        .tokens
        .revoke(&acme, revoked.id(), Caller::system())
        .await
        .expect("revoked");
    world.clock.advance(Duration::minutes(2));
    assert_ne!(globex_administrator, world.administrator);

    let not_good = [
        ("no token", None),
        ("an empty header", Some(String::new())),
        (
            "another scheme",
            Some(format!("Basic {}", world.administrator_token)),
        ),
        ("no scheme", Some(world.administrator_token.clone())),
        ("a malformed token", Some("Bearer not-a-token".to_owned())),
        (
            "an unknown token",
            Some(format!("Bearer hodor_at_{}", "0".repeat(64))),
        ),
        (
            "another tenant's token",
            Some(format!("Bearer {globex_token}")),
        ),
        (
            "a suspended user's token",
            Some(format!("Bearer {suspended_token}")),
        ),
        ("an expired token", Some(format!("Bearer {expired_token}"))),
        (
            "a revoked token",
            Some(format!("Bearer {}", revoked_secret.expose())),
        ),
    ];
    let mut answers = BTreeSet::new();
    for operation in documented_operations() {
        for (what, authorization) in &not_good {
            // A body that would be refused if it were read: it must not be.
            let reply = world
                .send(
                    operation.method.clone(),
                    &operation.path(),
                    authorization.as_deref(),
                    Some(serde_json::json!({ "unexpected": true })),
                )
                .await;
            let label = format!("{} {} with {what}", operation.method, operation.template);
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{label}");
            assert_eq!(reply.code(), "admin.not_authenticated", "{label}");
            assert_eq!(
                reply
                    .headers
                    .get(header::WWW_AUTHENTICATE)
                    .map(|v| v.as_bytes()),
                Some(b"Bearer".as_slice()),
                "{label}"
            );
            answers.insert(reply.body["detail"].to_string());
        }
    }
    assert_eq!(answers.len(), 1, "every refusal says the same: {answers:?}");
    // Nothing was done by any of them: the tenant still has the two users
    // this test made, and the one who was suspended is the only one.
    let users = world.as_administrator(Method::GET, "/users", None).await;
    assert_eq!(users.status, StatusCode::OK);
    let statuses: Vec<&str> = users.body["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|user| user["status"].as_str())
        .collect();
    assert_eq!(statuses, ["active", "suspended"]);
}

#[tokio::test]
async fn every_operation_is_refused_to_a_user_without_the_permission() {
    let world = world().await;
    let acme = world.acme.clone();
    let (_, nobody) = world.person(&acme, "nobody@example.com", &[]).await;
    let (_, auditor) = world
        .person(&acme, "auditor@example.com", &[Role::TenantAuditor])
        .await;
    // An administrator of another tenant who is also a user here, without
    // a role here: a role in one tenant means nothing in another.
    let (visitor, _) = world.person(&acme, "visitor@example.com", &[]).await;
    world
        .authorization
        .assign(
            &world.globex,
            visitor,
            Role::TenantAdministrator,
            Caller::system(),
        )
        .await
        .expect("role elsewhere");
    let visitor = world.token_for(&acme, visitor, Duration::hours(1)).await;

    for operation in documented_operations() {
        let label = format!("{} {}", operation.method, operation.template);
        for token in [&nobody, &visitor] {
            let reply = world
                .send(
                    operation.method.clone(),
                    &operation.path(),
                    Some(&format!("Bearer {token}")),
                    Some(serde_json::json!({ "unexpected": true })),
                )
                .await;
            assert_eq!(reply.status, StatusCode::FORBIDDEN, "{label}");
            assert_eq!(reply.code(), "admin.forbidden", "{label}");
        }

        // An auditor may read and may change nothing.
        let reply = world
            .send(
                operation.method.clone(),
                &operation.path(),
                Some(&format!("Bearer {auditor}")),
                None,
            )
            .await;
        if Role::TenantAuditor.allows(operation.permission) {
            assert_ne!(reply.status, StatusCode::FORBIDDEN, "{label}");
            assert_ne!(reply.status, StatusCode::UNAUTHORIZED, "{label}");
            assert_eq!(operation.method, Method::GET, "{label}");
        } else {
            assert_eq!(reply.status, StatusCode::FORBIDDEN, "{label}");
            assert_ne!(operation.method, Method::GET, "{label}");
        }
    }
}

#[tokio::test]
async fn every_documented_operation_is_answered_for_an_administrator() {
    let world = world().await;
    for operation in documented_operations() {
        let reply = world
            .send(
                operation.method.clone(),
                &operation.path(),
                Some(&format!("Bearer {}", world.administrator_token)),
                Some(serde_json::json!({ "email": "new@example.com", "reason": "test" })),
            )
            .await;
        let label = format!(
            "{} {}: {}",
            operation.method, operation.template, reply.status
        );
        assert_ne!(reply.status, StatusCode::UNAUTHORIZED, "{label}");
        assert_ne!(reply.status, StatusCode::FORBIDDEN, "{label}");
        assert_ne!(reply.status, StatusCode::METHOD_NOT_ALLOWED, "{label}");
        assert_ne!(reply.code(), "route.not_found", "{label}");
        assert!(!reply.status.is_server_error(), "{label}");
    }
}

#[tokio::test]
async fn an_administrator_creates_reads_and_suspends_a_user() {
    let world = world().await;

    let created = world
        .as_administrator(
            Method::POST,
            "/users",
            Some(serde_json::json!({
                "email": "Ana@Example.com", "display_name": "Ana Silva", "locale": "pt-BR"
            })),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED);
    let user = &created.body;
    assert_eq!(user["status"], "active");
    assert_eq!(user["kind"], "human");
    assert_eq!(user["display_name"], "Ana Silva");
    assert_eq!(user["locale"], "pt-BR");
    assert_eq!(user["identifiers"][0]["kind"], "email");
    assert_eq!(user["identifiers"][0]["verified"], false);
    assert_eq!(user["identifiers"][0]["primary"], true);
    let id = user["id"].as_str().expect("identifier").to_owned();

    let read = world
        .as_administrator(Method::GET, &format!("/users/{id}"), None)
        .await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.body, created.body);

    // The same address again is a conflict, and this interface may say so.
    let again = world
        .as_administrator(
            Method::POST,
            "/users",
            Some(serde_json::json!({ "email": "ana@example.com" })),
        )
        .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.code(), "identity.identifier_taken");

    let suspended = world
        .as_administrator(
            Method::POST,
            &format!("/users/{id}:suspend"),
            Some(serde_json::json!({ "reason": "left the company" })),
        )
        .await;
    assert_eq!(suspended.status, StatusCode::OK);
    assert_eq!(suspended.body["status"], "suspended");
    assert_eq!(suspended.body["status_reason"], "left the company");

    let twice = world
        .as_administrator(
            Method::POST,
            &format!("/users/{id}:suspend"),
            Some(serde_json::json!({ "reason": "again" })),
        )
        .await;
    assert_eq!(twice.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn requests_that_are_allowed_and_wrong_are_refused_for_what_is_wrong() {
    let world = world().await;
    let missing = UserId::generate();
    let cases = [
        (
            Method::GET,
            format!("/users/{missing}"),
            None,
            404,
            "identity.user_not_found",
        ),
        (
            Method::GET,
            "/users/not-an-identifier".to_owned(),
            None,
            404,
            "identity.user_not_found",
        ),
        (
            Method::POST,
            format!("/users/{missing}:suspend"),
            Some(serde_json::json!({ "reason": "x" })),
            404,
            "identity.user_not_found",
        ),
        (
            Method::POST,
            format!("/users/{missing}:promote"),
            Some(serde_json::json!({})),
            404,
            "route.not_found",
        ),
        (
            Method::POST,
            format!("/users/{}:suspend", world.administrator),
            Some(serde_json::json!({})),
            422,
            "request.body_invalid",
        ),
        (
            Method::POST,
            "/users".to_owned(),
            Some(serde_json::json!({ "mail": "x" })),
            422,
            "request.body_invalid",
        ),
        (
            Method::GET,
            format!("/users/{missing}/sessions"),
            None,
            404,
            "identity.user_not_found",
        ),
        (
            Method::DELETE,
            format!("/sessions/{missing}"),
            None,
            404,
            "session.not_found",
        ),
        (
            Method::DELETE,
            "/sessions/nope".to_owned(),
            None,
            404,
            "session.not_found",
        ),
        (
            Method::GET,
            "/users?limit=0".to_owned(),
            None,
            422,
            "request.query_invalid",
        ),
        (
            Method::GET,
            "/users?limit=201".to_owned(),
            None,
            422,
            "request.query_invalid",
        ),
        (
            Method::GET,
            "/users?limit=many".to_owned(),
            None,
            422,
            "request.query_invalid",
        ),
        (
            Method::GET,
            "/users?cursor=nope".to_owned(),
            None,
            422,
            "request.cursor_invalid",
        ),
        (
            Method::GET,
            "/audit-records?cursor=nope".to_owned(),
            None,
            422,
            "request.cursor_invalid",
        ),
    ];
    for (method, path, body, status, code) in cases {
        let reply = world.as_administrator(method.clone(), &path, body).await;
        assert_eq!(reply.status.as_u16(), status, "{method} {path}");
        assert_eq!(reply.code(), code, "{method} {path}");
    }

    let invalid = world
        .as_administrator(
            Method::POST,
            "/users",
            Some(serde_json::json!({ "email": "not an address" })),
        )
        .await;
    assert_eq!(invalid.status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn users_are_listed_a_page_at_a_time_in_the_order_they_were_created() {
    let world = world().await;
    for index in 0..4 {
        let created = world
            .as_administrator(
                Method::POST,
                "/users",
                Some(serde_json::json!({ "email": format!("person{index}@example.com") })),
            )
            .await;
        assert_eq!(created.status, StatusCode::CREATED);
    }
    // Another tenant's users are not this tenant's.
    world
        .person(&world.globex, "other@globex.example", &[])
        .await;

    let mut seen = Vec::new();
    let mut path = "/users?limit=2".to_owned();
    for _ in 0..10 {
        let page = world.as_administrator(Method::GET, &path, None).await;
        assert_eq!(page.status, StatusCode::OK);
        let items = page.body["items"].as_array().expect("items");
        assert!(items.len() <= 2);
        seen.extend(items.iter().map(|user| {
            user["identifiers"][0]["value"]
                .as_str()
                .expect("value")
                .to_owned()
        }));
        match page.body["next_cursor"].as_str() {
            Some(cursor) => path = format!("/users?limit=2&cursor={cursor}"),
            None => break,
        }
    }
    assert_eq!(
        seen,
        [
            "root@example.com",
            "person0@example.com",
            "person1@example.com",
            "person2@example.com",
            "person3@example.com"
        ]
    );
}

#[tokio::test]
async fn an_administrator_sees_and_ends_a_users_sessions() {
    let world = world().await;
    let acme = world.acme.clone();
    let (ana, _) = world.person(&acme, "ana@example.com", &[]).await;
    let token = world.start_session(ana).await;
    world.start_session(ana).await;

    let listed = world
        .as_administrator(Method::GET, &format!("/users/{ana}/sessions"), None)
        .await;
    assert_eq!(listed.status, StatusCode::OK);
    let sessions = listed.body["items"].as_array().expect("items");
    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions[0]["address"], "203.0.113.9");
    assert!(sessions[0].get("current").is_none());
    // No token of any session is in the list.
    assert!(!listed.body.to_string().contains(token.expose()));

    // The first session started is the last in the list.
    let first = sessions[1]["session_id"].as_str().expect("identifier");
    let ended = world
        .as_administrator(Method::DELETE, &format!("/sessions/{first}"), None)
        .await;
    assert_eq!(ended.status, StatusCode::NO_CONTENT);
    let found = world
        .sessions
        .find_by_token(&world.acme, token.expose())
        .await
        .expect("find");
    assert!(found.is_none(), "the session is ended");
    // Ending it again changes nothing.
    let again = world
        .as_administrator(Method::DELETE, &format!("/sessions/{first}"), None)
        .await;
    assert_eq!(again.status, StatusCode::NO_CONTENT);

    let remaining = world
        .as_administrator(Method::GET, &format!("/users/{ana}/sessions"), None)
        .await;
    assert_eq!(remaining.body["items"].as_array().map(Vec::len), Some(1));
}

#[tokio::test]
async fn what_an_administrator_does_is_in_the_audit_log_under_their_name() {
    let world = world().await;
    let created = world
        .as_administrator(
            Method::POST,
            "/users",
            Some(serde_json::json!({ "email": "ana@example.com" })),
        )
        .await;
    let id = created.body["id"].as_str().expect("identifier").to_owned();
    world
        .as_administrator(
            Method::POST,
            &format!("/users/{id}:suspend"),
            Some(serde_json::json!({ "reason": "left the company" })),
        )
        .await;
    world.record_audit().await;

    let mut records = Vec::new();
    let mut path = "/audit-records?limit=3".to_owned();
    for _ in 0..20 {
        let page = world.as_administrator(Method::GET, &path, None).await;
        assert_eq!(page.status, StatusCode::OK);
        records.extend(page.body["items"].as_array().expect("items").clone());
        match page.body["next_cursor"].as_str() {
            Some(cursor) => path = format!("/audit-records?limit=3&cursor={cursor}"),
            None => break,
        }
    }

    // In order, without gaps, each following the one before.
    for (index, record) in records.iter().enumerate() {
        assert_eq!(record["sequence"], index as u64 + 1);
        assert_eq!(record["hash"].as_str().map(str::len), Some(64));
        if index > 0 {
            assert_eq!(record["previous_hash"], records[index - 1]["hash"]);
        }
    }
    let suspended = records
        .iter()
        .find(|record| record["action"] == "identity.user_suspended")
        .expect("the suspension is recorded");
    assert_eq!(suspended["actor"]["kind"], "user");
    assert_eq!(suspended["actor"]["id"], world.administrator.to_string());
    assert_eq!(suspended["details"]["user_id"], id.as_str());
    assert_eq!(suspended["details"]["reason"], "left the company");
    // Issuing the administrator's token was recorded; the token was not.
    let everything = serde_json::Value::Array(records).to_string();
    assert!(everything.contains("credential.access_token_issued"));
    assert!(!everything.contains(&world.administrator_token));
    assert!(!everything.contains(&world.administrator_token[9..]));
    // Another tenant's log is not this tenant's.
    assert!(!everything.contains(&world.globex.tenant_id().to_string()));
}

const CLIENT_SECRET: &str = "the-client-secret-of-the-provider";

/// A change to the body that adds a provider.
type Change = fn(&mut serde_json::Value);

fn new_provider(alias: &str) -> serde_json::Value {
    serde_json::json!({
        "alias": alias,
        "display_name": "Example",
        "issuer": "https://accounts.example.com",
        "client_id": "hodor",
        "client_secret": CLIENT_SECRET,
    })
}

#[tokio::test]
async fn an_administrator_adds_changes_and_disables_an_identity_provider() {
    let world = world().await;

    let created = world
        .as_administrator(
            Method::POST,
            "/identity-providers",
            Some(new_provider("example")),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    let provider = &created.body;
    assert_eq!(provider["alias"], "example");
    assert_eq!(provider["kind"], "openid_connect");
    assert_eq!(provider["status"], "enabled");
    assert_eq!(provider["creates_users"], true);
    assert_eq!(
        provider["scopes"],
        serde_json::json!(["openid", "email", "profile"])
    );
    assert_eq!(
        provider["callback_address"],
        "https://auth.example/t/acme/account/providers/example/callback",
        "the address to register at the provider"
    );
    let id = provider["id"].as_str().expect("id").to_owned();
    let path = format!("/identity-providers/{id}");

    // What is left out of a change stays as it is.
    let changed = world
        .as_administrator(
            Method::PATCH,
            &path,
            Some(serde_json::json!({ "display_name": "Another name", "creates_users": false })),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{:?}", changed.body);
    assert_eq!(changed.body["display_name"], "Another name");
    assert_eq!(changed.body["creates_users"], false);
    assert_eq!(changed.body["issuer"], "https://accounts.example.com");
    assert_eq!(changed.body["alias"], "example");

    let disabled = world
        .as_administrator(Method::POST, &format!("{path}:disable"), None)
        .await;
    assert_eq!(disabled.status, StatusCode::OK);
    assert_eq!(disabled.body["status"], "disabled");
    let enabled = world
        .as_administrator(Method::POST, &format!("{path}:enable"), None)
        .await;
    assert_eq!(enabled.body["status"], "enabled");

    let replaced = world
        .as_administrator(
            Method::PUT,
            &format!("{path}/client-secret"),
            Some(serde_json::json!({ "client_secret": "a brand new secret" })),
        )
        .await;
    assert_eq!(replaced.status, StatusCode::NO_CONTENT);

    let read = world.as_administrator(Method::GET, &path, None).await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.body["display_name"], "Another name");
    let listed = world
        .as_administrator(Method::GET, "/identity-providers", None)
        .await;
    assert_eq!(listed.body["items"].as_array().expect("items").len(), 1);

    // Each change was made by the administrator, and is announced as theirs.
    let said = format!("{:?}", world.units_of_work.committed_events());
    for event in [
        "federation.provider_created",
        "federation.provider_changed",
        "federation.provider_disabled",
        "federation.provider_enabled",
        "federation.provider_secret_changed",
    ] {
        assert!(said.contains(event), "{event}");
    }
    assert!(said.contains(&world.administrator.to_string()));
}

#[tokio::test]
async fn a_client_secret_is_never_part_of_an_answer() {
    let world = world().await;
    let created = world
        .as_administrator(
            Method::POST,
            "/identity-providers",
            Some(new_provider("example")),
        )
        .await;
    let id = created.body["id"].as_str().expect("id").to_owned();
    let path = format!("/identity-providers/{id}");

    let answers = [
        created,
        world.as_administrator(Method::GET, &path, None).await,
        world
            .as_administrator(Method::GET, "/identity-providers", None)
            .await,
        world
            .as_administrator(
                Method::PATCH,
                &path,
                Some(serde_json::json!({ "client_id": "other" })),
            )
            .await,
        world
            .as_administrator(Method::POST, &format!("{path}:disable"), None)
            .await,
        world
            .as_administrator(
                Method::PUT,
                &format!("{path}/client-secret"),
                Some(serde_json::json!({ "client_secret": "replaced-secret-value" })),
            )
            .await,
        world.as_administrator(Method::GET, &path, None).await,
    ];
    for answer in &answers {
        let body = answer.body.to_string();
        assert!(!body.contains(CLIENT_SECRET), "{body}");
        assert!(!body.contains("replaced-secret-value"), "{body}");
        assert!(
            !body.contains("secret"),
            "no field is named for it either: {body}"
        );
    }
    // Nor of what is announced.
    let said = format!("{:?}", world.units_of_work.committed_events());
    assert!(!said.contains(CLIENT_SECRET));
    assert!(!said.contains("replaced-secret-value"));

    // The secret cannot be slipped into a change of settings.
    let slipped = world
        .as_administrator(
            Method::PATCH,
            &path,
            Some(serde_json::json!({ "client_secret": "x", "alias": "renamed" })),
        )
        .await;
    assert_eq!(slipped.status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn what_breaks_a_rule_of_identity_providers_is_refused_with_its_code() {
    let world = world().await;
    let with = |change: Change| {
        let mut body = new_provider("example");
        change(&mut body);
        body
    };
    let cases: [(Change, StatusCode, &str); 6] = [
        (
            |b| b["alias"] = "Not An Alias".into(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "federation.alias_invalid",
        ),
        (
            |b| b["issuer"] = "http://plain.example.com".into(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "federation.issuer_invalid",
        ),
        (
            |b| b["client_secret"] = "".into(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "federation.client_secret_invalid",
        ),
        (
            |b| b["scopes"] = serde_json::json!(["email"]),
            StatusCode::UNPROCESSABLE_ENTITY,
            "federation.scopes_invalid",
        ),
        (
            |b| {
                b.as_object_mut().expect("object").remove("client_id");
            },
            // A SAML provider has none, so the body may leave it out; an
            // OpenID Connect provider is refused without one.
            StatusCode::UNPROCESSABLE_ENTITY,
            "federation.client_id_invalid",
        ),
        (
            |b| b["unexpected"] = true.into(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "request.body_invalid",
        ),
    ];
    for (change, status, code) in cases {
        let reply = world
            .as_administrator(Method::POST, "/identity-providers", Some(with(change)))
            .await;
        assert_eq!(reply.status, status, "{code}: {:?}", reply.body);
        assert_eq!(reply.code(), code);
    }

    let first = world
        .as_administrator(
            Method::POST,
            "/identity-providers",
            Some(new_provider("example")),
        )
        .await;
    assert_eq!(first.status, StatusCode::CREATED);
    let again = world
        .as_administrator(
            Method::POST,
            "/identity-providers",
            Some(new_provider("example")),
        )
        .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.code(), "federation.alias_taken");

    for path in [
        format!("/identity-providers/{}", UserId::generate()),
        "/identity-providers/not-an-identifier".to_owned(),
        format!("/identity-providers/{}:disable", UserId::generate()),
    ] {
        let method = if path.ends_with(":disable") {
            Method::POST
        } else {
            Method::GET
        };
        let reply = world.as_administrator(method, &path, None).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(reply.code(), "federation.provider_not_found", "{path}");
    }
    let id = first.body["id"].as_str().expect("id");
    let unknown_action = world
        .as_administrator(
            Method::POST,
            &format!("/identity-providers/{id}:delete"),
            None,
        )
        .await;
    assert_eq!(unknown_action.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown_action.code(), "route.not_found");
}

#[tokio::test]
async fn the_identity_providers_of_one_tenant_do_not_exist_for_another() {
    let world = world().await;
    let created = world
        .as_administrator(
            Method::POST,
            "/identity-providers",
            Some(new_provider("example")),
        )
        .await;
    let id = created.body["id"].as_str().expect("id").to_owned();
    let globex = world.globex.clone();
    let (_, theirs) = world
        .person(&globex, "root@globex.example", &[Role::TenantAdministrator])
        .await;
    let authorization = format!("Bearer {theirs}");

    let listed = world
        .send(
            Method::GET,
            "/t/globex/api/v1/admin/identity-providers",
            Some(&authorization),
            None,
        )
        .await;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body["items"], serde_json::json!([]));
    for (method, suffix) in [
        (Method::GET, ""),
        (Method::POST, ":disable"),
        (Method::PATCH, ""),
    ] {
        let reply = world
            .send(
                method.clone(),
                &format!("/t/globex/api/v1/admin/identity-providers/{id}{suffix}"),
                Some(&authorization),
                Some(serde_json::json!({})),
            )
            .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{method} {suffix}");
        assert_eq!(reply.code(), "federation.provider_not_found");
    }
    // The same alias is theirs to use.
    let own = world
        .send(
            Method::POST,
            "/t/globex/api/v1/admin/identity-providers",
            Some(&authorization),
            Some(new_provider("example")),
        )
        .await;
    assert_eq!(own.status, StatusCode::CREATED);
    assert_eq!(
        own.body["callback_address"],
        "https://auth.example/t/globex/account/providers/example/callback"
    );
    let still = world
        .as_administrator(Method::GET, &format!("/identity-providers/{id}"), None)
        .await;
    assert_eq!(still.body["status"], "enabled");
}

#[tokio::test]
async fn a_provider_is_of_a_kind_and_may_be_trusted_with_addresses() {
    let world = world().await;

    // GitHub has an issuer and scopes of its own.
    let github = world
        .as_administrator(
            Method::POST,
            "/identity-providers",
            Some(serde_json::json!({
                "alias": "github", "kind": "github", "display_name": "GitHub",
                "client_id": "github-client", "client_secret": CLIENT_SECRET,
            })),
        )
        .await;
    assert_eq!(github.status, StatusCode::CREATED, "{:?}", github.body);
    assert_eq!(github.body["kind"], "github");
    assert_eq!(github.body["issuer"], "https://github.com");
    assert_eq!(
        github.body["scopes"],
        serde_json::json!(["read:user", "user:email"])
    );
    assert_eq!(github.body["trusts_email"], false);

    // An OpenID Connect provider has neither.
    let mut without_issuer = new_provider("example");
    without_issuer
        .as_object_mut()
        .expect("object")
        .remove("issuer");
    let refused = world
        .as_administrator(Method::POST, "/identity-providers", Some(without_issuer))
        .await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(refused.code(), "federation.issuer_invalid");
    let mut unknown = new_provider("example");
    unknown["kind"] = "kerberos".into();
    let refused = world
        .as_administrator(Method::POST, "/identity-providers", Some(unknown))
        .await;
    assert_eq!(refused.code(), "federation.kind_invalid");

    // Trust in addresses is off unless asked for, and can be changed.
    let mut trusted = new_provider("entra");
    trusted["trusts_email"] = true.into();
    let created = world
        .as_administrator(Method::POST, "/identity-providers", Some(trusted))
        .await;
    assert_eq!(created.body["trusts_email"], true);
    let id = created.body["id"].as_str().expect("id");
    let changed = world
        .as_administrator(
            Method::PATCH,
            &format!("/identity-providers/{id}"),
            Some(serde_json::json!({ "trusts_email": false })),
        )
        .await;
    assert_eq!(changed.body["trusts_email"], false);

    // The kind is not something a change can touch.
    let rekinded = world
        .as_administrator(
            Method::PATCH,
            &format!("/identity-providers/{id}"),
            Some(serde_json::json!({ "kind": "github" })),
        )
        .await;
    assert_eq!(rekinded.status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn an_administrator_adds_and_changes_a_directory() {
    let world = world().await;
    let directory = |issuer: &str| {
        serde_json::json!({
            "alias": "company", "kind": "ldap", "display_name": "Company directory",
            "issuer": issuer,
            "client_id": "cn=hodor,ou=services,dc=example,dc=com",
            "client_secret": CLIENT_SECRET,
            "trusts_email": true,
            "directory": { "base": "ou=people,dc=example,dc=com", "filter": "(uid={identifier})" },
        })
    };

    // A directory that is not on the installation's list.
    let refused = world
        .as_administrator(
            Method::POST,
            "/identity-providers",
            Some(directory("ldaps://ldap.elsewhere.example")),
        )
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{:?}", refused.body);
    assert_eq!(refused.code(), "federation.directory_not_allowed");

    let created = world
        .as_administrator(
            Method::POST,
            "/identity-providers",
            Some(directory("ldaps://ldap.example.com")),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    assert_eq!(created.body["kind"], "ldap");
    assert_eq!(created.body["callback_address"], serde_json::Value::Null);
    assert_eq!(created.body["scopes"], serde_json::json!([]));
    assert_eq!(
        created.body["directory"],
        serde_json::json!({
            "base": "ou=people,dc=example,dc=com", "filter": "(uid={identifier})",
            "subject_attribute": "entryUUID", "email_attribute": "mail", "name_attribute": "cn",
        })
    );
    assert!(!created.body.to_string().contains(CLIENT_SECRET));

    // A change of one field keeps the others.
    let id = created.body["id"].as_str().expect("id");
    let changed = world
        .as_administrator(
            Method::PATCH,
            &format!("/identity-providers/{id}"),
            Some(serde_json::json!({
                "directory": { "filter": "(sAMAccountName={identifier})", "subject_attribute": "objectGUID" }
            })),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{:?}", changed.body);
    assert_eq!(
        changed.body["directory"]["filter"],
        "(sAMAccountName={identifier})"
    );
    assert_eq!(changed.body["directory"]["subject_attribute"], "objectGUID");
    assert_eq!(
        changed.body["directory"]["base"],
        "ou=people,dc=example,dc=com"
    );

    // A filter that would match without what is typed is refused.
    let broken = world
        .as_administrator(
            Method::PATCH,
            &format!("/identity-providers/{id}"),
            Some(serde_json::json!({ "directory": { "filter": "(objectClass=*)" } })),
        )
        .await;
    assert_eq!(broken.code(), "federation.directory_invalid");

    // Another kind cannot be given a directory, nor a directory left without one.
    let mut misplaced = new_provider("example");
    misplaced["directory"] = serde_json::json!({ "base": "dc=x", "filter": "(uid={identifier})" });
    let refused = world
        .as_administrator(Method::POST, "/identity-providers", Some(misplaced))
        .await;
    assert_eq!(refused.code(), "federation.directory_invalid");
    let mut bare = directory("ldaps://ldap.example.com");
    bare["alias"] = "bare".into();
    bare.as_object_mut().expect("object").remove("directory");
    let refused = world
        .as_administrator(Method::POST, "/identity-providers", Some(bare))
        .await;
    assert_eq!(refused.code(), "federation.directory_invalid");
}

#[tokio::test]
async fn an_administrator_adds_and_changes_a_saml_provider() {
    let world = world().await;
    let identity_provider = hodor_saml::testing::TestIdentityProvider::rsa("urn:corp:idp");
    let created = world
        .as_administrator(
            Method::POST,
            "/identity-providers",
            Some(serde_json::json!({
                "alias": "corp",
                "kind": "saml",
                "display_name": "Corp",
                "issuer": "urn:corp:idp",
                "trusts_email": true,
                "saml": {
                    "single_sign_on_address": "https://idp.corp.example/sso",
                    "certificate": identity_provider.certificate_pem(),
                },
            })),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    assert_eq!(created.body["kind"], "saml");
    assert_eq!(created.body["client_id"], "");
    assert_eq!(created.body["saml"]["email_attribute"], "email");
    assert_eq!(created.body["saml"]["name_attribute"], "name");
    assert_eq!(
        created.body["metadata_address"],
        "https://auth.example/t/acme/interaction/sign-in/providers/corp/saml/metadata",
        "what to give the identity provider"
    );
    assert_eq!(
        created.body["callback_address"],
        serde_json::Value::Null,
        "a SAML provider is given Hodor's metadata, not a callback page"
    );
    let path = format!(
        "/identity-providers/{}",
        created.body["id"].as_str().expect("id")
    );

    // What is left out of a change stays as it is, its SAML settings too.
    let changed = world
        .as_administrator(
            Method::PATCH,
            &path,
            Some(serde_json::json!({
                "display_name": "Corp SSO",
                "trusts_email": false,
                "saml": { "email_attribute": "mail" },
            })),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{:?}", changed.body);
    assert_eq!(changed.body["display_name"], "Corp SSO");
    assert_eq!(changed.body["trusts_email"], false);
    assert_eq!(changed.body["saml"]["email_attribute"], "mail");
    assert_eq!(
        changed.body["saml"]["single_sign_on_address"],
        "https://idp.corp.example/sso"
    );

    let broken = world
        .as_administrator(
            Method::PATCH,
            &path,
            Some(serde_json::json!({ "saml": { "certificate": "not a certificate" } })),
        )
        .await;
    assert_eq!(broken.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(broken.code(), "federation.saml_invalid");
    assert!(
        broken.body["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("certificate_unreadable")),
        "{:?}",
        broken.body
    );

    let secret = world
        .as_administrator(
            Method::PUT,
            &format!("{path}/client-secret"),
            Some(serde_json::json!({ "client_secret": "a secret" })),
        )
        .await;
    assert_eq!(secret.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(secret.code(), "federation.client_secret_invalid");
}

#[tokio::test]
async fn an_administrator_rotates_and_revokes_a_signing_key_and_it_is_audited() {
    let world = world().await;
    let empty = world.as_administrator(Method::GET, "/keys/sig", None).await;
    assert_eq!(empty.status, StatusCode::OK);
    assert_eq!(empty.body["items"], serde_json::json!([]));

    let first = world
        .as_administrator(Method::POST, "/keys/sig:rotate", None)
        .await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.body);
    assert_eq!(first.body["state"], "active");
    assert_eq!(first.body["algorithm"], "ES256");
    assert_eq!(first.body["key_use"], "sig");
    let first_id = first.body["id"].as_str().expect("id").to_owned();

    let second = world
        .as_administrator(
            Method::POST,
            "/keys/sig:rotate",
            Some(serde_json::json!({ "algorithm": "ES256" })),
        )
        .await;
    assert_eq!(second.status, StatusCode::OK);
    let listed = world.as_administrator(Method::GET, "/keys/sig", None).await;
    let items = listed.body["items"].as_array().expect("items");
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["id"], second.body["id"]);
    assert_eq!(items[0]["state"], "active");
    assert_eq!(items[1]["id"], first_id.as_str());
    assert_eq!(items[1]["state"], "retiring");
    // A day of overlap, the installation's.
    assert_eq!(items[1]["retire_after"], "1970-01-02T00:00:00Z");

    let revoked = world
        .as_administrator(
            Method::POST,
            &format!("/keys/sig/versions/{first_id}:revoke"),
            Some(serde_json::json!({ "reason": "the laptop was stolen" })),
        )
        .await;
    assert_eq!(revoked.status, StatusCode::OK);
    assert_eq!(revoked.body["state"], "revoked");
    assert_eq!(revoked.body["revocation_reason"], "the laptop was stolen");

    // Nothing of a key is in any answer.
    for body in [&first.body, &second.body, &listed.body, &revoked.body] {
        let written = body.to_string();
        for member in ["material", "public", "\"x\"", "\"n\""] {
            assert!(!written.contains(member), "{member} in {written}");
        }
    }

    world.record_audit().await;
    let records = world
        .as_administrator(Method::GET, "/audit-records?limit=200", None)
        .await;
    let actions: Vec<&serde_json::Value> = records.body["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter(|record| {
            record["action"]
                .as_str()
                .is_some_and(|action| action.starts_with("keys."))
        })
        .collect();
    assert_eq!(actions.len(), 5, "two made, two activated, one revoked");
    for record in actions {
        assert_eq!(record["actor"]["id"], world.administrator.to_string());
    }
}

#[tokio::test]
async fn what_breaks_a_rule_of_keys_is_refused_with_its_code() {
    let world = world().await;
    let rotated = world
        .as_administrator(Method::POST, "/keys/sig:rotate", None)
        .await;
    let id = rotated.body["id"].as_str().expect("id").to_owned();
    let cases = [
        (
            Method::GET,
            "/keys/enc".to_owned(),
            None,
            StatusCode::NOT_FOUND,
            "keys.key_set_not_found",
        ),
        (
            Method::GET,
            "/keys/everything".to_owned(),
            None,
            StatusCode::NOT_FOUND,
            "keys.key_set_not_found",
        ),
        (
            Method::POST,
            "/keys/data:rotate".to_owned(),
            None,
            StatusCode::UNPROCESSABLE_ENTITY,
            "keys.rotation_not_offered",
        ),
        (
            Method::POST,
            "/keys/sig:explode".to_owned(),
            None,
            StatusCode::NOT_FOUND,
            "route.not_found",
        ),
        (
            Method::POST,
            "/keys/sig:rotate".to_owned(),
            Some(serde_json::json!({ "algorithm": "none" })),
            StatusCode::UNPROCESSABLE_ENTITY,
            "keys.algorithm_unsuitable",
        ),
        (
            Method::POST,
            "/keys/sig:rotate".to_owned(),
            Some(serde_json::json!({ "algorithm": "A256GCM" })),
            StatusCode::UNPROCESSABLE_ENTITY,
            "keys.algorithm_unsuitable",
        ),
        (
            Method::POST,
            "/keys/sig:rotate".to_owned(),
            Some(serde_json::json!({ "algorithm": "ES256", "overlap": 0 })),
            StatusCode::UNPROCESSABLE_ENTITY,
            "request.body_invalid",
        ),
        (
            Method::POST,
            format!("/keys/sig/versions/{id}:revoke"),
            Some(serde_json::json!({ "reason": "" })),
            StatusCode::UNPROCESSABLE_ENTITY,
            "keys.reason_invalid",
        ),
        (
            Method::POST,
            format!("/keys/sig/versions/{id}:revoke"),
            Some(serde_json::json!({ "reason": "x".repeat(201) })),
            StatusCode::UNPROCESSABLE_ENTITY,
            "keys.reason_invalid",
        ),
        (
            Method::POST,
            format!("/keys/sig/versions/{id}:revoke"),
            None,
            StatusCode::UNPROCESSABLE_ENTITY,
            "request.body_invalid",
        ),
        (
            Method::POST,
            format!("/keys/data/versions/{id}:revoke"),
            Some(serde_json::json!({ "reason": "wrong set" })),
            StatusCode::NOT_FOUND,
            "keys.version_not_found",
        ),
        (
            Method::POST,
            format!("/keys/sig/versions/{}:revoke", UserId::generate()),
            Some(serde_json::json!({ "reason": "unknown" })),
            StatusCode::NOT_FOUND,
            "keys.version_not_found",
        ),
        (
            Method::POST,
            "/keys/sig/versions/not-an-identifier:revoke".to_owned(),
            Some(serde_json::json!({ "reason": "malformed" })),
            StatusCode::NOT_FOUND,
            "keys.version_not_found",
        ),
        (
            Method::POST,
            format!("/keys/sig/versions/{id}:destroy"),
            Some(serde_json::json!({ "reason": "no such action" })),
            StatusCode::NOT_FOUND,
            "route.not_found",
        ),
    ];
    for (method, path, body, status, code) in cases {
        let reply = world.as_administrator(method.clone(), &path, body).await;
        assert_eq!(reply.status, status, "{method} {path}: {:?}", reply.body);
        assert_eq!(reply.code(), code, "{method} {path}");
    }
    // The version is still active: nothing above changed it.
    let listed = world.as_administrator(Method::GET, "/keys/sig", None).await;
    assert_eq!(listed.body["items"][0]["state"], "active");
}

#[tokio::test]
async fn the_keys_of_one_tenant_do_not_exist_for_another() {
    let world = world().await;
    let rotated = world
        .as_administrator(Method::POST, "/keys/sig:rotate", None)
        .await;
    let id = rotated.body["id"].as_str().expect("id").to_owned();
    let (_, globex) = world
        .person(
            &world.globex,
            "root@globex.example",
            &[Role::TenantAdministrator],
        )
        .await;
    let authorization = format!("Bearer {globex}");

    let listed = world
        .send(
            Method::GET,
            "/t/globex/api/v1/admin/keys/sig",
            Some(&authorization),
            None,
        )
        .await;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body["items"], serde_json::json!([]));
    let revoked = world
        .send(
            Method::POST,
            &format!("/t/globex/api/v1/admin/keys/sig/versions/{id}:revoke"),
            Some(&authorization),
            Some(serde_json::json!({ "reason": "not ours" })),
        )
        .await;
    assert_eq!(revoked.status, StatusCode::NOT_FOUND);
    assert_eq!(revoked.code(), "keys.version_not_found");
    // Globex's token means nothing at Acme.
    let elsewhere = world
        .send(
            Method::GET,
            "/t/acme/api/v1/admin/keys/sig",
            Some(&authorization),
            None,
        )
        .await;
    assert_eq!(elsewhere.status, StatusCode::UNAUTHORIZED);

    let acme = world.as_administrator(Method::GET, "/keys/sig", None).await;
    assert_eq!(acme.body["items"][0]["state"], "active");
}

#[tokio::test]
async fn without_keys_to_wrap_them_with_the_key_routes_say_so() {
    let world = world_with_keys(false).await;
    for (method, path) in [
        (Method::GET, "/keys/sig".to_owned()),
        (Method::POST, "/keys/sig:rotate".to_owned()),
        (
            Method::POST,
            format!("/keys/sig/versions/{}:revoke", UserId::generate()),
        ),
    ] {
        let reply = world
            .as_administrator(
                method.clone(),
                &path,
                Some(serde_json::json!({ "reason": "test" })),
            )
            .await;
        assert_eq!(
            reply.status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{method} {path}"
        );
        assert_eq!(reply.code(), "keys.not_configured", "{method} {path}");
    }
}

// Applications, clients and resource servers.

/// Registers an application in Acme and answers its identifier.
async fn new_application(world: &World, name: &str, first_party: bool) -> String {
    let created = world
        .as_administrator(
            Method::POST,
            "/applications",
            Some(serde_json::json!({ "name": name, "first_party": first_party })),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    created.body["id"].as_str().expect("id").to_owned()
}

/// The sector identifier address of the tests, which lists the redirect
/// addresses of the clients of `billing.example.com` and
/// `billing.example.net`.
const SECTOR_DOCUMENT: &str = "https://sector.example.org/redirect_uris.json";

fn sector_documents() -> hodor_oauth::testing::SectorDocuments {
    let documents = hodor_oauth::testing::SectorDocuments::default();
    documents.answer(
        SECTOR_DOCUMENT,
        200,
        r#"["https://billing.example.com/callback", "https://billing.example.net/callback"]"#,
    );
    documents.answer(
        "https://sector.example.org/short.json",
        200,
        r#"["https://billing.example.com/callback"]"#,
    );
    documents.answer("https://sector.example.org/object.json", 200, "{}");
    documents.answer("https://sector.example.org/gone.json", 404, "");
    documents
}

fn web_client() -> serde_json::Value {
    serde_json::json!({
        "name": "Billing web site",
        "type": "confidential",
        "grant_types": ["authorization_code", "refresh_token"],
        "redirect_uris": ["https://billing.example.com/callback"],
        "allowed_scopes": ["openid", "email"],
    })
}

#[tokio::test]
async fn an_administrator_registers_an_application_with_its_clients_and_resource_server() {
    let world = world().await;
    let application = new_application(&world, "Billing", true).await;
    let read = world
        .as_administrator(Method::GET, &format!("/applications/{application}"), None)
        .await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.body["name"], "Billing");
    assert_eq!(read.body["first_party"], true);
    assert_eq!(read.body["status"], "enabled");

    // A change leaves out what stays.
    let changed = world
        .as_administrator(
            Method::PATCH,
            &format!("/applications/{application}"),
            Some(serde_json::json!({ "name": "Billing and invoices" })),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK);
    assert_eq!(changed.body["name"], "Billing and invoices");
    assert_eq!(changed.body["first_party"], true);

    let created = world
        .as_administrator(
            Method::POST,
            &format!("/applications/{application}/clients"),
            Some(web_client()),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(created.body["type"], "confidential");
    assert_eq!(created.body["authentication_method"], "client_secret_basic");
    assert_eq!(created.body["require_pkce"], true);
    assert_eq!(created.body["token_policy"]["access_token_seconds"], 300);
    assert!(
        created.body["client_secret"]
            .as_str()
            .is_some_and(|secret| secret.starts_with("hodor_cs_")),
        "the first secret, once: {}",
        created.body
    );
    let client = created.body["id"].as_str().expect("client").to_owned();

    let listed = world
        .as_administrator(
            Method::GET,
            &format!("/applications/{application}/clients"),
            None,
        )
        .await;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body["items"][0]["id"], client.as_str());

    // Changed settings are checked as a whole; the token policy takes
    // any of its fields.
    let changed = world
        .as_administrator(
            Method::PATCH,
            &format!("/clients/{client}"),
            Some(serde_json::json!({
                "redirect_uris": ["https://billing.example.com/callback", "https://billing.example.com/other"],
                "post_logout_redirect_uris": ["https://billing.example.com/signed-out"],
                "token_policy": { "access_token_seconds": 600 },
            })),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.body);
    assert_eq!(
        changed.body["redirect_uris"].as_array().map(Vec::len),
        Some(2)
    );
    assert_eq!(
        changed.body["post_logout_redirect_uris"],
        serde_json::json!(["https://billing.example.com/signed-out"])
    );
    assert_eq!(changed.body["token_policy"]["access_token_seconds"], 600);
    assert_eq!(changed.body["token_policy"]["id_token_seconds"], 300);

    // A new secret is shown once; the newest previous keeps working.
    let rotated = world
        .as_administrator(Method::POST, &format!("/clients/{client}/secrets"), None)
        .await;
    assert_eq!(rotated.status, StatusCode::CREATED, "{}", rotated.body);
    let new_secret = rotated.body["id"].as_str().expect("secret").to_owned();
    let now = world
        .as_administrator(Method::GET, &format!("/clients/{client}"), None)
        .await;
    assert_eq!(now.body["secrets"].as_array().map(Vec::len), Some(2));
    let revoked = world
        .as_administrator(
            Method::DELETE,
            &format!("/clients/{client}/secrets/{new_secret}"),
            None,
        )
        .await;
    assert_eq!(revoked.status, StatusCode::NO_CONTENT);
    let now = world
        .as_administrator(Method::GET, &format!("/clients/{client}"), None)
        .await;
    assert_eq!(now.body["secrets"].as_array().map(Vec::len), Some(1));

    let disabled = world
        .as_administrator(Method::POST, &format!("/clients/{client}:disable"), None)
        .await;
    assert_eq!(disabled.body["status"], "disabled");
    let enabled = world
        .as_administrator(Method::POST, &format!("/clients/{client}:enable"), None)
        .await;
    assert_eq!(enabled.body["status"], "enabled");
    let disabled = world
        .as_administrator(
            Method::POST,
            &format!("/applications/{application}:disable"),
            None,
        )
        .await;
    assert_eq!(disabled.body["status"], "disabled");
    let unknown = world
        .as_administrator(
            Method::POST,
            &format!("/applications/{application}:archive"),
            None,
        )
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown.code(), "route.not_found");

    let server = world
        .as_administrator(
            Method::POST,
            "/resource-servers",
            Some(serde_json::json!({
                "application_id": application,
                "audience": "https://api.billing.example.com",
                "name": "Billing interface",
                "scopes": [{ "name": "invoices:read", "description": "Read your invoices" }],
            })),
        )
        .await;
    assert_eq!(server.status, StatusCode::CREATED, "{}", server.body);
    let id = server.body["id"].as_str().expect("id").to_owned();
    let changed = world
        .as_administrator(
            Method::PATCH,
            &format!("/resource-servers/{id}"),
            Some(serde_json::json!({
                "scopes": [
                    { "name": "invoices:read", "description": "Read your invoices" },
                    { "name": "invoices:write" },
                ],
            })),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.body);
    assert_eq!(changed.body["audience"], "https://api.billing.example.com");
    assert_eq!(changed.body["scopes"][1]["name"], "invoices:write");
    let listed = world
        .as_administrator(Method::GET, "/resource-servers", None)
        .await;
    assert_eq!(listed.body["items"][0]["id"], id.as_str());
    // The audience can never change: the field is not taken.
    let refused = world
        .as_administrator(
            Method::PATCH,
            &format!("/resource-servers/{id}"),
            Some(serde_json::json!({ "audience": "https://elsewhere.example.com" })),
        )
        .await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);

    // Every change is announced, under the administrator's name.
    world.record_audit().await;
    let records = world
        .as_administrator(Method::GET, "/audit-records?limit=200", None)
        .await;
    let said = records.body.to_string();
    for event in [
        "oauth.application_created",
        "oauth.application_changed",
        "oauth.application_disabled",
        "oauth.client_created",
        "oauth.client_changed",
        "oauth.client_secret_issued",
        "oauth.client_secret_revoked",
        "oauth.client_disabled",
        "oauth.client_enabled",
        "oauth.resource_server_created",
        "oauth.resource_server_changed",
    ] {
        assert!(said.contains(event), "{event}");
    }
    assert!(said.contains(&world.administrator.to_string()));
}

#[tokio::test]
async fn a_client_secret_is_shown_only_in_the_answers_that_make_it() {
    let world = world().await;
    let application = new_application(&world, "Billing", true).await;
    let created = world
        .as_administrator(
            Method::POST,
            &format!("/applications/{application}/clients"),
            Some(web_client()),
        )
        .await;
    let first = created.body["client_secret"]
        .as_str()
        .expect("first secret")
        .to_owned();
    let client = created.body["id"].as_str().expect("client").to_owned();
    let rotated = world
        .as_administrator(
            Method::POST,
            &format!("/clients/{client}/secrets"),
            Some(serde_json::json!({ "lifetime_days": 30, "keep_previous_days": 0 })),
        )
        .await;
    assert_eq!(rotated.status, StatusCode::CREATED, "{}", rotated.body);
    let second = rotated.body["client_secret"]
        .as_str()
        .expect("second secret")
        .to_owned();
    assert_ne!(first, second);
    // Ending the previous at once leaves one secret.
    let path = format!("/clients/{client}");
    let now = world.as_administrator(Method::GET, &path, None).await;
    assert_eq!(now.body["secrets"].as_array().map(Vec::len), Some(1));

    let answers = [
        now,
        world
            .as_administrator(
                Method::GET,
                &format!("/applications/{application}/clients"),
                None,
            )
            .await,
        world
            .as_administrator(
                Method::PATCH,
                &path,
                Some(serde_json::json!({ "name": "Renamed" })),
            )
            .await,
        world
            .as_administrator(Method::POST, &format!("{path}:disable"), None)
            .await,
    ];
    for answer in &answers {
        let body = answer.body.to_string();
        assert_eq!(answer.status, StatusCode::OK, "{body}");
        assert!(!body.contains(&first), "{body}");
        assert!(!body.contains(&second), "{body}");
        assert!(!body.contains("\"client_secret\":"), "{body}");
        assert!(!body.contains("hash"), "{body}");
    }
    // Nor is either secret announced.
    let said = format!("{:?}", world.units_of_work.committed_events());
    assert!(!said.contains(&first));
    assert!(!said.contains(&second));

    // A public client has no secret, so its answer has none.
    let public = world
        .as_administrator(
            Method::POST,
            &format!("/applications/{application}/clients"),
            Some(serde_json::json!({
                "name": "Billing mobile application",
                "type": "public",
                "grant_types": ["authorization_code"],
                "redirect_uris": ["com.example.billing:/callback"],
            })),
        )
        .await;
    assert_eq!(public.status, StatusCode::CREATED, "{}", public.body);
    assert_eq!(public.body["authentication_method"], "none");
    assert!(public.body.get("client_secret").is_none());
    let public_id = public.body["id"].as_str().expect("id").to_owned();
    let refused = world
        .as_administrator(Method::POST, &format!("/clients/{public_id}/secrets"), None)
        .await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(refused.code(), "oauth.client_secret_not_allowed");
}

#[tokio::test]
async fn keys_are_added_without_a_private_part_and_removed_by_their_kid() {
    let world = world().await;
    let application = new_application(&world, "Reports", true).await;
    let mut settings = web_client();
    settings["authentication_method"] = "private_key_jwt".into();
    let created = world
        .as_administrator(
            Method::POST,
            &format!("/applications/{application}/clients"),
            Some(settings),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    // A client that proves itself with a key gets no secret.
    assert!(created.body.get("client_secret").is_none());
    let client = created.body["id"].as_str().expect("client").to_owned();
    let key = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "kid": "2026/11+a",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    });
    let mut private = key.clone();
    private["d"] = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI".into();
    let refused = world
        .as_administrator(
            Method::POST,
            &format!("/clients/{client}/keys"),
            Some(serde_json::json!({ "jwk": private })),
        )
        .await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(refused.code(), "oauth.client_key_invalid");

    let added = world
        .as_administrator(
            Method::POST,
            &format!("/clients/{client}/keys"),
            Some(serde_json::json!({ "jwk": key })),
        )
        .await;
    assert_eq!(added.status, StatusCode::CREATED, "{}", added.body);
    assert_eq!(added.body["keys"][0]["kid"], "2026/11+a");
    assert_eq!(added.body["keys"][0]["jwk"]["crv"], "P-256");
    let again = world
        .as_administrator(
            Method::POST,
            &format!("/clients/{client}/keys"),
            Some(serde_json::json!({ "jwk": key })),
        )
        .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.code(), "oauth.client_key_taken");

    // The `kid` is written in the path with percent-encoding.
    let removed = world
        .as_administrator(
            Method::DELETE,
            &format!("/clients/{client}/keys/2026%2F11%2Ba"),
            None,
        )
        .await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    let now = world
        .as_administrator(Method::GET, &format!("/clients/{client}"), None)
        .await;
    assert_eq!(now.body["keys"].as_array().map(Vec::len), Some(0));
    let gone = world
        .as_administrator(
            Method::DELETE,
            &format!("/clients/{client}/keys/2026%2F11%2Ba"),
            None,
        )
        .await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
    assert_eq!(gone.code(), "oauth.client_key_not_found");
}

#[tokio::test]
async fn what_breaks_a_rule_of_a_client_is_refused_with_its_code() {
    let world = world().await;
    let application = new_application(&world, "Billing", true).await;
    let path = format!("/applications/{application}/clients");
    let cases: [(&str, Change, &str); 6] = [
        (
            "a kind of client that does not exist",
            |body| body["type"] = "trusted".into(),
            "oauth.client_type_invalid",
        ),
        (
            "a public client with a secret",
            |body| {
                body["type"] = "public".into();
                body["authentication_method"] = "client_secret_basic".into();
            },
            "oauth.client_authentication_method_invalid",
        ),
        (
            "a redirect address over plain HTTP",
            |body| {
                body["redirect_uris"] = serde_json::json!(["http://billing.example.com/callback"])
            },
            "oauth.client_redirect_uri_invalid",
        ),
        (
            "a grant that does not exist",
            |body| body["grant_types"] = serde_json::json!(["password"]),
            "oauth.client_grants_invalid",
        ),
        (
            "an access token that lives a day",
            |body| body["token_policy"] = serde_json::json!({ "access_token_seconds": 86400 }),
            "oauth.token_policy_invalid",
        ),
        (
            "a secret that lives ten years",
            |body| body["secret_lifetime_days"] = 3650.into(),
            "oauth.client_secret_lifetime_invalid",
        ),
    ];
    for (what, change, code) in cases {
        let mut body = web_client();
        change(&mut body);
        let reply = world
            .as_administrator(Method::POST, &path, Some(body))
            .await;
        assert_eq!(
            reply.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{what}: {}",
            reply.body
        );
        assert_eq!(reply.code(), code, "{what}");
    }
    // Nothing was created by any of them.
    let listed = world.as_administrator(Method::GET, &path, None).await;
    assert_eq!(listed.body["items"].as_array().map(Vec::len), Some(0));

    // Whether an application is first party is never assumed.
    let missing = world
        .as_administrator(
            Method::POST,
            "/applications",
            Some(serde_json::json!({ "name": "Billing" })),
        )
        .await;
    assert_eq!(missing.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(missing.code(), "request.body_invalid");
}

#[tokio::test]
async fn a_client_names_how_it_signs_its_request_objects() {
    let world = world().await;
    let application = new_application(&world, "Billing", true).await;
    let path = format!("/applications/{application}/clients");

    // None chosen unless given.
    let created = world
        .as_administrator(Method::POST, &path, Some(web_client()))
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(
        created.body["request_object_signing_alg"],
        serde_json::Value::Null
    );
    let client = created.body["id"].as_str().expect("id").to_owned();
    let client_path = format!("/clients/{client}");

    // Given when it is made.
    let mut body = web_client();
    body["request_object_signing_alg"] = "PS256".into();
    let named = world
        .as_administrator(Method::POST, &path, Some(body))
        .await;
    assert_eq!(named.status, StatusCode::CREATED, "{}", named.body);
    assert_eq!(named.body["request_object_signing_alg"], "PS256");

    // Changed to `none`, kept through a change of something else, and
    // removed with `null`.
    let changed = world
        .as_administrator(
            Method::PATCH,
            &client_path,
            Some(serde_json::json!({ "request_object_signing_alg": "none" })),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.body);
    assert_eq!(changed.body["request_object_signing_alg"], "none");
    let renamed = world
        .as_administrator(
            Method::PATCH,
            &client_path,
            Some(serde_json::json!({ "name": "Billing site" })),
        )
        .await;
    assert_eq!(renamed.body["request_object_signing_alg"], "none");
    let removed = world
        .as_administrator(
            Method::PATCH,
            &client_path,
            Some(serde_json::json!({ "request_object_signing_alg": null })),
        )
        .await;
    assert_eq!(removed.status, StatusCode::OK, "{}", removed.body);
    assert_eq!(
        removed.body["request_object_signing_alg"],
        serde_json::Value::Null
    );
    let read = world
        .as_administrator(Method::GET, &client_path, None)
        .await;
    assert_eq!(
        read.body["request_object_signing_alg"],
        serde_json::Value::Null
    );

    // An algorithm Hodor does not check is refused, when it is made and
    // when it is changed, and changes nothing.
    for refused in ["HS256", "None", "EdDSA"] {
        let mut body = web_client();
        body["request_object_signing_alg"] = refused.into();
        let reply = world
            .as_administrator(Method::POST, &path, Some(body))
            .await;
        assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY, "{refused}");
        assert_eq!(
            reply.code(),
            "oauth.client_request_object_algorithm_invalid"
        );
        let reply = world
            .as_administrator(
                Method::PATCH,
                &client_path,
                Some(serde_json::json!({ "request_object_signing_alg": refused })),
            )
            .await;
        assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY, "{refused}");
        assert_eq!(
            reply.code(),
            "oauth.client_request_object_algorithm_invalid"
        );
    }
    let read = world
        .as_administrator(Method::GET, &client_path, None)
        .await;
    assert_eq!(
        read.body["request_object_signing_alg"],
        serde_json::Value::Null
    );
}

#[tokio::test]
async fn a_client_gets_a_back_channel_logout_address_checked_as_a_webhook_endpoint() {
    let world = world().await;
    let application = new_application(&world, "Billing", true).await;
    let path = format!("/applications/{application}/clients");
    let mut body = web_client();
    body["backchannel_logout_uri"] = "https://billing.example.com/backchannel-logout".into();
    body["backchannel_logout_session_required"] = true.into();
    let created = world
        .as_administrator(Method::POST, &path, Some(body))
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(
        created.body["backchannel_logout_uri"],
        "https://billing.example.com/backchannel-logout"
    );
    assert_eq!(created.body["backchannel_logout_session_required"], true);
    let client = created.body["id"].as_str().expect("client").to_owned();

    // Unless given, a client has none.
    let plain = world
        .as_administrator(Method::POST, &path, Some(web_client()))
        .await;
    assert_eq!(
        plain.body["backchannel_logout_uri"],
        serde_json::Value::Null
    );
    assert_eq!(plain.body["backchannel_logout_session_required"], false);

    for (address, code) in [
        (
            "https://localhost/logout",
            "oauth.client_backchannel_logout_uri_forbidden",
        ),
        (
            "https://10.0.0.7/logout",
            "oauth.client_backchannel_logout_uri_forbidden",
        ),
        (
            "https://nowhere.example/logout",
            "oauth.client_backchannel_logout_uri_unresolvable",
        ),
        (
            "http://billing.example.com/logout",
            "oauth.client_backchannel_logout_uri_invalid",
        ),
        (
            "https://billing.example.com/logout#fragment",
            "oauth.client_backchannel_logout_uri_invalid",
        ),
    ] {
        let refused = world
            .as_administrator(
                Method::PATCH,
                &format!("/clients/{client}"),
                Some(serde_json::json!({ "backchannel_logout_uri": address })),
            )
            .await;
        assert_eq!(
            refused.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{address}: {}",
            refused.body
        );
        assert_eq!(refused.code(), code, "{address}");
    }

    // Removing the address while `sid` is still required breaks a rule;
    // removing both is a change.
    let alone = world
        .as_administrator(
            Method::PATCH,
            &format!("/clients/{client}"),
            Some(serde_json::json!({ "backchannel_logout_uri": null })),
        )
        .await;
    assert_eq!(alone.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(alone.code(), "oauth.client_backchannel_logout_uri_invalid");
    let removed = world
        .as_administrator(
            Method::PATCH,
            &format!("/clients/{client}"),
            Some(serde_json::json!({
                "backchannel_logout_uri": null,
                "backchannel_logout_session_required": false,
            })),
        )
        .await;
    assert_eq!(removed.status, StatusCode::OK, "{}", removed.body);
    assert_eq!(
        removed.body["backchannel_logout_uri"],
        serde_json::Value::Null
    );
    assert_eq!(removed.body["backchannel_logout_session_required"], false);

    // A client that signs nobody in has no address.
    let mut service = web_client();
    service["grant_types"] = serde_json::json!(["client_credentials"]);
    service
        .as_object_mut()
        .expect("object")
        .remove("redirect_uris");
    service["backchannel_logout_uri"] = "https://billing.example.com/logout".into();
    let refused = world
        .as_administrator(Method::POST, &path, Some(service))
        .await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        refused.code(),
        "oauth.client_backchannel_logout_uri_invalid"
    );
}

#[tokio::test]
async fn a_client_is_made_pairwise_with_its_sector_checked_and_fetched() {
    let world = world().await;
    let application = new_application(&world, "Billing", true).await;
    let path = format!("/applications/{application}/clients");

    // Unless given, a client is public.
    let plain = world
        .as_administrator(Method::POST, &path, Some(web_client()))
        .await;
    assert_eq!(plain.status, StatusCode::CREATED, "{}", plain.body);
    assert_eq!(plain.body["subject_type"], "public");
    assert_eq!(plain.body["sector_identifier_uri"], serde_json::Value::Null);

    // One host is a sector.
    let mut body = web_client();
    body["subject_type"] = "pairwise".into();
    let pairwise = world
        .as_administrator(Method::POST, &path, Some(body.clone()))
        .await;
    assert_eq!(pairwise.status, StatusCode::CREATED, "{}", pairwise.body);
    assert_eq!(pairwise.body["subject_type"], "pairwise");

    // Two hosts need a sector identifier address that lists both.
    body["redirect_uris"] = serde_json::json!([
        "https://billing.example.com/callback",
        "https://billing.example.net/callback"
    ]);
    let refused = world
        .as_administrator(Method::POST, &path, Some(body.clone()))
        .await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        refused.code(),
        "oauth.client_sector_identifier_uri_required"
    );
    body["sector_identifier_uri"] = SECTOR_DOCUMENT.into();
    let named = world
        .as_administrator(Method::POST, &path, Some(body.clone()))
        .await;
    assert_eq!(named.status, StatusCode::CREATED, "{}", named.body);
    assert_eq!(named.body["sector_identifier_uri"], SECTOR_DOCUMENT);
    let client = named.body["id"].as_str().expect("client").to_owned();

    for (address, code) in [
        (
            "https://sector.example.org/short.json",
            "oauth.client_sector_identifier_uri_mismatch",
        ),
        (
            "https://sector.example.org/object.json",
            "oauth.client_sector_identifier_uri_document_invalid",
        ),
        (
            "https://sector.example.org/gone.json",
            "oauth.client_sector_identifier_uri_unreachable",
        ),
        (
            "https://sector.example.org/unanswered.json",
            "oauth.client_sector_identifier_uri_unreachable",
        ),
        (
            "https://localhost/uris.json",
            "oauth.client_sector_identifier_uri_forbidden",
        ),
        (
            "https://nowhere.example/uris.json",
            "oauth.client_sector_identifier_uri_unresolvable",
        ),
        (
            "ftp://sector.example.org/uris.json",
            "oauth.client_sector_identifier_uri_invalid",
        ),
    ] {
        let refused = world
            .as_administrator(
                Method::PATCH,
                &format!("/clients/{client}"),
                Some(serde_json::json!({ "sector_identifier_uri": address })),
            )
            .await;
        assert_eq!(
            refused.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{address}: {}",
            refused.body
        );
        assert_eq!(refused.code(), code, "{address}");
    }

    // Back to one host, without the address, then public again.
    let changed = world
        .as_administrator(
            Method::PATCH,
            &format!("/clients/{client}"),
            Some(serde_json::json!({
                "redirect_uris": ["https://billing.example.com/callback"],
                "sector_identifier_uri": null,
            })),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.body);
    assert_eq!(
        changed.body["sector_identifier_uri"],
        serde_json::Value::Null
    );
    let public = world
        .as_administrator(
            Method::PATCH,
            &format!("/clients/{client}"),
            Some(serde_json::json!({ "subject_type": "public" })),
        )
        .await;
    assert_eq!(public.status, StatusCode::OK, "{}", public.body);
    assert_eq!(public.body["subject_type"], "public");

    // An unknown subject type, an address on a public client, and a
    // client that signs nobody in.
    let mut unknown = web_client();
    unknown["subject_type"] = "secret".into();
    let refused = world
        .as_administrator(Method::POST, &path, Some(unknown))
        .await;
    assert_eq!(refused.code(), "oauth.client_subject_type_invalid");
    let mut public_with_address = web_client();
    public_with_address["sector_identifier_uri"] = SECTOR_DOCUMENT.into();
    let refused = world
        .as_administrator(Method::POST, &path, Some(public_with_address))
        .await;
    assert_eq!(refused.code(), "oauth.client_sector_identifier_uri_invalid");
    let mut service = web_client();
    service["grant_types"] = serde_json::json!(["client_credentials"]);
    service
        .as_object_mut()
        .expect("object")
        .remove("redirect_uris");
    service["subject_type"] = "pairwise".into();
    let refused = world
        .as_administrator(Method::POST, &path, Some(service))
        .await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(refused.code(), "oauth.client_subject_type_invalid");
}

#[tokio::test]
async fn the_applications_of_one_tenant_do_not_exist_for_another() {
    let world = world().await;
    let application = new_application(&world, "Billing", true).await;
    let created = world
        .as_administrator(
            Method::POST,
            &format!("/applications/{application}/clients"),
            Some(web_client()),
        )
        .await;
    let client = created.body["id"].as_str().expect("client").to_owned();
    let (_, globex_token) = world
        .person(
            &world.globex,
            "root@globex.example",
            &[Role::TenantAdministrator],
        )
        .await;
    let as_globex = |method: Method, path: String, body: Option<serde_json::Value>| {
        let token = format!("Bearer {globex_token}");
        let world = &world;
        async move {
            world
                .send(
                    method,
                    &format!("/t/globex/api/v1/admin{path}"),
                    Some(&token),
                    body,
                )
                .await
        }
    };
    for (method, path, code) in [
        (
            Method::GET,
            format!("/applications/{application}"),
            "oauth.application_not_found",
        ),
        (
            Method::POST,
            format!("/applications/{application}:disable"),
            "oauth.application_not_found",
        ),
        (
            Method::GET,
            format!("/applications/{application}/clients"),
            "oauth.application_not_found",
        ),
        (
            Method::GET,
            format!("/clients/{client}"),
            "oauth.client_not_found",
        ),
        (
            Method::POST,
            format!("/clients/{client}/secrets"),
            "oauth.client_not_found",
        ),
        (
            Method::POST,
            format!("/clients/{client}:disable"),
            "oauth.client_not_found",
        ),
    ] {
        let reply = as_globex(method.clone(), path.clone(), None).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{method} {path}");
        assert_eq!(reply.code(), code, "{method} {path}");
    }
    let listed = as_globex(Method::GET, "/applications".to_owned(), None).await;
    assert_eq!(listed.body["items"].as_array().map(Vec::len), Some(0));
    // A client of Globex cannot be put in Acme's application either.
    let foreign = as_globex(
        Method::POST,
        format!("/applications/{application}/clients"),
        Some(web_client()),
    )
    .await;
    assert_eq!(foreign.status, StatusCode::NOT_FOUND);
    // And Acme's client is as it was.
    let still = world
        .as_administrator(Method::GET, &format!("/clients/{client}"), None)
        .await;
    assert_eq!(still.body["status"], "enabled");
    assert_eq!(still.body["secrets"].as_array().map(Vec::len), Some(1));
}

#[tokio::test]
async fn an_administrator_reads_and_replaces_the_assurance_levels_of_their_tenant_only() {
    let world = world().await;
    let defaults = world
        .as_administrator(Method::GET, "/assurance-levels", None)
        .await;
    assert_eq!(defaults.status, StatusCode::OK, "{:?}", defaults.body);
    assert_eq!(
        defaults.body,
        serde_json::json!({ "levels": [
            { "acr": "urn:hodor:acr:single-factor", "requirement": "single_factor" },
            { "acr": "urn:hodor:acr:mfa", "requirement": "multi_factor" },
        ]})
    );

    let replaced = world
        .as_administrator(
            Method::PUT,
            "/assurance-levels",
            Some(serde_json::json!({ "levels": [
                { "acr": "urn:acme:strong", "requirement": "phishing_resistant" },
                { "acr": "urn:acme:mfa", "requirement": "multi_factor" },
            ]})),
        )
        .await;
    assert_eq!(replaced.status, StatusCode::OK, "{:?}", replaced.body);
    assert_eq!(
        replaced.body["levels"][0]["acr"], "urn:acme:mfa",
        "weakest first"
    );
    let read = world
        .as_administrator(Method::GET, "/assurance-levels", None)
        .await;
    assert_eq!(read.body, replaced.body);

    // Globex keeps its own.
    let (_, globex) = world
        .person(
            &world.globex,
            "root@globex.example",
            &[Role::TenantAdministrator],
        )
        .await;
    let theirs = world
        .send(
            Method::GET,
            "/t/globex/api/v1/admin/assurance-levels",
            Some(&format!("Bearer {globex}")),
            None,
        )
        .await;
    assert_eq!(theirs.body, defaults.body);

    world.record_audit().await;
    let records = world
        .as_administrator(Method::GET, "/audit-records", None)
        .await;
    assert!(
        records.body["items"]
            .as_array()
            .expect("items")
            .iter()
            .any(|record| record["action"] == "tenant.settings_changed"),
        "{:?}",
        records.body
    );
}

#[tokio::test]
async fn levels_that_break_a_rule_are_refused_and_an_auditor_only_reads_them() {
    let world = world().await;
    for levels in [
        serde_json::json!({ "levels": [] }),
        serde_json::json!({ "levels": [{ "acr": "has space", "requirement": "single_factor" }] }),
        serde_json::json!({ "levels": [
            { "acr": "same", "requirement": "single_factor" },
            { "acr": "same", "requirement": "multi_factor" },
        ]}),
    ] {
        let refused = world
            .as_administrator(Method::PUT, "/assurance-levels", Some(levels))
            .await;
        assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(refused.code(), "tenant.settings_invalid");
    }
    let unknown = world
        .as_administrator(
            Method::PUT,
            "/assurance-levels",
            Some(serde_json::json!({ "levels": [{ "acr": "x", "requirement": "very_strong" }] })),
        )
        .await;
    assert_eq!(unknown.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(unknown.code(), "request.body_invalid");

    let acme = world.acme.clone();
    let (_, auditor) = world
        .person(&acme, "auditor@example.com", &[Role::TenantAuditor])
        .await;
    let authorization = format!("Bearer {auditor}");
    let read = world
        .send(
            Method::GET,
            "/t/acme/api/v1/admin/assurance-levels",
            Some(&authorization),
            None,
        )
        .await;
    assert_eq!(read.status, StatusCode::OK);
    let written = world
        .send(
            Method::PUT,
            "/t/acme/api/v1/admin/assurance-levels",
            Some(&authorization),
            Some(serde_json::json!({ "levels": [{ "acr": "x", "requirement": "single_factor" }] })),
        )
        .await;
    assert_eq!(written.status, StatusCode::FORBIDDEN);
}

impl World {
    /// Gives a person an authenticator application in use, as their pages
    /// would, and moves past the step of the code that confirmed it.
    async fn give_application(&self, user: UserId) {
        use hodor_kernel::Clock as _;
        let enrollment = self
            .totp
            .begin_enrollment(&self.acme, user, "acme", "ana@example.com")
            .await
            .expect("begin");
        let code = hodor_credential::api::totp_code_at(
            &hodor_credential::testing::FakeHmacSha1,
            &hodor_credential::testing::base32_secret(enrollment.secret()),
            self.clock.now(),
        );
        self.totp
            .confirm_enrollment(
                &self.acme,
                user,
                &hodor_kernel::Secret::from(code),
                Caller::system(),
            )
            .await
            .expect("confirm");
        self.clock
            .advance(Duration::seconds(hodor_credential::api::STEP_SECONDS));
    }

    /// Gives a person a key, as a finished registration would.
    async fn give_key(&self, user: UserId) -> hodor_credential::api::WebAuthnCredentialId {
        use hodor_credential::api::WebAuthnStore as _;
        use hodor_kernel::Clock as _;
        let key = hodor_credential::testing::stored_credential(
            user,
            hodor_credential::api::WebAuthnCredentialId::generate()
                .as_uuid()
                .as_bytes()
                .to_vec(),
            self.clock.now(),
        );
        let mut uow = self.units_of_work.begin(&self.acme).await.expect("begin");
        self.keys_of_people
            .insert(uow.as_mut(), &key)
            .await
            .expect("insert");
        uow.commit().await.expect("commit");
        key.id()
    }
}

#[tokio::test]
async fn an_administrator_sees_and_removes_a_persons_factors_whatever_the_policy() {
    let world = world().await;
    let acme = world.acme.clone();
    let (ana, _) = world.person(&acme, "ana@example.com", &[]).await;
    world.give_application(ana).await;
    let key = world.give_key(ana).await;
    // The policy requires a second factor: it holds the person back, not
    // an administrator.
    let mut settings = world
        .tenants
        .get(&acme)
        .await
        .expect("tenant")
        .snapshot()
        .settings
        .clone();
    settings.authentication.second_factor = hodor_tenant::api::SecondFactorPolicy::Required;
    world
        .tenants
        .change_settings(&acme, settings, Caller::system())
        .await
        .expect("settings");
    let listed = world
        .as_administrator(Method::GET, &format!("/users/{ana}/factors"), None)
        .await;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body["authenticator_application"]["in_use"], true);
    assert_eq!(listed.body["second_factor_required"], true);
    assert_eq!(listed.body["keys"][0]["id"], key.to_string());
    assert_eq!(listed.body["keys"][0]["name"], "Blue key");
    assert_eq!(listed.body["keys"][0]["passkey"], true);
    assert!(listed.body.get("recent_sign_in_until").is_none());
    // Nothing of a key's material is in the answer.
    assert!(listed.body["keys"][0].get("public_key").is_none());
    assert!(listed.body["keys"][0].get("credential_id").is_none());

    let removed = world
        .as_administrator(
            Method::DELETE,
            &format!("/users/{ana}/factors/authenticator-application"),
            None,
        )
        .await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    let again = world
        .as_administrator(
            Method::DELETE,
            &format!("/users/{ana}/factors/authenticator-application"),
            None,
        )
        .await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);
    assert_eq!(again.code(), "credential.totp_not_found");

    // The last second factor goes too, for an administrator.
    let removed = world
        .as_administrator(
            Method::DELETE,
            &format!("/users/{ana}/factors/keys/{key}"),
            None,
        )
        .await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    let left = world
        .as_administrator(Method::GET, &format!("/users/{ana}/factors"), None)
        .await;
    assert_eq!(left.body["authenticator_application"]["in_use"], false);
    assert_eq!(left.body["keys"].as_array().map(Vec::len), Some(0));
    assert_eq!(left.body["recovery_codes"]["remaining"], 0);

    let none = world
        .as_administrator(
            Method::DELETE,
            &format!("/users/{ana}/factors/recovery-codes"),
            None,
        )
        .await;
    assert_eq!(none.status, StatusCode::NOT_FOUND);
    assert_eq!(none.code(), "credential.recovery_codes_not_found");
    let unknown = world
        .as_administrator(
            Method::DELETE,
            &format!("/users/{ana}/factors/keys/{key}"),
            None,
        )
        .await;
    assert_eq!(unknown.code(), "credential.webauthn_credential_not_found");
}

#[tokio::test]
async fn the_factors_of_a_person_do_not_exist_for_another_tenants_administrator() {
    let world = world().await;
    let acme = world.acme.clone();
    let globex = world.globex.clone();
    let (ana, _) = world.person(&acme, "ana@example.com", &[]).await;
    let key = world.give_key(ana).await;
    let (_, theirs) = world
        .person(&globex, "root@globex.example", &[Role::TenantAdministrator])
        .await;
    let bearer = format!("Bearer {theirs}");
    for (method, path) in [
        (
            Method::GET,
            format!("/t/globex/api/v1/admin/users/{ana}/factors"),
        ),
        (
            Method::DELETE,
            format!("/t/globex/api/v1/admin/users/{ana}/factors/keys/{key}"),
        ),
        (
            Method::DELETE,
            format!("/t/globex/api/v1/admin/users/{ana}/factors/recovery-codes"),
        ),
    ] {
        let reply = world.send(method.clone(), &path, Some(&bearer), None).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{method} {path}");
        assert_eq!(reply.code(), "identity.user_not_found", "{method} {path}");
    }
    // Ana's key is still hers.
    let listed = world
        .as_administrator(Method::GET, &format!("/users/{ana}/factors"), None)
        .await;
    assert_eq!(listed.body["keys"].as_array().map(Vec::len), Some(1));
}

/// Ana agrees, as the consent page would, to what `client` asks for.
async fn agreed(world: &World, user: UserId, client: &str) {
    let request = hodor_oauth::api::AuthorizationRequest {
        client_id: client.parse().expect("client"),
        redirect_uri: "https://billing.example.com/callback".to_owned(),
        scopes: vec!["openid".to_owned(), "email".to_owned()],
        audiences: Vec::new(),
        code_challenge: None,
        state: None,
        nonce: None,
        prompt: Vec::new(),
        max_age: None,
        login_hint: None,
        ui_locales: None,
        acr_values: None,
        first_party: false,
        organization: None,
    };
    let person = hodor_oauth::api::SignedInPerson {
        user_id: user,
        session_id: hodor_session::api::SessionId::generate(),
        signed_in_at: Timestamp::UNIX_EPOCH,
        methods: vec!["password".to_owned()],
        acr: None,
    };
    let (id, secret) = world
        .consents
        .hold(&world.acme, request, &person)
        .await
        .expect("held");
    assert!(
        world
            .consents
            .answer(
                &world.acme,
                id,
                secret.expose(),
                &person,
                hodor_oauth::api::ConsentAnswer::Agreed,
                Caller::system(),
            )
            .await
            .expect("answered")
    );
}

#[tokio::test]
async fn an_administrator_sees_and_withdraws_a_users_consent() {
    let world = world().await;
    let acme = world.acme.clone();
    let (ana, _) = world.person(&acme, "ana@example.com", &[]).await;
    let application = new_application(&world, "Billing", false).await;
    let created = world
        .as_administrator(
            Method::POST,
            &format!("/applications/{application}/clients"),
            Some(web_client()),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(
        created.body["token_policy"]["consent_seconds"],
        365 * 86400,
        "a consent lasts a year unless the client says otherwise"
    );
    let client = created.body["id"].as_str().expect("client").to_owned();
    agreed(&world, ana, &client).await;

    let listed = world
        .as_administrator(Method::GET, &format!("/users/{ana}/consents"), None)
        .await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.body);
    let items = listed.body["items"].as_array().expect("items");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["client_id"], client.as_str());
    assert_eq!(items[0]["application"], "Billing");
    assert_eq!(items[0]["scopes"], serde_json::json!(["openid", "email"]));

    let withdrawn = world
        .as_administrator(
            Method::DELETE,
            &format!("/users/{ana}/consents/{client}"),
            None,
        )
        .await;
    assert_eq!(withdrawn.status, StatusCode::NO_CONTENT);
    let again = world
        .as_administrator(
            Method::DELETE,
            &format!("/users/{ana}/consents/{client}"),
            None,
        )
        .await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);
    assert_eq!(again.code(), "oauth.consent_not_found");
    let remaining = world
        .as_administrator(Method::GET, &format!("/users/{ana}/consents"), None)
        .await;
    assert_eq!(remaining.body["items"].as_array().map(Vec::len), Some(0));

    let nobody = UserId::generate();
    let unknown = world
        .as_administrator(Method::GET, &format!("/users/{nobody}/consents"), None)
        .await;
    assert_eq!(unknown.code(), "identity.user_not_found");
    let events = world.units_of_work.committed_events();
    let withdrawal = events
        .iter()
        .find(|event| event.event_type == "oauth.consent_withdrawn")
        .expect("recorded");
    assert_eq!(withdrawal.payload["by"], "administrator");
}

#[tokio::test]
async fn an_administrator_sets_and_reads_the_record_of_decisions_of_their_tenant_only() {
    use hodor_authorization::api::{DecisionLogStore as _, Effect};
    use hodor_authorization::testing::sample_decision_record;

    let world = world().await;
    let defaults = world
        .as_administrator(Method::GET, "/decision-log", None)
        .await;
    assert_eq!(defaults.status, StatusCode::OK, "{:?}", defaults.body);
    assert_eq!(
        defaults.body,
        serde_json::json!({ "mode": "full", "masks": [], "retention_days": 30 })
    );
    let settings = serde_json::json!({
        "mode": "sampled",
        "allow_sample_percent": 10,
        "masks": ["subject.attributes.email"],
        "retention_days": 90
    });
    let replaced = world
        .as_administrator(Method::PUT, "/decision-log", Some(settings.clone()))
        .await;
    assert_eq!(replaced.status, StatusCode::OK, "{:?}", replaced.body);
    assert_eq!(replaced.body, settings);

    for bad in [
        serde_json::json!({ "mode": "sampled", "retention_days": 30 }),
        serde_json::json!({ "mode": "full", "allow_sample_percent": 5, "retention_days": 30 }),
        serde_json::json!({ "mode": "full", "masks": ["subject.id"], "retention_days": 30 }),
        serde_json::json!({ "mode": "full", "retention_days": 401 }),
    ] {
        let refused = world
            .as_administrator(Method::PUT, "/decision-log", Some(bad))
            .await;
        assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(refused.code(), "authorization.decision_log_invalid");
    }
    let unknown = world
        .as_administrator(
            Method::PUT,
            "/decision-log",
            Some(serde_json::json!({ "mode": "everything", "retention_days": 30 })),
        )
        .await;
    assert_eq!(unknown.code(), "request.body_invalid");

    let older = sample_decision_record(1, Effect::Allow, "ana");
    let newer = sample_decision_record(2, Effect::Deny, "ana");
    let mut uow = hodor_kernel::UnitOfWorkFactory::begin(&world.units_of_work, &world.acme)
        .await
        .expect("begin");
    world
        .decisions
        .append(uow.as_mut(), &[older.clone(), newer.clone()])
        .await
        .expect("append");
    uow.commit().await.expect("commit");

    let page = world
        .as_administrator(Method::GET, "/decisions?limit=1", None)
        .await;
    assert_eq!(page.status, StatusCode::OK, "{:?}", page.body);
    assert_eq!(
        page.body["items"][0]["decision_id"],
        newer.decision_id.to_string()
    );
    assert_eq!(page.body["items"][0]["effect"], "deny");
    assert_eq!(page.body["items"][0]["subject"]["kind"], "user");
    assert_eq!(page.body["items"][0]["resource"]["type"], "document");
    let cursor = page.body["next_cursor"]
        .as_str()
        .expect("a cursor")
        .to_owned();
    let rest = world
        .as_administrator(
            Method::GET,
            &format!("/decisions?limit=1&cursor={cursor}"),
            None,
        )
        .await;
    assert_eq!(
        rest.body["items"][0]["decision_id"],
        older.decision_id.to_string()
    );
    let filtered = world
        .as_administrator(
            Method::GET,
            "/decisions?effect=allow&namespace=https%3A%2F%2Fdocuments.example.com&subject_kind=user&subject_id=ana",
            None,
        )
        .await;
    assert_eq!(filtered.body["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        filtered.body["items"][0]["decision_id"],
        older.decision_id.to_string()
    );
    for bad in ["effect=maybe", "from=yesterday", "subject_kind=user"] {
        let refused = world
            .as_administrator(Method::GET, &format!("/decisions?{bad}"), None)
            .await;
        assert_eq!(refused.code(), "request.query_invalid", "{bad}");
    }

    // Globex sees neither the records nor the settings of Acme.
    let (_, globex) = world
        .person(
            &world.globex,
            "root@globex.example",
            &[Role::TenantAdministrator],
        )
        .await;
    let theirs = world
        .send(
            Method::GET,
            "/t/globex/api/v1/admin/decisions",
            Some(&format!("Bearer {globex}")),
            None,
        )
        .await;
    assert_eq!(theirs.body["items"], serde_json::json!([]));
    let their_settings = world
        .send(
            Method::GET,
            "/t/globex/api/v1/admin/decision-log",
            Some(&format!("Bearer {globex}")),
            None,
        )
        .await;
    assert_eq!(their_settings.body, defaults.body);

    // An auditor reads the record and may not change what it keeps.
    let acme = world.acme.clone();
    let (_, auditor) = world
        .person(&acme, "auditor@example.com", &[Role::TenantAuditor])
        .await;
    let authorization = format!("Bearer {auditor}");
    let read = world
        .send(
            Method::GET,
            "/t/acme/api/v1/admin/decisions",
            Some(&authorization),
            None,
        )
        .await;
    assert_eq!(read.status, StatusCode::OK);
    let refused = world
        .send(
            Method::PUT,
            "/t/acme/api/v1/admin/decision-log",
            Some(&authorization),
            Some(settings),
        )
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn an_administrator_manages_roles_assignments_bindings_and_policy_versions() {
    let world = world().await;
    let application = world
        .as_administrator(
            Method::POST,
            "/applications",
            Some(serde_json::json!({ "name": "Documents", "first_party": true })),
        )
        .await;
    assert_eq!(
        application.status,
        StatusCode::CREATED,
        "{}",
        application.body
    );
    let application = application.body["id"].as_str().expect("id").to_owned();
    let server = world
        .as_administrator(
            Method::POST,
            "/resource-servers",
            Some(serde_json::json!({
                "application_id": application,
                "audience": "https://api.documents.example.com",
                "name": "Documents interface",
            })),
        )
        .await;
    assert_eq!(server.status, StatusCode::CREATED, "{}", server.body);
    let server = server.body["id"].as_str().expect("id").to_owned();
    let namespace = "https://api.documents.example.com";

    // Permissions, then a role that holds them and one that includes it.
    for permission in ["document:read", "document:write"] {
        let declared = world
            .as_administrator(
                Method::PUT,
                &format!("/resource-servers/{server}/permissions/{permission}"),
                Some(serde_json::json!({ "description": "A document" })),
            )
            .await;
        assert_eq!(declared.status, StatusCode::OK, "{}", declared.body);
    }
    let listed = world
        .as_administrator(
            Method::GET,
            &format!("/resource-servers/{server}/permissions"),
            None,
        )
        .await;
    assert_eq!(listed.body["items"][0]["name"], "document:read");
    let reader = world
        .as_administrator(
            Method::PUT,
            &format!("/resource-servers/{server}/roles/reader"),
            Some(serde_json::json!({ "permissions": [{ "name": "document:read" }] })),
        )
        .await;
    assert_eq!(reader.status, StatusCode::OK, "{}", reader.body);
    let editor = world
        .as_administrator(
            Method::PUT,
            &format!("/resource-servers/{server}/roles/editor"),
            Some(serde_json::json!({
                "description": "Edits documents",
                "permissions": [{ "name": "document:write" }],
                "includes": [{ "namespace": namespace, "name": "reader" }],
            })),
        )
        .await;
    assert_eq!(editor.status, StatusCode::OK, "{}", editor.body);
    assert_eq!(editor.body["includes"][0]["name"], "reader");

    // A role leading back to itself, and one holding an undeclared
    // permission, are refused.
    let cycle = world
        .as_administrator(
            Method::PUT,
            &format!("/resource-servers/{server}/roles/reader"),
            Some(serde_json::json!({
                "includes": [{ "namespace": namespace, "name": "editor" }],
            })),
        )
        .await;
    assert_eq!(cycle.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(cycle.code(), "authorization.role_cycle");
    let undeclared = world
        .as_administrator(
            Method::PUT,
            &format!("/resource-servers/{server}/roles/deleter"),
            Some(serde_json::json!({ "permissions": [{ "name": "document:delete" }] })),
        )
        .await;
    assert_eq!(undeclared.code(), "authorization.permission_not_declared");
    // A role another includes cannot be removed.
    let in_use = world
        .as_administrator(
            Method::DELETE,
            &format!("/resource-servers/{server}/roles/reader"),
            None,
        )
        .await;
    assert_eq!(in_use.status, StatusCode::CONFLICT);

    // A role given to a person, for one application, then taken away.
    let given = world
        .as_administrator(
            Method::POST,
            "/role-assignments",
            Some(serde_json::json!({
                "principal": { "kind": "user", "id": world.administrator.to_string() },
                "role": { "namespace": namespace, "name": "editor" },
                "application_id": application,
                "valid_until": "2099-01-01T00:00:00Z",
            })),
        )
        .await;
    assert_eq!(given.status, StatusCode::CREATED, "{}", given.body);
    let held = world
        .as_administrator(
            Method::GET,
            &format!("/users/{}/role-assignments", world.administrator),
            None,
        )
        .await;
    assert_eq!(held.body["items"][0]["role"]["name"], "editor");
    assert_eq!(
        held.body["items"][0]["application_id"],
        application.as_str()
    );

    // A role given to a group, and one scoped to an organization.
    let group = world
        .as_administrator(
            Method::POST,
            "/groups",
            Some(serde_json::json!({ "name": "writers" })),
        )
        .await
        .body["id"]
        .as_str()
        .expect("a group")
        .to_owned();
    let to_group = world
        .as_administrator(
            Method::POST,
            "/role-assignments",
            Some(serde_json::json!({
                "principal": { "kind": "group", "id": group },
                "role": { "namespace": namespace, "name": "reader" },
            })),
        )
        .await;
    assert_eq!(to_group.status, StatusCode::CREATED, "{}", to_group.body);
    let of_group = world
        .as_administrator(
            Method::GET,
            &format!("/groups/{group}/role-assignments"),
            None,
        )
        .await;
    assert_eq!(of_group.body["items"][0]["principal"]["kind"], "group");
    let organization = world
        .as_administrator(
            Method::POST,
            "/organizations",
            Some(serde_json::json!({ "name": "Acme" })),
        )
        .await
        .body["id"]
        .as_str()
        .expect("an organization")
        .to_owned();
    let scoped = world
        .as_administrator(
            Method::POST,
            "/role-assignments",
            Some(serde_json::json!({
                "principal": { "kind": "group", "id": group },
                "role": { "namespace": namespace, "name": "editor" },
                "organization_id": organization,
            })),
        )
        .await;
    assert_eq!(scoped.status, StatusCode::CREATED, "{}", scoped.body);
    assert_eq!(scoped.body["organization_id"], organization.as_str());
    let both = world
        .as_administrator(
            Method::POST,
            "/role-assignments",
            Some(serde_json::json!({
                "principal": { "kind": "group", "id": group },
                "role": { "namespace": namespace, "name": "editor" },
                "organization_id": organization,
                "application_id": application,
            })),
        )
        .await;
    assert_eq!(both.code(), "authorization.scope_invalid");
    let no_group = world
        .as_administrator(
            Method::POST,
            "/role-assignments",
            Some(serde_json::json!({
                "principal": { "kind": "group", "id": UserId::generate().to_string() },
                "role": { "namespace": namespace, "name": "reader" },
            })),
        )
        .await;
    assert_eq!(no_group.code(), "identity.group_not_found");
    let revoked = world
        .as_administrator(
            Method::POST,
            "/role-assignments:revoke",
            Some(serde_json::json!({
                "principal": { "kind": "group", "id": group },
                "role": { "namespace": namespace, "name": "editor" },
                "organization_id": organization,
            })),
        )
        .await;
    assert_eq!(revoked.status, StatusCode::NO_CONTENT, "{}", revoked.body);

    let nobody = world
        .as_administrator(
            Method::POST,
            "/role-assignments",
            Some(serde_json::json!({
                "principal": { "kind": "user", "id": UserId::generate().to_string() },
                "role": { "namespace": namespace, "name": "editor" },
            })),
        )
        .await;
    assert_eq!(nobody.status, StatusCode::NOT_FOUND);
    let revoke = serde_json::json!({
        "principal": { "kind": "user", "id": world.administrator.to_string() },
        "role": { "namespace": namespace, "name": "editor" },
        "application_id": application,
    });
    let taken = world
        .as_administrator(
            Method::POST,
            "/role-assignments:revoke",
            Some(revoke.clone()),
        )
        .await;
    assert_eq!(taken.status, StatusCode::NO_CONTENT, "{}", taken.body);
    let again = world
        .as_administrator(Method::POST, "/role-assignments:revoke", Some(revoke))
        .await;
    assert_eq!(again.code(), "authorization.assignment_not_found");

    // The resource server bound to the native engine, then unbound.
    let missing = world
        .as_administrator(
            Method::GET,
            &format!("/resource-servers/{server}/binding"),
            None,
        )
        .await;
    assert_eq!(missing.code(), "authorization.binding_not_found");
    let bound = world
        .as_administrator(
            Method::PUT,
            &format!("/resource-servers/{server}/binding"),
            Some(serde_json::json!({ "engine": "native", "time_limit_milliseconds": 300 })),
        )
        .await;
    assert_eq!(bound.status, StatusCode::OK, "{}", bound.body);
    assert_eq!(bound.body["time_limit_milliseconds"], 300);
    let unknown = world
        .as_administrator(
            Method::PUT,
            &format!("/resource-servers/{server}/binding"),
            Some(serde_json::json!({ "engine": "elsewhere" })),
        )
        .await;
    assert_eq!(unknown.code(), "authorization.unknown_engine");
    let bindings = world.as_administrator(Method::GET, "/bindings", None).await;
    assert_eq!(bindings.body["items"][0]["namespace"], namespace);
    let unbound = world
        .as_administrator(
            Method::DELETE,
            &format!("/resource-servers/{server}/binding"),
            None,
        )
        .await;
    assert_eq!(unbound.status, StatusCode::NO_CONTENT);

    // A policy version is drafted and asked to be checked; nothing is
    // published, so the status names no revision.
    let package = format!(
        "hodor.tenants.t{}",
        world.acme.tenant_id().to_string().replace('-', "")
    );
    let drafted = world
        .as_administrator(
            Method::POST,
            "/policy-versions",
            Some(serde_json::json!({
                "files": [{ "path": "policy.rego", "contents": format!("package {package}\n\ndefault allow := false\n") }],
            })),
        )
        .await;
    assert_eq!(drafted.status, StatusCode::CREATED, "{}", drafted.body);
    assert_eq!(drafted.body["state"], "draft");
    assert_eq!(drafted.body["written_by"], "tenant");
    let number = drafted.body["number"].as_u64().expect("number");
    let asked = world
        .as_administrator(
            Method::POST,
            &format!("/policy-versions/{number}:validate"),
            None,
        )
        .await;
    assert_eq!(asked.status, StatusCode::ACCEPTED, "{}", asked.body);
    assert_eq!(asked.body["state"], "validating");
    let status = world
        .as_administrator(Method::GET, "/policy-status", None)
        .await;
    assert_eq!(status.status, StatusCode::OK);
    assert!(status.body.get("latest").is_none());

    // Every change is announced.
    world.record_audit().await;
    let records = world
        .as_administrator(Method::GET, "/audit-records?limit=200", None)
        .await;
    let said = records.body.to_string();
    for event in [
        "authorization.permission_declared",
        "authorization.role_defined",
        "authorization.principal_role_assigned",
        "authorization.principal_role_revoked",
        "authorization.engine_bound",
        "authorization.engine_unbound",
    ] {
        assert!(said.contains(event), "{event} is not in the audit log");
    }
}

/// Groups, organizations and invitations over the given users.
fn memberships(
    units_of_work: &InMemoryUnitOfWorkFactory,
    clock: Arc<FixedClock>,
    users: Arc<InMemoryUsers>,
    identity: &IdentityService,
    tenants: &TenantService,
) -> (
    hodor_identity::api::GroupService,
    hodor_identity::api::OrganizationService,
    hodor_authentication::api::InvitationService,
) {
    let units = || Arc::new(units_of_work.clone());
    let groups = hodor_identity::api::GroupService::new(
        units(),
        Arc::new(hodor_identity::testing::InMemoryGroups::default()),
        users.clone(),
        Arc::new(hodor_identity::testing::FixedGroupPolicy(5)),
        clock.clone(),
    );
    let organizations = hodor_identity::api::OrganizationService::new(
        units(),
        Arc::new(hodor_identity::testing::InMemoryOrganizations::default()),
        Arc::new(hodor_identity::testing::InMemoryInvitations::default()),
        users,
        clock.clone(),
    );
    let invitations = hodor_authentication::api::InvitationService::new(
        units(),
        hodor_authentication::api::InvitationContexts {
            organizations: organizations.clone(),
            identity: identity.clone(),
            credentials: hodor_credential::api::CredentialService::new(
                units(),
                Arc::new(hodor_credential::testing::InMemoryPasswords::default()),
                Arc::new(hodor_credential::testing::FakeHasher::default()),
                clock.clone(),
            ),
            tenants: tenants.clone(),
            notifier: hodor_notification::api::Notifier::new(
                Arc::new(hodor_notification::testing::InMemoryMessages::default()),
                clock,
            ),
        },
        Arc::new(FakeDigest),
        Arc::new(SequentialRandom::default()),
        "https://auth.example",
    );
    (groups, organizations, invitations)
}

#[tokio::test]
async fn an_administrator_manages_groups_and_their_members() {
    let world = world().await;
    let person = world
        .as_administrator(
            Method::POST,
            "/users",
            Some(serde_json::json!({ "email": "ana@example.com" })),
        )
        .await;
    let ana = person.body["id"].as_str().expect("a user").to_owned();

    let finance = world
        .as_administrator(
            Method::POST,
            "/groups",
            Some(serde_json::json!({ "name": "finance", "description": "Bills" })),
        )
        .await;
    assert_eq!(finance.status, StatusCode::CREATED);
    let finance = finance.body["id"].as_str().expect("a group").to_owned();
    let payables = world
        .as_administrator(
            Method::POST,
            "/groups",
            Some(serde_json::json!({ "name": "payables" })),
        )
        .await
        .body["id"]
        .as_str()
        .expect("a group")
        .to_owned();
    let taken = world
        .as_administrator(
            Method::POST,
            "/groups",
            Some(serde_json::json!({ "name": "FINANCE" })),
        )
        .await;
    assert_eq!(
        (taken.status, taken.body["code"].as_str()),
        (StatusCode::CONFLICT, Some("identity.group_name_taken"))
    );

    let nested = world
        .as_administrator(
            Method::POST,
            &format!("/groups/{finance}/members"),
            Some(serde_json::json!({ "kind": "group", "id": payables })),
        )
        .await;
    assert_eq!(nested.status, StatusCode::NO_CONTENT);
    let added = world
        .as_administrator(
            Method::POST,
            &format!("/groups/{payables}/members"),
            Some(serde_json::json!({ "kind": "user", "id": ana })),
        )
        .await;
    assert_eq!(added.status, StatusCode::NO_CONTENT);
    let cycle = world
        .as_administrator(
            Method::POST,
            &format!("/groups/{payables}/members"),
            Some(serde_json::json!({ "kind": "group", "id": finance })),
        )
        .await;
    assert_eq!(
        (cycle.status, cycle.body["code"].as_str()),
        (StatusCode::CONFLICT, Some("identity.group_cycle"))
    );

    let of = world
        .as_administrator(Method::GET, &format!("/users/{ana}/groups"), None)
        .await;
    assert_eq!(of.status, StatusCode::OK);
    let mut seen: Vec<(String, bool)> = of.body["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| {
            (
                item["id"].as_str().unwrap_or_default().to_owned(),
                item["direct"] == true,
            )
        })
        .collect();
    seen.sort();
    let mut expected = vec![(finance.clone(), false), (payables.clone(), true)];
    expected.sort();
    assert_eq!(seen, expected);

    let members = world
        .as_administrator(Method::GET, &format!("/groups/{finance}/members"), None)
        .await;
    assert_eq!(
        members.body["items"],
        serde_json::json!([{ "kind": "group", "id": payables }])
    );
    let removed = world
        .as_administrator(
            Method::POST,
            &format!("/groups/{finance}/members:remove"),
            Some(serde_json::json!({ "kind": "group", "id": payables })),
        )
        .await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    let renamed = world
        .as_administrator(
            Method::PATCH,
            &format!("/groups/{finance}"),
            Some(serde_json::json!({ "name": "Finance" })),
        )
        .await;
    assert_eq!(renamed.body["name"], "Finance");
    assert!(
        renamed.body.get("description").is_none(),
        "a missing description removes it"
    );
    let deleted = world
        .as_administrator(Method::DELETE, &format!("/groups/{finance}"), None)
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    let gone = world
        .as_administrator(Method::GET, &format!("/groups/{finance}"), None)
        .await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_administrator_manages_organizations_units_members_and_invitations() {
    let world = world().await;
    let person = world
        .as_administrator(
            Method::POST,
            "/users",
            Some(serde_json::json!({ "email": "ana@example.com" })),
        )
        .await;
    let ana = person.body["id"].as_str().expect("a user").to_owned();
    let acme = world
        .as_administrator(
            Method::POST,
            "/organizations",
            Some(serde_json::json!({ "name": "Acme" })),
        )
        .await;
    assert_eq!(acme.status, StatusCode::CREATED);
    let acme = acme.body["id"]
        .as_str()
        .expect("an organization")
        .to_owned();

    let engineering = world
        .as_administrator(
            Method::POST,
            &format!("/organizations/{acme}/units"),
            Some(serde_json::json!({ "name": "Engineering", "kind": "unit" })),
        )
        .await;
    assert_eq!(engineering.status, StatusCode::CREATED);
    let engineering = engineering.body["id"].as_str().expect("a unit").to_owned();
    let platform = world
        .as_administrator(
            Method::POST,
            &format!("/organizations/{acme}/units"),
            Some(serde_json::json!({ "parent_id": engineering, "name": "Platform", "kind": "department" })),
        )
        .await
        .body["id"]
        .as_str()
        .expect("a unit")
        .to_owned();
    let cycle = world
        .as_administrator(
            Method::PUT,
            &format!("/organizations/{acme}/units/{engineering}"),
            Some(
                serde_json::json!({ "parent_id": platform, "name": "Engineering", "kind": "unit" }),
            ),
        )
        .await;
    assert_eq!(
        (cycle.status, cycle.body["code"].as_str()),
        (StatusCode::CONFLICT, Some("identity.unit_cycle"))
    );
    let not_empty = world
        .as_administrator(
            Method::DELETE,
            &format!("/organizations/{acme}/units/{engineering}"),
            None,
        )
        .await;
    assert_eq!(not_empty.status, StatusCode::CONFLICT);
    let units = world
        .as_administrator(Method::GET, &format!("/organizations/{acme}/units"), None)
        .await;
    assert_eq!(units.body["items"].as_array().map(Vec::len), Some(2));

    let joined = world
        .as_administrator(
            Method::PUT,
            &format!("/organizations/{acme}/members/{ana}"),
            Some(serde_json::json!({ "unit_ids": [platform] })),
        )
        .await;
    assert_eq!(joined.status, StatusCode::OK);
    assert_eq!(joined.body["unit_ids"], serde_json::json!([platform]));
    let moved = world
        .as_administrator(
            Method::PUT,
            &format!("/organizations/{acme}/members/{ana}"),
            Some(serde_json::json!({ "unit_ids": [engineering] })),
        )
        .await;
    assert_eq!(moved.body["unit_ids"], serde_json::json!([engineering]));
    let of = world
        .as_administrator(Method::GET, &format!("/users/{ana}/organizations"), None)
        .await;
    assert_eq!(of.body["items"][0]["organization_id"], acme.as_str());

    let invited = world
        .as_administrator(
            Method::POST,
            &format!("/organizations/{acme}/invitations"),
            Some(serde_json::json!({ "email": "bruno@example.com", "unit_ids": [platform], "locale": "pt-BR" })),
        )
        .await;
    assert_eq!(invited.status, StatusCode::ACCEPTED);
    let pending = world
        .as_administrator(
            Method::GET,
            &format!("/organizations/{acme}/invitations"),
            None,
        )
        .await;
    let pending = pending.body["items"].as_array().expect("items").clone();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0]["email"], "bruno@example.com");
    assert!(
        pending[0].get("token").is_none() && pending[0].get("token_hash").is_none(),
        "no secret is shown"
    );
    let invitation = pending[0]["id"].as_str().expect("an invitation").to_owned();
    let withdrawn = world
        .as_administrator(
            Method::DELETE,
            &format!("/organizations/{acme}/invitations/{invitation}"),
            None,
        )
        .await;
    assert_eq!(withdrawn.status, StatusCode::NO_CONTENT);
    let again = world
        .as_administrator(
            Method::DELETE,
            &format!("/organizations/{acme}/invitations/{invitation}"),
            None,
        )
        .await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);

    let left = world
        .as_administrator(
            Method::DELETE,
            &format!("/organizations/{acme}/members/{ana}"),
            None,
        )
        .await;
    assert_eq!(left.status, StatusCode::NO_CONTENT);
    let deleted = world
        .as_administrator(Method::DELETE, &format!("/organizations/{acme}"), None)
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn an_administrator_reads_and_sets_the_scim_deprovisioning_policy() {
    let world = world().await;
    let read = world
        .as_administrator(Method::GET, "/scim-deprovisioning", None)
        .await;
    assert_eq!(read.status, StatusCode::OK, "{:?}", read.body);
    assert_eq!(
        read.body,
        serde_json::json!({ "deprovisioning": "deactivate" })
    );
    let set = world
        .as_administrator(
            Method::PUT,
            "/scim-deprovisioning",
            Some(serde_json::json!({ "deprovisioning": "delete" })),
        )
        .await;
    assert_eq!(set.status, StatusCode::OK, "{:?}", set.body);
    assert_eq!(set.body, serde_json::json!({ "deprovisioning": "delete" }));
    let read = world
        .as_administrator(Method::GET, "/scim-deprovisioning", None)
        .await;
    assert_eq!(read.body["deprovisioning"], "delete");
    for refused in [
        serde_json::json!({ "deprovisioning": "suspend" }),
        serde_json::json!({ "deprovisioning": "delete", "other": 1 }),
    ] {
        let answer = world
            .as_administrator(Method::PUT, "/scim-deprovisioning", Some(refused))
            .await;
        assert_eq!(answer.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(answer.body["code"], "request.body_invalid");
    }
}

#[tokio::test]
async fn an_administrator_reads_and_sets_the_email_sign_in_policy() {
    let world = world().await;
    let read = world
        .as_administrator(Method::GET, "/email-sign-in", None)
        .await;
    assert_eq!(read.status, StatusCode::OK, "{:?}", read.body);
    assert_eq!(
        read.body,
        serde_json::json!({ "code": false, "link": false })
    );
    let set = world
        .as_administrator(
            Method::PUT,
            "/email-sign-in",
            Some(serde_json::json!({ "code": true, "link": false })),
        )
        .await;
    assert_eq!(set.status, StatusCode::OK, "{:?}", set.body);
    assert_eq!(set.body, serde_json::json!({ "code": true, "link": false }));
    let read = world
        .as_administrator(Method::GET, "/email-sign-in", None)
        .await;
    assert_eq!(
        read.body,
        serde_json::json!({ "code": true, "link": false })
    );
    for refused in [
        serde_json::json!({ "code": true }),
        serde_json::json!({ "code": "yes", "link": false }),
        serde_json::json!({ "code": true, "link": false, "sms": true }),
    ] {
        let answer = world
            .as_administrator(Method::PUT, "/email-sign-in", Some(refused))
            .await;
        assert_eq!(answer.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(answer.body["code"], "request.body_invalid");
    }
    let read = world
        .as_administrator(Method::GET, "/email-sign-in", None)
        .await;
    assert_eq!(
        read.body,
        serde_json::json!({ "code": true, "link": false })
    );
}

#[tokio::test]
async fn an_administrator_manages_service_accounts_and_agents_and_binds_clients_to_them() {
    let world = world().await;
    let (ana, _) = world.person(&world.acme, "ana@example.com", &[]).await;
    let (bob, _) = world.person(&world.acme, "bob@example.com", &[]).await;

    let created = world
        .as_administrator(
            Method::POST,
            "/service-accounts",
            Some(serde_json::json!({ "name": "Nightly export", "owners": [ana.to_string()] })),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(created.body["kind"], "service_account");
    assert_eq!(created.body["status"], "active");
    assert_eq!(created.body["owners"], serde_json::json!([ana.to_string()]));
    let id = created.body["id"].as_str().expect("identifier").to_owned();

    // It is a user, without a login identifier, and it is not an agent.
    let as_user = world
        .as_administrator(Method::GET, &format!("/users/{id}"), None)
        .await;
    assert_eq!(as_user.body["kind"], "service_account");
    assert_eq!(as_user.body["identifiers"], serde_json::json!([]));
    let not_an_agent = world
        .as_administrator(Method::GET, &format!("/agents/{id}"), None)
        .await;
    assert_eq!(not_an_agent.status, StatusCode::NOT_FOUND);
    assert_eq!(not_an_agent.code(), "identity.workload_not_found");
    let listed = world
        .as_administrator(Method::GET, "/service-accounts", None)
        .await;
    assert_eq!(listed.body["items"][0]["id"], id.as_str());
    let agents = world.as_administrator(Method::GET, "/agents", None).await;
    assert_eq!(agents.body["items"], serde_json::json!([]));

    let changed = world
        .as_administrator(
            Method::PATCH,
            &format!("/service-accounts/{id}"),
            Some(serde_json::json!({ "name": "Export", "owners": [bob.to_string()] })),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.body);
    assert_eq!(changed.body["name"], "Export");
    assert_eq!(changed.body["owners"], serde_json::json!([bob.to_string()]));
    for (owners, status, code) in [
        (
            serde_json::json!([]),
            StatusCode::UNPROCESSABLE_ENTITY,
            "identity.workload_owner_required",
        ),
        (
            serde_json::json!([id]),
            StatusCode::UNPROCESSABLE_ENTITY,
            "identity.workload_owner_invalid",
        ),
        (
            serde_json::json!(["not an identifier"]),
            StatusCode::NOT_FOUND,
            "identity.user_not_found",
        ),
    ] {
        let refused = world
            .as_administrator(
                Method::PATCH,
                &format!("/service-accounts/{id}"),
                Some(serde_json::json!({ "owners": owners })),
            )
            .await;
        assert_eq!((refused.status, refused.code()), (status, code));
    }

    // A client of the client credentials grant is bound to it; a person
    // and another grant are refused.
    let application = world
        .as_administrator(
            Method::POST,
            "/applications",
            Some(serde_json::json!({ "name": "Billing", "first_party": true })),
        )
        .await;
    let application = application.body["id"].as_str().expect("id").to_owned();
    let clients = format!("/applications/{application}/clients");
    let bound = world
        .as_administrator(
            Method::POST,
            &clients,
            Some(serde_json::json!({
                "name": "Export", "type": "confidential",
                "grant_types": ["client_credentials"], "principal": id
            })),
        )
        .await;
    assert_eq!(bound.status, StatusCode::CREATED, "{}", bound.body);
    assert_eq!(bound.body["principal"], id.as_str());
    let client = bound.body["id"].as_str().expect("id").to_owned();
    for (body, code) in [
        (
            serde_json::json!({
                "name": "Person", "type": "confidential",
                "grant_types": ["client_credentials"], "principal": ana.to_string()
            }),
            "oauth.client_principal_invalid",
        ),
        (
            serde_json::json!({
                "name": "Web", "type": "confidential",
                "grant_types": ["authorization_code"],
                "redirect_uris": ["https://billing.example.com/callback"],
                "principal": id
            }),
            "oauth.client_grants_invalid",
        ),
    ] {
        let refused = world
            .as_administrator(Method::POST, &clients, Some(body))
            .await;
        assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(refused.code(), code);
    }
    let unbound = world
        .as_administrator(
            Method::PATCH,
            &format!("/clients/{client}"),
            Some(serde_json::json!({ "principal": null })),
        )
        .await;
    assert_eq!(unbound.status, StatusCode::OK, "{}", unbound.body);
    assert_eq!(unbound.body["principal"], serde_json::Value::Null);
    let kept = world
        .as_administrator(
            Method::PATCH,
            &format!("/clients/{client}"),
            Some(serde_json::json!({ "name": "Nightly export" })),
        )
        .await;
    assert_eq!(
        kept.body["principal"],
        serde_json::Value::Null,
        "left out, kept"
    );

    let disabled = world
        .as_administrator(
            Method::POST,
            &format!("/service-accounts/{id}:disable"),
            None,
        )
        .await;
    assert_eq!(disabled.status, StatusCode::OK);
    assert_eq!(disabled.body["status"], "disabled");
    let enabled = world
        .as_administrator(
            Method::POST,
            &format!("/service-accounts/{id}:enable"),
            None,
        )
        .await;
    assert_eq!(enabled.body["status"], "active");
    let unknown = world
        .as_administrator(
            Method::POST,
            &format!("/service-accounts/{id}:rename"),
            None,
        )
        .await;
    assert_eq!(unknown.code(), "route.not_found");

    let deleted = world
        .as_administrator(Method::DELETE, &format!("/service-accounts/{id}"), None)
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    let gone = world
        .as_administrator(Method::GET, &format!("/service-accounts/{id}"), None)
        .await;
    assert_eq!(gone.code(), "identity.workload_not_found");
    let rebound = world
        .as_administrator(
            Method::PATCH,
            &format!("/clients/{client}"),
            Some(serde_json::json!({ "principal": id })),
        )
        .await;
    assert_eq!(
        rebound.code(),
        "oauth.client_principal_invalid",
        "a deleted one"
    );

    // An agent of the same shape, under its own path.
    let agent = world
        .as_administrator(
            Method::POST,
            "/agents",
            Some(serde_json::json!({ "name": "Support helper", "owners": [ana.to_string()] })),
        )
        .await;
    assert_eq!(agent.status, StatusCode::CREATED);
    assert_eq!(agent.body["kind"], "agent");
}

impl World {
    /// Does the worker's part for webhooks: makes the deliveries of the
    /// events announced in Acme since it last did, then sends what is due,
    /// once.
    async fn deliver_webhooks(&self, retry: hodor_webhooks::api::RetryPolicy) {
        let fan_out = hodor_webhooks::api::WebhookFanOut::new(
            Arc::new(self.webhooks.clone()),
            Arc::new(self.webhooks.clone()),
            self.clock.clone(),
        );
        let events = self.units_of_work.committed_events();
        let from = self.fanned_out.swap(events.len(), Ordering::SeqCst);
        for event in &events[from..] {
            if event.metadata.tenant_id != self.acme.tenant_id()
                || !fan_out.handles(&event.event_type)
            {
                continue;
            }
            let mut uow = self.units_of_work.begin(&self.acme).await.expect("begin");
            fan_out.handle(uow.as_mut(), event).await.expect("fan out");
            uow.commit().await.expect("commit");
        }
        let sender = hodor_webhooks::api::WebhookSender::new(
            hodor_webhooks::api::SenderPorts {
                units_of_work: Arc::new(self.units_of_work.clone()),
                endpoints: Arc::new(self.webhooks.clone()),
                deliveries: Arc::new(self.webhooks.clone()),
                due: Arc::new(self.webhooks.clone()),
                secrets: Arc::new(FakeSecretBox),
                http: Arc::new(self.endpoints.clone()),
                hmac: Arc::new(hodor_webhooks::testing::FakeHmac),
                clock: self.clock.clone(),
            },
            hodor_webhooks::api::DeliverySettings {
                retry,
                ..hodor_webhooks::api::DeliverySettings::default()
            },
        );
        for lease in sender.lease_due(100).await.expect("lease") {
            sender.send(lease).await.expect("send");
        }
    }
}

#[tokio::test]
async fn an_administrator_registers_subscribes_rotates_and_removes_a_webhook_endpoint() {
    let world = world().await;
    let types = world
        .as_administrator(Method::GET, "/webhook-event-types", None)
        .await;
    assert_eq!(types.status, StatusCode::OK);
    assert!(
        types.body["items"]
            .as_array()
            .expect("items")
            .contains(&serde_json::json!("session.started"))
    );

    let registered = world
        .as_administrator(
            Method::POST,
            "/webhook-endpoints",
            Some(serde_json::json!({
                "url": "https://hooks.example.com/hodor?token=receiver",
                "description": "Our directory",
                "event_types": ["session.started"],
            })),
        )
        .await;
    assert_eq!(registered.status, StatusCode::CREATED);
    assert_eq!(
        registered
            .headers
            .get(header::CACHE_CONTROL)
            .map(|value| value.as_bytes()),
        Some(b"no-store".as_slice())
    );
    let secret = registered.body["secret"]
        .as_str()
        .expect("secret")
        .to_owned();
    assert!(secret.starts_with("whsec_"));
    let endpoint = registered.body["endpoint"]["id"]
        .as_str()
        .expect("an endpoint")
        .to_owned();
    assert_eq!(
        registered.body["endpoint"]["event_types"],
        serde_json::json!(["session.started"])
    );
    assert_eq!(
        registered.body["endpoint"]["secrets"],
        serde_json::json!([{ "created_at": "1970-01-01T00:00:00Z", "expires_at": null }])
    );

    // The secret is never shown again.
    let listed = world
        .as_administrator(Method::GET, "/webhook-endpoints", None)
        .await;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body["items"].as_array().map(Vec::len), Some(1));
    let read = world
        .as_administrator(Method::GET, &format!("/webhook-endpoints/{endpoint}"), None)
        .await;
    assert_eq!(read.body, registered.body["endpoint"]);
    for reply in [&listed, &read] {
        assert!(!reply.body.to_string().contains(&secret));
    }

    let changed = world
        .as_administrator(
            Method::PUT,
            &format!("/webhook-endpoints/{endpoint}/subscriptions"),
            Some(
                serde_json::json!({ "event_types": ["session.revoked", "identity.user_created"] }),
            ),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK);
    assert_eq!(
        changed.body["event_types"],
        serde_json::json!(["identity.user_created", "session.revoked"])
    );

    world.clock.advance(Duration::minutes(30));
    let rotated = world
        .as_administrator(
            Method::POST,
            &format!("/webhook-endpoints/{endpoint}:rotate-secret"),
            Some(serde_json::json!({ "overlap_hours": 2 })),
        )
        .await;
    assert_eq!(rotated.status, StatusCode::OK);
    let new_secret = rotated.body["secret"].as_str().expect("secret");
    assert_ne!(new_secret, secret);
    assert_eq!(
        rotated.body["endpoint"]["secrets"],
        serde_json::json!([
            { "created_at": "1970-01-01T00:30:00Z", "expires_at": null },
            { "created_at": "1970-01-01T00:00:00Z", "expires_at": "1970-01-01T02:30:00Z" },
        ])
    );
    let default_overlap = world
        .as_administrator(
            Method::POST,
            &format!("/webhook-endpoints/{endpoint}:rotate-secret"),
            None,
        )
        .await;
    assert_eq!(default_overlap.status, StatusCode::OK);

    world.record_audit().await;
    let records = world
        .as_administrator(Method::GET, "/audit-records", None)
        .await;
    let actions: Vec<&str> = records.body["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|record| record["action"].as_str())
        .filter(|action| action.starts_with("webhooks."))
        .collect();
    assert_eq!(
        actions.len(),
        4,
        "registered, subscriptions changed, rotated twice: {actions:?}"
    );
    assert!(!records.body.to_string().contains("hooks.example.com"));

    let removed = world
        .as_administrator(
            Method::DELETE,
            &format!("/webhook-endpoints/{endpoint}"),
            None,
        )
        .await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    let gone = world
        .as_administrator(Method::GET, &format!("/webhook-endpoints/{endpoint}"), None)
        .await;
    assert_eq!(
        (gone.status, gone.code()),
        (StatusCode::NOT_FOUND, "webhooks.endpoint_not_found")
    );
}

#[tokio::test]
async fn an_endpoint_that_may_not_be_called_or_names_no_known_type_is_refused() {
    let world = world().await;
    for (body, code) in [
        (
            serde_json::json!({ "url": "https://169.254.169.254/latest/meta-data" }),
            "webhooks.endpoint_address_forbidden",
        ),
        (
            serde_json::json!({ "url": "https://localhost:8443/" }),
            "webhooks.endpoint_address_forbidden",
        ),
        (
            serde_json::json!({ "url": "http://hooks.example.com/" }),
            "webhooks.endpoint_address_invalid",
        ),
        (
            serde_json::json!({ "url": "https://nowhere.example/" }),
            "webhooks.endpoint_address_unresolvable",
        ),
        (
            serde_json::json!({ "url": "https://hooks.example.com/", "event_types": ["keys.version_created"] }),
            "webhooks.event_type_unknown",
        ),
        (
            serde_json::json!({ "url": "https://hooks.example.com/", "secret": "mine" }),
            "request.body_invalid",
        ),
    ] {
        let reply = world
            .as_administrator(Method::POST, "/webhook-endpoints", Some(body.clone()))
            .await;
        assert_eq!(
            (reply.status, reply.code()),
            (StatusCode::UNPROCESSABLE_ENTITY, code),
            "{body}"
        );
    }
    let listed = world
        .as_administrator(Method::GET, "/webhook-endpoints", None)
        .await;
    assert_eq!(listed.body["items"], serde_json::json!([]));
    let action = world
        .as_administrator(
            Method::POST,
            &format!("/webhook-endpoints/{}:frobnicate", UserId::generate()),
            None,
        )
        .await;
    assert_eq!(
        (action.status, action.code()),
        (StatusCode::NOT_FOUND, "route.not_found")
    );
}

#[tokio::test]
async fn deliveries_are_listed_and_a_set_aside_one_is_delivered_again_in_its_tenant_only() {
    let world = world().await;
    // What happened before the endpoint existed is not sent to it.
    world
        .deliver_webhooks(hodor_webhooks::api::RetryPolicy::DEFAULT)
        .await;
    let registered = world
        .as_administrator(
            Method::POST,
            "/webhook-endpoints",
            Some(serde_json::json!({
                "url": "https://down.example.com/",
                "event_types": ["identity.user_created"],
            })),
        )
        .await;
    let endpoint = registered.body["endpoint"]["id"]
        .as_str()
        .expect("an endpoint")
        .to_owned();
    // An event of a subscribed type: a user is created.
    world
        .as_administrator(
            Method::POST,
            "/users",
            Some(serde_json::json!({ "email": "ana@example.com" })),
        )
        .await;
    world.endpoints.answer(
        "https://down.example.com/",
        hodor_webhooks::testing::Answer::Status(500),
    );
    world
        .deliver_webhooks(
            hodor_webhooks::api::RetryPolicy::new(1, Duration::seconds(1)).expect("policy"),
        )
        .await;

    let set_aside = world
        .as_administrator(
            Method::GET,
            &format!("/webhook-deliveries?status=set_aside&endpoint_id={endpoint}"),
            None,
        )
        .await;
    assert_eq!(set_aside.status, StatusCode::OK);
    let items = set_aside.body["items"].as_array().expect("items");
    assert_eq!(items.len(), 1);
    let delivery = &items[0];
    assert_eq!(delivery["status"], "set_aside");
    assert_eq!(delivery["event_type"], "identity.user_created");
    assert_eq!(delivery["attempts"], 1);
    assert_eq!(delivery["last_response_status"], 500);
    assert_eq!(delivery["next_attempt_at"], serde_json::Value::Null);
    assert!(delivery.get("payload").is_none(), "the body is never shown");
    let id = delivery["id"].as_str().expect("an id").to_owned();

    // Another tenant's administrator sees nothing of it.
    let (_, globex_token) = world
        .person(
            &world.globex,
            "root@globex.example",
            &[Role::TenantAdministrator],
        )
        .await;
    let theirs = world
        .send(
            Method::GET,
            "/t/globex/api/v1/admin/webhook-deliveries",
            Some(&format!("Bearer {globex_token}")),
            None,
        )
        .await;
    assert_eq!(theirs.body["items"], serde_json::json!([]));
    let refused = world
        .send(
            Method::POST,
            &format!("/t/globex/api/v1/admin/webhook-deliveries/{id}:redeliver"),
            Some(&format!("Bearer {globex_token}")),
            None,
        )
        .await;
    assert_eq!(
        (refused.status, refused.code()),
        (StatusCode::NOT_FOUND, "webhooks.delivery_not_found")
    );

    let again = world
        .as_administrator(
            Method::POST,
            &format!("/webhook-deliveries/{id}:redeliver"),
            None,
        )
        .await;
    assert_eq!(again.status, StatusCode::OK);
    assert_eq!(again.body["status"], "pending");
    assert_eq!(again.body["attempts"], 0);
    let twice = world
        .as_administrator(
            Method::POST,
            &format!("/webhook-deliveries/{id}:redeliver"),
            None,
        )
        .await;
    assert_eq!(
        (twice.status, twice.code()),
        (StatusCode::CONFLICT, "webhooks.delivery_not_set_aside")
    );

    world.endpoints.answer(
        "https://down.example.com/",
        hodor_webhooks::testing::Answer::Status(204),
    );
    world
        .deliver_webhooks(hodor_webhooks::api::RetryPolicy::DEFAULT)
        .await;
    let delivered = world
        .as_administrator(Method::GET, "/webhook-deliveries?status=delivered", None)
        .await;
    assert_eq!(delivered.body["items"].as_array().map(Vec::len), Some(1));

    for query in ["status=lost", "endpoint_id=not-an-identifier"] {
        let reply = world
            .as_administrator(Method::GET, &format!("/webhook-deliveries?{query}"), None)
            .await;
        assert_eq!(
            (reply.status, reply.code()),
            (StatusCode::UNPROCESSABLE_ENTITY, "request.query_invalid"),
            "{query}"
        );
    }
}

#[tokio::test]
async fn without_keys_webhooks_are_not_offered() {
    let world = world_with_keys(false).await;
    let reply = world
        .as_administrator(
            Method::POST,
            "/webhook-endpoints",
            Some(serde_json::json!({ "url": "https://hooks.example.com/" })),
        )
        .await;
    assert_eq!(
        (reply.status, reply.code()),
        (StatusCode::SERVICE_UNAVAILABLE, "webhooks.not_configured")
    );
    let types = world
        .as_administrator(Method::GET, "/webhook-event-types", None)
        .await;
    assert_eq!(types.status, StatusCode::OK);
}

#[tokio::test]
async fn a_workloads_api_key_is_shown_once_and_does_no_more_than_its_scopes_and_its_roles() {
    let world = world().await;
    let (ana, _) = world.person(&world.acme, "ana@example.com", &[]).await;
    let created = world
        .as_administrator(
            Method::POST,
            "/service-accounts",
            Some(serde_json::json!({ "name": "Reports", "owners": [ana.to_string()] })),
        )
        .await;
    let account = created.body["id"].as_str().expect("id").to_owned();
    let keys = format!("/service-accounts/{account}/api-keys");

    // What breaks a rule is refused with its code.
    for (body, code) in [
        (
            serde_json::json!({ "name": "x", "scopes": ["users:delete"] }),
            "authorization.scope_unknown",
        ),
        (
            serde_json::json!({ "name": "x", "scopes": ["authz:evaluate"] }),
            "authorization.scope_needs_application",
        ),
        (
            serde_json::json!({ "name": "x", "scopes": ["users:read"], "lifetime_days": 400 }),
            "credential.api_key_lifetime_invalid",
        ),
        (
            serde_json::json!({
                "name": "x", "scopes": ["authz:evaluate"],
                "application_id": UserId::generate().to_string()
            }),
            "credential.api_key_application_invalid",
        ),
    ] {
        let refused = world
            .as_administrator(Method::POST, &keys, Some(body))
            .await;
        assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY, "{code}");
        assert_eq!(refused.code(), code);
    }

    let made = world
        .as_administrator(
            Method::POST,
            &keys,
            Some(serde_json::json!({ "name": "Reports on the build server", "scopes": ["users:read"] })),
        )
        .await;
    assert_eq!(made.status, StatusCode::CREATED, "{}", made.body);
    let secret = made.body["api_key"].as_str().expect("the key").to_owned();
    assert!(
        secret.starts_with("hodor_ak_") && secret.len() == 73,
        "{secret}"
    );
    assert_eq!(made.body["status"], "active");
    assert_eq!(
        made.body["hint"],
        format!("…{}", &secret[secret.len() - 4..])
    );
    let key_id = made.body["id"].as_str().expect("id").to_owned();

    // Never shown again.
    let listed = world.as_administrator(Method::GET, &keys, None).await;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body["items"][0]["id"], key_id.as_str());
    assert!(!listed.body.to_string().contains(&secret[9..]));
    assert!(listed.body["items"][0].get("api_key").is_none());

    // The key does nothing until its holder holds a role, and then only
    // what its scopes say.
    let bearer = format!("Bearer {secret}");
    let with_key = |method: Method, path: &str| {
        let path = format!("/t/acme/api/v1/admin{path}");
        let bearer = bearer.clone();
        let world = &world;
        async move {
            world
                .send(
                    method,
                    &path,
                    Some(&bearer),
                    Some(serde_json::json!({ "email": "new@example.com" })),
                )
                .await
        }
    };
    let reply = with_key(Method::GET, "/users").await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN, "no role yet");
    world
        .authorization
        .assign(
            &world.acme,
            account.parse().expect("an identifier"),
            Role::TenantAdministrator,
            Caller::system(),
        )
        .await
        .expect("a role");
    assert_eq!(with_key(Method::GET, "/users").await.status, StatusCode::OK);
    for (method, path) in [(Method::GET, "/groups"), (Method::POST, "/users")] {
        let reply = with_key(method.clone(), path).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{method} {path}");
        assert_eq!(reply.code(), "admin.forbidden");
    }
    let elsewhere = world
        .send(
            Method::GET,
            "/t/globex/api/v1/admin/users",
            Some(&format!("Bearer {secret}")),
            None,
        )
        .await;
    assert_eq!(elsewhere.status, StatusCode::UNAUTHORIZED, "another tenant");

    // Rotated: both work for the overlap.
    let rotated = world
        .as_administrator(
            Method::POST,
            &format!("{keys}/{key_id}:rotate"),
            Some(serde_json::json!({ "keep_previous_days": 1 })),
        )
        .await;
    assert_eq!(rotated.status, StatusCode::CREATED, "{}", rotated.body);
    let next = rotated.body["api_key"]
        .as_str()
        .expect("the key")
        .to_owned();
    assert_ne!(next, secret);
    let next_id = rotated.body["id"].as_str().expect("id").to_owned();
    assert_eq!(with_key(Method::GET, "/users").await.status, StatusCode::OK);
    let reply = world
        .send(
            Method::GET,
            "/t/acme/api/v1/admin/users",
            Some(&format!("Bearer {next}")),
            None,
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    let again = world
        .as_administrator(Method::POST, &format!("{keys}/{key_id}:rotate"), None)
        .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.code(), "credential.api_key_not_rotatable");

    // Disabling the holder stops its keys; enabling lets them work again.
    world
        .as_administrator(
            Method::POST,
            &format!("/service-accounts/{account}:disable"),
            None,
        )
        .await;
    let reply = with_key(Method::GET, "/users").await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.code(), "admin.not_authenticated");
    world
        .as_administrator(
            Method::POST,
            &format!("/service-accounts/{account}:enable"),
            None,
        )
        .await;
    assert_eq!(with_key(Method::GET, "/users").await.status, StatusCode::OK);

    // Revoked: refused at once, and listed as revoked.
    let revoked = world
        .as_administrator(Method::DELETE, &format!("{keys}/{key_id}"), None)
        .await;
    assert_eq!(revoked.status, StatusCode::NO_CONTENT);
    assert_eq!(
        with_key(Method::GET, "/users").await.status,
        StatusCode::UNAUTHORIZED
    );
    let listed = world.as_administrator(Method::GET, &keys, None).await;
    let statuses: Vec<(&str, &str)> = listed.body["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|key| {
            (
                key["id"].as_str().expect("id"),
                key["status"].as_str().expect("status"),
            )
        })
        .collect();
    assert_eq!(
        statuses,
        [(next_id.as_str(), "active"), (key_id.as_str(), "revoked")]
    );

    // A key is reached only under its own workload and kind.
    let agent_path = format!("/agents/{account}/api-keys");
    assert_eq!(
        world
            .as_administrator(Method::GET, &agent_path, None)
            .await
            .code(),
        "identity.workload_not_found"
    );
    let other = world
        .as_administrator(
            Method::POST,
            "/service-accounts",
            Some(serde_json::json!({ "name": "Other", "owners": [ana.to_string()] })),
        )
        .await;
    let other = other.body["id"].as_str().expect("id").to_owned();
    let missing = world
        .as_administrator(
            Method::DELETE,
            &format!("/service-accounts/{other}/api-keys/{next_id}"),
            None,
        )
        .await;
    assert_eq!(missing.code(), "credential.api_key_not_found");

    // Deleting the holder revokes its keys.
    world
        .as_administrator(
            Method::DELETE,
            &format!("/service-accounts/{account}"),
            None,
        )
        .await;
    let reply = world
        .send(
            Method::GET,
            "/t/acme/api/v1/admin/users",
            Some(&format!("Bearer {next}")),
            None,
        )
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn only_an_agents_client_is_given_the_token_exchange_grant_with_its_rules() {
    let world = world().await;
    let (ana, _) = world.person(&world.acme, "ana@example.com", &[]).await;
    let owners = serde_json::json!([ana.to_string()]);
    let agent = world
        .as_administrator(
            Method::POST,
            "/agents",
            Some(serde_json::json!({ "name": "Assistant", "owners": owners })),
        )
        .await;
    let agent = agent.body["id"].as_str().expect("id").to_owned();
    let account = world
        .as_administrator(
            Method::POST,
            "/service-accounts",
            Some(serde_json::json!({ "name": "Export", "owners": owners })),
        )
        .await;
    let account = account.body["id"].as_str().expect("id").to_owned();
    let application = world
        .as_administrator(
            Method::POST,
            "/applications",
            Some(serde_json::json!({ "name": "Assistant", "first_party": true })),
        )
        .await;
    let clients = format!(
        "/applications/{}/clients",
        application.body["id"].as_str().expect("id")
    );
    let body = |principal: &str, rules: serde_json::Value| {
        serde_json::json!({
            "name": "Assistant", "type": "confidential",
            "grant_types": ["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
            "principal": principal,
            "exchange_rules": rules
        })
    };
    let rules = serde_json::json!([
        { "subject_audience": "urn:example:assistant", "audience": "https://api.example.com" }
    ]);
    let made = world
        .as_administrator(Method::POST, &clients, Some(body(&agent, rules.clone())))
        .await;
    assert_eq!(made.status, StatusCode::CREATED, "{}", made.body);
    assert_eq!(made.body["exchange_rules"], rules);
    for (principal, rules, code) in [
        (
            account.as_str(),
            rules.clone(),
            "oauth.client_principal_invalid",
        ),
        (
            agent.as_str(),
            serde_json::json!([]),
            "oauth.client_exchange_rules_invalid",
        ),
    ] {
        let refused = world
            .as_administrator(Method::POST, &clients, Some(body(principal, rules)))
            .await;
        assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(refused.code(), code);
    }
    // A service account's client cannot be given the grant afterwards.
    let plain = world
        .as_administrator(
            Method::POST,
            &clients,
            Some(serde_json::json!({
                "name": "Export", "type": "confidential",
                "grant_types": ["client_credentials"], "principal": account
            })),
        )
        .await;
    let refused = world
        .as_administrator(
            Method::PATCH,
            &format!("/clients/{}", plain.body["id"].as_str().expect("id")),
            Some(serde_json::json!({
                "grant_types": ["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
                "exchange_rules": rules
            })),
        )
        .await;
    assert_eq!(refused.code(), "oauth.client_principal_invalid");
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn an_administrator_grants_lists_and_removes_entries_of_access_control_lists() {
    let world = world().await;
    let application = world
        .as_administrator(
            Method::POST,
            "/applications",
            Some(serde_json::json!({ "name": "Documents", "first_party": true })),
        )
        .await;
    let application = application.body["id"].as_str().expect("id").to_owned();
    let server = world
        .as_administrator(
            Method::POST,
            "/resource-servers",
            Some(serde_json::json!({
                "application_id": application,
                "audience": "https://api.documents.example.com",
                "name": "Documents interface",
            })),
        )
        .await;
    let server = server.body["id"].as_str().expect("id").to_owned();
    let declared = world
        .as_administrator(
            Method::PUT,
            &format!("/resource-servers/{server}/permissions/document:read"),
            Some(serde_json::json!({ "description": "Read a document" })),
        )
        .await;
    assert_eq!(declared.status, StatusCode::OK, "{}", declared.body);
    let group = world
        .as_administrator(
            Method::POST,
            "/groups",
            Some(serde_json::json!({ "name": "finance" })),
        )
        .await
        .body["id"]
        .as_str()
        .expect("a group")
        .to_owned();
    let entries = format!("/resource-servers/{server}/access-entries");

    // Granted once, answered again the second time.
    let share = serde_json::json!({
        "permission": "document:read",
        "resource_id": "d-42",
        "principal": { "kind": "group", "id": group },
    });
    let granted = world
        .as_administrator(Method::POST, &entries, Some(share.clone()))
        .await;
    assert_eq!(granted.status, StatusCode::CREATED, "{}", granted.body);
    assert_eq!(
        granted.body["namespace"],
        "https://api.documents.example.com"
    );
    assert_eq!(granted.body["resource_kind"], "document");
    assert_eq!(granted.body["resource_id"], "d-42");
    assert_eq!(granted.body["principal"]["kind"], "group");
    let entry = granted.body["id"].as_str().expect("id").to_owned();
    let again = world
        .as_administrator(Method::POST, &entries, Some(share))
        .await;
    assert_eq!(again.status, StatusCode::OK);
    assert_eq!(again.body["id"], entry.as_str());
    let to_ana = world
        .as_administrator(
            Method::POST,
            &entries,
            Some(serde_json::json!({
                "permission": "document:read",
                "resource_id": "d-43",
                "principal": { "kind": "user", "id": world.administrator.to_string() },
            })),
        )
        .await;
    assert_eq!(to_ana.status, StatusCode::CREATED, "{}", to_ana.body);

    // What the rules refuse.
    let globex = world.globex.clone();
    let (stranger, globex_token) = world
        .person(&globex, "root@globex.example", &[Role::TenantAdministrator])
        .await;
    for (asked, status, code) in [
        (
            serde_json::json!({
                "permission": "document:write", "resource_id": "d-42",
                "principal": { "kind": "group", "id": group },
            }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "authorization.permission_not_declared",
        ),
        (
            serde_json::json!({
                "permission": "read", "resource_id": "d-42",
                "principal": { "kind": "group", "id": group },
            }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "authorization.permission_invalid",
        ),
        (
            serde_json::json!({
                "permission": "document:read", "resource_id": "",
                "principal": { "kind": "group", "id": group },
            }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "authorization.resource_invalid",
        ),
        (
            serde_json::json!({
                "permission": "document:read", "resource_id": "d-42",
                "principal": { "kind": "organization", "id": group },
            }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "authorization.principal_kind_invalid",
        ),
        (
            serde_json::json!({
                "permission": "document:read", "resource_id": "d-42",
                "principal": { "kind": "user", "id": stranger.to_string() },
            }),
            StatusCode::NOT_FOUND,
            "identity.user_not_found",
        ),
        (
            serde_json::json!({
                "permission": "document:read", "resource_id": "d-42",
                "principal": { "kind": "group", "id": UserId::generate().to_string() },
            }),
            StatusCode::NOT_FOUND,
            "identity.group_not_found",
        ),
        (
            serde_json::json!({ "permission": "document:read" }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "request.body_invalid",
        ),
    ] {
        let refused = world
            .as_administrator(Method::POST, &entries, Some(asked))
            .await;
        assert_eq!(refused.status, status, "{code}: {}", refused.body);
        assert_eq!(refused.code(), code);
    }
    let nowhere = world
        .as_administrator(
            Method::GET,
            &format!("/resource-servers/{}/access-entries", UserId::generate()),
            None,
        )
        .await;
    assert_eq!(nowhere.code(), "oauth.resource_server_not_found");

    // Listed oldest first, a page at a time, and narrowed.
    let listed = world.as_administrator(Method::GET, &entries, None).await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.body);
    assert_eq!(listed.body["items"].as_array().map(Vec::len), Some(2));
    assert_eq!(listed.body["items"][0]["id"], entry.as_str());
    let first = world
        .as_administrator(Method::GET, &format!("{entries}?limit=1"), None)
        .await;
    let cursor = first.body["next_cursor"].as_str().expect("more").to_owned();
    let second = world
        .as_administrator(
            Method::GET,
            &format!("{entries}?limit=1&cursor={cursor}"),
            None,
        )
        .await;
    assert_eq!(second.body["items"][0]["resource_id"], "d-43");
    assert!(second.body.get("next_cursor").is_none());
    for (query, expected) in [
        ("resource_id=d-42", 1),
        ("resource_kind=document", 2),
        ("resource_kind=folder", 0),
        (&*format!("principal_kind=group&principal_id={group}"), 1),
    ] {
        let narrowed = world
            .as_administrator(Method::GET, &format!("{entries}?{query}"), None)
            .await;
        assert_eq!(
            narrowed.body["items"].as_array().map(Vec::len),
            Some(expected),
            "{query}"
        );
    }
    for query in [
        "principal_kind=group",
        "principal_kind=team&principal_id=x",
        "cursor=nonsense",
        "limit=0",
    ] {
        let refused = world
            .as_administrator(Method::GET, &format!("{entries}?{query}"), None)
            .await;
        assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY, "{query}");
        assert_eq!(refused.code(), "request.query_invalid", "{query}");
    }

    // Read, and out of reach of another tenant's administrator.
    let one = world
        .as_administrator(Method::GET, &format!("/access-entries/{entry}"), None)
        .await;
    assert_eq!(one.status, StatusCode::OK);
    assert_eq!(one.body, granted.body);
    for method in [Method::GET, Method::DELETE] {
        let theirs = world
            .send(
                method.clone(),
                &format!("/t/globex/api/v1/admin/access-entries/{entry}"),
                Some(&format!("Bearer {globex_token}")),
                None,
            )
            .await;
        assert_eq!(theirs.status, StatusCode::NOT_FOUND, "{method}");
        assert_eq!(theirs.code(), "authorization.access_entry_not_found");
    }
    let unknown = world
        .as_administrator(Method::GET, "/access-entries/not-an-identifier", None)
        .await;
    assert_eq!(unknown.code(), "authorization.access_entry_not_found");

    // An auditor reads entries and may not grant or remove them.
    let acme = world.acme.clone();
    let (_, auditor) = world
        .person(&acme, "auditor@example.com", &[Role::TenantAuditor])
        .await;
    let as_auditor = format!("Bearer {auditor}");
    let read = world
        .send(
            Method::GET,
            &format!("/t/acme/api/v1/admin/access-entries/{entry}"),
            Some(&as_auditor),
            None,
        )
        .await;
    assert_eq!(read.status, StatusCode::OK);
    let refused = world
        .send(
            Method::DELETE,
            &format!("/t/acme/api/v1/admin/access-entries/{entry}"),
            Some(&as_auditor),
            None,
        )
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);

    // Removed once.
    let removed = world
        .as_administrator(Method::DELETE, &format!("/access-entries/{entry}"), None)
        .await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    let gone = world
        .as_administrator(Method::DELETE, &format!("/access-entries/{entry}"), None)
        .await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
    assert_eq!(gone.code(), "authorization.access_entry_not_found");

    // Both changes are in the audit log; granting again is not.
    world.record_audit().await;
    let records = world
        .as_administrator(Method::GET, "/audit-records?limit=200", None)
        .await;
    let said = records.body.to_string();
    assert_eq!(
        said.matches("authorization.access_entry_granted").count(),
        2
    );
    assert_eq!(
        said.matches("authorization.access_entry_removed").count(),
        1
    );
}

#[tokio::test]
async fn an_administrator_manages_the_claim_mappers_of_a_client() {
    let world = world().await;
    let application = new_application(&world, "Billing", true).await;
    let created = world
        .as_administrator(
            Method::POST,
            &format!("/applications/{application}/clients"),
            Some(web_client()),
        )
        .await;
    let client = created.body["id"].as_str().expect("client").to_owned();
    let group = world
        .as_administrator(
            Method::POST,
            "/groups",
            Some(serde_json::json!({ "name": "finance" })),
        )
        .await
        .body["id"]
        .as_str()
        .expect("a group")
        .to_owned();
    let mappers = format!("/clients/{client}/claim-mappers");

    let member = world
        .as_administrator(
            Method::POST,
            &mappers,
            Some(serde_json::json!({
                "claim": "in_finance",
                "targets": ["access_token", "id_token"],
                "source": { "kind": "group_member", "group_id": group },
            })),
        )
        .await;
    assert_eq!(member.status, StatusCode::CREATED, "{}", member.body);
    assert_eq!(member.body["client_id"], client.as_str());
    assert_eq!(
        member.body["targets"],
        serde_json::json!(["id_token", "access_token"])
    );
    assert_eq!(member.body["scope"], serde_json::Value::Null);
    assert_eq!(member.body["source"]["group_id"], group.as_str());
    let member_id = member.body["id"].as_str().expect("id").to_owned();

    // A mapper that names a claim Hodor sets is refused.
    for name in ["sub", "iss", "acr"] {
        let refused = world
            .as_administrator(
                Method::POST,
                &mappers,
                Some(serde_json::json!({
                    "claim": name,
                    "targets": ["id_token"],
                    "source": { "kind": "constant", "value": "x" },
                })),
            )
            .await;
        assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY, "{name}");
        assert_eq!(refused.code(), "oauth.claim_mapper_name_reserved", "{name}");
    }
    // A token past the bound is refused when the mapper is saved.
    let teams = world
        .as_administrator(
            Method::POST,
            &mappers,
            Some(serde_json::json!({
                "claim": "teams",
                "targets": ["id_token"],
                "source": { "kind": "groups" },
            })),
        )
        .await;
    assert_eq!(teams.status, StatusCode::CREATED, "{}", teams.body);
    let too_large = world
        .as_administrator(
            Method::POST,
            &mappers,
            Some(serde_json::json!({
                "claim": "full_name",
                "targets": ["id_token"],
                "source": { "kind": "attribute", "attribute": "display_name" },
            })),
        )
        .await;
    assert_eq!(too_large.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(too_large.code(), "oauth.claim_mapper_token_too_large");

    for (case, body, status, code) in [
        (
            "a group of no tenant",
            serde_json::json!({
                "claim": "in_payables",
                "targets": ["id_token"],
                "source": { "kind": "group_member", "group_id": UserId::generate().to_string() },
            }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "oauth.claim_mapper_group_unknown",
        ),
        (
            "an unknown target",
            serde_json::json!({
                "claim": "plan",
                "targets": ["logout_token"],
                "source": { "kind": "groups" },
            }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "oauth.claim_mapper_targets_invalid",
        ),
        (
            "an unknown source",
            serde_json::json!({
                "claim": "plan",
                "targets": ["userinfo"],
                "source": { "kind": "roles" },
            }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "oauth.claim_mapper_source_invalid",
        ),
        (
            "a scope the client may not ask for",
            serde_json::json!({
                "claim": "plan",
                "targets": ["userinfo"],
                "scope": "invoices:read",
                "source": { "kind": "groups" },
            }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "oauth.claim_mapper_scope_not_allowed",
        ),
        (
            "a claim taken without regard to case",
            serde_json::json!({
                "claim": "TEAMS",
                "targets": ["userinfo"],
                "source": { "kind": "groups" },
            }),
            StatusCode::CONFLICT,
            "oauth.claim_mapper_name_taken",
        ),
    ] {
        let refused = world
            .as_administrator(Method::POST, &mappers, Some(body))
            .await;
        assert_eq!(refused.status, status, "{case}: {}", refused.body);
        assert_eq!(refused.code(), code, "{case}");
    }

    let listed = world.as_administrator(Method::GET, &mappers, None).await;
    assert_eq!(listed.status, StatusCode::OK);
    let claims: Vec<&str> = listed.body["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|item| item["claim"].as_str())
        .collect();
    assert_eq!(claims, ["in_finance", "teams"], "only what was accepted");

    let one = format!("{mappers}/{member_id}");
    let replaced = world
        .as_administrator(
            Method::PUT,
            &one,
            Some(serde_json::json!({
                "claim": "plan",
                "targets": ["userinfo"],
                "scope": "email",
                "source": { "kind": "constant", "value": { "tier": "gold" } },
            })),
        )
        .await;
    assert_eq!(replaced.status, StatusCode::OK, "{}", replaced.body);
    let read = world.as_administrator(Method::GET, &one, None).await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.body["claim"], "plan");
    assert_eq!(read.body["source"]["value"]["tier"], "gold");

    let deleted = world.as_administrator(Method::DELETE, &one, None).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    let gone = world.as_administrator(Method::GET, &one, None).await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
    assert_eq!(gone.code(), "oauth.claim_mapper_not_found");
    let unknown = world
        .as_administrator(
            Method::GET,
            &format!("/clients/{}/claim-mappers", UserId::generate()),
            None,
        )
        .await;
    assert_eq!(unknown.code(), "oauth.client_not_found");

    // Another tenant's administrator reads and changes nothing of it.
    let (_, globex_token) = world
        .person(
            &world.globex,
            "root@globex.example",
            &[Role::TenantAdministrator],
        )
        .await;
    let teams_id = teams.body["id"].as_str().expect("id");
    for (method, path) in [
        (Method::GET, mappers.clone()),
        (Method::GET, format!("{mappers}/{teams_id}")),
        (Method::DELETE, format!("{mappers}/{teams_id}")),
    ] {
        let reply = world
            .send(
                method.clone(),
                &format!("/t/globex/api/v1/admin{path}"),
                Some(&format!("Bearer {globex_token}")),
                None,
            )
            .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{method} {path}");
        assert_eq!(reply.code(), "oauth.client_not_found", "{method} {path}");
    }
    let still = world.as_administrator(Method::GET, &mappers, None).await;
    assert_eq!(still.body["items"].as_array().map(Vec::len), Some(1));
}

#[tokio::test]
async fn an_administrator_adds_reads_replaces_and_removes_trust_domains() {
    let world = world().await;
    let bundle = hodor_keys::testing::sample_bundle(Some(3), &["one"]);
    let added = world
        .as_administrator(
            Method::POST,
            "/trust-domains",
            Some(serde_json::json!({
                "name": "prod.example.com",
                "source": "uploaded",
                "bundle": bundle,
            })),
        )
        .await;
    assert_eq!(added.status, StatusCode::CREATED, "{}", added.body);
    let id = added.body["id"].as_str().expect("id").to_owned();
    assert_eq!(added.body["source"], "uploaded");
    assert_eq!(added.body["bundle"]["spiffe_sequence"], 3);
    assert_eq!(
        added.body["bundle"]["keys"].as_array().map(Vec::len),
        Some(2)
    );
    assert!(added.body.get("refresh").is_none());
    assert!(added.body.get("bundle_endpoint_url").is_none());

    // From a bundle endpoint: fetched once when it is saved.
    let url = "https://spire.example.com/bundle?token=receiver";
    world.bundle_endpoints.serve(
        url,
        &hodor_keys::testing::sample_bundle(Some(1), &["spire"]),
    );
    let fetched = world
        .as_administrator(
            Method::POST,
            "/trust-domains",
            Some(serde_json::json!({
                "name": "spire.example",
                "source": "bundle_endpoint",
                "bundle_endpoint_url": url,
            })),
        )
        .await;
    assert_eq!(fetched.status, StatusCode::CREATED, "{}", fetched.body);
    assert_eq!(fetched.body["bundle_endpoint_url"], url);
    assert_eq!(
        fetched.body["refresh"]["fetched_at"],
        "1970-01-01T00:00:00Z"
    );
    assert_eq!(fetched.body["refresh"]["next_at"], "1970-01-01T00:05:00Z");
    assert_eq!(
        fetched.body["refresh"]["failing_since"],
        serde_json::Value::Null
    );
    let mesh = world
        .as_administrator(
            Method::POST,
            "/trust-domains",
            Some(serde_json::json!({ "name": "cluster.local", "source": "mesh" })),
        )
        .await;
    assert_eq!(mesh.status, StatusCode::CREATED);
    assert!(mesh.body.get("bundle").is_none());

    let listed = world
        .as_administrator(Method::GET, "/trust-domains?limit=2", None)
        .await;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body["items"].as_array().map(Vec::len), Some(2));
    assert!(listed.body["next_cursor"].is_string());

    // A replacement that does not read is refused, and the bundle stays.
    let refused = world
        .as_administrator(
            Method::PUT,
            &format!("/trust-domains/{id}"),
            Some(serde_json::json!({
                "source": "uploaded",
                "bundle": { "keys": [{ "use": "jwt-svid", "kty": "EC", "crv": "P-256", "kid": "k", "x": "AA", "y": "AA" }] },
            })),
        )
        .await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(refused.body["code"], "keys.trust_bundle_invalid");
    let read = world
        .as_administrator(Method::GET, &format!("/trust-domains/{id}"), None)
        .await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.body["bundle"], added.body["bundle"]);

    let replaced = world
        .as_administrator(
            Method::PUT,
            &format!("/trust-domains/{id}"),
            Some(serde_json::json!({ "source": "mesh" })),
        )
        .await;
    assert_eq!(replaced.status, StatusCode::OK);
    assert_eq!(replaced.body["name"], "prod.example.com");
    assert!(replaced.body.get("bundle").is_none());

    let removed = world
        .as_administrator(Method::DELETE, &format!("/trust-domains/{id}"), None)
        .await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    let gone = world
        .as_administrator(Method::GET, &format!("/trust-domains/{id}"), None)
        .await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
    assert_eq!(gone.body["code"], "keys.trust_domain_not_found");

    // Every change is an event for the audit log, and none names the
    // address.
    let types: Vec<String> = world
        .units_of_work
        .committed_events()
        .into_iter()
        .filter(|event| event.event_type.starts_with("keys.trust"))
        .map(|event| {
            assert!(!event.payload.to_string().contains("spire.example.com"));
            event.event_type
        })
        .collect();
    assert_eq!(
        types,
        [
            "keys.trust_domain_added",
            "keys.trust_domain_added",
            "keys.trust_domain_added",
            "keys.trust_domain_replaced",
            "keys.trust_domain_removed",
        ]
    );
}

#[tokio::test]
async fn each_refusal_of_a_trust_domain_has_its_code() {
    let world = world().await;
    world.bundle_endpoints.forbid("https://10.0.0.1/bundle");
    world
        .bundle_endpoints
        .answer("https://moved.example/bundle", 302, b"");
    let cases = [
        (
            serde_json::json!({ "name": "Prod", "source": "mesh" }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "keys.trust_domain_name_invalid",
        ),
        (
            serde_json::json!({ "name": "prod", "source": "other" }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "keys.trust_domain_source_invalid",
        ),
        (
            serde_json::json!({ "name": "prod", "source": "uploaded" }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "keys.trust_domain_source_invalid",
        ),
        (
            serde_json::json!({ "name": "prod", "source": "mesh", "bundle_endpoint_url": "https://e.example/b" }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "keys.trust_domain_source_invalid",
        ),
        (
            serde_json::json!({ "name": "prod", "source": "uploaded", "bundle": [] }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "keys.trust_bundle_invalid",
        ),
        (
            serde_json::json!({ "name": "prod", "source": "bundle_endpoint", "bundle_endpoint_url": "ftp://e.example/b" }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "keys.bundle_endpoint_invalid",
        ),
        (
            serde_json::json!({ "name": "prod", "source": "bundle_endpoint", "bundle_endpoint_url": "https://10.0.0.1/bundle" }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "keys.bundle_endpoint_forbidden",
        ),
        (
            serde_json::json!({ "name": "prod", "source": "bundle_endpoint", "bundle_endpoint_url": "https://moved.example/bundle" }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "keys.bundle_endpoint_unreachable",
        ),
    ];
    for (body, status, code) in cases {
        let reply = world
            .as_administrator(Method::POST, "/trust-domains", Some(body.clone()))
            .await;
        assert_eq!(reply.status, status, "{body}");
        assert_eq!(reply.body["code"], code, "{body}");
    }
    let first = world
        .as_administrator(
            Method::POST,
            "/trust-domains",
            Some(serde_json::json!({ "name": "cluster.local", "source": "mesh" })),
        )
        .await;
    assert_eq!(first.status, StatusCode::CREATED);
    let again = world
        .as_administrator(
            Method::POST,
            "/trust-domains",
            Some(serde_json::json!({ "name": "cluster.local", "source": "mesh" })),
        )
        .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.body["code"], "keys.trust_domain_name_taken");
    // The name cannot be changed.
    let renamed = world
        .as_administrator(
            Method::PUT,
            &format!("/trust-domains/{}", first.body["id"].as_str().expect("id")),
            Some(serde_json::json!({ "name": "other", "source": "mesh" })),
        )
        .await;
    assert_eq!(renamed.status, StatusCode::UNPROCESSABLE_ENTITY);
    // Nothing was fetched from a forbidden address.
    assert!(
        !world
            .bundle_endpoints
            .asked()
            .iter()
            .any(|url| url.contains("10.0.0.1"))
    );

    // An auditor reads trust domains and changes none.
    let acme = world.acme.clone();
    let (_, auditor) = world
        .person(&acme, "auditor@example.com", &[Role::TenantAuditor])
        .await;
    let read = world
        .send(
            Method::GET,
            "/t/acme/api/v1/admin/trust-domains",
            Some(&format!("Bearer {auditor}")),
            None,
        )
        .await;
    assert_eq!(read.status, StatusCode::OK);
    let write = world
        .send(
            Method::POST,
            "/t/acme/api/v1/admin/trust-domains",
            Some(&format!("Bearer {auditor}")),
            Some(serde_json::json!({ "name": "x", "source": "mesh" })),
        )
        .await;
    assert_eq!(write.status, StatusCode::FORBIDDEN);
}
