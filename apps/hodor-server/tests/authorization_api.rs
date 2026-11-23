//! An application asks the Authorization API of the real server binary,
//! against a real database, with an access token it got with its own
//! credentials.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hodor_adapters_crypto::{LocalKeyProvider, OsRandom, SecretKeys, Sha256Digest};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgApplicationStore, PgClientStore, PgEngineBindingStore, PgKeyStore, PgNativeRoleStore,
    PgResourceServerStore, PgRoleAssignmentStore, PgTenantDirectory, PgTenantRepository,
    PgUserRepository,
};
use hodor_authorization::api::{
    AssignmentScope, Attributes, BindingSettings, EngineId, EngineRegistry, EvaluationService,
    Namespace, NativeEngine, PermissionName, RoleContents, RoleKey, RoleName, RoleService, Subject,
    SubjectAttributeSource, SubjectKind, Validity,
};
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_kernel::{Caller, DomainError, Secret, SystemClock, TenantContext, UserId};
use hodor_keys::api::{KeyAlgorithm, KeyService, RotationPolicy};
use hodor_oauth::api::{
    ApplicationId, ApplicationPorts, ApplicationService, ApplicationSettings, AuthenticationMethod,
    ClientSettings, ClientType, CreateClient, CreateResourceServer, GrantType,
    ResourceServerSettings, ScopeDefinition,
};
use hodor_tenant::api::{CreateTenant, TenantService};
use reqwest::StatusCode;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

mod support;
use support::{Server, start_server_with};

/// A root key for tests only, written here in the clear.
const ROOT_KEY: &str = "test:gV8TjmTiZoYOlhsN4OdTTiWMwWa1t/o5RPNGCdbBNro=";
const API: &str = "urn:hodor:authorization";
const PAYROLL: &str = "urn:example:payroll";
const LEDGER: &str = "urn:example:ledger";

/// What Hodor knows of nobody: enough to bind, the server resolves for
/// real.
struct NoAttributes;

#[async_trait::async_trait]
impl SubjectAttributeSource for NoAttributes {
    async fn attributes_of(
        &self,
        _tenant: &TenantContext,
        _subject: &Subject,
    ) -> Result<Attributes, DomainError> {
        Ok(Attributes::none())
    }
}

/// A client of one application, with its secret.
struct Credentials {
    id: String,
    secret: String,
}

struct Tenant {
    ana: UserId,
    bob: UserId,
    /// Of Payroll, allowed to evaluate and simulate.
    evaluator: Credentials,
    /// Of Payroll, also allowed explanations.
    explainer: Credentials,
    /// Of Ledger, whose resource server has no binding.
    ledger: Credentials,
    /// Of Reports, which has no resource server.
    reports: Credentials,
}

fn units(database: &TestDatabase) -> Arc<hodor_adapters_postgres::Database> {
    Arc::new(database.app().clone())
}

async fn person(identity: &IdentityService, tenant: &TenantContext, email: &str) -> UserId {
    identity
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
        .id()
}

async fn application(
    applications: &ApplicationService,
    tenant: &TenantContext,
    name: &str,
    audience: Option<(&str, &[&str])>,
) -> ApplicationId {
    let application = applications
        .create_application(
            tenant,
            ApplicationSettings {
                name: name.to_owned(),
                first_party: true,
            },
            Caller::system(),
        )
        .await
        .expect("application")
        .id();
    if let Some((audience, scopes)) = audience {
        applications
            .create_resource_server(
                tenant,
                CreateResourceServer {
                    application_id: application,
                    audience: audience.to_owned(),
                    settings: ResourceServerSettings {
                        name: name.to_owned(),
                        scopes: scopes
                            .iter()
                            .map(|scope| ScopeDefinition {
                                name: (*scope).to_owned(),
                                description: (*scope).to_owned(),
                            })
                            .collect(),
                    },
                },
                Caller::system(),
            )
            .await
            .expect("resource server");
    }
    application
}

async fn service_client(
    applications: &ApplicationService,
    tenant: &TenantContext,
    application_id: ApplicationId,
    scopes: &[&str],
) -> Credentials {
    let mut settings = ClientSettings::new(
        "Service",
        ClientType::Confidential,
        vec![GrantType::ClientCredentials],
        Vec::new(),
    );
    settings.authentication_method = AuthenticationMethod::ClientSecretBasic;
    settings.allowed_scopes = scopes.iter().map(|scope| (*scope).to_owned()).collect();
    let (client, secret) = applications
        .create_client(
            tenant,
            CreateClient {
                application_id,
                client_type: ClientType::Confidential,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client");
    Credentials {
        id: client.id().to_string(),
        secret: secret.expect("a secret").expose().to_owned(),
    }
}

/// A tenant whose Payroll application asks about invoices: Ana holds the
/// approver role, Bob holds nothing.
async fn tenant(database: &TestDatabase, slug: &str) -> Tenant {
    let clock = Arc::new(SystemClock);
    let created = TenantService::new(
        units(database),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.app().clone())),
        clock.clone(),
    )
    .create(
        CreateTenant {
            slug: slug.to_owned(),
            display_name: slug.to_owned(),
            open_registration: false,
            system: false,
        },
        Caller::system(),
    )
    .await
    .expect("tenant");
    let context = TenantContext::assume(created.id());
    let identity = IdentityService::new(units(database), Arc::new(PgUserRepository), clock.clone());
    let ana = person(&identity, &context, "ana@example.com").await;
    let bob = person(&identity, &context, "bob@example.com").await;
    let root = Arc::new(SecretKeys::parse(&Secret::from(ROOT_KEY.to_owned())).expect("root"));
    KeyService::new(
        units(database),
        Arc::new(PgKeyStore),
        Arc::new(LocalKeyProvider::new(root)),
        clock.clone(),
    )
    .rotate_now(
        &context,
        KeyAlgorithm::Es256,
        &RotationPolicy::DEFAULT,
        Caller::system(),
    )
    .await
    .expect("a signing key");

    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: units(database),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        digest: Arc::new(Sha256Digest),
        random: Arc::new(OsRandom),
        clock: clock.clone(),
    });
    let api_scopes: &[&str] = &["authz:evaluate", "authz:simulate", "authz:explain"];
    application(
        &applications,
        &context,
        "Authorization API",
        Some((API, api_scopes)),
    )
    .await;
    let payroll = application(
        &applications,
        &context,
        "Payroll",
        Some((PAYROLL, &["payroll:read"])),
    )
    .await;
    let ledger = application(
        &applications,
        &context,
        "Ledger",
        Some((LEDGER, &["ledger:read"])),
    )
    .await;
    let reports = application(&applications, &context, "Reports", None).await;
    let evaluator = service_client(
        &applications,
        &context,
        payroll,
        &["authz:evaluate", "authz:simulate"],
    )
    .await;
    let explainer = service_client(&applications, &context, payroll, api_scopes).await;
    let ledger = service_client(&applications, &context, ledger, &["authz:evaluate"]).await;
    let reports = service_client(&applications, &context, reports, &["authz:evaluate"]).await;

    // Payroll's invoices are answered by the native engine.
    let roles = RoleService::new(units(database), Arc::new(PgNativeRoleStore), clock.clone());
    let namespace = Namespace::parse(PAYROLL).expect("namespace");
    let approve = PermissionName::parse("invoice:approve").expect("permission");
    roles
        .declare_permission(
            &context,
            namespace.clone(),
            approve.clone(),
            "approves an invoice",
            Caller::system(),
        )
        .await
        .expect("permission");
    let approver = RoleKey::new(
        namespace.clone(),
        RoleName::parse("approver").expect("name"),
    );
    roles
        .define_role(
            &context,
            approver.clone(),
            RoleContents {
                description: String::new(),
                permissions: BTreeSet::from([approve]),
                includes: BTreeSet::new(),
                conditions: BTreeMap::new(),
            },
            Caller::system(),
        )
        .await
        .expect("role");
    roles
        .assign(
            &context,
            Subject::new(SubjectKind::User, &ana.to_string()).expect("subject"),
            approver,
            AssignmentScope::Tenant,
            Validity::default(),
            Caller::system(),
        )
        .await
        .expect("assignment");
    let mut registry = EngineRegistry::new();
    registry
        .register(Arc::new(NativeEngine::new(
            units(database),
            Arc::new(PgRoleAssignmentStore),
            Arc::new(PgNativeRoleStore),
            clock.clone(),
        )))
        .expect("register");
    EvaluationService::new(
        units(database),
        Arc::new(PgRoleAssignmentStore),
        Arc::new(PgEngineBindingStore),
        Arc::new(NoAttributes),
        registry,
        clock,
    )
    .bind(
        &context,
        BindingSettings::new(namespace, EngineId::native()),
        Caller::system(),
    )
    .await
    .expect("binding");

    Tenant {
        ana,
        bob,
        evaluator,
        explainer,
        ledger,
        reports,
    }
}

async fn server(database: &TestDatabase) -> Server {
    start_server_with(database, &[("HODOR_SECRET_KEYS", ROOT_KEY)]).await
}

fn basic(client: &Credentials) -> String {
    format!(
        "Basic {}",
        STANDARD.encode(format!("{}:{}", client.id, client.secret))
    )
}

/// An access token for the Authorization API, with `scope`.
async fn access_token(server: &Server, slug: &str, client: &Credentials, scope: &str) -> String {
    let response = reqwest::Client::new()
        .post(format!("{}/t/{slug}/oauth2/token", server.base))
        .header("authorization", basic(client))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(
            form_urlencoded::Serializer::new(String::new())
                .extend_pairs([
                    ("grant_type", "client_credentials"),
                    ("resource", API),
                    ("scope", scope),
                ])
                .finish(),
        )
        .send()
        .await
        .expect("token response");
    let status = response.status();
    let body: Value = response.json().await.expect("token body");
    assert_eq!(status, StatusCode::OK, "{body}");
    body["access_token"].as_str().expect("token").to_owned()
}

struct Answer {
    status: StatusCode,
    challenge: Option<String>,
    body: Value,
}

async fn ask(
    server: &Server,
    slug: &str,
    route: &str,
    token: Option<&str>,
    body: &Value,
) -> Answer {
    let mut request = reqwest::Client::new()
        .post(format!(
            "{}/t/{slug}/api/v1/authorization/{route}",
            server.base
        ))
        .json(body);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.expect("response");
    let status = response.status();
    let challenge = response
        .headers()
        .get("www-authenticate")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = response.json().await.unwrap_or(Value::Null);
    Answer {
        status,
        challenge,
        body,
    }
}

fn question(user: UserId) -> Value {
    json!({
        "subject": { "type": "user", "id": user.to_string() },
        "resource": { "type": "invoice", "id": "invoice-456", "attributes": { "amount": 5000 } },
        "action": "approve",
        "context": { "environment": "production" }
    })
}

#[tokio::test]
async fn an_application_asks_about_its_own_resources() {
    let database = TestDatabase::start().await;
    let acme = tenant(&database, "acme").await;
    let server = server(&database).await;
    let token = access_token(
        &server,
        "acme",
        &acme.evaluator,
        "authz:evaluate authz:simulate",
    )
    .await;

    let allowed = ask(
        &server,
        "acme",
        "evaluate",
        Some(&token),
        &question(acme.ana),
    )
    .await;
    assert_eq!(allowed.status, StatusCode::OK, "{}", allowed.body);
    assert_eq!(allowed.body["decision"], "ALLOW");
    assert_eq!(allowed.body["reason"], "matching_role");
    assert_eq!(allowed.body["engine"], "native");
    assert!(allowed.body["decision_id"].is_string());
    assert!(allowed.body["evaluated_at"].is_string());
    // Without authz:explain, the reason code only.
    assert!(
        allowed.body.get("matched_policies").is_none(),
        "{}",
        allowed.body
    );
    // Nothing of the subject comes back.
    assert!(!allowed.body.to_string().contains("active"));

    let denied = ask(
        &server,
        "acme",
        "evaluate",
        Some(&token),
        &question(acme.bob),
    )
    .await;
    assert_eq!(denied.body["decision"], "DENY");
    assert_eq!(denied.body["reason"], "no_matching_role");

    // One result per request, in order; one that cannot be read is a
    // problem in its place.
    let batch = ask(
        &server,
        "acme",
        "batch",
        Some(&token),
        &json!({ "requests": [
            question(acme.ana),
            { "subject": { "type": "group", "id": "x" }, "resource": { "type": "invoice" }, "action": "approve" },
            question(acme.bob),
        ] }),
    )
    .await;
    assert_eq!(batch.status, StatusCode::OK, "{}", batch.body);
    let results = batch.body["results"].as_array().expect("results");
    assert_eq!(results.len(), 3);
    assert_eq!(results[0]["decision"], "ALLOW");
    assert_eq!(
        results[1]["code"], "authorization.subject_kind_invalid",
        "{}",
        results[1]
    );
    assert_eq!(results[2]["decision"], "DENY");
    let too_many: Vec<Value> = (0..101).map(|_| question(acme.ana)).collect();
    let refused = ask(
        &server,
        "acme",
        "batch",
        Some(&token),
        &json!({ "requests": too_many }),
    )
    .await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(refused.body["code"], "authorization.batch_too_large");

    // A simulation against what is published, without its trace.
    let mut simulated_question = question(acme.ana);
    simulated_question["against"] = json!({ "published": true });
    let simulated = ask(
        &server,
        "acme",
        "simulate",
        Some(&token),
        &simulated_question,
    )
    .await;
    assert_eq!(simulated.status, StatusCode::OK, "{}", simulated.body);
    assert_eq!(simulated.body["decision"], "ALLOW");
    assert!(simulated.body.get("trace").is_none());
    let mut revision = question(acme.ana);
    revision["against"] = json!({ "revision": "rev-1" });
    let unsupported = ask(&server, "acme", "simulate", Some(&token), &revision).await;
    assert_eq!(unsupported.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        unsupported.body["code"],
        "authorization.simulation_unsupported"
    );

    // With authz:explain: the role that decided, and the trace.
    let explaining = access_token(
        &server,
        "acme",
        &acme.explainer,
        "authz:evaluate authz:simulate authz:explain",
    )
    .await;
    let explained = ask(
        &server,
        "acme",
        "evaluate",
        Some(&explaining),
        &question(acme.ana),
    )
    .await;
    let policies = explained.body["matched_policies"]
        .as_array()
        .expect("policies");
    assert!(
        policies.iter().any(|policy| policy
            .as_str()
            .is_some_and(|name| name.contains("approver"))),
        "{}",
        explained.body
    );
    let traced = ask(
        &server,
        "acme",
        "simulate",
        Some(&explaining),
        &simulated_question,
    )
    .await;
    assert!(
        traced.body["trace"]
            .as_array()
            .is_some_and(|trace| !trace.is_empty())
    );

    // An unbound resource server is denied everything.
    let ledger = access_token(&server, "acme", &acme.ledger, "authz:evaluate").await;
    let unbound = ask(
        &server,
        "acme",
        "evaluate",
        Some(&ledger),
        &question(acme.ana),
    )
    .await;
    assert_eq!(unbound.body["decision"], "DENY");
    assert_eq!(unbound.body["reason"], "no_engine_bound");

    // An application without a resource server has nothing to ask about.
    let reports = access_token(&server, "acme", &acme.reports, "authz:evaluate").await;
    let nothing = ask(
        &server,
        "acme",
        "evaluate",
        Some(&reports),
        &question(acme.ana),
    )
    .await;
    assert_eq!(nothing.status, StatusCode::FORBIDDEN);
    assert_eq!(nothing.body["code"], "authorization.no_resource_server");

    // The document of the API is served without a token.
    let document: Value = reqwest::get(format!(
        "{}/t/acme/api/v1/authorization/openapi.json",
        server.base
    ))
    .await
    .expect("document")
    .json()
    .await
    .expect("json");
    assert_eq!(document["info"]["title"], "Hodor Authorization API");
}

#[tokio::test]
async fn only_a_good_token_of_the_tenant_with_the_scope_may_ask() {
    let database = TestDatabase::start().await;
    let acme = tenant(&database, "acme").await;
    let globex = tenant(&database, "globex").await;
    let server = server(&database).await;
    let body = question(acme.ana);

    let missing = ask(&server, "acme", "evaluate", None, &body).await;
    assert_eq!(missing.status, StatusCode::UNAUTHORIZED);
    assert_eq!(missing.challenge.as_deref(), Some("Bearer"));

    // Globex's token, at Acme: another issuer and other keys.
    let foreign = access_token(&server, "globex", &globex.evaluator, "authz:evaluate").await;
    let refused = ask(&server, "acme", "evaluate", Some(&foreign), &body).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        refused.challenge.as_deref(),
        Some("Bearer error=\"invalid_token\"")
    );

    // A token without the route's scope.
    let evaluate_only = access_token(&server, "acme", &acme.evaluator, "authz:evaluate").await;
    let mut simulation = body.clone();
    simulation["against"] = json!({ "published": true });
    let scope = ask(
        &server,
        "acme",
        "simulate",
        Some(&evaluate_only),
        &simulation,
    )
    .await;
    assert_eq!(scope.status, StatusCode::FORBIDDEN);
    assert_eq!(
        scope.challenge.as_deref(),
        Some("Bearer error=\"insufficient_scope\", scope=\"authz:simulate\"")
    );

    // A revoked token stops working at once.
    let revocable = access_token(&server, "acme", &acme.evaluator, "authz:evaluate").await;
    assert_eq!(
        ask(&server, "acme", "evaluate", Some(&revocable), &body)
            .await
            .status,
        StatusCode::OK
    );
    let revoked = reqwest::Client::new()
        .post(format!("{}/t/acme/oauth2/revoke", server.base))
        .header("authorization", basic(&acme.evaluator))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(
            form_urlencoded::Serializer::new(String::new())
                .append_pair("token", &revocable)
                .finish(),
        )
        .send()
        .await
        .expect("revocation");
    assert_eq!(revoked.status(), StatusCode::OK);
    let after = ask(&server, "acme", "evaluate", Some(&revocable), &body).await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);

    // A body that names a tenant, or anything unknown, is not a question.
    let mut named = body.clone();
    named["tenant_id"] = json!("anything");
    let unreadable = ask(&server, "acme", "evaluate", Some(&evaluate_only), &named).await;
    assert_eq!(unreadable.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(unreadable.body["code"], "request.body_invalid");

    // Globex's own question about Acme's people is answered in Globex:
    // Ana holds nothing there.
    let globex_token = access_token(&server, "globex", &globex.evaluator, "authz:evaluate").await;
    let elsewhere = ask(&server, "globex", "evaluate", Some(&globex_token), &body).await;
    assert_eq!(elsewhere.body["decision"], "DENY");
}

#[tokio::test]
async fn the_decisions_asked_for_are_recorded_and_simulations_are_not() {
    let database = TestDatabase::start().await;
    let acme = tenant(&database, "acme").await;
    let server = server(&database).await;
    let token = access_token(
        &server,
        "acme",
        &acme.evaluator,
        "authz:evaluate authz:simulate",
    )
    .await;

    let allowed = ask(
        &server,
        "acme",
        "evaluate",
        Some(&token),
        &question(acme.ana),
    )
    .await;
    let denied = ask(
        &server,
        "acme",
        "evaluate",
        Some(&token),
        &question(acme.bob),
    )
    .await;
    let mut simulated_question = question(acme.ana);
    simulated_question["against"] = json!({ "published": true });
    let simulated = ask(
        &server,
        "acme",
        "simulate",
        Some(&token),
        &simulated_question,
    )
    .await;
    assert_eq!(simulated.status, StatusCode::OK, "{}", simulated.body);

    let rows: Vec<(String, String, String, String, Value)> = sqlx::query_as(
        "SELECT decision_id::text, effect, reason, subject_id, input
         FROM \"authorization\".decision_log ORDER BY decided_at",
    )
    .fetch_all(database.owner())
    .await
    .expect("records");
    let ids: Vec<&str> = rows.iter().map(|row| row.0.as_str()).collect();
    assert_eq!(
        ids,
        [
            allowed.body["decision_id"].as_str().expect("allowed"),
            denied.body["decision_id"].as_str().expect("denied"),
        ],
        "the two evaluations, and not the simulation"
    );
    assert_eq!(
        (rows[0].1.as_str(), rows[0].2.as_str()),
        ("allow", "matching_role")
    );
    assert_eq!(
        (rows[1].1.as_str(), rows[1].2.as_str()),
        ("deny", "no_matching_role")
    );
    assert_eq!(rows[0].3, acme.ana.to_string());
    assert_eq!(rows[0].4["resource"]["attributes"]["amount"], 5000);
    assert_eq!(
        rows[0].4["context"]["attributes"]["environment"],
        "production"
    );
}
