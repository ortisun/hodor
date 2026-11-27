//! The latency of `evaluate`, against the real server binary and a real
//! database, for a tenant with a few roles, nested groups and an access
//! control list. A measurement, run by hand:
//! `cargo test --release -p hodor-server --test evaluate_latency -- --ignored --nocapture`.
//!
//! The figures, and the machine they were taken on, are in
//! `docs/architecture/contexts/authorization.md`, "The cost of a decision".

#![allow(
    clippy::print_stderr,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the measurement prints what it measured"
)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hodor_adapters_crypto::{OsRandom, Sha256Digest};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgAccessTokenStore, PgRoleAssignmentStore, PgTenantDirectory, PgTenantRepository,
    PgUserRepository,
};
use hodor_authorization::api::{AuthorizationService, Role};
use hodor_credential::api::AccessTokenService;
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_kernel::{Caller, SystemClock, TenantContext, UserId};
use hodor_tenant::api::{CreateTenant, TenantService};
use reqwest::{Client, Method, StatusCode};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::{Duration, Instant};

mod support;
use support::{Server, start_server_with};

/// A root key for tests only, written here in the clear.
const ROOT_KEY: &str = "test:gV8TjmTiZoYOlhsN4OdTTiWMwWa1t/o5RPNGCdbBNro=";
const API: &str = "urn:hodor:authorization";
const DOCUMENTS: &str = "urn:example:documents";

struct World {
    server: Server,
    database: TestDatabase,
    ana: UserId,
    bob: UserId,
    administrator: String,
}

async fn world() -> World {
    let database = TestDatabase::start().await;
    let units = || Arc::new(database.app().clone());
    let clock = Arc::new(SystemClock);
    let tenant = TenantService::new(
        units(),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.app().clone())),
        clock.clone(),
    )
    .create(
        CreateTenant {
            slug: "acme".to_owned(),
            display_name: "Acme".to_owned(),
            open_registration: false,
            system: false,
        },
        Caller::system(),
    )
    .await
    .expect("tenant");
    let tenant = TenantContext::assume(tenant.id());
    let identity = IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone());
    let mut people = Vec::new();
    for email in ["ana@example.com", "bob@example.com", "root@example.com"] {
        let user = identity
            .create(
                &tenant,
                CreateUser {
                    kind: UserKind::Human,
                    identifiers: vec![(IdentifierKind::Email, email.to_owned())],
                    profile: Profile::default(),
                    confirmed: true,
                },
                Caller::system(),
            )
            .await
            .expect("a person");
        people.push(user.id());
    }
    AuthorizationService::new(units(), Arc::new(PgRoleAssignmentStore), clock.clone())
        .assign(
            &tenant,
            people[2],
            Role::TenantAdministrator,
            Caller::system(),
        )
        .await
        .expect("role");
    let (_, secret) = AccessTokenService::new(
        units(),
        Arc::new(PgAccessTokenStore),
        Arc::new(Sha256Digest),
        Arc::new(OsRandom),
        clock,
    )
    .issue(
        &tenant,
        people[2],
        "latency",
        time::Duration::minutes(60),
        Caller::system(),
    )
    .await
    .expect("token");
    let server = start_server_with(&database, &[("HODOR_SECRET_KEYS", ROOT_KEY)]).await;
    World {
        server,
        database,
        ana: people[0],
        bob: people[1],
        administrator: secret.expose().to_owned(),
    }
}

impl World {
    async fn admin(&self, method: Method, path: &str, body: Option<Value>) -> Value {
        let url = format!("{}/t/acme/api/v1/admin{path}", self.server.base);
        let mut request = Client::new()
            .request(method.clone(), url)
            .bearer_auth(&self.administrator);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.expect("response");
        let status = response.status();
        let answer = response.json().await.unwrap_or(Value::Null);
        assert!(status.is_success(), "{method} {path}: {status} {answer}");
        answer
    }

    async fn token(&self, client: &(String, String)) -> String {
        let basic = STANDARD.encode(format!("{}:{}", client.0, client.1));
        let response = Client::new()
            .post(format!("{}/t/acme/oauth2/token", self.server.base))
            .header("authorization", format!("Basic {basic}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(
                form_urlencoded::Serializer::new(String::new())
                    .extend_pairs([
                        ("grant_type", "client_credentials"),
                        ("resource", API),
                        ("scope", "authz:evaluate"),
                    ])
                    .finish(),
            )
            .send()
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let issued: Value = response.json().await.expect("JSON");
        issued["access_token"].as_str().expect("a token").to_owned()
    }
}

/// The Documents application, bound to the native engine, with four
/// permissions, four roles (one including another, one with a
/// condition), two nested groups, assignments to a group and to a person,
/// and one entry of an access control list. Answers the client that asks.
async fn documents(world: &World) -> (String, String) {
    let api = world
        .admin(
            Method::POST,
            "/applications",
            Some(json!({ "name": "Authorization API", "first_party": true })),
        )
        .await;
    world
        .admin(
            Method::POST,
            "/resource-servers",
            Some(json!({
                "application_id": api["id"], "audience": API, "name": "Authorization API",
                "scopes": [{ "name": "authz:evaluate", "description": "Ask" }]
            })),
        )
        .await;
    let application = world
        .admin(
            Method::POST,
            "/applications",
            Some(json!({ "name": "Documents", "first_party": true })),
        )
        .await;
    let server = world
        .admin(
            Method::POST,
            "/resource-servers",
            Some(json!({
                "application_id": application["id"], "audience": DOCUMENTS, "name": "Documents",
                "scopes": [{ "name": "documents:read", "description": "Read documents" }]
            })),
        )
        .await;
    let server = server["id"].as_str().expect("id").to_owned();
    for permission in [
        "document:read",
        "document:write",
        "document:delete",
        "report:read",
    ] {
        world
            .admin(
                Method::PUT,
                &format!("/resource-servers/{server}/permissions/{permission}"),
                Some(json!({ "description": permission })),
            )
            .await;
    }
    for (role, body) in [
        (
            "reader",
            json!({ "permissions": [{ "name": "document:read" }] }),
        ),
        (
            "editor",
            json!({ "permissions": [{ "name": "document:write" }],
                    "includes": [{ "namespace": DOCUMENTS, "name": "reader" }] }),
        ),
        (
            "auditor",
            json!({ "permissions": [{ "name": "report:read" }] }),
        ),
        (
            "cleaner",
            json!({ "permissions": [{ "name": "document:delete",
                                      "condition": "context.attributes.reason == 'cleanup'" }] }),
        ),
    ] {
        world
            .admin(
                Method::PUT,
                &format!("/resource-servers/{server}/roles/{role}"),
                Some(body),
            )
            .await;
    }
    world
        .admin(
            Method::PUT,
            &format!("/resource-servers/{server}/binding"),
            Some(json!({
                "engine": "native", "time_limit_milliseconds": 1000, "sensitive": false,
                "fail_open_actions": [], "trust_asserted": false
            })),
        )
        .await;
    let staff = world
        .admin(Method::POST, "/groups", Some(json!({ "name": "staff" })))
        .await;
    let staff = staff["id"].as_str().expect("id").to_owned();
    let finance = world
        .admin(Method::POST, "/groups", Some(json!({ "name": "finance" })))
        .await;
    let finance = finance["id"].as_str().expect("id").to_owned();
    for (group, member) in [
        (&staff, json!({ "kind": "group", "id": finance })),
        (
            &finance,
            json!({ "kind": "user", "id": world.ana.to_string() }),
        ),
        (
            &staff,
            json!({ "kind": "user", "id": world.bob.to_string() }),
        ),
    ] {
        world
            .admin(
                Method::POST,
                &format!("/groups/{group}/members"),
                Some(member),
            )
            .await;
    }
    for (kind, id, role) in [
        ("group", staff.clone(), "reader"),
        ("group", finance.clone(), "auditor"),
        ("user", world.ana.to_string(), "editor"),
        ("user", world.ana.to_string(), "cleaner"),
    ] {
        world
            .admin(
                Method::POST,
                "/role-assignments",
                Some(json!({ "principal": { "kind": kind, "id": id },
                             "role": { "namespace": DOCUMENTS, "name": role } })),
            )
            .await;
    }
    world
        .admin(
            Method::POST,
            &format!("/resource-servers/{server}/access-entries"),
            Some(json!({
                "permission": "document:delete", "resource_id": "d-42",
                "principal": { "kind": "group", "id": finance }
            })),
        )
        .await;
    let client = world
        .admin(
            Method::POST,
            &format!(
                "/applications/{}/clients",
                application["id"].as_str().expect("id")
            ),
            Some(json!({
                "name": "Documents back end", "type": "confidential",
                "grant_types": ["client_credentials"], "allowed_scopes": ["authz:evaluate"]
            })),
        )
        .await;
    (
        client["id"].as_str().expect("id").to_owned(),
        client["client_secret"]
            .as_str()
            .expect("a secret")
            .to_owned(),
    )
}

/// The questions asked in turn, with the answer each must get: an allow
/// through a group's role, one through an entry, one through a condition,
/// and a deny.
fn questions(world: &World) -> Vec<(Value, &'static str)> {
    let (ana, bob) = (world.ana.to_string(), world.bob.to_string());
    vec![
        (
            json!({ "subject": { "type": "user", "id": ana },
                    "resource": { "type": "document", "id": "d-1" }, "action": "read" }),
            "ALLOW",
        ),
        (
            json!({ "subject": { "type": "user", "id": ana },
                    "resource": { "type": "document", "id": "d-42" }, "action": "delete" }),
            "ALLOW",
        ),
        (
            json!({ "subject": { "type": "user", "id": ana },
                    "resource": { "type": "document", "id": "d-7" }, "action": "delete",
                    "context": { "reason": "cleanup" } }),
            "ALLOW",
        ),
        (
            json!({ "subject": { "type": "user", "id": bob },
                    "resource": { "type": "report", "id": "r-1" }, "action": "read" }),
            "DENY",
        ),
    ]
}

/// The statements one decision of each question sends to the database,
/// as the database logged them: how many, in how many transactions, and,
/// with `EVALUATE_TRACE` set, each of them.
async fn trace(world: &World, http: &Client, url: &str, token: &str, questions: &[(Value, &str)]) {
    const MARKER: &str = "SELECT 'next question'";
    let owner = world.database.owner();
    for statement in [
        "ALTER SYSTEM SET log_min_duration_statement = 0",
        "ALTER SYSTEM SET log_line_prefix = '%m [%p] '",
        "SELECT pg_reload_conf()",
    ] {
        sqlx::query(statement)
            .execute(owner)
            .await
            .expect("logging");
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    for (question, expected) in questions {
        sqlx::query(MARKER).execute(owner).await.expect("marker");
        ask(http, url, token, question, expected).await;
    }
    sqlx::query(MARKER).execute(owner).await.expect("marker");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let port = world
        .database
        .app_url()
        .rsplit(':')
        .next()
        .and_then(|tail| tail.split('/').next())
        .expect("port")
        .to_owned();
    let found = std::process::Command::new("docker")
        .args(["ps", "-q", "--filter", &format!("publish={port}")])
        .output()
        .expect("docker ps");
    let container = String::from_utf8_lossy(&found.stdout).trim().to_owned();
    let logs = std::process::Command::new("docker")
        .args(["logs", &container])
        .output()
        .expect("docker logs");
    let text = String::from_utf8_lossy(&logs.stderr);
    let printed = std::env::var_os("EVALUATE_TRACE").is_some();
    // Each decision lies between the executions of two markers; the
    // statements of the extended protocol are logged at `execute`, the
    // simple ones whole.
    let mut decisions: Vec<Vec<&str>> = Vec::new();
    for line in text.lines() {
        let executed = line.contains(" execute ") || line.contains(" statement: ");
        if !executed {
            continue;
        }
        if line.contains(MARKER) {
            decisions.push(Vec::new());
        } else if let Some(decision) = decisions.last_mut() {
            decision.push(line);
        }
    }
    decisions.truncate(questions.len());
    for (index, statements) in decisions.iter().enumerate() {
        let transactions = statements
            .iter()
            .filter(|line| line.contains("BEGIN"))
            .count();
        eprintln!(
            "question {}: {} statements in {} transactions",
            index + 1,
            statements.len(),
            transactions
        );
        if printed {
            for line in statements {
                eprintln!("    {}", line.chars().take(160).collect::<String>());
            }
        }
    }
}

fn percentile(samples: &mut [Duration], rank: f64) -> f64 {
    samples.sort();
    let index = ((samples.len() as f64) * rank).ceil() as usize;
    samples[index.saturating_sub(1).min(samples.len() - 1)].as_secs_f64() * 1000.0
}

async fn ask(http: &Client, url: &str, token: &str, question: &Value, expected: &str) {
    let response = http
        .post(url)
        .bearer_auth(token)
        .json(question)
        .send()
        .await
        .expect("evaluate");
    assert_eq!(response.status(), StatusCode::OK);
    let answer: Value = response.json().await.expect("JSON");
    assert_eq!(answer["decision"], expected, "{question} {answer}");
}

/// The 50th and 99th percentiles of one caller asking in turn, the
/// throughput of 16 callers at once, and the statements one decision
/// sends to the database.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement, run by hand and published"]
async fn latency() {
    const WARM_UP: usize = 200;
    const MEASURED: usize = 2000;
    const CALLERS: usize = 16;
    const PER_CALLER: usize = 250;
    let world = world().await;
    let client = documents(&world).await;
    let token = world.token(&client).await;
    let questions = questions(&world);
    let url = format!("{}/t/acme/api/v1/authorization/evaluate", world.server.base);
    let http = Client::new();

    for round in 0..WARM_UP {
        let (question, expected) = &questions[round % questions.len()];
        ask(&http, &url, &token, question, expected).await;
    }

    let mut one_caller = Vec::with_capacity(MEASURED);
    for round in 0..MEASURED {
        let (question, expected) = &questions[round % questions.len()];
        let started = Instant::now();
        ask(&http, &url, &token, question, expected).await;
        one_caller.push(started.elapsed());
    }

    let started = Instant::now();
    let mut callers = Vec::new();
    for caller in 0..CALLERS {
        let (http, url, token, questions) =
            (http.clone(), url.clone(), token.clone(), questions.clone());
        callers.push(tokio::spawn(async move {
            let mut took = Vec::with_capacity(PER_CALLER);
            for round in 0..PER_CALLER {
                let (question, expected) = &questions[(caller + round) % questions.len()];
                let asked = Instant::now();
                ask(&http, &url, &token, question, expected).await;
                took.push(asked.elapsed());
            }
            took
        }));
    }
    let mut at_once = Vec::with_capacity(CALLERS * PER_CALLER);
    for caller in callers {
        at_once.extend(caller.await.expect("a caller"));
    }
    let elapsed = started.elapsed();

    eprintln!(
        "one caller: 50th percentile {:.2} ms, 99th percentile {:.2} ms, {:.0} decisions per second",
        percentile(&mut one_caller, 0.50),
        percentile(&mut one_caller, 0.99),
        MEASURED as f64 / one_caller.iter().sum::<Duration>().as_secs_f64()
    );
    eprintln!(
        "{CALLERS} callers: 50th percentile {:.2} ms, 99th percentile {:.2} ms, {:.0} decisions per second",
        percentile(&mut at_once, 0.50),
        percentile(&mut at_once, 0.99),
        (CALLERS * PER_CALLER) as f64 / elapsed.as_secs_f64()
    );
    // Last, since logging every statement slows the database down.
    trace(&world, &http, &url, &token, &questions).await;
}
