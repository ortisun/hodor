//! The interaction interface, exercised over HTTP against the real
//! contexts running on their in-memory ports.

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use hodor_authentication::api::{
    AccountService, AttemptGuard, AuthFlow, AuthenticationService, FlowEngine,
    IdentifierAuthenticator, PasswordAuthenticator,
};
use hodor_authentication::testing::{
    InMemoryAttempts, InMemoryTransactions, InMemoryVerificationTokens,
};
use hodor_credential::api::{CredentialService, NewPassword, PasswordRules};
use hodor_credential::testing::{FakeHasher, InMemoryPasswords};
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_identity::testing::InMemoryUsers;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, DomainError, Secret, TenantContext, Timestamp, UserId};
use hodor_notification::api::Notifier;
use hodor_notification::testing::InMemoryMessages;
use hodor_protocol_http::{
    InteractionState, Limits, ResolvedTenant, TenantResolver, TenantStatus, interaction_routes,
    public_router,
};
use hodor_session::api::SessionService;
use hodor_session::testing::{InMemorySessions, SequentialRandom};
use hodor_tenant::api::{CreateTenant, TenantService};
use hodor_tenant::testing::InMemoryTenants;
use http_body_util::BodyExt as _;
use std::collections::BTreeMap;
use std::sync::Arc;
use time::Duration;
use tower::ServiceExt as _;

const PASSWORD: &str = "correct horse battery staple";
const HOST: &str = "auth.example";

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
    ana: UserId,
    acme: TenantContext,
    /// What would be in people's mailboxes.
    messages: InMemoryMessages,
}

impl World {
    /// The token in the link of the newest message, as a page would read
    /// it from the address bar.
    fn newest_token(&self) -> String {
        let message = self
            .messages
            .of_tenant(self.acme.tenant_id())
            .pop()
            .expect("a message was queued");
        let link = &message.snapshot().variables["link"];
        link.split_once("#token=").expect("token").1.to_owned()
    }

    fn templates(&self) -> Vec<&'static str> {
        self.messages
            .of_tenant(self.acme.tenant_id())
            .iter()
            .map(|message| message.snapshot().template.key())
            .collect()
    }
}

async fn world() -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let clock = Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH));
    let digest = Arc::new(FakeDigest);
    let units = || Arc::new(units_of_work.clone());

    let tenant_rows = InMemoryTenants::default();
    let tenants = TenantService::new(
        units(),
        Arc::new(tenant_rows.clone()),
        Arc::new(tenant_rows),
        clock.clone(),
    );
    let identity = IdentityService::new(units(), Arc::new(InMemoryUsers::default()), clock.clone());
    let credentials = CredentialService::new(
        units(),
        Arc::new(InMemoryPasswords::default()),
        Arc::new(FakeHasher::default()),
        clock.clone(),
    );
    let sessions = SessionService::new(
        units(),
        Arc::new(InMemorySessions::default()),
        digest.clone(),
        Arc::new(SequentialRandom::default()),
        clock.clone(),
    );
    let guard = AttemptGuard::new(
        units(),
        Arc::new(InMemoryAttempts::default()),
        digest.clone(),
        clock.clone(),
    );
    let engine = FlowEngine::new()
        .with(Arc::new(IdentifierAuthenticator::new(
            identity.clone(),
            digest.clone(),
        )))
        .with(Arc::new(PasswordAuthenticator::new(
            credentials.clone(),
            identity.clone(),
            tenants.clone(),
            guard.clone(),
        )));
    let messages = InMemoryMessages::default();
    let accounts = AccountService::new(
        units(),
        Arc::new(InMemoryVerificationTokens::default()),
        identity.clone(),
        credentials.clone(),
        sessions.clone(),
        tenants.clone(),
        Notifier::new(Arc::new(messages.clone()), clock.clone()),
        guard,
        digest.clone(),
        Arc::new(SequentialRandom::default()),
        clock.clone(),
        "https://auth.example",
    );
    let authentication = AuthenticationService::new(
        units(),
        Arc::new(InMemoryTransactions::default()),
        engine,
        AuthFlow::built_in(),
        identity.clone(),
        sessions.clone(),
        tenants.clone(),
        digest.clone(),
        Arc::new(SequentialRandom::default()),
        clock.clone(),
    )
    .expect("the built-in flow is valid");

    let mut contexts = Vec::new();
    for slug in ["acme", "globex"] {
        let created = tenants
            .create(
                CreateTenant {
                    slug: slug.to_owned(),
                    display_name: slug.to_owned(),
                    // Acme accepts registrations; Globex does not.
                    open_registration: slug == "acme",
                    system: false,
                },
                Caller::system(),
            )
            .await
            .expect("tenant");
        contexts.push(TenantContext::assume(created.id()));
    }
    let (acme, globex) = (contexts[0].clone(), contexts[1].clone());

    let ana = identity
        .create(
            &acme,
            CreateUser {
                kind: UserKind::Human,
                identifiers: vec![(IdentifierKind::Email, "ana@example.com".to_owned())],
                profile: Profile::default(),
                confirmed: true,
            },
            Caller::system(),
        )
        .await
        .expect("user")
        .id();
    let password = Secret::from(PASSWORD.to_owned());
    let new = NewPassword {
        password: &password,
        rules: PasswordRules {
            min_length: 12,
            max_length: 128,
            history_depth: 5,
        },
        own_names: &[],
    };
    credentials
        .set_password(&acme, ana, new, false, Caller::system())
        .await
        .expect("password");

    let state = InteractionState {
        authentication,
        accounts,
        sessions,
        digest,
        clock: clock.clone(),
    };
    let router = public_router(
        Arc::new(Tenants {
            acme: acme.clone(),
            globex,
        }),
        Router::new().nest("/interaction", interaction_routes(state)),
        Router::new(),
        Limits::default(),
    );
    World {
        router,
        clock,
        ana,
        acme,
        messages,
    }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: serde_json::Value,
}

impl Reply {
    fn set_cookies(&self) -> Vec<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().expect("ascii").to_owned())
            .collect()
    }

    fn code(&self) -> &str {
        self.body["code"].as_str().unwrap_or_default()
    }
}

/// A browser, as far as these tests need one: it keeps cookies and the
/// CSRF token, and sends them back.
#[derive(Default, Clone)]
struct Browser {
    cookies: BTreeMap<String, String>,
    csrf_token: Option<String>,
    origin: Option<&'static str>,
}

impl Browser {
    fn remember(&mut self, reply: &Reply) {
        for cookie in reply.set_cookies() {
            let pair = cookie.split(';').next().expect("name=value");
            let (name, value) = pair.split_once('=').expect("name=value");
            if cookie.contains("Max-Age=0") {
                self.cookies.remove(name);
            } else {
                self.cookies.insert(name.to_owned(), value.to_owned());
            }
        }
        if let Some(token) = reply.body["csrf_token"].as_str() {
            self.csrf_token = Some(token.to_owned());
        }
    }

    async fn send(
        &mut self,
        world: &World,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Reply {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, HOST);
        if !self.cookies.is_empty() {
            let cookies: Vec<String> = self
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            request = request.header(header::COOKIE, cookies.join("; "));
        }
        if let Some(token) = &self.csrf_token {
            request = request.header("x-csrf-token", token);
        }
        if let Some(origin) = self.origin {
            request = request.header(header::ORIGIN, origin);
        }
        let request = match body {
            Some(body) => request
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        }
        .expect("request");

        let response = world
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("response");
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.expect("body").to_bytes();
        let reply = Reply {
            status: parts.status,
            headers: parts.headers,
            body: serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        };
        self.remember(&reply);
        reply
    }

    async fn start(&mut self, world: &World) -> Reply {
        self.send(world, Method::POST, "/t/acme/interaction/sign-in", None)
            .await
    }

    async fn identifier(&mut self, world: &World, typed: &str) -> Reply {
        let body = serde_json::json!({ "identifier": typed });
        self.send(
            world,
            Method::POST,
            "/t/acme/interaction/sign-in/steps/identifier",
            Some(body),
        )
        .await
    }

    async fn password(&mut self, world: &World, typed: &str) -> Reply {
        let body = serde_json::json!({ "password": typed });
        self.send(
            world,
            Method::POST,
            "/t/acme/interaction/sign-in/steps/password",
            Some(body),
        )
        .await
    }

    async fn session(&mut self, world: &World, tenant: &str) -> Reply {
        self.send(
            world,
            Method::GET,
            &format!("/t/{tenant}/interaction/session"),
            None,
        )
        .await
    }
}

#[tokio::test]
async fn a_person_signs_in_and_the_browser_ends_up_with_a_session() {
    let world = world().await;
    let mut browser = Browser::default();

    let started = browser.start(&world).await;
    assert_eq!(started.status, StatusCode::CREATED);
    assert_eq!(started.body["status"], "pending");
    assert_eq!(started.body["step"], "identifier");

    let next = browser.identifier(&world, "Ana@Example.com").await;
    assert_eq!(
        (next.status, next.body["step"].as_str()),
        (StatusCode::OK, Some("password"))
    );

    let done = browser.password(&world, PASSWORD).await;
    assert_eq!(done.status, StatusCode::OK);
    assert_eq!(done.body, serde_json::json!({ "status": "completed" }));

    let session = browser.session(&world, "acme").await;
    assert_eq!(session.status, StatusCode::OK);
    assert_eq!(session.body["user_id"], world.ana.to_string());
    assert_eq!(session.body["assurance"], "single_factor");
    assert_eq!(session.body["methods"], serde_json::json!(["password"]));
    assert_eq!(session.body["signed_in_at"], "1970-01-01T00:00:00Z");
    assert_eq!(session.body["expires_at"], "1970-01-01T00:30:00Z");
}

#[tokio::test]
async fn the_cookies_have_every_attribute_the_specification_gives_them() {
    let world = world().await;
    let mut browser = Browser::default();

    let started = browser.start(&world).await;
    let cookies = started.set_cookies();
    assert_eq!(cookies.len(), 1);
    let sign_in = &cookies[0];
    assert!(sign_in.starts_with("__Secure-hodor_signin="), "{sign_in}");
    assert!(
        sign_in.ends_with(
            "; Path=/t/acme/interaction; Max-Age=600; HttpOnly; Secure; SameSite=Strict"
        ),
        "{sign_in}"
    );

    browser.identifier(&world, "ana@example.com").await;
    let done = browser.password(&world, PASSWORD).await;
    let cookies = done.set_cookies();
    assert_eq!(cookies.len(), 2, "{cookies:?}");
    assert_eq!(
        cookies[0],
        "__Secure-hodor_signin=; Path=/t/acme/interaction; Max-Age=0; HttpOnly; Secure; SameSite=Strict",
        "the sign-in cookie is removed"
    );
    let session = &cookies[1];
    assert!(session.starts_with("__Secure-hodor_session="), "{session}");
    // Twelve hours: the tenant's absolute session timeout.
    assert!(
        session.ends_with("; Path=/t/acme; Max-Age=43200; HttpOnly; Secure; SameSite=Lax"),
        "{session}"
    );
    let token = session.split(['=', ';']).nth(1).expect("value");
    assert_eq!(token.len(), 64);
}

#[tokio::test]
async fn nothing_about_a_sign_in_but_its_state_reaches_the_page() {
    let world = world().await;
    let mut browser = Browser::default();
    let started = browser.start(&world).await;
    let cookie = browser.cookies["__Secure-hodor_signin"].clone();
    let (transaction_id, secret) = cookie.split_once('.').expect("identifier and secret");

    // The body holds the state and the CSRF token, and neither the
    // identifier of the sign-in nor its secret.
    let keys: Vec<&String> = started.body.as_object().expect("object").keys().collect();
    assert_eq!(keys, ["csrf_token", "status", "step"]);
    let body = started.body.to_string();
    assert!(!body.contains(transaction_id) && !body.contains(secret));
    // The CSRF token is derived from the secret, but is not the secret.
    assert_ne!(started.body["csrf_token"], secret);

    // Sign-in responses are not to be cached.
    assert_eq!(started.headers[header::CACHE_CONTROL], "no-store");
}

#[tokio::test]
async fn a_wrong_password_is_a_normal_answer_and_five_of_them_end_the_sign_in() {
    let world = world().await;
    let mut browser = Browser::default();
    browser.start(&world).await;
    browser.identifier(&world, "ana@example.com").await;

    for attempts_left in (1..=4).rev() {
        let rejected = browser.password(&world, "a wrong guess").await;
        assert_eq!(rejected.status, StatusCode::OK);
        assert_eq!(rejected.body["status"], "rejected");
        assert_eq!(rejected.body["step"], "password");
        assert_eq!(rejected.body["attempts_left"], attempts_left);
        assert!(rejected.set_cookies().is_empty());
    }
    let failed = browser.password(&world, "a wrong guess").await;
    assert_eq!(failed.body, serde_json::json!({ "status": "failed" }));
    assert!(
        failed.set_cookies()[0].contains("Max-Age=0"),
        "the sign-in cookie is removed"
    );
    assert!(!browser.cookies.contains_key("__Secure-hodor_session"));

    // The cookie is gone, so the browser has no sign-in any more.
    let after = browser.password(&world, PASSWORD).await;
    assert_eq!(after.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_request_without_the_right_csrf_token_changes_nothing() {
    let world = world().await;
    let mut browser = Browser::default();
    browser.start(&world).await;
    let token = browser.csrf_token.clone().expect("token");

    for forged in [
        None,
        Some("0".repeat(64)),
        Some(token.to_uppercase()),
        Some(String::new()),
    ] {
        let mut attacker = browser.clone();
        attacker.csrf_token = forged.clone();
        let refused = attacker.identifier(&world, "ana@example.com").await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{forged:?}");
        assert_eq!(refused.code(), "request.csrf_token_invalid");
        let cancel = attacker
            .send(&world, Method::DELETE, "/t/acme/interaction/sign-in", None)
            .await;
        assert_eq!(cancel.status, StatusCode::FORBIDDEN, "{forged:?}");
    }

    // The sign-in is still waiting for its first step.
    let state = browser
        .send(&world, Method::GET, "/t/acme/interaction/sign-in", None)
        .await;
    assert_eq!(state.body["step"], "identifier");
}

#[tokio::test]
async fn a_request_that_names_another_origin_is_refused() {
    let world = world().await;
    let mut browser = Browser::default();
    browser.start(&world).await;

    for origin in [
        "https://evil.example",
        "https://auth.example.evil.example",
        "null",
    ] {
        let mut forged = browser.clone();
        forged.origin = Some(origin);
        let refused = forged.identifier(&world, "ana@example.com").await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{origin}");
        assert_eq!(refused.code(), "request.cross_origin");
        let start = forged.start(&world).await;
        assert_eq!(
            start.status,
            StatusCode::FORBIDDEN,
            "starting is refused too: {origin}"
        );
    }

    // The server's own origin is accepted, and reading is never refused.
    browser.origin = Some("https://auth.example");
    assert_eq!(
        browser.identifier(&world, "ana@example.com").await.status,
        StatusCode::OK
    );
    browser.origin = Some("https://evil.example");
    let read = browser
        .send(&world, Method::GET, "/t/acme/interaction/sign-in", None)
        .await;
    assert_eq!(read.status, StatusCode::OK);
}

#[tokio::test]
async fn a_sign_in_cannot_be_continued_from_another_browser() {
    let world = world().await;
    let mut victim = Browser::default();
    victim.start(&world).await;
    let cookie = victim.cookies["__Secure-hodor_signin"].clone();
    let (transaction_id, secret) = cookie.split_once('.').expect("identifier and secret");

    let mut answers = Vec::new();
    for value in [
        None,
        Some(format!("{transaction_id}.{}", "0".repeat(64))),
        Some(transaction_id.to_owned()),
        Some(format!("not-an-identifier.{secret}")),
        Some("garbage".to_owned()),
    ] {
        let mut other = Browser::default();
        if let Some(value) = &value {
            other
                .cookies
                .insert("__Secure-hodor_signin".to_owned(), value.clone());
        }
        // Even with the victim's CSRF token.
        other.csrf_token = victim.csrf_token.clone();
        let read = other
            .send(&world, Method::GET, "/t/acme/interaction/sign-in", None)
            .await;
        assert_eq!(read.status, StatusCode::NOT_FOUND, "{value:?}");
        assert_eq!(read.code(), "authentication.transaction_not_found");
        let mut body = read.body.clone();
        body.as_object_mut().expect("object").remove("request_id");
        answers.push(body.to_string());
    }
    assert!(
        answers.windows(2).all(|pair| pair[0] == pair[1]),
        "one answer for all: {answers:?}"
    );
}

#[tokio::test]
async fn the_wrong_step_is_refused_and_a_reload_finds_the_same_place() {
    let world = world().await;
    let mut browser = Browser::default();
    browser.start(&world).await;

    let out_of_order = browser.password(&world, PASSWORD).await;
    assert_eq!(out_of_order.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(out_of_order.code(), "authentication.unexpected_step");

    browser.identifier(&world, "ana@example.com").await;
    let token = browser.csrf_token.clone();
    // The page is reloaded: it lost its token, and asks again.
    browser.csrf_token = None;
    let reloaded = browser
        .send(&world, Method::GET, "/t/acme/interaction/sign-in", None)
        .await;
    assert_eq!(reloaded.body["status"], "pending");
    assert_eq!(reloaded.body["step"], "password");
    assert_eq!(
        browser.csrf_token, token,
        "the token is the same for the whole sign-in"
    );
    assert_eq!(
        browser.password(&world, PASSWORD).await.body["status"],
        "completed"
    );
}

#[tokio::test]
async fn abandoning_a_sign_in_removes_it() {
    let world = world().await;
    let mut browser = Browser::default();
    browser.start(&world).await;

    let cancelled = browser
        .send(&world, Method::DELETE, "/t/acme/interaction/sign-in", None)
        .await;
    assert_eq!(cancelled.status, StatusCode::NO_CONTENT);
    assert!(cancelled.set_cookies()[0].contains("Max-Age=0"));
    assert!(browser.cookies.is_empty());

    let gone = browser
        .send(&world, Method::GET, "/t/acme/interaction/sign-in", None)
        .await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn too_many_attempts_are_answered_with_how_long_to_wait() {
    let world = world().await;
    // Five wrong passwords, each in its own sign-in so that the limit that
    // is reached is the identifier's, not the transaction's.
    for _ in 0..5 {
        let mut browser = Browser::default();
        browser.start(&world).await;
        browser.identifier(&world, "ana@example.com").await;
        assert_eq!(
            browser.password(&world, "a wrong guess").await.body["status"],
            "rejected"
        );
    }

    let mut browser = Browser::default();
    browser.start(&world).await;
    browser.identifier(&world, "ana@example.com").await;
    let limited = browser.password(&world, PASSWORD).await;

    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.code(), "authentication.too_many_attempts");
    assert_eq!(limited.headers[header::RETRY_AFTER], "60");
    assert!(limited.set_cookies().is_empty(), "no session");
}

#[tokio::test]
async fn without_a_valid_session_there_is_one_answer() {
    let world = world().await;
    let mut signed_in = Browser::default();
    signed_in.start(&world).await;
    signed_in.identifier(&world, "ana@example.com").await;
    signed_in.password(&world, PASSWORD).await;
    let token = signed_in.cookies["__Secure-hodor_session"].clone();

    let mut answers = Vec::new();
    let mut ask = async |cookie: Option<String>, tenant: &str| {
        let mut browser = Browser::default();
        if let Some(cookie) = cookie {
            browser
                .cookies
                .insert("__Secure-hodor_session".to_owned(), cookie);
        }
        let reply = browser.session(&world, tenant).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.code(), "session.not_authenticated");
        let mut body = reply.body;
        body.as_object_mut().expect("object").remove("request_id");
        answers.push(body.to_string());
    };
    ask(None, "acme").await;
    ask(Some("garbage".to_owned()), "acme").await;
    ask(Some("f".repeat(64)), "acme").await;
    // A session of one tenant is nobody's session in another.
    ask(Some(token.clone()), "globex").await;

    // After the idle timeout the real token is not accepted either.
    world.clock.advance(Duration::minutes(30));
    ask(Some(token), "acme").await;
    assert!(
        answers.windows(2).all(|pair| pair[0] == pair[1]),
        "{answers:?}"
    );
}

#[tokio::test]
async fn a_body_of_the_wrong_shape_is_refused_before_anything_happens() {
    let world = world().await;
    let mut browser = Browser::default();
    browser.start(&world).await;

    let wrong_field = browser
        .send(
            &world,
            Method::POST,
            "/t/acme/interaction/sign-in/steps/identifier",
            Some(serde_json::json!({ "username": "ana" })),
        )
        .await;
    assert_eq!(wrong_field.status, StatusCode::UNPROCESSABLE_ENTITY);
    let not_json = browser
        .send(
            &world,
            Method::POST,
            "/t/acme/interaction/sign-in/steps/identifier",
            None,
        )
        .await;
    assert_eq!(not_json.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let state = browser
        .send(&world, Method::GET, "/t/acme/interaction/sign-in", None)
        .await;
    assert_eq!(state.body["step"], "identifier", "nothing advanced");
}

impl Browser {
    async fn post(&mut self, world: &World, path: &str, body: serde_json::Value) -> Reply {
        self.send(
            world,
            Method::POST,
            &format!("/t/acme/interaction/{path}"),
            Some(body),
        )
        .await
    }

    /// Signs in from the first step and says whether it completed.
    async fn signs_in(&mut self, world: &World, email: &str, password: &str) -> bool {
        self.start(world).await;
        self.identifier(world, email).await;
        self.password(world, password).await.body["status"] == "completed"
    }
}

#[tokio::test]
async fn a_person_registers_through_their_mailbox_and_then_signs_in() {
    let world = world().await;
    let mut browser = Browser::default();

    let asked = browser
        .post(
            &world,
            "registration",
            serde_json::json!({ "email": "bia@example.com", "locale": "pt-BR" }),
        )
        .await;
    assert_eq!(asked.status, StatusCode::ACCEPTED);
    assert_eq!(asked.body, serde_json::json!({ "status": "accepted" }));
    assert!(asked.set_cookies().is_empty());

    let finished = browser
        .post(
            &world,
            "registration/complete",
            serde_json::json!({
                "token": world.newest_token(),
                "password": "a long passphrase for bia",
                "display_name": "Bia"
            }),
        )
        .await;
    assert_eq!(finished.status, StatusCode::NO_CONTENT);
    // Finishing does not sign the person in.
    assert!(finished.set_cookies().is_empty());

    assert!(
        browser
            .signs_in(&world, "bia@example.com", "a long passphrase for bia")
            .await
    );
}

#[tokio::test]
async fn asking_answers_the_same_whoever_the_address_belongs_to() {
    let world = world().await;
    let mut answers = Vec::new();
    for path in ["registration", "recovery"] {
        for email in ["ana@example.com", "nobody@example.com", "not an address"] {
            let reply = Browser::default()
                .post(&world, path, serde_json::json!({ "email": email }))
                .await;
            answers.push((reply.status, reply.body.to_string()));
        }
    }

    assert!(
        answers
            .iter()
            .all(|answer| *answer == (StatusCode::ACCEPTED, r#"{"status":"accepted"}"#.to_owned())),
        "{answers:?}"
    );
    // What differs is what reached the mailboxes: a note to the address
    // that has an account, a link to the one that has none, then a
    // recovery link to the one that has an account.
    assert_eq!(
        world.templates(),
        [
            "already_registered",
            "email_verification",
            "password_recovery"
        ]
    );
}

#[tokio::test]
async fn a_person_recovers_a_password_and_every_session_ends() {
    let world = world().await;
    let mut signed_in = Browser::default();
    assert!(
        signed_in
            .signs_in(&world, "ana@example.com", PASSWORD)
            .await
    );
    assert_eq!(
        signed_in.session(&world, "acme").await.status,
        StatusCode::OK
    );

    let mut browser = Browser::default();
    let asked = browser
        .post(
            &world,
            "recovery",
            serde_json::json!({ "email": "ana@example.com" }),
        )
        .await;
    assert_eq!(asked.status, StatusCode::ACCEPTED);
    let token = world.newest_token();

    // A password that is not acceptable is refused and the link stays good.
    let refused = browser
        .post(
            &world,
            "recovery/complete",
            serde_json::json!({ "token": token, "password": "short" }),
        )
        .await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);

    let reset = browser
        .post(
            &world,
            "recovery/complete",
            serde_json::json!({ "token": token, "password": "a different long passphrase" }),
        )
        .await;
    assert_eq!(reset.status, StatusCode::NO_CONTENT);
    assert!(reset.set_cookies().is_empty());

    // The browser that was signed in no longer is.
    assert_eq!(
        signed_in.session(&world, "acme").await.status,
        StatusCode::UNAUTHORIZED
    );
    assert!(
        !Browser::default()
            .signs_in(&world, "ana@example.com", PASSWORD)
            .await
    );
    assert!(
        Browser::default()
            .signs_in(&world, "ana@example.com", "a different long passphrase")
            .await
    );
    assert_eq!(world.templates().last(), Some(&"password_changed"));

    // The link worked once.
    let again = browser
        .post(
            &world,
            "recovery/complete",
            serde_json::json!({ "token": token, "password": "yet another long passphrase" }),
        )
        .await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);
    assert_eq!(again.code(), "authentication.verification_token_invalid");
}

#[tokio::test]
async fn a_token_that_is_not_good_is_refused_in_one_way() {
    let world = world().await;
    for path in ["registration/complete", "recovery/complete"] {
        for token in ["", "abc", &"0".repeat(64)] {
            let reply = Browser::default()
                .post(
                    &world,
                    path,
                    serde_json::json!({ "token": token, "password": "a long enough passphrase" }),
                )
                .await;
            assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path} {token}");
            assert_eq!(reply.code(), "authentication.verification_token_invalid");
        }
    }
}

#[tokio::test]
async fn a_tenant_that_does_not_accept_registrations_says_so() {
    let world = world().await;
    let reply = Browser::default()
        .send(
            &world,
            Method::POST,
            "/t/globex/interaction/registration",
            Some(serde_json::json!({ "email": "bia@example.com" })),
        )
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.code(), "authentication.registration_closed");
}

#[tokio::test]
async fn asking_too_often_is_answered_with_how_long_to_wait() {
    let world = world().await;
    let mut last = None;
    for _ in 0..6 {
        last = Some(
            Browser::default()
                .post(
                    &world,
                    "recovery",
                    serde_json::json!({ "email": "ana@example.com" }),
                )
                .await,
        );
    }
    let last = last.expect("a reply");
    assert_eq!(last.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(last.code(), "authentication.too_many_attempts");
    assert!(last.headers.contains_key(header::RETRY_AFTER));
    assert_eq!(world.templates().len(), 5);
}

#[tokio::test]
async fn account_requests_from_another_site_or_of_the_wrong_shape_are_refused() {
    let world = world().await;
    let mut elsewhere = Browser {
        origin: Some("https://evil.example"),
        ..Browser::default()
    };
    let forged = elsewhere
        .post(
            &world,
            "recovery",
            serde_json::json!({ "email": "ana@example.com" }),
        )
        .await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);
    assert_eq!(forged.code(), "request.cross_origin");

    let malformed = Browser::default()
        .post(&world, "registration", serde_json::json!({ "mail": "x" }))
        .await;
    assert!(malformed.status.is_client_error());
    assert!(world.templates().is_empty());
}

impl Browser {
    /// Asks who is signed in, which also hands the browser the CSRF token
    /// of its session.
    async fn whoami(&mut self, world: &World) -> Reply {
        self.session(world, "acme").await
    }

    async fn delete(&mut self, world: &World, path: &str) -> Reply {
        self.send(
            world,
            Method::DELETE,
            &format!("/t/acme/interaction/{path}"),
            None,
        )
        .await
    }

    async fn listed(&mut self, world: &World) -> Vec<serde_json::Value> {
        let reply = self
            .send(world, Method::GET, "/t/acme/interaction/sessions", None)
            .await;
        assert_eq!(reply.status, StatusCode::OK);
        reply.body["sessions"].as_array().expect("sessions").clone()
    }
}

/// A browser signed in as Ana, holding the CSRF token of its session.
async fn signed_in_browser(world: &World) -> Browser {
    let mut browser = Browser::default();
    assert!(browser.signs_in(world, "ana@example.com", PASSWORD).await);
    assert_eq!(browser.whoami(world).await.status, StatusCode::OK);
    browser
}

#[tokio::test]
async fn signing_out_ends_the_session_on_the_server_and_removes_the_cookie() {
    let world = world().await;
    let mut browser = signed_in_browser(&world).await;
    // A copy of the cookie made before signing out, as a thief would hold.
    let mut copy = browser.clone();

    let reply = browser.delete(&world, "session").await;

    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    let cleared = reply.set_cookies();
    assert_eq!(cleared.len(), 1);
    assert!(
        cleared[0].starts_with("__Secure-hodor_session=;"),
        "{cleared:?}"
    );
    assert!(cleared[0].contains("Max-Age=0") && cleared[0].contains("Path=/t/acme"));
    assert!(!browser.cookies.contains_key("__Secure-hodor_session"));
    // The session is over, not merely forgotten: the copy stops working.
    let after = copy.whoami(&world).await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
    assert_eq!(after.code(), "session.not_authenticated");
}

#[tokio::test]
async fn signing_out_ends_one_session_and_leaves_the_others() {
    let world = world().await;
    let mut laptop = signed_in_browser(&world).await;
    let mut phone = signed_in_browser(&world).await;

    assert_eq!(
        laptop.delete(&world, "session").await.status,
        StatusCode::NO_CONTENT
    );

    assert_eq!(phone.whoami(&world).await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_person_sees_their_own_sessions_and_which_one_is_this() {
    let world = world().await;
    let mut laptop = signed_in_browser(&world).await;
    world.clock.advance(Duration::minutes(5));
    let mut phone = signed_in_browser(&world).await;

    let listed = phone.listed(&world).await;

    assert_eq!(listed.len(), 2);
    // Newest first, and only the asking browser's is marked current.
    assert_eq!(listed[0]["current"], true);
    assert_eq!(listed[1]["current"], false);
    assert_eq!(
        listed[1]["session_id"],
        laptop.whoami(&world).await.body["session_id"]
    );
    for session in &listed {
        for field in ["started_at", "last_activity_at", "expires_at"] {
            assert!(session[field].is_string(), "{field}");
        }
    }
    // No token, of this session or of the other, is in the list.
    let shown = serde_json::Value::Array(listed).to_string();
    for browser in [&laptop, &phone] {
        assert!(!shown.contains(&browser.cookies["__Secure-hodor_session"]));
    }
}

#[tokio::test]
async fn a_person_ends_another_of_their_sessions_and_it_stops_working() {
    let world = world().await;
    let mut laptop = signed_in_browser(&world).await;
    let mut phone = signed_in_browser(&world).await;
    let phone_session = phone.whoami(&world).await.body["session_id"]
        .as_str()
        .expect("identifier")
        .to_owned();

    let reply = laptop
        .delete(&world, &format!("sessions/{phone_session}"))
        .await;

    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert!(reply.set_cookies().is_empty(), "the laptop stays signed in");
    assert_eq!(phone.whoami(&world).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(laptop.whoami(&world).await.status, StatusCode::OK);
    assert_eq!(laptop.listed(&world).await.len(), 1);

    // Ending it again, ending one that never existed and ending something
    // that is not an identifier are answered alike.
    for target in [
        phone_session.as_str(),
        "0193f1c9-0000-7000-8000-000000000000",
        "not-an-identifier",
    ] {
        let reply = laptop.delete(&world, &format!("sessions/{target}")).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{target}");
        assert_eq!(reply.code(), "session.not_found");
    }
}

#[tokio::test]
async fn ending_the_current_session_by_its_identifier_is_signing_out() {
    let world = world().await;
    let mut browser = signed_in_browser(&world).await;
    let current = browser.whoami(&world).await.body["session_id"]
        .as_str()
        .expect("identifier")
        .to_owned();
    let mut copy = browser.clone();

    let reply = browser.delete(&world, &format!("sessions/{current}")).await;

    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert_eq!(reply.set_cookies().len(), 1);
    assert_eq!(copy.whoami(&world).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_person_ends_every_session_but_this_one() {
    let world = world().await;
    let mut phone = signed_in_browser(&world).await;
    let mut tablet = signed_in_browser(&world).await;
    let mut laptop = signed_in_browser(&world).await;

    let reply = laptop.delete(&world, "sessions").await;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body, serde_json::json!({ "ended": 2 }));
    assert_eq!(phone.whoami(&world).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(tablet.whoami(&world).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(laptop.whoami(&world).await.status, StatusCode::OK);
}

#[tokio::test]
async fn one_person_cannot_end_or_see_the_sessions_of_another() {
    let world = world().await;
    let mut ana = signed_in_browser(&world).await;
    let ana_session = ana.whoami(&world).await.body["session_id"]
        .as_str()
        .expect("identifier")
        .to_owned();
    // Another person of the same tenant, registered through their mailbox.
    let mut bia = Browser::default();
    bia.post(
        &world,
        "registration",
        serde_json::json!({ "email": "bia@example.com" }),
    )
    .await;
    bia.post(
        &world,
        "registration/complete",
        serde_json::json!({ "token": world.newest_token(), "password": "a long passphrase for bia" }),
    )
    .await;
    let mut bia = Browser::default();
    assert!(
        bia.signs_in(&world, "bia@example.com", "a long passphrase for bia")
            .await
    );
    bia.whoami(&world).await;

    let listed = bia.listed(&world).await;
    assert_eq!(listed.len(), 1);
    assert_ne!(listed[0]["session_id"], ana_session.as_str());

    let reply = bia.delete(&world, &format!("sessions/{ana_session}")).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(reply.code(), "session.not_found");
    bia.delete(&world, "sessions").await;
    assert_eq!(ana.whoami(&world).await.status, StatusCode::OK);
}

#[tokio::test]
async fn changing_requests_need_the_session_csrf_token_and_the_same_origin() {
    let world = world().await;
    let mut browser = signed_in_browser(&world).await;
    let second = signed_in_browser(&world).await;

    for path in [
        "session",
        "sessions",
        "sessions/0193f1c9-0000-7000-8000-000000000000",
    ] {
        // Without the token, and with the token of another session.
        for token in [None, second.csrf_token.clone()] {
            let mut forged = browser.clone();
            forged.csrf_token = token;
            let reply = forged.delete(&world, path).await;
            assert_eq!(reply.status, StatusCode::FORBIDDEN, "{path}");
            assert_eq!(reply.code(), "request.csrf_token_invalid");
        }
        let mut elsewhere = browser.clone();
        elsewhere.origin = Some("https://evil.example");
        let reply = elsewhere.delete(&world, path).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(reply.code(), "request.cross_origin");
    }

    // Nothing was ended.
    assert_eq!(browser.listed(&world).await.len(), 2);
}

#[tokio::test]
async fn the_routes_of_a_signed_in_person_refuse_everyone_else_in_one_way() {
    let world = world().await;
    let mut nobody = Browser::default();
    for (method, path) in [
        (Method::GET, "session"),
        (Method::DELETE, "session"),
        (Method::GET, "sessions"),
        (Method::DELETE, "sessions"),
        (
            Method::DELETE,
            "sessions/0193f1c9-0000-7000-8000-000000000000",
        ),
    ] {
        let reply = nobody
            .send(
                &world,
                method.clone(),
                &format!("/t/acme/interaction/{path}"),
                None,
            )
            .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{method} {path}");
        assert_eq!(reply.code(), "session.not_authenticated");
    }
}
