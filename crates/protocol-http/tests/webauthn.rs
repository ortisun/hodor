//! WebAuthn over the interaction interface: a signed-in person registers a
//! key, and then signs in with a password and the key. The contexts run on
//! their in-memory ports; the key is a real one, in software.

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use hodor_adapters_crypto::testing::webauthn::SoftwareAuthenticator;
use hodor_authentication::api::{
    AccountService, AttemptGuard, AuthFlow, AuthenticationService, FactorService, FlowEngine,
    IdentifierAuthenticator, PasswordAuthenticator, RecoveryCodeAuthenticator, Requirement,
    WebAuthnAuthenticator,
};
use hodor_authentication::testing::{
    InMemoryAttempts, InMemoryTransactions, InMemoryVerificationTokens,
};
use hodor_credential::api::{CredentialService, NewPassword, PasswordRules, RecoveryCodeService};
use hodor_credential::testing::{FakeHasher, InMemoryPasswords, InMemoryRecoveryCodes};
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_identity::testing::InMemoryUsers;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::{CountingRandom, FakeDigest};
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, DomainError, Secret, TenantContext, Timestamp};
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
    /// Recovery codes; nobody has any unless a test makes them.
    recovery_codes: RecoveryCodeService,
    acme: TenantContext,
    ana: hodor_kernel::UserId,
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
    let webauthn = webauthn_service(units_of_work.clone(), clock.clone());
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
        )))
        .with(Arc::new(WebAuthnAuthenticator::new(webauthn.clone())));
    let recovery_codes = RecoveryCodeService::new(
        units(),
        Arc::new(InMemoryRecoveryCodes::default()),
        digest.clone(),
        Arc::new(CountingRandom::default()),
        clock.clone(),
    );
    let engine = engine.with(Arc::new(RecoveryCodeAuthenticator::new(
        recovery_codes.clone(),
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
        AuthFlow::built_in()
            .with_step(
                WebAuthnAuthenticator::KIND,
                WebAuthnAuthenticator::KIND,
                Requirement::Optional,
            )
            .with_substitute(WebAuthnAuthenticator::KIND, RecoveryCodeAuthenticator::KIND),
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
        factors: FactorService::new(identity.clone(), webauthn),
        external: None,
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
        recovery_codes,
        acme,
        ana,
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

const ORIGIN: &str = "https://auth.example";
const STEPS: &str = "/t/acme/interaction/sign-in/steps";

impl Browser {
    async fn signed_in_with_password(world: &World) -> Self {
        let mut browser = Self::default();
        browser.start(world).await;
        browser.identifier(world, "ana@example.com").await;
        let done = browser.password(world, PASSWORD).await;
        assert_eq!(done.body["status"], "completed", "{:?}", done.body);
        // The CSRF token of the session.
        browser.session(world, "acme").await;
        browser
    }

    async fn register(&mut self, world: &World, key: &SoftwareAuthenticator) -> Reply {
        let begun = self
            .send(
                world,
                Method::POST,
                "/t/acme/interaction/webauthn/registrations",
                None,
            )
            .await;
        assert_eq!(begun.status, StatusCode::CREATED, "{:?}", begun.body);
        let id = begun.body["registration_id"]
            .as_str()
            .expect("an identifier");
        let body = key.register(&begun.body["public_key"]);
        self.send(
            world,
            Method::POST,
            &format!("/t/acme/interaction/webauthn/registrations/{id}"),
            Some(body),
        )
        .await
    }

    async fn options(&mut self, world: &World) -> Reply {
        self.send(
            world,
            Method::POST,
            &format!("{STEPS}/webauthn/options"),
            None,
        )
        .await
    }

    async fn answer(&mut self, world: &World, body: serde_json::Value) -> Reply {
        self.send(
            world,
            Method::POST,
            &format!("{STEPS}/webauthn"),
            Some(body),
        )
        .await
    }

    /// A new sign-in in the same browser, up to the WebAuthn step.
    async fn up_to_the_key(&mut self, world: &World) {
        self.start(world).await;
        self.identifier(world, "ana@example.com").await;
        let next = self.password(world, PASSWORD).await;
        assert_eq!(
            (next.body["status"].as_str(), next.body["step"].as_str()),
            (Some("pending"), Some("webauthn")),
            "{:?}",
            next.body
        );
    }
}

async fn registered_key(world: &World) -> (Browser, SoftwareAuthenticator) {
    let mut browser = Browser::signed_in_with_password(world).await;
    let key = SoftwareAuthenticator::new(ORIGIN);
    let registered = browser.register(world, &key).await;
    assert_eq!(
        registered.status,
        StatusCode::CREATED,
        "{:?}",
        registered.body
    );
    assert_eq!(registered.body["name"], "Software key");
    (browser, key)
}

#[tokio::test]
async fn a_person_with_a_key_signs_in_with_the_password_and_the_key() {
    let world = world().await;
    let (mut browser, key) = registered_key(&world).await;

    browser.up_to_the_key(&world).await;
    let options = browser.options(&world).await;
    assert_eq!(options.status, StatusCode::OK, "{:?}", options.body);
    let public_key = &options.body["public_key"];
    assert_eq!(public_key["rpId"], "auth.example");
    assert_eq!(public_key["allowCredentials"][0]["id"], key.credential_id());
    assert_eq!(public_key["userVerification"], "discouraged");

    let done = browser.answer(&world, key.answer(public_key)).await;
    assert_eq!(done.body["status"], "completed", "{:?}", done.body);
    let session = browser.session(&world, "acme").await;
    assert_eq!(session.body["assurance"], "multi_factor");
    assert_eq!(
        session.body["methods"],
        serde_json::json!(["password", "webauthn"])
    );
}

#[tokio::test]
async fn a_person_without_a_key_is_asked_for_nothing_more() {
    let world = world().await;
    let browser = Browser::signed_in_with_password(&world).await;
    drop(browser);
}

#[tokio::test]
async fn an_answer_by_another_key_or_to_a_used_challenge_is_a_rejection() {
    let world = world().await;
    let (mut browser, key) = registered_key(&world).await;
    browser.up_to_the_key(&world).await;

    let options = browser.options(&world).await.body["public_key"].clone();
    let stranger = SoftwareAuthenticator::new(ORIGIN);
    let refused = browser.answer(&world, stranger.answer(&options)).await;
    assert_eq!(
        (
            refused.body["status"].as_str(),
            refused.body["step"].as_str()
        ),
        (Some("rejected"), Some("webauthn"))
    );
    // The challenge was used up by the rejected answer.
    let refused = browser.answer(&world, key.answer(&options)).await;
    assert_eq!(refused.body["status"], "rejected");

    // The same key on a site that imitates Hodor's.
    let options = browser.options(&world).await.body["public_key"].clone();
    let phished = key.at_origin("https://auth.example.evil.example");
    let refused = browser.answer(&world, phished.answer(&options)).await;
    assert_eq!(refused.body["status"], "rejected");

    // Something that is not base64url is a rejection like any other.
    browser.options(&world).await;
    let refused = browser
        .answer(
            &world,
            serde_json::json!({
                "credential_id": "%%%", "client_data": "e30", "authenticator_data": "AA",
                "signature": "AA",
            }),
        )
        .await;
    assert_eq!(refused.body["status"], "rejected");

    let options = browser.options(&world).await.body["public_key"].clone();
    let done = browser.answer(&world, key.answer(&options)).await;
    assert_eq!(done.body["status"], "completed", "{:?}", done.body);
}

#[tokio::test]
async fn a_challenge_is_given_only_for_the_webauthn_step_of_ones_own_sign_in() {
    let world = world().await;
    let (mut browser, _key) = registered_key(&world).await;

    browser.start(&world).await;
    let early = browser.options(&world).await;
    assert_eq!(early.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(early.code(), "authentication.unexpected_step");

    // Without the CSRF token of the sign-in.
    browser.identifier(&world, "ana@example.com").await;
    browser.password(&world, PASSWORD).await;
    let mut forged = browser.clone();
    forged.csrf_token = Some("0".repeat(64));
    let refused = forged.options(&world).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);

    // Another browser has no sign-in to ask about.
    let mut stranger = Browser::default();
    let refused = stranger.options(&world).await;
    assert_eq!(refused.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn registering_needs_a_session_and_its_csrf_token() {
    let world = world().await;
    let mut nobody = Browser::default();
    let refused = nobody
        .send(
            &world,
            Method::POST,
            "/t/acme/interaction/webauthn/registrations",
            None,
        )
        .await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);

    let mut browser = Browser::signed_in_with_password(&world).await;
    let mut forged = browser.clone();
    forged.csrf_token = None;
    let refused = forged
        .send(
            &world,
            Method::POST,
            "/t/acme/interaction/webauthn/registrations",
            None,
        )
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);

    // A registration that is not one, and an answer from another site.
    let refused = browser
        .send(
            &world,
            Method::POST,
            "/t/acme/interaction/webauthn/registrations/not-an-identifier",
            Some(serde_json::json!({ "client_data": "e30", "attestation_object": "oA" })),
        )
        .await;
    assert_eq!(refused.code(), "credential.webauthn_registration_not_found");
    let elsewhere = SoftwareAuthenticator::new("https://evil.example");
    let refused = browser.register(&world, &elsewhere).await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(refused.code(), "credential.webauthn_registration_refused");
}

#[tokio::test]
async fn a_key_registered_in_one_tenant_is_not_offered_in_another() {
    let world = world().await;
    let (_, key) = registered_key(&world).await;
    // Globex has no Ana: a sign-in there never reaches a key step, and the
    // key's answer is not something its sign-in takes.
    let mut browser = Browser::default();
    browser
        .send(&world, Method::POST, "/t/globex/interaction/sign-in", None)
        .await;
    let refused = browser
        .send(
            &world,
            Method::POST,
            "/t/globex/interaction/sign-in/steps/webauthn",
            Some(key.answer(&serde_json::json!({ "challenge": "AA", "rpId": "auth.example" }))),
        )
        .await;
    assert_eq!(refused.code(), "authentication.unexpected_step");
}

/// The WebAuthn use cases on the in-memory store, with real cryptography.
fn webauthn_service(
    units_of_work: InMemoryUnitOfWorkFactory,
    clock: Arc<FixedClock>,
) -> hodor_credential::api::WebAuthnService {
    hodor_credential::api::WebAuthnService::new(
        Arc::new(units_of_work),
        Arc::new(hodor_credential::testing::InMemoryWebAuthn::default()),
        hodor_credential::api::RelyingParty::from_public_address("https://auth.example")
            .expect("valid"),
        Arc::new(hodor_adapters_crypto::Sha256Digest),
        Arc::new(hodor_adapters_crypto::AwsLcVerifier),
        Arc::new(hodor_adapters_crypto::OsRandom),
        clock,
    )
}

#[tokio::test]
async fn a_person_who_lost_their_key_gives_a_recovery_code_in_its_place() {
    let world = world().await;
    let (mut browser, _key) = registered_key(&world).await;
    let codes = world
        .recovery_codes
        .generate(&world.acme, world.ana, Caller::system())
        .await
        .expect("generate");
    let written_down = codes.codes().next().expect("a code").to_owned();

    browser.up_to_the_key(&world).await;
    let body = serde_json::json!({ "code": written_down });
    let done = browser
        .send(
            &world,
            Method::POST,
            "/t/acme/interaction/sign-in/steps/recovery_code",
            Some(body),
        )
        .await;
    assert_eq!(done.body["status"], "completed", "{:?}", done.body);
    let session = browser.session(&world, "acme").await;
    assert_eq!(session.body["assurance"], "multi_factor");
    assert_eq!(
        session.body["methods"],
        serde_json::json!(["password", "recovery_code"])
    );
}
