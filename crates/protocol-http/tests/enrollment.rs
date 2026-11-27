//! Enrolling a second factor during a sign-in, over the interaction
//! interface: a person whose tenant requires a second factor and who has
//! none sets up an authenticator application, a security key or a passkey
//! after the password, and the sign-in completes with it. The contexts run
//! on their in-memory ports; the keys are real ones, in software.

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use hodor_adapters_crypto::testing::webauthn::SoftwareAuthenticator;
use hodor_authentication::api::{
    AccountService, AttemptGuard, AuthFlow, AuthenticationService, Condition,
    EnrollmentAuthenticator, FactorService, FlowEngine, IdentifierAuthenticator,
    PasskeyAuthenticator, PasswordAuthenticator, RecoveryCodeAuthenticator, Requirement,
    TotpAuthenticator, WebAuthnAuthenticator,
};
use hodor_authentication::testing::{
    InMemoryAttempts, InMemoryTransactions, InMemoryVerificationTokens,
};
use hodor_credential::api::{
    CredentialService, NewPassword, PasswordRules, RecoveryCodeService, STEP_SECONDS, TotpService,
    totp_code_at,
};
use hodor_credential::testing::{
    FakeHasher, FakeHmacSha1, InMemoryPasswords, InMemoryRecoveryCodes, InMemoryTotps,
    base32_secret,
};
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_identity::testing::InMemoryUsers;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::{CountingRandom, FakeDigest};
use hodor_kernel::sealing::testing::FakeSecretBox;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, Clock as _, DomainError, Secret, TenantContext, Timestamp};
use hodor_notification::api::Notifier;
use hodor_notification::testing::InMemoryMessages;
use hodor_protocol_http::{
    InteractionState, Limits, ResolvedTenant, TenantResolver, TenantStatus, interaction_routes,
    public_router,
};
use hodor_session::api::SessionService;
use hodor_session::testing::{InMemorySessions, SequentialRandom};
use hodor_tenant::api::{CreateTenant, SecondFactorPolicy, TenantService};
use hodor_tenant::testing::InMemoryTenants;
use http_body_util::BodyExt as _;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use time::Duration;
use tower::ServiceExt as _;

const PASSWORD: &str = "correct horse battery staple";
const HOST: &str = "auth.example";
const ORIGIN: &str = "https://auth.example";
const STEPS: &str = "/t/acme/interaction/sign-in/steps";

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
}

async fn world() -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + Duration::seconds(STEP_SECONDS * 60_000_000),
    ));
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
    let webauthn = hodor_credential::api::WebAuthnService::new(
        units(),
        Arc::new(hodor_credential::testing::InMemoryWebAuthn::default()),
        hodor_credential::api::RelyingParty::from_public_address(ORIGIN).expect("valid"),
        Arc::new(hodor_adapters_crypto::Sha256Digest),
        Arc::new(hodor_adapters_crypto::AwsLcVerifier),
        Arc::new(hodor_adapters_crypto::OsRandom),
        clock.clone(),
    );
    let totp = TotpService::new(
        units(),
        Arc::new(InMemoryTotps::default()),
        Arc::new(FakeSecretBox),
        Arc::new(FakeHmacSha1),
        Arc::new(CountingRandom::default()),
        clock.clone(),
    );
    let recovery_codes = RecoveryCodeService::new(
        units(),
        Arc::new(InMemoryRecoveryCodes::default()),
        digest.clone(),
        Arc::new(CountingRandom::default()),
        clock.clone(),
    );
    let factors = FactorService::new(
        identity.clone(),
        tenants.clone(),
        webauthn.clone(),
        recovery_codes.clone(),
    )
    .with_totp(totp.clone());
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
        .with(Arc::new(WebAuthnAuthenticator::new(webauthn.clone())))
        .with(Arc::new(PasskeyAuthenticator::new(
            webauthn,
            identity.clone(),
            tenants.clone(),
            guard.clone(),
        )))
        .with(Arc::new(TotpAuthenticator::new(
            totp,
            tenants.clone(),
            guard.clone(),
        )))
        .with(Arc::new(RecoveryCodeAuthenticator::new(
            recovery_codes,
            tenants.clone(),
            guard.clone(),
        )))
        .with(Arc::new(EnrollmentAuthenticator::new(
            factors.clone(),
            identity.clone(),
        )));
    let accounts = AccountService::new(
        units(),
        Arc::new(InMemoryVerificationTokens::default()),
        identity.clone(),
        credentials.clone(),
        sessions.clone(),
        tenants.clone(),
        Notifier::new(Arc::new(InMemoryMessages::default()), clock.clone()),
        guard,
        digest.clone(),
        Arc::new(SequentialRandom::default()),
        clock.clone(),
        ORIGIN,
    );
    let authentication = AuthenticationService::new(
        units(),
        Arc::new(InMemoryTransactions::default()),
        engine,
        // As the server runs it.
        AuthFlow::built_in()
            .with_step(
                WebAuthnAuthenticator::KIND,
                WebAuthnAuthenticator::KIND,
                Requirement::Conditional(Condition::StrongerAssuranceNeeded),
            )
            .with_substitute(WebAuthnAuthenticator::KIND, RecoveryCodeAuthenticator::KIND)
            .with_step(
                TotpAuthenticator::KIND,
                TotpAuthenticator::KIND,
                Requirement::Conditional(Condition::MultiFactorNotReached),
            )
            .with_substitute(TotpAuthenticator::KIND, RecoveryCodeAuthenticator::KIND)
            .with_step(
                EnrollmentAuthenticator::KIND,
                EnrollmentAuthenticator::KIND,
                Requirement::Conditional(Condition::AssuranceNotReached),
            )
            .with_alternative(PasskeyAuthenticator::KIND, PasskeyAuthenticator::KIND),
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
    // Acme requires a second factor; Ana has none.
    let mut settings = tenants
        .get(&acme)
        .await
        .expect("tenant")
        .snapshot()
        .settings
        .clone();
    settings.authentication.second_factor = SecondFactorPolicy::Required;
    tenants
        .change_settings(&acme, settings, Caller::system())
        .await
        .expect("settings");

    let ana = identity
        .create(
            &acme,
            CreateUser {
                kind: UserKind::Human,
                identifiers: vec![(IdentifierKind::Email, "ana@example.com".to_owned())],
                profile: Profile {
                    display_name: Some("Ana Lima".to_owned()),
                    ..Profile::default()
                },
                confirmed: true,
            },
            Caller::system(),
        )
        .await
        .expect("user")
        .id();
    let password = Secret::from(PASSWORD.to_owned());
    credentials
        .set_password(
            &acme,
            ana,
            NewPassword {
                password: &password,
                rules: PasswordRules {
                    min_length: 12,
                    max_length: 128,
                    history_depth: 5,
                },
                own_names: &[],
            },
            false,
            Caller::system(),
        )
        .await
        .expect("password");

    let state = InteractionState {
        authentication,
        accounts,
        sessions,
        factors,
        external: None,
        digest,
        clock: clock.clone(),
        front_channel: None,
    };
    let router = public_router(
        Arc::new(Tenants { acme, globex }),
        Router::new().nest("/interaction", interaction_routes(state)),
        Router::new(),
        Limits::default(),
    );
    World { router, clock }
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
    /// The address the connection comes from, when a test needs one.
    address: Option<SocketAddr>,
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
        let mut request = match body {
            Some(body) => request
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        }
        .expect("request");
        if let Some(address) = self.address {
            request.extensions_mut().insert(ConnectInfo(address));
        }

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

impl Browser {
    /// A new sign-in in this browser, through the password, which names
    /// the step that comes next.
    async fn after_password(&mut self, world: &World) -> Reply {
        self.start(world).await;
        self.identifier(world, "ana@example.com").await;
        self.password(world, PASSWORD).await
    }

    async fn begin(&mut self, world: &World, kind: &str) -> Reply {
        self.send(
            world,
            Method::POST,
            &format!("{STEPS}/enrollment/options"),
            Some(serde_json::json!({ "kind": kind })),
        )
        .await
    }

    async fn finish(&mut self, world: &World, body: serde_json::Value) -> Reply {
        self.send(
            world,
            Method::POST,
            &format!("{STEPS}/enrollment"),
            Some(body),
        )
        .await
    }
}

fn phone(world: &World, secret: &str) -> String {
    totp_code_at(&FakeHmacSha1, &base32_secret(secret), world.clock.now())
}

fn status_and_step(reply: &Reply) -> (Option<&str>, Option<&str>) {
    (reply.body["status"].as_str(), reply.body["step"].as_str())
}

#[tokio::test]
async fn the_kinds_to_set_up_need_no_sign_in() {
    let world = world().await;
    let mut browser = Browser::default();
    let kinds = browser
        .send(
            &world,
            Method::GET,
            &format!("{STEPS}/enrollment/kinds"),
            None,
        )
        .await;
    assert_eq!(kinds.status, StatusCode::OK);
    assert_eq!(
        kinds.body,
        serde_json::json!({ "kinds": ["authenticator_application", "security_key", "passkey"] })
    );
}

#[tokio::test]
async fn a_person_sets_up_an_authenticator_application_and_is_signed_in_at_multi_factor() {
    let world = world().await;
    let mut browser = Browser::default();
    let next = browser.after_password(&world).await;
    assert_eq!(
        status_and_step(&next),
        (Some("pending"), Some("enrollment")),
        "{:?}",
        next.body
    );

    let begun = browser.begin(&world, "authenticator_application").await;
    assert_eq!(begun.status, StatusCode::OK, "{:?}", begun.body);
    assert_eq!(begun.body["kind"], "authenticator_application");
    assert!(
        begun.body["uri"]
            .as_str()
            .expect("uri")
            .starts_with("otpauth://totp/ACME:ana%40example.com?secret="),
        "{:?}",
        begun.body
    );
    let secret = begun.body["secret"].as_str().expect("secret").to_owned();

    // A mistyped code is a rejection, and the same secret still works.
    let wrong = browser
        .finish(&world, serde_json::json!({ "code": "000000" }))
        .await;
    assert_eq!(
        status_and_step(&wrong),
        (Some("rejected"), Some("enrollment"))
    );
    let done = browser
        .finish(
            &world,
            serde_json::json!({ "code": phone(&world, &secret) }),
        )
        .await;
    assert_eq!(done.status, StatusCode::OK, "{:?}", done.body);
    assert_eq!(done.body["status"], "completed", "{:?}", done.body);
    assert_eq!(
        done.body["recovery_codes"].as_array().map(Vec::len),
        Some(10),
        "{:?}",
        done.body
    );
    assert!(
        done.set_cookies()
            .iter()
            .any(|cookie| cookie.starts_with("__Secure-hodor_session=")),
        "the session cookie is set"
    );

    let session = browser.session(&world, "acme").await;
    assert_eq!(
        session.body["assurance"], "multi_factor",
        "{:?}",
        session.body
    );
    assert_eq!(
        session.body["methods"],
        serde_json::json!(["password", "enrollment"])
    );

    // The next sign-in asks for the code, and shows no codes.
    world.clock.advance(Duration::seconds(STEP_SECONDS));
    let mut next_browser = Browser::default();
    let next = next_browser.after_password(&world).await;
    assert_eq!(status_and_step(&next), (Some("pending"), Some("totp")));
    let done = next_browser
        .send(
            &world,
            Method::POST,
            &format!("{STEPS}/totp"),
            Some(serde_json::json!({ "code": phone(&world, &secret) })),
        )
        .await;
    assert_eq!(done.body["status"], "completed", "{:?}", done.body);
    assert!(done.body.get("recovery_codes").is_none());
}

#[tokio::test]
async fn a_security_key_set_up_during_the_sign_in_is_asked_for_the_next_time() {
    let world = world().await;
    let mut browser = Browser::default();
    browser.after_password(&world).await;
    let begun = browser.begin(&world, "security_key").await;
    assert_eq!(begun.status, StatusCode::OK, "{:?}", begun.body);
    assert_eq!(begun.body["kind"], "security_key");
    assert!(begun.body.get("registration_id").is_none());
    let key = SoftwareAuthenticator::new(ORIGIN);
    let done = browser
        .finish(&world, key.register(&begun.body["public_key"]))
        .await;
    assert_eq!(done.body["status"], "completed", "{:?}", done.body);
    assert_eq!(
        done.body["recovery_codes"].as_array().map(Vec::len),
        Some(10)
    );
    let session = browser.session(&world, "acme").await;
    assert_eq!(
        session.body["assurance"], "multi_factor",
        "a key bound during the sign-in is not phishing-resistant"
    );

    let mut next_browser = Browser::default();
    let next = next_browser.after_password(&world).await;
    assert_eq!(status_and_step(&next), (Some("pending"), Some("webauthn")));
    let options = next_browser
        .send(
            &world,
            Method::POST,
            &format!("{STEPS}/webauthn/options"),
            None,
        )
        .await;
    let done = next_browser
        .send(
            &world,
            Method::POST,
            &format!("{STEPS}/webauthn"),
            Some(key.answer(&options.body["public_key"])),
        )
        .await;
    assert_eq!(done.body["status"], "completed", "{:?}", done.body);
    let session = next_browser.session(&world, "acme").await;
    assert_eq!(session.body["assurance"], "phishing_resistant");
}

#[tokio::test]
async fn a_passkey_set_up_during_the_sign_in_signs_in_alone_the_next_time() {
    let world = world().await;
    let mut browser = Browser::default();
    browser.after_password(&world).await;
    let begun = browser.begin(&world, "passkey").await;
    assert_eq!(begun.status, StatusCode::OK, "{:?}", begun.body);
    assert_eq!(
        begun.body["public_key"]["authenticatorSelection"]["residentKey"],
        "required"
    );
    let passkey = SoftwareAuthenticator::passkey(ORIGIN);
    let done = browser
        .finish(&world, passkey.register(&begun.body["public_key"]))
        .await;
    assert_eq!(done.body["status"], "completed", "{:?}", done.body);

    let mut next_browser = Browser::default();
    next_browser.start(&world).await;
    let options = next_browser
        .send(
            &world,
            Method::POST,
            &format!("{STEPS}/passkey/options"),
            None,
        )
        .await;
    let done = next_browser
        .send(
            &world,
            Method::POST,
            &format!("{STEPS}/passkey"),
            Some(passkey.answer(&options.body["public_key"])),
        )
        .await;
    assert_eq!(done.body["status"], "completed", "{:?}", done.body);
}

#[tokio::test]
async fn enrolling_needs_the_sign_in_its_csrf_token_and_the_first_factor() {
    let world = world().await;

    // No sign-in at all.
    let mut stranger = Browser::default();
    let refused = stranger.begin(&world, "authenticator_application").await;
    assert_eq!(refused.status, StatusCode::NOT_FOUND);
    assert_eq!(refused.code(), "authentication.transaction_not_found");

    // Before the first factor.
    let mut browser = Browser::default();
    browser.start(&world).await;
    let refused = browser.begin(&world, "authenticator_application").await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(refused.code(), "authentication.unexpected_step");
    browser.identifier(&world, "ana@example.com").await;
    let refused = browser
        .finish(&world, serde_json::json!({ "code": "123456" }))
        .await;
    assert_eq!(refused.code(), "authentication.unexpected_step");
    browser.password(&world, PASSWORD).await;

    // Without the CSRF token, or with another site's origin.
    let mut forged = browser.clone();
    forged.csrf_token = Some("0".repeat(64));
    let refused = forged.begin(&world, "authenticator_application").await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.code(), "request.csrf_token_invalid");
    let refused = forged
        .finish(&world, serde_json::json!({ "code": "123456" }))
        .await;
    assert_eq!(refused.code(), "request.csrf_token_invalid");
    let mut elsewhere = browser.clone();
    elsewhere.origin = Some("https://evil.example");
    let refused = elsewhere.begin(&world, "authenticator_application").await;
    assert_eq!(refused.code(), "request.cross_origin");

    // A kind that is none of the three.
    let refused = browser.begin(&world, "sms").await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(refused.code(), "request.invalid_body");

    // The browser that signed in can.
    let begun = browser.begin(&world, "authenticator_application").await;
    assert_eq!(begun.status, StatusCode::OK, "{:?}", begun.body);
}

#[tokio::test]
async fn the_enrollment_of_another_browser_cannot_be_finished() {
    let world = world().await;
    let mut ana = Browser::default();
    ana.after_password(&world).await;
    let begun = ana.begin(&world, "authenticator_application").await;
    let secret = begun.body["secret"].as_str().expect("secret").to_owned();

    // Someone else's sign-in of the same person reaches the step but has
    // begun nothing: the code of the secret Ana was shown finishes nothing.
    let mut other = Browser::default();
    other.after_password(&world).await;
    let refused = other
        .finish(
            &world,
            serde_json::json!({ "code": phone(&world, &secret) }),
        )
        .await;
    assert_eq!(
        status_and_step(&refused),
        (Some("rejected"), Some("enrollment"))
    );

    // Ana's own still finishes.
    let done = ana
        .finish(
            &world,
            serde_json::json!({ "code": phone(&world, &secret) }),
        )
        .await;
    assert_eq!(done.body["status"], "completed", "{:?}", done.body);

    // And the other sign-in is now told the person has a factor.
    let refused = other
        .finish(
            &world,
            serde_json::json!({ "code": phone(&world, &secret) }),
        )
        .await;
    assert_eq!(refused.status, StatusCode::CONFLICT);
    assert_eq!(refused.code(), "authentication.enrollment_not_needed");
}
