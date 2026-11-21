//! Signing in through an identity provider, over HTTP, against the real
//! contexts on their in-memory ports and a provider that signs real
//! tokens. Above all: the ways an account must not be reachable.

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use hodor_adapters_crypto::testing::{CLIENT_ID, CLIENT_SECRET, SigningKey, TestProvider};
use hodor_adapters_crypto::{AwsLcVerifier, Sha256Digest};
use hodor_authentication::api::{
    AccountService, AttemptGuard, AuthFlow, AuthenticationService, FlowEngine,
    IdentifierAuthenticator, PasswordAuthenticator,
};
use hodor_authentication::testing::{
    InMemoryAttempts, InMemoryTransactions, InMemoryVerificationTokens,
};
use hodor_credential::api::{CredentialService, NewPassword, PasswordRules};
use hodor_credential::testing::{FakeHasher, InMemoryPasswords};
use hodor_federation::api::{
    CreateProvider, EXTERNAL_STEP, ExternalIdentityAuthenticator, ExternalSignIn,
    FederationService, OpenIdClient, ProviderId, ProviderKind, ProviderSettings, ProviderStatus,
};
use hodor_federation::testing::InMemoryFederation;
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_identity::testing::InMemoryUsers;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::sealing::testing::FakeSecretBox;
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
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use time::Duration;
use tower::ServiceExt as _;

const HOST: &str = "auth.example";
const PUBLIC: &str = "https://auth.example";
const ISSUER: &str = "https://provider.example.com";
const NOW: i64 = 1_800_000_000;
const PASSWORD: &str = "correct horse battery staple";

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
    provider: TestProvider,
    key: SigningKey,
    federation: FederationService,
    identity: IdentityService,
    credentials: CredentialService,
    acme: TenantContext,
    /// The provider `example` of the tenant acme.
    example: ProviderId,
}

fn settings(creates_users: bool) -> ProviderSettings {
    ProviderSettings {
        display_name: "Example".to_owned(),
        issuer: ISSUER.to_owned(),
        client_id: CLIENT_ID.to_owned(),
        scopes: ProviderSettings::default_scopes(),
        creates_users,
    }
}

async fn world() -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let clock = Arc::new(FixedClock::at(
        Timestamp::from_unix_timestamp(NOW).expect("a time"),
    ));
    let digest = Arc::new(Sha256Digest);
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

    let key = SigningKey::p256();
    let provider = TestProvider::new(ISSUER, &[("key-1", &key)]);
    let stores = InMemoryFederation::default();
    let federation = FederationService::new(
        units(),
        Arc::new(stores.clone()),
        Arc::new(stores.clone()),
        Arc::new(FakeSecretBox),
        clock.clone(),
    );
    let openid = OpenIdClient::new(
        Arc::new(provider.clone()),
        Arc::new(AwsLcVerifier),
        digest.clone(),
        Arc::new(SequentialRandom::default()),
        clock.clone(),
    );
    let external = ExternalSignIn::new(
        federation.clone(),
        openid,
        identity.clone(),
        Arc::new(stores),
        units(),
        Arc::new(FakeSecretBox),
        digest.clone(),
        clock.clone(),
        PUBLIC,
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
        )))
        .with(Arc::new(ExternalIdentityAuthenticator::new(
            external.clone(),
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
        PUBLIC,
    );
    let authentication = AuthenticationService::new(
        units(),
        Arc::new(InMemoryTransactions::default()),
        engine,
        AuthFlow::built_in().with_alternative(EXTERNAL_STEP, EXTERNAL_STEP),
        identity.clone(),
        sessions.clone(),
        tenants.clone(),
        digest.clone(),
        Arc::new(SequentialRandom::default()),
        clock.clone(),
    )
    .expect("the flow with its alternative is valid");

    let mut contexts = Vec::new();
    for slug in ["acme", "globex"] {
        let created = tenants
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
        contexts.push(TenantContext::assume(created.id()));
    }
    let (acme, globex) = (contexts[0].clone(), contexts[1].clone());
    let example = federation
        .create_provider(
            &acme,
            CreateProvider {
                alias: "example".to_owned(),
                kind: ProviderKind::OpenIdConnect,
                settings: settings(true),
                client_secret: Secret::from(CLIENT_SECRET.to_owned()),
            },
            Caller::system(),
        )
        .await
        .expect("provider")
        .id();

    let state = InteractionState {
        authentication,
        accounts,
        sessions,
        external: Some(external),
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
        units_of_work,
        provider,
        key,
        federation,
        identity,
        credentials,
        acme,
        example,
    }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

impl Reply {
    fn code(&self) -> &str {
        self.body["code"].as_str().unwrap_or_default()
    }

    fn sign_in_status(&self) -> &str {
        self.body["status"].as_str().unwrap_or_default()
    }
}

/// A browser, as far as these tests need one.
#[derive(Default, Clone)]
struct Browser {
    cookies: BTreeMap<String, String>,
    csrf_token: Option<String>,
}

/// What a browser carries away to a provider and back.
struct Departure {
    state: String,
    nonce: String,
}

impl Browser {
    async fn send(
        &mut self,
        world: &World,
        method: Method,
        path: &str,
        body: Option<Value>,
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
            body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        };
        for cookie in reply.headers.get_all(header::SET_COOKIE) {
            let cookie = cookie.to_str().expect("ascii");
            let (name, value) = cookie
                .split(';')
                .next()
                .and_then(|pair| pair.split_once('='))
                .expect("name=value");
            if cookie.contains("Max-Age=0") {
                self.cookies.remove(name);
            } else {
                self.cookies.insert(name.to_owned(), value.to_owned());
            }
        }
        if let Some(token) = reply.body["csrf_token"].as_str() {
            self.csrf_token = Some(token.to_owned());
        }
        reply
    }

    /// Starts a sign-in in `tenant` and chooses the provider `alias`.
    async fn leave_for(&mut self, world: &World, tenant: &str, alias: &str) -> Departure {
        let started = self
            .send(
                world,
                Method::POST,
                &format!("/t/{tenant}/interaction/sign-in"),
                None,
            )
            .await;
        assert_eq!(started.status, StatusCode::CREATED, "{:?}", started.body);
        self.choose(world, tenant, alias).await
    }

    async fn choose(&mut self, world: &World, tenant: &str, alias: &str) -> Departure {
        let chosen = self
            .send(
                world,
                Method::POST,
                &format!("/t/{tenant}/interaction/sign-in/providers/{alias}"),
                None,
            )
            .await;
        assert_eq!(chosen.status, StatusCode::OK, "{:?}", chosen.body);
        let redirect = chosen.body["redirect"].as_str().expect("an address");
        let (address, query) = redirect.split_once('?').expect("a query");
        assert_eq!(address, format!("{ISSUER}/authorize"));
        let sent: HashMap<String, String> = form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        assert_eq!(
            sent["redirect_uri"],
            format!("{PUBLIC}/t/{tenant}/account/providers/{alias}/callback"),
            "the provider sends people back to a page of this tenant and provider"
        );
        Departure {
            state: sent["state"].clone(),
            nonce: sent["nonce"].clone(),
        }
    }

    /// Comes back from the provider with a code and a state.
    async fn come_back(
        &mut self,
        world: &World,
        tenant: &str,
        alias: &str,
        code: &str,
        state: &str,
    ) -> Reply {
        self.send(
            world,
            Method::POST,
            &format!("/t/{tenant}/interaction/sign-in/providers/{alias}/callback"),
            Some(json!({ "code": code, "state": state })),
        )
        .await
    }

    async fn who(&mut self, world: &World, tenant: &str) -> Reply {
        self.send(
            world,
            Method::GET,
            &format!("/t/{tenant}/interaction/session"),
            None,
        )
        .await
    }
}

impl World {
    /// Makes the provider answer `code` with a token for this person and request.
    fn provider_vouches(
        &self,
        code: &str,
        leaving: &Departure,
        subject: &str,
        email: Option<(&str, bool)>,
    ) {
        let mut claims = json!({
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": subject,
            "exp": NOW + 300,
            "iat": NOW,
            "nonce": leaving.nonce,
            "name": "Bia Example",
            "locale": "pt-BR",
        });
        if let Some((address, verified)) = email {
            claims["email"] = json!(address);
            claims["email_verified"] = json!(verified);
        }
        let token = self
            .key
            .token(&json!({ "alg": "ES256", "kid": "key-1" }), &claims);
        self.provider.answer_code(code, &token);
    }

    /// One whole sign-in through the provider `example` of acme.
    async fn sign_in(&self, subject: &str, email: Option<(&str, bool)>) -> (Browser, Reply) {
        let mut browser = Browser::default();
        let leaving = browser.leave_for(self, "acme", "example").await;
        self.provider_vouches("code", &leaving, subject, email);
        let reply = browser
            .come_back(self, "acme", "example", "code", &leaving.state)
            .await;
        (browser, reply)
    }

    async fn user_with(&self, address: &str) -> Option<UserId> {
        self.identity
            .find_by_login(&self.acme, address)
            .await
            .expect("find")
            .map(|user| user.id())
    }

    fn refusals(&self) -> Vec<String> {
        self.units_of_work
            .committed_events()
            .iter()
            .filter(|event| event.event_type == "federation.sign_in_refused")
            .map(|event| {
                event.payload["reason"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned()
            })
            .collect()
    }

    fn count(&self, event_type: &str) -> usize {
        self.units_of_work
            .committed_event_types()
            .iter()
            .filter(|name| *name == event_type)
            .count()
    }

    /// Ana, who registered in acme with a password.
    async fn ana_with_a_password(&self) -> UserId {
        let ana = self
            .identity
            .create(
                &self.acme,
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
        self.credentials
            .set_password(&self.acme, ana, new, false, Caller::system())
            .await
            .expect("password");
        ana
    }
}

#[track_caller]
fn rejected(reply: &Reply) {
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    assert_eq!(reply.sign_in_status(), "rejected", "{:?}", reply.body);
    assert!(
        reply.headers.get(header::SET_COOKIE).is_none(),
        "no session"
    );
    // Nothing in the answer says why: it has the fields of any rejected
    // step and no other.
    let mut fields: Vec<&str> = reply
        .body
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(fields, ["attempts_left", "csrf_token", "status", "step"]);
    assert_eq!(
        reply.body["step"], "identifier",
        "the sign-in is where it was"
    );
}

#[tokio::test]
async fn a_person_nobody_knows_is_created_and_signed_in_on_their_first_visit() {
    let world = world().await;
    let (mut browser, reply) = world
        .sign_in("subject-of-bia", Some(("bia@example.com", true)))
        .await;

    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    assert_eq!(reply.sign_in_status(), "completed");
    assert!(browser.cookies.contains_key("__Secure-hodor_session"));
    assert!(!browser.cookies.contains_key("__Secure-hodor_signin"));

    // The session says how the person got in.
    let session = browser.who(&world, "acme").await;
    assert_eq!(session.status, StatusCode::OK);
    assert_eq!(session.body["methods"], json!(["external"]));
    assert_eq!(session.body["assurance"], "single_factor");

    // The user exists with what the provider vouched for, already verified.
    let user = world
        .identity
        .find_by_login(&world.acme, "bia@example.com")
        .await
        .expect("find")
        .expect("created");
    assert_eq!(session.body["user_id"], user.id().to_string());
    assert!(user.may_sign_in());
    assert!(user.snapshot().identifiers[0].is_verified());
    assert_eq!(
        user.snapshot().profile.display_name.as_deref(),
        Some("Bia Example")
    );
    assert_eq!(user.snapshot().profile.locale.as_deref(), Some("pt-BR"));

    // And is linked to the external identity.
    let links = world
        .federation
        .links_of(&world.acme, user.id())
        .await
        .expect("links");
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].provider_id, world.example);
    assert_eq!(links[0].subject.expose(), "subject-of-bia");
    for event in [
        "identity.user_created",
        "federation.identity_linked",
        "session.started",
        "authentication.succeeded",
    ] {
        assert_eq!(world.count(event), 1, "{event}");
    }
    assert!(world.refusals().is_empty());
}

#[tokio::test]
async fn the_same_external_identity_is_the_same_user_every_time() {
    let world = world().await;
    let (mut first, _) = world
        .sign_in("subject-of-bia", Some(("bia@example.com", true)))
        .await;
    // Later, with another address at the provider: the subject is what counts.
    let (mut second, reply) = world
        .sign_in("subject-of-bia", Some(("renamed@example.com", true)))
        .await;

    assert_eq!(reply.sign_in_status(), "completed");
    let (one, two) = (
        first.who(&world, "acme").await,
        second.who(&world, "acme").await,
    );
    assert_eq!(one.body["user_id"], two.body["user_id"]);
    assert_eq!(world.count("identity.user_created"), 1, "no second user");
    assert_eq!(world.count("federation.identity_linked"), 1);
    assert_eq!(
        world.user_with("renamed@example.com").await,
        None,
        "the profile is not rewritten"
    );
}

#[tokio::test]
async fn an_external_identity_is_never_let_into_an_existing_account_by_its_email_address() {
    let world = world().await;
    let ana = world.ana_with_a_password().await;

    // Somebody arrives from the provider with ana's address, vouched for.
    let (mut browser, reply) = world
        .sign_in("subject-of-a-stranger", Some(("ana@example.com", true)))
        .await;

    rejected(&reply);
    assert_eq!(
        browser.who(&world, "acme").await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(world.refusals(), ["email_belongs_to_a_user"]);
    // Ana's account is exactly as it was: no link, no second user, the
    // same way in.
    assert!(
        world
            .federation
            .links_of(&world.acme, ana)
            .await
            .expect("links")
            .is_empty()
    );
    assert_eq!(world.user_with("ana@example.com").await, Some(ana));
    assert_eq!(world.count("identity.user_created"), 1);
    assert_eq!(world.count("federation.identity_linked"), 0);

    let mut hers = Browser::default();
    hers.send(&world, Method::POST, "/t/acme/interaction/sign-in", None)
        .await;
    hers.send(
        &world,
        Method::POST,
        "/t/acme/interaction/sign-in/steps/identifier",
        Some(json!({ "identifier": "ana@example.com" })),
    )
    .await;
    let signed = hers
        .send(
            &world,
            Method::POST,
            "/t/acme/interaction/sign-in/steps/password",
            Some(json!({ "password": PASSWORD })),
        )
        .await;
    assert_eq!(signed.sign_in_status(), "completed");

    // The same in any spelling of the address.
    let (_, reply) = world
        .sign_in("subject-of-another", Some(("ANA@Example.COM", true)))
        .await;
    rejected(&reply);
}

#[tokio::test]
async fn an_address_the_provider_does_not_vouch_for_creates_nobody() {
    let world = world().await;
    for (subject, email) in [
        ("subject-1", Some(("bia@example.com", false))),
        ("subject-2", None),
    ] {
        let (_, reply) = world.sign_in(subject, email).await;
        rejected(&reply);
    }
    assert_eq!(world.refusals(), ["no_vouched_email", "no_vouched_email"]);
    assert_eq!(world.count("identity.user_created"), 0);
    assert_eq!(world.user_with("bia@example.com").await, None);
}

#[tokio::test]
async fn a_provider_that_does_not_create_users_lets_in_only_whom_it_is_linked_to() {
    let world = world().await;
    let (_, created) = world
        .sign_in("subject-of-bia", Some(("bia@example.com", true)))
        .await;
    assert_eq!(created.sign_in_status(), "completed");

    world
        .federation
        .change_provider(
            &world.acme,
            hodor_federation::api::ChangeProvider {
                id: world.example,
                settings: settings(false),
            },
            Caller::system(),
        )
        .await
        .expect("change");

    let (_, known) = world
        .sign_in("subject-of-bia", Some(("bia@example.com", true)))
        .await;
    assert_eq!(known.sign_in_status(), "completed");
    let (_, unknown) = world
        .sign_in("subject-of-carla", Some(("carla@example.com", true)))
        .await;
    rejected(&unknown);
    assert_eq!(world.refusals(), ["not_linked"]);
    assert_eq!(world.user_with("carla@example.com").await, None);
}

#[tokio::test]
async fn a_linked_user_who_may_not_sign_in_is_refused() {
    let world = world().await;
    world
        .sign_in("subject-of-bia", Some(("bia@example.com", true)))
        .await;
    let bia = world.user_with("bia@example.com").await.expect("created");
    world
        .identity
        .suspend(&world.acme, bia, "left the company", Caller::system())
        .await
        .expect("suspend");

    let (_, reply) = world
        .sign_in("subject-of-bia", Some(("bia@example.com", true)))
        .await;
    rejected(&reply);
    assert_eq!(world.refusals(), ["user_may_not_sign_in"]);
}

#[tokio::test]
async fn an_answer_with_another_state_is_refused_and_the_trip_is_gone() {
    let world = world().await;
    let mut browser = Browser::default();
    let leaving = browser.leave_for(&world, "acme", "example").await;
    world.provider_vouches(
        "code",
        &leaving,
        "subject-of-bia",
        Some(("bia@example.com", true)),
    );

    let wrong = browser
        .come_back(&world, "acme", "example", "code", "not-the-state")
        .await;
    rejected(&wrong);
    // Even the right state no longer works: the pending authorization was used.
    let late = browser
        .come_back(&world, "acme", "example", "code", &leaving.state)
        .await;
    rejected(&late);

    assert_eq!(
        world.refusals(),
        ["state_mismatch", "no_pending_authorization"]
    );
    assert_eq!(world.count("identity.user_created"), 0);
    assert_eq!(
        world.provider.requests_to("/token"),
        0,
        "the code was never exchanged"
    );
}

#[tokio::test]
async fn an_answer_cannot_be_presented_twice() {
    let world = world().await;
    let mut browser = Browser::default();
    let leaving = browser.leave_for(&world, "acme", "example").await;
    world.provider_vouches(
        "code",
        &leaving,
        "subject-of-bia",
        Some(("bia@example.com", true)),
    );
    let first = browser
        .come_back(&world, "acme", "example", "code", &leaving.state)
        .await;
    assert_eq!(first.sign_in_status(), "completed");

    // Whoever saw the address of that answer tries it in a browser of their own.
    let mut thief = Browser::default();
    thief
        .send(&world, Method::POST, "/t/acme/interaction/sign-in", None)
        .await;
    let replayed = thief
        .come_back(&world, "acme", "example", "code", &leaving.state)
        .await;
    rejected(&replayed);
    // And after making a pending authorization of their own, to have one at all.
    thief.choose(&world, "acme", "example").await;
    let replayed = thief
        .come_back(&world, "acme", "example", "code", &leaving.state)
        .await;
    rejected(&replayed);

    assert_eq!(
        world.refusals(),
        ["no_pending_authorization", "state_mismatch"]
    );
    assert_eq!(
        thief.who(&world, "acme").await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn an_answer_obtained_by_someone_else_cannot_be_finished_in_a_victims_browser() {
    let world = world().await;
    // The attacker goes to the provider as themself and keeps the answer.
    let mut attacker = Browser::default();
    let theirs = attacker.leave_for(&world, "acme", "example").await;
    world.provider_vouches(
        "attacker-code",
        &theirs,
        "subject-of-the-attacker",
        Some(("attacker@example.com", true)),
    );

    // The victim's browser is made to present it, with a pending authorization of its own
    // under way.
    let mut victim = Browser::default();
    victim.leave_for(&world, "acme", "example").await;
    let forged = victim
        .come_back(&world, "acme", "example", "attacker-code", &theirs.state)
        .await;

    rejected(&forged);
    assert_eq!(world.refusals(), ["state_mismatch"]);
    assert_eq!(
        victim.who(&world, "acme").await.status,
        StatusCode::UNAUTHORIZED
    );
    // The attacker's own pending authorization was not touched by any of it.
    let own = attacker
        .come_back(&world, "acme", "example", "attacker-code", &theirs.state)
        .await;
    assert_eq!(own.sign_in_status(), "completed");
}

#[tokio::test]
async fn an_answer_is_only_checked_against_the_provider_the_trip_was_made_for() {
    let world = world().await;
    let other_key = SigningKey::p256();
    world
        .federation
        .create_provider(
            &world.acme,
            CreateProvider {
                alias: "other".to_owned(),
                kind: ProviderKind::OpenIdConnect,
                settings: settings(true),
                client_secret: Secret::from(CLIENT_SECRET.to_owned()),
            },
            Caller::system(),
        )
        .await
        .expect("provider");
    drop(other_key);

    let mut browser = Browser::default();
    let leaving = browser.leave_for(&world, "acme", "example").await;
    world.provider_vouches(
        "code",
        &leaving,
        "subject-of-bia",
        Some(("bia@example.com", true)),
    );
    // Presented at the address of the other provider.
    let crossed = browser
        .come_back(&world, "acme", "other", "code", &leaving.state)
        .await;

    rejected(&crossed);
    assert_eq!(world.refusals(), ["another_provider"]);
    assert_eq!(world.count("identity.user_created"), 0);
}

#[tokio::test]
async fn a_disabled_provider_is_not_offered_and_signs_nobody_in() {
    let world = world().await;
    let mut browser = Browser::default();
    let offered = browser
        .send(
            &world,
            Method::GET,
            "/t/acme/interaction/sign-in/providers",
            None,
        )
        .await;
    assert_eq!(
        offered.body,
        json!({ "providers": [{ "alias": "example", "display_name": "Example" }] }),
        "what the page shows, and nothing else"
    );

    // A pending authorization is under way when the provider is disabled.
    let leaving = browser.leave_for(&world, "acme", "example").await;
    world.provider_vouches(
        "code",
        &leaving,
        "subject-of-bia",
        Some(("bia@example.com", true)),
    );
    world
        .federation
        .set_provider_status(
            &world.acme,
            world.example,
            ProviderStatus::Disabled,
            Caller::system(),
        )
        .await
        .expect("disable");

    let finished = browser
        .come_back(&world, "acme", "example", "code", &leaving.state)
        .await;
    rejected(&finished);
    assert_eq!(world.refusals(), ["provider_not_offered"]);

    let offered = browser
        .send(
            &world,
            Method::GET,
            "/t/acme/interaction/sign-in/providers",
            None,
        )
        .await;
    assert_eq!(offered.body, json!({ "providers": [] }));
    let mut fresh = Browser::default();
    fresh
        .send(&world, Method::POST, "/t/acme/interaction/sign-in", None)
        .await;
    let chosen = fresh
        .send(
            &world,
            Method::POST,
            "/t/acme/interaction/sign-in/providers/example",
            None,
        )
        .await;
    assert_eq!(chosen.status, StatusCode::NOT_FOUND);
    assert_eq!(chosen.code(), "federation.provider_not_found");
}

#[tokio::test]
async fn the_provider_of_one_tenant_does_nothing_in_another() {
    let world = world().await;
    let mut browser = Browser::default();
    let offered = browser
        .send(
            &world,
            Method::GET,
            "/t/globex/interaction/sign-in/providers",
            None,
        )
        .await;
    assert_eq!(offered.body, json!({ "providers": [] }));

    browser
        .send(&world, Method::POST, "/t/globex/interaction/sign-in", None)
        .await;
    let chosen = browser
        .send(
            &world,
            Method::POST,
            "/t/globex/interaction/sign-in/providers/example",
            None,
        )
        .await;
    assert_eq!(chosen.status, StatusCode::NOT_FOUND);
    assert_eq!(chosen.code(), "federation.provider_not_found");

    // An answer made for acme, presented to globex by a browser with a
    // sign-in there.
    let mut at_acme = Browser::default();
    let leaving = at_acme.leave_for(&world, "acme", "example").await;
    world.provider_vouches(
        "code",
        &leaving,
        "subject-of-bia",
        Some(("bia@example.com", true)),
    );
    let crossed = browser
        .come_back(&world, "globex", "example", "code", &leaving.state)
        .await;
    rejected(&crossed);
    assert_eq!(
        browser.who(&world, "globex").await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn choosing_a_provider_needs_a_sign_in_of_this_browser_and_its_token() {
    let world = world().await;
    // No sign-in at all.
    let mut nobody = Browser::default();
    let chosen = nobody
        .send(
            &world,
            Method::POST,
            "/t/acme/interaction/sign-in/providers/example",
            None,
        )
        .await;
    assert_eq!(chosen.status, StatusCode::NOT_FOUND);
    assert_eq!(chosen.code(), "authentication.transaction_not_found");

    // A sign-in, but not the token a page of this origin would have.
    let mut browser = Browser::default();
    browser
        .send(&world, Method::POST, "/t/acme/interaction/sign-in", None)
        .await;
    let mut without_token = browser.clone();
    without_token.csrf_token = None;
    for path in [
        "/t/acme/interaction/sign-in/providers/example",
        "/t/acme/interaction/sign-in/providers/example/callback",
    ] {
        let refused = without_token
            .send(
                &world,
                Method::POST,
                path,
                Some(json!({ "code": "c", "state": "s" })),
            )
            .await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(refused.code(), "request.csrf_token_invalid");
    }

    // An alias that could not be one is a provider that does not exist.
    let odd = browser
        .send(
            &world,
            Method::POST,
            "/t/acme/interaction/sign-in/providers/Not%20An%20Alias",
            None,
        )
        .await;
    assert_eq!(odd.status, StatusCode::NOT_FOUND);
    assert_eq!(odd.code(), "federation.provider_not_found");
}

#[tokio::test]
async fn a_sign_in_is_completed_by_its_steps_or_by_a_provider_never_by_part_of_each() {
    let world = world().await;
    world.ana_with_a_password().await;
    let mut browser = Browser::default();
    browser
        .send(&world, Method::POST, "/t/acme/interaction/sign-in", None)
        .await;
    // An identifier is given first, naming ana.
    browser
        .send(
            &world,
            Method::POST,
            "/t/acme/interaction/sign-in/steps/identifier",
            Some(json!({ "identifier": "ana@example.com" })),
        )
        .await;
    // Then a provider vouches for somebody else.
    let leaving = browser.choose(&world, "acme", "example").await;
    world.provider_vouches(
        "code",
        &leaving,
        "subject-of-bia",
        Some(("bia@example.com", true)),
    );
    let mixed = browser
        .come_back(&world, "acme", "example", "code", &leaving.state)
        .await;

    assert_eq!(
        mixed.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{:?}",
        mixed.body
    );
    assert_eq!(mixed.code(), "authentication.unexpected_step");
    assert_eq!(
        browser.who(&world, "acme").await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(world.count("identity.user_created"), 1, "only ana exists");
}

#[tokio::test]
async fn a_trip_expires_with_its_sign_in() {
    let world = world().await;
    let mut browser = Browser::default();
    let leaving = browser.leave_for(&world, "acme", "example").await;
    world.provider_vouches(
        "code",
        &leaving,
        "subject-of-bia",
        Some(("bia@example.com", true)),
    );

    world.clock.advance(Duration::minutes(11));
    let late = browser
        .come_back(&world, "acme", "example", "code", &leaving.state)
        .await;

    assert_ne!(late.sign_in_status(), "completed");
    assert!(!browser.cookies.contains_key("__Secure-hodor_session"));
    assert_eq!(world.count("identity.user_created"), 0);
}

#[tokio::test]
async fn a_provider_that_cannot_be_reached_is_an_error_and_not_a_rejection() {
    let world = world().await;
    let mut browser = Browser::default();
    browser
        .send(&world, Method::POST, "/t/acme/interaction/sign-in", None)
        .await;
    world.provider.set_down(true);

    let chosen = browser
        .send(
            &world,
            Method::POST,
            "/t/acme/interaction/sign-in/providers/example",
            None,
        )
        .await;

    assert_eq!(chosen.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(chosen.code(), "federation.provider_unavailable");
    // What went wrong with the provider is not told to the person.
    assert!(!chosen.body.to_string().contains("could not be fetched"));
}

#[tokio::test]
async fn rejections_through_a_provider_count_against_the_sign_in() {
    let world = world().await;
    let mut browser = Browser::default();
    browser
        .send(&world, Method::POST, "/t/acme/interaction/sign-in", None)
        .await;
    let mut last = None;
    for _ in 0..5 {
        last = Some(
            browser
                .come_back(&world, "acme", "example", "code", "a-guess")
                .await,
        );
    }
    let last = last.expect("five answers");
    assert_eq!(last.sign_in_status(), "failed", "{:?}", last.body);
}
