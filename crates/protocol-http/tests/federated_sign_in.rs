//! Signing in through an identity provider, over HTTP, against the real
//! contexts on their in-memory ports and a provider that signs real
//! tokens. Above all: the ways an account must not be reachable.

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use hodor_adapters_crypto::testing::{CLIENT_ID, CLIENT_SECRET, SigningKey, TestProvider};
use hodor_adapters_crypto::{AwsLcVerifier, Sha256Digest};
use hodor_adapters_ldap::LdapDirectoryClient;
use hodor_adapters_ldap::testing::{BASE, BIND_NAME, BIND_PASSWORD, Person, TestDirectory};
use hodor_authentication::api::{
    AccountService, AttemptGuard, AuthFlow, AuthenticationService, FlowEngine,
    IdentifierAuthenticator, LockoutRules, PasswordAuthenticator,
};
use hodor_authentication::testing::{
    InMemoryAttempts, InMemoryTransactions, InMemoryVerificationTokens,
};
use hodor_credential::api::{CredentialService, NewPassword, PasswordRules};
use hodor_credential::testing::{FakeHasher, InMemoryPasswords};
use hodor_federation::api::{
    CreateProvider, DirectoryAnswer, DirectoryClient, DirectoryQuery, DirectorySettings,
    EXTERNAL_STEP, ExternalIdentityAuthenticator, ExternalSignIn, FederationService, GitHubClient,
    LockoutPolicy, OpenIdClient, ProviderId, ProviderKind, ProviderSettings, ProviderStatus,
};
use hodor_federation::testing::InMemoryFederation;
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_identity::testing::InMemoryUsers;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::sealing::testing::FakeSecretBox;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, DomainError, HttpClient, HttpRequest, HttpResponse, Secret, TenantContext, Timestamp,
    UserId,
};
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
use std::sync::Mutex;
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

/// GitHub, as far as Hodor talks to it: it answers a code with a token,
/// and a token with who the person is. Every request is kept.
#[derive(Clone, Default)]
struct FakeGitHub {
    /// What `/user` answers, and what `/user/emails` answers.
    person: Arc<Mutex<(Value, Value)>>,
    requests: Arc<Mutex<Vec<HttpRequest>>>,
}

impl FakeGitHub {
    fn is(&self, user: Value, emails: Value) {
        *self.person.lock().expect("person") = (user, emails);
    }

    fn requests(&self) -> Vec<HttpRequest> {
        self.requests.lock().expect("requests").clone()
    }
}

#[async_trait::async_trait]
impl HttpClient for FakeGitHub {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, DomainError> {
        self.requests
            .lock()
            .expect("requests")
            .push(request.clone());
        let (user, emails) = self.person.lock().expect("person").clone();
        let answer = |status: u16, body: Value| HttpResponse {
            status,
            headers: Vec::new(),
            body: body.to_string().into_bytes(),
        };
        let authorized = request
            .headers
            .iter()
            .any(|(name, value)| name == "authorization" && value == "Bearer token-of-github");
        Ok(match request.url.as_str() {
            "https://github.com/login/oauth/access_token" => {
                let form: HashMap<String, String> =
                    form_urlencoded::parse(request.body.as_deref().unwrap_or_default())
                        .into_owned()
                        .collect();
                let good = form.get("code").map(String::as_str) == Some("github-code")
                    && form.get("client_secret").map(String::as_str) == Some(CLIENT_SECRET);
                if good {
                    answer(
                        200,
                        json!({ "access_token": "token-of-github", "token_type": "bearer" }),
                    )
                } else {
                    // As GitHub does: a refusal with status 200.
                    answer(200, json!({ "error": "bad_verification_code" }))
                }
            }
            "https://api.github.com/user" if authorized => answer(200, user),
            "https://api.github.com/user/emails" if authorized => answer(200, emails),
            _ => answer(401, json!({ "message": "Bad credentials" })),
        })
    }
}

struct World {
    router: Router,
    clock: Arc<FixedClock>,
    units_of_work: InMemoryUnitOfWorkFactory,
    provider: TestProvider,
    github: FakeGitHub,
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
        trusts_email: false,
        directory: None,
    }
}

async fn world() -> World {
    world_with(None).await
}

/// A world whose sign-in can also ask this directory, as
/// `host:port`, through this client.
async fn world_with(directory: Option<(String, Arc<dyn DirectoryClient>)>) -> World {
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
    // A directory in a container is reached in the clear at a private
    // address: both lists name it, as they would on a development stack.
    let hosts: Vec<String> = directory.iter().map(|(host, _)| host.clone()).collect();
    let federation = FederationService::new(
        units(),
        Arc::new(stores.clone()),
        Arc::new(stores.clone()),
        Arc::new(FakeSecretBox),
        clock.clone(),
    )
    .allowing_development_hosts(&hosts)
    .allowing_directory_hosts(&hosts);
    let openid = OpenIdClient::new(
        Arc::new(provider.clone()),
        Arc::new(AwsLcVerifier),
        digest.clone(),
        Arc::new(SequentialRandom::default()),
        clock.clone(),
    );
    let github = FakeGitHub::default();
    let external = ExternalSignIn::new(
        federation.clone(),
        openid,
        GitHubClient::new(
            Arc::new(github.clone()),
            Arc::new(SequentialRandom::default()),
        ),
        identity.clone(),
        Arc::new(stores),
        units(),
        Arc::new(FakeSecretBox),
        digest.clone(),
        clock.clone(),
        PUBLIC,
    );
    let external = match directory {
        Some((_, client)) => {
            external.with_directories(client, guard.clone(), Arc::new(FiveAttempts))
        }
        None => external,
    };

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
        github,
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
        json!({ "providers": [{ "alias": "example", "display_name": "Example", "kind": "openid_connect" }] }),
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

impl World {
    /// Adds a provider of the kind GitHub to acme.
    async fn with_github(&self) {
        self.federation
            .create_provider(
                &self.acme,
                CreateProvider {
                    alias: "github".to_owned(),
                    kind: ProviderKind::GitHub,
                    settings: ProviderSettings {
                        display_name: "GitHub".to_owned(),
                        issuer: "https://github.com".to_owned(),
                        client_id: "github-client".to_owned(),
                        scopes: ProviderSettings::default_scopes_for(ProviderKind::GitHub),
                        creates_users: true,
                        trusts_email: false,
                        directory: None,
                    },
                    client_secret: Secret::from(CLIENT_SECRET.to_owned()),
                },
                Caller::system(),
            )
            .await
            .expect("provider");
    }

    /// One whole sign-in through GitHub with this code.
    async fn sign_in_with_github(&self, code: &str) -> (Browser, Reply) {
        let mut browser = Browser::default();
        browser
            .send(self, Method::POST, "/t/acme/interaction/sign-in", None)
            .await;
        let chosen = browser
            .send(
                self,
                Method::POST,
                "/t/acme/interaction/sign-in/providers/github",
                None,
            )
            .await;
        assert_eq!(chosen.status, StatusCode::OK, "{:?}", chosen.body);
        let redirect = chosen.body["redirect"].as_str().expect("an address");
        let (address, query) = redirect.split_once('?').expect("a query");
        assert_eq!(address, "https://github.com/login/oauth/authorize");
        let sent: HashMap<String, String> = form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        assert_eq!(sent["client_id"], "github-client");
        assert_eq!(sent["scope"], "read:user user:email");
        assert_eq!(
            sent["redirect_uri"],
            format!("{PUBLIC}/t/acme/account/providers/github/callback")
        );
        let state = sent["state"].clone();
        assert_eq!(state.len(), 64);
        let reply = browser
            .come_back(self, "acme", "github", code, &state)
            .await;
        (browser, reply)
    }
}

#[tokio::test]
async fn a_person_signs_in_through_github_by_their_number_and_their_verified_address() {
    let world = world().await;
    world.with_github().await;
    world.github.is(
        json!({ "id": 583_231, "login": "octocat", "name": "The Octocat", "email": "shown@example.com" }),
        json!([
            { "email": "old@example.com", "primary": false, "verified": true },
            { "email": "unchecked@example.com", "primary": true, "verified": false },
            { "email": "octocat@example.com", "primary": true, "verified": true },
        ]),
    );

    let (mut browser, reply) = world.sign_in_with_github("github-code").await;
    assert_eq!(reply.sign_in_status(), "completed", "{:?}", reply.body);

    // Created with the address that is both primary and verified, not
    // the one in the profile and not an unverified one.
    let user = world
        .identity
        .find_by_login(&world.acme, "octocat@example.com")
        .await
        .expect("find")
        .expect("created");
    assert_eq!(
        user.snapshot().profile.display_name.as_deref(),
        Some("The Octocat")
    );
    for other in [
        "shown@example.com",
        "unchecked@example.com",
        "old@example.com",
    ] {
        assert_eq!(world.user_with(other).await, None, "{other}");
    }
    // Linked by the number, never by the login name.
    let links = world
        .federation
        .links_of(&world.acme, user.id())
        .await
        .expect("links");
    assert_eq!(links[0].subject.expose(), "583231");
    let session = browser.who(&world, "acme").await;
    assert_eq!(session.body["user_id"], user.id().to_string());

    // The person renames themself at GitHub: still the same user here.
    world.github.is(
        json!({ "id": 583_231, "login": "renamed", "name": "Another Name" }),
        json!([{ "email": "other@example.com", "primary": true, "verified": true }]),
    );
    let (mut again, reply) = world.sign_in_with_github("github-code").await;
    assert_eq!(reply.sign_in_status(), "completed");
    assert_eq!(
        again.who(&world, "acme").await.body["user_id"],
        user.id().to_string()
    );
    assert_eq!(world.count("identity.user_created"), 1);

    // The client secret went to GitHub's token address and nowhere else.
    for request in world.github.requests() {
        let body =
            String::from_utf8_lossy(request.body.as_deref().unwrap_or_default()).into_owned();
        assert_eq!(
            body.contains("client_secret"),
            request.url.ends_with("/login/oauth/access_token"),
            "{}",
            request.url
        );
    }
}

#[tokio::test]
async fn github_signs_nobody_in_without_a_good_code_a_number_or_a_verified_address() {
    let world = world().await;
    world.with_github().await;
    let octocat = json!({ "id": 583_231, "login": "octocat" });
    let verified = json!([{ "email": "octocat@example.com", "primary": true, "verified": true }]);

    // A code GitHub refuses, which it does with status 200.
    world.github.is(octocat.clone(), verified.clone());
    let (_, reply) = world.sign_in_with_github("a-code-of-someone-else").await;
    rejected(&reply);

    // No address that is both primary and verified.
    world.github.is(
        octocat.clone(),
        json!([{ "email": "octocat@example.com", "primary": true, "verified": false }]),
    );
    let (_, reply) = world.sign_in_with_github("github-code").await;
    rejected(&reply);
    world.github.is(octocat, json!({ "message": "Not Found" }));
    let (_, reply) = world.sign_in_with_github("github-code").await;
    rejected(&reply);

    // An answer that does not say who the person is by number.
    for user in [
        json!({ "login": "octocat" }),
        json!({ "id": "583231" }),
        json!([]),
    ] {
        world.github.is(user, verified.clone());
        let (_, reply) = world.sign_in_with_github("github-code").await;
        rejected(&reply);
    }

    assert_eq!(world.count("identity.user_created"), 0);
    assert_eq!(
        world.refusals(),
        [
            "answer_refused",
            "no_vouched_email",
            "no_vouched_email",
            "answer_refused",
            "answer_refused",
            "answer_refused"
        ]
    );
}

#[tokio::test]
async fn github_does_not_open_an_account_that_exists_with_the_same_address() {
    let world = world().await;
    world.with_github().await;
    let ana = world.ana_with_a_password().await;
    world.github.is(
        json!({ "id": 99, "login": "not-ana" }),
        json!([{ "email": "ana@example.com", "primary": true, "verified": true }]),
    );

    let (_, reply) = world.sign_in_with_github("github-code").await;

    rejected(&reply);
    assert_eq!(world.refusals(), ["email_belongs_to_a_user"]);
    assert!(
        world
            .federation
            .links_of(&world.acme, ana)
            .await
            .expect("links")
            .is_empty()
    );
}

#[tokio::test]
async fn a_provider_trusted_with_addresses_creates_people_it_does_not_vouch_for_and_opens_no_account()
 {
    let world = world().await;
    let ana = world.ana_with_a_password().await;
    let mut trusting = settings(true);
    trusting.trusts_email = true;
    world
        .federation
        .change_provider(
            &world.acme,
            hodor_federation::api::ChangeProvider {
                id: world.example,
                settings: trusting,
            },
            Caller::system(),
        )
        .await
        .expect("change");

    // The provider gives an address and does not say it vouches: created.
    let (_, reply) = world
        .sign_in("subject-of-bia", Some(("bia@example.com", false)))
        .await;
    assert_eq!(reply.sign_in_status(), "completed", "{:?}", reply.body);
    assert!(world.user_with("bia@example.com").await.is_some());

    // No address at all still creates nobody.
    let (_, reply) = world.sign_in("subject-of-carla", None).await;
    rejected(&reply);

    // And trust in addresses never opens an account that exists.
    let (_, reply) = world
        .sign_in("subject-of-a-stranger", Some(("ana@example.com", false)))
        .await;
    rejected(&reply);
    assert!(
        world
            .federation
            .links_of(&world.acme, ana)
            .await
            .expect("links")
            .is_empty()
    );
    assert_eq!(
        world.refusals(),
        ["no_vouched_email", "email_belongs_to_a_user"]
    );
}

/// The lockout policy of these tests: five failures in fifteen minutes.
struct FiveAttempts;

#[async_trait::async_trait]
impl LockoutPolicy for FiveAttempts {
    async fn rules(&self, _tenant: &TenantContext) -> Result<LockoutRules, DomainError> {
        Ok(LockoutRules {
            max_failures: 5,
            window: Duration::minutes(15),
            first_lockout: Duration::minutes(1),
            longest_lockout: Duration::hours(1),
        })
    }
}

/// The real directory client, counting the questions it is asked.
struct Counting {
    inner: LdapDirectoryClient,
    asked: Arc<std::sync::atomic::AtomicUsize>,
    filters: Arc<Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl DirectoryClient for Counting {
    async fn verify(
        &self,
        query: &DirectoryQuery,
        password: &Secret<String>,
    ) -> Result<DirectoryAnswer, DomainError> {
        self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.filters
            .lock()
            .expect("filters")
            .push(query.filter.clone());
        self.inner.verify(query, password).await
    }
}

const ANA_IN_DIRECTORY: Person<'static> = Person {
    uid: "ana",
    name: "Ana Example",
    email: "ana@example.com",
    password: "the directory password of ana",
};

struct DirectoryWorld {
    world: World,
    directory: TestDirectory,
    asked: Arc<std::sync::atomic::AtomicUsize>,
    filters: Arc<Mutex<Vec<String>>>,
}

/// A world with a real directory holding ana and bia, offered by acme as
/// the provider `company`.
async fn directory_world(trusts_email: bool) -> DirectoryWorld {
    let directory = TestDirectory::start().await;
    directory.add(&ANA_IN_DIRECTORY).await;
    directory
        .add(&Person {
            uid: "bia",
            name: "Bia Example",
            email: "bia@example.com",
            password: "the directory password of bia",
        })
        .await;
    let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let filters = Arc::new(Mutex::new(Vec::new()));
    let client = Counting {
        inner: LdapDirectoryClient::new(std::slice::from_ref(&directory.host)),
        asked: asked.clone(),
        filters: filters.clone(),
    };
    let world = world_with(Some((directory.host.clone(), Arc::new(client)))).await;
    world
        .federation
        .create_provider(
            &world.acme,
            CreateProvider {
                alias: "company".to_owned(),
                kind: ProviderKind::Ldap,
                settings: ProviderSettings {
                    display_name: "Company directory".to_owned(),
                    issuer: directory.address.clone(),
                    client_id: BIND_NAME.to_owned(),
                    scopes: Vec::new(),
                    creates_users: true,
                    trusts_email,
                    directory: Some(DirectorySettings::new(BASE, "(uid={identifier})")),
                },
                client_secret: Secret::from(BIND_PASSWORD.to_owned()),
            },
            Caller::system(),
        )
        .await
        .expect("the directory provider");
    DirectoryWorld {
        world,
        directory,
        asked,
        filters,
    }
}

impl DirectoryWorld {
    fn asked(&self) -> usize {
        self.asked.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Signs in through the directory with what a person typed.
    async fn sign_in(&self, browser: &mut Browser, identifier: &str, password: &str) -> Reply {
        if !browser.cookies.contains_key("__Secure-hodor_signin") {
            browser
                .send(
                    &self.world,
                    Method::POST,
                    "/t/acme/interaction/sign-in",
                    None,
                )
                .await;
        }
        browser
            .send(
                &self.world,
                Method::POST,
                "/t/acme/interaction/sign-in/providers/company/password",
                Some(json!({ "identifier": identifier, "password": password })),
            )
            .await
    }
}

#[tokio::test]
async fn a_person_signs_in_through_the_directory_and_is_the_same_user_every_time() {
    let setup = directory_world(true).await;
    let world = &setup.world;

    // The page learns the provider is a directory, to ask for a password.
    let mut browser = Browser::default();
    let offered = browser
        .send(
            world,
            Method::GET,
            "/t/acme/interaction/sign-in/providers",
            None,
        )
        .await;
    assert_eq!(
        offered.body["providers"][0],
        json!({ "alias": "company", "display_name": "Company directory", "kind": "ldap" })
    );

    let reply = setup
        .sign_in(&mut browser, "ana", ANA_IN_DIRECTORY.password)
        .await;
    assert_eq!(reply.sign_in_status(), "completed", "{:?}", reply.body);
    let session = browser.who(world, "acme").await;
    assert_eq!(session.body["methods"], json!(["external"]));

    let ana = world
        .identity
        .find_by_login(&world.acme, "ana@example.com")
        .await
        .expect("find")
        .expect("created, the provider being trusted with addresses");
    assert_eq!(
        ana.snapshot().profile.display_name.as_deref(),
        Some("Ana Example")
    );
    // Linked by the directory's unchanging identifier of the entry.
    let links = world
        .federation
        .links_of(&world.acme, ana.id())
        .await
        .expect("links");
    assert_eq!(links[0].subject.expose().len(), 36);

    // The directory changes her address: still the same user here.
    setup
        .directory
        .change_email("ana", "ana.renamed@example.com")
        .await;
    let mut again = Browser::default();
    let reply = setup
        .sign_in(&mut again, "ana", ANA_IN_DIRECTORY.password)
        .await;
    assert_eq!(reply.sign_in_status(), "completed");
    assert_eq!(
        again.who(world, "acme").await.body["user_id"],
        ana.id().to_string()
    );
    assert_eq!(world.count("identity.user_created"), 1);
}

#[tokio::test]
async fn every_refusal_of_the_directory_is_answered_alike() {
    let setup = directory_world(true).await;
    for (identifier, password, reason) in [
        ("ana", "a wrong password", "wrong_password"),
        ("ana", "the directory password of bia", "wrong_password"),
        ("nobody", "the directory password of ana", "not_found"),
        // A filter cannot be widened or closed by what is typed: these
        // are looked for as they are, and are nobody.
        ("*", "the directory password of ana", "not_found"),
        ("ana)(uid=*", "the directory password of ana", "not_found"),
        ("a*", "the directory password of ana", "not_found"),
        // An anonymous bind would succeed: the directory is not even asked.
        ("ana", "", "empty_password"),
    ] {
        let mut browser = Browser::default();
        let reply = setup.sign_in(&mut browser, identifier, password).await;
        rejected(&reply);
        assert_eq!(
            setup.world.refusals().last().map(String::as_str),
            Some(reason),
            "{identifier}"
        );
    }
    assert_eq!(setup.world.count("identity.user_created"), 0);
    // What was typed reached the directory only escaped.
    let filters = setup.filters.lock().expect("filters").clone();
    assert!(filters.contains(&"(uid=\\2a)".to_owned()), "{filters:?}");
    assert!(
        filters.contains(&"(uid=ana\\29\\28uid=\\2a)".to_owned()),
        "{filters:?}"
    );
    assert!(!filters.iter().any(|filter| filter.contains("(uid=*)")));
    assert_eq!(setup.asked(), 6, "the empty password was never asked about");
}

#[tokio::test]
async fn attempts_through_the_directory_are_limited_before_it_is_asked() {
    let setup = directory_world(true).await;
    for _ in 0..5 {
        let mut browser = Browser::default();
        rejected(&setup.sign_in(&mut browser, "ana", "a wrong guess").await);
    }
    assert_eq!(setup.asked(), 5);

    // Locked out: even the right password is refused, and the directory
    // is not asked.
    let mut browser = Browser::default();
    let locked = setup
        .sign_in(&mut browser, "ana", ANA_IN_DIRECTORY.password)
        .await;
    assert_eq!(
        locked.status,
        StatusCode::TOO_MANY_REQUESTS,
        "{:?}",
        locked.body
    );
    assert_eq!(locked.code(), "authentication.too_many_attempts");
    assert_eq!(setup.asked(), 5);

    // Somebody else is not locked out by it.
    let mut other = Browser::default();
    let reply = setup
        .sign_in(&mut other, "bia", "the directory password of bia")
        .await;
    assert_eq!(reply.sign_in_status(), "completed");
}

#[tokio::test]
async fn a_directory_does_not_vouch_for_addresses_unless_its_provider_is_trusted() {
    let setup = directory_world(false).await;
    let mut browser = Browser::default();
    let reply = setup
        .sign_in(&mut browser, "ana", ANA_IN_DIRECTORY.password)
        .await;
    rejected(&reply);
    assert_eq!(setup.world.refusals(), ["no_vouched_email"]);
    assert_eq!(setup.world.count("identity.user_created"), 0);
}

#[tokio::test]
async fn a_directory_does_not_open_an_account_that_exists_with_the_same_address() {
    let setup = directory_world(true).await;
    let ana = setup.world.ana_with_a_password().await;
    let mut browser = Browser::default();
    let reply = setup
        .sign_in(&mut browser, "ana", ANA_IN_DIRECTORY.password)
        .await;
    rejected(&reply);
    assert_eq!(setup.world.refusals(), ["email_belongs_to_a_user"]);
    assert!(
        setup
            .world
            .federation
            .links_of(&setup.world.acme, ana)
            .await
            .expect("links")
            .is_empty()
    );
}

#[tokio::test]
async fn a_directory_is_not_left_for_and_another_provider_takes_no_password() {
    let setup = directory_world(true).await;
    let world = &setup.world;
    let mut browser = Browser::default();
    browser
        .send(world, Method::POST, "/t/acme/interaction/sign-in", None)
        .await;
    let left = browser
        .send(
            world,
            Method::POST,
            "/t/acme/interaction/sign-in/providers/company",
            None,
        )
        .await;
    assert_eq!(left.status, StatusCode::NOT_FOUND);
    assert_eq!(left.code(), "federation.provider_not_found");

    let reply = browser
        .send(
            world,
            Method::POST,
            "/t/acme/interaction/sign-in/providers/example/password",
            Some(json!({ "identifier": "ana", "password": "x" })),
        )
        .await;
    rejected(&reply);
    assert_eq!(world.refusals(), ["another_kind"]);
    assert_eq!(setup.asked(), 0);
}

#[tokio::test]
async fn a_directory_that_is_not_on_the_list_cannot_be_added() {
    let world = world().await;
    let refused = world
        .federation
        .create_provider(
            &world.acme,
            CreateProvider {
                alias: "elsewhere".to_owned(),
                kind: ProviderKind::Ldap,
                settings: ProviderSettings {
                    display_name: "Somewhere".to_owned(),
                    issuer: "ldaps://ldap.internal.example:636".to_owned(),
                    client_id: BIND_NAME.to_owned(),
                    scopes: Vec::new(),
                    creates_users: true,
                    trusts_email: false,
                    directory: Some(DirectorySettings::new(BASE, "(uid={identifier})")),
                },
                client_secret: Secret::from(BIND_PASSWORD.to_owned()),
            },
            Caller::system(),
        )
        .await
        .expect_err("not on the list");
    assert_eq!(refused.code(), "federation.directory_not_allowed");
}
