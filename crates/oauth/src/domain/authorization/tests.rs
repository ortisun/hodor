//! The rules of the authorization endpoint, case by case.

use super::*;
use crate::domain::application::{Application, ApplicationSettings, Status};
use crate::domain::client::{ClientSettings, ClientType};
use crate::domain::resource_server::{Audience, ResourceServerSettings, ScopeDefinition};
use crate::domain::secret::ClientSecret;
use hodor_kernel::random::testing::FakeDigest;

const REDIRECT: &str = "https://payroll.example.com/callback";
const AUDIENCE: &str = "https://api.payroll.example.com";
const MOMENT: Timestamp = Timestamp::UNIX_EPOCH;
const ISSUER: &str = "https://hodor.example.com/t/acme";

fn objects() -> RequestObjectCheck<'static> {
    RequestObjectCheck {
        keys: &[],
        issuer: ISSUER,
        now: MOMENT,
        verifier: &crate::testing::FakeVerifier,
    }
}

/// Different bytes on every call.
struct Counting(std::sync::atomic::AtomicU8);

impl RandomSource for Counting {
    fn fill(&self, buffer: &mut [u8]) {
        let seed = self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = seed.wrapping_add(u8::try_from(index % 256).unwrap_or(0));
        }
    }
}

fn random() -> Counting {
    Counting(std::sync::atomic::AtomicU8::new(1))
}

fn application(first_party: bool) -> Application {
    Application::create(
        ApplicationSettings {
            name: "Payroll".to_owned(),
            first_party,
        },
        MOMENT,
    )
    .expect("application")
}

fn client_of(application: &Application, client_type: ClientType) -> Client {
    let mut settings = ClientSettings::new(
        "Payroll web",
        client_type,
        vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        vec![
            REDIRECT.to_owned(),
            "https://payroll.example.com/other?x=1".to_owned(),
        ],
    );
    settings.allowed_scopes = vec![
        "openid".to_owned(),
        "email".to_owned(),
        "read".to_owned(),
        "write".to_owned(),
        "unknown".to_owned(),
    ];
    Client::create(
        application.id(),
        client_type,
        settings,
        ClientSecret::DEFAULT_LIFETIME,
        MOMENT,
        &random(),
        &FakeDigest,
    )
    .expect("client")
    .0
}

fn server(application: &Application, audience: &str, scopes: &[&str]) -> ResourceServer {
    ResourceServer::create(
        application.id(),
        Audience::parse(audience).expect("audience"),
        ResourceServerSettings {
            name: "Payroll interface".to_owned(),
            scopes: scopes
                .iter()
                .map(|name| ScopeDefinition {
                    name: (*name).to_owned(),
                    description: String::new(),
                })
                .collect(),
        },
        MOMENT,
    )
    .expect("server")
}

struct Setting {
    application: Application,
    client: Client,
    servers: Vec<ResourceServer>,
}

fn setting() -> Setting {
    let application = application(true);
    let client = client_of(&application, ClientType::Public);
    let servers = vec![server(&application, AUDIENCE, &["read", "write"])];
    Setting {
        application,
        client,
        servers,
    }
}

/// Parameters as name and value pairs.
type Pairs = Vec<(String, String)>;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn good(client: &Client) -> Vec<(String, String)> {
    [
        ("response_type", "code"),
        ("client_id", &client.id().to_string()),
        ("redirect_uri", REDIRECT),
        ("scope", "openid read"),
        ("state", "xyz"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
    .collect()
}

fn with(
    mut pairs: Vec<(String, String)>,
    name: &str,
    value: Option<&str>,
) -> Vec<(String, String)> {
    pairs.retain(|(key, _)| key != name);
    if let Some(value) = value {
        pairs.push((name.to_owned(), value.to_owned()));
    }
    pairs
}

fn check(
    setting: &Setting,
    pairs: Vec<(String, String)>,
) -> Result<AuthorizationRequest, AuthorizationRefusal> {
    check_request(
        &AuthorizationParameters::from_pairs(pairs),
        Some(&setting.client),
        Some(&setting.application),
        &setting.servers,
        objects(),
        false,
    )
}

fn error_of(result: Result<AuthorizationRequest, AuthorizationRefusal>) -> &'static str {
    match result {
        Err(AuthorizationRefusal::Redirect(error)) => {
            assert_eq!(error.redirect_uri, REDIRECT);
            error.error
        }
        other => panic!("expected an error at the redirect address, got {other:?}"),
    }
}

fn page_of(result: Result<AuthorizationRequest, AuthorizationRefusal>) -> &'static str {
    match result {
        Err(AuthorizationRefusal::NotRedirectable(code)) => code,
        other => panic!("expected Hodor's own page, got {other:?}"),
    }
}

#[test]
fn a_good_request_is_accepted_with_what_it_asked_for() {
    let setting = setting();
    let request = check(&setting, good(&setting.client)).expect("accepted");
    assert_eq!(request.client_id, setting.client.id());
    assert_eq!(request.redirect_uri, REDIRECT);
    assert_eq!(request.scopes, ["openid", "read"]);
    assert_eq!(request.audiences, [AUDIENCE]);
    assert_eq!(request.code_challenge.as_deref(), Some(CHALLENGE));
    assert_eq!(request.state.as_deref(), Some("xyz"));
}

#[test]
fn a_client_that_must_push_its_requests_is_refused_without_one() {
    let setting = setting();
    let refused = |pairs: Vec<(String, String)>| {
        check_request(
            &AuthorizationParameters::from_pairs(pairs),
            Some(&setting.client),
            Some(&setting.application),
            &setting.servers,
            objects(),
            true,
        )
    };
    let result = refused(good(&setting.client));
    match &result {
        Err(AuthorizationRefusal::Redirect(error)) => {
            assert_eq!(
                error.description,
                "this client must push its authorization requests"
            );
            assert_eq!(error.state.as_deref(), Some("xyz"));
        }
        other => panic!("expected an error at the redirect address, got {other:?}"),
    }
    assert_eq!(error_of(result), "invalid_request");
    // Until its address is trusted, nothing is sent there.
    assert_eq!(
        page_of(refused(with(
            good(&setting.client),
            "redirect_uri",
            Some("https://elsewhere.example.com/callback")
        ))),
        "oauth.authorization_redirect_uri_unregistered"
    );
    // The same request is accepted when nothing requires it.
    assert!(check(&setting, good(&setting.client)).is_ok());
}

#[test]
fn nothing_is_sent_to_an_address_that_is_not_trusted() {
    let setting = setting();
    let unknown = "oauth.authorization_client_unknown";
    // No client, a malformed one, one given twice, one of no store.
    assert_eq!(
        page_of(check(
            &setting,
            with(good(&setting.client), "client_id", None)
        )),
        unknown
    );
    assert_eq!(
        page_of(check(
            &setting,
            with(good(&setting.client), "client_id", Some("x"))
        )),
        unknown
    );
    let mut twice = good(&setting.client);
    twice.push(("client_id".to_owned(), setting.client.id().to_string()));
    assert_eq!(page_of(check(&setting, twice)), unknown);
    assert_eq!(
        page_of(check_request(
            &AuthorizationParameters::from_pairs(good(&setting.client)),
            None,
            None,
            &[],
            objects(),
            false,
        )),
        unknown,
        "a client of another tenant is not found here"
    );

    // A disabled client, a disabled application.
    let mut disabled = setting.client.clone();
    disabled.set_status(Status::Disabled, MOMENT);
    let result = check_request(
        &AuthorizationParameters::from_pairs(good(&setting.client)),
        Some(&disabled),
        Some(&setting.application),
        &setting.servers,
        objects(),
        false,
    );
    assert_eq!(page_of(result), unknown);
    let mut application = setting.application.clone();
    application.set_status(Status::Disabled, MOMENT);
    let result = check_request(
        &AuthorizationParameters::from_pairs(good(&setting.client)),
        Some(&setting.client),
        Some(&application),
        &setting.servers,
        objects(),
        false,
    );
    assert_eq!(page_of(result), unknown);

    // The redirect address: missing, twice, not registered, close but
    // not equal.
    let missing = "oauth.authorization_redirect_uri_missing";
    let unregistered = "oauth.authorization_redirect_uri_unregistered";
    assert_eq!(
        page_of(check(
            &setting,
            with(good(&setting.client), "redirect_uri", None)
        )),
        missing
    );
    let mut twice = good(&setting.client);
    twice.push(("redirect_uri".to_owned(), REDIRECT.to_owned()));
    assert_eq!(page_of(check(&setting, twice)), missing);
    for near in [
        "https://attacker.example/callback",
        "https://payroll.example.com/callback/",
        "https://PAYROLL.example.com/callback",
        "https://payroll.example.com/callback?x=1",
        "https://payroll.example.com:443/callback",
        "https://payroll.example.com/other",
    ] {
        assert_eq!(
            page_of(check(
                &setting,
                with(good(&setting.client), "redirect_uri", Some(near))
            )),
            unregistered,
            "{near}"
        );
    }
}

#[test]
fn every_malformed_request_is_refused_for_its_own_reason() {
    let setting = setting();
    let base = good(&setting.client);
    let cases: Vec<(&str, Pairs, &str)> = vec![
        (
            "no response type",
            with(base.clone(), "response_type", None),
            "invalid_request",
        ),
        (
            "a token response type, for a client that is not marked",
            with(base.clone(), "response_type", Some("token")),
            "unauthorized_client",
        ),
        (
            "a response type of OAuth that OpenID Connect does not define",
            with(base.clone(), "response_type", Some("device_code")),
            "unsupported_response_type",
        ),
        (
            "a hybrid response type the client did not register",
            with(base.clone(), "response_type", Some("code id_token")),
            "unauthorized_client",
        ),
        (
            "an unknown response type",
            with(base.clone(), "response_type", Some("code code")),
            "unsupported_response_type",
        ),
        (
            "a response mode not offered",
            with(base.clone(), "response_mode", Some("form_post.jwt")),
            "invalid_request",
        ),
        (
            "a request object that is not one",
            with(base.clone(), "request", Some("eyJ")),
            "invalid_request_object",
        ),
        (
            "a reference beside the request it would name",
            with(base.clone(), "request_uri", Some("urn:x")),
            "invalid_request",
        ),
        (
            "no challenge from a public client",
            with(base.clone(), "code_challenge", None),
            "invalid_request",
        ),
        (
            "the plain method",
            with(base.clone(), "code_challenge_method", Some("plain")),
            "invalid_request",
        ),
        (
            "a challenge without a method",
            with(base.clone(), "code_challenge_method", None),
            "invalid_request",
        ),
        (
            "a short challenge",
            with(base.clone(), "code_challenge", Some("abc")),
            "invalid_request",
        ),
        (
            "a challenge that is not base64url",
            with(base.clone(), "code_challenge", Some(&"+".repeat(43))),
            "invalid_request",
        ),
        (
            "a long state",
            with(base.clone(), "state", Some(&"s".repeat(1025))),
            "invalid_request",
        ),
        (
            "a long nonce",
            with(base.clone(), "nonce", Some(&"n".repeat(1025))),
            "invalid_request",
        ),
        (
            "an unknown prompt",
            with(base.clone(), "prompt", Some("sometimes")),
            "invalid_request",
        ),
        (
            "none with another prompt",
            with(base.clone(), "prompt", Some("none login")),
            "invalid_request",
        ),
        (
            "a negative max_age",
            with(base.clone(), "max_age", Some("-1")),
            "invalid_request",
        ),
        (
            "a max_age with a sign",
            with(base.clone(), "max_age", Some("+5")),
            "invalid_request",
        ),
        (
            "a max_age over a year",
            with(base.clone(), "max_age", Some("31536001")),
            "invalid_request",
        ),
        (
            "a long login hint",
            with(base.clone(), "login_hint", Some(&"h".repeat(256))),
            "invalid_request",
        ),
        (
            "no scope",
            with(base.clone(), "scope", None),
            "invalid_scope",
        ),
        (
            "a scope the client may not ask for",
            with(base.clone(), "scope", Some("openid admin")),
            "invalid_scope",
        ),
        (
            "a scope nobody defines",
            with(base.clone(), "scope", Some("unknown")),
            "invalid_scope",
        ),
        (
            "a resource that is not absolute",
            with(base.clone(), "resource", Some("api")),
            "invalid_target",
        ),
        (
            "a resource with a fragment",
            with(
                base.clone(),
                "resource",
                Some("https://api.payroll.example.com#x"),
            ),
            "invalid_target",
        ),
        (
            "a resource of nobody",
            with(
                base.clone(),
                "resource",
                Some("https://elsewhere.example.com"),
            ),
            "invalid_target",
        ),
    ];
    for (name, pairs, expected) in cases {
        assert_eq!(error_of(check(&setting, pairs)), expected, "{name}");
    }

    let mut twice = base.clone();
    twice.push(("scope".to_owned(), "read".to_owned()));
    assert_eq!(
        error_of(check(&setting, twice)),
        "invalid_request",
        "a repeated parameter"
    );

    let mut many = base;
    for _ in 0..11 {
        many.push(("resource".to_owned(), AUDIENCE.to_owned()));
    }
    assert_eq!(
        error_of(check(&setting, many)),
        "invalid_target",
        "eleven resources"
    );
}

#[test]
fn the_state_goes_back_with_an_error_when_it_can_be_read() {
    let setting = setting();
    match check(
        &setting,
        with(good(&setting.client), "response_type", Some("token")),
    ) {
        Err(AuthorizationRefusal::Redirect(error)) => {
            assert_eq!(error.state.as_deref(), Some("xyz"))
        }
        other => panic!("{other:?}"),
    }
    match check(
        &setting,
        with(good(&setting.client), "state", Some(&"s".repeat(1025))),
    ) {
        Err(AuthorizationRefusal::Redirect(error)) => assert_eq!(error.state, None),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_request_is_answered_in_the_mode_it_names_or_in_the_query() {
    let setting = setting();
    let base = good(&setting.client);
    let named = |mode: Option<&str>| {
        check(&setting, with(base.clone(), "response_mode", mode))
            .expect("accepted")
            .response_mode
    };
    assert_eq!(named(None), ResponseMode::Query);
    assert_eq!(named(Some("query")), ResponseMode::Query);
    assert_eq!(named(Some("form_post")), ResponseMode::FormPost);
    assert_eq!(named(Some("fragment")), ResponseMode::Fragment);
}

#[test]
fn a_mode_hodor_does_not_offer_is_refused_in_the_mode_of_the_type() {
    let setting = setting();
    let base = good(&setting.client);
    for mode in ["jwt", "query.jwt", "form_post.jwt", "FORM_POST", "anything"] {
        match check(&setting, with(base.clone(), "response_mode", Some(mode))) {
            Err(AuthorizationRefusal::Redirect(error)) => {
                assert_eq!(error.error, "invalid_request", "{mode}");
                assert_eq!(
                    error.description, "the response modes are query, fragment and form_post",
                    "{mode}"
                );
                assert_eq!(error.mode, ResponseMode::Query, "{mode}");
                assert_eq!(error.state.as_deref(), Some("xyz"));
            }
            other => panic!("{mode}: {other:?}"),
        }
    }
    // Given twice, it is refused like any parameter given twice.
    let mut twice = base;
    twice.push(("response_mode".to_owned(), "form_post".to_owned()));
    twice.push(("response_mode".to_owned(), "query".to_owned()));
    assert_eq!(error_of(check(&setting, twice)), "invalid_request");
}

#[test]
fn every_error_after_the_address_is_trusted_comes_in_the_mode_asked_for() {
    let setting = setting();
    let form_post = with(good(&setting.client), "response_mode", Some("form_post"));
    let cases: Vec<(&str, Pairs, &str)> = vec![
        (
            "a type Hodor does not answer",
            with(form_post.clone(), "response_type", Some("token token")),
            "unsupported_response_type",
        ),
        (
            "a type that returns an access token, for a client that is not marked",
            with(form_post.clone(), "response_type", Some("token")),
            "unauthorized_client",
        ),
        (
            "no type",
            with(form_post.clone(), "response_type", None),
            "invalid_request",
        ),
        (
            "a scope the client may not ask for",
            with(form_post.clone(), "scope", Some("openid admin")),
            "invalid_scope",
        ),
        (
            "a plain challenge",
            with(form_post.clone(), "code_challenge_method", Some("plain")),
            "invalid_request",
        ),
        (
            "an unknown prompt",
            with(form_post, "prompt", Some("always")),
            "invalid_request",
        ),
    ];
    for (case, pairs, expected) in cases {
        match check(&setting, pairs) {
            Err(AuthorizationRefusal::Redirect(error)) => {
                assert_eq!(error.error, expected, "{case}");
                assert_eq!(error.mode, ResponseMode::FormPost, "{case}");
                assert_eq!(error.state.as_deref(), Some("xyz"), "{case}");
            }
            other => panic!("{case}: {other:?}"),
        }
    }
    // Before the address is trusted, nothing goes to it in any mode.
    assert_eq!(
        page_of(check(
            &setting,
            with(
                with(good(&setting.client), "response_mode", Some("form_post")),
                "redirect_uri",
                Some("https://attacker.example/callback"),
            ),
        )),
        "oauth.authorization_redirect_uri_unregistered"
    );
}

#[test]
fn a_request_kept_before_response_modes_existed_reads_as_the_query() {
    let setting = setting();
    let request = check(
        &setting,
        with(good(&setting.client), "response_mode", Some("form_post")),
    )
    .expect("accepted");
    let mut written = serde_json::to_value(&request).expect("written");
    assert_eq!(written["response_mode"], "form_post");
    let read: AuthorizationRequest = serde_json::from_value(written.clone()).expect("read");
    assert_eq!(read.response_mode, ResponseMode::FormPost);
    written
        .as_object_mut()
        .expect("an object")
        .remove("response_mode");
    let read: AuthorizationRequest = serde_json::from_value(written).expect("read");
    assert_eq!(read.response_mode, ResponseMode::Query);
}

#[test]
fn parameters_without_a_value_are_as_if_omitted_and_unknown_ones_are_ignored() {
    let setting = setting();
    let mut pairs = good(&setting.client);
    pairs.push(("nonce".to_owned(), String::new()));
    pairs.push(("nonce".to_owned(), "n-1".to_owned()));
    pairs.push(("something_new".to_owned(), "x".to_owned()));
    let request = check(&setting, pairs).expect("accepted");
    assert_eq!(request.nonce.as_deref(), Some("n-1"));
}

#[test]
fn a_confidential_client_may_go_without_pkce_only_when_it_is_turned_off() {
    let application = application(true);
    let mut client = client_of(&application, ClientType::Confidential);
    let servers = vec![server(&application, AUDIENCE, &["read"])];
    let setting = Setting {
        application: application.clone(),
        client: client.clone(),
        servers: servers.clone(),
    };
    let pairs = with(
        with(good(&client), "code_challenge", None),
        "code_challenge_method",
        None,
    );
    assert_eq!(error_of(check(&setting, pairs.clone())), "invalid_request");

    let mut settings = client.snapshot().settings.clone();
    settings.require_pkce = false;
    client.change(settings, MOMENT).expect("changed");
    let setting = Setting {
        application,
        client,
        servers,
    };
    let request = check(&setting, pairs).expect("accepted without PKCE");
    assert_eq!(request.code_challenge, None);
}

#[test]
fn resources_decide_the_audiences_and_must_define_the_scopes() {
    let application = application(true);
    let client = client_of(&application, ClientType::Public);
    let other = crate::domain::application::Application::create(
        ApplicationSettings {
            name: "Mail".to_owned(),
            first_party: true,
        },
        MOMENT,
    )
    .expect("application");
    let servers = vec![
        server(&application, AUDIENCE, &["read"]),
        server(&other, "urn:example:mail", &["write"]),
    ];
    let setting = Setting {
        application,
        client,
        servers,
    };
    // Without resources: every resource server that defines a scope.
    let request = check(
        &setting,
        with(good(&setting.client), "scope", Some("read write")),
    )
    .expect("accepted");
    assert_eq!(request.audiences, [AUDIENCE, "urn:example:mail"]);

    // With a resource: only it, and its scopes only.
    let pairs = with(good(&setting.client), "resource", Some("urn:example:mail"));
    let request =
        check(&setting, with(pairs.clone(), "scope", Some("openid write"))).expect("accepted");
    assert_eq!(request.audiences, ["urn:example:mail"]);
    assert_eq!(
        error_of(check(&setting, with(pairs, "scope", Some("read")))),
        "invalid_scope",
        "read is not defined by the resource named"
    );

    // OpenID Connect scopes alone need no resource server.
    let request = check(
        &setting,
        with(good(&setting.client), "scope", Some("openid email")),
    )
    .expect("accepted");
    assert!(request.audiences.is_empty());
}

#[test]
fn a_request_says_whether_its_application_is_first_party() {
    for first_party in [true, false] {
        let application = application(first_party);
        let client = client_of(&application, ClientType::Public);
        let servers = vec![server(&application, AUDIENCE, &["read"])];
        let setting = Setting {
            application,
            client,
            servers,
        };
        let request = check(&setting, good(&setting.client)).expect("accepted");
        assert_eq!(request.first_party, first_party);
    }
}

#[test]
fn a_client_that_registered_itself_is_never_first_party() {
    let application = application(true);
    let client = client_of(&application, ClientType::Public)
        .registered_from(crate::domain::client::SelfRegistration { address_hash: None });
    let servers = vec![server(&application, AUDIENCE, &["read"])];
    let setting = Setting {
        application,
        client,
        servers,
    };
    let request = check(&setting, good(&setting.client)).expect("accepted");
    assert!(!request.first_party, "its person is always asked");
}

#[test]
fn a_request_kept_before_consent_existed_reads_as_third_party() {
    let setting = setting();
    let request = check(&setting, good(&setting.client)).expect("accepted");
    let mut written = serde_json::to_value(&request).expect("written");
    written
        .as_object_mut()
        .expect("an object")
        .remove("first_party");
    let read: AuthorizationRequest = serde_json::from_value(written).expect("read");
    assert!(!read.first_party);
}

fn person(signed_in_at: Timestamp) -> SignedInPerson {
    SignedInPerson {
        user_id: UserId::generate(),
        session_id: SessionId::generate(),
        signed_in_at,
        methods: vec!["password".to_owned()],
        acr: Some("urn:hodor:acr:single-factor".to_owned()),
    }
}

fn request_with(prompt: &[&str], max_age: Option<u32>) -> AuthorizationRequest {
    let setting = setting();
    let mut request = check(&setting, good(&setting.client)).expect("accepted");
    request.prompt = prompt.iter().map(|p| (*p).to_owned()).collect();
    request.max_age = max_age;
    request
}

fn proofs(ages_in_minutes: &[(&str, i64)], now: Timestamp) -> Vec<Proof> {
    ages_in_minutes
        .iter()
        .map(|(method, minutes)| Proof {
            method: (*method).to_owned(),
            proven_at: now - Duration::minutes(*minutes),
        })
        .collect()
}

fn methods(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

#[test]
fn the_session_decides_whether_the_person_signs_in_or_steps_up() {
    let password = methods(&["password"]);
    let issue = SessionDecision::Issue;
    let step_up = |carried: &[&str]| SessionDecision::StepUp {
        carried: methods(carried),
    };

    assert_eq!(
        request_with(&[], None).decide(false, &[], false),
        SessionDecision::SignIn
    );
    assert_eq!(request_with(&[], None).decide(true, &password, true), issue);
    assert_eq!(
        request_with(&["none"], None).decide(false, &[], false),
        SessionDecision::LoginRequired
    );
    assert_eq!(
        request_with(&["none"], None).decide(true, &password, true),
        issue
    );
    assert_eq!(
        request_with(&["login"], None).decide(true, &password, true),
        SessionDecision::SignIn
    );
    assert_eq!(
        request_with(&["select_account"], None).decide(true, &password, true),
        SessionDecision::SignIn
    );
    assert_eq!(
        request_with(&["consent"], None).decide(true, &password, true),
        issue
    );
    // Below the level asked for: only what is missing is asked.
    assert_eq!(
        request_with(&[], None).decide(true, &password, false),
        step_up(&["password"])
    );
    // Nothing counts any more, as with a stale session for `max_age`.
    assert_eq!(
        request_with(&[], Some(600)).decide(true, &[], true),
        step_up(&[])
    );
    // With `prompt=none` nobody is asked anything.
    assert_eq!(
        request_with(&["none"], None).decide(true, &password, false),
        SessionDecision::LoginRequired
    );
    assert_eq!(
        request_with(&["none"], Some(600)).decide(true, &[], true),
        SessionDecision::LoginRequired
    );
}

#[test]
fn with_max_age_only_the_methods_proven_within_it_count() {
    let now = MOMENT + Duration::hours(3);
    let session = proofs(&[("password", 120), ("webauthn", 1)], now);
    let names = |request: &AuthorizationRequest| -> Vec<String> {
        request
            .counting(&session, now, None)
            .iter()
            .map(|proof| proof.method.clone())
            .collect()
    };
    assert_eq!(
        names(&request_with(&[], None)),
        methods(&["password", "webauthn"])
    );
    assert_eq!(names(&request_with(&[], Some(600))), methods(&["webauthn"]));
    assert!(names(&request_with(&[], Some(30))).is_empty());
    assert_eq!(
        names(&request_with(&[], Some(7200))),
        methods(&["password", "webauthn"]),
        "proven exactly max_age seconds ago still counts"
    );
    // Proven after the request arrived: made for it, whatever max_age says.
    let received = now - Duration::minutes(2);
    let after: Vec<String> = request_with(&[], Some(0))
        .counting(&session, now, Some(received))
        .iter()
        .map(|proof| proof.method.clone())
        .collect();
    assert_eq!(after, methods(&["webauthn"]));
}

#[test]
fn after_signing_in_a_request_that_asked_for_a_new_sign_in_needs_one() {
    let received = MOMENT + Duration::hours(1);
    let before = received - Duration::minutes(5);
    let after = received + Duration::minutes(1);

    assert!(request_with(&[], None).signed_in_as_asked(before, received));
    assert!(!request_with(&["login"], None).signed_in_as_asked(before, received));
    assert!(request_with(&["login"], None).signed_in_as_asked(after, received));
    assert!(!request_with(&["select_account"], None).signed_in_as_asked(before, received));
}

#[test]
fn a_pending_request_belongs_to_the_browser_with_its_secret_for_ten_minutes() {
    let (pending, secret) =
        PendingAuthorization::hold(request_with(&[], None), MOMENT, &random(), &FakeDigest);
    assert_eq!(secret.expose().len(), 43);
    assert!(pending.belongs_to(secret.expose(), &FakeDigest));
    assert!(!pending.belongs_to("A".repeat(43).as_str(), &FakeDigest));
    assert!(!pending.belongs_to("", &FakeDigest));
    assert!(pending.is_live_at(MOMENT + Duration::minutes(9)));
    assert!(!pending.is_live_at(MOMENT + PENDING_LIFETIME));
    assert!(!format!("{secret:?}").contains(secret.expose()));
}

struct Issued {
    code: AuthorizationCode,
    value: CodeValue,
    verifier: String,
}

fn issued(with_challenge: bool) -> Issued {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_owned();
    let mut request = request_with(&[], None);
    request.code_challenge = with_challenge.then(|| s256_challenge(&verifier, &FakeDigest));
    let person = person(MOMENT);
    let grant = Grant::make(&request, &person, MOMENT);
    let (code, value) =
        AuthorizationCode::issue(&grant, &request, &person, MOMENT, &random(), &FakeDigest);
    Issued {
        code,
        value,
        verifier,
    }
}

#[test]
fn a_code_is_kept_only_as_its_hash_and_lives_sixty_seconds() {
    let issued = issued(true);
    assert_eq!(issued.value.expose().len(), 43);
    assert_eq!(
        CodeHash::of_presented(issued.value.expose(), &FakeDigest),
        Some(issued.code.hash)
    );
    assert_eq!(CodeHash::of_presented("short", &FakeDigest), None);
    assert_eq!(issued.code.expires_at, MOMENT + CODE_LIFETIME);
    assert!(!format!("{:?}", issued.code).contains(issued.value.expose()));
    assert!(!format!("{:?}", issued.value).contains(issued.value.expose()));
}

#[test]
fn a_code_is_redeemed_only_by_its_client_with_its_address_and_verifier() {
    let issued = issued(true);
    let code = &issued.code;
    let client_id = code.client_id;
    let right = CodePresentation {
        client_id,
        redirect_uri: Some(REDIRECT),
        verifier: Some(&issued.verifier),
    };
    let at = MOMENT + Duration::seconds(10);
    assert_eq!(code.check_redemption(right, at, &FakeDigest), Ok(()));

    let cases = [
        (
            CodePresentation {
                client_id: ClientId::generate(),
                ..right
            },
            CodeRefusal::OtherClient,
        ),
        (
            CodePresentation {
                redirect_uri: None,
                ..right
            },
            CodeRefusal::OtherRedirectUri,
        ),
        (
            CodePresentation {
                redirect_uri: Some("https://payroll.example.com/other?x=1"),
                ..right
            },
            CodeRefusal::OtherRedirectUri,
        ),
        (
            CodePresentation {
                verifier: None,
                ..right
            },
            CodeRefusal::VerifierMissing,
        ),
        (
            CodePresentation {
                verifier: Some("short"),
                ..right
            },
            CodeRefusal::VerifierMalformed,
        ),
        (
            CodePresentation {
                verifier: Some(&"a".repeat(43)),
                ..right
            },
            CodeRefusal::VerifierWrong,
        ),
    ];
    for (presentation, expected) in cases {
        assert_eq!(
            code.check_redemption(presentation, at, &FakeDigest),
            Err(expected)
        );
    }
    assert_eq!(
        code.check_redemption(right, MOMENT + CODE_LIFETIME, &FakeDigest),
        Err(CodeRefusal::Expired)
    );
    let mut redeemed = code.clone();
    redeemed.redeemed_at = Some(at);
    assert_eq!(
        redeemed.check_redemption(right, at, &FakeDigest),
        Err(CodeRefusal::AlreadyRedeemed)
    );
}

#[test]
fn a_verifier_for_a_code_without_a_challenge_is_refused() {
    let issued = issued(false);
    let presentation = CodePresentation {
        client_id: issued.code.client_id,
        redirect_uri: Some(REDIRECT),
        verifier: Some(&issued.verifier),
    };
    assert_eq!(
        issued
            .code
            .check_redemption(presentation, MOMENT, &FakeDigest),
        Err(CodeRefusal::VerifierWithoutChallenge)
    );
    assert_eq!(
        issued.code.check_redemption(
            CodePresentation {
                verifier: None,
                ..presentation
            },
            MOMENT,
            &FakeDigest
        ),
        Ok(())
    );
}

#[test]
fn a_grant_is_revoked_once() {
    let request = request_with(&[], None);
    let mut grant = Grant::make(&request, &person(MOMENT), MOMENT);
    assert!(grant.revoke("code_reused", MOMENT).is_some());
    assert_eq!(grant.status, GrantStatus::Revoked);
    assert_eq!(grant.revocation_reason.as_deref(), Some("code_reused"));
    assert!(grant.revoke("code_reused", MOMENT).is_none());
}

#[test]
fn the_s256_challenge_is_that_of_rfc_7636() {
    struct Sha256;
    impl Digest for Sha256 {
        fn sha256(&self, data: &[u8]) -> [u8; 32] {
            // The digest of the verifier of RFC 7636, appendix B.
            assert_eq!(data, b"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
            [
                0x13, 0xd3, 0x1e, 0x96, 0x1a, 0x1a, 0xd8, 0xec, 0x2f, 0x16, 0xb1, 0x0c, 0x4c, 0x98,
                0x2e, 0x08, 0x76, 0xa8, 0x78, 0xad, 0x6d, 0xf1, 0x44, 0x56, 0x6e, 0xe1, 0x89, 0x4a,
                0xcb, 0x70, 0xf9, 0xc3,
            ]
        }
        fn sha512(&self, _data: &[u8]) -> [u8; 64] {
            unreachable!("a challenge is SHA-256")
        }
    }
    assert_eq!(
        s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", &Sha256),
        CHALLENGE
    );
}

#[test]
fn the_claims_parameter_is_kept_with_the_request_and_its_essential_acr_becomes_acr_values() {
    let setting = setting();
    let claims = r#"{"id_token":{"email":null,"acr":{"essential":true,"values":["urn:hodor:acr:mfa"]}},"userinfo":{"name":{"essential":true},"sub":{"value":"someone"}}}"#;
    let pairs = with(good(&setting.client), "claims", Some(claims));
    let pairs = with(pairs, "claims_locales", Some("fr-CA en"));
    let request = check(&setting, pairs).expect("accepted");
    assert_eq!(request.claims.id_token, ["email"]);
    assert_eq!(request.claims.userinfo, ["name"]);
    assert_eq!(request.claims.subject.as_deref(), Some("someone"));
    assert_eq!(request.acr_values.as_deref(), Some("urn:hodor:acr:mfa"));
    assert_eq!(request.claims_locales.as_deref(), Some("fr-CA en"));
    // Kept as it is while the person signs in.
    let written = serde_json::to_value(&request).expect("written");
    let read: AuthorizationRequest = serde_json::from_value(written).expect("read");
    assert_eq!(read, request);
}

#[test]
fn an_acr_asked_without_essential_is_a_preference_and_asks_for_no_level() {
    let setting = setting();
    let claims = r#"{"id_token":{"acr":{"values":["urn:hodor:acr:mfa"]}}}"#;
    let request = check(
        &setting,
        with(good(&setting.client), "claims", Some(claims)),
    )
    .expect("accepted");
    assert_eq!(request.acr_values, None);
}

#[test]
fn a_malformed_or_conflicting_claims_parameter_is_an_invalid_request() {
    let setting = setting();
    let too_many: String = format!(
        "{{\"userinfo\":{{{}}}}}",
        (0..65)
            .map(|index| format!("\"claim_{index}\":null"))
            .collect::<Vec<_>>()
            .join(",")
    );
    let too_large = format!(
        "{{\"userinfo\":{{\"name\":{{\"value\":\"{}\"}}}}}}",
        "a".repeat(4096)
    );
    for claims in [
        "not json",
        "[]",
        r#"{"id_token":[]}"#,
        r#"{"userinfo":{"name":true}}"#,
        r#"{"userinfo":{"name":{"essential":"yes"}}}"#,
        r#"{"userinfo":{"name":{"values":"one"}}}"#,
        r#"{"id_token":{"acr":{"essential":true,"values":[1]}}}"#,
        r#"{"id_token":{"sub":{"value":1}}}"#,
        r#"{"id_token":{"sub":{"value":"a"}},"userinfo":{"sub":{"value":"b"}}}"#,
        too_many.as_str(),
        too_large.as_str(),
    ] {
        let pairs = with(good(&setting.client), "claims", Some(claims));
        assert_eq!(
            error_of(check(&setting, pairs)),
            "invalid_request",
            "{claims}"
        );
    }
    let both = with(
        with(
            good(&setting.client),
            "claims",
            Some(r#"{"id_token":{"acr":{"essential":true,"value":"urn:hodor:acr:mfa"}}}"#),
        ),
        "acr_values",
        Some("urn:hodor:acr:mfa"),
    );
    assert_eq!(error_of(check(&setting, both)), "invalid_request");
    // An `acr` without a value asks for nothing more beside `acr_values`.
    let named = with(
        with(
            good(&setting.client),
            "claims",
            Some(r#"{"id_token":{"acr":null}}"#),
        ),
        "acr_values",
        Some("urn:hodor:acr:mfa"),
    );
    assert!(check(&setting, named).is_ok());
    let locales = with(
        good(&setting.client),
        "claims_locales",
        Some(&"a".repeat(256)),
    );
    assert_eq!(error_of(check(&setting, locales)), "invalid_request");
}

#[test]
fn a_request_names_another_person_only_when_it_asked_for_a_sub_with_a_value() {
    let setting = setting();
    let plain = check(&setting, good(&setting.client)).expect("accepted");
    assert!(!plain.names_another("anyone"));
    let asked = check(
        &setting,
        with(
            good(&setting.client),
            "claims",
            Some(r#"{"id_token":{"sub":{"value":"ana"}}}"#),
        ),
    )
    .expect("accepted");
    assert!(!asked.names_another("ana"));
    assert!(asked.names_another("bruno"));
}

#[test]
fn a_grant_is_made_giving_no_claim() {
    let setting = setting();
    let request = check(
        &setting,
        with(
            good(&setting.client),
            "claims",
            Some(r#"{"id_token":{"email":null}}"#),
        ),
    )
    .expect("accepted");
    let grant = Grant::make(&request, &person(MOMENT), MOMENT);
    assert_eq!(grant.claims, GrantClaims::default());
}

/// The setting with a client registered for every response type that
/// returns no access token.
fn every_type() -> Setting {
    let mut setting = setting();
    let mut settings = setting.client.snapshot().settings.clone();
    settings.response_types = ResponseType::ALL[..4].to_vec();
    setting
        .client
        .change(settings, MOMENT)
        .expect("every response type");
    setting
}

/// A request for `response_type`, with a nonce, and without the code
/// challenge of [`good`].
fn asking(setting: &Setting, response_type: &str) -> Pairs {
    let pairs = with(good(&setting.client), "response_type", Some(response_type));
    let pairs = with(pairs, "nonce", Some("n-0S6_WzA2Mj"));
    let pairs = with(pairs, "code_challenge", None);
    with(pairs, "code_challenge_method", None)
}

fn mode_of(
    result: Result<AuthorizationRequest, AuthorizationRefusal>,
) -> (&'static str, ResponseMode) {
    match result {
        Err(AuthorizationRefusal::Redirect(error)) => (error.error, error.mode),
        other => panic!("expected an error at the redirect address, got {other:?}"),
    }
}

#[test]
fn each_registered_type_is_answered_in_its_default_mode_unless_another_is_named() {
    let setting = every_type();
    for (written, kind, mode) in [
        ("id_token", ResponseType::IdToken, ResponseMode::Fragment),
        (
            "code id_token",
            ResponseType::CodeIdToken,
            ResponseMode::Fragment,
        ),
        (
            "id_token code",
            ResponseType::CodeIdToken,
            ResponseMode::Fragment,
        ),
        ("none", ResponseType::None, ResponseMode::Query),
    ] {
        let mut pairs = asking(&setting, written);
        if kind.returns_code() {
            // A public client's code still needs its challenge.
            pairs = with(pairs, "code_challenge", Some(CHALLENGE));
            pairs = with(pairs, "code_challenge_method", Some("S256"));
        }
        let request = check(&setting, pairs.clone()).expect(written);
        assert_eq!(request.response_type, kind, "{written}");
        assert_eq!(request.response_mode, mode, "{written}");
        let fragment = check(&setting, with(pairs, "response_mode", Some("fragment")))
            .expect("the fragment for every type");
        assert_eq!(fragment.response_mode, ResponseMode::Fragment);
    }
    let code = check(&setting, good(&setting.client)).expect("code");
    assert_eq!(
        (code.response_type, code.response_mode),
        (ResponseType::Code, ResponseMode::Query)
    );
}

#[test]
fn a_type_without_a_code_reads_no_challenge() {
    let setting = every_type();
    // A public client must send a challenge for a code, and need not for
    // an ID token alone; one sent anyway is not read, however written.
    let without = check(&setting, asking(&setting, "id_token")).expect("no challenge needed");
    assert_eq!(without.code_challenge, None);
    let ignored = with(asking(&setting, "id_token"), "code_challenge", Some("abc"));
    let ignored = with(ignored, "code_challenge_method", Some("plain"));
    assert_eq!(
        check(&setting, ignored).expect("not read").code_challenge,
        None
    );
    assert_eq!(
        mode_of(check(&setting, asking(&setting, "code id_token"))),
        ("invalid_request", ResponseMode::Fragment),
        "a code needs its challenge"
    );
}

#[test]
fn an_id_token_needs_a_nonce_and_openid_and_never_goes_into_a_query() {
    let setting = every_type();
    for written in ["id_token", "code id_token"] {
        let mut pairs = asking(&setting, written);
        pairs = with(pairs, "code_challenge", Some(CHALLENGE));
        pairs = with(pairs, "code_challenge_method", Some("S256"));
        assert_eq!(
            mode_of(check(&setting, with(pairs.clone(), "nonce", None))),
            ("invalid_request", ResponseMode::Fragment),
            "{written} without a nonce"
        );
        assert_eq!(
            mode_of(check(
                &setting,
                with(pairs.clone(), "response_mode", Some("query"))
            )),
            ("invalid_request", ResponseMode::Fragment),
            "{written} in the query"
        );
        assert_eq!(
            mode_of(check(&setting, with(pairs.clone(), "scope", Some("read")))),
            ("invalid_scope", ResponseMode::Fragment),
            "{written} without openid"
        );
    }
    // `code` and `none` need no nonce.
    let none = with(asking(&setting, "none"), "nonce", None);
    assert!(check(&setting, none).is_ok());
}

#[test]
fn an_error_goes_back_in_the_mode_the_answer_would_have_had() {
    let setting = every_type();
    let base = asking(&setting, "id_token");
    let mut twice = base.clone();
    twice.push(("scope".to_owned(), "openid".to_owned()));
    assert_eq!(
        mode_of(check(&setting, twice)),
        ("invalid_request", ResponseMode::Fragment),
        "an error before the type is checked, for a type of the fragment"
    );
    assert_eq!(
        mode_of(check(
            &setting,
            with(base.clone(), "response_type", Some("token id_token"))
        )),
        ("unauthorized_client", ResponseMode::Fragment),
        "a type that returns an access token, which the client may not use, answers in the \
         fragment"
    );
    assert_eq!(
        mode_of(check(
            &setting,
            with(base.clone(), "response_type", Some("code token code"))
        )),
        ("unsupported_response_type", ResponseMode::Query),
        "an unknown type answers in the query"
    );
    assert_eq!(
        mode_of(check(
            &setting,
            with(
                with(base.clone(), "response_type", Some("code code")),
                "response_mode",
                Some("fragment")
            )
        )),
        ("unsupported_response_type", ResponseMode::Fragment),
        "the mode the request names, when Hodor offers it"
    );
    assert_eq!(
        mode_of(check(
            &setting,
            with(base.clone(), "response_mode", Some("fragment.jwt"))
        )),
        ("invalid_request", ResponseMode::Fragment),
        "a mode not offered falls back to the type's"
    );
    // A type that returns an ID token may come as a form, its errors too.
    assert_eq!(
        check(
            &setting,
            with(base.clone(), "response_mode", Some("form_post"))
        )
        .map(|request| request.response_mode)
        .ok(),
        Some(ResponseMode::FormPost),
        "an ID token posted by the page of form_post"
    );
    assert_eq!(
        mode_of(check(
            &setting,
            with(
                with(base, "response_mode", Some("form_post")),
                "nonce",
                None
            )
        )),
        ("invalid_request", ResponseMode::FormPost),
        "an error of a type of the fragment, asked as a form"
    );
}

#[test]
fn a_type_the_client_did_not_register_is_unauthorized() {
    let setting = setting();
    for written in ["id_token", "code id_token", "none"] {
        let mut pairs = asking(&setting, written);
        pairs = with(pairs, "code_challenge", Some(CHALLENGE));
        pairs = with(pairs, "code_challenge_method", Some("S256"));
        let (error, _) = mode_of(check(&setting, pairs));
        assert_eq!(error, "unauthorized_client", "{written}");
    }
}

/// The setting with a client of every response type, marked for access
/// tokens through the browser with `scopes`.
fn marked_for(scopes: &[&str]) -> Setting {
    let mut setting = every_type();
    let mut settings = setting.client.snapshot().settings.clone();
    settings.response_types = ResponseType::ALL.to_vec();
    settings.browser_access_tokens =
        Some(crate::domain::browser_access::BrowserAccessTokens::asked(
            scopes.iter().map(|scope| (*scope).to_owned()).collect(),
        ));
    setting.client.change(settings, MOMENT).expect("marked");
    setting
}

const TOKEN_TYPES: [(&str, ResponseType); 4] = [
    ("token", ResponseType::Token),
    ("id_token token", ResponseType::IdTokenToken),
    ("code token", ResponseType::CodeToken),
    ("code id_token token", ResponseType::CodeIdTokenToken),
];

/// A request of a type that returns an access token, with what its type
/// needs: a challenge for a code.
fn asking_for_a_token(setting: &Setting, written: &str, kind: ResponseType) -> Pairs {
    let mut pairs = asking(setting, written);
    if kind.returns_code() {
        pairs = with(pairs, "code_challenge", Some(CHALLENGE));
        pairs = with(pairs, "code_challenge_method", Some("S256"));
    }
    pairs
}

#[test]
fn a_marked_client_is_answered_a_token_in_the_fragment_and_never_in_the_query() {
    let setting = marked_for(&["read"]);
    for (written, kind) in TOKEN_TYPES {
        let pairs = asking_for_a_token(&setting, written, kind);
        let request = check(&setting, pairs.clone()).expect(written);
        assert_eq!(request.response_type, kind, "{written}");
        assert_eq!(request.response_mode, ResponseMode::Fragment, "{written}");
        let posted = check(
            &setting,
            with(pairs.clone(), "response_mode", Some("form_post")),
        )
        .expect("a form for every type");
        assert_eq!(posted.response_mode, ResponseMode::FormPost);
        assert_eq!(
            mode_of(check(&setting, with(pairs, "response_mode", Some("query")))),
            ("invalid_request", ResponseMode::Fragment),
            "{written} in the query"
        );
    }
}

#[test]
fn a_client_that_is_not_marked_is_refused_every_type_that_returns_an_access_token() {
    // A client may not even register them without the mark; a request
    // for one is refused as a type the client did not register.
    let setting = every_type();
    let mut unmarked = setting.client.snapshot().settings.clone();
    unmarked.response_types = ResponseType::ALL.to_vec();
    assert_eq!(
        setting
            .client
            .clone()
            .change(unmarked, MOMENT)
            .expect_err("refused")
            .code(),
        "oauth.client_response_types_invalid"
    );
    for (written, kind) in TOKEN_TYPES {
        assert_eq!(
            mode_of(check(&setting, asking_for_a_token(&setting, written, kind))),
            ("unauthorized_client", ResponseMode::Fragment),
            "{written}"
        );
    }
}

#[test]
fn a_request_for_a_token_asks_only_for_what_the_mark_allows() {
    let setting = marked_for(&["read"]);
    for (written, kind) in TOKEN_TYPES {
        let pairs = asking_for_a_token(&setting, written, kind);
        // The scopes of OpenID Connect, `offline_access` for the code's
        // refresh token at the token endpoint, and those of the mark.
        let client_scopes = with(pairs.clone(), "scope", Some("openid email read"));
        assert!(check(&setting, client_scopes).is_ok(), "{written}");
        assert_eq!(
            mode_of(check(&setting, with(pairs, "scope", Some("openid write")))),
            ("invalid_scope", ResponseMode::Fragment),
            "{written}: `write` is not in the mark"
        );
    }
    let none = marked_for(&[]);
    assert_eq!(
        mode_of(check(
            &none,
            asking_for_a_token(&none, "token", ResponseType::Token)
        )),
        ("invalid_scope", ResponseMode::Fragment),
        "a mark of no scope allows those of OpenID Connect alone"
    );
    assert!(
        check(
            &none,
            with(
                asking_for_a_token(&none, "token", ResponseType::Token),
                "scope",
                Some("openid email")
            )
        )
        .is_ok()
    );
    // A type that returns no access token is not held to the mark.
    assert!(check(&none, asking(&none, "id_token")).is_ok());
}

#[test]
fn a_nonce_is_needed_where_an_id_token_comes_and_a_challenge_where_a_code_does() {
    let setting = marked_for(&["read"]);
    for (written, kind) in TOKEN_TYPES {
        let pairs = asking_for_a_token(&setting, written, kind);
        let without_nonce = check(&setting, with(pairs, "nonce", None));
        if kind.returns_id_token() {
            assert_eq!(
                mode_of(without_nonce),
                ("invalid_request", ResponseMode::Fragment),
                "{written}"
            );
        } else {
            assert!(without_nonce.is_ok(), "{written}: no ID token, no nonce");
        }
        let without_challenge = check(&setting, asking(&setting, written));
        if kind.returns_code() {
            assert_eq!(
                mode_of(without_challenge),
                ("invalid_request", ResponseMode::Fragment),
                "{written}: a public client's code needs its challenge"
            );
        } else {
            assert_eq!(
                without_challenge.expect(written).code_challenge,
                None,
                "{written}: nothing to redeem"
            );
        }
    }
    // `token` alone is OAuth's, and needs no `openid`.
    let oauth_only = with(asking(&setting, "token"), "scope", Some("read"));
    assert!(check(&setting, with(oauth_only, "nonce", None)).is_ok());
}

#[test]
fn a_kept_request_is_answered_only_while_the_client_is_still_marked_for_it() {
    let mut setting = marked_for(&["read"]);
    let request = check(
        &setting,
        asking_for_a_token(&setting, "id_token token", ResponseType::IdTokenToken),
    )
    .expect("checked while marked");
    assert_eq!(still_answerable(&setting.client, &request), None);

    // The mark no longer allows one of its scopes.
    let mut settings = setting.client.snapshot().settings.clone();
    settings.browser_access_tokens = Some(
        crate::domain::browser_access::BrowserAccessTokens::asked(Vec::new()),
    );
    setting.client.change(settings, MOMENT).expect("narrowed");
    let refused = still_answerable(&setting.client, &request).expect("refused");
    assert_eq!(
        (refused.error, refused.mode, refused.state.as_deref()),
        ("invalid_scope", ResponseMode::Fragment, Some("xyz"))
    );
    assert_eq!(refused.redirect_uri, REDIRECT);

    // The mark is gone, and the types it allowed with it.
    let mut settings = setting.client.snapshot().settings.clone();
    settings.browser_access_tokens = None;
    settings.response_types = crate::domain::response::response_types_kept(
        &settings.response_types,
        &settings.grant_types,
        false,
    );
    setting.client.change(settings, MOMENT).expect("unmarked");
    let refused = still_answerable(&setting.client, &request).expect("refused");
    assert_eq!(refused.error, "unauthorized_client");

    // A request that returns no access token is never held to the mark.
    let id_token = check(&setting, asking(&setting, "id_token")).expect("still registered");
    assert_eq!(still_answerable(&setting.client, &id_token), None);
}
