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
    );
    assert_eq!(page_of(result), unknown);
    let mut application = setting.application.clone();
    application.set_status(Status::Disabled, MOMENT);
    let result = check_request(
        &AuthorizationParameters::from_pairs(good(&setting.client)),
        Some(&setting.client),
        Some(&application),
        &setting.servers,
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
            "a token response type",
            with(base.clone(), "response_type", Some("token")),
            "unsupported_response_type",
        ),
        (
            "a hybrid response type",
            with(base.clone(), "response_type", Some("code id_token")),
            "unsupported_response_type",
        ),
        (
            "a fragment response mode",
            with(base.clone(), "response_mode", Some("fragment")),
            "invalid_request",
        ),
        (
            "a request object",
            with(base.clone(), "request", Some("eyJ")),
            "request_not_supported",
        ),
        (
            "a request object by reference",
            with(base.clone(), "request_uri", Some("urn:x")),
            "request_uri_not_supported",
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
fn only_first_party_applications_are_answered_until_consent_exists() {
    let application = application(false);
    let client = client_of(&application, ClientType::Public);
    let servers = vec![server(&application, AUDIENCE, &["read"])];
    let setting = Setting {
        application,
        client,
        servers,
    };
    assert_eq!(
        error_of(check(&setting, good(&setting.client))),
        "access_denied"
    );
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
    }
    assert_eq!(
        s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", &Sha256),
        CHALLENGE
    );
}
