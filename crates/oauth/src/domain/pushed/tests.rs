//! The rules of pushed authorization requests, case by case.

use super::*;
use crate::domain::application::ApplicationSettings;
use crate::domain::client::{ClientId, ClientSettings, ClientType, GrantType};
use crate::domain::resource_server::{Audience, ResourceServerSettings, ScopeDefinition};
use crate::domain::response::ResponseMode;
use crate::domain::secret::ClientSecret;
use hodor_kernel::random::testing::{CountingRandom, FakeDigest};

const REDIRECT: &str = "https://payroll.example.com/callback";
const AUDIENCE: &str = "https://api.payroll.example.com";
const MOMENT: Timestamp = Timestamp::UNIX_EPOCH;
const ISSUER: &str = "https://hodor.example.com/t/acme";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn objects() -> RequestObjectCheck<'static> {
    RequestObjectCheck {
        keys: &[],
        issuer: ISSUER,
        now: MOMENT,
        verifier: &crate::testing::FakeVerifier,
    }
}

struct Setting {
    application: Application,
    client: Client,
    servers: Vec<ResourceServer>,
}

fn client_of(application: &Application, grants: Vec<GrantType>, redirects: &[&str]) -> Client {
    let mut settings = ClientSettings::new(
        "Payroll web",
        ClientType::Confidential,
        grants,
        redirects.iter().map(|uri| (*uri).to_owned()).collect(),
    );
    settings.allowed_scopes = vec!["openid".to_owned(), "read".to_owned()];
    Client::create(
        application.id(),
        ClientType::Confidential,
        settings,
        ClientSecret::DEFAULT_LIFETIME,
        MOMENT,
        &CountingRandom::default(),
        &FakeDigest,
    )
    .expect("client")
    .0
}

fn setting() -> Setting {
    let application = Application::create(
        ApplicationSettings {
            name: "Payroll".to_owned(),
            first_party: true,
        },
        MOMENT,
    )
    .expect("application");
    let client = client_of(
        &application,
        vec![GrantType::AuthorizationCode],
        &[REDIRECT],
    );
    let servers = vec![
        ResourceServer::create(
            application.id(),
            Audience::parse(AUDIENCE).expect("audience"),
            ResourceServerSettings {
                name: "Payroll interface".to_owned(),
                scopes: vec![ScopeDefinition {
                    name: "read".to_owned(),
                    description: String::new(),
                }],
            },
            MOMENT,
        )
        .expect("server"),
    ];
    Setting {
        application,
        client,
        servers,
    }
}

fn pairs(given: &[(&str, &str)]) -> Vec<(String, String)> {
    given
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect()
}

fn parameters(given: &[(&str, &str)]) -> AuthorizationParameters {
    AuthorizationParameters::from_pairs(pairs(given))
}

/// What a client pushes, without its `client_id`, which the endpoint adds.
fn pushed_form() -> Vec<(&'static str, &'static str)> {
    vec![
        ("response_type", "code"),
        ("redirect_uri", REDIRECT),
        ("scope", "openid read"),
        ("state", "pushed state"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ]
}

fn pushed_request(setting: &Setting) -> AuthorizationRequest {
    check_pushed_request(
        parameters(&pushed_form()),
        &setting.client,
        &setting.application,
        &setting.servers,
        objects(),
    )
    .expect("a good request")
}

fn pushed(setting: &Setting, lifetime: Duration) -> (PushedAuthorization, RequestReference) {
    PushedAuthorization::push(
        pushed_request(setting),
        lifetime,
        MOMENT,
        &CountingRandom::default(),
        &FakeDigest,
    )
}

fn error_of(result: Result<AuthorizationRequest, AuthorizationRefusal>) -> AuthorizationError {
    match result {
        Err(AuthorizationRefusal::Redirect(error)) => error,
        other => panic!("expected an error at a redirect address, got {other:?}"),
    }
}

fn page_of(result: Result<AuthorizationRequest, AuthorizationRefusal>) -> &'static str {
    match result {
        Err(AuthorizationRefusal::NotRedirectable(code)) => code,
        other => panic!("expected Hodor's own page, got {other:?}"),
    }
}

#[test]
fn a_reference_holds_nothing_but_random_bytes_and_only_its_hash_is_kept() {
    let setting = setting();
    let (pushed, reference) = pushed(&setting, Duration::seconds(60));
    let value = reference.expose();
    let random = value
        .strip_prefix(REFERENCE_PREFIX)
        .expect("Hodor's prefix");
    assert_eq!(random.len(), 43);
    assert!(is_base64url(random));
    assert_eq!(
        ReferenceHash::of_presented(value, &FakeDigest),
        Some(pushed.reference_hash)
    );
    assert_eq!(pushed.expires_at, MOMENT + Duration::seconds(60));
    assert!(pushed.is_live_at(MOMENT + Duration::seconds(59)));
    assert!(!pushed.is_live_at(MOMENT + Duration::seconds(60)));
    assert_eq!(format!("{reference:?}"), "RequestReference([REDACTED])");
    assert_eq!(format!("{:?}", pushed.reference_hash), "ReferenceHash(..)");

    // What does not have the shape is no reference, and nothing is
    // computed for it.
    for other in [
        String::new(),
        random.to_owned(),
        format!("urn:ietf:params:oauth:request_uri:{}", &random[1..]),
        format!("urn:ietf:params:oauth:request_uri:{random}x"),
        format!("urn:ietf:params:oauth:request_uri:{}*", &random[1..]),
        format!("urn:example:{random}"),
    ] {
        assert_eq!(
            ReferenceHash::of_presented(&other, &FakeDigest),
            None,
            "{other}"
        );
    }
}

#[test]
fn the_life_of_a_pushed_request_stays_within_its_bounds() {
    let policy = |seconds| PushedRequestPolicy {
        lifetime: Duration::seconds(seconds),
        required: false,
    };
    assert_eq!(
        pushed_lifetime(&PushedRequestPolicy::default()),
        Duration::seconds(60)
    );
    assert_eq!(pushed_lifetime(&policy(1)), Duration::seconds(10));
    assert_eq!(pushed_lifetime(&policy(10)), Duration::seconds(10));
    assert_eq!(pushed_lifetime(&policy(600)), Duration::seconds(600));
    assert_eq!(pushed_lifetime(&policy(6000)), Duration::seconds(600));
}

#[test]
fn a_client_or_its_tenant_requires_pushed_requests() {
    let setting = setting();
    let mut strict = setting.client.clone();
    let mut settings = strict.snapshot().settings.clone();
    settings.require_pushed_requests = true;
    strict.change(settings, MOMENT).expect("changed");
    let lenient = PushedRequestPolicy::default();
    let tenant = PushedRequestPolicy {
        required: true,
        ..lenient
    };
    assert!(!lenient.requires(Some(&setting.client)));
    assert!(lenient.requires(Some(&strict)));
    assert!(tenant.requires(Some(&setting.client)));
    assert!(tenant.requires(None));
    assert!(!lenient.requires(None));
}

#[test]
fn request_uri_says_which_kind_of_reference_it_is() {
    let kind = |given: &[(&str, &str)]| match parameters(given).reference() {
        Reference::Absent => "absent",
        Reference::Pushed(_) => "pushed",
        Reference::Address(_) => "address",
        Reference::Unknown => "unknown",
    };
    assert_eq!(kind(&[]), "absent");
    let ours = "urn:ietf:params:oauth:request_uri:abc";
    let given = parameters(&[("request_uri", ours)]);
    assert_eq!(given.reference(), Reference::Pushed(ours));
    assert_eq!(
        kind(&[("request_uri", "https://client.example.com/request.jwt")]),
        "address"
    );
    assert_eq!(
        kind(&[("request_uri", "http://client.example.com/request.jwt")]),
        "address",
        "plain HTTP, which only a host of the development exception can answer"
    );
    assert_eq!(
        kind(&[("request_uri", "ftp://client.example.com/r")]),
        "unknown"
    );
    assert_eq!(
        kind(&[("request_uri", ours), ("request_uri", ours)]),
        "unknown",
        "given twice"
    );
}

#[test]
fn a_pushed_request_is_the_request_its_reference_brings() {
    let setting = setting();
    let (pushed, reference) = pushed(&setting, Duration::seconds(60));
    let id = setting.client.id().to_string();
    let request = check_reference(
        &parameters(&[("client_id", &id), ("request_uri", reference.expose())]),
        &setting.client,
        Some(pushed.clone()),
        MOMENT,
    )
    .expect("the request");
    assert_eq!(request, pushed.request);
    assert_eq!(request.client_id, setting.client.id());
    assert_eq!(request.state.as_deref(), Some("pushed state"));

    // What OpenID Connect asks to repeat may be repeated, the scopes in
    // any order; everything else outside is ignored.
    let request = check_reference(
        &parameters(&[
            ("client_id", &id),
            ("request_uri", reference.expose()),
            ("response_type", "code"),
            ("scope", "read openid"),
            ("redirect_uri", "https://elsewhere.example.com/callback"),
            ("state", "outside"),
            ("prompt", "none"),
        ]),
        &setting.client,
        Some(pushed.clone()),
        MOMENT,
    )
    .expect("the request");
    assert_eq!(request, pushed.request, "nothing outside is read");

    // Repeated with other values: invalid_request at the pushed request's
    // own address, with its state.
    for (name, value) in [
        ("scope", "openid"),
        ("response_type", "token"),
        ("response_type", "code id_token"),
    ] {
        let error = error_of(check_reference(
            &parameters(&[
                ("client_id", &id),
                ("request_uri", reference.expose()),
                (name, value),
            ]),
            &setting.client,
            Some(pushed.clone()),
            MOMENT,
        ));
        assert_eq!(error.error, "invalid_request", "{name}");
        assert_eq!(error.redirect_uri, REDIRECT);
        assert_eq!(error.state.as_deref(), Some("pushed state"));
    }
}

#[test]
fn a_reference_that_cannot_be_used_is_refused_where_the_client_can_hear_it() {
    let setting = setting();
    let (pushed, reference) = pushed(&setting, Duration::seconds(60));
    let id = setting.client.id().to_string();
    let other_client = client_of(
        &setting.application,
        vec![GrantType::AuthorizationCode],
        &[REDIRECT],
    );
    let mut of_another_client = pushed.clone();
    of_another_client.request.client_id = other_client.id();
    let outside = |extra: &[(&str, &str)]| {
        let mut given = vec![
            ("client_id", id.as_str()),
            ("request_uri", reference.expose()),
            ("redirect_uri", REDIRECT),
            ("state", "outside"),
        ];
        given.extend_from_slice(extra);
        parameters(&given)
    };

    // Unknown or used before, past its life, another client's.
    for (taken, at) in [
        (None, MOMENT),
        (Some(pushed.clone()), MOMENT + Duration::seconds(60)),
        (Some(of_another_client), MOMENT),
    ] {
        let error = error_of(check_reference(&outside(&[]), &setting.client, taken, at));
        assert_eq!(error.error, "invalid_request_uri");
        assert_eq!(error.redirect_uri, REDIRECT, "the address outside");
        assert_eq!(error.state.as_deref(), Some("outside"));
    }

    // `request` beside it, and an address of the client's.
    let error = error_of(check_reference(
        &outside(&[("request", "eyJ.eyJ.")]),
        &setting.client,
        Some(pushed.clone()),
        MOMENT,
    ));
    assert_eq!(error.error, "invalid_request");
    let error = error_of(check_reference(
        &parameters(&[
            ("client_id", &id),
            ("request_uri", "https://payroll.example.com/request.jwt"),
            ("redirect_uri", REDIRECT),
        ]),
        &setting.client,
        None,
        MOMENT,
    ));
    assert_eq!(error.error, "request_uri_not_supported");
    let error = error_of(check_reference(
        &parameters(&[
            ("client_id", &id),
            ("request_uri", "urn:example:anything"),
            ("redirect_uri", REDIRECT),
        ]),
        &setting.client,
        None,
        MOMENT,
    ));
    assert_eq!(error.error, "invalid_request_uri");

    // Without a redirect address of the client's outside, nothing can be
    // sent anywhere: Hodor's own page.
    for redirect in [None, Some("https://elsewhere.example.com/callback")] {
        let mut given = vec![
            ("client_id", id.as_str()),
            ("request_uri", reference.expose()),
        ];
        if let Some(redirect) = redirect {
            given.push(("redirect_uri", redirect));
        }
        assert_eq!(
            page_of(check_reference(
                &parameters(&given),
                &setting.client,
                None,
                MOMENT
            )),
            "oauth.authorization_request_uri_invalid"
        );
    }
}

#[test]
fn a_pushed_request_is_checked_at_once_and_answered_as_json() {
    let setting = setting();
    let id = setting.client.id().to_string();
    let request = pushed_request(&setting);
    assert_eq!(
        request.client_id,
        setting.client.id(),
        "the client that proved who it is"
    );
    assert_eq!(request.redirect_uri, REDIRECT);
    assert_eq!(request.audiences, [AUDIENCE]);

    // The client may name itself; never another.
    let mut naming_itself = pushed_form();
    naming_itself.push(("client_id", &id));
    let other = ClientId::generate().to_string();
    let mut naming_another = pushed_form();
    naming_another.push(("client_id", &other));
    assert!(
        check_pushed_request(
            parameters(&naming_itself),
            &setting.client,
            &setting.application,
            &setting.servers,
            objects(),
        )
        .is_ok()
    );

    let refused = |given: Vec<(&str, &str)>, client: &Client| {
        check_pushed_request(
            parameters(&given),
            client,
            &setting.application,
            &setting.servers,
            objects(),
        )
        .expect_err("refused")
        .error
    };
    let without = |name: &str| {
        pushed_form()
            .into_iter()
            .filter(|(given, _)| *given != name)
            .collect::<Vec<_>>()
    };
    let with = |name: &'static str, value: &'static str| {
        let mut given = without(name);
        given.push((name, value));
        given
    };
    assert_eq!(refused(naming_another, &setting.client), "invalid_request");
    assert_eq!(
        refused(without("redirect_uri"), &setting.client),
        "invalid_request"
    );
    assert_eq!(
        refused(
            with("redirect_uri", "https://elsewhere.example.com/callback"),
            &setting.client
        ),
        "invalid_request"
    );
    assert_eq!(
        refused(
            with("request_uri", "urn:ietf:params:oauth:request_uri:abc"),
            &setting.client
        ),
        "invalid_request",
        "a pushed request cannot name another"
    );
    assert_eq!(
        refused(with("response_type", "token"), &setting.client),
        "unauthorized_client"
    );
    assert_eq!(
        refused(with("scope", "openid write"), &setting.client),
        "invalid_scope"
    );
    assert_eq!(
        refused(
            with("resource", "https://elsewhere.example.com"),
            &setting.client
        ),
        "invalid_target"
    );
    assert_eq!(
        refused(with("code_challenge_method", "plain"), &setting.client),
        "invalid_request"
    );
    assert_eq!(
        refused(with("request", "not an object"), &setting.client),
        "invalid_request_object"
    );
    let machine = client_of(
        &setting.application,
        vec![GrantType::ClientCredentials],
        &[],
    );
    assert_eq!(
        refused(pushed_form(), &machine),
        "unauthorized_client",
        "a client that may not use the authorization code"
    );
}

#[test]
fn a_pushed_request_names_its_client_once_and_keeps_its_resources() {
    let form = pairs(&[
        ("client_id", "c"),
        ("client_secret", "s"),
        ("response_type", "code"),
        ("resource", "https://one.example.com"),
        ("resource", "https://two.example.com"),
    ]);
    let read = PushedRequest::parse(None, form).expect("read");
    assert!(matches!(read.client, PresentedClient::Secret { .. }));
    assert_eq!(
        read.parameters.once("client_secret"),
        None,
        "not a parameter"
    );
    assert_eq!(read.parameters.once("client_id"), Some("c"));
    assert_eq!(read.parameters.all("resource").len(), 2);

    let assertion = pairs(&[
        (
            "client_assertion_type",
            crate::domain::token::ASSERTION_TYPE,
        ),
        ("client_assertion", "a.b.c"),
        ("scope", "openid"),
    ]);
    let read = PushedRequest::parse(None, assertion).expect("read");
    assert!(matches!(read.client, PresentedClient::Assertion { .. }));
    assert_eq!(read.parameters.once("client_assertion"), None);
    assert_eq!(read.parameters.once("client_assertion_type"), None);

    let twice = pairs(&[("client_id", "c"), ("scope", "a"), ("scope", "b")]);
    assert_eq!(
        PushedRequest::parse(None, twice).expect_err("twice").error,
        "invalid_request"
    );
    let nobody = pairs(&[("scope", "openid")]);
    assert_eq!(
        PushedRequest::parse(None, nobody)
            .expect_err("nobody")
            .error,
        "invalid_client"
    );
    let both = pairs(&[
        ("client_id", "c"),
        ("client_secret", "s"),
        (
            "client_assertion_type",
            crate::domain::token::ASSERTION_TYPE,
        ),
        ("client_assertion", "a.b.c"),
    ]);
    assert_eq!(
        PushedRequest::parse(None, both)
            .expect_err("two ways")
            .error,
        "invalid_request"
    );
}

#[test]
fn a_pushed_request_is_answered_in_its_own_mode_and_a_refused_reference_in_the_mode_outside() {
    let setting = setting();
    let mut form = pushed_form();
    form.push(("response_mode", "form_post"));
    let request = check_pushed_request(
        parameters(&form),
        &setting.client,
        &setting.application,
        &setting.servers,
        objects(),
    )
    .expect("a good request");
    assert_eq!(request.response_mode, ResponseMode::FormPost);
    let (pushed, reference) = PushedAuthorization::push(
        request,
        Duration::seconds(60),
        MOMENT,
        &CountingRandom::default(),
        &FakeDigest,
    );
    let id = setting.client.id().to_string();

    // Taken, it keeps its mode, whatever is outside; contradicted, its
    // error comes back in that mode.
    let taken = check_reference(
        &parameters(&[
            ("client_id", &id),
            ("request_uri", reference.expose()),
            ("response_mode", "query"),
        ]),
        &setting.client,
        Some(pushed.clone()),
        MOMENT,
    )
    .expect("the request");
    assert_eq!(taken.response_mode, ResponseMode::FormPost);
    let error = error_of(check_reference(
        &parameters(&[
            ("client_id", &id),
            ("request_uri", reference.expose()),
            ("scope", "openid"),
            ("response_mode", "query"),
        ]),
        &setting.client,
        Some(pushed),
        MOMENT,
    ));
    assert_eq!(error.mode, ResponseMode::FormPost);

    // Refused, nothing of it is read: the mode named outside, beside the
    // redirect address, and the query without one.
    for (outside, mode) in [
        (Some("form_post"), ResponseMode::FormPost),
        (Some("fragment.jwt"), ResponseMode::Query),
        (None, ResponseMode::Query),
    ] {
        let mut given = vec![
            ("client_id", id.as_str()),
            ("request_uri", reference.expose()),
            ("redirect_uri", REDIRECT),
        ];
        if let Some(outside) = outside {
            given.push(("response_mode", outside));
        }
        let error = error_of(check_reference(
            &parameters(&given),
            &setting.client,
            None,
            MOMENT,
        ));
        assert_eq!(error.error, "invalid_request_uri");
        assert_eq!(error.mode, mode, "{outside:?}");
    }
}

#[test]
fn a_pushed_request_keeps_its_response_type_and_the_fragment() {
    let mut setting = setting();
    let mut settings = setting.client.snapshot().settings.clone();
    settings.response_types = crate::domain::response::ResponseType::ALL.to_vec();
    settings.browser_access_tokens = Some(
        crate::domain::browser_access::BrowserAccessTokens::asked(Vec::new()),
    );
    setting
        .client
        .change(settings, MOMENT)
        .expect("a client of every response type");
    let mut form = pushed_form();
    form[0] = ("response_type", "id_token code");
    form.push(("nonce", "n-0S6_WzA2Mj"));
    let request = check_pushed_request(
        parameters(&form),
        &setting.client,
        &setting.application,
        &setting.servers,
        objects(),
    )
    .expect("a hybrid request");
    assert_eq!(
        request.response_type,
        crate::domain::response::ResponseType::CodeIdToken
    );
    assert_eq!(request.response_mode, ResponseMode::Fragment);
    let (pushed, reference) = PushedAuthorization::push(
        request,
        Duration::seconds(60),
        MOMENT,
        &CountingRandom::default(),
        &FakeDigest,
    );
    let id = setting.client.id().to_string();
    // Repeated outside in another order of its words, it is the same type.
    let taken = check_reference(
        &parameters(&[
            ("client_id", &id),
            ("request_uri", reference.expose()),
            ("response_type", "code id_token"),
        ]),
        &setting.client,
        Some(pushed.clone()),
        MOMENT,
    )
    .expect("the request");
    assert_eq!(taken, pushed.request);
    assert_eq!(taken.response_mode, ResponseMode::Fragment);
    // Another type outside is refused in the pushed request's own mode.
    let error = error_of(check_reference(
        &parameters(&[
            ("client_id", &id),
            ("request_uri", reference.expose()),
            ("response_type", "code"),
        ]),
        &setting.client,
        Some(pushed),
        MOMENT,
    ));
    assert_eq!(error.error, "invalid_request");
    assert_eq!(error.mode, ResponseMode::Fragment);
}
