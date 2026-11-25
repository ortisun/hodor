//! The parameters of a request completed by Issue-125: `display`,
//! `prompt=create`, `id_token_hint`, and the client's defaults for a
//! sign-in.

use super::*;
use crate::domain::application::{Application, ApplicationSettings};
use crate::domain::client::{ClientSettings, ClientType};
use crate::domain::secret::ClientSecret;
use hodor_kernel::random::testing::{CountingRandom, FakeDigest};

const REDIRECT: &str = "https://payroll.example.com/callback";
const MOMENT: Timestamp = Timestamp::UNIX_EPOCH;
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

struct Setting {
    application: Application,
    client: Client,
}

fn setting_with(change: impl FnOnce(&mut ClientSettings)) -> Setting {
    let application = Application::create(
        ApplicationSettings {
            name: "Payroll".to_owned(),
            first_party: true,
        },
        MOMENT,
    )
    .expect("application");
    let mut settings = ClientSettings::new(
        "Payroll web",
        ClientType::Public,
        vec![GrantType::AuthorizationCode],
        vec![REDIRECT.to_owned()],
    );
    settings.allowed_scopes = vec!["openid".to_owned()];
    change(&mut settings);
    let client = Client::create(
        application.id(),
        ClientType::Public,
        settings,
        ClientSecret::DEFAULT_LIFETIME,
        MOMENT,
        &CountingRandom::default(),
        &FakeDigest,
    )
    .expect("client")
    .0;
    Setting {
        application,
        client,
    }
}

fn setting() -> Setting {
    setting_with(|_| {})
}

fn check(
    setting: &Setting,
    extra: &[(&str, &str)],
) -> Result<AuthorizationRequest, AuthorizationRefusal> {
    let client_id = setting.client.id().to_string();
    let mut pairs: Vec<(String, String)> = [
        ("response_type", "code"),
        ("client_id", client_id.as_str()),
        ("redirect_uri", REDIRECT),
        ("scope", "openid"),
        ("state", "xyz"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ]
    .iter()
    .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
    .collect();
    pairs.extend(
        extra
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
    );
    check_request(
        &AuthorizationParameters::from_pairs(pairs),
        Some(&setting.client),
        Some(&setting.application),
        &[],
        RequestObjectCheck {
            issuer: "https://hodor.example.com/t/acme",
            now: MOMENT,
            verifier: &crate::testing::FakeVerifier,
        },
    )
}

fn refused(result: Result<AuthorizationRequest, AuthorizationRefusal>) -> AuthorizationError {
    match result {
        Err(AuthorizationRefusal::Redirect(error)) => error,
        other => panic!("expected an error at the redirect address, got {other:?}"),
    }
}

#[test]
fn display_is_one_of_the_values_the_pages_are_made_for() {
    let setting = setting();
    for value in ["page", "popup", "touch"] {
        assert!(check(&setting, &[("display", value)]).is_ok(), "{value}");
    }
    for value in ["wap", "PAGE", "full"] {
        let error = refused(check(&setting, &[("display", value)]));
        assert_eq!(error.error, "invalid_request", "{value}");
        assert_eq!(error.state.as_deref(), Some("xyz"));
    }
}

#[test]
fn prompt_create_sends_the_person_to_register_for_a_new_sign_in() {
    let setting = setting();
    let request = check(&setting, &[("prompt", "create")]).expect("accepted");
    assert!(request.asks_to_register());
    assert!(!check(&setting, &[]).expect("plain").asks_to_register());
    // With another value, but never with `none`.
    assert!(check(&setting, &[("prompt", "create consent")]).is_ok());
    assert_eq!(
        refused(check(&setting, &[("prompt", "none create")])).error,
        "invalid_request"
    );

    // A session from before is not taken for the account just made.
    let password = vec!["password".to_owned()];
    assert_eq!(
        request.decide(true, &password, true),
        SessionDecision::SignIn
    );
    let received = MOMENT + Duration::hours(1);
    assert!(!request.signed_in_as_asked(received - Duration::minutes(1), received));
    assert!(request.signed_in_as_asked(received + Duration::minutes(1), received));

    // A tenant closed to registration does not support the value.
    assert_eq!(request.registration_refusal(true), None);
    let error = request.registration_refusal(false).expect("refused");
    assert_eq!(error.error, "invalid_request");
    assert!(error.description.contains("prompt=create"));
    assert_eq!(error.redirect_uri, REDIRECT);
    assert_eq!(error.state.as_deref(), Some("xyz"));
    // A request without `create` is never refused for it.
    assert_eq!(
        check(&setting, &[])
            .expect("plain")
            .registration_refusal(false),
        None
    );
}

#[test]
fn a_request_without_max_age_or_acr_values_takes_the_client_s_defaults() {
    let defaults = setting_with(|settings| {
        settings.default_max_age = Some(600);
        settings.default_acr_values = vec![
            "urn:hodor:acr:mfa".to_owned(),
            "urn:example:gold".to_owned(),
        ];
    });
    let request = check(&defaults, &[]).expect("accepted");
    assert_eq!(request.max_age, Some(600));
    assert_eq!(
        request.acr_values.as_deref(),
        Some("urn:hodor:acr:mfa urn:example:gold")
    );
    // A request's own values win, smaller or larger.
    let own = check(
        &defaults,
        &[
            ("max_age", "0"),
            ("acr_values", "urn:hodor:acr:single-factor"),
        ],
    )
    .expect("accepted");
    assert_eq!(own.max_age, Some(0));
    assert_eq!(
        own.acr_values.as_deref(),
        Some("urn:hodor:acr:single-factor")
    );
    let longer = check(&defaults, &[("max_age", "86400")]).expect("accepted");
    assert_eq!(longer.max_age, Some(86_400));
    // A client without defaults asks for nothing.
    let plain = check(&setting(), &[]).expect("accepted");
    assert_eq!(plain.max_age, None);
    assert_eq!(plain.acr_values, None);
}

fn hint(client_id: ClientId, subject: &str) -> IdTokenHint {
    IdTokenHint {
        client_id,
        subject: subject.to_owned(),
        session: Some("a-session".to_owned()),
    }
}

#[test]
fn a_hint_issued_to_the_client_names_the_person_the_session_must_be() {
    let setting = setting();
    let request = check(&setting, &[]).expect("accepted");
    // Without a hint, any person answers.
    assert!(request.names_person("anyone"));

    let hinted = request
        .clone()
        .hinted(Ok(hint(setting.client.id(), "ana")))
        .expect("the client's own hint");
    assert_eq!(hinted.id_token_hint.as_deref(), Some("ana"));
    assert!(hinted.names_person("ana"));
    assert!(!hinted.names_person("bruno"));

    // Issued to another client of the tenant, or not an ID token of the
    // tenant at all: `invalid_request` at the redirect address.
    let (refusal, reason) = request
        .clone()
        .hinted(Ok(hint(ClientId::generate(), "ana")))
        .expect_err("another client's");
    assert_eq!(reason, "the hint was issued to another client");
    let AuthorizationRefusal::Redirect(error) = refusal else {
        panic!("expected an error at the redirect address");
    };
    assert_eq!(error.error, "invalid_request");
    assert_eq!(error.state.as_deref(), Some("xyz"));
    let (refusal, reason) = request
        .hinted(Err("the hint's key is not published by this tenant"))
        .expect_err("another tenant's");
    assert_eq!(reason, "the hint's key is not published by this tenant");
    assert!(matches!(
        refusal,
        AuthorizationRefusal::Redirect(AuthorizationError {
            error: "invalid_request",
            ..
        })
    ));
}

#[test]
fn a_request_kept_before_hints_were_read_has_none() {
    let setting = setting();
    let request = check(&setting, &[]).expect("accepted");
    let mut stored = serde_json::to_value(&request).expect("JSON");
    stored
        .as_object_mut()
        .expect("an object")
        .remove("id_token_hint");
    let read: AuthorizationRequest = serde_json::from_value(stored).expect("read");
    assert_eq!(read.id_token_hint, None);
    assert!(read.names_person("anyone"));
}
