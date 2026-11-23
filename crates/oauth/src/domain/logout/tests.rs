use super::*;
use crate::domain::application::{ApplicationSettings, Status};
use crate::domain::client::{ClientSettings, ClientType, GrantType};
use crate::domain::secret::ClientSecret;
use crate::testing::{FakeVerifier, fake_signature};
use hodor_kernel::random::testing::{CountingRandom, FakeDigest};
use hodor_kernel::{PublicKey, Timestamp};
use serde_json::json;

const ISSUER: &str = "https://hodor.example.com/t/acme";
const KEY_ID: &str = "0193a0b2-0000-7000-8000-000000000001";
const OUT: &str = "https://payroll.example.com/signed-out";

fn key() -> PublicKey {
    PublicKey::P256 {
        x: vec![1; 32],
        y: vec![2; 32],
    }
}

fn published() -> Vec<PublishedKey> {
    vec![PublishedKey {
        key_id: KEY_ID.to_owned(),
        algorithm: SignatureAlgorithm::Es256,
        key: key(),
    }]
}

fn sign(header: &Value, claims: &Value) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature = fake_signature(SignatureAlgorithm::Es256, &key(), input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn header() -> Value {
    json!({"alg": "ES256", "typ": "JWT", "kid": KEY_ID})
}

struct Who {
    client: ClientId,
    user: UserId,
    session: SessionId,
}

fn who() -> Who {
    Who {
        client: ClientId::generate(),
        user: UserId::generate(),
        session: SessionId::generate(),
    }
}

fn claims(who: &Who) -> Value {
    json!({
        "iss": ISSUER,
        "sub": who.user.to_string(),
        "aud": who.client.to_string(),
        "sid": who.session.to_string(),
        // Long expired: the hint's expiry is not checked.
        "exp": 1,
        "iat": 0,
    })
}

fn check(token: &str) -> Result<IdTokenHint, &'static str> {
    check_id_token_hint(token, ISSUER, &published(), &FakeVerifier)
}

#[test]
fn a_hint_says_which_client_person_and_session_even_when_expired() {
    let who = who();
    let hint = check(&sign(&header(), &claims(&who))).expect("a good hint");
    assert_eq!(
        hint,
        IdTokenHint {
            client_id: who.client,
            user_id: who.user,
            session_id: Some(who.session),
        }
    );
    let mut without_sid = claims(&who);
    without_sid.as_object_mut().expect("object").remove("sid");
    assert_eq!(
        check(&sign(&header(), &without_sid))
            .expect("an ID token from before sid")
            .session_id,
        None
    );
    let mut one_audience = claims(&who);
    one_audience["aud"] = json!([who.client.to_string()]);
    assert!(check(&sign(&header(), &one_audience)).is_ok());
}

#[test]
fn a_hint_that_is_not_this_tenants_id_token_is_refused() {
    let who = who();
    let good = sign(&header(), &claims(&who));
    let mut tampered = good;
    tampered.pop();
    tampered.push(if tampered.ends_with('A') { 'B' } else { 'A' });
    let with_header = |change: &dyn Fn(&mut Value)| {
        let mut h = header();
        change(&mut h);
        sign(&h, &claims(&who))
    };
    let with_claims = |change: &dyn Fn(&mut Value)| {
        let mut c = claims(&who);
        change(&mut c);
        sign(&header(), &c)
    };
    let cases = [
        ("not three parts", "a.b".to_owned()),
        ("a changed signature", tampered),
        (
            "a key the tenant does not publish",
            with_header(&|h| h["kid"] = json!("0193a0b2-0000-7000-8000-000000000099")),
        ),
        (
            "an access token",
            with_header(&|h| h["typ"] = json!("at+jwt")),
        ),
        (
            "a shared-secret algorithm",
            with_header(&|h| h["alg"] = json!("HS256")),
        ),
        (
            "another issuer",
            with_claims(&|c| c["iss"] = json!("https://hodor.example.com/t/globex")),
        ),
        (
            "two audiences",
            with_claims(&|c| c["aud"] = json!([c["aud"].clone(), "another"])),
        ),
        (
            "a malformed session",
            with_claims(&|c| c["sid"] = json!("not a session")),
        ),
        ("too large", "a".repeat(17 * 1024)),
    ];
    for (name, token) in cases {
        assert!(check(&token).is_err(), "{name}");
    }
}

fn pairs(list: &[(&str, &str)]) -> LogoutParameters {
    LogoutParameters::from_pairs(
        list.iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned())),
    )
}

#[test]
fn the_shape_is_checked_before_anything_stored() {
    assert_eq!(check_shape(&pairs(&[])), Ok(None));
    assert_eq!(
        check_shape(&pairs(&[("state", "a"), ("state", "b")])),
        Err(refusal::REQUEST_INVALID)
    );
    assert_eq!(
        check_shape(&pairs(&[("state", &"s".repeat(1025))])),
        Err(refusal::REQUEST_INVALID)
    );
    assert_eq!(
        check_shape(&pairs(&[("state", "line\nbreak")])),
        Err(refusal::REQUEST_INVALID)
    );
    assert_eq!(
        check_shape(&pairs(&[("ui_locales", &"x".repeat(256))])),
        Err(refusal::REQUEST_INVALID)
    );
    assert_eq!(
        check_shape(&pairs(&[("client_id", "not-a-client")])),
        Err(refusal::CLIENT_UNKNOWN)
    );
    let id = ClientId::generate();
    assert_eq!(
        check_shape(&pairs(&[
            ("client_id", &id.to_string()),
            ("logout_hint", "x")
        ])),
        Ok(Some(id)),
        "logout_hint and unknown parameters are ignored"
    );
}

fn now() -> Timestamp {
    Timestamp::UNIX_EPOCH
}

fn application() -> Application {
    Application::create(
        ApplicationSettings {
            name: "Payroll".to_owned(),
            first_party: false,
        },
        now(),
    )
    .expect("application")
}

fn client(application: &Application) -> Client {
    let mut settings = ClientSettings::new(
        "Payroll web",
        ClientType::Public,
        vec![GrantType::AuthorizationCode],
        vec!["https://payroll.example.com/callback".to_owned()],
    );
    settings.post_logout_redirect_uris = vec![OUT.to_owned()];
    Client::create(
        application.id(),
        ClientType::Public,
        settings,
        ClientSecret::DEFAULT_LIFETIME,
        now(),
        &CountingRandom::default(),
        &FakeDigest,
    )
    .expect("client")
    .0
}

fn hint_for(client: ClientId) -> IdTokenHint {
    IdTokenHint {
        client_id: client,
        user_id: UserId::generate(),
        session_id: Some(SessionId::generate()),
    }
}

#[test]
fn the_return_address_must_be_registered_for_the_client_the_request_names() {
    let application = application();
    let client = client(&application);
    let loaded = Some((&client, Some(&application)));

    let by_id = check_request(
        &pairs(&[("post_logout_redirect_uri", OUT), ("state", "xyz")]),
        Some(client.id()),
        None,
        loaded,
    )
    .expect("registered");
    assert_eq!(
        by_id.return_to,
        Some(ReturnAddress {
            client_id: client.id(),
            uri: OUT.to_owned(),
            state: Some("xyz".to_owned()),
        })
    );

    let by_hint = check_request(
        &pairs(&[("post_logout_redirect_uri", OUT)]),
        None,
        Some(hint_for(client.id())),
        loaded,
    )
    .expect("the hint names the client");
    assert!(by_hint.return_to.is_some());

    assert_eq!(
        check_request(
            &pairs(&[(
                "post_logout_redirect_uri",
                "https://payroll.example.com/signed-out/"
            )]),
            Some(client.id()),
            None,
            loaded,
        ),
        Err(refusal::REDIRECT_URI_UNREGISTERED),
        "character for character"
    );
    assert_eq!(
        check_request(
            &pairs(&[(
                "post_logout_redirect_uri",
                "https://payroll.example.com/callback"
            )]),
            Some(client.id()),
            None,
            loaded,
        ),
        Err(refusal::REDIRECT_URI_UNREGISTERED),
        "a redirect address is not a post-logout one"
    );
    assert_eq!(
        check_request(
            &pairs(&[("post_logout_redirect_uri", OUT)]),
            None,
            None,
            None
        ),
        Err(refusal::CLIENT_UNKNOWN),
        "an address without a client"
    );
    assert_eq!(
        check_request(&pairs(&[]), Some(client.id()), None, None),
        Err(refusal::CLIENT_UNKNOWN),
        "a client the tenant does not have"
    );
    assert_eq!(
        check_request(
            &pairs(&[]),
            Some(client.id()),
            Some(hint_for(ClientId::generate())),
            loaded
        ),
        Err(refusal::CLIENT_MISMATCH)
    );
    let bare = check_request(&pairs(&[("ui_locales", "pt-BR")]), None, None, None)
        .expect("a bare request is fine");
    assert_eq!(bare.return_to, None);
    assert_eq!(bare.ui_locales.as_deref(), Some("pt-BR"));

    let mut disabled = application.clone();
    disabled.set_status(Status::Disabled, now());
    assert_eq!(
        check_request(
            &pairs(&[]),
            Some(client.id()),
            None,
            Some((&client, Some(&disabled)))
        ),
        Err(refusal::CLIENT_UNKNOWN),
        "the client of a disabled application"
    );
}

#[test]
fn the_session_ends_without_asking_only_when_the_hint_names_it() {
    let user = UserId::generate();
    let session = SessionId::generate();
    let current = CurrentSession {
        user_id: user,
        session_id: session,
    };
    let request = |hint: Option<IdTokenHint>| LogoutRequest {
        hint,
        return_to: None,
        ui_locales: None,
    };
    let ours = IdTokenHint {
        client_id: ClientId::generate(),
        user_id: user,
        session_id: Some(session),
    };
    assert_eq!(request(None).decide(None, false), LogoutDecision::Finish);
    assert_eq!(
        request(Some(ours.clone())).decide(Some(current), false),
        LogoutDecision::EndSession
    );
    assert_eq!(
        request(Some(ours.clone())).decide(Some(current), true),
        LogoutDecision::Ask,
        "a form always asks"
    );
    assert_eq!(
        request(None).decide(Some(current), false),
        LogoutDecision::Ask
    );
    let older = IdTokenHint {
        session_id: Some(SessionId::generate()),
        ..ours.clone()
    };
    assert_eq!(
        request(Some(older)).decide(Some(current), false),
        LogoutDecision::Ask
    );
    let someone_else = IdTokenHint {
        user_id: UserId::generate(),
        ..ours.clone()
    };
    assert_eq!(
        request(Some(someone_else)).decide(Some(current), false),
        LogoutDecision::Ask
    );
    let without_sid = IdTokenHint {
        session_id: None,
        ..ours
    };
    assert_eq!(
        request(Some(without_sid)).decide(Some(current), false),
        LogoutDecision::Ask
    );
}

#[test]
fn a_kept_return_address_is_checked_again() {
    let application = application();
    let client = client(&application);
    let kept = ReturnAddress {
        client_id: client.id(),
        uri: OUT.to_owned(),
        state: None,
    };
    assert!(still_returns(&kept, Some((&client, Some(&application)))));
    assert!(!still_returns(&kept, None));
    let elsewhere = ReturnAddress {
        uri: "https://evil.example.com/".to_owned(),
        ..kept.clone()
    };
    assert!(!still_returns(
        &elsewhere,
        Some((&client, Some(&application)))
    ));
    let mut disabled = client.clone();
    disabled.set_status(Status::Disabled, now());
    assert!(!still_returns(&kept, Some((&disabled, Some(&application)))));
}
