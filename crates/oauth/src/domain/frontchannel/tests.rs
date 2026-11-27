use super::*;
use crate::domain::client::{ClientSettings, GrantType};
use hodor_kernel::random::testing::{CountingRandom, FakeDigest};

const REDIRECT: &str = "https://payroll.example.com/callback";

fn redirects(uris: &[&str]) -> Vec<String> {
    uris.iter().map(|uri| (*uri).to_owned()).collect()
}

fn check(uri: &str, uris: &[&str]) -> Result<(), DomainError> {
    check_frontchannel_logout_uri(uri, &redirects(uris))
}

fn reason(uri: &str, uris: &[&str]) -> String {
    let error = check(uri, uris).expect_err("refused");
    assert_eq!(error.code(), "oauth.client_frontchannel_logout_uri_invalid");
    error.detail().unwrap_or_default().to_owned()
}

fn web() -> ClientSettings {
    ClientSettings::new(
        "Payroll",
        ClientType::Confidential,
        vec![GrantType::AuthorizationCode],
        vec![REDIRECT.to_owned()],
    )
}

#[test]
fn an_address_on_the_site_of_a_redirect_address_is_accepted() {
    for uri in [
        "https://payroll.example.com/frontchannel-logout",
        "https://payroll.example.com/logout?from=hodor&x=1",
        "https://PAYROLL.example.com/logout",
        "https://payroll.example.com:443/logout",
        "https://payroll.example.com",
    ] {
        assert!(check(uri, &[REDIRECT]).is_ok(), "{uri}");
    }
    assert!(
        check(
            "http://127.0.0.1:8080/logout",
            &["http://127.0.0.1:8080/callback"]
        )
        .is_ok()
    );
    assert!(check("http://[::1]/logout", &["http://[::1]/callback"]).is_ok());
    // Any of the client's redirect addresses will do.
    assert!(
        check(
            "https://reports.example.com/logout",
            &[REDIRECT, "https://reports.example.com/callback"]
        )
        .is_ok()
    );
}

#[test]
fn an_address_on_another_site_is_refused() {
    let another = "the scheme, host and port are those of none of the client's redirect addresses";
    assert_eq!(
        reason("https://evil.example.net/logout", &[REDIRECT]),
        another
    );
    assert_eq!(
        reason("https://payroll.example.com:8443/logout", &[REDIRECT]),
        another,
        "another port"
    );
    assert_eq!(
        reason(
            "http://127.0.0.1:9090/logout",
            &["http://127.0.0.1:8080/callback"]
        ),
        another
    );
    assert_eq!(
        reason("https://example.com/logout", &[REDIRECT]),
        another,
        "a parent domain is another site"
    );
    assert_eq!(
        reason("https://payroll.example.com/logout", &[]),
        another,
        "no redirect address at all"
    );
    // A private-use redirect address has no site.
    assert_eq!(
        reason(
            "https://payroll.example.com/logout",
            &["com.example.payroll:/callback"]
        ),
        another
    );
}

#[test]
fn an_address_that_is_not_a_web_address_on_a_host_is_refused() {
    for uri in [
        "",
        "payroll.example.com/logout",
        "com.example.payroll:/logout",
        "javascript:alert(1)",
        "ftp://payroll.example.com/logout",
        "https://payroll.example.com/logout#here",
        "https://payroll.example.com/*",
        "https://user:pass@payroll.example.com/logout",
        "https://payroll.example.com/log out",
        "https:///logout",
        "https://payroll.example.com:0/logout",
        "https://payroll.example.com:99999/logout",
        "http://payroll.example.com/logout",
        "http://localhost/logout",
        "https://pay;roll.example.com/logout",
        "https://pay%72oll.example.com/logout",
    ] {
        assert!(check(uri, &[REDIRECT]).is_err(), "{uri}");
    }
    let long = format!("https://payroll.example.com/{}", "a".repeat(2000));
    assert!(check(&long, &[REDIRECT]).is_err());
}

#[test]
fn a_client_keeps_its_address_only_with_a_code_and_on_its_own_site() {
    let mut settings = web();
    settings.frontchannel_logout_uri = Some("https://payroll.example.com/fc".to_owned());
    settings.frontchannel_logout_session_required = true;
    let checked = settings
        .clone()
        .checked(ClientType::Confidential)
        .expect("valid");
    assert_eq!(
        checked.frontchannel_logout_uri.as_deref(),
        Some("https://payroll.example.com/fc")
    );
    assert!(checked.frontchannel_logout_session_required);

    // A change that takes away the address's site is refused.
    let mut moved = settings;
    moved.redirect_uris = vec!["https://payroll.example.net/callback".to_owned()];
    assert_eq!(
        moved
            .checked(ClientType::Confidential)
            .expect_err("another site")
            .code(),
        "oauth.client_frontchannel_logout_uri_invalid"
    );

    let mut service = ClientSettings::new(
        "Payroll jobs",
        ClientType::Confidential,
        vec![GrantType::ClientCredentials],
        Vec::new(),
    );
    service.frontchannel_logout_uri = Some("https://payroll.example.com/fc".to_owned());
    assert_eq!(
        service
            .checked(ClientType::Confidential)
            .expect_err("no code")
            .code(),
        "oauth.client_frontchannel_logout_uri_invalid"
    );

    let mut without = web();
    without.frontchannel_logout_session_required = true;
    assert_eq!(
        without
            .checked(ClientType::Confidential)
            .expect_err("no address")
            .code(),
        "oauth.client_frontchannel_logout_uri_invalid"
    );
    assert!(web().checked(ClientType::Confidential).is_ok());
}

#[test]
fn a_frame_carries_the_issuer_and_the_session_in_its_query() {
    assert_eq!(
        frame_address(
            "https://payroll.example.com/fc",
            "https://id.example.com/t/acme",
            "0193f1c9-0000-7000-8000-000000000000"
        ),
        "https://payroll.example.com/fc?iss=https%3A%2F%2Fid.example.com%2Ft%2Facme\
         &sid=0193f1c9-0000-7000-8000-000000000000"
    );
    assert_eq!(
        frame_address(
            "https://payroll.example.com/fc?from=hodor",
            "https://id.example.com/t/acme",
            "a b&c"
        ),
        "https://payroll.example.com/fc?from=hodor&iss=https%3A%2F%2Fid.example.com%2Ft%2Facme\
         &sid=a+b%26c"
    );
}

#[test]
fn the_policy_names_each_site_once() {
    let frames = vec![
        "https://payroll.example.com/fc?iss=x&sid=1".to_owned(),
        "https://PAYROLL.example.com/other?iss=x&sid=2".to_owned(),
        "https://reports.example.com:8443/fc?iss=x&sid=3".to_owned(),
        "http://127.0.0.1:8080/fc?iss=x&sid=4".to_owned(),
        "http://[::1]/fc?iss=x&sid=5".to_owned(),
        // Never kept, but never written into the policy either.
        "https://x;script-src/fc".to_owned(),
        "javascript:alert(1)".to_owned(),
    ];
    assert_eq!(
        frame_sources(&frames),
        vec![
            "https://payroll.example.com",
            "https://reports.example.com:8443",
            "http://127.0.0.1:8080",
            "http://[::1]",
        ]
    );
    assert!(frame_sources(&[]).is_empty());
}

#[test]
fn frames_are_kept_under_the_hash_of_a_handle_for_two_minutes() {
    let random = CountingRandom::default();
    let digest = FakeDigest;
    let now = Timestamp::now_utc();
    let session = SessionId::generate();
    assert!(FrontChannelLogout::keep(session, Vec::new(), now, &random, &digest).is_none());

    let (kept, handle) = FrontChannelLogout::keep(
        session,
        vec!["https://payroll.example.com/fc?iss=x&sid=y".to_owned()],
        now,
        &random,
        &digest,
    )
    .expect("kept");
    assert_eq!(kept.session_id, session);
    assert_eq!(kept.expires_at, now + Duration::seconds(120));
    assert!(kept.is_live_at(now + Duration::seconds(119)));
    assert!(!kept.is_live_at(now + Duration::seconds(120)));
    assert_eq!(handle.expose().len(), 43);
    assert_eq!(
        HandleHash::of_presented(handle.expose(), &digest),
        Some(kept.handle_hash)
    );
    assert!(!format!("{handle:?}").contains(handle.expose()));
    assert_eq!(format!("{:?}", kept.handle_hash), "HandleHash(..)");

    // Anything that is not the shape of a handle is not hashed at all.
    for presented in [
        "",
        "short",
        &"a".repeat(44),
        &format!("{}=", &handle.expose()[1..]),
    ] {
        assert_eq!(
            HandleHash::of_presented(presented, &digest),
            None,
            "{presented}"
        );
    }
}
