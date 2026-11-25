use super::*;
use crate::domain::client::{ClientSettings, ClientType, GrantType};

const NOW: Timestamp = Timestamp::UNIX_EPOCH;

fn delivery() -> LogoutDelivery {
    LogoutDelivery::make(
        ClientId::generate(),
        SessionId::generate(),
        UserId::generate(),
        NOW,
    )
}

fn web() -> ClientSettings {
    ClientSettings::new(
        "Payroll web",
        ClientType::Confidential,
        vec![GrantType::AuthorizationCode],
        vec!["https://payroll.example.com/callback".to_owned()],
    )
}

#[test]
fn an_address_is_https_or_http_with_a_host_and_no_fragment() {
    for good in [
        "https://payroll.example.com/backchannel-logout",
        "https://payroll.example.com:8443/logout?tenant=acme",
        "https://[2001:db8::1]:443/logout",
        "http://suite-relay:8080/test/a/hodor/backchannel_logout",
    ] {
        assert!(check_backchannel_logout_uri(good).is_ok(), "{good}");
    }
    for bad in [
        "",
        "payroll.example.com/logout",
        "ftp://payroll.example.com/logout",
        "com.example.payroll:/logout",
        "https:///logout",
        "https://user:password@payroll.example.com/logout",
        "https://payroll.example.com/logout#fragment",
        "https://payroll.example.com:99999/logout",
        "https://payroll.example.com/log out",
        "https://payroll.example.com/é",
        "https://[]/logout",
    ] {
        assert_eq!(
            check_backchannel_logout_uri(bad).expect_err(bad).code(),
            "oauth.client_backchannel_logout_uri_invalid",
            "{bad}"
        );
    }
    let long = format!("https://payroll.example.com/{}", "a".repeat(2000));
    assert!(check_backchannel_logout_uri(&long).is_err());
}

#[test]
fn only_a_client_that_signs_people_in_has_an_address() {
    let mut settings = web();
    settings.backchannel_logout_uri = Some("https://payroll.example.com/logout".to_owned());
    settings.backchannel_logout_session_required = true;
    let checked = settings
        .clone()
        .checked(ClientType::Confidential)
        .expect("valid");
    assert_eq!(
        checked.backchannel_logout_uri.as_deref(),
        Some("https://payroll.example.com/logout")
    );
    assert!(checked.backchannel_logout_session_required);

    let mut service = ClientSettings::new(
        "Payroll jobs",
        ClientType::Confidential,
        vec![GrantType::ClientCredentials],
        Vec::new(),
    );
    service.backchannel_logout_uri = Some("https://payroll.example.com/logout".to_owned());
    assert_eq!(
        service
            .checked(ClientType::Confidential)
            .expect_err("no code")
            .code(),
        "oauth.client_backchannel_logout_uri_invalid"
    );

    let mut without = web();
    without.backchannel_logout_session_required = true;
    assert_eq!(
        without
            .checked(ClientType::Confidential)
            .expect_err("no address")
            .code(),
        "oauth.client_backchannel_logout_uri_invalid"
    );

    let mut broken = web();
    broken.backchannel_logout_uri = Some("https://payroll.example.com/#out".to_owned());
    assert!(broken.checked(ClientType::Confidential).is_err());
    assert!(web().checked(ClientType::Confidential).is_ok());
}

#[test]
fn a_logout_token_names_the_session_and_the_person_never_a_nonce() {
    let client_id = ClientId::generate();
    let user_id = UserId::generate();
    let session_id = SessionId::generate();
    let claims = logout_token_claims(
        LogoutTokenSubject {
            issuer: "https://login.example.com/t/acme",
            client_id,
            subject: &user_id.to_string(),
            session: &session_id.to_string(),
        },
        NOW + Duration::seconds(100),
        "jti-1",
    );
    assert_eq!(claims["iss"], "https://login.example.com/t/acme");
    assert_eq!(claims["aud"], client_id.to_string());
    assert_eq!(claims["sub"], user_id.to_string());
    assert_eq!(claims["sid"], session_id.to_string());
    assert_eq!(claims["iat"], 100);
    assert_eq!(claims["exp"], 220);
    assert_eq!(claims["jti"], "jti-1");
    assert_eq!(
        claims["events"],
        json!({ "http://schemas.openid.net/event/backchannel-logout": {} })
    );
    assert!(claims.get("nonce").is_none());
    assert_eq!(
        logout_token_header("RS256", "k1"),
        json!({"alg": "RS256", "typ": "logout+jwt", "kid": "k1"})
    );
}

#[test]
fn waits_double_from_the_first_up_to_an_hour() {
    let policy = LogoutRetryPolicy::DEFAULT;
    let waits: Vec<i64> = (1..=9)
        .map(|attempt| policy.wait_after(attempt).whole_seconds())
        .collect();
    assert_eq!(waits, [30, 60, 120, 240, 480, 960, 1_920, 3_600, 3_600]);
    for (attempts, wait) in [
        (0, Duration::seconds(1)),
        (21, Duration::seconds(1)),
        (3, Duration::ZERO),
        (3, Duration::hours(2)),
    ] {
        assert_eq!(
            LogoutRetryPolicy::new(attempts, wait)
                .expect_err("refused")
                .code(),
            "oauth.logout_retry_policy_invalid"
        );
    }
}

#[test]
fn a_delivery_is_retried_with_growing_waits_then_set_aside() {
    let policy = LogoutRetryPolicy::new(3, Duration::seconds(10)).expect("policy");
    let mut delivery = delivery();
    let mut now = NOW;
    let mut waits = Vec::new();
    for _ in 0..2 {
        delivery
            .lease(now, now + Duration::minutes(1))
            .expect("due");
        assert!(delivery.is_leased(now));
        assert!(!delivery.is_due(now));
        assert!(delivery.is_as_leased(delivery.snapshot().attempts));
        assert!(
            delivery
                .record_failure(now, Some(400), "the client answered 400", &policy)
                .is_none()
        );
        waits.push(delivery.snapshot().next_attempt_at - now);
        now = delivery.snapshot().next_attempt_at;
        assert!(delivery.is_due(now));
    }
    assert_eq!(waits, [Duration::seconds(10), Duration::seconds(20)]);
    delivery
        .lease(now, now + Duration::minutes(1))
        .expect("due");
    let event = delivery
        .record_failure(now, None, "http.timed_out", &policy)
        .expect("set aside");
    assert_eq!(delivery.status(), LogoutDeliveryStatus::SetAside);
    assert_eq!(delivery.snapshot().finished_at, Some(now));
    assert!(matches!(
        event,
        OauthEvent::BackchannelLogoutSetAside { attempts: 3, .. }
    ));
    assert!(!delivery.is_due(now + Duration::days(1)));
}

#[test]
fn a_delivered_one_is_finished_and_a_lease_that_ran_out_is_taken_again() {
    let mut delivery = delivery();
    delivery
        .lease(NOW, NOW + Duration::seconds(70))
        .expect("due");
    assert!(delivery.lease(NOW + Duration::seconds(69), NOW).is_err());
    assert!(delivery.is_due(NOW + Duration::seconds(70)));
    assert!(!delivery.is_as_leased(1));
    delivery.record_success(NOW, 200);
    assert_eq!(delivery.status(), LogoutDeliveryStatus::Delivered);
    assert_eq!(delivery.snapshot().attempts, 1);
    assert_eq!(delivery.snapshot().last_response_status, Some(200));
    assert!(!delivery.is_due(NOW + Duration::days(1)));
}

#[test]
fn a_delivery_set_aside_at_once_keeps_a_short_reason() {
    let mut delivery = delivery();
    let event = delivery.set_aside(NOW, &"é".repeat(800));
    assert!(matches!(
        event,
        OauthEvent::BackchannelLogoutSetAside { attempts: 0, .. }
    ));
    assert_eq!(
        delivery
            .snapshot()
            .last_error
            .as_deref()
            .map(|reason| reason.chars().count()),
        Some(MAX_LOGOUT_ERROR_LENGTH)
    );
    assert!(
        LogoutDeliveryStatus::ALL
            .iter()
            .all(|status| LogoutDeliveryStatus::from_name(status.as_str()) == Some(*status))
    );
}
