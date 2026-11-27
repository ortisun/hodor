use super::*;
use crate::domain::response::ResponseType;
use time::Duration;

fn moment() -> Timestamp {
    Timestamp::UNIX_EPOCH + Duration::days(20_000)
}

fn texts(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn on() -> RegistrationSettings {
    RegistrationSettings {
        enabled: true,
        application_id: Some(ApplicationId::generate()),
        ..RegistrationSettings::default()
    }
}

fn refused_policy(policy: RegistrationPolicy) -> String {
    let error = policy.checked().expect_err("refused");
    assert_eq!(error.code(), "oauth.client_registration_policy_invalid");
    error.detail().unwrap_or_default().to_owned()
}

#[test]
fn a_tenant_that_never_set_them_reads_as_off_with_the_defaults() {
    let settings = RegistrationSettings::default();
    assert!(!settings.enabled);
    assert_eq!(settings.application_id, None);
    assert_eq!(settings.ways, [RegistrationWay::InitialAccessToken]);
    assert_eq!(settings.max_clients, 100);
    for way in RegistrationWay::ALL {
        assert!(!settings.allows(way), "{way:?}");
    }
    let policy = &settings.policy;
    assert_eq!(policy.grant_types, [GrantType::AuthorizationCode]);
    assert_eq!(policy.response_types, [ResponseType::Code]);
    assert_eq!(policy.scopes, ["openid", "profile", "email"]);
    assert_eq!(
        policy.authentication_methods,
        [
            AuthenticationMethod::ClientSecretBasic,
            AuthenticationMethod::PrivateKeyJwt
        ]
    );
    assert_eq!(policy.subject_types, [SubjectType::Public]);
    assert_eq!(policy.hosts, None);
    assert_eq!(settings.clone().checked().expect("valid"), settings);
}

#[test]
fn registration_on_names_an_application_and_a_way() {
    let settings = on();
    assert!(settings.allows(RegistrationWay::InitialAccessToken));
    assert!(!settings.allows(RegistrationWay::Open));
    let error = RegistrationSettings {
        application_id: None,
        ..on()
    }
    .checked()
    .expect_err("no application");
    assert_eq!(
        error.code(),
        "oauth.client_registration_application_invalid"
    );
    let error = RegistrationSettings {
        ways: Vec::new(),
        ..on()
    }
    .checked()
    .expect_err("no way");
    assert_eq!(error.code(), "oauth.client_registration_ways_invalid");
    // Off, neither is needed.
    assert!(
        RegistrationSettings {
            enabled: false,
            application_id: None,
            ways: Vec::new(),
            ..on()
        }
        .checked()
        .is_ok()
    );
}

#[test]
fn ways_are_kept_once_in_the_order_given_and_read_by_name() {
    let settings = RegistrationSettings {
        ways: vec![
            RegistrationWay::Open,
            RegistrationWay::InitialAccessToken,
            RegistrationWay::Open,
        ],
        ..on()
    }
    .checked()
    .expect("valid");
    assert_eq!(settings.way_names(), ["open", "initial_access_token"]);
    for way in RegistrationWay::ALL {
        assert_eq!(RegistrationWay::parse(way.as_str()).expect("known"), way);
    }
    assert_eq!(
        RegistrationWay::parse("anyone")
            .expect_err("unknown")
            .code(),
        "oauth.client_registration_ways_invalid"
    );
    assert_eq!(
        ways_from_stored(&texts(&["software_statement"])).expect("stored"),
        [RegistrationWay::SoftwareStatement]
    );
    assert_eq!(
        ways_from_stored(&texts(&["anyone"]))
            .expect_err("corrupted")
            .code(),
        "oauth.stored_data_invalid"
    );
}

#[test]
fn the_application_of_registered_clients_holds_one_to_a_thousand_clients() {
    for max_clients in [1, 1000] {
        assert!(
            RegistrationSettings {
                max_clients,
                ..on()
            }
            .checked()
            .is_ok()
        );
    }
    for max_clients in [0, 1001] {
        assert_eq!(
            RegistrationSettings {
                max_clients,
                ..on()
            }
            .checked()
            .expect_err("refused")
            .code(),
            "oauth.client_registration_most_clients_invalid"
        );
    }
}

#[test]
fn a_policy_never_allows_the_grants_of_workloads() {
    for grant in [GrantType::ClientCredentials, GrantType::TokenExchange] {
        let detail = refused_policy(RegistrationPolicy {
            grant_types: vec![GrantType::AuthorizationCode, grant],
            ..RegistrationPolicy::default()
        });
        assert!(detail.contains("client_credentials"), "{detail}");
    }
    refused_policy(RegistrationPolicy {
        grant_types: Vec::new(),
        ..RegistrationPolicy::default()
    });
    refused_policy(RegistrationPolicy {
        grant_types: vec![GrantType::RefreshToken],
        ..RegistrationPolicy::default()
    });
    let policy = RegistrationPolicy {
        grant_types: vec![
            GrantType::AuthorizationCode,
            GrantType::RefreshToken,
            GrantType::AuthorizationCode,
        ],
        ..RegistrationPolicy::default()
    }
    .checked()
    .expect("valid");
    assert_eq!(
        policy.grant_types,
        [GrantType::AuthorizationCode, GrantType::RefreshToken]
    );
}

#[test]
fn a_policy_names_only_response_types_hodor_answers() {
    let policy = RegistrationPolicy {
        response_types: vec![ResponseType::Code, ResponseType::Code],
        ..RegistrationPolicy::default()
    }
    .checked()
    .expect("valid");
    assert_eq!(policy.response_types, [ResponseType::Code]);
    refused_policy(RegistrationPolicy {
        response_types: Vec::new(),
        ..RegistrationPolicy::default()
    });
    // The types of an ID token through the browser, in any order of their
    // words (Issue-127).
    let policy = RegistrationPolicy::from_json(&serde_json::json!({
        "response_types": ["code", "id_token", "id_token code", "none"]
    }))
    .expect("answered");
    assert_eq!(
        policy.response_types,
        [
            ResponseType::Code,
            ResponseType::IdToken,
            ResponseType::CodeIdToken,
            ResponseType::None
        ]
    );
    for bad in ["token", "id_token token", "Code", "device_code", ""] {
        let detail = RegistrationPolicy::from_json(&serde_json::json!({ "response_types": [bad] }))
            .expect_err("not answered")
            .detail()
            .unwrap_or_default()
            .to_owned();
        assert!(detail.contains("response type"), "{bad}: {detail}");
    }
}

#[test]
fn a_policy_lists_one_to_fifty_scopes_written_as_scopes_are() {
    let fifty: Vec<String> = (0..50).map(|n| format!("scope:{n}")).collect();
    assert!(
        RegistrationPolicy {
            scopes: fifty.clone(),
            ..RegistrationPolicy::default()
        }
        .checked()
        .is_ok()
    );
    let mut fifty_one = fifty;
    fifty_one.push("one:more".to_owned());
    for scopes in [
        Vec::new(),
        fifty_one,
        texts(&["with space"]),
        texts(&["a\"b"]),
    ] {
        refused_policy(RegistrationPolicy {
            scopes,
            ..RegistrationPolicy::default()
        });
    }
}

#[test]
fn a_policy_never_allows_the_methods_of_workloads() {
    for method in [
        AuthenticationMethod::SpiffeJwt,
        AuthenticationMethod::TlsClientAuth,
        AuthenticationMethod::SpiffeX509,
        AuthenticationMethod::LinkerdIdentity,
    ] {
        let detail = refused_policy(RegistrationPolicy {
            authentication_methods: vec![method],
            ..RegistrationPolicy::default()
        });
        assert!(detail.contains(method.as_str()), "{detail}");
    }
    refused_policy(RegistrationPolicy {
        authentication_methods: Vec::new(),
        ..RegistrationPolicy::default()
    });
    assert!(
        RegistrationPolicy {
            authentication_methods: REGISTERABLE_METHODS.to_vec(),
            ..RegistrationPolicy::default()
        }
        .checked()
        .is_ok()
    );
    refused_policy(RegistrationPolicy {
        subject_types: Vec::new(),
        ..RegistrationPolicy::default()
    });
}

#[test]
fn a_policy_allows_any_host_or_lists_hosts_in_lowercase_without_a_port() {
    for good in [
        "example.com",
        "app.example.com",
        "127.0.0.1",
        "[::1]",
        "[2001:db8::1]",
        "xn--bcher-kva.example",
    ] {
        assert!(is_policy_host(good), "{good}");
    }
    for bad in [
        "",
        "Example.com",
        "example.com:443",
        "https://example.com",
        "example..com",
        ".example.com",
        "*.example.com",
        "[]",
        "[::G]",
        &format!("{}.com", "a".repeat(64)),
        &"a.".repeat(127),
    ] {
        assert!(!is_policy_host(bad), "{bad}");
    }
    refused_policy(RegistrationPolicy {
        hosts: Some(Vec::new()),
        ..RegistrationPolicy::default()
    });
    refused_policy(RegistrationPolicy {
        hosts: Some((0..51).map(|n| format!("h{n}.example.com")).collect()),
        ..RegistrationPolicy::default()
    });
    refused_policy(RegistrationPolicy {
        hosts: Some(texts(&["Example.com"])),
        ..RegistrationPolicy::default()
    });
}

#[test]
fn a_policy_reads_back_what_it_writes_and_takes_defaults_for_what_is_left_out() {
    let policy = RegistrationPolicy {
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        response_types: vec![ResponseType::Code],
        scopes: texts(&["openid", "offline_access"]),
        authentication_methods: vec![AuthenticationMethod::None],
        subject_types: vec![SubjectType::Pairwise, SubjectType::Public],
        hosts: Some(texts(&["app.example.com"])),
    };
    let written = policy.to_json();
    assert_eq!(
        written,
        serde_json::json!({
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scopes": ["openid", "offline_access"],
            "token_endpoint_auth_methods": ["none"],
            "subject_types": ["pairwise", "public"],
            "hosts": ["app.example.com"],
        })
    );
    assert_eq!(
        RegistrationPolicy::from_json(&written).expect("read"),
        policy
    );
    assert_eq!(
        RegistrationPolicy::from_json(&serde_json::json!({})).expect("defaults"),
        RegistrationPolicy::default()
    );
    assert_eq!(
        RegistrationPolicy::from_json(&serde_json::json!({ "hosts": null }))
            .expect("any host")
            .hosts,
        None
    );
    for bad in [
        serde_json::json!([]),
        serde_json::json!({ "grants": ["authorization_code"] }),
        serde_json::json!({ "grant_types": "authorization_code" }),
        serde_json::json!({ "grant_types": ["implicit"] }),
        serde_json::json!({ "token_endpoint_auth_methods": ["client_secret_jwt"] }),
        serde_json::json!({ "subject_types": ["ephemeral"] }),
        serde_json::json!({ "scopes": [1] }),
        serde_json::json!({ "hosts": "example.com" }),
    ] {
        assert_eq!(
            RegistrationPolicy::from_json(&bad)
                .expect_err("refused")
                .code(),
            "oauth.client_registration_policy_invalid",
            "{bad}"
        );
    }
}

fn a_request<'a>(
    grants: &'a [GrantType],
    response_types: &'a [ResponseType],
    scopes: &'a [String],
    addresses: &'a [&'a str],
) -> RegistrationRequest<'a> {
    RegistrationRequest {
        grant_types: grants,
        response_types,
        scopes,
        authentication_method: AuthenticationMethod::ClientSecretBasic,
        subject_type: SubjectType::Public,
        addresses,
    }
}

#[test]
fn a_registration_within_the_policy_is_allowed() {
    let policy = RegistrationPolicy {
        hosts: Some(texts(&["app.example.com", "[::1]"])),
        ..RegistrationPolicy::default()
    };
    let response_types = [ResponseType::Code];
    let scopes = texts(&["openid", "email"]);
    let request = a_request(
        &[GrantType::AuthorizationCode],
        &response_types,
        &scopes,
        &[
            "https://app.example.com/callback",
            "https://APP.example.com:8443/logo.png",
            "http://[::1]:8080/callback",
        ],
    );
    check_registration(&policy, &request).expect("allowed");
}

#[test]
fn each_limit_of_the_policy_refuses_what_it_does_not_list() {
    let policy = RegistrationPolicy {
        hosts: Some(texts(&["app.example.com"])),
        ..RegistrationPolicy::default()
    };
    let code = [ResponseType::Code];
    let openid = texts(&["openid"]);
    let callback = ["https://app.example.com/callback"];
    let refused = |request: RegistrationRequest<'_>| {
        check_registration(&policy, &request)
            .expect_err("refused")
            .code()
            .to_owned()
    };
    assert_eq!(
        refused(a_request(
            &[GrantType::ClientCredentials],
            &code,
            &openid,
            &callback
        )),
        "oauth.registration_grant_not_allowed"
    );
    assert_eq!(
        refused(a_request(
            &[GrantType::AuthorizationCode, GrantType::RefreshToken],
            &code,
            &openid,
            &callback
        )),
        "oauth.registration_grant_not_allowed"
    );
    // A policy that lists none of a request's types refuses them; with one
    // type Hodor answers, a policy allows it or none at all.
    let none_allowed = RegistrationPolicy {
        response_types: Vec::new(),
        ..policy.clone()
    };
    assert_eq!(
        check_registration(
            &none_allowed,
            &a_request(&[GrantType::AuthorizationCode], &code, &openid, &callback)
        )
        .expect_err("refused")
        .code(),
        "oauth.registration_response_type_not_allowed"
    );
    for scope in ["groups", "offline_access", "invoices:read"] {
        let scopes = texts(&["openid", scope]);
        assert_eq!(
            refused(a_request(
                &[GrantType::AuthorizationCode],
                &code,
                &scopes,
                &callback
            )),
            "oauth.registration_scope_not_allowed",
            "{scope}"
        );
    }
    for method in [
        AuthenticationMethod::None,
        AuthenticationMethod::ClientSecretPost,
        AuthenticationMethod::SpiffeJwt,
    ] {
        assert_eq!(
            refused(RegistrationRequest {
                authentication_method: method,
                ..a_request(&[GrantType::AuthorizationCode], &code, &openid, &callback)
            }),
            "oauth.registration_method_not_allowed",
            "{method:?}"
        );
    }
    assert_eq!(
        refused(RegistrationRequest {
            subject_type: SubjectType::Pairwise,
            ..a_request(&[GrantType::AuthorizationCode], &code, &openid, &callback)
        }),
        "oauth.registration_subject_type_not_allowed"
    );
    for address in [
        "https://evil.example.com/callback",
        "https://sub.app.example.com/callback",
        "https://app.example.com.evil.example/callback",
        "https://app.example.com@evil.example/callback",
        "com.example.app:/callback",
    ] {
        let detail = check_registration(
            &policy,
            &a_request(
                &[GrantType::AuthorizationCode],
                &code,
                &openid,
                &["https://app.example.com/callback", address],
            ),
        )
        .expect_err("refused");
        assert_eq!(detail.code(), "oauth.registration_host_not_allowed");
        assert!(
            detail.detail().unwrap_or_default().contains(address),
            "{detail:?}"
        );
    }
}

#[test]
fn any_host_allows_an_address_without_one() {
    let policy = RegistrationPolicy::default();
    let code = [ResponseType::Code];
    let openid = texts(&["openid"]);
    check_registration(
        &policy,
        &a_request(
            &[GrantType::AuthorizationCode],
            &code,
            &openid,
            &["com.example.app:/callback", "https://anywhere.example/"],
        ),
    )
    .expect("any host");
}

#[test]
fn settings_are_replaced_as_a_whole_and_the_same_settings_change_nothing() {
    let first = on();
    let (mut registration, event) =
        ClientRegistration::create(first.clone(), moment()).expect("valid");
    assert_eq!(
        event,
        OauthEvent::ClientRegistrationChanged {
            enabled: true,
            application_id: first.application_id,
            ways: vec!["initial_access_token"],
            max_clients: 100,
            policy: RegistrationPolicy::default().to_json(),
        }
    );
    assert_eq!(registration.snapshot().version, 0);
    assert_eq!(
        registration
            .replace(first.clone(), moment() + Duration::hours(1))
            .expect("valid"),
        None
    );
    assert_eq!(registration.snapshot().updated_at, moment());
    let off = RegistrationSettings {
        enabled: false,
        ..first
    };
    let event = registration
        .replace(off.clone(), moment() + Duration::hours(1))
        .expect("valid")
        .expect("changed");
    assert!(matches!(
        event,
        OauthEvent::ClientRegistrationChanged { enabled: false, .. }
    ));
    assert_eq!(registration.settings(), &off);
    assert_eq!(
        registration.snapshot().updated_at,
        moment() + Duration::hours(1)
    );
    let error = registration
        .replace(
            RegistrationSettings {
                max_clients: 0,
                ..off.clone()
            },
            moment(),
        )
        .expect_err("refused");
    assert_eq!(
        error.code(),
        "oauth.client_registration_most_clients_invalid"
    );
    assert_eq!(
        registration.settings(),
        &off,
        "a refused change changes nothing"
    );
}
