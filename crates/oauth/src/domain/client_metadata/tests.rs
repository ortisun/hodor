use super::*;
use crate::domain::application::ApplicationId;
use crate::domain::client::ClientType;
use crate::domain::key::ClientKey;
use hodor_kernel::Timestamp;
use hodor_kernel::random::testing::{CountingRandom, FakeDigest};
use time::Duration;

fn policy() -> RegistrationPolicy {
    RegistrationPolicy::default()
}

fn read(body: Value) -> Result<ClientMetadata, DomainError> {
    read_client_metadata(&body, &policy())
}

fn code(result: Result<ClientMetadata, DomainError>) -> String {
    result.expect_err("refused").code().to_owned()
}

fn minimal() -> Value {
    json!({ "redirect_uris": ["https://portal.partner.example/callback"] })
}

fn with(member: &str, value: Value) -> Value {
    let mut body = minimal();
    body[member] = value;
    body
}

fn p256(kid: &str) -> Value {
    json!({
        "kty": "EC", "crv": "P-256", "kid": kid,
        "x": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        "y": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"
    })
}

#[test]
fn a_member_left_out_takes_the_default_of_its_specification() {
    let read = read(minimal()).expect("read");
    assert_eq!(read.client_type, ClientType::Confidential);
    assert_eq!(read.settings.response_types, vec![ResponseType::Code]);
    let settings = &read.settings;
    assert_eq!(settings.name, DEFAULT_REGISTERED_CLIENT_NAME);
    assert_eq!(
        settings.authentication_method,
        AuthenticationMethod::ClientSecretBasic
    );
    assert_eq!(settings.grant_types, vec![GrantType::AuthorizationCode]);
    assert_eq!(settings.application_type, Some(ApplicationType::Web));
    // OpenID Connect Registration's default, not Hodor's own `ES256`.
    assert_eq!(settings.id_token_algorithm, IdTokenAlgorithm::Rs256);
    assert_eq!(settings.userinfo_algorithm, None);
    assert_eq!(settings.request_object_algorithm, None);
    assert_eq!(settings.subject_type, SubjectType::Public);
    // No `scope`: every scope the policy allows.
    assert_eq!(settings.allowed_scopes, policy().scopes);
    assert!(settings.require_pkce);
    assert!(!settings.require_auth_time);
    assert!(!settings.certificate_bound_access_tokens);
    assert!(read.keys.is_empty());
    settings
        .clone()
        .checked(read.client_type)
        .expect("a client by the rules of every client");
}

#[test]
fn every_member_hodor_keeps_becomes_a_setting() {
    let read = read(json!({
        "redirect_uris": ["https://portal.partner.example/callback"],
        "post_logout_redirect_uris": ["https://portal.partner.example/signed-out"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "application_type": "web",
        "client_name": "Partner portal",
        "client_uri": "https://portal.partner.example",
        "logo_uri": "https://portal.partner.example/logo.png",
        "policy_uri": "https://portal.partner.example/privacy",
        "tos_uri": "https://portal.partner.example/terms",
        "token_endpoint_auth_method": "private_key_jwt",
        "token_endpoint_auth_signing_alg": "ES256",
        "jwks": { "keys": [p256("one")] },
        "scope": "openid  email",
        "subject_type": "pairwise",
        "sector_identifier_uri": "https://portal.partner.example/sector.json",
        "id_token_signed_response_alg": "ES256",
        "userinfo_signed_response_alg": "PS256",
        "request_object_signing_alg": "RS256",
        "default_max_age": 3600,
        "default_acr_values": ["silver"],
        "require_auth_time": true,
        "backchannel_logout_uri": "https://portal.partner.example/logout",
        "backchannel_logout_session_required": true,
        "tls_client_certificate_bound_access_tokens": true,
        "request_uris": ["https://portal.partner.example/requests/"],
        "require_pushed_authorization_requests": true
    }))
    .expect("read");
    let settings = &read.settings;
    assert_eq!(
        settings.request_uris,
        vec!["https://portal.partner.example/requests/"]
    );
    assert!(settings.require_pushed_requests);
    assert_eq!(settings.name, "Partner portal");
    assert_eq!(
        settings.post_logout_redirect_uris,
        vec!["https://portal.partner.example/signed-out"]
    );
    assert_eq!(
        settings.grant_types,
        vec![GrantType::AuthorizationCode, GrantType::RefreshToken]
    );
    assert_eq!(
        settings.authentication_method,
        AuthenticationMethod::PrivateKeyJwt
    );
    assert_eq!(settings.allowed_scopes, vec!["openid", "email"]);
    assert_eq!(settings.subject_type, SubjectType::Pairwise);
    assert_eq!(settings.id_token_algorithm, IdTokenAlgorithm::Es256);
    assert_eq!(settings.userinfo_algorithm, Some(IdTokenAlgorithm::Ps256));
    assert_eq!(
        settings.request_object_algorithm,
        Some(RequestObjectAlgorithm::Rs256)
    );
    assert_eq!(settings.default_max_age, Some(3600));
    assert_eq!(settings.default_acr_values, vec!["silver"]);
    assert!(settings.require_auth_time);
    assert!(settings.backchannel_logout_session_required);
    assert!(settings.certificate_bound_access_tokens);
    assert_eq!(
        settings.display_uris(),
        vec![
            ("client_uri", "https://portal.partner.example"),
            ("logo_uri", "https://portal.partner.example/logo.png"),
            ("policy_uri", "https://portal.partner.example/privacy"),
            ("tos_uri", "https://portal.partner.example/terms"),
        ]
    );
    assert_eq!(read.keys.len(), 1);
    settings
        .clone()
        .checked(read.client_type)
        .expect("a client by the rules of every client");
}

#[test]
fn none_makes_a_public_client() {
    let read = read(with("token_endpoint_auth_method", json!("none"))).expect("read");
    assert_eq!(read.client_type, ClientType::Public);
    assert_eq!(
        read.settings.authentication_method,
        AuthenticationMethod::None
    );
}

#[test]
fn null_is_taken_as_left_out() {
    let read = read(json!({
        "redirect_uris": ["https://portal.partner.example/callback"],
        "client_name": null,
        "logo_uri": null,
        "token_endpoint_auth_method": null
    }))
    .expect("read");
    assert_eq!(read.settings.name, DEFAULT_REGISTERED_CLIENT_NAME);
    assert_eq!(read.settings.logo_uri, None);
}

#[test]
fn members_hodor_does_not_keep_are_ignored() {
    let read = read(json!({
        "redirect_uris": ["https://portal.partner.example/callback"],
        "contacts": ["ops@partner.example"],
        "software_id": "4NRB1-0XZABZI9E6-5SM3R",
        "software_version": "2.1",
        "initiate_login_uri": "https://portal.partner.example/login",
        "frontchannel_logout_uri": "https://portal.partner.example/front",
        "client_name#ja-Jpan-JP": "クライアント名",
        "spiffe_id": "spiffe://cluster.local/ns/a/sa/b",
        "something_else": { "deep": true }
    }))
    .expect("read");
    assert_eq!(read.settings.name, DEFAULT_REGISTERED_CLIENT_NAME);
    assert_eq!(read.settings.spiffe_id, None);
}

#[test]
fn a_member_hodor_would_need_and_does_not_have_is_refused() {
    for member in NOT_SUPPORTED {
        let refused =
            read(with(member, json!("https://portal.partner.example/x"))).expect_err(member);
        assert_eq!(refused.code(), "oauth.registration_member_not_supported");
        assert_eq!(refused.detail(), Some(format!("`{member}`").as_str()));
    }
    let both = json!({
        "redirect_uris": ["https://portal.partner.example/callback"],
        "token_endpoint_auth_method": "private_key_jwt",
        "jwks": { "keys": [p256("one")] },
        "jwks_uri": "https://portal.partner.example/jwks"
    });
    assert_eq!(code(read(both)), "oauth.client_metadata_invalid");
}

#[test]
fn a_member_of_the_wrong_kind_is_refused_by_name() {
    for (member, value) in [
        (
            "redirect_uris",
            json!("https://portal.partner.example/callback"),
        ),
        ("grant_types", json!([1])),
        ("client_name", json!(7)),
        (
            "logo_uri",
            json!(["https://portal.partner.example/logo.png"]),
        ),
        ("require_auth_time", json!("yes")),
        ("default_max_age", json!(-1)),
        ("default_max_age", json!(1.5)),
        ("scope", json!(["openid"])),
        ("jwks", json!([p256("one")])),
    ] {
        let refused = read(with(member, value)).expect_err(member);
        assert_eq!(refused.code(), "oauth.client_metadata_invalid", "{member}");
        assert!(
            refused
                .detail()
                .is_some_and(|detail| detail.contains(member)),
            "{member}: {:?}",
            refused.detail()
        );
    }
    assert_eq!(
        code(read_client_metadata(
            &json!(["not", "an", "object"]),
            &policy()
        )),
        "oauth.client_metadata_invalid"
    );
    assert_eq!(
        code(read_client_metadata(&Value::Null, &policy())),
        "oauth.client_metadata_invalid"
    );
}

#[test]
fn response_types_are_kept_by_the_rules_of_every_client() {
    let browser = read(with(
        "response_types",
        json!(["id_token", "code id_token", "code"]),
    ))
    .expect("read");
    let checked = browser
        .settings
        .checked(browser.client_type)
        .expect("a client by the rules of every client");
    assert_eq!(
        checked.response_types,
        vec![
            ResponseType::Code,
            ResponseType::IdToken,
            ResponseType::CodeIdToken
        ]
    );
    // `implicit`, which a client of `id_token` names, is the code grant.
    let implicit = read(json!({
        "redirect_uris": ["https://portal.partner.example/callback"],
        "grant_types": ["implicit"],
        "response_types": ["id_token"]
    }))
    .expect("read");
    assert_eq!(
        implicit.settings.grant_types,
        vec![GrantType::AuthorizationCode]
    );
    // A type that returns an access token needs an administrator's mark,
    // which a registered client never has (Decision 0083).
    for refused in ["id_token token", "code token", "token", "anything"] {
        assert_eq!(
            code(read(with("response_types", json!([refused])))),
            "oauth.client_response_types_invalid",
            "{refused}"
        );
    }
    // None at all, or some without the code grant, break the client's rules.
    for body in [
        with("response_types", json!([])),
        json!({ "grant_types": ["client_credentials"], "response_types": ["code"] }),
    ] {
        let read = read(body).expect("read");
        assert_eq!(
            read.settings
                .checked(read.client_type)
                .expect_err("refused")
                .code(),
            "oauth.client_response_types_invalid"
        );
    }
}

#[test]
fn the_signing_algorithm_of_assertions_is_checked_and_not_kept() {
    let assertion = |algorithm: &str, method: &str| {
        json!({
            "redirect_uris": ["https://portal.partner.example/callback"],
            "token_endpoint_auth_method": method,
            "token_endpoint_auth_signing_alg": algorithm,
            "jwks": { "keys": [p256("one")] }
        })
    };
    read(assertion("PS256", "private_key_jwt")).expect("one Hodor accepts");
    assert_eq!(
        code(read(assertion("HS256", "private_key_jwt"))),
        "oauth.client_metadata_invalid"
    );
    let mut secret = assertion("ES256", "client_secret_basic");
    secret.as_object_mut().expect("object").remove("jwks");
    assert_eq!(code(read(secret)), "oauth.client_metadata_invalid");
}

#[test]
fn a_client_of_private_key_jwt_registers_its_keys_by_value_or_at_its_address() {
    assert_eq!(
        code(read(with(
            "token_endpoint_auth_method",
            json!("private_key_jwt")
        ))),
        "oauth.client_metadata_invalid"
    );
    let at_its_address = read(json!({
        "redirect_uris": ["https://portal.partner.example/callback"],
        "token_endpoint_auth_method": "private_key_jwt",
        "jwks_uri": "https://portal.partner.example/jwks"
    }))
    .expect("read");
    assert!(at_its_address.keys.is_empty());
    assert_eq!(
        at_its_address.settings.jwks_uri.as_deref(),
        Some("https://portal.partner.example/jwks")
    );
    at_its_address
        .settings
        .checked(at_its_address.client_type)
        .expect("a client by the rules of every client");
    let (client, _) = registered(json!({
        "redirect_uris": ["https://portal.partner.example/callback"],
        "token_endpoint_auth_method": "private_key_jwt",
        "jwks_uri": "https://portal.partner.example/jwks"
    }));
    let answer = registration_answer(&client, None);
    assert_eq!(answer["jwks_uri"], "https://portal.partner.example/jwks");
    assert!(answer.get("jwks").is_none());
}

#[test]
fn names_hodor_does_not_know_are_refused_with_their_own_codes() {
    for (member, value, expected) in [
        (
            "grant_types",
            json!(["password"]),
            "oauth.client_grants_invalid",
        ),
        (
            "application_type",
            json!("desktop"),
            "oauth.client_application_type_invalid",
        ),
        (
            "subject_type",
            json!("anonymous"),
            "oauth.client_subject_type_invalid",
        ),
        (
            "id_token_signed_response_alg",
            json!("none"),
            "oauth.client_id_token_algorithm_invalid",
        ),
    ] {
        assert_eq!(code(read(with(member, value))), expected, "{member}");
    }
}

#[test]
fn a_software_statement_is_seen_and_refused() {
    assert!(has_software_statement(&with(
        "software_statement",
        json!("eyJ...")
    )));
    assert!(!has_software_statement(&with(
        "software_statement",
        Value::Null
    )));
    assert!(!has_software_statement(&minimal()));
    assert_eq!(
        software_statement_unapproved().code(),
        "oauth.software_statement_unapproved"
    );
}

#[test]
fn a_web_client_has_https_redirect_addresses_only() {
    for address in [
        "http://127.0.0.1:8080/callback",
        "com.example.app:/callback",
    ] {
        let web = read(json!({
            "redirect_uris": [address],
            "token_endpoint_auth_method": "none"
        }))
        .expect("read");
        assert_eq!(
            web.settings
                .checked(web.client_type)
                .expect_err(address)
                .code(),
            "oauth.client_application_type_invalid"
        );
        let native = read_client_metadata(
            &json!({
                "redirect_uris": [address],
                "token_endpoint_auth_method": "none",
                "application_type": "native"
            }),
            &policy(),
        )
        .expect("read");
        native
            .settings
            .checked(native.client_type)
            .expect("a native client may");
    }
}

#[test]
fn an_address_a_person_is_shown_is_https_with_a_host() {
    for address in [
        "http://portal.partner.example/logo.png",
        "https://",
        "https://user:pass@portal.partner.example/logo.png",
        "https://portal.partner.example/logo.png#top",
        "https://portal.partner.example/a logo.png",
        "javascript:alert(1)",
        "data:image/png;base64,AAAA",
    ] {
        let logo = read(with("logo_uri", json!(address))).expect("read");
        let refused = logo.settings.checked(logo.client_type).expect_err(address);
        assert_eq!(
            refused.code(),
            "oauth.client_display_uri_invalid",
            "{address}"
        );
        assert!(
            refused
                .detail()
                .is_some_and(|detail| detail.starts_with("`logo_uri`")),
            "{address}"
        );
    }
    let long = format!("https://portal.partner.example/{}", "a".repeat(2000));
    let too_long = read(with("tos_uri", json!(long))).expect("read");
    assert_eq!(
        too_long
            .settings
            .checked(too_long.client_type)
            .expect_err("too long")
            .code(),
        "oauth.client_display_uri_invalid"
    );
    let with_port = read(with(
        "policy_uri",
        json!("https://[::1]:8443/privacy?lang=en"),
    ))
    .expect("read");
    with_port
        .settings
        .checked(with_port.client_type)
        .expect("a port, a path and a query are allowed");
}

fn registered(body: Value) -> (Client, Option<ClientSecretValue>) {
    let read = read(body).expect("read");
    let now = Timestamp::UNIX_EPOCH + Duration::days(20_000);
    let (mut client, secret) = Client::create(
        ApplicationId::generate(),
        read.client_type,
        read.settings,
        crate::domain::secret::ClientSecret::DEFAULT_LIFETIME,
        now,
        &CountingRandom::default(),
        &FakeDigest,
    )
    .expect("created");
    for jwk in &read.keys {
        client
            .add_key(ClientKey::parse(jwk, now).expect("key"), now)
            .expect("added");
    }
    (client, secret)
}

#[test]
fn the_answer_gives_back_every_member_kept_and_the_secret_once() {
    let (client, secret) = registered(json!({
        "redirect_uris": ["https://portal.partner.example/callback"],
        "client_name": "Partner portal",
        "logo_uri": "https://portal.partner.example/logo.png",
        "contacts": ["ops@partner.example"]
    }));
    let answer = registration_answer(&client, secret.as_ref());
    let state = client.snapshot();
    assert_eq!(answer["client_id"], state.id.to_string());
    assert_eq!(
        answer["client_id_issued_at"],
        state.created_at.unix_timestamp()
    );
    assert_eq!(
        answer["client_secret"],
        secret.as_ref().expect("a secret").expose()
    );
    assert_eq!(
        answer["client_secret_expires_at"],
        (state.created_at + Duration::days(365)).unix_timestamp()
    );
    assert_eq!(answer["client_name"], "Partner portal");
    assert_eq!(answer["application_type"], "web");
    assert_eq!(answer["grant_types"], json!(["authorization_code"]));
    assert_eq!(answer["response_types"], json!(["code"]));
    assert_eq!(answer["token_endpoint_auth_method"], "client_secret_basic");
    assert_eq!(answer["scope"], "openid profile email");
    assert_eq!(answer["subject_type"], "public");
    assert_eq!(answer["id_token_signed_response_alg"], "RS256");
    assert_eq!(answer["require_auth_time"], false);
    assert_eq!(
        answer["logo_uri"],
        "https://portal.partner.example/logo.png"
    );
    assert_eq!(answer["require_pushed_authorization_requests"], false);
    // Nothing that was not kept, nothing without a value.
    for left_out in [
        "contacts",
        "jwks",
        "policy_uri",
        "post_logout_redirect_uris",
        "default_acr_values",
        "userinfo_signed_response_alg",
        "backchannel_logout_uri",
        "registration_access_token",
        "request_uris",
    ] {
        assert!(answer.get(left_out).is_none(), "{left_out}");
    }
    // The answer without the secret, as Hodor could give it later.
    let again = registration_answer(&client, None);
    assert!(again.get("client_secret").is_none());
    assert!(again.get("client_secret_expires_at").is_none());
}

#[test]
fn the_answer_of_a_client_with_keys_gives_them_back() {
    let (client, secret) = registered(json!({
        "redirect_uris": ["https://portal.partner.example/callback"],
        "token_endpoint_auth_method": "private_key_jwt",
        "jwks": { "keys": [p256("one")] }
    }));
    assert!(secret.is_none());
    let answer = registration_answer(&client, None);
    assert_eq!(answer["jwks"]["keys"][0]["kid"], "one");
    assert_eq!(answer["token_endpoint_auth_method"], "private_key_jwt");
}
