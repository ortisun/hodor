//! An application asks the real server binary for an authorization code
//! over HTTP, against a real database, and a person signs in on the way.

use hodor_adapters_crypto::{
    Argon2Parameters, Argon2idHasher, HashingLimits, OsRandom, Sha256Digest,
};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgApplicationStore, PgAuthorizationCodeStore, PgAuthorizationRequestStore, PgClientStore,
    PgGrantStore, PgInvitationRepository, PgOrganizationRepository, PgPasswordStore,
    PgResourceServerStore, PgTenantDirectory, PgTenantRepository, PgUserRepository,
};
use hodor_credential::api::{CredentialService, NewPassword, PasswordRules};
use hodor_identity::api::{
    CreateUser, IdentifierKind, IdentityService, OrganizationService, Profile, UserKind,
};
use hodor_kernel::{Caller, Secret, SystemClock, TenantContext};
use hodor_oauth::api::{
    ApplicationPorts, ApplicationService, ApplicationSettings, AuthorizationCodePorts,
    AuthorizationCodeService, ClientId, ClientSettings, ClientType, CodePresentation, CreateClient,
    CreateResourceServer, GrantType, ResourceServerSettings, ScopeDefinition, s256_challenge,
};
use hodor_oauth::testing::MembershipsOf;
use hodor_tenant::api::{CreateTenant, TenantService};
use reqwest::{Method, StatusCode};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

mod support;
use support::{Browser, MEMORY_KIBIBYTES, PASSES, start_server};

const PASSWORD: &str = "correct horse battery staple";
const REDIRECT: &str = "https://payroll.example.com/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const ISSUER: &str = "http://localhost:8080/t/acme";

/// A tenant with Ana, who has a password, and a first-party application
/// with a public client and a resource server. Returns the client.
async fn tenant_with_an_application(
    database: &TestDatabase,
    slug: &str,
) -> (TenantContext, ClientId) {
    let units = || Arc::new(database.app().clone());
    let clock = Arc::new(SystemClock);
    let tenants = TenantService::new(
        units(),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.app().clone())),
        clock.clone(),
    );
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
    let tenant = TenantContext::assume(created.id());
    let identity = IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone());
    let ana = identity
        .create(
            &tenant,
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
    let hasher = Argon2idHasher::new(
        Argon2Parameters {
            memory_kibibytes: MEMORY_KIBIBYTES,
            passes: PASSES,
            lanes: 1,
        },
        HashingLimits {
            concurrent: 2,
            queued: 8,
        },
        Arc::new(OsRandom),
    )
    .expect("hasher");
    let credentials = CredentialService::new(
        units(),
        Arc::new(PgPasswordStore),
        Arc::new(hasher),
        clock.clone(),
    );
    let password = Secret::from(PASSWORD.to_owned());
    credentials
        .set_password(
            &tenant,
            ana,
            NewPassword {
                password: &password,
                rules: PasswordRules {
                    min_length: 12,
                    max_length: 128,
                    history_depth: 5,
                },
                own_names: &[],
            },
            false,
            Caller::system(),
        )
        .await
        .expect("password");

    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: units(),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        digest: Arc::new(Sha256Digest),
        random: Arc::new(OsRandom),
        clock,
    });
    let application = applications
        .create_application(
            &tenant,
            ApplicationSettings {
                name: "Payroll".to_owned(),
                first_party: true,
            },
            Caller::system(),
        )
        .await
        .expect("application");
    let mut settings = ClientSettings::new(
        "Payroll web",
        ClientType::Public,
        vec![GrantType::AuthorizationCode],
        vec![REDIRECT.to_owned()],
    );
    settings.allowed_scopes = vec!["openid".to_owned(), "payroll:read".to_owned()];
    let (client, _) = applications
        .create_client(
            &tenant,
            CreateClient {
                application_id: application.id(),
                client_type: ClientType::Public,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client");
    applications
        .create_resource_server(
            &tenant,
            CreateResourceServer {
                application_id: application.id(),
                audience: "https://api.payroll.example.com".to_owned(),
                settings: ResourceServerSettings {
                    name: "Payroll interface".to_owned(),
                    scopes: vec![ScopeDefinition {
                        name: "payroll:read".to_owned(),
                        description: "reads payslips".to_owned(),
                    }],
                },
            },
            Caller::system(),
        )
        .await
        .expect("resource server");
    (tenant, client.id())
}

fn query(client_id: ClientId, extra: &[(&str, &str)]) -> String {
    let challenge = s256_challenge(VERIFIER, &Sha256Digest);
    let client_id = client_id.to_string();
    let mut parameters: Vec<(&str, &str)> = vec![
        ("response_type", "code"),
        ("client_id", &client_id),
        ("redirect_uri", REDIRECT),
        ("scope", "openid payroll:read"),
        ("state", "the state"),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
    ];
    for (name, value) in extra {
        parameters.retain(|(known, _)| known != name);
        if !value.is_empty() {
            parameters.push((name, value));
        }
    }
    form_urlencoded::Serializer::new(String::new())
        .extend_pairs(parameters)
        .finish()
}

/// The parameters a redirect to the client carries.
fn sent_back(location: &str) -> BTreeMap<String, String> {
    let (address, query) = location.split_once('?').expect("a query");
    assert_eq!(address, REDIRECT, "sent to the registered address only");
    form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect()
}

fn code_service(database: &TestDatabase) -> AuthorizationCodeService {
    AuthorizationCodeService::new(AuthorizationCodePorts {
        units_of_work: Arc::new(database.app().clone()),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        requests: Arc::new(PgAuthorizationRequestStore),
        grants: Arc::new(PgGrantStore),
        codes: Arc::new(PgAuthorizationCodeStore),
        memberships: Arc::new(MembershipsOf::default()),
        verifier: Arc::new(hodor_oauth::testing::FakeVerifier),
        digest: Arc::new(Sha256Digest),
        random: Arc::new(OsRandom),
        clock: Arc::new(SystemClock),
    })
}

#[tokio::test]
async fn an_application_gets_a_code_after_the_person_signs_in() {
    let database = TestDatabase::start().await;
    let (tenant, client_id) = tenant_with_an_application(&database, "acme").await;
    let server = start_server(&database).await;
    let mut browser = Browser::not_following(&server);

    // Nobody is signed in: the request is kept and the person sent to sign in.
    let (status, location, _) = browser
        .navigate(
            Method::GET,
            &format!("/t/acme/oauth2/authorize?{}", query(client_id, &[])),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        location.as_deref(),
        Some("/t/acme/account/sign-in?continue=authorization")
    );
    assert!(browser.cookies.contains_key("__Secure-hodor_authorization"));

    // The sign-in, as the pages do it, says where to continue.
    let (_, body) = browser.sign_in("acme", "ana@example.com", PASSWORD).await;
    assert_eq!(body["status"], "completed");
    assert_eq!(body["continue"], "/t/acme/oauth2/authorize/resume");

    // Coming back gives the client its code, with the state and the issuer.
    let (status, location, _) = browser
        .navigate(Method::GET, "/t/acme/oauth2/authorize/resume", None)
        .await;
    assert_eq!(status, StatusCode::FOUND);
    let answer = sent_back(&location.expect("a redirect"));
    assert_eq!(answer["state"], "the state");
    assert_eq!(answer["iss"], ISSUER);
    let code = answer["code"].clone();
    assert!(!browser.cookies.contains_key("__Secure-hodor_authorization"));

    // The pending request is gone: coming back again finds nothing.
    let (status, location, body) = browser
        .navigate(Method::GET, "/t/acme/oauth2/authorize/resume", None)
        .await;
    assert_eq!((status, location), (StatusCode::BAD_REQUEST, None));
    assert!(body.contains("oauth.authorization_request_not_found"));

    // A signed-in browser gets a code at once, by query or by form.
    let (status, location, _) = browser
        .navigate(
            Method::GET,
            &format!("/t/acme/oauth2/authorize?{}", query(client_id, &[])),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(sent_back(&location.expect("a redirect")).contains_key("code"));
    let (status, location, _) = browser
        .navigate(
            Method::POST,
            "/t/acme/oauth2/authorize",
            Some(&query(client_id, &[])),
        )
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(sent_back(&location.expect("a redirect")).contains_key("code"));

    // The code redeems once, with the verifier, for what was asked.
    let codes = code_service(&database);
    let presentation = CodePresentation {
        client_id,
        redirect_uri: Some(REDIRECT),
        verifier: Some(VERIFIER),
    };
    let redeemed = codes
        .redeem_code(&tenant, &code, presentation, Caller::system())
        .await
        .expect("redeemed");
    assert_eq!(redeemed.code.scopes, ["openid", "payroll:read"]);
    assert_eq!(redeemed.code.audiences, ["https://api.payroll.example.com"]);
    assert_eq!(redeemed.code.methods, ["password"]);
    let again = codes
        .redeem_code(&tenant, &code, presentation, Caller::system())
        .await
        .expect_err("twice");
    assert_eq!(again.detail(), Some("already_redeemed"));

    // Neither the code nor the secret of the pending request is stored.
    let everything: String = sqlx::query_scalar(
        r#"SELECT concat(
               (SELECT string_agg(to_jsonb(t)::text, '') FROM oauth.authorization_code t),
               (SELECT string_agg(to_jsonb(t)::text, '') FROM oauth.authorization_request t),
               (SELECT string_agg(to_jsonb(t)::text, '') FROM platform.outbox t))"#,
    )
    .fetch_one(database.owner())
    .await
    .expect("dump");
    assert!(!everything.contains(&code));
}

#[tokio::test]
async fn a_person_signs_in_for_an_organization_only_as_a_member() {
    let database = TestDatabase::start().await;
    let (tenant, client_id) = tenant_with_an_application(&database, "acme").await;
    let clock = Arc::new(SystemClock);
    let organizations = OrganizationService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgOrganizationRepository),
        Arc::new(PgInvitationRepository),
        Arc::new(PgUserRepository),
        clock.clone(),
    );
    let member_of = organizations
        .create(&tenant, "Initech", None, Caller::system())
        .await
        .expect("organization")
        .id();
    let elsewhere = organizations
        .create(&tenant, "Umbrella", None, Caller::system())
        .await
        .expect("organization")
        .id();
    let ana = IdentityService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgUserRepository),
        clock,
    )
    .find_by_login(&tenant, "ana@example.com")
    .await
    .expect("lookup")
    .expect("ana")
    .id();
    organizations
        .add_member(&tenant, member_of, ana, BTreeSet::new(), Caller::system())
        .await
        .expect("member");
    let server = start_server(&database).await;
    let mut browser = Browser::not_following(&server);
    browser.sign_in("acme", "ana@example.com", PASSWORD).await;

    // Not an identifier: refused before anything else.
    let (status, location, _) = browser
        .navigate(
            Method::GET,
            &format!(
                "/t/acme/oauth2/authorize?{}",
                query(client_id, &[("organization", "initech")])
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        sent_back(&location.expect("a redirect"))["error"],
        "invalid_request"
    );

    // An organization she is not in, and one the tenant does not have, are
    // answered alike, and no code is made.
    for organization in [elsewhere.to_string(), uuid_like()] {
        let (status, location, _) = browser
            .navigate(
                Method::GET,
                &format!(
                    "/t/acme/oauth2/authorize?{}",
                    query(client_id, &[("organization", &organization)])
                ),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::FOUND);
        let answer = sent_back(&location.expect("a redirect"));
        assert_eq!(answer["error"], "access_denied", "{organization}");
        assert_eq!(
            answer["error_description"],
            "the person is not a member of the organization"
        );
        assert_eq!(answer["state"], "the state");
        assert!(!answer.contains_key("code"));
    }

    // Her own organization gives a code, and the grant keeps it.
    let (status, location, _) = browser
        .navigate(
            Method::GET,
            &format!(
                "/t/acme/oauth2/authorize?{}",
                query(client_id, &[("organization", &member_of.to_string())])
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(sent_back(&location.expect("a redirect")).contains_key("code"));
    let kept: Option<sqlx::types::Uuid> =
        sqlx::query_scalar("SELECT organization FROM oauth.authorization_grant")
            .fetch_one(database.owner())
            .await
            .expect("the grant");
    assert_eq!(kept.map(|id| id.to_string()), Some(member_of.to_string()));
}

/// An identifier no organization has.
fn uuid_like() -> String {
    "0193f1c2-0000-7000-8000-00000000abcd".to_owned()
}

#[tokio::test]
async fn nothing_is_sent_to_an_address_that_is_not_trusted() {
    let database = TestDatabase::start().await;
    let (_, client_id) = tenant_with_an_application(&database, "acme").await;
    tenant_with_an_application(&database, "globex").await;
    let server = start_server(&database).await;
    let mut browser = Browser::not_following(&server);

    let refused = [
        (
            format!(
                "/t/acme/oauth2/authorize?{}",
                query(client_id, &[("client_id", "")])
            ),
            "oauth.authorization_client_unknown",
        ),
        (
            // The client of acme is unknown at globex.
            format!("/t/globex/oauth2/authorize?{}", query(client_id, &[])),
            "oauth.authorization_client_unknown",
        ),
        (
            format!(
                "/t/acme/oauth2/authorize?{}",
                query(
                    client_id,
                    &[("redirect_uri", "https://attacker.example/callback")]
                )
            ),
            "oauth.authorization_redirect_uri_unregistered",
        ),
        (
            format!(
                "/t/acme/oauth2/authorize?{}",
                query(client_id, &[("redirect_uri", "")])
            ),
            "oauth.authorization_redirect_uri_missing",
        ),
    ];
    for (path, code) in refused {
        let (status, location, body) = browser.navigate(Method::GET, &path, None).await;
        assert_eq!(
            (status, location),
            (StatusCode::BAD_REQUEST, None),
            "{code}"
        );
        assert!(body.contains(code), "{code}: {body}");
    }

    // A form is the only body the endpoint reads.
    let (status, _, body) = browser
        .navigate(Method::POST, "/t/acme/oauth2/authorize", None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("oauth.authorization_form_expected"));
}

#[tokio::test]
async fn errors_go_back_to_a_trusted_address_with_the_state_and_the_issuer() {
    let database = TestDatabase::start().await;
    let (_, client_id) = tenant_with_an_application(&database, "acme").await;
    let server = start_server(&database).await;
    let mut browser = Browser::not_following(&server);

    let cases = [
        (
            vec![("response_type", "token")],
            "unsupported_response_type",
        ),
        (vec![("code_challenge_method", "plain")], "invalid_request"),
        (vec![("code_challenge", "")], "invalid_request"),
        (vec![("scope", "openid admin")], "invalid_scope"),
        (
            vec![("resource", "https://elsewhere.example.com")],
            "invalid_target",
        ),
        (vec![("prompt", "none")], "login_required"),
    ];
    for (extra, error) in cases {
        let (status, location, _) = browser
            .navigate(
                Method::GET,
                &format!("/t/acme/oauth2/authorize?{}", query(client_id, &extra)),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::FOUND, "{error}");
        let answer = sent_back(&location.expect("a redirect"));
        assert_eq!(answer["error"], error);
        assert_eq!(answer["state"], "the state");
        assert_eq!(answer["iss"], ISSUER);
        assert!(!answer.contains_key("code"));
    }
}

#[tokio::test]
async fn a_request_for_a_new_sign_in_is_not_answered_by_the_old_session() {
    let database = TestDatabase::start().await;
    let (_, client_id) = tenant_with_an_application(&database, "acme").await;
    let server = start_server(&database).await;
    let mut browser = Browser::not_following(&server);
    let (_, body) = browser.sign_in("acme", "ana@example.com", PASSWORD).await;
    assert_eq!(body["status"], "completed");

    // prompt=login sends a signed-in person to sign in again.
    let (status, location, _) = browser
        .navigate(
            Method::GET,
            &format!(
                "/t/acme/oauth2/authorize?{}",
                query(client_id, &[("prompt", "login")])
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        location.as_deref(),
        Some("/t/acme/account/sign-in?continue=authorization")
    );

    // Coming back without signing in again: the old session is not enough.
    let (status, location, _) = browser
        .navigate(Method::GET, "/t/acme/oauth2/authorize/resume", None)
        .await;
    assert_eq!(status, StatusCode::FOUND);
    let answer = sent_back(&location.expect("a redirect"));
    assert_eq!(answer["error"], "access_denied");
    assert!(!answer.contains_key("code"));

    // Signing in again is.
    browser
        .navigate(
            Method::GET,
            &format!(
                "/t/acme/oauth2/authorize?{}",
                query(client_id, &[("prompt", "login")])
            ),
            None,
        )
        .await;
    let (_, body) = browser.sign_in("acme", "ana@example.com", PASSWORD).await;
    assert_eq!(body["continue"], "/t/acme/oauth2/authorize/resume");
    let (_, location, _) = browser
        .navigate(Method::GET, "/t/acme/oauth2/authorize/resume", None)
        .await;
    assert!(sent_back(&location.expect("a redirect")).contains_key("code"));
}
