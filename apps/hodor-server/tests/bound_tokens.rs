//! Certificate-bound access tokens (RFC 8705) against the real server
//! binary behind a trusted proxy address and a real database: tokens bound
//! to the certificate the proxy forwards, or to Envoy's hash of it, and
//! refused without it or with another at UserInfo, the Authorization API,
//! the SCIM server, token exchange and the administration interface;
//! introspection answering `cnf`; a public client's refresh tokens bound;
//! the setting of a client and the discovery document.
//!
//! The tests connect from 127.0.0.1, which plays the proxy: the server
//! trusts it through `HODOR_TRUSTED_PROXIES`.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Certificate-bound
//! access tokens", and Decision 0057.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hodor_adapters_crypto::testing::certificates::{Leaf, TestAuthority};
use hodor_adapters_crypto::{
    Argon2Parameters, Argon2idHasher, HashingLimits, OsRandom, Sha256Digest,
};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgAccessTokenStore, PgPasswordStore, PgRoleAssignmentStore, PgTenantDirectory,
    PgTenantRepository, PgUserRepository,
};
use hodor_authorization::api::{AuthorizationService, Role};
use hodor_credential::api::{AccessTokenService, CredentialService, NewPassword, PasswordRules};
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_kernel::{Caller, Digest as _, Secret, SystemClock, TenantContext};
use hodor_oauth::api::s256_challenge;
use hodor_tenant::api::{CreateTenant, TenantService};
use reqwest::{Client, Method, StatusCode};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;

mod support;
use support::{Browser, MEMORY_KIBIBYTES, PASSES, Server, start_server_with};

/// A root key for tests only, written here in the clear.
const ROOT_KEY: &str = "test:gV8TjmTiZoYOlhsN4OdTTiWMwWa1t/o5RPNGCdbBNro=";
const PASSWORD: &str = "correct horse battery staple";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const SHOP: &str = "https://api.shop.example";
const AUTHORIZATION: &str = "urn:hodor:authorization";
const SCIM: &str = "urn:hodor:scim";
const REDIRECT: &str = "https://shop.example.com/callback";
const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// A header the proxy would add, or none.
type Forwarded = Option<(&'static str, String)>;

struct World {
    server: Server,
    /// Kept alive for as long as the server runs.
    _database: TestDatabase,
    /// The administrator's access token of the credential context.
    administrator: String,
    /// The administrator, who signs in with a password and owns the
    /// workloads.
    owner: String,
    /// The application Shop, whose resource server is `SHOP`.
    shop: String,
}

/// A tenant `acme` with an administrator who has a password, a signing
/// key, the application Shop and its resource server, and the Authorization
/// API and SCIM opened, served by a server with these settings besides the
/// root key.
async fn world(settings: &[(&str, &str)]) -> World {
    let database = TestDatabase::start().await;
    let units = || Arc::new(database.app().clone());
    let clock = Arc::new(SystemClock);
    let tenant = TenantService::new(
        units(),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.app().clone())),
        clock.clone(),
    )
    .create(
        CreateTenant {
            slug: "acme".to_owned(),
            display_name: "Acme".to_owned(),
            open_registration: false,
            system: false,
        },
        Caller::system(),
    )
    .await
    .expect("tenant");
    let tenant = TenantContext::assume(tenant.id());
    let root = IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone())
        .create(
            &tenant,
            CreateUser {
                kind: UserKind::Human,
                identifiers: vec![(IdentifierKind::Email, "root@example.com".to_owned())],
                profile: Profile::default(),
                confirmed: true,
            },
            Caller::system(),
        )
        .await
        .expect("a person");
    AuthorizationService::new(units(), Arc::new(PgRoleAssignmentStore), clock.clone())
        .assign(
            &tenant,
            root.id(),
            Role::TenantAdministrator,
            Caller::system(),
        )
        .await
        .expect("role");
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
    CredentialService::new(
        units(),
        Arc::new(PgPasswordStore),
        Arc::new(hasher),
        clock.clone(),
    )
    .set_password(
        &tenant,
        root.id(),
        NewPassword {
            password: &Secret::from(PASSWORD.to_owned()),
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
    let (_, secret) = AccessTokenService::new(
        units(),
        Arc::new(PgAccessTokenStore),
        Arc::new(Sha256Digest),
        Arc::new(OsRandom),
        clock,
    )
    .issue(
        &tenant,
        root.id(),
        "bound tokens",
        time::Duration::minutes(30),
        Caller::system(),
    )
    .await
    .expect("token");
    let mut all = vec![("HODOR_SECRET_KEYS", ROOT_KEY)];
    all.extend_from_slice(settings);
    let server = start_server_with(&database, &all).await;
    let mut world = World {
        server,
        _database: database,
        administrator: secret.expose().to_owned(),
        owner: root.id().to_string(),
        shop: String::new(),
    };
    world.admin(Method::POST, "/keys/sig:rotate", None).await;
    world.shop = world.application_with("Shop", SHOP, &["read"]).await;
    world
        .application_with("Authorization API", AUTHORIZATION, &["authz:evaluate"])
        .await;
    world.application_with("Directory", SCIM, &["scim"]).await;
    world
}

/// Trusts 127.0.0.1, where the tests connect from, for `header` alone.
async fn behind_proxy(header: &str) -> World {
    world(&[
        ("HODOR_TRUSTED_PROXIES", "127.0.0.1"),
        ("HODOR_FORWARDED_HEADER", "none"),
        ("HODOR_CLIENT_IDENTITY_HEADER", header),
    ])
    .await
}

impl World {
    async fn admin_answer(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let url = format!("{}/t/acme/api/v1/admin{path}", self.server.base);
        let mut request = Client::new()
            .request(method, url)
            .bearer_auth(&self.administrator);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.expect("response");
        let status = response.status();
        (status, response.json().await.unwrap_or(Value::Null))
    }

    /// A request to the administration interface, which must succeed.
    async fn admin(&self, method: Method, path: &str, body: Option<Value>) -> Value {
        let (status, answer) = self.admin_answer(method.clone(), path, body).await;
        assert!(status.is_success(), "{method} {path}: {status} {answer}");
        answer
    }

    /// An application with a resource server of `audience` defining
    /// `scopes`. Answers the application's identifier.
    async fn application_with(&self, name: &str, audience: &str, scopes: &[&str]) -> String {
        let application = self
            .admin(
                Method::POST,
                "/applications",
                Some(json!({ "name": name, "first_party": true })),
            )
            .await;
        let id = application["id"].as_str().expect("id").to_owned();
        let scopes: Vec<Value> = scopes
            .iter()
            .map(|scope| json!({ "name": scope, "description": "A scope" }))
            .collect();
        self.admin(
            Method::POST,
            "/resource-servers",
            Some(json!({
                "application_id": id, "audience": audience, "name": name, "scopes": scopes
            })),
        )
        .await;
        id
    }

    /// A client of Shop with these settings. Answers its identifier and
    /// its secret, when it has one.
    async fn client(&self, settings: Value) -> (String, Option<String>) {
        let created = self
            .admin(
                Method::POST,
                &format!("/applications/{}/clients", self.shop),
                Some(settings),
            )
            .await;
        (
            created["id"].as_str().expect("id").to_owned(),
            created["client_secret"].as_str().map(str::to_owned),
        )
    }

    /// A confidential client of client credentials that asks for bound
    /// tokens, allowed to ask the Authorization API, SCIM and Shop.
    async fn workload(&self) -> (String, String) {
        let (id, secret) = self
            .client(json!({
                "name": "Shop back end",
                "type": "confidential",
                "grant_types": ["client_credentials"],
                "allowed_scopes": ["authz:evaluate", "scim", "read"],
                "tls_client_certificate_bound_access_tokens": true,
            }))
            .await;
        (id, secret.expect("a secret"))
    }

    /// A form to an OAuth endpoint, with the client's secret in `Basic`
    /// when it has one and its identifier in the form otherwise, and the
    /// header the proxy would add.
    async fn oauth(
        &self,
        endpoint: &str,
        client: &(String, Option<String>),
        pairs: &[(&str, &str)],
        forwarded: &Forwarded,
    ) -> (StatusCode, Value) {
        let mut form = form_urlencoded::Serializer::new(String::new());
        form.extend_pairs(pairs);
        let mut request = Client::new()
            .post(format!("{}/t/acme/oauth2/{endpoint}", self.server.base))
            .header("content-type", "application/x-www-form-urlencoded");
        match &client.1 {
            Some(secret) => {
                request = request.header(
                    "authorization",
                    format!(
                        "Basic {}",
                        STANDARD.encode(format!("{}:{secret}", client.0))
                    ),
                );
            }
            None => {
                form.append_pair("client_id", &client.0);
            }
        }
        if let Some((name, value)) = forwarded {
            request = request.header(*name, value);
        }
        let response = request.body(form.finish()).send().await.expect("response");
        let status = response.status();
        (status, response.json().await.unwrap_or(Value::Null))
    }

    /// A token of client credentials for `scope`.
    async fn token(
        &self,
        client: &(String, String),
        scope: &str,
        forwarded: &Forwarded,
    ) -> (StatusCode, Value) {
        self.oauth(
            "token",
            &(client.0.clone(), Some(client.1.clone())),
            &[("grant_type", "client_credentials"), ("scope", scope)],
            forwarded,
        )
        .await
    }

    /// A request to one of Hodor's own resource servers with `token` as the
    /// bearer token, and the header the proxy would add. Answers the
    /// status and the challenge.
    async fn bearer(
        &self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<Value>,
        forwarded: &Forwarded,
    ) -> (StatusCode, String) {
        let mut request = Client::new()
            .request(method, format!("{}/t/acme{path}", self.server.base))
            .bearer_auth(token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        if let Some((name, value)) = forwarded {
            request = request.header(*name, value);
        }
        let response = request.send().await.expect("response");
        let challenge = response
            .headers()
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        (response.status(), challenge)
    }

    async fn evaluate(&self, token: &str, forwarded: &Forwarded) -> (StatusCode, String) {
        self.bearer(
            Method::POST,
            "/api/v1/authorization/evaluate",
            token,
            Some(json!({
                "subject": { "type": "user", "id": self.owner },
                "resource": { "type": "order", "id": "order-1" },
                "action": "read",
            })),
            forwarded,
        )
        .await
    }

    async fn scim(&self, token: &str, forwarded: &Forwarded) -> (StatusCode, String) {
        self.bearer(Method::GET, "/scim/v2/Users", token, None, forwarded)
            .await
    }

    async fn userinfo(&self, token: &str, forwarded: &Forwarded) -> (StatusCode, String) {
        self.bearer(Method::GET, "/oauth2/userinfo", token, None, forwarded)
            .await
    }

    /// UserInfo with `token` in a form body (RFC 6750, section 2.2)
    /// rather than the `Authorization` header.
    async fn userinfo_in_form(&self, token: &str, forwarded: &Forwarded) -> (StatusCode, String) {
        let mut request = Client::new()
            .post(format!("{}/t/acme/oauth2/userinfo", self.server.base))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(
                form_urlencoded::Serializer::new(String::new())
                    .append_pair("access_token", token)
                    .finish(),
            );
        if let Some((name, value)) = forwarded {
            request = request.header(*name, value);
        }
        let response = request.send().await.expect("response");
        let challenge = response
            .headers()
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        (response.status(), challenge)
    }

    async fn administration(&self, token: &str, forwarded: &Forwarded) -> (StatusCode, String) {
        self.bearer(Method::GET, "/api/v1/admin/users", token, None, forwarded)
            .await
    }

    async fn discovery(&self) -> Value {
        Client::new()
            .get(format!(
                "{}/t/acme/.well-known/openid-configuration",
                self.server.base
            ))
            .send()
            .await
            .expect("response")
            .json()
            .await
            .expect("JSON")
    }

    /// The code the administrator's browser gets for `client`, for `scope`
    /// and the resource Shop.
    async fn code(&self, browser: &mut Browser, client: &str, scope: &str) -> String {
        let challenge = s256_challenge(VERIFIER, &Sha256Digest);
        let query = form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("response_type", "code"),
                ("client_id", client),
                ("redirect_uri", REDIRECT),
                ("scope", scope),
                ("resource", SHOP),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
            ])
            .finish();
        let (status, location, body) = browser
            .navigate(
                Method::GET,
                &format!("/t/acme/oauth2/authorize?{query}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::FOUND, "{body}");
        let location = location.expect("a redirect");
        let (_, query) = location.split_once('?').expect("a query");
        let answer: BTreeMap<String, String> = form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        answer.get("code").expect("a code").clone()
    }
}

/// A certificate of a workload, in DER.
fn certificate(name: &str) -> Vec<u8> {
    TestAuthority::root(name).issue(&Leaf::uri(&format!(
        "spiffe://cluster.local/ns/shop/sa/{name}"
    )))
}

/// What the proxy adds in `Client-Cert` for `der`.
fn client_cert(der: &[u8]) -> Forwarded {
    Some(("client-cert", format!(":{}:", STANDARD.encode(der))))
}

/// The `x5t#S256` of `der`.
fn thumbprint(der: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256Digest.sha256(der))
}

/// The claims of a JSON Web Token, unchecked.
fn claims_of(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("claims");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url")).expect("JSON")
}

fn issued(answer: &(StatusCode, Value)) -> String {
    assert_eq!(answer.0, StatusCode::OK, "{}", answer.1);
    answer.1["access_token"]
        .as_str()
        .expect("a token")
        .to_owned()
}

/// A bound token's refusal at a resource server: `401` with
/// `invalid_token`.
fn refused_as_invalid((status, challenge): &(StatusCode, String)) {
    assert_eq!(*status, StatusCode::UNAUTHORIZED, "{challenge}");
    assert!(challenge.contains("invalid_token"), "{challenge}");
}

/// A token accepted by a resource server, whatever it then answers.
fn accepted((status, challenge): &(StatusCode, String)) {
    assert_ne!(*status, StatusCode::UNAUTHORIZED, "{challenge}");
}

#[tokio::test]
async fn a_bound_token_is_refused_without_its_certificate_everywhere_hodor_checks_tokens() {
    let world = behind_proxy("client-cert").await;
    let workload = world.workload().await;
    let mine = certificate("web");
    let other = certificate("api");

    // A bound client without a certificate gets no token.
    let refused = world.token(&workload, "authz:evaluate scim", &None).await;
    assert_eq!(refused.0, StatusCode::BAD_REQUEST, "{}", refused.1);
    assert_eq!(refused.1["error"], "invalid_request");

    let token = issued(
        &world
            .token(&workload, "authz:evaluate scim", &client_cert(&mine))
            .await,
    );
    assert_eq!(
        claims_of(&token)["cnf"],
        json!({ "x5t#S256": thumbprint(&mine) })
    );

    // The Authorization API and the SCIM server take it with its
    // certificate alone.
    accepted(&world.evaluate(&token, &client_cert(&mine)).await);
    refused_as_invalid(&world.evaluate(&token, &None).await);
    refused_as_invalid(&world.evaluate(&token, &client_cert(&other)).await);
    let (status, challenge) = world.scim(&token, &client_cert(&mine)).await;
    assert_eq!(status, StatusCode::OK, "{challenge}");
    refused_as_invalid(&world.scim(&token, &None).await);
    refused_as_invalid(&world.scim(&token, &client_cert(&other)).await);

    // The administration interface takes no OAuth access token at all.
    for forwarded in [client_cert(&mine), None, client_cert(&other)] {
        let (status, _) = world.administration(&token, &forwarded).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // Introspection answers `cnf` and compares nothing: the certificate of
    // its own request is the caller's.
    let caller = (workload.0.clone(), Some(workload.1.clone()));
    for forwarded in [None, client_cert(&other), client_cert(&mine)] {
        let (status, answer) = world
            .oauth("introspect", &caller, &[("token", &token)], &forwarded)
            .await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(answer["active"], true, "{answer}");
        assert_eq!(
            answer["cnf"],
            json!({ "x5t#S256": thumbprint(&mine) }),
            "{answer}"
        );
    }

    // A token of a client that does not ask is bound to nothing.
    let (id, secret) = world
        .client(json!({
            "name": "Unbound back end",
            "type": "confidential",
            "grant_types": ["client_credentials"],
            "allowed_scopes": ["scim"],
        }))
        .await;
    let unbound = issued(
        &world
            .token(
                &(id, secret.expect("a secret")),
                "scim",
                &client_cert(&mine),
            )
            .await,
    );
    assert!(claims_of(&unbound).get("cnf").is_none());
    let (status, challenge) = world.scim(&unbound, &None).await;
    assert_eq!(status, StatusCode::OK, "{challenge}");
}

#[tokio::test]
async fn a_public_client_s_tokens_and_refresh_tokens_are_bound_and_userinfo_checks_them() {
    let world = behind_proxy("client-cert").await;
    let (public, _) = world
        .client(json!({
            "name": "Shop app",
            "type": "public",
            "grant_types": ["authorization_code", "refresh_token"],
            "redirect_uris": [REDIRECT],
            "allowed_scopes": ["openid", "read"],
            "tls_client_certificate_bound_access_tokens": true,
        }))
        .await;
    let public = (public, None);
    let mine = certificate("app");
    let other = certificate("thief");
    let mut browser = Browser::not_following(&world.server);
    let (status, answer) = browser.sign_in("acme", "root@example.com", PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "{answer}");

    // Without a certificate the code is not redeemed, and it still is with
    // one.
    let code = world.code(&mut browser, &public.0, "openid read").await;
    let redeem = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
    ];
    let (status, refused) = world.oauth("token", &public, &redeem, &None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert_eq!(refused["error"], "invalid_request");
    let (status, tokens) = world
        .oauth("token", &public, &redeem, &client_cert(&mine))
        .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let access = tokens["access_token"].as_str().expect("a token").to_owned();
    assert_eq!(
        claims_of(&access)["cnf"],
        json!({ "x5t#S256": thumbprint(&mine) })
    );
    assert_eq!(tokens["token_type"], "Bearer");

    // UserInfo.
    let (status, challenge) = world.userinfo(&access, &client_cert(&mine)).await;
    assert_eq!(status, StatusCode::OK, "{challenge}");
    refused_as_invalid(&world.userinfo(&access, &None).await);
    refused_as_invalid(&world.userinfo(&access, &client_cert(&other)).await);
    // The token read from a form body is held to the same certificate.
    let (status, challenge) = world.userinfo_in_form(&access, &client_cert(&mine)).await;
    assert_eq!(status, StatusCode::OK, "{challenge}");
    refused_as_invalid(&world.userinfo_in_form(&access, &None).await);
    refused_as_invalid(&world.userinfo_in_form(&access, &client_cert(&other)).await);

    // The refresh token is bound to the same certificate: another one is
    // refused, and ends nothing.
    let refresh = tokens["refresh_token"].as_str().expect("a refresh token");
    let pairs = [("grant_type", "refresh_token"), ("refresh_token", refresh)];
    let (status, refused) = world
        .oauth("token", &public, &pairs, &client_cert(&other))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert_eq!(refused["error"], "invalid_grant");
    let (status, refused) = world.oauth("token", &public, &pairs, &None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    let (status, refreshed) = world
        .oauth("token", &public, &pairs, &client_cert(&mine))
        .await;
    assert_eq!(status, StatusCode::OK, "{refreshed}");
    let access = refreshed["access_token"].as_str().expect("a token");
    assert_eq!(
        claims_of(access)["cnf"],
        json!({ "x5t#S256": thumbprint(&mine) })
    );
    let (status, challenge) = world.userinfo(access, &client_cert(&mine)).await;
    assert_eq!(status, StatusCode::OK, "{challenge}");
}

#[tokio::test]
async fn token_exchange_checks_the_subject_token_and_the_actor_token() {
    let world = behind_proxy("client-cert").await;
    let (public, _) = world
        .client(json!({
            "name": "Shop app",
            "type": "public",
            "grant_types": ["authorization_code"],
            "redirect_uris": [REDIRECT],
            "allowed_scopes": ["openid", "read"],
            "tls_client_certificate_bound_access_tokens": true,
        }))
        .await;
    let person = certificate("app");
    let agent_certificate = certificate("agent");
    let mut browser = Browser::not_following(&world.server);
    browser.sign_in("acme", "root@example.com", PASSWORD).await;
    let code = world.code(&mut browser, &public, "openid read").await;
    let (status, tokens) = world
        .oauth(
            "token",
            &(public, None),
            &[
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", REDIRECT),
                ("code_verifier", VERIFIER),
            ],
            &client_cert(&person),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let subject = tokens["access_token"].as_str().expect("a token").to_owned();

    let agent = world
        .admin(
            Method::POST,
            "/agents",
            Some(json!({ "name": "Helper", "owners": [world.owner] })),
        )
        .await;
    let (id, secret) = world
        .client(json!({
            "name": "Helper",
            "type": "confidential",
            "grant_types": ["client_credentials", TOKEN_EXCHANGE],
            "allowed_scopes": ["read"],
            "principal": agent["id"],
            "exchange_rules": [{ "subject_audience": SHOP, "audience": SHOP }],
        }))
        .await;
    let helper = (id.clone(), secret.expect("a secret"));
    let actor = issued(&world.token(&helper, "read", &None).await);

    // The person's token is bound to their client's certificate: the agent
    // presents it only with that certificate.
    for forwarded in [None, client_cert(&agent_certificate)] {
        let (status, refused) = exchange(&world, &helper, &subject, &actor, &forwarded).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
        assert_eq!(refused["error"], "invalid_request");
    }
    let (status, exchanged) =
        exchange(&world, &helper, &subject, &actor, &client_cert(&person)).await;
    assert_eq!(status, StatusCode::OK, "{exchanged}");

    // The agent's own token, bound to its certificate, is refused with the
    // person's.
    world
        .admin(
            Method::PATCH,
            &format!("/clients/{id}"),
            Some(json!({ "tls_client_certificate_bound_access_tokens": true })),
        )
        .await;
    let bound_actor = issued(
        &world
            .token(&helper, "read", &client_cert(&agent_certificate))
            .await,
    );
    let (status, refused) = exchange(
        &world,
        &helper,
        &subject,
        &bound_actor,
        &client_cert(&person),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert_eq!(refused["error"], "invalid_request");
}

#[tokio::test]
async fn envoy_s_hash_binds_a_token_when_only_the_names_are_forwarded() {
    let world = behind_proxy("x-forwarded-client-cert").await;
    let workload = world.workload().await;
    let mine = certificate("web");
    let other = certificate("api");
    let element = |der: &[u8]| -> Forwarded {
        let hash: String = Sha256Digest
            .sha256(der)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Some((
            "x-forwarded-client-cert",
            format!(
                "By=spiffe://cluster.local/ns/hodor/sa/hodor;Hash={hash};Subject=\"\";\
                 URI=spiffe://cluster.local/ns/shop/sa/web"
            ),
        ))
    };
    let token = issued(&world.token(&workload, "scim", &element(&mine)).await);
    assert_eq!(
        claims_of(&token)["cnf"],
        json!({ "x5t#S256": thumbprint(&mine) })
    );
    let (status, challenge) = world.scim(&token, &element(&mine)).await;
    assert_eq!(status, StatusCode::OK, "{challenge}");
    refused_as_invalid(&world.scim(&token, &element(&other)).await);
    refused_as_invalid(&world.scim(&token, &None).await);
    // The same certificate in `Cert` names the same thumbprint.
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        STANDARD.encode(&mine)
    );
    let encoded: String = pem
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect();
    let (status, challenge) = world
        .scim(
            &token,
            &Some((
                "x-forwarded-client-cert",
                format!("Hash=00;Cert=\"{encoded}\";URI=spiffe://cluster.local/ns/shop/sa/web"),
            )),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{challenge}");
    // A hash that does not read binds nothing, and the client gets nothing.
    let (status, refused) = world
        .token(
            &workload,
            "scim",
            &Some((
                "x-forwarded-client-cert",
                "Hash=abc;URI=spiffe://cluster.local/ns/shop/sa/web".to_owned(),
            )),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
}

#[tokio::test]
async fn an_administrator_sets_the_binding_and_discovery_offers_it_with_a_certificate_header() {
    let world = behind_proxy("client-cert").await;
    let discovery = world.discovery().await;
    assert_eq!(
        discovery["tls_client_certificate_bound_access_tokens"],
        json!(true)
    );

    let (id, _) = world
        .client(json!({
            "name": "Back end",
            "type": "confidential",
            "grant_types": ["client_credentials"],
            "allowed_scopes": ["read"],
        }))
        .await;
    let read = world
        .admin(Method::GET, &format!("/clients/{id}"), None)
        .await;
    assert_eq!(read["tls_client_certificate_bound_access_tokens"], false);
    let changed = world
        .admin(
            Method::PATCH,
            &format!("/clients/{id}"),
            Some(json!({ "tls_client_certificate_bound_access_tokens": true })),
        )
        .await;
    assert_eq!(changed["tls_client_certificate_bound_access_tokens"], true);
    let kept = world
        .admin(
            Method::PATCH,
            &format!("/clients/{id}"),
            Some(json!({ "name": "Renamed back end" })),
        )
        .await;
    assert_eq!(
        kept["tls_client_certificate_bound_access_tokens"], true,
        "left out, it stays"
    );

    // Linkerd forwards no certificate to bind to.
    let account = world
        .admin(
            Method::POST,
            "/service-accounts",
            Some(json!({ "name": "Shop web", "owners": [world.owner] })),
        )
        .await;
    let (status, refused) = world
        .admin_answer(
            Method::POST,
            &format!("/applications/{}/clients", world.shop),
            Some(json!({
                "name": "Linkerd web",
                "type": "confidential",
                "authentication_method": "linkerd_identity",
                "linkerd_identity": "web.shop.serviceaccount.identity.linkerd.cluster.local",
                "principal": account["id"],
                "grant_types": ["client_credentials"],
                "allowed_scopes": ["read"],
                "tls_client_certificate_bound_access_tokens": true,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{refused}");
    assert_eq!(
        refused["code"],
        "oauth.client_certificate_bound_access_tokens_invalid"
    );

    // A server that reads no certificate does not offer the binding.
    for settings in [
        vec![],
        vec![
            ("HODOR_TRUSTED_PROXIES", "127.0.0.1"),
            ("HODOR_FORWARDED_HEADER", "none"),
            ("HODOR_CLIENT_IDENTITY_HEADER", "l5d-client-id"),
        ],
    ] {
        let elsewhere = crate::world(&settings).await;
        assert!(
            elsewhere
                .discovery()
                .await
                .get("tls_client_certificate_bound_access_tokens")
                .is_none()
        );
    }
}

/// An agent's client, `helper`, exchanging the person's `subject` token
/// with its own `actor` token for one of Shop.
async fn exchange(
    world: &World,
    helper: &(String, String),
    subject: &str,
    actor: &str,
    forwarded: &Forwarded,
) -> (StatusCode, Value) {
    world
        .oauth(
            "token",
            &(helper.0.clone(), Some(helper.1.clone())),
            &[
                ("grant_type", TOKEN_EXCHANGE),
                ("subject_token", subject),
                ("subject_token_type", ACCESS_TOKEN_TYPE),
                ("actor_token", actor),
                ("actor_token_type", ACCESS_TOKEN_TYPE),
                ("audience", SHOP),
            ],
            forwarded,
        )
        .await
}
