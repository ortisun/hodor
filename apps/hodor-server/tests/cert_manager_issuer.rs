//! `hodor-cert-manager-issuer`'s client against the real server binary and
//! a real database: an access token for the audience of the certificate
//! authority, got with the client's key and with its mesh identity, signing
//! an intermediate whose workloads Hodor then trusts; and every way such a
//! token is refused.
//!
//! The tests connect from 127.0.0.1, which plays the proxy in front of
//! Hodor and forwards `Client-Cert`.
//!
//! Specified in `docs/operations/hodor-cert-manager-issuer.md` and
//! `docs/architecture/contexts/keys.md`, "Who may sign".

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hodor_adapters_crypto::testing::certificates::{
    Leaf, MeshIntermediate, MeshRequest, TestAuthority, bundle,
};
use hodor_adapters_crypto::{OsRandom, Sha256Digest};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    OutboxDispatcher, PgAccessTokenStore, PgAuditLog, PgRoleAssignmentStore, PgTenantDirectory,
    PgTenantRepository, PgUserRepository,
};
use hodor_audit::api::{AuditHandler, AuditService};
use hodor_authorization::api::{AuthorizationService, Role};
use hodor_cert_manager_issuer::{Failure, Hodor, Settings, Signer};
use hodor_credential::api::AccessTokenService;
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_kernel::{Caller, SystemClock, TenantContext};
use hodor_tenant::api::{CreateTenant, TenantService};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, Method, StatusCode};
use serde_json::{Value, json};
use std::sync::Arc;

mod support;
use support::{Server, start_server_with};

/// A root key for tests only, written here in the clear.
const ROOT_KEY: &str = "test:gV8TjmTiZoYOlhsN4OdTTiWMwWa1t/o5RPNGCdbBNro=";
const AUDIENCE: &str = "urn:hodor:certificate-authority";
const SIGN: &str = "certificate-authority:sign";
/// The issuer's identity in its mesh.
const ISSUER_IDENTITY: &str = "spiffe://cluster.local/ns/cert-manager/sa/hodor-cert-manager-issuer";
/// A workload of a mesh under the tenant's authority.
const PROD_WEB: &str = "spiffe://prod.example.com/ns/shop/sa/web";

struct World {
    server: Server,
    /// Kept alive for as long as the server runs.
    database: TestDatabase,
    tenant: TenantContext,
    administrator: String,
    owner: String,
    /// The application whose resource server has the authority's audience.
    application: String,
    /// The mesh the issuer runs in, whose trust domain is `cluster.local`.
    mesh: TestAuthority,
}

/// A tenant `acme` with an administrator, a signing key, a root authority
/// for `prod.example.com`, the issuer's mesh `cluster.local` trusted by its
/// bundle, and the authority's audience opened, on a server that trusts
/// 127.0.0.1 for `Client-Cert`.
async fn world() -> World {
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
        "cert-manager issuer",
        time::Duration::minutes(30),
        Caller::system(),
    )
    .await
    .expect("token");
    let server = start_server_with(
        &database,
        &[
            ("HODOR_SECRET_KEYS", ROOT_KEY),
            ("HODOR_CERTIFICATE_AUTHORITY", "development"),
            ("HODOR_TRUSTED_PROXIES", "127.0.0.1"),
            ("HODOR_FORWARDED_HEADER", "none"),
            ("HODOR_CLIENT_IDENTITY_HEADER", "client-cert"),
        ],
    )
    .await;
    let mut world = World {
        server,
        database,
        tenant,
        administrator: secret.expose().to_owned(),
        owner: root.id().to_string(),
        application: String::new(),
        mesh: TestAuthority::root("cluster.local mesh"),
    };
    world.admin(Method::POST, "/keys/sig:rotate", None).await;
    world
        .admin(
            Method::POST,
            "/certificate-authority",
            Some(json!({ "kind": "root", "trust_domains": ["prod.example.com"] })),
        )
        .await;
    world
        .admin(
            Method::POST,
            "/trust-domains",
            Some(json!({
                "name": "cluster.local", "source": "uploaded",
                "bundle": bundle(&[world.mesh.bundle_element()])
            })),
        )
        .await;
    let application = world
        .admin(
            Method::POST,
            "/applications",
            Some(json!({ "name": "Certificate authority", "first_party": true })),
        )
        .await;
    world.application = application["id"].as_str().expect("id").to_owned();
    world
        .admin(
            Method::POST,
            "/resource-servers",
            Some(json!({
                "application_id": world.application, "audience": AUDIENCE,
                "name": "Certificate authority",
                "scopes": [
                    { "name": SIGN, "description": "Sign intermediates" },
                    { "name": "certificate-authority:status", "description": "Nothing that signs" }
                ]
            })),
        )
        .await;
    world
}

impl World {
    async fn admin_with(
        &self,
        bearer: &str,
        method: Method,
        path: &str,
        body: Option<Value>,
        headers: &[(&str, String)],
    ) -> (StatusCode, Value) {
        let url = format!("{}/t/acme/api/v1/admin{path}", self.server.base);
        let mut request = Client::new().request(method, url).bearer_auth(bearer);
        if let Some(body) = body {
            request = request.json(&body);
        }
        for (name, value) in headers {
            request = request.header(*name, value);
        }
        let response = request.send().await.expect("response");
        let status = response.status();
        (status, response.json().await.unwrap_or(Value::Null))
    }

    async fn admin(&self, method: Method, path: &str, body: Option<Value>) -> Value {
        let (status, answer) = self
            .admin_with(&self.administrator, method.clone(), path, body, &[])
            .await;
        assert!(status.is_success(), "{method} {path}: {status} {answer}");
        answer
    }

    /// A service account, holding `certificate_signer` when `signer`.
    async fn service_account(&self, signer: bool) -> String {
        let account = self
            .admin(
                Method::POST,
                "/service-accounts",
                Some(json!({ "name": "cert-manager issuer", "owners": [self.owner] })),
            )
            .await;
        let account = account["id"].as_str().expect("id").to_owned();
        if signer {
            AuthorizationService::new(
                Arc::new(self.database.app().clone()),
                Arc::new(PgRoleAssignmentStore),
                Arc::new(SystemClock),
            )
            .assign(
                &self.tenant,
                account.parse().expect("an identifier"),
                Role::CertificateSigner,
                Caller::system(),
            )
            .await
            .expect("role");
        }
        account
    }

    /// A client of the client credentials grant in the authority's
    /// application, with these settings.
    async fn client(&self, settings: Value) -> Value {
        let mut body = json!({
            "name": "cert-manager issuer",
            "type": "confidential",
            "grant_types": ["client_credentials"],
            "allowed_scopes": [SIGN],
        });
        for (field, value) in settings.as_object().expect("an object") {
            body[field] = value.clone();
        }
        self.admin(
            Method::POST,
            &format!("/applications/{}/clients", self.application),
            Some(body),
        )
        .await
    }

    /// The issuer's client, proving who it is with its key: the client,
    /// and the issuer's configuration with the key's file.
    async fn key_client(&self, principal: Option<&str>, key: &std::path::Path) -> Settings {
        let key_text = std::fs::read_to_string(key).expect("the key");
        let jwk = hodor_cert_manager_issuer::ClientKey::from_pem(&key_text, Some("k1".to_owned()))
            .expect("a key")
            .jwk();
        let mut settings = json!({ "authentication_method": "private_key_jwt" });
        if let Some(principal) = principal {
            settings["principal"] = json!(principal);
        }
        let client = self.client(settings).await;
        let id = client["id"].as_str().expect("id").to_owned();
        self.admin(
            Method::POST,
            &format!("/clients/{id}/keys"),
            Some(json!({ "jwk": jwk })),
        )
        .await;
        self.settings(
            &id,
            json!({ "method": "private_key_jwt", "key_file": key, "key_id": "k1" }),
        )
    }

    fn settings(&self, client_id: &str, authentication: Value) -> Settings {
        Settings::from_json(
            &json!({
                // The server's public address is its default, which is
                // not where the tests reach it.
                "hodor": {
                    "url": self.server.base, "tenant": "acme",
                    "issuer": "http://localhost:8080/t/acme"
                },
                "client": { "client_id": client_id, "authentication": authentication }
            })
            .to_string(),
        )
        .expect("the issuer's configuration")
    }

    /// A token of `client` with its secret, for these pairs.
    async fn secret_token(&self, client: &Value, pairs: &[(&str, &str)]) -> (StatusCode, Value) {
        let basic = STANDARD.encode(format!(
            "{}:{}",
            client["id"].as_str().expect("id"),
            client["client_secret"].as_str().expect("a secret")
        ));
        let response = Client::new()
            .post(format!("{}/t/acme/oauth2/token", self.server.base))
            .header("authorization", format!("Basic {basic}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(
                form_urlencoded::Serializer::new(String::new())
                    .append_pair("grant_type", "client_credentials")
                    .extend_pairs(pairs)
                    .finish(),
            )
            .send()
            .await
            .expect("response");
        let status = response.status();
        (status, response.json().await.unwrap_or(Value::Null))
    }

    /// The issuer's pod in its mesh: its certificate, which the proxy in
    /// front of Hodor forwards.
    fn issuer_certificate(&self) -> String {
        byte_sequence(&self.mesh.issue(&Leaf::uri(ISSUER_IDENTITY)))
    }
}

fn byte_sequence(der: &[u8]) -> String {
    format!(":{}:", STANDARD.encode(der))
}

fn der_of(pem: &str) -> Vec<u8> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    STANDARD.decode(body).expect("base64")
}

/// An HTTP client that adds what the issuer's sidecar would present.
fn through_sidecar(certificate: &str) -> Client {
    let mut headers = HeaderMap::new();
    headers.insert(
        "client-cert",
        HeaderValue::from_str(certificate).expect("a header"),
    );
    Client::builder()
        .default_headers(headers)
        .build()
        .expect("a client")
}

/// A key of the issuer's client, in PEM, in a file of its own.
fn key_file() -> tempfile_like::KeyFile {
    tempfile_like::KeyFile::new()
}

mod tempfile_like {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use std::path::{Path, PathBuf};

    /// A key in a file removed when it is dropped.
    pub(super) struct KeyFile(PathBuf);

    impl KeyFile {
        pub(super) fn new() -> Self {
            let document = EcdsaKeyPair::generate_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &SystemRandom::new(),
            )
            .expect("a key");
            let body = STANDARD.encode(document.as_ref());
            let lines: Vec<&str> = body
                .as_bytes()
                .chunks(64)
                .map(|chunk| std::str::from_utf8(chunk).expect("ASCII"))
                .collect();
            let pem = format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
                lines.join("\n")
            );
            let path = std::env::temp_dir().join(format!(
                "hodor-issuer-key-{}-{}.pem",
                std::process::id(),
                uuid_like()
            ));
            std::fs::write(&path, pem).expect("the key's file");
            Self(path)
        }

        pub(super) fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for KeyFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn uuid_like() -> String {
        let mut bytes = [0_u8; 8];
        aws_lc_rs::rand::fill(&mut bytes).expect("random");
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

/// Does the worker's part: turns every waiting event into an audit record.
async fn record_events(database: &TestDatabase) {
    let audit = AuditService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgAuditLog),
        Arc::new(Sha256Digest),
        Arc::new(SystemClock),
    );
    let dispatcher = OutboxDispatcher::new(
        database.platform().clone(),
        database.app().clone(),
        vec![Arc::new(AuditHandler::new(audit))],
    );
    while dispatcher
        .dispatch_batch(100)
        .await
        .expect("dispatch")
        .delivered
        > 0
    {}
}

#[tokio::test]
async fn the_issuers_client_signs_with_its_key_and_hodor_trusts_the_intermediates_workloads() {
    let world = world().await;
    let signer = world.service_account(true).await;
    let key = key_file();
    let settings = world.key_client(Some(&signer), key.path()).await;
    let key_text = std::fs::read_to_string(key.path()).expect("the key");
    let issuer = Hodor::new(
        &settings,
        Some(
            hodor_cert_manager_issuer::ClientKey::from_pem(&key_text, Some("k1".to_owned()))
                .expect("a key"),
        ),
        Client::new(),
    );
    issuer.check_access().await.expect("a token");

    // A mesh's intermediate, as cert-manager asks for it.
    let mesh = MeshIntermediate::new(&MeshRequest::authority("istio-ca"));
    let signed = issuer.sign(mesh.request(), Some(2)).await.expect("signed");
    let authority = world
        .admin(Method::GET, "/certificate-authority", None)
        .await;
    assert_eq!(
        signed.chain.len(),
        1,
        "a root authority: the chain is its certificate"
    );
    assert_eq!(
        der_of(&signed.chain[0]),
        der_of(authority["certificate"].as_str().expect("PEM"))
    );
    let listed = world
        .admin(
            Method::GET,
            &format!("/certificate-authority/intermediates/{}", signed.id),
            None,
        )
        .await;
    assert_eq!(listed["serial_number"], signed.serial_number.as_str());
    assert_eq!(listed["state"], "active");

    // A workload under it gets a token: Hodor trusts what was signed.
    let workload_client = world
        .client(json!({
            "authentication_method": "spiffe_x509",
            "spiffe_id": PROD_WEB,
            "principal": world.service_account(false).await,
        }))
        .await;
    let response = Client::new()
        .post(format!("{}/t/acme/oauth2/token", world.server.base))
        .header("content-type", "application/x-www-form-urlencoded")
        .header(
            "client-cert",
            byte_sequence(&mesh.issue(&Leaf::uri(PROD_WEB))),
        )
        .header(
            "client-cert-chain",
            byte_sequence(&der_of(&signed.certificate)),
        )
        .body(
            form_urlencoded::Serializer::new(String::new())
                .append_pair("grant_type", "client_credentials")
                .append_pair("client_id", workload_client["id"].as_str().expect("id"))
                .append_pair("scope", SIGN)
                .append_pair("resource", AUDIENCE)
                .finish(),
        )
        .send()
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    // A request Hodor refuses is named with its code and its reason, and
    // nothing signed.
    let outside = MeshIntermediate::new(&MeshRequest {
        dns_names: vec!["identity.linkerd.other.example.com".to_owned()],
        ..MeshRequest::authority("identity.linkerd.other.example.com")
    });
    match issuer.sign(outside.request(), None).await {
        Err(Failure::Refused {
            status,
            code,
            detail,
        }) => {
            assert_eq!(status, 422);
            assert_eq!(code, "keys.intermediate_name_outside_trust_domains");
            // The reason: the name outside the trust domains.
            assert!(
                detail.contains("identity.linkerd.other.example.com"),
                "{detail}"
            );
        }
        other => panic!("refused, not {other:?}"),
    }
    match issuer.sign(mesh.request(), Some(31)).await {
        Err(Failure::Refused { code, .. }) => {
            assert_eq!(code, "keys.intermediate_lifetime_invalid")
        }
        other => panic!("refused, not {other:?}"),
    }

    // The signature is recorded with the service account as the actor.
    record_events(&world.database).await;
    let records = world
        .admin(Method::GET, "/audit-records?limit=200", None)
        .await;
    let signature = records["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|record| {
            record["action"] == "keys.authority_signed"
                && record["details"]["intermediate_id"] == signed.id.as_str()
        })
        .expect("the signature");
    assert_eq!(signature["actor"]["kind"], "user");
    assert_eq!(signature["actor"]["id"], signer.as_str());
}

#[tokio::test]
async fn the_issuers_client_signs_with_its_mesh_identity_alone() {
    let world = world().await;
    let signer = world.service_account(true).await;
    let client = world
        .client(json!({
            "authentication_method": "spiffe_x509",
            "spiffe_id": ISSUER_IDENTITY,
            "principal": signer,
            "tls_client_certificate_bound_access_tokens": true,
        }))
        .await;
    assert!(client.get("client_secret").is_none(), "no secret");
    let id = client["id"].as_str().expect("id").to_owned();
    let settings = world.settings(&id, json!({ "method": "forwarded" }));
    let certificate = world.issuer_certificate();
    let issuer = Hodor::new(&settings, None, through_sidecar(&certificate));
    let mesh = MeshIntermediate::new(&MeshRequest {
        dns_names: vec!["identity.linkerd.prod.example.com".to_owned()],
        ..MeshRequest::authority("identity.linkerd.prod.example.com")
    });
    let signed = issuer.sign(mesh.request(), Some(2)).await.expect("signed");
    assert!(
        signed
            .certificate
            .starts_with("-----BEGIN CERTIFICATE-----")
    );

    // Without its sidecar, the issuer's client is not even known for who
    // it is: no token, nothing signed.
    let alone = Hodor::new(&settings, None, Client::new());
    assert!(matches!(
        alone.sign(mesh.request(), Some(2)).await,
        Err(Failure::Unavailable(reason)) if reason.contains("invalid_client")
    ));

    // Its tokens are bound to the sidecar's certificate: one presented
    // without it is not good at the signing operation.
    let response = through_sidecar(&certificate)
        .post(format!("{}/t/acme/oauth2/token", world.server.base))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(
            form_urlencoded::Serializer::new(String::new())
                .append_pair("grant_type", "client_credentials")
                .append_pair("client_id", &id)
                .append_pair("resource", AUDIENCE)
                .append_pair("scope", SIGN)
                .finish(),
        )
        .send()
        .await
        .expect("response");
    let token: Value = response.json().await.expect("JSON");
    let token = token["access_token"].as_str().expect("a token").to_owned();
    let body = json!({ "certificate_signing_request": mesh.request() });
    let (status, _) = world
        .admin_with(
            &token,
            Method::POST,
            "/certificate-authority/intermediates",
            Some(body.clone()),
            &[],
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let other = byte_sequence(&world.mesh.issue(&Leaf::uri(
        "spiffe://cluster.local/ns/cert-manager/sa/someone-else",
    )));
    let (status, _) = world
        .admin_with(
            &token,
            Method::POST,
            "/certificate-authority/intermediates",
            Some(body.clone()),
            &[("client-cert", other)],
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, answer) = world
        .admin_with(
            &token,
            Method::POST,
            "/certificate-authority/intermediates",
            Some(body),
            &[("client-cert", certificate)],
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{answer}");
}

#[tokio::test]
async fn a_signing_token_is_good_at_the_signing_operation_alone_and_only_of_a_signing_service_account()
 {
    let world = world().await;
    let signer = world.service_account(true).await;
    let mesh = MeshIntermediate::new(&MeshRequest::authority("istio-ca"));
    let body = json!({ "certificate_signing_request": mesh.request(), "lifetime_days": 2 });
    let sign = |token: String| {
        let (world, body) = (&world, body.clone());
        async move {
            world
                .admin_with(
                    &token,
                    Method::POST,
                    "/certificate-authority/intermediates",
                    Some(body),
                    &[],
                )
                .await
        }
    };

    // A client of the signing service account, with a secret, as a
    // stand-in for any way of proving who it is.
    world
        .admin(
            Method::POST,
            "/resource-servers",
            Some(json!({
                "application_id": world.application_of_another_resource_server().await,
                "audience": "https://api.shop.example", "name": "Shop",
                "scopes": [{ "name": "read", "description": "Reads orders" }]
            })),
        )
        .await;
    let client = world
        .client(json!({
            "principal": signer,
            "allowed_scopes": [SIGN, "certificate-authority:status", "read"],
        }))
        .await;
    let token = |pairs: &'static [(&'static str, &'static str)]| {
        let (world, client) = (&world, client.clone());
        async move {
            let (status, answer) = world.secret_token(&client, pairs).await;
            assert_eq!(status, StatusCode::OK, "{answer}");
            answer["access_token"].as_str().expect("a token").to_owned()
        }
    };
    let signing = token(&[("resource", AUDIENCE), ("scope", SIGN)]).await;
    let (status, answer) = sign(signing.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "{answer}");

    // Good at the signing operation alone: every other one refuses it.
    for (method, path, body) in [
        (Method::GET, "/certificate-authority/intermediates", None),
        (
            Method::GET,
            &format!(
                "/certificate-authority/intermediates/{}",
                answer["id"].as_str().expect("id")
            ) as &str,
            None,
        ),
        (
            Method::POST,
            &format!(
                "/certificate-authority/intermediates/{}:withdraw",
                answer["id"].as_str().expect("id")
            ),
            Some(json!({ "reason": "not its to do" })),
        ),
        (Method::GET, "/certificate-authority", None),
        (Method::DELETE, "/certificate-authority", None),
        (Method::GET, "/users", None),
        (Method::GET, "/audit-records", None),
    ] {
        let (status, _) = world
            .admin_with(&signing, method.clone(), path, body, &[])
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path}");
    }

    // For another audience: not good here.
    let other_audience =
        token(&[("resource", "https://api.shop.example"), ("scope", "read")]).await;
    let (status, answer) = sign(other_audience).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{answer}");
    assert_eq!(answer["code"], "admin.not_authenticated");

    // For the audience, without the signing scope: forbidden.
    let without_scope = token(&[
        ("resource", AUDIENCE),
        ("scope", "certificate-authority:status"),
    ])
    .await;
    let (status, answer) = sign(without_scope).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    assert_eq!(answer["code"], "admin.forbidden");

    // A client acting as no service account: not good here.
    let own = world.client(json!({})).await;
    let (status, answer) = world
        .secret_token(&own, &[("resource", AUDIENCE), ("scope", SIGN)])
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let (status, _) = sign(answer["access_token"].as_str().expect("a token").to_owned()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A service account without the role: forbidden.
    let unprivileged = world
        .client(json!({ "principal": world.service_account(false).await }))
        .await;
    let (_, answer) = world
        .secret_token(&unprivileged, &[("resource", AUDIENCE), ("scope", SIGN)])
        .await;
    let (status, answer) = sign(answer["access_token"].as_str().expect("a token").to_owned()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");

    // A token that does not read, and one tampered with.
    let (status, _) = sign("eyJhbGciOiJFUzI1NiJ9.e30.c2ln".to_owned()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let mut parts: Vec<String> = signing.split('.').map(str::to_owned).collect();
    parts[1] = parts[1].chars().rev().collect();
    let (status, _) = sign(parts.join(".")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Disabling the service account stops its token at once.
    world
        .admin(
            Method::POST,
            &format!("/service-accounts/{signer}:disable"),
            None,
        )
        .await;
    let (status, _) = sign(signing).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

impl World {
    /// An application of its own, for a resource server of another
    /// audience.
    async fn application_of_another_resource_server(&self) -> String {
        let application = self
            .admin(
                Method::POST,
                "/applications",
                Some(json!({ "name": "Shop", "first_party": true })),
            )
            .await;
        application["id"].as_str().expect("id").to_owned()
    }
}

/// The issuer on a real Kubernetes interface with cert-manager installed,
/// in the cluster `HODOR_ISSUER_TEST_KUBECONFIG` names, and the chart's two
/// kinds defined there. It runs in this process, against the real server.
mod on_kubernetes {
    use super::{AUDIENCE, MeshIntermediate, MeshRequest, SIGN, World, der_of, key_file, world};
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use hodor_cert_manager_issuer::kubernetes::{Kubernetes, certificate_requests, issuers, run};
    use hodor_cert_manager_issuer::{ClientKey, Hodor, Reconciler, Settings, Signer};
    use k8s_openapi::api::core::v1::{Namespace, Secret};
    use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding};
    use kube::api::{Api, DeleteParams, DynamicObject, Patch, PatchParams, PostParams};
    use kube::config::{KubeConfigOptions, Kubeconfig};
    use kube::core::{ApiResource, GroupVersionKind};
    use reqwest::Method;
    use serde_json::{Value, json};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::sync::oneshot;

    const GROUP: &str = "hodor.ortisun.github.io";

    async fn cluster() -> kube::Client {
        let path = std::env::var("HODOR_ISSUER_TEST_KUBECONFIG").expect(
            "HODOR_ISSUER_TEST_KUBECONFIG names the kubeconfig of a cluster with cert-manager",
        );
        let config = kube::Config::from_custom_kubeconfig(
            Kubeconfig::read_from(path).expect("a kubeconfig"),
            &KubeConfigOptions::default(),
        )
        .await
        .expect("a configuration");
        kube::Client::try_from(config).expect("a client")
    }

    /// The issuer's controller, in this process, until the sender is
    /// dropped or sent to.
    fn controller(client: kube::Client, signer: Arc<dyn Signer>) -> oneshot::Sender<()> {
        let (stop, stopped) = oneshot::channel::<()>();
        let reconciler = Arc::new(
            Reconciler::new(Arc::new(Kubernetes::new(client.clone())), signer)
                .with_first_wait(Duration::from_secs(1)),
        );
        tokio::spawn(run(client, reconciler, async move {
            let _ = stopped.await;
        }));
        stop
    }

    fn request_body(name: &str, request: &str, is_ca: bool, kind: &str, group: &str) -> Value {
        json!({
            "apiVersion": "cert-manager.io/v1",
            "kind": "CertificateRequest",
            "metadata": { "name": name },
            "spec": {
                "request": STANDARD.encode(request),
                "isCA": is_ca,
                "duration": "48h0m0s",
                "usages": ["cert sign", "crl sign"],
                "issuerRef": { "name": "hodor", "kind": kind, "group": group }
            }
        })
    }

    async fn create_request(requests: &Api<DynamicObject>, body: Value) {
        let object: DynamicObject = serde_json::from_value(body).expect("a request");
        requests
            .create(&PostParams::default(), &object)
            .await
            .expect("created");
    }

    /// Sets the condition an approver sets: `Approved` or `Denied`.
    async fn decide(requests: &Api<DynamicObject>, name: &str, kind: &str) {
        let patch = json!({ "status": { "conditions": [{
            "type": kind, "status": "True", "reason": "IssuerTest",
            "message": "decided by the test", "lastTransitionTime": hodor_cert_manager_issuer::kubernetes::now()
        }] } });
        requests
            .patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
            .await
            .expect("decided");
    }

    fn ready(object: &DynamicObject) -> Option<(String, String, String)> {
        let conditions = object.data.pointer("/status/conditions")?.as_array()?;
        let ready = conditions
            .iter()
            .find(|condition| condition["type"] == "Ready")?;
        Some((
            ready["status"].as_str().unwrap_or_default().to_owned(),
            ready["reason"].as_str().unwrap_or_default().to_owned(),
            ready["message"].as_str().unwrap_or_default().to_owned(),
        ))
    }

    /// Waits until `name`'s `Ready` reason is `reason`.
    async fn until_ready(requests: &Api<DynamicObject>, name: &str, reason: &str) -> DynamicObject {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let object = requests.get(name).await.expect("the request");
            if ready(&object).is_some_and(|(_, found, _)| found == reason) {
                return object;
            }
            assert!(
                Instant::now() < deadline,
                "{name} is not {reason}: {:?}",
                ready(&object)
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    async fn intermediates(world: &World) -> usize {
        world
            .admin(
                Method::GET,
                "/certificate-authority/intermediates?limit=200",
                None,
            )
            .await["items"]
            .as_array()
            .expect("items")
            .len()
    }

    fn pem_of(object: &DynamicObject, field: &str) -> String {
        let encoded = object
            .data
            .pointer(&format!("/status/{field}"))
            .and_then(Value::as_str)
            .expect("the field");
        String::from_utf8(STANDARD.decode(encoded).expect("base64")).expect("PEM")
    }

    /// The signing client of the issuer, by its key, in a world of its own.
    async fn signing_hodor(world: &World, key: &std::path::Path) -> (Settings, Hodor) {
        let signer = world.service_account(true).await;
        let settings = world.key_client(Some(&signer), key).await;
        let text = std::fs::read_to_string(key).expect("the key");
        let hodor = Hodor::new(
            &settings,
            Some(ClientKey::from_pem(&text, Some("k1".to_owned())).expect("a key")),
            reqwest::Client::new(),
        );
        (settings, hodor)
    }

    #[tokio::test]
    #[ignore = "needs a Kubernetes cluster with cert-manager: HODOR_ISSUER_TEST_KUBECONFIG"]
    async fn the_issuer_signs_on_a_cluster_only_what_it_should() {
        let client = cluster().await;
        let namespace = format!("issuer-test-{}", std::process::id());
        let namespaces: Api<Namespace> = Api::all(client.clone());
        namespaces
            .create(
                &PostParams::default(),
                &serde_json::from_value(json!({ "metadata": { "name": namespace } }))
                    .expect("a namespace"),
            )
            .await
            .expect("the namespace");
        let issuer_api: Api<DynamicObject> =
            Api::namespaced_with(client.clone(), &namespace, &issuers());
        issuer_api
            .create(
                &PostParams::default(),
                &serde_json::from_value(json!({
                    "apiVersion": format!("{GROUP}/v1alpha1"), "kind": "HodorIssuer",
                    "metadata": { "name": "hodor" }, "spec": {}
                }))
                .expect("an issuer"),
            )
            .await
            .expect("the issuer");
        let requests: Api<DynamicObject> =
            Api::namespaced_with(client.clone(), &namespace, &certificate_requests());

        // Hodor's world, and its signing client.
        let world = world().await;
        let key = key_file();
        let (settings, hodor) = signing_hodor(&world, key.path()).await;
        let authority = world
            .admin(Method::GET, "/certificate-authority", None)
            .await;
        let root = authority["certificate"].as_str().expect("PEM").to_owned();

        // Hodor unreachable: an approved request waits, pending, and the
        // issuer's kind says why.
        let unreachable = Settings::from_json(
            &json!({
                "hodor": { "url": "http://127.0.0.1:9", "tenant": "acme" },
                "client": { "client_id": settings.client_id, "authentication": { "method": "forwarded" } }
            })
            .to_string(),
        )
        .expect("settings");
        let down = controller(
            client.clone(),
            Arc::new(Hodor::new(&unreachable, None, reqwest::Client::new())),
        );
        let first = MeshIntermediate::new(&MeshRequest::authority("istio-ca"));
        create_request(
            &requests,
            request_body(
                "while-hodor-is-down",
                first.request(),
                true,
                "HodorIssuer",
                GROUP,
            ),
        )
        .await;
        decide(&requests, "while-hodor-is-down", "Approved").await;
        let pending = until_ready(&requests, "while-hodor-is-down", "Pending").await;
        let (status, _, message) = ready(&pending).expect("Ready");
        assert_eq!(status, "False");
        assert!(message.contains("could not be reached"), "{message}");
        drop(down);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(intermediates(&world).await, 0);

        // Hodor back: the same request is signed without anyone making it
        // again, under the tenant's root.
        let _up = controller(client.clone(), Arc::new(hodor));
        let issued = until_ready(&requests, "while-hodor-is-down", "Issued").await;
        assert_eq!(der_of(&pem_of(&issued, "ca")), der_of(&root));
        assert!(pem_of(&issued, "certificate").starts_with("-----BEGIN CERTIFICATE-----"));
        assert_eq!(intermediates(&world).await, 1);

        // Not approved: left alone, and signed once approved.
        let second = MeshIntermediate::new(&MeshRequest::authority("istio-ca-2"));
        create_request(
            &requests,
            request_body(
                "not-approved-yet",
                second.request(),
                true,
                "HodorIssuer",
                GROUP,
            ),
        )
        .await;
        // Denied: marked so. Not for an authority: failed. Outside the
        // trust domains: Hodor's refusal named. Another issuer's: untouched.
        let third = MeshIntermediate::new(&MeshRequest::authority("denied"));
        create_request(
            &requests,
            request_body("denied", third.request(), true, "HodorIssuer", GROUP),
        )
        .await;
        decide(&requests, "denied", "Denied").await;
        // A workload's own request asks for no authority, as cert-manager
        // checks against `isCA`.
        let workload = MeshIntermediate::new(&MeshRequest {
            authority: None,
            ..MeshRequest::authority("a-workload")
        });
        create_request(
            &requests,
            request_body(
                "a-workload",
                workload.request(),
                false,
                "HodorIssuer",
                GROUP,
            ),
        )
        .await;
        decide(&requests, "a-workload", "Approved").await;
        let outside = MeshIntermediate::new(&MeshRequest {
            dns_names: vec!["identity.linkerd.other.example.com".to_owned()],
            ..MeshRequest::authority("identity.linkerd.other.example.com")
        });
        create_request(
            &requests,
            request_body("outside", outside.request(), true, "HodorIssuer", GROUP),
        )
        .await;
        decide(&requests, "outside", "Approved").await;
        create_request(
            &requests,
            request_body(
                "another-issuers",
                second.request(),
                true,
                "Issuer",
                "cert-manager.io",
            ),
        )
        .await;
        // cert-manager's own approver approves it, for an issuer of its own.

        let denied = until_ready(&requests, "denied", "Denied").await;
        assert_eq!(ready(&denied).expect("Ready").0, "False");
        let failed = until_ready(&requests, "a-workload", "Failed").await;
        assert!(
            ready(&failed)
                .expect("Ready")
                .2
                .contains("not for an authority"),
            "{:?}",
            ready(&failed)
        );
        let refused = until_ready(&requests, "outside", "Failed").await;
        assert!(
            ready(&refused)
                .expect("Ready")
                .2
                .contains("keys.intermediate_name_outside_trust_domains"),
            "{:?}",
            ready(&refused)
        );
        let waiting = requests.get("not-approved-yet").await.expect("the request");
        assert!(ready(&waiting).is_none(), "{:?}", ready(&waiting));
        let theirs = requests.get("another-issuers").await.expect("the request");
        assert!(
            ready(&theirs).is_none_or(|(_, reason, _)| reason != "Issued"),
            "{:?}",
            ready(&theirs)
        );
        assert_eq!(intermediates(&world).await, 1, "nothing more was signed");
        decide(&requests, "not-approved-yet", "Approved").await;
        until_ready(&requests, "not-approved-yet", "Issued").await;
        assert_eq!(intermediates(&world).await, 2);

        // cert-manager's own approver allowed to approve for Hodor's kinds:
        // a Certificate shaped as Linkerd's identity issuer is kept by
        // cert-manager through the issuer, and renewed without anyone
        // acting. Hodor's validity starts a minute early, so a lifetime of
        // a day renewed 23 hours and 58 minutes before it ends is renewed
        // about a minute after it is signed.
        let approver = format!("hodor-issuer-test-approver-{}", std::process::id());
        let roles: Api<ClusterRole> = Api::all(client.clone());
        roles
            .create(
                &PostParams::default(),
                &serde_json::from_value(json!({
                    "metadata": { "name": approver },
                    "rules": [{
                        "apiGroups": ["cert-manager.io"], "resources": ["signers"], "verbs": ["approve"],
                        "resourceNames": [format!("hodorissuers.{GROUP}/*"), format!("hodorclusterissuers.{GROUP}/*")]
                    }]
                }))
                .expect("a role"),
            )
            .await
            .expect("the role");
        let bindings: Api<ClusterRoleBinding> = Api::all(client.clone());
        bindings
            .create(
                &PostParams::default(),
                &serde_json::from_value(json!({
                    "metadata": { "name": approver },
                    "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": approver },
                    "subjects": [{ "kind": "ServiceAccount", "name": "cert-manager", "namespace": "cert-manager" }]
                }))
                .expect("a binding"),
            )
            .await
            .expect("the binding");
        let certificates: Api<DynamicObject> = Api::namespaced_with(
            client.clone(),
            &namespace,
            &ApiResource::from_gvk_with_plural(
                &GroupVersionKind::gvk("cert-manager.io", "v1", "Certificate"),
                "certificates",
            ),
        );
        certificates
            .create(
                &PostParams::default(),
                &serde_json::from_value(json!({
                    "apiVersion": "cert-manager.io/v1", "kind": "Certificate",
                    "metadata": { "name": "linkerd-identity-issuer" },
                    "spec": {
                        "secretName": "linkerd-identity-issuer",
                        "duration": "24h", "renewBefore": "23h58m",
                        "issuerRef": { "group": GROUP, "kind": "HodorIssuer", "name": "hodor" },
                        "commonName": "identity.linkerd.prod.example.com",
                        "dnsNames": ["identity.linkerd.prod.example.com"],
                        "isCA": true,
                        "privateKey": { "algorithm": "ECDSA", "rotationPolicy": "Always" },
                        "usages": ["cert sign", "crl sign"]
                    }
                }))
                .expect("a certificate"),
            )
            .await
            .expect("the certificate");
        let secrets: Api<Secret> = Api::namespaced(client.clone(), &namespace);
        let deadline = Instant::now() + Duration::from_secs(300);
        let mut first_certificate = None;
        let renewed = loop {
            if let Some(secret) = secrets
                .get_opt("linkerd-identity-issuer")
                .await
                .expect("the secret")
            {
                let data = secret.data.unwrap_or_default();
                let certificate = data.get("tls.crt").map(|bytes| bytes.0.clone());
                if let (Some(certificate), Some(ca)) = (certificate, data.get("ca.crt")) {
                    assert_eq!(
                        der_of(&String::from_utf8(ca.0.clone()).expect("PEM")),
                        der_of(&root),
                        "ca.crt is the tenant's root"
                    );
                    assert!(data.contains_key("tls.key"));
                    match &first_certificate {
                        None => first_certificate = Some(certificate),
                        Some(first) if *first != certificate => break certificate,
                        Some(_) => {}
                    }
                }
            }
            assert!(
                Instant::now() < deadline,
                "the Certificate was not signed and renewed in time"
            );
            tokio::time::sleep(Duration::from_secs(2)).await;
        };
        assert!(!renewed.is_empty());
        assert!(
            intermediates(&world).await >= 4,
            "two signatures of the Certificate"
        );

        // The scope and audience asked for are the ones of the authority.
        assert_eq!(AUDIENCE, hodor_cert_manager_issuer::hodor::AUDIENCE);
        assert_eq!(SIGN, hodor_cert_manager_issuer::hodor::SCOPE);

        let _ = bindings.delete(&approver, &DeleteParams::default()).await;
        let _ = roles.delete(&approver, &DeleteParams::default()).await;
        let _ = namespaces
            .delete(&namespace, &DeleteParams::default())
            .await;
    }
}
