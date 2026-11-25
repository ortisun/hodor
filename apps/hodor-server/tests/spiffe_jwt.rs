//! A service account's client proves who it is with a JWT-SVID
//! (`spiffe_jwt`, draft-ietf-oauth-spiffe-client-auth-03), against the real
//! server binary and a real database: the trust domain and the client set
//! up through the administration interface, the JWT-SVID signed by a key
//! made here whose bundle the tenant holds, and presented at the token,
//! introspection and revocation endpoints.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "The SPIFFE
//! identifier of a client" and "Checking a JWT-SVID".

use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_adapters_crypto::{OsRandom, Sha256Digest};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgAccessTokenStore, PgRoleAssignmentStore, PgTenantDirectory, PgTenantRepository,
    PgUserRepository,
};
use hodor_authorization::api::{AuthorizationService, Role};
use hodor_credential::api::AccessTokenService;
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_kernel::{Caller, SystemClock, TenantContext};
use hodor_oauth::api::{SPIFFE_ASSERTION_TYPE, SPIFFE_CLIENT_AUTHENTICATION_DRAFT};
use hodor_tenant::api::{CreateTenant, TenantService};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::{Client, Method, StatusCode};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

mod support;
use support::{Server, start_server_with};

/// A root key for tests only, written here in the clear.
const ROOT_KEY: &str = "test:gV8TjmTiZoYOlhsN4OdTTiWMwWa1t/o5RPNGCdbBNro=";
const EXPORTS: &str = "urn:example:exports";
const EXPORT: &str = "spiffe://cluster.local/ns/payroll/sa/export";
const IMPORT: &str = "spiffe://cluster.local/ns/payroll/sa/import";

struct World {
    server: Server,
    /// Kept alive for as long as the server runs.
    _database: TestDatabase,
    /// The tenant administrator's token for the administration interface.
    administrator: String,
    /// The person who owns the workloads.
    ana: String,
}

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
    let identity = IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone());
    let mut people = Vec::new();
    for email in ["ana@example.com", "root@example.com"] {
        let user = identity
            .create(
                &tenant,
                CreateUser {
                    kind: UserKind::Human,
                    identifiers: vec![(IdentifierKind::Email, email.to_owned())],
                    profile: Profile::default(),
                    confirmed: true,
                },
                Caller::system(),
            )
            .await
            .expect("a person");
        people.push(user.id());
    }
    AuthorizationService::new(units(), Arc::new(PgRoleAssignmentStore), clock.clone())
        .assign(
            &tenant,
            people[1],
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
        people[1],
        "workloads",
        time::Duration::minutes(30),
        Caller::system(),
    )
    .await
    .expect("token");
    let server = start_server_with(&database, &[("HODOR_SECRET_KEYS", ROOT_KEY)]).await;
    World {
        server,
        _database: database,
        administrator: secret.expose().to_owned(),
        ana: people[0].to_string(),
    }
}

impl World {
    /// A request to the administration interface as the administrator.
    async fn admin(&self, method: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
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

    async fn created(&self, path: &str, body: Value) -> Value {
        let (status, answer) = self.admin(Method::POST, path, Some(body)).await;
        assert_eq!(status, StatusCode::CREATED, "{path}: {answer}");
        answer
    }

    /// A form to an OAuth endpoint of the tenant `slug`, with no
    /// `Authorization` header.
    async fn oauth(
        &self,
        slug: &str,
        endpoint: &str,
        pairs: &[(&str, &str)],
    ) -> (StatusCode, Value) {
        let response = Client::new()
            .post(format!("{}/t/{slug}/oauth2/{endpoint}", self.server.base))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(
                form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(pairs)
                    .finish(),
            )
            .send()
            .await
            .expect("response");
        let status = response.status();
        (status, response.json().await.unwrap_or(Value::Null))
    }

    async fn discovery(&self) -> Value {
        reqwest::get(format!(
            "{}/t/acme/.well-known/openid-configuration",
            self.server.base
        ))
        .await
        .expect("response")
        .json()
        .await
        .expect("JSON")
    }
}

/// An authority of a trust domain: a P-256 key made here, as SPIRE would
/// sign JWT-SVIDs with.
struct Authority {
    kid: String,
    pkcs8: Vec<u8>,
    public: Vec<u8>,
}

impl Authority {
    fn new(kid: &str) -> Self {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .expect("a key");
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
            .expect("the key reads");
        Self {
            kid: kid.to_owned(),
            pkcs8: pkcs8.as_ref().to_vec(),
            public: pair.public_key().as_ref().to_vec(),
        }
    }

    /// The bundle of a trust domain whose JWT-SVIDs this authority signs.
    fn bundle(&self) -> Value {
        // An uncompressed point: 4, then x and y.
        let (x, y) = self.public[1..].split_at(32);
        json!({
            "spiffe_sequence": 1,
            "spiffe_refresh_hint": 300,
            "keys": [{
                "use": "jwt-svid", "kty": "EC", "crv": "P-256", "kid": self.kid,
                "x": URL_SAFE_NO_PAD.encode(x), "y": URL_SAFE_NO_PAD.encode(y),
            }],
        })
    }

    /// A JWT-SVID of `subject` for `audience`, living five minutes.
    fn svid(&self, subject: &str, audience: &str) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("after 1970")
            .as_secs();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.kid.clone());
        // Each JWT-SVID differs from the one before, as SPIRE's do.
        let mut nonce = [0_u8; 16];
        SystemRandom::new().fill(&mut nonce).expect("random bytes");
        let nonce = URL_SAFE_NO_PAD.encode(nonce);
        jsonwebtoken::encode(
            &header,
            &json!({
                "sub": subject, "aud": [audience], "iat": now, "exp": now + 300,
                "x-nonce": nonce,
            }),
            &EncodingKey::from_ec_der(&self.pkcs8),
        )
        .expect("a JWT-SVID")
    }
}

/// The application that owns the resource server, and a service account.
async fn exports_and_a_service_account(world: &World) -> (String, String) {
    let application = world
        .created(
            "/applications",
            json!({ "name": "Exports", "first_party": true }),
        )
        .await;
    let application = application["id"].as_str().expect("id").to_owned();
    world
        .created(
            "/resource-servers",
            json!({
                "application_id": application, "audience": EXPORTS, "name": "Exports",
                "scopes": [{ "name": "read", "description": "Read" }]
            }),
        )
        .await;
    let account = world
        .created(
            "/service-accounts",
            json!({ "name": "Nightly export", "owners": [world.ana] }),
        )
        .await;
    (application, account["id"].as_str().expect("id").to_owned())
}

fn client_body(account: &str, spiffe_id: &str) -> Value {
    json!({
        "name": "Nightly export", "type": "confidential",
        "authentication_method": "spiffe_jwt", "spiffe_id": spiffe_id,
        "grant_types": ["client_credentials"], "allowed_scopes": ["read"],
        "principal": account
    })
}

fn with_svid<'a>(
    client: &'a str,
    svid: &'a str,
    rest: &[(&'a str, &'a str)],
) -> Vec<(&'a str, &'a str)> {
    let mut pairs = rest.to_vec();
    pairs.extend([
        ("client_id", client),
        ("client_assertion_type", SPIFFE_ASSERTION_TYPE),
        ("client_assertion", svid),
    ]);
    pairs
}

#[tokio::test]
async fn a_service_account_proves_who_it_is_with_a_jwt_svid_at_every_endpoint() {
    let world = world().await;
    let cluster = Authority::new("cluster-2026-11");
    world
        .created(
            "/trust-domains",
            json!({ "name": "cluster.local", "source": "uploaded", "bundle": cluster.bundle() }),
        )
        .await;
    let (application, account) = exports_and_a_service_account(&world).await;
    let client = world
        .created(
            &format!("/applications/{application}/clients"),
            client_body(&account, EXPORT),
        )
        .await;
    assert_eq!(client["authentication_method"], "spiffe_jwt");
    assert_eq!(client["spiffe_id"], EXPORT);
    assert!(client.get("client_secret").is_none(), "{client}");
    let client = client["id"].as_str().expect("id").to_owned();

    // The metadata names the method at all three endpoints.
    let discovery = world.discovery().await;
    for list in [
        "token_endpoint_auth_methods_supported",
        "revocation_endpoint_auth_methods_supported",
        "introspection_endpoint_auth_methods_supported",
    ] {
        assert!(
            discovery[list]
                .as_array()
                .expect("a list")
                .contains(&json!("spiffe_jwt")),
            "{list}: {discovery}"
        );
    }
    assert_eq!(
        SPIFFE_CLIENT_AUTHENTICATION_DRAFT,
        "draft-ietf-oauth-spiffe-client-auth-03"
    );
    let issuer = discovery["issuer"].as_str().expect("issuer").to_owned();

    // A token with a JWT-SVID.
    let svid = cluster.svid(EXPORT, &issuer);
    let (status, issued) = world
        .oauth(
            "acme",
            "token",
            &with_svid(&client, &svid, &[("grant_type", "client_credentials")]),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let access = issued["access_token"].as_str().expect("a token").to_owned();
    let payload = access.split('.').nth(1).expect("claims");
    let claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url")).expect("JSON");
    assert_eq!(claims["sub"], account.as_str());
    assert_eq!(claims["principal_kind"], "service_account");
    assert_eq!(claims["client_id"], client.as_str());

    // Presented a second time, it is refused.
    let (status, again) = world
        .oauth(
            "acme",
            "token",
            &with_svid(&client, &svid, &[("grant_type", "client_credentials")]),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{again}");
    assert_eq!(again["error"], "invalid_client");

    // Introspection and revocation, each with a JWT-SVID of its own.
    let introspected = cluster.svid(EXPORT, &issuer);
    let (status, answer) = world
        .oauth(
            "acme",
            "introspect",
            &with_svid(&client, &introspected, &[("token", &access)]),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["active"], true);
    let revoking = cluster.svid(EXPORT, &issuer);
    let (status, _) = world
        .oauth(
            "acme",
            "revoke",
            &with_svid(&client, &revoking, &[("token", &access)]),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let checking = cluster.svid(EXPORT, &issuer);
    let (status, answer) = world
        .oauth(
            "acme",
            "introspect",
            &with_svid(&client, &checking, &[("token", &access)]),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer, json!({ "active": false }));
    // The JWT-SVID that introspected once does not introspect again.
    let (status, _) = world
        .oauth(
            "acme",
            "introspect",
            &with_svid(&client, &introspected, &[("token", &access)]),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_jwt_svid_of_another_trust_domain_identifier_or_issuer_is_refused() {
    let world = world().await;
    let cluster = Authority::new("cluster-2026-11");
    let partner = Authority::new("partner-2026-11");
    for (name, authority) in [("cluster.local", &cluster), ("partner.example", &partner)] {
        world
            .created(
                "/trust-domains",
                json!({ "name": name, "source": "uploaded", "bundle": authority.bundle() }),
            )
            .await;
    }
    let (application, account) = exports_and_a_service_account(&world).await;
    let client = world
        .created(
            &format!("/applications/{application}/clients"),
            client_body(&account, EXPORT),
        )
        .await;
    let client = client["id"].as_str().expect("id").to_owned();
    let issuer = world.discovery().await["issuer"]
        .as_str()
        .expect("issuer")
        .to_owned();
    let refused = |svid: String| {
        let world = &world;
        let client = client.clone();
        async move {
            let (status, answer) = world
                .oauth(
                    "acme",
                    "token",
                    &with_svid(&client, &svid, &[("grant_type", "client_credentials")]),
                )
                .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{answer}");
            assert_eq!(answer["error"], "invalid_client");
        }
    };
    // Signed by the authority of another trust domain the tenant trusts.
    refused(partner.svid(EXPORT, &issuer)).await;
    // Signed by a key no bundle holds, under the right kid.
    refused(Authority::new("cluster-2026-11").svid(EXPORT, &issuer)).await;
    // Of another workload of the same trust domain.
    refused(cluster.svid(IMPORT, &issuer)).await;
    // For another tenant's issuer, or for an endpoint.
    let globex = issuer.replace("/t/acme", "/t/globex");
    refused(cluster.svid(EXPORT, &globex)).await;
    refused(cluster.svid(EXPORT, &format!("{issuer}/oauth2/token"))).await;
    // Without `client_id`.
    let svid = cluster.svid(EXPORT, &issuer);
    let (status, _) = world
        .oauth(
            "acme",
            "token",
            &[
                ("grant_type", "client_credentials"),
                ("client_assertion_type", SPIFFE_ASSERTION_TYPE),
                ("client_assertion", &svid),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // The right one still passes: nothing refused was remembered.
    let (status, issued) = world
        .oauth(
            "acme",
            "token",
            &with_svid(&client, &svid, &[("grant_type", "client_credentials")]),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{issued}");

    // Once the trust domain is removed, its workloads are refused.
    let (_, listed) = world.admin(Method::GET, "/trust-domains", None).await;
    let cluster_id = listed["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["name"] == "cluster.local")
        .and_then(|item| item["id"].as_str())
        .expect("cluster.local")
        .to_owned();
    let (status, _) = world
        .admin(
            Method::DELETE,
            &format!("/trust-domains/{cluster_id}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    refused(cluster.svid(EXPORT, &issuer)).await;
}

#[tokio::test]
async fn a_client_is_bound_to_one_exact_identifier_of_a_service_account() {
    let world = world().await;
    let (application, account) = exports_and_a_service_account(&world).await;
    let clients = format!("/applications/{application}/clients");
    let refused = |body: Value| {
        let world = &world;
        let clients = clients.clone();
        async move {
            let (status, answer) = world.admin(Method::POST, &clients, Some(body)).await;
            (
                status,
                answer["code"].as_str().unwrap_or_default().to_owned(),
            )
        }
    };
    // A prefix, a malformed identifier, none, or one with another method.
    for spiffe_id in [
        json!("spiffe://cluster.local/ns/payroll/*"),
        json!("spiffe://cluster.local"),
        json!("https://cluster.local/ns/payroll"),
        json!(null),
    ] {
        let mut body = client_body(&account, EXPORT);
        body["spiffe_id"] = spiffe_id.clone();
        assert_eq!(
            refused(body).await,
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                "oauth.client_spiffe_id_invalid".to_owned()
            ),
            "{spiffe_id}"
        );
    }
    let mut with_secret = client_body(&account, EXPORT);
    with_secret["authentication_method"] = json!("client_secret_basic");
    assert_eq!(
        refused(with_secret).await,
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            "oauth.client_spiffe_id_invalid".to_owned()
        )
    );
    // An agent proves who it is with its own credentials.
    let agent = world
        .created(
            "/agents",
            json!({ "name": "Assistant", "owners": [world.ana] }),
        )
        .await;
    let agent = agent["id"].as_str().expect("id").to_owned();
    assert_eq!(
        refused(client_body(&agent, EXPORT)).await,
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            "oauth.client_principal_invalid".to_owned()
        )
    );

    // One client per identifier in the tenant.
    let first = world.created(&clients, client_body(&account, EXPORT)).await;
    assert_eq!(
        refused(client_body(&account, EXPORT)).await,
        (
            StatusCode::CONFLICT,
            "oauth.client_spiffe_id_taken".to_owned()
        )
    );
    let second = world.created(&clients, client_body(&account, IMPORT)).await;
    let second = second["id"].as_str().expect("id").to_owned();
    let (status, answer) = world
        .admin(
            Method::PATCH,
            &format!("/clients/{second}"),
            Some(json!({ "spiffe_id": EXPORT })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["code"], "oauth.client_spiffe_id_taken");

    // Leaving `spiffe_jwt` takes the identifier away with it.
    let first = first["id"].as_str().expect("id").to_owned();
    let (status, answer) = world
        .admin(
            Method::PATCH,
            &format!("/clients/{first}"),
            Some(json!({ "authentication_method": "client_secret_basic" })),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
    assert_eq!(answer["code"], "oauth.client_spiffe_id_invalid");
    let (status, answer) = world
        .admin(
            Method::PATCH,
            &format!("/clients/{first}"),
            Some(json!({ "authentication_method": "client_secret_basic", "spiffe_id": null })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["spiffe_id"], Value::Null);
    let (status, answer) = world
        .admin(
            Method::PATCH,
            &format!("/clients/{second}"),
            Some(json!({ "spiffe_id": EXPORT })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["spiffe_id"], EXPORT);
}
