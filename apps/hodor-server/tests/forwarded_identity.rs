//! The caller's identity from the proxy in front of Hodor, against the real
//! server binary behind a trusted proxy address and a real database: each
//! header's format, each method at the token endpoint, revocation and
//! introspection, the discovery document, and what is never read.
//!
//! The tests connect from 127.0.0.1, which plays the proxy: the server
//! trusts it, or not, through `HODOR_TRUSTED_PROXIES`.
//!
//! Specified in `docs/api/api-spec.md`, "The caller's identity from a
//! proxy", and `docs/architecture/contexts/oauth.md`, "An identity
//! forwarded by a proxy".

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hodor_adapters_crypto::testing::certificates::{Leaf, TestAuthority, bundle};
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
use hodor_tenant::api::{CreateTenant, TenantService};
use reqwest::{Client, Method, StatusCode};
use serde_json::{Value, json};
use std::sync::Arc;

mod support;
use support::{Server, start_server_with};

/// A root key for tests only, written here in the clear.
const ROOT_KEY: &str = "test:gV8TjmTiZoYOlhsN4OdTTiWMwWa1t/o5RPNGCdbBNro=";
const WEB: &str = "spiffe://cluster.local/ns/shop/sa/web";
const LINKERD_WEB: &str = "web.shop.serviceaccount.identity.linkerd.cluster.local";

struct World {
    server: Server,
    /// Kept alive for as long as the server runs.
    _database: TestDatabase,
    administrator: String,
    /// The administrator, who owns the service accounts.
    owner: String,
    /// The application the clients belong to.
    application: String,
}

/// A tenant `acme` with an administrator, a signing key, an application
/// and a resource server with the scope `read`, served by a server with
/// these settings besides the root key.
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
        "forwarded identities",
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
        application: String::new(),
    };
    world.admin(Method::POST, "/keys/sig:rotate", None).await;
    let application = world
        .admin(
            Method::POST,
            "/applications",
            Some(json!({ "name": "Shop", "first_party": true })),
        )
        .await;
    world.application = application["id"].as_str().expect("id").to_owned();
    world
        .admin(
            Method::POST,
            "/resource-servers",
            Some(json!({
                "application_id": world.application,
                "audience": "https://api.shop.example",
                "name": "Shop interface",
                "scopes": [{ "name": "read", "description": "Reads orders" }]
            })),
        )
        .await;
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

    /// Trusts a trust domain, with a bundle of these authorities, or as
    /// checked by the mesh when there are none.
    async fn trust(&self, name: &str, authorities: &[&TestAuthority]) {
        let body = if authorities.is_empty() {
            json!({ "name": name, "source": "mesh" })
        } else {
            let elements: Vec<Value> = authorities.iter().map(|a| a.bundle_element()).collect();
            json!({ "name": name, "source": "uploaded", "bundle": bundle(&elements) })
        };
        self.admin(Method::POST, "/trust-domains", Some(body)).await;
    }

    /// A service account, owned by the administrator.
    async fn service_account(&self) -> String {
        let account = self
            .admin(
                Method::POST,
                "/service-accounts",
                Some(json!({ "name": "Shop web", "owners": [self.owner] })),
            )
            .await;
        account["id"].as_str().expect("id").to_owned()
    }

    /// A client of the client credentials grant with this method and
    /// identity, acting as a service account of its own, allowed `read`.
    async fn client(&self, method: &str, identity: Value) -> String {
        let mut body = json!({
            "name": "Web",
            "type": "confidential",
            "authentication_method": method,
            "grant_types": ["client_credentials"],
            "allowed_scopes": ["read"],
            "principal": self.service_account().await,
        });
        for (field, value) in identity.as_object().expect("an object") {
            body[field] = value.clone();
        }
        let created = self
            .admin(
                Method::POST,
                &format!("/applications/{}/clients", self.application),
                Some(body),
            )
            .await;
        assert!(created.get("client_secret").is_none(), "{created}");
        created["id"].as_str().expect("id").to_owned()
    }

    /// A form to an OAuth endpoint with the client's identifier alone, and
    /// the headers the proxy would add.
    async fn oauth(
        &self,
        endpoint: &str,
        client: &str,
        pairs: &[(&str, &str)],
        headers: &[(&str, String)],
    ) -> (StatusCode, Value) {
        let mut request = Client::new()
            .post(format!("{}/t/acme/oauth2/{endpoint}", self.server.base))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(
                form_urlencoded::Serializer::new(String::new())
                    .append_pair("client_id", client)
                    .extend_pairs(pairs)
                    .finish(),
            );
        for (name, value) in headers {
            request = request.header(*name, value);
        }
        let response = request.send().await.expect("response");
        let status = response.status();
        (status, response.json().await.unwrap_or(Value::Null))
    }

    async fn token(&self, client: &str, headers: &[(&str, String)]) -> (StatusCode, Value) {
        self.oauth(
            "token",
            client,
            &[("grant_type", "client_credentials"), ("scope", "read")],
            headers,
        )
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
}

fn issued(answer: &(StatusCode, Value)) -> String {
    assert_eq!(answer.0, StatusCode::OK, "{}", answer.1);
    answer.1["access_token"]
        .as_str()
        .expect("a token")
        .to_owned()
}

fn refused(answer: &(StatusCode, Value)) {
    assert_eq!(answer.0, StatusCode::UNAUTHORIZED, "{}", answer.1);
    assert_eq!(answer.1["error"], "invalid_client", "{}", answer.1);
}

/// Percent-encodes as Envoy does.
fn encoded(text: &str) -> String {
    text.bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

/// One element of `X-Forwarded-Client-Cert` holding a certificate in PEM.
fn envoy_element(pem: &str, chain: Option<&str>, uri: &str) -> String {
    let mut element = format!(
        "By=spiffe://cluster.local/ns/hodor/sa/hodor;Hash=0a1b;Cert=\"{}\"",
        encoded(pem)
    );
    if let Some(chain) = chain {
        element.push_str(&format!(";Chain=\"{}\"", encoded(chain)));
    }
    element.push_str(&format!(";Subject=\"CN=workload,O=Shop\";URI={uri}"));
    element
}

fn byte_sequence(der: &[u8]) -> String {
    format!(":{}:", STANDARD.encode(der))
}

#[tokio::test]
async fn an_envoy_certificate_proves_a_spiffe_x509_client_and_an_earlier_element_is_never_read() {
    let world = behind_proxy("x-forwarded-client-cert").await;
    let mesh = TestAuthority::root("mesh");
    let stranger = TestAuthority::root("stranger");
    world.trust("cluster.local", &[&mesh]).await;
    let web = world
        .client("spiffe_x509", json!({ "spiffe_id": WEB }))
        .await;
    let good = envoy_element(&mesh.issue_pem(&Leaf::uri(WEB)), None, WEB);
    let forged = envoy_element(&stranger.issue_pem(&Leaf::uri(WEB)), None, WEB);

    let token = issued(
        &world
            .token(&web, &[("x-forwarded-client-cert", good.clone())])
            .await,
    );
    assert!(!token.is_empty());

    // The proxy's element is the last: a forged one before it is passed
    // over, whether it is good or not.
    issued(
        &world
            .token(
                &web,
                &[("x-forwarded-client-cert", format!("{forged},{good}"))],
            )
            .await,
    );
    refused(
        &world
            .token(
                &web,
                &[("x-forwarded-client-cert", format!("{good},{forged}"))],
            )
            .await,
    );
    refused(
        &world
            .token(
                &web,
                &[
                    ("x-forwarded-client-cert", good.clone()),
                    ("x-forwarded-client-cert", forged.clone()),
                ],
            )
            .await,
    );

    // A certificate that does not chain to the trust domain's bundle.
    refused(
        &world
            .token(&web, &[("x-forwarded-client-cert", forged)])
            .await,
    );
    // Nothing forwarded, or only another header.
    refused(&world.token(&web, &[]).await);
    refused(
        &world
            .token(
                &web,
                &[("client-cert", byte_sequence(&mesh.issue(&Leaf::uri(WEB))))],
            )
            .await,
    );
    // A certificate of another identity.
    let api = "spiffe://cluster.local/ns/shop/sa/api";
    refused(
        &world
            .token(
                &web,
                &[(
                    "x-forwarded-client-cert",
                    envoy_element(&mesh.issue_pem(&Leaf::uri(api)), None, api),
                )],
            )
            .await,
    );
}

#[tokio::test]
async fn an_envoy_chain_and_names_alone_for_a_trust_domain_checked_by_the_mesh() {
    let world = behind_proxy("x-forwarded-client-cert").await;
    let root = TestAuthority::root("root");
    let intermediate = root.intermediate("intermediate");
    world.trust("cluster.local", &[&root]).await;
    world.trust("mesh.local", &[]).await;
    let web = world
        .client("spiffe_x509", json!({ "spiffe_id": WEB }))
        .await;
    let leaf = intermediate.issue_pem(&Leaf::uri(WEB));
    let chain = format!("{leaf}{}", intermediate.pem());
    issued(
        &world
            .token(
                &web,
                &[(
                    "x-forwarded-client-cert",
                    envoy_element(&leaf, Some(&chain), WEB),
                )],
            )
            .await,
    );
    refused(
        &world
            .token(
                &web,
                &[("x-forwarded-client-cert", envoy_element(&leaf, None, WEB))],
            )
            .await,
    );

    // Istio forwards the names alone by default: believed only for a trust
    // domain checked by the mesh.
    let istio = |uri: &str| {
        format!("By=spiffe://mesh.local/ns/hodor/sa/hodor;Hash=0a1b;Subject=\"\";URI={uri}")
    };
    refused(
        &world
            .token(&web, &[("x-forwarded-client-cert", istio(WEB))])
            .await,
    );
    let in_mesh = "spiffe://mesh.local/ns/shop/sa/web";
    let mesh_client = world
        .client("spiffe_x509", json!({ "spiffe_id": in_mesh }))
        .await;
    issued(
        &world
            .token(&mesh_client, &[("x-forwarded-client-cert", istio(in_mesh))])
            .await,
    );
    refused(
        &world
            .token(
                &mesh_client,
                &[(
                    "x-forwarded-client-cert",
                    istio("spiffe://mesh.local/ns/shop/sa/api"),
                )],
            )
            .await,
    );
}

#[tokio::test]
async fn an_rfc_9440_certificate_with_its_chain_proves_a_tls_client_auth_client() {
    let world = behind_proxy("client-cert").await;
    let root = TestAuthority::root("root");
    let intermediate = root.intermediate("intermediate");
    world.trust("cluster.local", &[&root]).await;
    let by_uri = world
        .client("tls_client_auth", json!({ "spiffe_id": WEB }))
        .await;
    let by_dns = world
        .client(
            "tls_client_auth",
            json!({ "linkerd_identity": LINKERD_WEB }),
        )
        .await;
    let leaf = intermediate.issue(&Leaf {
        uris: vec!["https://web.example".to_owned(), WEB.to_owned()],
        dns_names: vec![LINKERD_WEB.to_owned()],
        ..Leaf::default()
    });
    let with_chain = |certificate: &[u8]| {
        vec![
            ("client-cert", byte_sequence(certificate)),
            ("client-cert-chain", byte_sequence(&intermediate.der())),
        ]
    };
    issued(&world.token(&by_uri, &with_chain(&leaf)).await);
    issued(&world.token(&by_dns, &with_chain(&leaf)).await);
    refused(
        &world
            .token(&by_uri, &[("client-cert", byte_sequence(&leaf))])
            .await,
    );
    // The nearest element of Client-Cert is the one read.
    let stranger = TestAuthority::root("stranger").issue(&Leaf::uri(WEB));
    let mut forged_first = with_chain(&leaf);
    forged_first[0].1 = format!("{}, {}", byte_sequence(&stranger), byte_sequence(&leaf));
    issued(&world.token(&by_uri, &forged_first).await);
    let mut forged_last = with_chain(&leaf);
    forged_last[0].1 = format!("{}, {}", byte_sequence(&leaf), byte_sequence(&stranger));
    refused(&world.token(&by_uri, &forged_last).await);
    // An expired certificate, and one of another authority.
    let expired = intermediate.issue(&Leaf {
        expired: true,
        ..Leaf::uri(WEB)
    });
    refused(&world.token(&by_uri, &with_chain(&expired)).await);
    refused(&world.token(&by_uri, &with_chain(&stranger)).await);

    // Revocation and introspection take the same forwarded certificate.
    let token = issued(&world.token(&by_uri, &with_chain(&leaf)).await);
    let (status, answer) = world
        .oauth(
            "introspect",
            &by_uri,
            &[("token", &token)],
            &with_chain(&leaf),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["active"], true, "{answer}");
    refused(
        &world
            .oauth("introspect", &by_uri, &[("token", &token)], &[])
            .await,
    );
    let (status, answer) = world
        .oauth("revoke", &by_uri, &[("token", &token)], &with_chain(&leaf))
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let (_, answer) = world
        .oauth(
            "introspect",
            &by_uri,
            &[("token", &token)],
            &with_chain(&leaf),
        )
        .await;
    assert_eq!(answer, json!({ "active": false }));
}

#[tokio::test]
async fn a_linkerd_identity_proves_a_linkerd_identity_client_of_a_trust_domain_checked_by_the_mesh()
{
    let world = behind_proxy("l5d-client-id").await;
    world.trust("cluster.local", &[]).await;
    let web = world
        .client(
            "linkerd_identity",
            json!({ "linkerd_identity": LINKERD_WEB }),
        )
        .await;
    issued(
        &world
            .token(&web, &[("l5d-client-id", LINKERD_WEB.to_owned())])
            .await,
    );
    refused(
        &world
            .token(
                &web,
                &[(
                    "l5d-client-id",
                    "api.shop.serviceaccount.identity.linkerd.cluster.local".to_owned(),
                )],
            )
            .await,
    );
    refused(
        &world
            .token(
                &web,
                &[
                    ("l5d-client-id", LINKERD_WEB.to_owned()),
                    (
                        "l5d-client-id",
                        "api.shop.serviceaccount.identity.linkerd.cluster.local".to_owned(),
                    ),
                ],
            )
            .await,
    );
    refused(&world.token(&web, &[]).await);

    // A trust domain with a bundle is never taken on the proxy's word.
    let mesh = TestAuthority::root("mesh");
    world.trust("bundled.local", &[&mesh]).await;
    let bundled = "web.shop.serviceaccount.identity.linkerd.bundled.local";
    let bundled_client = world
        .client("linkerd_identity", json!({ "linkerd_identity": bundled }))
        .await;
    refused(
        &world
            .token(&bundled_client, &[("l5d-client-id", bundled.to_owned())])
            .await,
    );

    let document = world.discovery().await;
    for member in [
        "token_endpoint_auth_methods_supported",
        "revocation_endpoint_auth_methods_supported",
        "introspection_endpoint_auth_methods_supported",
    ] {
        let named = document[member].as_array().expect(member);
        assert!(named.contains(&json!("linkerd_identity")), "{member}");
        assert!(!named.contains(&json!("spiffe_x509")), "{member}");
    }
}

#[tokio::test]
async fn the_header_from_a_peer_that_is_not_a_trusted_proxy_is_ignored() {
    let world = world(&[
        ("HODOR_TRUSTED_PROXIES", "10.0.0.0/8"),
        ("HODOR_CLIENT_IDENTITY_HEADER", "l5d-client-id"),
    ])
    .await;
    world.trust("cluster.local", &[]).await;
    let web = world
        .client(
            "linkerd_identity",
            json!({ "linkerd_identity": LINKERD_WEB }),
        )
        .await;
    refused(
        &world
            .token(&web, &[("l5d-client-id", LINKERD_WEB.to_owned())])
            .await,
    );
}

#[tokio::test]
async fn no_header_is_read_when_none_is_named() {
    let world = world(&[("HODOR_TRUSTED_PROXIES", "127.0.0.1")]).await;
    let mesh = TestAuthority::root("mesh");
    world.trust("cluster.local", &[&mesh]).await;
    world.trust("mesh.local", &[]).await;
    let web = world
        .client("spiffe_x509", json!({ "spiffe_id": WEB }))
        .await;
    let leaf = mesh.issue(&Leaf::uri(WEB));
    for header in [
        ("client-cert", byte_sequence(&leaf)),
        (
            "x-forwarded-client-cert",
            envoy_element(&mesh.issue_pem(&Leaf::uri(WEB)), None, WEB),
        ),
    ] {
        refused(&world.token(&web, &[header]).await);
    }
    let linkerd = world
        .client(
            "linkerd_identity",
            json!({ "linkerd_identity": "web.shop.serviceaccount.identity.linkerd.mesh.local" }),
        )
        .await;
    refused(
        &world
            .token(
                &linkerd,
                &[(
                    "l5d-client-id",
                    "web.shop.serviceaccount.identity.linkerd.mesh.local".to_owned(),
                )],
            )
            .await,
    );
    let document = world.discovery().await;
    assert_eq!(
        document["token_endpoint_auth_methods_supported"],
        json!([
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
            "spiffe_jwt",
            "none"
        ])
    );
}

#[tokio::test]
async fn the_administration_interface_binds_a_client_to_one_identity() {
    let world = behind_proxy("x-forwarded-client-cert").await;
    let clients = format!("/applications/{}/clients", world.application);
    let base = json!({
        "name": "Web",
        "type": "confidential",
        "grant_types": ["client_credentials"],
        "principal": world.service_account().await,
    });
    let with = |fields: Value| {
        let mut body = base.clone();
        for (field, value) in fields.as_object().expect("an object") {
            body[field] = value.clone();
        }
        Some(body)
    };
    let (spiffe_refused, linkerd_refused) = (
        "oauth.client_spiffe_id_invalid",
        "oauth.client_linkerd_identity_invalid",
    );
    for (refused_body, code) in [
        (
            json!({ "authentication_method": "spiffe_x509" }),
            spiffe_refused,
        ),
        (
            json!({ "authentication_method": "spiffe_x509", "linkerd_identity": LINKERD_WEB }),
            spiffe_refused,
        ),
        (
            json!({ "authentication_method": "tls_client_auth", "spiffe_id": WEB, "linkerd_identity": LINKERD_WEB }),
            spiffe_refused,
        ),
        (
            json!({ "authentication_method": "client_secret_basic", "spiffe_id": WEB }),
            spiffe_refused,
        ),
        (
            json!({ "authentication_method": "spiffe_x509", "spiffe_id": "spiffe://cluster.local" }),
            spiffe_refused,
        ),
        (
            json!({ "authentication_method": "linkerd_identity", "linkerd_identity": "web.shop.svc.cluster.local" }),
            linkerd_refused,
        ),
        (
            json!({ "authentication_method": "linkerd_identity", "linkerd_identity": LINKERD_WEB, "principal": null }),
            linkerd_refused,
        ),
    ] {
        let mut body = with(refused_body.clone()).expect("a body");
        if refused_body.get("principal").is_some() {
            body.as_object_mut().expect("an object").remove("principal");
        }
        let (status, answer) = world.admin_answer(Method::POST, &clients, Some(body)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{refused_body}");
        assert_eq!(answer["code"], code, "{refused_body}");
    }
    let created = world
        .admin(
            Method::POST,
            &clients,
            with(json!({ "authentication_method": "tls_client_auth", "spiffe_id": WEB })),
        )
        .await;
    assert_eq!(created["spiffe_id"], WEB);
    assert_eq!(created["linkerd_identity"], Value::Null);
    assert!(created.get("client_secret").is_none());
    let path = format!("/clients/{}", created["id"].as_str().expect("id"));
    // Given the other identity, the client is bound to it alone.
    let changed = world
        .admin(
            Method::PATCH,
            &path,
            Some(json!({ "linkerd_identity": LINKERD_WEB })),
        )
        .await;
    assert_eq!(changed["spiffe_id"], Value::Null);
    assert_eq!(changed["linkerd_identity"], LINKERD_WEB);
    let (status, answer) = world
        .admin_answer(
            Method::PATCH,
            &path,
            Some(json!({ "authentication_method": "spiffe_x509" })),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
    assert_eq!(answer["code"], "oauth.client_spiffe_id_invalid");
    let changed = world
        .admin(
            Method::PATCH,
            &path,
            Some(json!({ "authentication_method": "spiffe_x509", "spiffe_id": WEB })),
        )
        .await;
    assert_eq!(changed["spiffe_id"], WEB);
    // Moving to a method that takes no identity drops it.
    let changed = world
        .admin(
            Method::PATCH,
            &path,
            Some(json!({ "authentication_method": "private_key_jwt" })),
        )
        .await;
    assert_eq!(changed["spiffe_id"], Value::Null);
    assert_eq!(changed["linkerd_identity"], Value::Null);

    // One Linkerd identity, one client of the tenant.
    world
        .client(
            "linkerd_identity",
            json!({ "linkerd_identity": LINKERD_WEB }),
        )
        .await;
    let (status, answer) = world
        .admin_answer(
            Method::POST,
            &clients,
            with(json!({ "authentication_method": "tls_client_auth", "linkerd_identity": LINKERD_WEB })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["code"], "oauth.client_linkerd_identity_taken");

    let document = world.discovery().await;
    let named = &document["token_endpoint_auth_methods_supported"];
    assert_eq!(
        named,
        &json!([
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
            "spiffe_jwt",
            "none",
            "tls_client_auth",
            "spiffe_x509"
        ])
    );
    assert!(
        !document["introspection_endpoint_auth_methods_supported"]
            .as_array()
            .expect("an array")
            .contains(&json!("none"))
    );
}
