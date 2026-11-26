//! The SCIM server over HTTP, with in-memory stores and access tokens the
//! token endpoint's use case issues: every route, and the checks of the
//! caller's token.

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use hodor_identity::api::{GroupService, IdentityService};
use hodor_identity::testing::{FixedGroupPolicy, InMemoryGroups, InMemoryUsers};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::sealing::testing::FakeSecretBox;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, CorrelationId, DomainError, PublicKey, SignatureAlgorithm, SignatureVerifier,
    TenantContext, TenantId, Timestamp, UserId,
};
use hodor_keys::api::{KeyAlgorithm, KeyService, RotationPolicy};
use hodor_keys::testing::{FakeKeyProvider, InMemoryKeys};
use hodor_oauth::api::{
    AccessTokenRegister, ApplicationPorts, ApplicationService, ApplicationSettings,
    AuthenticationMethod, AuthorizationCodePorts, AuthorizationCodeService, BasicCredentials,
    ClientSettings, ClientType, CreateClient, CreateResourceServer, GrantType, Issuer,
    ResourceAccessPorts, ResourceAccessService, ResourceServerSettings, ScopeDefinition,
    TokenPorts, TokenQuery, TokenRequest, TokenService,
};
use hodor_oauth::testing::{
    DistinctRandom, FakeVerifier, InMemoryAccessTokenRecords, InMemoryAuthorizationCodes,
    InMemoryAuthorizationRequests, InMemoryClientAssertions, InMemoryGrants, InMemoryRefreshTokens,
    InMemoryStores, MembershipsOf, StandingOf,
};
use hodor_protocol_http::{
    Limits, ResolvedTenant, SCIM_MEDIA_TYPE, ScimState, TenantResolver, TenantStatus,
    public_router, scim_routes,
};
use hodor_provisioning::api::{ProvisioningPorts, ProvisioningService};
use hodor_provisioning::testing::{
    FixedDeprovisioning, InMemoryProvisionedGroups, InMemoryProvisionedUsers,
    RecordingAccessRevoker,
};
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use std::sync::Arc;
use time::Duration;
use tower::ServiceExt as _;

const PUBLIC_URL: &str = "https://auth.example";
const USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const PATCH: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const BULK: &str = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";

/// Checks the stand-in signatures of the fake key provider, which signs
/// the tenants' access tokens here.
#[derive(Debug, Clone, Copy)]
struct Fakes;

impl SignatureVerifier for Fakes {
    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        key: &PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        FakeVerifier.verify(algorithm, key, message, signature)
            || (signature.starts_with(b"fake|") && signature.ends_with(message))
    }
}

struct Tenants {
    acme: TenantContext,
    globex: TenantContext,
}

#[async_trait::async_trait]
impl TenantResolver for Tenants {
    async fn resolve(&self, slug: &str) -> Result<Option<ResolvedTenant>, DomainError> {
        let context = match slug {
            "acme" => self.acme.clone(),
            "globex" => self.globex.clone(),
            _ => return Ok(None),
        };
        Ok(Some(ResolvedTenant {
            context,
            status: TenantStatus::Active,
        }))
    }
}

/// A client of a tenant, with its secret.
#[derive(Clone)]
struct Credentials {
    id: String,
    secret: String,
}

impl Credentials {
    fn basic(&self) -> Option<BasicCredentials> {
        Some(BasicCredentials {
            client_id: self.id.clone(),
            secret: self.secret.clone().into(),
        })
    }
}

/// A tenant whose SCIM is open, and its clients.
struct Tenant {
    slug: &'static str,
    context: TenantContext,
    /// Allowed the scope `scim`.
    provisioner: Credentials,
    /// Allowed only another scope of SCIM's resource server.
    auditor: Credentials,
    /// Allowed only a scope of another resource server.
    payroll: Credentials,
}

struct World {
    router: Router,
    /// The identity context behind SCIM, to see a person as Hodor keeps it.
    identity: IdentityService,
    tokens: TokenService,
    revoked: RecordingAccessRevoker,
    acme: Tenant,
    globex: Tenant,
}

struct Reply {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: Value,
}

fn issuer(slug: &str) -> (String, String) {
    let issuer = format!("{PUBLIC_URL}/t/{slug}");
    let endpoint = format!("{issuer}/oauth2/token");
    (issuer, endpoint)
}

async fn client(
    applications: &ApplicationService,
    tenant: &TenantContext,
    application_id: hodor_oauth::api::ApplicationId,
    scopes: &[&str],
) -> Credentials {
    let mut settings = ClientSettings::new(
        "Directory",
        ClientType::Confidential,
        vec![GrantType::ClientCredentials],
        Vec::new(),
    );
    settings.authentication_method = AuthenticationMethod::ClientSecretBasic;
    settings.allowed_scopes = scopes.iter().map(|scope| (*scope).to_owned()).collect();
    let (client, secret) = applications
        .create_client(
            tenant,
            CreateClient {
                application_id,
                client_type: ClientType::Confidential,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client");
    Credentials {
        id: client.id().to_string(),
        secret: secret.expect("a secret").expose().to_owned(),
    }
}

async fn open_tenant(
    slug: &'static str,
    keys: &KeyService,
    applications: &ApplicationService,
) -> Tenant {
    let context = TenantContext::assume(TenantId::generate());
    keys.rotate_now(
        &context,
        KeyAlgorithm::Es256,
        &RotationPolicy::DEFAULT,
        Caller::system(),
    )
    .await
    .expect("a signing key");
    let mut owners = Vec::new();
    for (name, audience, scopes) in [
        ("SCIM", "urn:hodor:scim", vec!["scim", "scim:audit"]),
        ("Payroll", "urn:example:payroll", vec!["payroll:read"]),
    ] {
        let application = applications
            .create_application(
                &context,
                ApplicationSettings {
                    name: name.to_owned(),
                    first_party: true,
                },
                Caller::system(),
            )
            .await
            .expect("application")
            .id();
        applications
            .create_resource_server(
                &context,
                CreateResourceServer {
                    application_id: application,
                    audience: audience.to_owned(),
                    settings: ResourceServerSettings {
                        name: name.to_owned(),
                        scopes: scopes
                            .iter()
                            .map(|scope| ScopeDefinition {
                                name: (*scope).to_owned(),
                                description: (*scope).to_owned(),
                            })
                            .collect(),
                    },
                },
                Caller::system(),
            )
            .await
            .expect("resource server");
        owners.push(application);
    }
    let directory = applications
        .create_application(
            &context,
            ApplicationSettings {
                name: "Directory".to_owned(),
                first_party: true,
            },
            Caller::system(),
        )
        .await
        .expect("application")
        .id();
    Tenant {
        slug,
        provisioner: client(applications, &context, directory, &["scim"]).await,
        auditor: client(applications, &context, directory, &["scim:audit"]).await,
        payroll: client(applications, &context, owners[1], &["payroll:read"]).await,
        context,
    }
}

async fn world() -> World {
    let units = InMemoryUnitOfWorkFactory::default();
    let stores = InMemoryStores::default();
    let grants = InMemoryGrants::new(&stores.clients);
    let families = InMemoryRefreshTokens::new(&grants);
    let records = InMemoryAccessTokenRecords::new(&stores.clients);
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + Duration::days(20_000),
    ));
    let keys = KeyService::new(
        Arc::new(units.clone()),
        Arc::new(InMemoryKeys::default()),
        Arc::new(FakeKeyProvider),
        clock.clone(),
    );
    let codes = AuthorizationCodeService::new(AuthorizationCodePorts {
        units_of_work: Arc::new(units.clone()),
        applications: Arc::new(stores.applications.clone()),
        clients: Arc::new(stores.clients.clone()),
        resource_servers: Arc::new(stores.resource_servers.clone()),
        requests: Arc::new(InMemoryAuthorizationRequests::new(&stores.clients)),
        grants: Arc::new(grants.clone()),
        codes: Arc::new(InMemoryAuthorizationCodes::new(&grants)),
        memberships: Arc::new(MembershipsOf::default()),
        verifier: Arc::new(hodor_oauth::testing::FakeVerifier),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    let tokens = TokenService::new(TokenPorts {
        units_of_work: Arc::new(units.clone()),
        applications: Arc::new(stores.applications.clone()),
        clients: Arc::new(stores.clients.clone()),
        resource_servers: Arc::new(stores.resource_servers.clone()),
        grants: Arc::new(grants.clone()),
        assertions: Arc::new(InMemoryClientAssertions::new(&stores.clients)),
        refresh_tokens: Arc::new(families.clone()),
        access_tokens: Arc::new(records.clone()),
        standing: Arc::new(StandingOf::default()),
        memberships: Arc::new(MembershipsOf::default()),
        mapping: hodor_oauth::api::ClaimMapping::new(
            Arc::new(units.clone()),
            Arc::new(hodor_oauth::testing::InMemoryClaimMappers::new(
                &stores.clients,
            )),
            Arc::new(MembershipsOf::default()),
            Arc::new(hodor_oauth::testing::ClaimSourcesOf::default()),
        ),
        secrets: Arc::new(FakeSecretBox),
        codes,
        keys: keys.clone(),
        verifier: Arc::new(Fakes),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(units.clone()),
        applications: Arc::new(stores.applications.clone()),
        clients: Arc::new(stores.clients.clone()),
        resource_servers: Arc::new(stores.resource_servers.clone()),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    let access = ResourceAccessService::new(ResourceAccessPorts {
        keys: keys.clone(),
        verifier: Arc::new(Fakes),
        register: AccessTokenRegister::new(
            Arc::new(units.clone()),
            Arc::new(records),
            Arc::new(grants),
            Arc::new(families),
            Arc::new(hodor_oauth::testing::StandingOf::default()),
        ),
        applications: applications.clone(),
        digest: Arc::new(FakeDigest),
        clock: clock.clone(),
    });
    let users = InMemoryUsers::default();
    let groups = InMemoryGroups::default();
    let revoked = RecordingAccessRevoker::default();
    let identity = IdentityService::new(
        Arc::new(units.clone()),
        Arc::new(users.clone()),
        clock.clone(),
    )
    .with_groups(Arc::new(groups.clone()));
    let provisioning = ProvisioningService::new(ProvisioningPorts {
        units_of_work: Arc::new(units.clone()),
        identity: identity.clone(),
        groups: GroupService::new(
            Arc::new(units.clone()),
            Arc::new(groups.clone()),
            Arc::new(users.clone()),
            Arc::new(FixedGroupPolicy(5)),
            clock.clone(),
        ),
        users: Arc::new(InMemoryProvisionedUsers::new(Arc::new(users))),
        provisioned_groups: Arc::new(InMemoryProvisionedGroups::new(Arc::new(groups))),
        deprovisioning: Arc::new(FixedDeprovisioning::default()),
        access: Arc::new(revoked.clone()),
        clock,
    });
    let acme = open_tenant("acme", &keys, &applications).await;
    let globex = open_tenant("globex", &keys, &applications).await;
    let router = public_router(
        Arc::new(Tenants {
            acme: acme.context.clone(),
            globex: globex.context.clone(),
        }),
        Router::new().nest(
            "/scim/v2",
            scim_routes(ScimState {
                access,
                provisioning,
                public_url: PUBLIC_URL.to_owned(),
            }),
        ),
        Router::new(),
        Limits::default(),
    );
    World {
        router,
        identity,
        tokens,
        revoked,
        acme,
        globex,
    }
}

impl World {
    async fn token(
        &self,
        tenant: &Tenant,
        client: &Credentials,
        resource: &str,
        scope: &str,
    ) -> String {
        let (issuer, endpoint) = issuer(tenant.slug);
        let request = TokenRequest::parse(
            client.basic(),
            vec![
                ("grant_type".to_owned(), "client_credentials".to_owned()),
                ("resource".to_owned(), resource.to_owned()),
                ("scope".to_owned(), scope.to_owned()),
            ],
        )
        .expect("a token request");
        self.tokens
            .token(
                &tenant.context,
                Issuer {
                    issuer: &issuer,
                    token_endpoint: &endpoint,
                },
                request,
                CorrelationId::generate(),
            )
            .await
            .expect("storage")
            .expect("tokens")
            .access_token
            .expose()
            .clone()
    }

    async fn scim_token(&self, tenant: &Tenant) -> String {
        self.token(tenant, &tenant.provisioner, "urn:hodor:scim", "scim")
            .await
    }

    async fn revoke(&self, tenant: &Tenant, client: &Credentials, token: &str) {
        let (issuer, endpoint) = issuer(tenant.slug);
        let query = TokenQuery::parse(client.basic(), vec![("token".to_owned(), token.to_owned())])
            .expect("a query");
        self.tokens
            .revoke(
                &tenant.context,
                Issuer {
                    issuer: &issuer,
                    token_endpoint: &endpoint,
                },
                &format!("{issuer}/oauth2/revoke"),
                query,
                CorrelationId::generate(),
            )
            .await
            .expect("storage")
            .expect("revoked");
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<(&str, String)>,
    ) -> Reply {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, "auth.example");
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let request = match body {
            Some((media_type, body)) => request
                .header(header::CONTENT_TYPE, media_type)
                .body(Body::from(body)),
            None => request.body(Body::empty()),
        }
        .expect("request");
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("response");
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.expect("body").to_bytes();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        }
    }

    async fn scim(&self, method: Method, path: &str, token: &str, body: Option<Value>) -> Reply {
        self.send(
            method,
            path,
            Some(token),
            body.map(|body| (SCIM_MEDIA_TYPE, body.to_string())),
        )
        .await
    }
}

fn challenge(reply: &Reply) -> &str {
    reply
        .headers
        .get(header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
}

fn assert_scim_error(reply: &Reply, status: StatusCode, scim_type: Option<&str>) {
    assert_eq!(reply.status, status, "{}", reply.body);
    assert_eq!(
        reply.body["schemas"],
        json!(["urn:ietf:params:scim:api:messages:2.0:Error"])
    );
    assert_eq!(reply.body["status"], status.as_u16().to_string());
    assert_eq!(
        reply.body.get("scimType").and_then(Value::as_str),
        scim_type,
        "{}",
        reply.body
    );
    assert!(reply.body["detail"].is_string());
    assert_eq!(
        reply
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(SCIM_MEDIA_TYPE)
    );
}

/// Every route of the surface, with a body where it takes one.
fn routes() -> Vec<(Method, String, Option<Value>)> {
    let id = UserId::generate();
    let user = json!({ "schemas": [USER], "userName": "nobody" });
    let group = json!({ "schemas": [GROUP], "displayName": "nobody" });
    let patch = json!({ "schemas": [PATCH], "Operations": [{ "op": "replace", "path": "active", "value": true }] });
    vec![
        (Method::GET, "/ServiceProviderConfig".to_owned(), None),
        (Method::GET, "/ResourceTypes".to_owned(), None),
        (Method::GET, "/ResourceTypes/User".to_owned(), None),
        (Method::GET, "/Schemas".to_owned(), None),
        (Method::GET, format!("/Schemas/{USER}"), None),
        (Method::GET, "/Users".to_owned(), None),
        (Method::POST, "/Users".to_owned(), Some(user.clone())),
        (Method::GET, format!("/Users/{id}"), None),
        (Method::PUT, format!("/Users/{id}"), Some(user)),
        (Method::PATCH, format!("/Users/{id}"), Some(patch.clone())),
        (Method::DELETE, format!("/Users/{id}"), None),
        (Method::GET, "/Groups".to_owned(), None),
        (Method::POST, "/Groups".to_owned(), Some(group.clone())),
        (Method::GET, format!("/Groups/{id}"), None),
        (Method::PUT, format!("/Groups/{id}"), Some(group)),
        (Method::PATCH, format!("/Groups/{id}"), Some(patch)),
        (Method::DELETE, format!("/Groups/{id}"), None),
        (
            Method::POST,
            "/Bulk".to_owned(),
            Some(json!({ "schemas": [BULK], "Operations": [] })),
        ),
        (Method::POST, "/.search".to_owned(), None),
    ]
}

#[tokio::test]
async fn every_route_refuses_a_token_that_is_not_good_here() {
    let world = world().await;
    let acme = &world.acme;
    let other_audience = world
        .token(acme, &acme.payroll, "urn:example:payroll", "payroll:read")
        .await;
    let without_scope = world
        .token(acme, &acme.auditor, "urn:hodor:scim", "scim:audit")
        .await;
    let of_globex = world.scim_token(&world.globex).await;
    for (method, path, body) in routes() {
        let path = format!("/t/acme/scim/v2{path}");
        let body = body.map(|body| (SCIM_MEDIA_TYPE, body.to_string()));
        let missing = world.send(method.clone(), &path, None, body.clone()).await;
        assert_scim_error(&missing, StatusCode::UNAUTHORIZED, None);
        assert_eq!(challenge(&missing), "Bearer", "{method} {path}");
        for token in [&other_audience, &of_globex, &"not.a.token".to_owned()] {
            let refused = world
                .send(method.clone(), &path, Some(token), body.clone())
                .await;
            assert_scim_error(&refused, StatusCode::UNAUTHORIZED, None);
            assert_eq!(
                challenge(&refused),
                "Bearer error=\"invalid_token\"",
                "{method} {path}"
            );
        }
        let refused = world
            .send(method.clone(), &path, Some(&without_scope), body.clone())
            .await;
        assert_scim_error(&refused, StatusCode::FORBIDDEN, None);
        assert_eq!(
            challenge(&refused),
            "Bearer error=\"insufficient_scope\", scope=\"scim\"",
            "{method} {path}"
        );
    }
}

#[tokio::test]
async fn a_revoked_token_is_refused_at_once() {
    let world = world().await;
    let token = world.scim_token(&world.acme).await;
    let path = "/t/acme/scim/v2/Users";
    assert_eq!(
        world.scim(Method::GET, path, &token, None).await.status,
        StatusCode::OK
    );
    world
        .revoke(&world.acme, &world.acme.provisioner, &token)
        .await;
    let refused = world.scim(Method::GET, path, &token, None).await;
    assert_scim_error(&refused, StatusCode::UNAUTHORIZED, None);
}

#[tokio::test]
async fn the_discovery_documents_say_what_is_supported() {
    let world = world().await;
    let token = world.scim_token(&world.acme).await;
    let base = "/t/acme/scim/v2";
    let config = world
        .scim(
            Method::GET,
            &format!("{base}/ServiceProviderConfig"),
            &token,
            None,
        )
        .await;
    assert_eq!(config.status, StatusCode::OK);
    assert_eq!(
        config
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(SCIM_MEDIA_TYPE)
    );
    assert_eq!(
        config
            .headers
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    for (feature, supported) in [
        ("patch", true),
        ("bulk", true),
        ("etag", true),
        ("filter", true),
        ("sort", true),
    ] {
        assert_eq!(config.body[feature]["supported"], supported, "{feature}");
    }
    assert_eq!(config.body["filter"]["maxResults"], 200);
    assert_eq!(
        config.body["meta"]["location"],
        format!("{PUBLIC_URL}{base}/ServiceProviderConfig")
    );

    let types = world
        .scim(Method::GET, &format!("{base}/ResourceTypes"), &token, None)
        .await;
    assert_eq!(types.body["totalResults"], 2);
    let user = world
        .scim(
            Method::GET,
            &format!("{base}/ResourceTypes/User"),
            &token,
            None,
        )
        .await;
    assert_eq!(user.body["endpoint"], "/Users");
    assert_eq!(
        user.body["schemaExtensions"][0]["schema"],
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
    );
    let schemas = world
        .scim(Method::GET, &format!("{base}/Schemas"), &token, None)
        .await;
    assert_eq!(schemas.body["totalResults"], 3);
    let group = world
        .scim(
            Method::GET,
            &format!("{base}/Schemas/{GROUP}"),
            &token,
            None,
        )
        .await;
    assert_eq!(group.body["name"], "Group");
    for path in [
        "/ResourceTypes/Device",
        "/Schemas/urn:example:none",
        "/Elsewhere",
    ] {
        let missing = world
            .scim(Method::GET, &format!("{base}{path}"), &token, None)
            .await;
        assert_scim_error(&missing, StatusCode::NOT_FOUND, None);
    }
}

#[tokio::test]
async fn users_are_created_read_replaced_and_listed() {
    let world = world().await;
    let token = world.scim_token(&world.acme).await;
    let base = "/t/acme/scim/v2";
    let created = world
        .scim(
            Method::POST,
            &format!("{base}/Users"),
            &token,
            Some(json!({
                "schemas": [USER],
                "userName": "bjensen@example.com",
                "externalId": "701984",
                "name": { "givenName": "Barbara", "familyName": "Jensen" },
                "displayName": "Babs Jensen",
                "emails": [{ "value": "babs@jensen.org" }],
            })),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    let id = created.body["id"].as_str().expect("an id").to_owned();
    let location = format!("{PUBLIC_URL}{base}/Users/{id}");
    assert_eq!(
        created
            .headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some(location.as_str())
    );
    assert_eq!(created.body["meta"]["location"], location);
    assert_eq!(created.body["userName"], "bjensen@example.com");
    assert_eq!(created.body["emails"][0]["primary"], true);

    let read = world
        .scim(Method::GET, &format!("{base}/Users/{id}"), &token, None)
        .await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.body, created.body);

    let replaced = world
        .scim(
            Method::PUT,
            &format!("{base}/Users/{id}"),
            &token,
            Some(json!({
                "schemas": [USER],
                "userName": "bjensen",
                "active": false,
                "emails": [{ "value": "bjensen@example.com", "primary": true }],
            })),
        )
        .await;
    assert_eq!(replaced.status, StatusCode::OK, "{}", replaced.body);
    assert_eq!(replaced.body["userName"], "bjensen");
    assert_eq!(replaced.body["active"], false);
    assert!(replaced.body.get("externalId").is_none());

    for name in ["ana", "carla"] {
        let made = world
            .send(
                Method::POST,
                &format!("{base}/Users"),
                Some(&token),
                Some((
                    "application/json",
                    json!({ "schemas": [USER], "userName": name }).to_string(),
                )),
            )
            .await;
        assert_eq!(
            made.status,
            StatusCode::CREATED,
            "application/json is accepted"
        );
    }
    let listed = world
        .scim(
            Method::GET,
            &format!("{base}/Users?filter=active%20eq%20true&sortBy=userName&sortOrder=descending&startIndex=1&count=1"),
            &token,
            None,
        )
        .await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.body);
    assert_eq!(
        listed.body["schemas"],
        json!(["urn:ietf:params:scim:api:messages:2.0:ListResponse"])
    );
    assert_eq!(listed.body["totalResults"], 2);
    assert_eq!(listed.body["itemsPerPage"], 1);
    assert_eq!(listed.body["startIndex"], 1);
    assert_eq!(listed.body["Resources"][0]["userName"], "carla");
    let counted = world
        .scim(Method::GET, &format!("{base}/Users?count=0"), &token, None)
        .await;
    assert_eq!(counted.body["totalResults"], 3);
    assert_eq!(counted.body["Resources"], json!([]));
}

#[tokio::test]
async fn the_standard_claims_scim_names_are_the_persons_and_the_others_are_kept() {
    let world = world().await;
    let token = world.scim_token(&world.acme).await;
    let base = "/t/acme/scim/v2";
    let created = world
        .scim(
            Method::POST,
            &format!("{base}/Users"),
            &token,
            Some(json!({
                "schemas": [USER],
                "userName": "bjensen",
                "name": { "givenName": "Barbara", "familyName": "Jensen", "middleName": "Jane" },
                "nickName": "Babs",
                "profileUrl": "https://login.example.com/bjensen",
                "timezone": "America/Los_Angeles",
                "phoneNumbers": [
                    { "value": "+1 555 555 0100", "type": "home" },
                    { "value": "+1 555 555 0123", "type": "work", "primary": true }
                ],
                "addresses": [{
                    "streetAddress": "100 Universal City Plaza", "locality": "Hollywood",
                    "region": "CA", "postalCode": "91608", "country": "US", "type": "work"
                }],
            })),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    let body = &created.body;
    assert_eq!(
        body["name"],
        json!({ "givenName": "Barbara", "familyName": "Jensen", "middleName": "Jane" })
    );
    assert_eq!(body["nickName"], "Babs");
    assert_eq!(body["timezone"], "America/Los_Angeles");
    assert_eq!(
        body["phoneNumbers"],
        json!([{ "value": "+15555550123", "primary": true }])
    );
    assert_eq!(
        body["addresses"],
        json!([{
            "streetAddress": "100 Universal City Plaza", "locality": "Hollywood",
            "region": "CA", "postalCode": "91608", "country": "US", "primary": true
        }])
    );
    let id = body["id"].as_str().expect("an id").to_owned();

    // They are the person's: an administrator sees them, the number
    // verified, and gives a birth date SCIM does not name.
    let person = world
        .identity
        .get(&world.acme.context, id.parse().expect("an identifier"))
        .await
        .expect("the person");
    let claims = &person.snapshot().claims;
    assert_eq!(claims.given_name.as_deref(), Some("Barbara"));
    assert_eq!(
        claims.profile.as_deref(),
        Some("https://login.example.com/bjensen")
    );
    assert!(claims.phone_number_verified);
    let mut more = claims.clone();
    more.birthdate = Some("1960".to_owned());
    world
        .identity
        .change_claims(
            &world.acme.context,
            person.id(),
            more,
            hodor_kernel::Caller::system(),
        )
        .await
        .expect("a birth date");

    // A PUT without them removes them, and keeps what SCIM does not name.
    let replaced = world
        .scim(
            Method::PUT,
            &format!("{base}/Users/{id}"),
            &token,
            Some(json!({ "schemas": [USER], "userName": "bjensen", "name": { "givenName": "Babs" } })),
        )
        .await;
    assert_eq!(replaced.status, StatusCode::OK, "{}", replaced.body);
    assert_eq!(replaced.body["name"], json!({ "givenName": "Babs" }));
    for gone in [
        "nickName",
        "timezone",
        "phoneNumbers",
        "addresses",
        "profileUrl",
    ] {
        assert!(replaced.body.get(gone).is_none(), "{gone}");
    }
    let person = world
        .identity
        .get(&world.acme.context, person.id())
        .await
        .expect("the person");
    assert_eq!(person.snapshot().claims.birthdate.as_deref(), Some("1960"));
    assert_eq!(person.snapshot().claims.phone_number, None);

    // A value that breaks the claim's rule is refused, and nothing changes.
    let refused = world
        .scim(
            Method::PUT,
            &format!("{base}/Users/{id}"),
            &token,
            Some(json!({ "schemas": [USER], "userName": "bjensen", "timezone": "Not a zone!" })),
        )
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
    assert_eq!(refused.body["scimType"], "invalidValue");

    // The filter on the given name reads the person's claim.
    let found = world
        .scim(
            Method::GET,
            &format!("{base}/Users?filter=name.givenName%20eq%20%22babs%22"),
            &token,
            None,
        )
        .await;
    assert_eq!(found.body["totalResults"], 1, "{}", found.body);
}

#[tokio::test]
async fn refusals_are_scim_errors_of_their_own_type() {
    let world = world().await;
    let token = world.scim_token(&world.acme).await;
    let base = "/t/acme/scim/v2";
    let ana = json!({ "schemas": [USER], "userName": "ana" });
    world
        .scim(
            Method::POST,
            &format!("{base}/Users"),
            &token,
            Some(ana.clone()),
        )
        .await;

    let taken = world
        .scim(
            Method::POST,
            &format!("{base}/Users"),
            &token,
            Some(json!({ "schemas": [USER], "userName": "ANA" })),
        )
        .await;
    assert_scim_error(&taken, StatusCode::CONFLICT, Some("uniqueness"));

    let deep = format!("{}userName%20pr{}", "(".repeat(11), ")".repeat(11));
    let filters = [
        ("title%20pr", "title cannot be filtered on"),
        (deep.as_str(), "a filter nests at most 10 levels deep"),
    ];
    for (filter, detail) in filters {
        let refused = world
            .scim(
                Method::GET,
                &format!("{base}/Users?filter={filter}"),
                &token,
                None,
            )
            .await;
        assert_scim_error(&refused, StatusCode::BAD_REQUEST, Some("invalidFilter"));
        assert_eq!(refused.body["detail"], detail);
    }
    let long = format!("{base}/Groups?filter={}", "a".repeat(1001));
    let refused = world.scim(Method::GET, &long, &token, None).await;
    assert_scim_error(&refused, StatusCode::BAD_REQUEST, Some("invalidFilter"));
    assert_eq!(
        refused.body["detail"],
        "a filter holds at most 1000 characters"
    );

    for query in ["sortBy=emails", "sortOrder=sideways", "count=many"] {
        let refused = world
            .scim(Method::GET, &format!("{base}/Users?{query}"), &token, None)
            .await;
        assert_scim_error(&refused, StatusCode::BAD_REQUEST, Some("invalidValue"));
    }

    let bad_bodies = [
        (json!({ "userName": "x" }), "invalidSyntax"),
        (
            json!({ "schemas": [USER], "userName": "has space" }),
            "invalidValue",
        ),
        (
            json!({ "schemas": [USER], "userName": "x1", "password": "secret" }),
            "mutability",
        ),
    ];
    for (body, scim_type) in bad_bodies {
        let refused = world
            .scim(Method::POST, &format!("{base}/Users"), &token, Some(body))
            .await;
        assert_scim_error(&refused, StatusCode::BAD_REQUEST, Some(scim_type));
    }
    let not_json = world
        .send(
            Method::POST,
            &format!("{base}/Users"),
            Some(&token),
            Some((SCIM_MEDIA_TYPE, "{".to_owned())),
        )
        .await;
    assert_scim_error(&not_json, StatusCode::BAD_REQUEST, Some("invalidSyntax"));
    let plain = world
        .send(
            Method::POST,
            &format!("{base}/Users"),
            Some(&token),
            Some(("text/plain", ana.to_string())),
        )
        .await;
    assert_scim_error(&plain, StatusCode::UNSUPPORTED_MEDIA_TYPE, None);

    for path in [
        format!("{base}/Users/{}", UserId::generate()),
        format!("{base}/Users/not-an-identifier"),
        format!("{base}/Groups/{}", UserId::generate()),
    ] {
        let missing = world.scim(Method::GET, &path, &token, None).await;
        assert_scim_error(&missing, StatusCode::NOT_FOUND, None);
    }
    let unsupported = world
        .scim(Method::POST, &format!("{base}/Users/.search"), &token, None)
        .await;
    assert_scim_error(&unsupported, StatusCode::NOT_IMPLEMENTED, None);
    for method in [Method::PATCH, Method::DELETE] {
        let body = (method == Method::PATCH).then(
            || json!({ "schemas": [PATCH], "Operations": [{ "op": "remove", "path": "title" }] }),
        );
        let missing = world
            .scim(
                method,
                &format!("{base}/Users/{}", UserId::generate()),
                &token,
                body,
            )
            .await;
        assert_scim_error(&missing, StatusCode::NOT_FOUND, None);
    }
}

#[tokio::test]
async fn groups_are_created_with_members_replaced_listed_and_deleted() {
    let world = world().await;
    let token = world.scim_token(&world.acme).await;
    let base = "/t/acme/scim/v2";
    let ana = world
        .scim(
            Method::POST,
            &format!("{base}/Users"),
            &token,
            Some(json!({ "schemas": [USER], "userName": "ana" })),
        )
        .await
        .body["id"]
        .as_str()
        .expect("an id")
        .to_owned();
    let created = world
        .scim(
            Method::POST,
            &format!("{base}/Groups"),
            &token,
            Some(json!({
                "schemas": [GROUP],
                "displayName": "finance",
                "externalId": "F-1",
                "members": [{ "value": ana, "type": "User" }],
            })),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    let id = created.body["id"].as_str().expect("an id").to_owned();
    assert_eq!(created.body["members"][0]["display"], "ana");

    let taken = world
        .scim(
            Method::POST,
            &format!("{base}/Groups"),
            &token,
            Some(json!({ "schemas": [GROUP], "displayName": "FINANCE" })),
        )
        .await;
    assert_scim_error(&taken, StatusCode::CONFLICT, Some("uniqueness"));
    let too_many: Vec<Value> = (0..1001)
        .map(|_| json!({ "value": UserId::generate().to_string() }))
        .collect();
    let refused = world
        .scim(
            Method::PUT,
            &format!("{base}/Groups/{id}"),
            &token,
            Some(json!({ "schemas": [GROUP], "displayName": "finance", "members": too_many })),
        )
        .await;
    assert_scim_error(&refused, StatusCode::BAD_REQUEST, Some("invalidValue"));
    assert_eq!(
        refused.body["detail"],
        "a group takes at most 1000 members in one request"
    );

    let listed = world
        .scim(
            Method::GET,
            &format!("{base}/Groups?filter=members%20eq%20%22{ana}%22"),
            &token,
            None,
        )
        .await;
    assert_eq!(listed.body["totalResults"], 1);
    let user = world
        .scim(Method::GET, &format!("{base}/Users/{ana}"), &token, None)
        .await;
    assert_eq!(user.body["groups"][0]["value"], id);

    let replaced = world
        .scim(
            Method::PUT,
            &format!("{base}/Groups/{id}"),
            &token,
            Some(json!({ "schemas": [GROUP], "displayName": "Finance team" })),
        )
        .await;
    assert_eq!(replaced.status, StatusCode::OK);
    assert_eq!(replaced.body["displayName"], "Finance team");
    assert_eq!(replaced.body["members"], json!([]));

    let deleted = world
        .scim(Method::DELETE, &format!("{base}/Groups/{id}"), &token, None)
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    let gone = world
        .scim(Method::GET, &format!("{base}/Groups/{id}"), &token, None)
        .await;
    assert_scim_error(&gone, StatusCode::NOT_FOUND, None);
}

#[tokio::test]
async fn another_tenants_resources_are_answered_as_ones_that_do_not_exist() {
    let world = world().await;
    let acme = world.scim_token(&world.acme).await;
    let globex = world.scim_token(&world.globex).await;
    let user = world
        .scim(
            Method::POST,
            "/t/acme/scim/v2/Users",
            &acme,
            Some(json!({ "schemas": [USER], "userName": "ana" })),
        )
        .await
        .body["id"]
        .as_str()
        .expect("an id")
        .to_owned();
    let group = world
        .scim(
            Method::POST,
            "/t/acme/scim/v2/Groups",
            &acme,
            Some(json!({ "schemas": [GROUP], "displayName": "finance" })),
        )
        .await
        .body["id"]
        .as_str()
        .expect("an id")
        .to_owned();
    for (method, path, body) in [
        (Method::GET, format!("/Users/{user}"), None),
        (
            Method::PUT,
            format!("/Users/{user}"),
            Some(json!({ "schemas": [USER], "userName": "ana" })),
        ),
        (Method::GET, format!("/Groups/{group}"), None),
        (
            Method::PUT,
            format!("/Groups/{group}"),
            Some(json!({ "schemas": [GROUP], "displayName": "finance" })),
        ),
        (Method::DELETE, format!("/Groups/{group}"), None),
    ] {
        let missing = world
            .scim(method, &format!("/t/globex/scim/v2{path}"), &globex, body)
            .await;
        assert_scim_error(&missing, StatusCode::NOT_FOUND, None);
    }
    let refused = world
        .scim(
            Method::POST,
            "/t/globex/scim/v2/Groups",
            &globex,
            Some(json!({ "schemas": [GROUP], "displayName": "finance", "members": [{ "value": user }] })),
        )
        .await;
    assert_scim_error(&refused, StatusCode::BAD_REQUEST, Some("invalidValue"));
    let listed = world
        .scim(Method::GET, "/t/globex/scim/v2/Users", &globex, None)
        .await;
    assert_eq!(listed.body["totalResults"], 0);
    let still = world
        .scim(
            Method::GET,
            &format!("/t/acme/scim/v2/Groups/{group}"),
            &acme,
            None,
        )
        .await;
    assert_eq!(
        still.status,
        StatusCode::OK,
        "the group is still where it belongs"
    );
}

fn header_text(reply: &Reply, name: header::HeaderName) -> Option<String> {
    reply
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

impl World {
    async fn conditional(
        &self,
        method: Method,
        path: &str,
        token: &str,
        condition: (header::HeaderName, &str),
        body: Option<Value>,
    ) -> Reply {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, "auth.example")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(condition.0, condition.1);
        let request = match body {
            Some(body) => request
                .header(header::CONTENT_TYPE, SCIM_MEDIA_TYPE)
                .body(Body::from(body.to_string())),
            None => {
                request = request.header(header::CONTENT_LENGTH, "0");
                request.body(Body::empty())
            }
        }
        .expect("request");
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("response");
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.expect("body").to_bytes();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        }
    }
}

fn operations(operations: Value) -> Value {
    json!({ "schemas": [PATCH], "Operations": operations })
}

#[tokio::test]
async fn versions_guard_changes_and_answer_reads_that_changed_nothing() {
    let world = world().await;
    let token = world.scim_token(&world.acme).await;
    let base = "/t/acme/scim/v2";
    let created = world
        .scim(
            Method::POST,
            &format!("{base}/Users"),
            &token,
            Some(json!({ "schemas": [USER], "userName": "ana", "emails": [{ "value": "ana@example.com", "type": "work" }] })),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED);
    let first = header_text(&created, header::ETAG).expect("an ETag");
    assert_eq!(created.body["meta"]["version"], first.as_str());
    assert!(first.starts_with("W/\""), "{first}");
    let path = format!(
        "{base}/Users/{}",
        created.body["id"].as_str().expect("an id")
    );

    let unchanged = world
        .conditional(
            Method::GET,
            &path,
            &token,
            (header::IF_NONE_MATCH, &first),
            None,
        )
        .await;
    assert_eq!(unchanged.status, StatusCode::NOT_MODIFIED);
    assert_eq!(
        header_text(&unchanged, header::ETAG).as_deref(),
        Some(first.as_str())
    );

    let patched = world
        .conditional(
            Method::PATCH,
            &path,
            &token,
            (header::IF_MATCH, &first),
            Some(operations(json!([
                { "op": "replace", "path": "emails[type eq \"work\"].value", "value": "ana.silva@example.com" },
                { "op": "add", "value": { "displayName": "Ana Silva" } }
            ]))),
        )
        .await;
    assert_eq!(patched.status, StatusCode::OK, "{}", patched.body);
    assert_eq!(patched.body["emails"][0]["value"], "ana.silva@example.com");
    assert_eq!(patched.body["emails"][0]["type"], "work");
    assert_eq!(patched.body["displayName"], "Ana Silva");
    let second = header_text(&patched, header::ETAG).expect("an ETag");
    assert_ne!(second, first);

    // The acceptance: a change for a stale version is refused.
    for (method, body) in [
        (
            Method::PATCH,
            Some(operations(
                json!([{ "op": "replace", "path": "displayName", "value": "Late" }]),
            )),
        ),
        (
            Method::PUT,
            Some(json!({ "schemas": [USER], "userName": "ana" })),
        ),
        (Method::DELETE, None),
    ] {
        let stale = world
            .conditional(
                method.clone(),
                &path,
                &token,
                (header::IF_MATCH, &first),
                body,
            )
            .await;
        assert_scim_error(&stale, StatusCode::PRECONDITION_FAILED, None);
        assert_eq!(
            stale.body["detail"], "the resource changed since the version given",
            "{method}"
        );
    }
    let read = world.scim(Method::GET, &path, &token, None).await;
    assert_eq!(
        header_text(&read, header::ETAG).as_deref(),
        Some(second.as_str()),
        "nothing changed"
    );
    let any = world
        .conditional(
            Method::PATCH,
            &path,
            &token,
            (header::IF_MATCH, "*"),
            Some(operations(
                json!([{ "op": "replace", "path": "displayName", "value": "Ana" }]),
            )),
        )
        .await;
    assert_eq!(any.status, StatusCode::OK);

    let many: Vec<Value> = (0..101)
        .map(|_| json!({ "op": "replace", "path": "active", "value": true }))
        .collect();
    for (body, scim_type) in [
        (operations(Value::Array(many)), "tooMany"),
        (
            operations(json!([{ "op": "replace", "path": "id", "value": "x" }])),
            "mutability",
        ),
        (
            operations(json!([{ "op": "add", "path": "emails[", "value": 1 }])),
            "invalidPath",
        ),
        (operations(json!([{ "op": "remove" }])), "noTarget"),
        (
            operations(
                json!([{ "op": "replace", "path": "emails[value co \"nowhere\"].type", "value": "home" }]),
            ),
            "noTarget",
        ),
        (json!({ "Operations": [] }), "invalidSyntax"),
    ] {
        let refused = world.scim(Method::PATCH, &path, &token, Some(body)).await;
        assert_scim_error(&refused, StatusCode::BAD_REQUEST, Some(scim_type));
    }
}

#[tokio::test]
async fn deleting_a_user_deprovisions_them_and_they_are_gone_from_scim() {
    let world = world().await;
    let token = world.scim_token(&world.acme).await;
    let base = "/t/acme/scim/v2";
    let created = world
        .scim(
            Method::POST,
            &format!("{base}/Users"),
            &token,
            Some(json!({ "schemas": [USER], "userName": "ana" })),
        )
        .await;
    let id = created.body["id"].as_str().expect("an id").to_owned();
    let path = format!("{base}/Users/{id}");
    let deleted = world.scim(Method::DELETE, &path, &token, None).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    let gone = world.scim(Method::GET, &path, &token, None).await;
    assert_scim_error(&gone, StatusCode::NOT_FOUND, None);
    let listed = world
        .scim(Method::GET, &format!("{base}/Users"), &token, None)
        .await;
    assert_eq!(listed.body["totalResults"], 0);
    let again = world.scim(Method::DELETE, &path, &token, None).await;
    assert_scim_error(&again, StatusCode::NOT_FOUND, None);
    assert_eq!(
        world.revoked.revoked().len(),
        1,
        "the person's access ended"
    );
    assert_eq!(world.revoked.revoked()[0].1.to_string(), id);
}

#[tokio::test]
async fn a_bulk_request_resolves_references_in_order_and_is_bounded() {
    let world = world().await;
    let token = world.scim_token(&world.acme).await;
    let base = "/t/acme/scim/v2";
    let bulk = |operations: Value, fail_on_errors: Option<u64>| {
        let mut body = json!({ "schemas": [BULK], "Operations": operations });
        if let Some(limit) = fail_on_errors {
            body["failOnErrors"] = json!(limit);
        }
        body
    };
    let answered = world
        .scim(
            Method::POST,
            &format!("{base}/Bulk"),
            &token,
            Some(bulk(
                json!([
                    { "method": "POST", "path": "/Users", "bulkId": "ana", "data": { "schemas": [USER], "userName": "ana" } },
                    { "method": "POST", "path": "/Groups", "bulkId": "finance", "data": { "schemas": [GROUP], "displayName": "finance", "members": [{ "value": "bulkId:ana" }, { "value": "bulkId:bob" }] } },
                    { "method": "POST", "path": "/Users", "bulkId": "bob", "data": { "schemas": [USER], "userName": "bob" } },
                    { "method": "POST", "path": "/Groups", "bulkId": "payables", "data": { "schemas": [GROUP], "displayName": "payables", "members": [{ "value": "bulkId:ana" }, { "value": "bulkId:bob" }] } },
                    { "method": "PATCH", "path": "/Users/bulkId:ana", "data": { "schemas": [PATCH], "Operations": [{ "op": "replace", "path": "displayName", "value": "Ana" }] } },
                    { "method": "POST", "path": "/Users", "bulkId": "ana", "data": { "schemas": [USER], "userName": "ana2" } },
                    { "method": "GET", "path": "/Users" },
                    { "method": "DELETE", "path": "/Groups/bulkId:payables" }
                ]),
                None,
            )),
        )
        .await;
    assert_eq!(answered.status, StatusCode::OK, "{}", answered.body);
    assert_eq!(
        answered.body["schemas"],
        json!(["urn:ietf:params:scim:api:messages:2.0:BulkResponse"])
    );
    let results = answered.body["Operations"].as_array().expect("results");
    let statuses: Vec<&str> = results
        .iter()
        .map(|result| result["status"].as_str().expect("a status"))
        .collect();
    assert_eq!(
        statuses,
        ["201", "400", "201", "201", "200", "400", "400", "204"]
    );
    assert_eq!(
        results[1]["response"]["scimType"], "invalidValue",
        "bob comes later"
    );
    assert!(
        results[0]["location"]
            .as_str()
            .is_some_and(|location| location.contains("/Users/"))
    );
    assert!(
        results[0]["version"]
            .as_str()
            .is_some_and(|version| version.starts_with("W/"))
    );
    assert_eq!(results[0]["bulkId"], "ana");
    let groups = world
        .scim(Method::GET, &format!("{base}/Groups"), &token, None)
        .await;
    assert_eq!(
        groups.body["totalResults"], 0,
        "finance failed, payables was deleted"
    );

    // failOnErrors: the rest is not done.
    let stopped = world
        .scim(
            Method::POST,
            &format!("{base}/Bulk"),
            &token,
            Some(bulk(
                json!([
                    { "method": "PUT", "path": format!("/Users/{}", UserId::generate()), "data": { "schemas": [USER], "userName": "xavier" } },
                    { "method": "POST", "path": "/Users", "bulkId": "carla", "data": { "schemas": [USER], "userName": "carla" } }
                ]),
                Some(1),
            )),
        )
        .await;
    assert_eq!(stopped.body["Operations"].as_array().map(Vec::len), Some(1));
    assert_eq!(stopped.body["Operations"][0]["status"], "404");

    // The acceptance: a bulk request past the bound is refused whole.
    let too_many: Vec<Value> = (0..101)
        .map(|index| json!({ "method": "POST", "path": "/Users", "bulkId": format!("u{index}"), "data": { "schemas": [USER], "userName": format!("u{index}") } }))
        .collect();
    let refused = world
        .scim(
            Method::POST,
            &format!("{base}/Bulk"),
            &token,
            Some(bulk(Value::Array(too_many), None)),
        )
        .await;
    assert_scim_error(&refused, StatusCode::PAYLOAD_TOO_LARGE, Some("tooMany"));
    let large = bulk(
        json!([{ "method": "POST", "path": "/Users", "bulkId": "big", "data": { "schemas": [USER], "userName": "big", "title": "x".repeat(1_100_000) } }]),
        None,
    );
    let refused = world
        .scim(Method::POST, &format!("{base}/Bulk"), &token, Some(large))
        .await;
    assert_scim_error(&refused, StatusCode::PAYLOAD_TOO_LARGE, Some("tooMany"));
    let users = world
        .scim(Method::GET, &format!("{base}/Users"), &token, None)
        .await;
    assert_eq!(
        users.body["totalResults"], 2,
        "only ana and bob: nothing of the refused requests"
    );
}
