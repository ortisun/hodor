//! A client of a service account proves who it is with a JWT-SVID
//! (`spiffe_jwt`) at the token, introspection and revocation endpoints, on
//! the in-memory stores.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "The SPIFFE
//! identifier of a client" and "Checking a JWT-SVID".

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::sealing::testing::FakeSecretBox;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, Clock as _, CorrelationId, PublicKey, SignatureAlgorithm, SignatureVerifier,
    TenantContext, TenantId, Timestamp, UserId,
};
use hodor_keys::api::{
    KeyAlgorithm, KeyService, RotationPolicy, TrustDomainPorts, TrustDomainService,
    TrustSourceRequest,
};
use hodor_keys::testing::{
    FakeBundleEndpoints, FakeKeyProvider, InMemoryKeys, InMemoryTrustDomains,
};
use hodor_oauth::api::{
    ApplicationId, ApplicationPorts, ApplicationService, ApplicationSettings, AuthenticationMethod,
    AuthorizationCodePorts, AuthorizationCodeService, BasicCredentials, ClientId, ClientSettings,
    ClientType, CreateClient, CreateResourceServer, GrantType, IssuedTokens, Issuer,
    ResourceServerSettings, SPIFFE_ASSERTION_TYPE, ScopeDefinition, SpiffeId, TokenError,
    TokenPorts, TokenQuery, TokenRequest, TokenService,
};
use hodor_oauth::testing::{
    DistinctRandom, FakeVerifier, InMemoryAccessTokenRecords, InMemoryAuthorizationCodes,
    InMemoryAuthorizationRequests, InMemoryClientAssertions, InMemoryGrants, InMemoryRefreshTokens,
    InMemoryStores, MembershipsOf, StandingOf, fake_signature,
};
use serde_json::{Value, json};
use std::sync::Arc;
use time::Duration;

const ISSUER: &str = "https://hodor.example.com/t/acme";
const OTHER_ISSUER: &str = "https://hodor.example.com/t/globex";
const TOKEN_ENDPOINT: &str = "https://hodor.example.com/t/acme/oauth2/token";
const REVOCATION: &str = "https://hodor.example.com/t/acme/oauth2/revoke";
const INTROSPECTION: &str = "https://hodor.example.com/t/acme/oauth2/introspect";
const AUDIENCE: &str = "https://api.payroll.example.com";
const EXPORT: &str = "spiffe://cluster.local/ns/payroll/sa/export";
const IMPORT: &str = "spiffe://cluster.local/ns/payroll/sa/import";

const ISSUER_OF: Issuer<'static> = Issuer {
    issuer: ISSUER,
    token_endpoint: TOKEN_ENDPOINT,
};

/// Checks both the stand-in signatures of JWT-SVIDs and those of the fake
/// key provider, which signs the tenant's access tokens here.
#[derive(Debug, Clone, Copy)]
struct BothFakes;

impl SignatureVerifier for BothFakes {
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

/// A key of a trust domain's authority, for [`FakeVerifier`]: a P-256
/// point made from `seed`. Never a real key.
#[derive(Debug, Clone, Copy)]
struct Authority {
    kid: &'static str,
    seed: u8,
}

impl Authority {
    fn public(self) -> PublicKey {
        PublicKey::P256 {
            x: vec![self.seed; 32],
            y: vec![self.seed.wrapping_add(1); 32],
        }
    }

    fn bundle(self) -> Vec<u8> {
        json!({ "spiffe_sequence": 1, "keys": [{
            "use": "jwt-svid", "kty": "EC", "crv": "P-256", "kid": self.kid,
            "x": URL_SAFE_NO_PAD.encode([self.seed; 32]),
            "y": URL_SAFE_NO_PAD.encode([self.seed.wrapping_add(1); 32]),
        }] })
        .to_string()
        .into_bytes()
    }

    /// A JWT-SVID with these claims, signed by this authority.
    fn sign(self, claims: &Value) -> String {
        let header = json!({ "alg": "ES256", "kid": self.kid, "typ": "JWT" });
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature = fake_signature(SignatureAlgorithm::Es256, &self.public(), input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }
}

const CLUSTER: Authority = Authority {
    kid: "cluster-2026-11",
    seed: 21,
};
const PARTNER: Authority = Authority {
    kid: "partner-2026-11",
    seed: 42,
};

struct World {
    standing: StandingOf,
    clock: Arc<FixedClock>,
    applications: ApplicationService,
    keys: KeyService,
    trust_domains: TrustDomainService,
    tokens: TokenService,
    /// The same, without trust domains.
    blind: TokenService,
}

fn world() -> World {
    let units = InMemoryUnitOfWorkFactory::default();
    let stores = InMemoryStores::default();
    let grants = InMemoryGrants::new(&stores.clients);
    let standing = StandingOf::default();
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + Duration::days(20_000),
    ));
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
    let keys = KeyService::new(
        Arc::new(units.clone()),
        Arc::new(InMemoryKeys::default()),
        Arc::new(FakeKeyProvider),
        clock.clone(),
    );
    let endpoints = FakeBundleEndpoints::default();
    let trust_domains = TrustDomainService::new(TrustDomainPorts {
        units_of_work: Arc::new(units.clone()),
        store: Arc::new(InMemoryTrustDomains::default()),
        destinations: Arc::new(endpoints.clone()),
        http: Arc::new(endpoints),
        digest: Arc::new(FakeDigest),
        clock: clock.clone(),
    });
    let blind = TokenService::new(TokenPorts {
        units_of_work: Arc::new(units.clone()),
        applications: Arc::new(stores.applications.clone()),
        clients: Arc::new(stores.clients.clone()),
        resource_servers: Arc::new(stores.resource_servers.clone()),
        grants: Arc::new(grants.clone()),
        assertions: Arc::new(InMemoryClientAssertions::new(&stores.clients)),
        refresh_tokens: Arc::new(InMemoryRefreshTokens::new(&grants)),
        access_tokens: Arc::new(InMemoryAccessTokenRecords::new(&stores.clients)),
        standing: Arc::new(standing.clone()),
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
        verifier: Arc::new(BothFakes),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    let tokens = blind.clone().with_trust_domains(trust_domains.clone());
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(units),
        applications: Arc::new(stores.applications),
        clients: Arc::new(stores.clients),
        resource_servers: Arc::new(stores.resource_servers),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    World {
        standing,
        clock,
        applications,
        keys,
        trust_domains,
        tokens,
        blind,
    }
}

/// A tenant with a signing key, the application that owns the resource
/// server, and `cluster.local`, whose bundle holds [`CLUSTER`]'s key.
struct Tenant {
    context: TenantContext,
    application: ApplicationId,
}

async fn tenant(world: &World) -> Tenant {
    let context = TenantContext::assume(TenantId::generate());
    world
        .keys
        .rotate_now(
            &context,
            KeyAlgorithm::Es256,
            &RotationPolicy::DEFAULT,
            Caller::system(),
        )
        .await
        .expect("a signing key");
    let application = world
        .applications
        .create_application(
            &context,
            ApplicationSettings {
                name: "Payroll".to_owned(),
                first_party: true,
            },
            Caller::system(),
        )
        .await
        .expect("application");
    world
        .applications
        .create_resource_server(
            &context,
            CreateResourceServer {
                application_id: application.id(),
                audience: AUDIENCE.to_owned(),
                settings: ResourceServerSettings {
                    name: "Payroll interface".to_owned(),
                    scopes: vec![ScopeDefinition {
                        name: "read".to_owned(),
                        description: "Read payroll".to_owned(),
                    }],
                },
            },
            Caller::system(),
        )
        .await
        .expect("resource server");
    trust(world, &context, "cluster.local", CLUSTER).await;
    Tenant {
        context,
        application: application.id(),
    }
}

async fn trust(world: &World, tenant: &TenantContext, name: &str, authority: Authority) {
    world
        .trust_domains
        .add(
            tenant,
            name,
            TrustSourceRequest::Uploaded {
                bundle: authority.bundle(),
            },
            Caller::system(),
        )
        .await
        .expect("trust domain");
}

/// A client of a service account that acts as it, bound to `spiffe_id`.
async fn workload_client(world: &World, tenant: &Tenant, spiffe_id: &str) -> ClientId {
    let account = UserId::generate();
    world.standing.workload(account, "service_account");
    let mut settings = ClientSettings::new(
        "Nightly export",
        ClientType::Confidential,
        vec![GrantType::ClientCredentials],
        Vec::new(),
    );
    settings.authentication_method = AuthenticationMethod::SpiffeJwt;
    settings.allowed_scopes = vec!["read".to_owned()];
    settings.principal = Some(account);
    settings.spiffe_id = Some(SpiffeId::parse(spiffe_id).expect("identifier"));
    let (client, secret) = world
        .applications
        .create_client(
            &tenant.context,
            CreateClient {
                application_id: tenant.application,
                client_type: ClientType::Confidential,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client");
    assert!(secret.is_none(), "a client of `spiffe_jwt` has no secret");
    client.id()
}

/// The claims of a JWT-SVID of `subject` for `audience`, made `offset`
/// seconds from now, so that two made apart differ.
fn claims(world: &World, subject: &str, audience: &str, offset: i64) -> Value {
    let at = world.clock.now().unix_timestamp() + offset;
    json!({ "sub": subject, "aud": [audience], "iat": at, "exp": at + 300 })
}

/// A fresh JWT-SVID of [`EXPORT`] for the tenant, signed by [`CLUSTER`].
fn svid(world: &World, offset: i64) -> String {
    CLUSTER.sign(&claims(world, EXPORT, ISSUER, offset))
}

fn with_svid(client: Option<ClientId>, svid: &str, rest: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut form: Vec<(String, String)> = rest
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    form.push((
        "client_assertion_type".to_owned(),
        SPIFFE_ASSERTION_TYPE.to_owned(),
    ));
    form.push(("client_assertion".to_owned(), svid.to_owned()));
    if let Some(client) = client {
        form.push(("client_id".to_owned(), client.to_string()));
    }
    form
}

async fn ask_with(
    tokens: &TokenService,
    tenant: &TenantContext,
    basic: Option<BasicCredentials>,
    form: Vec<(String, String)>,
) -> Result<IssuedTokens, TokenError> {
    let request = TokenRequest::parse(basic, form)?;
    tokens
        .token(tenant, ISSUER_OF, request, CorrelationId::generate())
        .await
        .expect("storage")
}

/// A token by client credentials for `client`, proven with `svid`.
async fn token(
    world: &World,
    tenant: &TenantContext,
    client: Option<ClientId>,
    svid: &str,
) -> Result<IssuedTokens, TokenError> {
    let form = with_svid(
        client,
        svid,
        &[("grant_type", "client_credentials"), ("resource", AUDIENCE)],
    );
    ask_with(&world.tokens, tenant, None, form).await
}

fn refused_as_client(result: Result<IssuedTokens, TokenError>) -> &'static str {
    let error = result.expect_err("refused");
    assert_eq!(error.error, "invalid_client", "{error:?}");
    error.reason
}

#[tokio::test]
async fn a_service_account_s_client_gets_a_token_with_its_jwt_svid() {
    let world = world();
    let tenant = tenant(&world).await;
    let client = workload_client(&world, &tenant, EXPORT).await;
    let issued = token(&world, &tenant.context, Some(client), &svid(&world, 0))
        .await
        .expect("a token");
    let payload = issued
        .access_token
        .expose()
        .split('.')
        .nth(1)
        .expect("claims")
        .to_owned();
    let access: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url")).expect("JSON");
    assert_eq!(access["client_id"], client.to_string());
    assert_eq!(access["principal_kind"], "service_account");
    assert_eq!(access["aud"], AUDIENCE);

    // Another JWT-SVID of the same workload is another proof.
    token(&world, &tenant.context, Some(client), &svid(&world, 1))
        .await
        .expect("a fresh JWT-SVID");
}

#[tokio::test]
async fn a_jwt_svid_presented_a_second_time_is_refused() {
    let world = world();
    let tenant = tenant(&world).await;
    let client = workload_client(&world, &tenant, EXPORT).await;
    let once = svid(&world, 0);
    token(&world, &tenant.context, Some(client), &once)
        .await
        .expect("the first time");
    assert_eq!(
        refused_as_client(token(&world, &tenant.context, Some(client), &once).await),
        "the JWT-SVID was presented before"
    );

    // Remembered even when the request it came with fails afterwards.
    let failing = svid(&world, 1);
    let form = with_svid(
        Some(client),
        &failing,
        &[("grant_type", "client_credentials"), ("scope", "write")],
    );
    let error = ask_with(&world.tokens, &tenant.context, None, form)
        .await
        .expect_err("a scope it may not have");
    assert_eq!(error.error, "invalid_scope");
    assert_eq!(
        refused_as_client(token(&world, &tenant.context, Some(client), &failing).await),
        "the JWT-SVID was presented before"
    );

    // And at another endpoint: it was presented to Hodor.
    let query = TokenQuery::parse(None, with_svid(Some(client), &once, &[("token", "x")]))
        .expect("a query");
    let error = world
        .tokens
        .introspect(&tenant.context, ISSUER_OF, INTROSPECTION, query)
        .await
        .expect("storage")
        .expect_err("presented before");
    assert_eq!(error.error, "invalid_client");
}

#[tokio::test]
async fn a_jwt_svid_of_another_trust_domain_is_refused() {
    let world = world();
    let tenant = tenant(&world).await;
    trust(&world, &tenant.context, "partner.example", PARTNER).await;
    let client = workload_client(&world, &tenant, EXPORT).await;
    // Signed by the authority of a trust domain the tenant trusts too, but
    // not the client's.
    let foreign = PARTNER.sign(&claims(&world, EXPORT, ISSUER, 0));
    assert_eq!(
        refused_as_client(token(&world, &tenant.context, Some(client), &foreign).await),
        "the trust domain's bundle has no key of the JWT-SVID's kid"
    );
    // The partner's own workload, for the client bound to `cluster.local`.
    let partner = PARTNER.sign(&claims(
        &world,
        "spiffe://partner.example/billing",
        ISSUER,
        1,
    ));
    assert!(
        token(&world, &tenant.context, Some(client), &partner)
            .await
            .is_err()
    );

    // A client of a trust domain the tenant does not trust.
    let stranger = workload_client(&world, &tenant, "spiffe://elsewhere.example/job").await;
    let svid = CLUSTER.sign(&claims(&world, "spiffe://elsewhere.example/job", ISSUER, 2));
    assert_eq!(
        refused_as_client(token(&world, &tenant.context, Some(stranger), &svid).await),
        "the tenant does not trust the client's trust domain"
    );

    // A trust domain the mesh checks has no bundle to check against.
    world
        .trust_domains
        .add(
            &tenant.context,
            "mesh.local",
            TrustSourceRequest::Mesh,
            Caller::system(),
        )
        .await
        .expect("trust domain");
    let meshed = workload_client(&world, &tenant, "spiffe://mesh.local/ns/a/sa/b").await;
    let svid = CLUSTER.sign(&claims(&world, "spiffe://mesh.local/ns/a/sa/b", ISSUER, 3));
    assert_eq!(
        refused_as_client(token(&world, &tenant.context, Some(meshed), &svid).await),
        "the client's trust domain is checked by the mesh and has no bundle"
    );
}

#[tokio::test]
async fn a_jwt_svid_for_another_identifier_is_refused() {
    let world = world();
    let tenant = tenant(&world).await;
    let export = workload_client(&world, &tenant, EXPORT).await;
    let import = workload_client(&world, &tenant, IMPORT).await;
    // The import job's JWT-SVID, presented as the export job's client.
    let theirs = CLUSTER.sign(&claims(&world, IMPORT, ISSUER, 0));
    assert_eq!(
        refused_as_client(token(&world, &tenant.context, Some(export), &theirs).await),
        "the JWT-SVID is not of the client's SPIFFE identifier"
    );
    // It is still good for its own client: a refused JWT-SVID is not
    // remembered.
    token(&world, &tenant.context, Some(import), &theirs)
        .await
        .expect("its own client");
}

#[tokio::test]
async fn a_jwt_svid_for_another_tenant_s_issuer_is_refused() {
    let world = world();
    let tenant = tenant(&world).await;
    let client = workload_client(&world, &tenant, EXPORT).await;
    for audience in [
        OTHER_ISSUER,
        TOKEN_ENDPOINT,
        "https://api.payroll.example.com",
    ] {
        let svid = CLUSTER.sign(&claims(&world, EXPORT, audience, 0));
        assert_eq!(
            refused_as_client(token(&world, &tenant.context, Some(client), &svid).await),
            "the JWT-SVID's audience is not the tenant's issuer alone",
            "{audience}"
        );
    }
}

#[tokio::test]
async fn a_jwt_svid_names_its_client_and_only_a_client_of_spiffe_jwt_uses_one() {
    let world = world();
    let tenant = tenant(&world).await;
    let client = workload_client(&world, &tenant, EXPORT).await;
    // Without `client_id`, the SPIFFE identifier would be the client
    // identifier, and no client has one.
    assert_eq!(
        refused_as_client(token(&world, &tenant.context, None, &svid(&world, 0)).await),
        "the client is unknown"
    );

    // A client of another method may not present one, and the client of
    // `spiffe_jwt` may present nothing else.
    let mut settings = ClientSettings::new(
        "Payroll service",
        ClientType::Confidential,
        vec![GrantType::ClientCredentials],
        Vec::new(),
    );
    settings.allowed_scopes = vec!["read".to_owned()];
    let (other, secret) = world
        .applications
        .create_client(
            &tenant.context,
            CreateClient {
                application_id: tenant.application,
                client_type: ClientType::Confidential,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client");
    assert_eq!(
        refused_as_client(token(&world, &tenant.context, Some(other.id()), &svid(&world, 1)).await),
        "the client used another method than its own"
    );
    let secret = secret.expect("a secret").expose().to_owned();
    let form = vec![("grant_type".to_owned(), "client_credentials".to_owned())];
    let basic = BasicCredentials {
        client_id: client.to_string(),
        secret: secret.into(),
    };
    let error = ask_with(&world.tokens, &tenant.context, Some(basic), form)
        .await
        .expect_err("refused");
    assert_eq!(error.error, "invalid_client");

    // A server that was given no trust domains checks no JWT-SVID.
    let form = with_svid(
        Some(client),
        &svid(&world, 2),
        &[("grant_type", "client_credentials")],
    );
    let error = ask_with(&world.blind, &tenant.context, None, form)
        .await
        .expect_err("refused");
    assert_eq!(error.reason, "this server checks no JWT-SVID");
}

#[tokio::test]
async fn a_workload_introspects_and_revokes_its_tokens_with_jwt_svids() {
    let world = world();
    let tenant = tenant(&world).await;
    let client = workload_client(&world, &tenant, EXPORT).await;
    let issued = token(&world, &tenant.context, Some(client), &svid(&world, 0))
        .await
        .expect("a token");
    let access = issued.access_token.expose().clone();
    let ask = |svid: String| {
        TokenQuery::parse(None, with_svid(Some(client), &svid, &[("token", &access)]))
            .expect("a query")
    };
    let answer = world
        .tokens
        .introspect(
            &tenant.context,
            ISSUER_OF,
            INTROSPECTION,
            ask(svid(&world, 1)),
        )
        .await
        .expect("storage")
        .expect("answered");
    assert_eq!(answer["active"], true);
    assert_eq!(answer["client_id"], client.to_string());

    world
        .tokens
        .revoke(
            &tenant.context,
            ISSUER_OF,
            REVOCATION,
            ask(svid(&world, 2)),
            CorrelationId::generate(),
        )
        .await
        .expect("storage")
        .expect("revoked");
    let answer = world
        .tokens
        .introspect(
            &tenant.context,
            ISSUER_OF,
            INTROSPECTION,
            ask(svid(&world, 3)),
        )
        .await
        .expect("storage")
        .expect("answered");
    assert_eq!(answer, json!({ "active": false }));

    // The endpoint's own address is not an audience of a JWT-SVID.
    let at_endpoint = CLUSTER.sign(&claims(&world, EXPORT, INTROSPECTION, 4));
    let error = world
        .tokens
        .introspect(&tenant.context, ISSUER_OF, INTROSPECTION, ask(at_endpoint))
        .await
        .expect("storage")
        .expect_err("refused");
    assert_eq!(error.error, "invalid_client");
}
