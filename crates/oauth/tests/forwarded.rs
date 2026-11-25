//! Clients that prove who they are with the identity a trusted proxy
//! forwards: `tls_client_auth`, `spiffe_x509` and `linkerd_identity`, on
//! the in-memory stores and a certificate check that reads certificates
//! written for the test.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "An identity
//! forwarded by a proxy".

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::sealing::testing::FakeSecretBox;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, Clock as _, CorrelationId, PublicKey, SignatureAlgorithm, SignatureVerifier,
    TenantContext, TenantId, Timestamp, UnitOfWorkFactory as _, UserId,
};
use hodor_keys::api::{
    CheckedSource, KeyAlgorithm, KeyService, RotationPolicy, TrustBundle, TrustDomain,
    TrustDomainPorts, TrustDomainService, TrustDomainStore as _,
};
use hodor_keys::testing::{
    FakeBundleEndpoints, FakeKeyProvider, InMemoryKeys, InMemoryTrustDomains,
};
use hodor_oauth::api::{
    ApplicationId, ApplicationPorts, ApplicationService, ApplicationSettings, AuthenticationMethod,
    AuthorizationCodePorts, AuthorizationCodeService, CertificateCheck, CertificateNames, ClientId,
    ClientSettings, ClientType, CreateClient, CreateResourceServer, ForwardedIdentity, GrantType,
    IssuedTokens, Issuer, LinkerdIdentity, ResourceServerSettings, ScopeDefinition, SpiffeId,
    TokenError, TokenPorts, TokenQuery, TokenRequest, TokenService,
};
use hodor_oauth::testing::{
    DistinctRandom, FakeVerifier, InMemoryAccessTokenRecords, InMemoryAuthorizationCodes,
    InMemoryAuthorizationRequests, InMemoryClientAssertions, InMemoryGrants, InMemoryRefreshTokens,
    InMemoryStores, MembershipsOf, StandingOf,
};
use serde_json::{Value, json};
use std::sync::Arc;
use time::Duration;

const ISSUER: &str = "https://hodor.example.com/t/acme";
const ENDPOINT: &str = "https://hodor.example.com/t/acme/oauth2/token";
const WEB: &str = "spiffe://cluster.local/ns/shop/sa/web";
const LINKERD_WEB: &str = "web.shop.serviceaccount.identity.linkerd.cluster.local";

const ISSUER_OF: Issuer<'static> = Issuer {
    issuer: ISSUER,
    token_endpoint: ENDPOINT,
};

/// Certificates written for the test: a DER sequence tag followed by JSON
/// naming the certificate's URIs and DNS names and the authority that
/// signed it. An authority's certificate is the tag followed by its name.
struct FakeCertificates;

fn fake_certificate(uris: &[&str], dns: &[&str], signed_by: &str) -> Vec<u8> {
    let mut der = vec![0x30];
    der.extend(
        json!({ "uris": uris, "dns": dns, "issuer": signed_by })
            .to_string()
            .bytes(),
    );
    der
}

impl CertificateCheck for FakeCertificates {
    fn names(&self, certificate: &[u8]) -> Option<CertificateNames> {
        let read: Value = serde_json::from_slice(certificate.strip_prefix(&[0x30])?).ok()?;
        let strings = |name: &str| -> Vec<String> {
            read[name]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|value| value.as_str().map(str::to_owned))
                .collect()
        };
        Some(CertificateNames {
            uris: strings("uris"),
            dns_names: strings("dns"),
        })
    }

    fn chains_to(
        &self,
        certificate: &[u8],
        _chain: &[Vec<u8>],
        authorities: &[&str],
        _now: Timestamp,
    ) -> bool {
        let Some(read) = certificate
            .strip_prefix(&[0x30])
            .and_then(|json| serde_json::from_slice::<Value>(json).ok())
        else {
            return false;
        };
        let issuer = read["issuer"].as_str().unwrap_or_default();
        authorities.iter().any(|element| {
            let element: Value = serde_json::from_str(element).expect("an element");
            let der = STANDARD
                .decode(element["x5c"][0].as_str().expect("x5c"))
                .expect("base64");
            der.strip_prefix(&[0x30]) == Some(issuer.as_bytes())
        })
    }
}

/// Checks the assertions of the fake verifier, and the signatures of the
/// fake key provider, so that introspection reads the tokens it signed.
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

/// A bundle trusting the authorities named.
fn bundle(authorities: &[&str]) -> TrustBundle {
    let elements: Vec<Value> = authorities
        .iter()
        .map(|name| {
            let mut der = vec![0x30];
            der.extend(name.bytes());
            json!({
                "use": "x509-svid",
                "kty": "EC",
                "crv": "P-256",
                "x": URL_SAFE_NO_PAD.encode([1_u8; 32]),
                "y": URL_SAFE_NO_PAD.encode([2_u8; 32]),
                "x5c": [STANDARD.encode(der)],
            })
        })
        .collect();
    TrustBundle::parse(json!({ "keys": elements }).to_string().as_bytes()).expect("a bundle")
}

struct World {
    units: InMemoryUnitOfWorkFactory,
    clock: Arc<FixedClock>,
    applications: ApplicationService,
    keys: KeyService,
    trust_domains: InMemoryTrustDomains,
    standing: StandingOf,
    tokens: TokenService,
    /// The same service, without forwarded identities.
    unconfigured: TokenService,
}

fn world() -> World {
    let units = InMemoryUnitOfWorkFactory::default();
    let stores = InMemoryStores::default();
    let grants = InMemoryGrants::new(&stores.clients);
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
    let trust_domains = InMemoryTrustDomains::default();
    let standing = StandingOf::default();
    let endpoints = FakeBundleEndpoints::default();
    let service = TrustDomainService::new(TrustDomainPorts {
        units_of_work: Arc::new(units.clone()),
        store: Arc::new(trust_domains.clone()),
        destinations: Arc::new(endpoints.clone()),
        http: Arc::new(endpoints),
        digest: Arc::new(FakeDigest),
        clock: clock.clone(),
    });
    let ports = TokenPorts {
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
    };
    let unconfigured = TokenService::new(ports.clone());
    let tokens = TokenService::new(ports)
        .with_trust_domains(service)
        .with_certificate_check(Arc::new(FakeCertificates));
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(units.clone()),
        applications: Arc::new(stores.applications),
        clients: Arc::new(stores.clients),
        resource_servers: Arc::new(stores.resource_servers),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    World {
        units,
        clock,
        applications,
        keys,
        trust_domains,
        standing,
        tokens,
        unconfigured,
    }
}

/// A tenant with a signing key and an application.
async fn tenant(world: &World) -> (TenantContext, ApplicationId) {
    let tenant = TenantContext::assume(TenantId::generate());
    world
        .keys
        .rotate_now(
            &tenant,
            KeyAlgorithm::Es256,
            &RotationPolicy::DEFAULT,
            Caller::system(),
        )
        .await
        .expect("a signing key");
    let application = world
        .applications
        .create_application(
            &tenant,
            ApplicationSettings {
                name: "Shop".to_owned(),
                first_party: true,
            },
            Caller::system(),
        )
        .await
        .expect("application");
    world
        .applications
        .create_resource_server(
            &tenant,
            CreateResourceServer {
                application_id: application.id(),
                audience: "https://api.shop.example".to_owned(),
                settings: ResourceServerSettings {
                    name: "Shop interface".to_owned(),
                    scopes: vec![ScopeDefinition {
                        name: "read".to_owned(),
                        description: "reads orders".to_owned(),
                    }],
                },
            },
            Caller::system(),
        )
        .await
        .expect("a resource server");
    (tenant, application.id())
}

async fn trust(world: &World, tenant: &TenantContext, name: &str, source: CheckedSource) {
    let domain = TrustDomain::add(name, source, world.clock.now()).expect("a trust domain");
    let mut uow = world.units.begin(tenant).await.expect("a unit of work");
    world
        .trust_domains
        .insert(uow.as_mut(), &domain)
        .await
        .expect("stored");
    uow.commit().await.expect("committed");
}

/// The identities a client is bound to: a SPIFFE identifier, a Linkerd
/// identity, or neither.
type Bound = (Option<SpiffeId>, Option<LinkerdIdentity>);

fn spiffe(id: &str) -> Bound {
    (Some(SpiffeId::parse(id).expect("an identifier")), None)
}

fn linkerd(id: &str) -> Bound {
    (None, Some(LinkerdIdentity::parse(id).expect("an identity")))
}

const UNBOUND: Bound = (None, None);

async fn client(
    world: &World,
    tenant: &TenantContext,
    application: ApplicationId,
    method: AuthenticationMethod,
    identity: Bound,
) -> ClientId {
    let account = UserId::generate();
    world.standing.workload(account, "service_account");
    let mut settings = ClientSettings::new(
        "Web",
        ClientType::Confidential,
        vec![GrantType::ClientCredentials],
        Vec::new(),
    );
    settings.authentication_method = method;
    (settings.spiffe_id, settings.linkerd_identity) = identity;
    settings.principal = Some(account);
    settings.allowed_scopes = vec!["read".to_owned()];
    let (client, secret) = world
        .applications
        .create_client(
            tenant,
            CreateClient {
                application_id: application,
                client_type: ClientType::Confidential,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client");
    assert!(
        secret.is_none(),
        "a client of a forwarded identity has no secret"
    );
    client.id()
}

async fn ask(
    world: &World,
    tenant: &TenantContext,
    client: ClientId,
    forwarded: Option<ForwardedIdentity>,
) -> Result<IssuedTokens, TokenError> {
    let mut request = TokenRequest::parse(
        None,
        vec![
            ("grant_type".to_owned(), "client_credentials".to_owned()),
            ("client_id".to_owned(), client.to_string()),
            ("scope".to_owned(), "read".to_owned()),
        ],
    )
    .expect("a request");
    request.client = request.client.with_forwarded(forwarded);
    world
        .tokens
        .token(tenant, ISSUER_OF, request, CorrelationId::generate())
        .await
        .expect("storage")
}

fn certificate(uris: &[&str], dns: &[&str], signed_by: &str) -> Option<ForwardedIdentity> {
    Some(ForwardedIdentity::Certificate {
        certificate: fake_certificate(uris, dns, signed_by),
        chain: Vec::new(),
    })
}

fn names(uris: &[&str], dns: &[&str]) -> Option<ForwardedIdentity> {
    Some(ForwardedIdentity::Names {
        uris: uris.iter().map(|&uri| uri.to_owned()).collect(),
        dns_names: dns.iter().map(|&name| name.to_owned()).collect(),
    })
}

fn refused(answer: Result<IssuedTokens, TokenError>) {
    let error = answer.expect_err("refused");
    assert!(error.is_invalid_client(), "{error:?}");
}

#[tokio::test]
async fn a_certificate_that_chains_to_the_bundle_proves_a_spiffe_x509_client() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    trust(
        &world,
        &tenant,
        "cluster.local",
        CheckedSource::Uploaded(bundle(&["mesh"])),
    )
    .await;
    let web = client(
        &world,
        &tenant,
        application,
        AuthenticationMethod::SpiffeX509,
        spiffe(WEB),
    )
    .await;
    let issued = ask(&world, &tenant, web, certificate(&[WEB], &[], "mesh"))
        .await
        .expect("a token");
    assert_eq!(issued.token_type, "Bearer");
}

#[tokio::test]
async fn a_certificate_that_does_not_chain_to_the_bundle_is_refused() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    trust(
        &world,
        &tenant,
        "cluster.local",
        CheckedSource::Uploaded(bundle(&["mesh"])),
    )
    .await;
    let web = client(
        &world,
        &tenant,
        application,
        AuthenticationMethod::SpiffeX509,
        spiffe(WEB),
    )
    .await;
    refused(ask(&world, &tenant, web, certificate(&[WEB], &[], "stranger")).await);
}

#[tokio::test]
async fn an_x509_svid_must_hold_the_clients_one_identifier() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    trust(
        &world,
        &tenant,
        "cluster.local",
        CheckedSource::Uploaded(bundle(&["mesh"])),
    )
    .await;
    let web = client(
        &world,
        &tenant,
        application,
        AuthenticationMethod::SpiffeX509,
        spiffe(WEB),
    )
    .await;
    let other = "spiffe://cluster.local/ns/shop/sa/api";
    refused(ask(&world, &tenant, web, certificate(&[other], &[], "mesh")).await);
    refused(
        ask(
            &world,
            &tenant,
            web,
            certificate(&[WEB, other], &[], "mesh"),
        )
        .await,
    );
    refused(ask(&world, &tenant, web, certificate(&[], &[], "mesh")).await);
    refused(
        ask(
            &world,
            &tenant,
            web,
            certificate(&["spiffe://cluster.local/ns/shop/sa/web/"], &[], "mesh"),
        )
        .await,
    );
}

#[tokio::test]
async fn names_without_a_certificate_are_believed_only_for_a_trust_domain_checked_by_the_mesh() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    trust(
        &world,
        &tenant,
        "cluster.local",
        CheckedSource::Uploaded(bundle(&["mesh"])),
    )
    .await;
    trust(&world, &tenant, "mesh.local", CheckedSource::Mesh).await;
    let by_bundle = client(
        &world,
        &tenant,
        application,
        AuthenticationMethod::SpiffeX509,
        spiffe(WEB),
    )
    .await;
    refused(ask(&world, &tenant, by_bundle, names(&[WEB], &[])).await);
    let in_mesh_id = "spiffe://mesh.local/ns/shop/sa/web";
    let by_mesh = client(
        &world,
        &tenant,
        application,
        AuthenticationMethod::SpiffeX509,
        spiffe(in_mesh_id),
    )
    .await;
    ask(&world, &tenant, by_mesh, names(&[in_mesh_id], &[]))
        .await
        .expect("the mesh checked it");
    ask(
        &world,
        &tenant,
        by_mesh,
        certificate(&[in_mesh_id], &[], "anyone"),
    )
    .await
    .expect("a forwarded certificate is read for its names, and the mesh checked it");
    refused(
        ask(
            &world,
            &tenant,
            by_mesh,
            names(&["spiffe://mesh.local/ns/shop/sa/api"], &[]),
        )
        .await,
    );
}

#[tokio::test]
async fn a_linkerd_identity_is_believed_only_exactly_and_only_for_the_mesh() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    trust(&world, &tenant, "cluster.local", CheckedSource::Mesh).await;
    trust(
        &world,
        &tenant,
        "bundled.local",
        CheckedSource::Uploaded(bundle(&["mesh"])),
    )
    .await;
    let web = client(
        &world,
        &tenant,
        application,
        AuthenticationMethod::LinkerdIdentity,
        linkerd(LINKERD_WEB),
    )
    .await;
    ask(
        &world,
        &tenant,
        web,
        Some(ForwardedIdentity::Linkerd(LINKERD_WEB.to_owned())),
    )
    .await
    .expect("a token");
    refused(
        ask(
            &world,
            &tenant,
            web,
            Some(ForwardedIdentity::Linkerd(
                "api.shop.serviceaccount.identity.linkerd.cluster.local".to_owned(),
            )),
        )
        .await,
    );
    refused(
        ask(
            &world,
            &tenant,
            web,
            certificate(&[], &[LINKERD_WEB], "mesh"),
        )
        .await,
    );
    let bundled_identity = "web.shop.serviceaccount.identity.linkerd.bundled.local";
    let bundled = client(
        &world,
        &tenant,
        application,
        AuthenticationMethod::LinkerdIdentity,
        linkerd(bundled_identity),
    )
    .await;
    refused(
        ask(
            &world,
            &tenant,
            bundled,
            Some(ForwardedIdentity::Linkerd(bundled_identity.to_owned())),
        )
        .await,
    );
}

#[tokio::test]
async fn tls_client_auth_matches_one_uri_or_one_dns_name_of_a_certificate() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    trust(
        &world,
        &tenant,
        "cluster.local",
        CheckedSource::Uploaded(bundle(&["mesh"])),
    )
    .await;
    let by_uri = client(
        &world,
        &tenant,
        application,
        AuthenticationMethod::TlsClientAuth,
        spiffe(WEB),
    )
    .await;
    ask(
        &world,
        &tenant,
        by_uri,
        certificate(&["https://web.example", WEB], &["web.local"], "mesh"),
    )
    .await
    .expect("one of its URIs");
    let by_dns = client(
        &world,
        &tenant,
        application,
        AuthenticationMethod::TlsClientAuth,
        linkerd(LINKERD_WEB),
    )
    .await;
    ask(
        &world,
        &tenant,
        by_dns,
        certificate(&[], &["web.local", LINKERD_WEB], "mesh"),
    )
    .await
    .expect("one of its DNS names");
    refused(
        ask(
            &world,
            &tenant,
            by_dns,
            certificate(&[LINKERD_WEB], &[], "mesh"),
        )
        .await,
    );
    refused(
        ask(
            &world,
            &tenant,
            by_uri,
            certificate(&[WEB], &[], "stranger"),
        )
        .await,
    );
    refused(
        ask(
            &world,
            &tenant,
            by_dns,
            Some(ForwardedIdentity::Linkerd(LINKERD_WEB.to_owned())),
        )
        .await,
    );
}

#[tokio::test]
async fn without_a_forwarded_identity_or_a_trust_domain_the_client_is_refused() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    let web = client(
        &world,
        &tenant,
        application,
        AuthenticationMethod::SpiffeX509,
        spiffe(WEB),
    )
    .await;
    refused(ask(&world, &tenant, web, certificate(&[WEB], &[], "mesh")).await);
    trust(
        &world,
        &tenant,
        "cluster.local",
        CheckedSource::Uploaded(bundle(&["mesh"])),
    )
    .await;
    refused(ask(&world, &tenant, web, None).await);
    ask(&world, &tenant, web, certificate(&[WEB], &[], "mesh"))
        .await
        .expect("once the trust domain is trusted");
}

#[tokio::test]
async fn another_tenants_trust_domain_of_the_same_name_is_never_read() {
    let world = world();
    let (ours, application) = tenant(&world).await;
    let (theirs, _) = tenant(&world).await;
    trust(
        &world,
        &theirs,
        "cluster.local",
        CheckedSource::Uploaded(bundle(&["theirs"])),
    )
    .await;
    trust(
        &world,
        &ours,
        "cluster.local",
        CheckedSource::Uploaded(bundle(&["ours"])),
    )
    .await;
    let web = client(
        &world,
        &ours,
        application,
        AuthenticationMethod::SpiffeX509,
        spiffe(WEB),
    )
    .await;
    refused(ask(&world, &ours, web, certificate(&[WEB], &[], "theirs")).await);
    ask(&world, &ours, web, certificate(&[WEB], &[], "ours"))
        .await
        .expect("its own bundle");
    refused(ask(&world, &theirs, web, certificate(&[WEB], &[], "theirs")).await);
}

#[tokio::test]
async fn a_forwarded_identity_never_stands_for_a_secret_or_proves_without_the_service() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    trust(
        &world,
        &tenant,
        "cluster.local",
        CheckedSource::Uploaded(bundle(&["mesh"])),
    )
    .await;
    let secret_client = client_with_secret(&world, &tenant, application).await;
    refused(
        ask(
            &world,
            &tenant,
            secret_client,
            certificate(&[WEB], &[], "mesh"),
        )
        .await,
    );
    let web = client(
        &world,
        &tenant,
        application,
        AuthenticationMethod::SpiffeX509,
        spiffe(WEB),
    )
    .await;
    let unconfigured = World {
        tokens: world.unconfigured.clone(),
        ..world
    };
    refused(
        ask(
            &unconfigured,
            &tenant,
            web,
            certificate(&[WEB], &[], "mesh"),
        )
        .await,
    );
}

async fn client_with_secret(
    world: &World,
    tenant: &TenantContext,
    application: ApplicationId,
) -> ClientId {
    let (client, _) = world
        .applications
        .create_client(
            tenant,
            CreateClient {
                application_id: application,
                client_type: ClientType::Confidential,
                settings: ClientSettings::new(
                    "Billing",
                    ClientType::Confidential,
                    vec![GrantType::ClientCredentials],
                    Vec::new(),
                ),
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client");
    client.id()
}

#[tokio::test]
async fn revocation_and_introspection_take_the_same_forwarded_identity() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    trust(
        &world,
        &tenant,
        "cluster.local",
        CheckedSource::Uploaded(bundle(&["mesh"])),
    )
    .await;
    let web = client(
        &world,
        &tenant,
        application,
        AuthenticationMethod::SpiffeX509,
        spiffe(WEB),
    )
    .await;
    let issued = ask(&world, &tenant, web, certificate(&[WEB], &[], "mesh"))
        .await
        .expect("a token");
    let query = |forwarded: Option<ForwardedIdentity>| {
        let mut query = TokenQuery::parse(
            None,
            vec![
                ("token".to_owned(), issued.access_token.expose().clone()),
                ("client_id".to_owned(), web.to_string()),
            ],
        )
        .expect("a query");
        query.client = query.client.with_forwarded(forwarded);
        query
    };
    let endpoint = format!("{ISSUER}/oauth2/introspect");
    let answer = world
        .tokens
        .introspect(
            &tenant,
            ISSUER_OF,
            &endpoint,
            query(certificate(&[WEB], &[], "stranger")),
        )
        .await
        .expect("storage");
    assert!(answer.expect_err("refused").is_invalid_client());
    let answer = world
        .tokens
        .introspect(
            &tenant,
            ISSUER_OF,
            &endpoint,
            query(certificate(&[WEB], &[], "mesh")),
        )
        .await
        .expect("storage")
        .expect("introspected");
    assert_eq!(answer["active"], json!(true));
    let revoked = world
        .tokens
        .revoke(
            &tenant,
            ISSUER_OF,
            &format!("{ISSUER}/oauth2/revoke"),
            query(certificate(&[WEB], &[], "mesh")),
            CorrelationId::generate(),
        )
        .await
        .expect("storage");
    assert!(revoked.is_ok());
}

#[tokio::test]
async fn a_client_is_bound_to_the_identity_its_method_takes() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    let (spiffe_refused, linkerd_refused) = (
        "oauth.client_spiffe_id_invalid",
        "oauth.client_linkerd_identity_invalid",
    );
    let both = (spiffe(WEB).0, linkerd(LINKERD_WEB).1);
    for (method, identity, principal, code) in [
        (
            AuthenticationMethod::SpiffeX509,
            UNBOUND,
            true,
            spiffe_refused,
        ),
        (
            AuthenticationMethod::SpiffeX509,
            linkerd(LINKERD_WEB),
            true,
            spiffe_refused,
        ),
        (
            AuthenticationMethod::LinkerdIdentity,
            spiffe(WEB),
            true,
            linkerd_refused,
        ),
        (
            AuthenticationMethod::LinkerdIdentity,
            UNBOUND,
            true,
            linkerd_refused,
        ),
        (
            AuthenticationMethod::TlsClientAuth,
            UNBOUND,
            true,
            spiffe_refused,
        ),
        (
            AuthenticationMethod::TlsClientAuth,
            both,
            true,
            spiffe_refused,
        ),
        (
            AuthenticationMethod::ClientSecretBasic,
            spiffe(WEB),
            true,
            spiffe_refused,
        ),
        (
            AuthenticationMethod::PrivateKeyJwt,
            linkerd(LINKERD_WEB),
            true,
            linkerd_refused,
        ),
        (
            AuthenticationMethod::SpiffeX509,
            spiffe(WEB),
            false,
            spiffe_refused,
        ),
        (
            AuthenticationMethod::LinkerdIdentity,
            linkerd(LINKERD_WEB),
            false,
            linkerd_refused,
        ),
    ] {
        let mut settings = ClientSettings::new(
            "Web",
            ClientType::Confidential,
            vec![GrantType::ClientCredentials],
            Vec::new(),
        );
        settings.authentication_method = method;
        (settings.spiffe_id, settings.linkerd_identity) = identity;
        settings.principal = principal.then(UserId::generate);
        let error = world
            .applications
            .create_client(
                &tenant,
                CreateClient {
                    application_id: application,
                    client_type: ClientType::Confidential,
                    settings,
                    secret_lifetime: None,
                },
                Caller::system(),
            )
            .await
            .expect_err("refused");
        assert_eq!(error.code(), code, "{method:?} {principal}");
    }
    let mut public = ClientSettings::new(
        "Browser",
        ClientType::Public,
        vec![GrantType::AuthorizationCode],
        vec!["https://shop.example/callback".to_owned()],
    );
    public.authentication_method = AuthenticationMethod::SpiffeX509;
    public.spiffe_id = spiffe(WEB).0;
    let error = world
        .applications
        .create_client(
            &tenant,
            CreateClient {
                application_id: application,
                client_type: ClientType::Public,
                settings: public,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect_err("a public client proves nothing");
    assert_eq!(error.code(), "oauth.client_authentication_method_invalid");
}
