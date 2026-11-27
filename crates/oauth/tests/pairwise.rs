//! Pairwise subject identifiers on the in-memory stores: the token
//! endpoint, introspection, token exchange and the end-session endpoint
//! naming a person as each client knows them, the tenant's pairwise secret,
//! and the sector identifier address fetched when it is set.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::sealing::testing::FakeSecretBox;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, Clock as _, CorrelationId, DomainError, PublicKey, SignatureAlgorithm,
    SignatureVerifier, TenantContext, TenantId, Timestamp, UserId,
};
use hodor_keys::api::{KeyAlgorithm, KeyService, RotationPolicy};
use hodor_keys::testing::{FakeKeyProvider, InMemoryKeys};
use hodor_oauth::api::{
    ApplicationId, ApplicationPorts, ApplicationService, ApplicationSettings, AuthenticationMethod,
    AuthorizationCodePorts, AuthorizationCodeService, AuthorizationParameters, BasicCredentials,
    ClientId, ClientSettings, ClientType, CreateClient, CreateResourceServer, CurrentSession,
    ExchangeRule, GrantType, IdTokenHint, IssuedTokens, Issuer, LogoutDecision, LogoutPorts,
    LogoutRequest, LogoutService, PairwiseSubjects, ResourceServerSettings, ScopeDefinition,
    SignedInPerson, SubjectType, TokenError, TokenPorts, TokenQuery, TokenRequest, TokenService,
    s256_challenge,
};
use hodor_oauth::testing::{
    DistinctRandom, FakeDestinations, FakeVerifier, InMemoryAccessTokenRecords,
    InMemoryAuthorizationCodes, InMemoryAuthorizationRequests, InMemoryClientAssertions,
    InMemoryGrants, InMemoryPairwiseSecrets, InMemoryRefreshTokens, InMemoryStores, MembershipsOf,
    PairwiseSecretStorePorts, SectorDocuments, StandingOf, pairwise_subjects,
    run_pairwise_secret_contract,
};
use hodor_session::api::SessionId;
use serde_json::{Value, json};
use std::sync::Arc;
use time::Duration;

const ISSUER: &str = "https://hodor.example.com/t/acme";
const TOKEN_ENDPOINT: &str = "https://hodor.example.com/t/acme/oauth2/token";
const INTROSPECTION: &str = "https://hodor.example.com/t/acme/oauth2/introspect";
const AUDIENCE: &str = "https://api.payroll.example.com";
const LEDGER: &str = "urn:example:ledger";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// The two hosts, and so the two sectors, of the clients here.
const PAYROLL: &str = "https://payroll.example.com/callback";
const PAYROLL_OTHER: &str = "https://payroll.example.com:8443/other";
const TRAVEL: &str = "https://travel.example.net/callback";
const SECTOR_DOCUMENT: &str = "https://sector.example.org/redirect_uris.json";

const ISSUER_OF: Issuer<'static> = Issuer {
    issuer: ISSUER,
    token_endpoint: TOKEN_ENDPOINT,
};

/// Checks both the stand-in signatures of client assertions and those of
/// the fake key provider, which signs the tenant's tokens here.
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

struct World {
    units: InMemoryUnitOfWorkFactory,
    standing: StandingOf,
    clock: Arc<FixedClock>,
    records: InMemoryAccessTokenRecords,
    secrets: InMemoryPairwiseSecrets,
    documents: SectorDocuments,
    stores: InMemoryStores,
    codes: AuthorizationCodeService,
    applications: ApplicationService,
    keys: KeyService,
    pairwise: PairwiseSubjects,
    tokens: TokenService,
    /// The same token endpoint, given no pairwise subjects.
    without_pairwise: TokenService,
}

fn world() -> World {
    let units = InMemoryUnitOfWorkFactory::default();
    let stores = InMemoryStores::default();
    let requests = InMemoryAuthorizationRequests::new(&stores.clients);
    let grants = InMemoryGrants::new(&stores.clients);
    let code_store = InMemoryAuthorizationCodes::new(&grants);
    let families = InMemoryRefreshTokens::new(&grants);
    let records = InMemoryAccessTokenRecords::new(&stores.clients);
    let standing = StandingOf::default();
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + Duration::days(20_000),
    ));
    let codes = AuthorizationCodeService::new(AuthorizationCodePorts {
        units_of_work: Arc::new(units.clone()),
        applications: Arc::new(stores.applications.clone()),
        clients: Arc::new(stores.clients.clone()),
        resource_servers: Arc::new(stores.resource_servers.clone()),
        requests: Arc::new(requests),
        grants: Arc::new(grants.clone()),
        codes: Arc::new(code_store),
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
    let secrets = InMemoryPairwiseSecrets::default();
    let pairwise = pairwise_subjects(Arc::new(units.clone()), Arc::new(secrets.clone()));
    let without_pairwise = TokenService::new(TokenPorts {
        units_of_work: Arc::new(units.clone()),
        applications: Arc::new(stores.applications.clone()),
        clients: Arc::new(stores.clients.clone()),
        resource_servers: Arc::new(stores.resource_servers.clone()),
        grants: Arc::new(grants.clone()),
        assertions: Arc::new(InMemoryClientAssertions::new(&stores.clients)),
        refresh_tokens: Arc::new(families),
        access_tokens: Arc::new(records.clone()),
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
        codes: codes.clone(),
        keys: keys.clone(),
        verifier: Arc::new(BothFakes),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    let tokens = without_pairwise
        .clone()
        .with_pairwise_subjects(pairwise.clone());
    let documents = SectorDocuments::default();
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(units.clone()),
        applications: Arc::new(stores.applications.clone()),
        clients: Arc::new(stores.clients.clone()),
        resource_servers: Arc::new(stores.resource_servers.clone()),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    })
    .with_destinations(Arc::new(FakeDestinations))
    .with_sector_documents(Arc::new(documents.clone()));
    World {
        units,
        standing,
        clock,
        records,
        secrets,
        documents,
        stores,
        codes,
        applications,
        keys,
        pairwise,
        tokens,
        without_pairwise,
    }
}

/// A tenant with an active signing key, the application of the clients,
/// and the application that owns the resource server and the ledger.
struct Tenant {
    context: TenantContext,
    application: ApplicationId,
    resource_owner: ApplicationId,
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
    let create = |name: &str| ApplicationSettings {
        name: name.to_owned(),
        first_party: true,
    };
    let application = world
        .applications
        .create_application(&context, create("Payroll"), Caller::system())
        .await
        .expect("application");
    let resource_owner = world
        .applications
        .create_application(&context, create("Payroll interface"), Caller::system())
        .await
        .expect("application");
    for (audience, name) in [(AUDIENCE, "Payroll interface"), (LEDGER, "Ledger")] {
        world
            .applications
            .create_resource_server(
                &context,
                CreateResourceServer {
                    application_id: if audience == AUDIENCE {
                        resource_owner.id()
                    } else {
                        application.id()
                    },
                    audience: audience.to_owned(),
                    settings: ResourceServerSettings {
                        name: name.to_owned(),
                        scopes: vec![ScopeDefinition {
                            name: "read".to_owned(),
                            description: "Read".to_owned(),
                        }],
                    },
                },
                Caller::system(),
            )
            .await
            .expect("resource server");
    }
    Tenant {
        context,
        application: application.id(),
        resource_owner: resource_owner.id(),
    }
}

/// How a client proves who it is, and where it takes its codes.
#[derive(Clone)]
struct Credentials {
    id: ClientId,
    secret: String,
    redirect: String,
}

impl Credentials {
    fn basic(&self) -> Option<BasicCredentials> {
        Some(BasicCredentials {
            client_id: self.id.to_string(),
            secret: self.secret.clone().into(),
        })
    }
}

fn web_settings(redirects: &[&str]) -> ClientSettings {
    let mut settings = ClientSettings::new(
        "Payroll",
        ClientType::Confidential,
        vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        redirects.iter().map(|uri| (*uri).to_owned()).collect(),
    );
    settings.authentication_method = AuthenticationMethod::ClientSecretBasic;
    settings.allowed_scopes = vec![
        "openid".to_owned(),
        "offline_access".to_owned(),
        "read".to_owned(),
    ];
    settings
}

async fn create(
    world: &World,
    tenant: &Tenant,
    settings: ClientSettings,
) -> Result<Credentials, DomainError> {
    let redirect = settings.redirect_uris[0].clone();
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
        .await?;
    Ok(Credentials {
        id: client.id(),
        secret: secret.expect("a secret").expose().to_owned(),
        redirect,
    })
}

async fn client(
    world: &World,
    tenant: &Tenant,
    subject_type: SubjectType,
    redirects: &[&str],
) -> Credentials {
    let settings = ClientSettings {
        subject_type,
        ..web_settings(redirects)
    };
    create(world, tenant, settings).await.expect("client")
}

fn person(world: &World) -> SignedInPerson {
    SignedInPerson {
        user_id: UserId::generate(),
        session_id: SessionId::generate(),
        signed_in_at: world.clock.now() - Duration::minutes(2),
        methods: vec!["password".to_owned()],
        acr: Some("urn:hodor:acr:single-factor".to_owned()),
    }
}

/// The tokens for a code issued to `client` for `who`, for `scope` and the
/// resource server.
async fn signed_in(
    world: &World,
    tokens: &TokenService,
    tenant: &TenantContext,
    client: &Credentials,
    who: &SignedInPerson,
    scope: &str,
) -> Result<Result<IssuedTokens, TokenError>, DomainError> {
    let challenge = s256_challenge(VERIFIER, &FakeDigest);
    let id = client.id.to_string();
    let pairs = [
        ("response_type", "code"),
        ("client_id", id.as_str()),
        ("redirect_uri", client.redirect.as_str()),
        ("scope", scope),
        ("resource", AUDIENCE),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ];
    let parameters = AuthorizationParameters::from_pairs(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
    );
    let request = world
        .codes
        .check(
            tenant,
            "https://hodor.example.com/t/acme",
            &parameters,
            &hodor_oauth::api::PushedRequestPolicy::default(),
        )
        .await
        .expect("storage")
        .expect("a valid request");
    let code = world
        .codes
        .issue_code(tenant, &request, who, Caller::system())
        .await
        .expect("code");
    let form = vec![
        ("grant_type".to_owned(), "authorization_code".to_owned()),
        ("code".to_owned(), code.expose().to_owned()),
        ("redirect_uri".to_owned(), client.redirect.clone()),
        ("code_verifier".to_owned(), VERIFIER.to_owned()),
    ];
    let request = TokenRequest::parse(client.basic(), form).expect("a request");
    tokens
        .token(tenant, ISSUER_OF, request, CorrelationId::generate())
        .await
}

async fn tokens_for(
    world: &World,
    tenant: &TenantContext,
    client: &Credentials,
    who: &SignedInPerson,
) -> IssuedTokens {
    signed_in(
        world,
        &world.tokens,
        tenant,
        client,
        who,
        "openid read offline_access",
    )
    .await
    .expect("storage")
    .expect("tokens")
}

async fn ask(
    world: &World,
    tenant: &TenantContext,
    client: &Credentials,
    pairs: Vec<(String, String)>,
) -> Result<IssuedTokens, TokenError> {
    let request = TokenRequest::parse(client.basic(), pairs)?;
    world
        .tokens
        .token(tenant, ISSUER_OF, request, CorrelationId::generate())
        .await
        .expect("storage")
}

fn claims(token: &str) -> Value {
    let part = token.split('.').nth(1).expect("claims");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("json")
}

fn access(issued: &IssuedTokens) -> String {
    issued.access_token.expose().clone()
}

fn id_token(issued: &IssuedTokens) -> Value {
    claims(issued.id_token.as_ref().expect("an ID token").expose())
}

async fn introspect(
    world: &World,
    tenant: &TenantContext,
    client: &Credentials,
    token: &str,
) -> Value {
    let form = vec![("token".to_owned(), token.to_owned())];
    world
        .tokens
        .introspect(
            tenant,
            ISSUER_OF,
            INTROSPECTION,
            TokenQuery::parse(client.basic(), form).expect("a query"),
        )
        .await
        .expect("storage")
        .expect("answered")
}

#[tokio::test]
async fn clients_of_one_sector_know_a_person_by_one_identifier_and_of_another_by_another() {
    let world = world();
    let tenant = tenant(&world).await;
    let payroll = client(&world, &tenant, SubjectType::Pairwise, &[PAYROLL]).await;
    // Another client of the same host, another port and path: one sector.
    let payroll_too = client(&world, &tenant, SubjectType::Pairwise, &[PAYROLL_OTHER]).await;
    let travel = client(&world, &tenant, SubjectType::Pairwise, &[TRAVEL]).await;
    let public = client(&world, &tenant, SubjectType::Public, &[PAYROLL]).await;
    let ana = person(&world);

    let at_payroll = tokens_for(&world, &tenant.context, &payroll, &ana).await;
    let at_payroll_too = tokens_for(&world, &tenant.context, &payroll_too, &ana).await;
    let at_travel = tokens_for(&world, &tenant.context, &travel, &ana).await;
    let at_public = tokens_for(&world, &tenant.context, &public, &ana).await;

    let sub = |issued: &IssuedTokens| id_token(issued)["sub"].clone();
    let sid = |issued: &IssuedTokens| id_token(issued)["sid"].clone();
    // One sector, one identifier; another sector, another.
    assert_eq!(sub(&at_payroll), sub(&at_payroll_too));
    assert_ne!(sub(&at_payroll), sub(&at_travel));
    assert_eq!(sid(&at_payroll), sid(&at_payroll_too));
    assert_ne!(sid(&at_payroll), sid(&at_travel));
    // Neither is the user or session identifier, which a public client
    // gets.
    for pairwise in [&at_payroll, &at_travel] {
        assert_ne!(sub(pairwise), ana.user_id.to_string());
        assert_ne!(sid(pairwise), ana.session_id.to_string());
        assert_eq!(sub(pairwise).as_str().map(str::len), Some(43));
    }
    assert_eq!(sub(&at_public), ana.user_id.to_string());
    assert_eq!(sid(&at_public), ana.session_id.to_string());
    // The access token names the person as the ID token does.
    for issued in [&at_payroll, &at_payroll_too, &at_travel, &at_public] {
        assert_eq!(claims(&access(issued))["sub"], sub(issued));
    }
    // Another person, another identifier in the same sector.
    let bruno = person(&world);
    let bruno_at_payroll = tokens_for(&world, &tenant.context, &payroll, &bruno).await;
    assert_ne!(sub(&bruno_at_payroll), sub(&at_payroll));

    // The audit log keeps the user identifier.
    let issued: Vec<Value> = world
        .units
        .committed_events()
        .into_iter()
        .filter(|event| event.event_type == "oauth.access_token_issued")
        .map(|event| event.payload)
        .collect();
    assert!(
        issued
            .iter()
            .any(|payload| payload["user_id"] == ana.user_id.to_string()),
        "{issued:?}"
    );
    assert!(
        !issued.iter().any(|payload| payload
            .to_string()
            .contains(sub(&at_payroll).as_str().expect("a sub"))),
        "no event names the pairwise identifier"
    );
}

#[tokio::test]
async fn a_refresh_and_introspection_name_the_person_as_the_id_token_does() {
    let world = world();
    let tenant = tenant(&world).await;
    let payroll = client(&world, &tenant, SubjectType::Pairwise, &[PAYROLL]).await;
    let ana = person(&world);
    let issued = tokens_for(&world, &tenant.context, &payroll, &ana).await;
    let sub = id_token(&issued)["sub"].clone();

    let refresh = issued.refresh_token.as_ref().expect("a refresh token");
    let refreshed = ask(
        &world,
        &tenant.context,
        &payroll,
        vec![
            ("grant_type".to_owned(), "refresh_token".to_owned()),
            ("refresh_token".to_owned(), refresh.expose().clone()),
        ],
    )
    .await
    .expect("refreshed");
    assert_eq!(claims(&access(&refreshed))["sub"], sub);

    // The client introspects its access and refresh tokens.
    let answer = introspect(&world, &tenant.context, &payroll, &access(&refreshed)).await;
    assert_eq!(answer["active"], true, "{answer}");
    assert_eq!(answer["sub"], sub);
    let next = refreshed.refresh_token.as_ref().expect("the next one");
    let answer = introspect(&world, &tenant.context, &payroll, next.expose()).await;
    assert_eq!(answer["active"], true, "{answer}");
    assert_eq!(answer["sub"], sub);

    // So does a client of the resource server the token is for.
    let mut settings = ClientSettings::new(
        "Payroll interface",
        ClientType::Confidential,
        vec![GrantType::ClientCredentials],
        Vec::new(),
    );
    settings.authentication_method = AuthenticationMethod::ClientSecretBasic;
    let (server, secret) = world
        .applications
        .create_client(
            &tenant.context,
            CreateClient {
                application_id: tenant.resource_owner,
                client_type: ClientType::Confidential,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client");
    let server = Credentials {
        id: server.id(),
        secret: secret.expect("secret").expose().to_owned(),
        redirect: String::new(),
    };
    let answer = introspect(&world, &tenant.context, &server, &access(&refreshed)).await;
    assert_eq!(answer["active"], true, "{answer}");
    assert_eq!(answer["sub"], sub);
}

#[tokio::test]
async fn an_exchange_finds_the_person_through_the_record_and_keeps_the_sub() {
    let world = world();
    let tenant = tenant(&world).await;
    let payroll = client(&world, &tenant, SubjectType::Pairwise, &[PAYROLL]).await;
    let ana = person(&world);
    let issued = tokens_for(&world, &tenant.context, &payroll, &ana).await;
    let sub = id_token(&issued)["sub"].clone();

    let agent = UserId::generate();
    world.standing.workload(agent, "agent");
    let mut settings = ClientSettings::new(
        "Assistant",
        ClientType::Confidential,
        vec![GrantType::ClientCredentials, GrantType::TokenExchange],
        Vec::new(),
    );
    settings.authentication_method = AuthenticationMethod::ClientSecretBasic;
    settings.allowed_scopes = vec!["read".to_owned()];
    settings.principal = Some(agent);
    settings.exchange_rules = vec![ExchangeRule {
        subject_audience: AUDIENCE.to_owned(),
        audience: LEDGER.to_owned(),
    }];
    let (assistant, secret) = world
        .applications
        .create_client(
            &tenant.context,
            CreateClient {
                application_id: tenant.resource_owner,
                client_type: ClientType::Confidential,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client");
    let assistant = Credentials {
        id: assistant.id(),
        secret: secret.expect("secret").expose().to_owned(),
        redirect: String::new(),
    };
    let own = ask(
        &world,
        &tenant.context,
        &assistant,
        vec![("grant_type".to_owned(), "client_credentials".to_owned())],
    )
    .await
    .expect("the agent's own token");
    let form = |subject: &str| {
        vec![
            ("grant_type".to_owned(), TOKEN_EXCHANGE.to_owned()),
            ("subject_token".to_owned(), subject.to_owned()),
            (
                "subject_token_type".to_owned(),
                ACCESS_TOKEN_TYPE.to_owned(),
            ),
            ("actor_token".to_owned(), access(&own)),
            ("actor_token_type".to_owned(), ACCESS_TOKEN_TYPE.to_owned()),
            ("audience".to_owned(), LEDGER.to_owned()),
        ]
    };
    let exchanged = ask(&world, &tenant.context, &assistant, form(&access(&issued)))
        .await
        .expect("exchanged");
    let new = claims(&access(&exchanged));
    assert_eq!(new["sub"], sub, "the subject token's own sub");
    assert_eq!(new["act"]["sub"], agent.to_string());
    let answer = introspect(&world, &tenant.context, &assistant, &access(&exchanged)).await;
    assert_eq!(answer["sub"], sub);
    // The audit log names the person by the user identifier.
    let exchange_event = world
        .units
        .committed_events()
        .into_iter()
        .find(|event| event.event_type == "oauth.token_exchanged")
        .expect("the exchange is audited");
    assert_eq!(
        exchange_event.payload["subject_id"],
        ana.user_id.to_string()
    );

    // An exchange of the exchanged token: the person is still found, and
    // the chain keeps the sub.
    let record = world
        .records
        .all(tenant.context.tenant_id())
        .into_iter()
        .find(|record| record.parent_token_id.is_some())
        .expect("the exchanged token's record");
    assert!(record.grant_id.is_some(), "the person's grant");

    // A person who may no longer sign in: the exchange is refused, though
    // nothing in the `sub` names them.
    world.standing.bar(ana.user_id);
    let refused = ask(&world, &tenant.context, &assistant, form(&access(&issued)))
        .await
        .expect_err("refused");
    assert_eq!(refused.error, "invalid_request");
}

#[tokio::test]
async fn one_person_in_two_tenants_gets_two_identifiers_for_one_sector() {
    let world = world();
    let acme = tenant(&world).await;
    let globex = tenant(&world).await;
    let at_acme = client(&world, &acme, SubjectType::Pairwise, &[PAYROLL]).await;
    let at_globex = client(&world, &globex, SubjectType::Pairwise, &[PAYROLL]).await;
    let ana = person(&world);
    let in_acme = tokens_for(&world, &acme.context, &at_acme, &ana).await;
    let in_globex = tokens_for(&world, &globex.context, &at_globex, &ana).await;
    assert_ne!(id_token(&in_acme)["sub"], id_token(&in_globex)["sub"]);
    assert_eq!(world.secrets.len(), 2, "a secret per tenant");
}

#[tokio::test]
async fn the_pairwise_secret_is_made_once_and_never_replaced() {
    let world = world();
    let tenant = tenant(&world).await;
    let payroll = client(&world, &tenant, SubjectType::Pairwise, &[PAYROLL]).await;
    let public = client(&world, &tenant, SubjectType::Public, &[PAYROLL]).await;
    let ana = person(&world);
    // A public client needs no secret.
    tokens_for(&world, &tenant.context, &public, &ana).await;
    assert!(world.secrets.is_empty());
    let first = tokens_for(&world, &tenant.context, &payroll, &ana).await;
    let again = tokens_for(&world, &tenant.context, &payroll, &ana).await;
    assert_eq!(id_token(&first)["sub"], id_token(&again)["sub"]);
    assert_eq!(world.secrets.len(), 1);

    // A secret that no longer opens is an error, never a reason to make a
    // new one.
    world.secrets.damage(tenant.context.tenant_id());
    let error = signed_in(
        &world,
        &world.tokens,
        &tenant.context,
        &payroll,
        &ana,
        "openid",
    )
    .await
    .expect_err("the secret does not open");
    assert_eq!(error.code(), "secret.unreadable");
    let error = world
        .pairwise
        .subject(
            &tenant.context,
            &world
                .applications
                .client(&tenant.context, payroll.id)
                .await
                .expect("client"),
            ana.user_id,
        )
        .await
        .expect_err("still damaged");
    assert_eq!(error.code(), "secret.unreadable");
    // The public client is answered as before.
    tokens_for(&world, &tenant.context, &public, &ana).await;
}

#[tokio::test]
async fn a_token_endpoint_without_pairwise_subjects_never_gives_a_pairwise_client_the_user() {
    let world = world();
    let tenant = tenant(&world).await;
    let payroll = client(&world, &tenant, SubjectType::Pairwise, &[PAYROLL]).await;
    let public = client(&world, &tenant, SubjectType::Public, &[PAYROLL]).await;
    let ana = person(&world);
    let error = signed_in(
        &world,
        &world.without_pairwise,
        &tenant.context,
        &payroll,
        &ana,
        "openid",
    )
    .await
    .expect_err("refused");
    assert_eq!(error.code(), "oauth.pairwise_unavailable");
    signed_in(
        &world,
        &world.without_pairwise,
        &tenant.context,
        &public,
        &ana,
        "openid",
    )
    .await
    .expect("storage")
    .expect("a public client is answered");
}

#[tokio::test]
async fn the_sector_identifier_address_is_fetched_when_it_is_set_and_must_list_the_addresses() {
    let world = world();
    let tenant = tenant(&world).await;
    let settings = || ClientSettings {
        subject_type: SubjectType::Pairwise,
        sector_identifier_uri: Some(SECTOR_DOCUMENT.to_owned()),
        ..web_settings(&[PAYROLL, TRAVEL])
    };
    // Without an address, two hosts have no sector.
    let error = create(
        &world,
        &tenant,
        ClientSettings {
            sector_identifier_uri: None,
            ..settings()
        },
    )
    .await
    .err()
    .expect("two hosts");
    assert_eq!(error.code(), "oauth.client_sector_identifier_uri_required");

    let refusals = [
        (
            404,
            format!(r#"["{PAYROLL}", "{TRAVEL}"]"#),
            "oauth.client_sector_identifier_uri_unreachable",
        ),
        (
            200,
            r#"{"redirect_uris": []}"#.to_owned(),
            "oauth.client_sector_identifier_uri_document_invalid",
        ),
        (
            200,
            format!(r#"["{PAYROLL}"]"#),
            "oauth.client_sector_identifier_uri_mismatch",
        ),
        (
            200,
            format!(r#"["{PAYROLL}", "{TRAVEL}", "{}"]"#, "x".repeat(70_000)),
            "oauth.client_sector_identifier_uri_unreachable",
        ),
    ];
    for (status, body, code) in refusals {
        world.documents.answer(SECTOR_DOCUMENT, status, &body);
        let error = create(&world, &tenant, settings())
            .await
            .err()
            .expect("refused");
        assert_eq!(
            error.code(),
            code,
            "{status} {}",
            &body[..body.len().min(60)]
        );
    }
    for (address, code) in [
        (
            "https://internal.example/uris.json",
            "oauth.client_sector_identifier_uri_forbidden",
        ),
        (
            "https://nowhere.example/uris.json",
            "oauth.client_sector_identifier_uri_unresolvable",
        ),
        (
            "https://sector.example.org/unanswered.json",
            "oauth.client_sector_identifier_uri_unreachable",
        ),
    ] {
        let error = create(
            &world,
            &tenant,
            ClientSettings {
                sector_identifier_uri: Some(address.to_owned()),
                ..settings()
            },
        )
        .await
        .err()
        .expect("refused");
        assert_eq!(error.code(), code, "{address}");
    }

    world.documents.answer(
        SECTOR_DOCUMENT,
        200,
        &format!(r#"["{TRAVEL}", "{PAYROLL}"]"#),
    );
    let fetched = world.documents.fetched();
    let made = create(&world, &tenant, settings()).await.expect("listed");
    assert_eq!(world.documents.fetched(), fetched + 1, "fetched once");

    // Its sector is the address's host: another client of that sector
    // knows the person by the same identifier, whatever its own hosts.
    world
        .documents
        .answer(SECTOR_DOCUMENT, 200, &format!(r#"["{PAYROLL_OTHER}"]"#));
    let other = create(
        &world,
        &tenant,
        ClientSettings {
            subject_type: SubjectType::Pairwise,
            sector_identifier_uri: Some(SECTOR_DOCUMENT.to_owned()),
            ..web_settings(&[PAYROLL_OTHER])
        },
    )
    .await
    .expect("another of the sector");
    let ana = person(&world);
    let at_made = tokens_for(&world, &tenant.context, &made, &ana).await;
    let at_other = tokens_for(&world, &tenant.context, &other, &ana).await;
    let at_payroll = tokens_for(
        &world,
        &tenant.context,
        &client(&world, &tenant, SubjectType::Pairwise, &[PAYROLL]).await,
        &ana,
    )
    .await;
    assert_eq!(id_token(&at_made)["sub"], id_token(&at_other)["sub"]);
    assert_ne!(id_token(&at_made)["sub"], id_token(&at_payroll)["sub"]);

    // Changing the name fetches nothing; changing the redirect addresses
    // fetches the document again, which must list the new ones.
    let current = world
        .applications
        .client(&tenant.context, made.id)
        .await
        .expect("client");
    let fetched = world.documents.fetched();
    let renamed = ClientSettings {
        name: "Payroll renamed".to_owned(),
        ..current.snapshot().settings.clone()
    };
    world
        .applications
        .change_client(&tenant.context, made.id, renamed.clone(), Caller::system())
        .await
        .expect("renamed");
    assert_eq!(world.documents.fetched(), fetched, "nothing fetched");
    let moved = ClientSettings {
        redirect_uris: vec![PAYROLL.to_owned(), PAYROLL_OTHER.to_owned()],
        ..renamed
    };
    let error = world
        .applications
        .change_client(&tenant.context, made.id, moved, Caller::system())
        .await
        .expect_err("not listed");
    assert_eq!(error.code(), "oauth.client_sector_identifier_uri_mismatch");
    assert_eq!(world.documents.fetched(), fetched + 1);
}

#[tokio::test]
async fn an_installation_that_cannot_fetch_accepts_no_sector_identifier_address() {
    let world = world();
    let tenant = tenant(&world).await;
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(world.units.clone()),
        applications: Arc::new(world.stores.applications.clone()),
        clients: Arc::new(world.stores.clients.clone()),
        resource_servers: Arc::new(world.stores.resource_servers.clone()),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: world.clock.clone(),
    });
    let error = applications
        .create_client(
            &tenant.context,
            CreateClient {
                application_id: tenant.application,
                client_type: ClientType::Confidential,
                settings: ClientSettings {
                    subject_type: SubjectType::Pairwise,
                    sector_identifier_uri: Some(SECTOR_DOCUMENT.to_owned()),
                    ..web_settings(&[PAYROLL])
                },
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect_err("refused");
    assert_eq!(error.code(), "oauth.client_sector_identifier_uri_forbidden");
}

#[tokio::test]
async fn a_pairwise_hint_ends_the_session_it_names_and_no_other() {
    let world = world();
    let tenant = tenant(&world).await;
    let payroll = client(&world, &tenant, SubjectType::Pairwise, &[PAYROLL]).await;
    let ana = person(&world);
    let issued = tokens_for(&world, &tenant.context, &payroll, &ana).await;
    let claims = id_token(&issued);
    let logout = LogoutService::new(LogoutPorts {
        units_of_work: Arc::new(world.units.clone()),
        applications: Arc::new(world.stores.applications.clone()),
        clients: Arc::new(world.stores.clients.clone()),
        keys: world.keys.clone(),
        verifier: Arc::new(BothFakes),
    });
    let with_pairwise = logout
        .clone()
        .with_pairwise_subjects(world.pairwise.clone());
    let request = |subject: &str, session: &str| LogoutRequest {
        hint: Some(IdTokenHint {
            client_id: payroll.id,
            subject: subject.to_owned(),
            session: Some(session.to_owned()),
        }),
        return_to: None,
        ui_locales: None,
    };
    let current = CurrentSession {
        user_id: ana.user_id,
        session_id: ana.session_id,
    };
    let hint = request(
        claims["sub"].as_str().expect("sub"),
        claims["sid"].as_str().expect("sid"),
    );
    let decide = |service: &LogoutService, hint: LogoutRequest, current, by_form| {
        let service = service.clone();
        let tenant = tenant.context.clone();
        async move {
            service
                .decide(&tenant, &hint, current, by_form)
                .await
                .expect("decided")
        }
    };
    assert_eq!(
        decide(&with_pairwise, hint.clone(), Some(current), false).await,
        LogoutDecision::EndSession
    );
    assert_eq!(
        decide(&with_pairwise, hint.clone(), Some(current), true).await,
        LogoutDecision::Ask,
        "a form always asks"
    );
    // The user and session identifiers are not what the client was told.
    let plain = request(&ana.user_id.to_string(), &ana.session_id.to_string());
    assert_eq!(
        decide(&with_pairwise, plain, Some(current), false).await,
        LogoutDecision::Ask
    );
    // Another session of the person.
    let elsewhere = CurrentSession {
        session_id: SessionId::generate(),
        ..current
    };
    assert_eq!(
        decide(&with_pairwise, hint.clone(), Some(elsewhere), false).await,
        LogoutDecision::Ask
    );
    assert_eq!(
        decide(&with_pairwise, hint.clone(), None, false).await,
        LogoutDecision::Finish
    );
    // A service that cannot compare a pairwise hint asks.
    assert_eq!(
        decide(&logout, hint, Some(current), false).await,
        LogoutDecision::Ask
    );
}

#[tokio::test]
async fn the_in_memory_store_of_pairwise_secrets_passes_the_contract() {
    let units = InMemoryUnitOfWorkFactory::default();
    let secrets = InMemoryPairwiseSecrets::default();
    run_pairwise_secret_contract(PairwiseSecretStorePorts {
        units_of_work: &units,
        secrets: &secrets,
    })
    .await;
}

/// A request of `client` that asks through `claims` for the `sub` `value`.
async fn asking_for_sub(
    world: &World,
    tenant: &TenantContext,
    client: &Credentials,
    value: &str,
) -> hodor_oauth::api::AuthorizationRequest {
    let challenge = s256_challenge(VERIFIER, &FakeDigest);
    let id = client.id.to_string();
    let claims = json!({"id_token": {"sub": {"value": value}}}).to_string();
    let pairs = [
        ("response_type", "code"),
        ("client_id", id.as_str()),
        ("redirect_uri", client.redirect.as_str()),
        ("scope", "openid"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("claims", claims.as_str()),
    ];
    let parameters = AuthorizationParameters::from_pairs(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
    );
    world
        .codes
        .check(
            tenant,
            "https://hodor.example.com/t/acme",
            &parameters,
            &hodor_oauth::api::PushedRequestPolicy::default(),
        )
        .await
        .expect("storage")
        .expect("a valid request")
}

#[tokio::test]
async fn a_sub_asked_through_claims_is_compared_with_the_person_as_a_pairwise_client_knows_them() {
    let world = world();
    let tenant = tenant(&world).await;
    let payroll = client(&world, &tenant, SubjectType::Pairwise, &[PAYROLL]).await;
    let ana = person(&world);
    let bruno = person(&world);
    let known_as = id_token(&tokens_for(&world, &tenant.context, &payroll, &ana).await)["sub"]
        .as_str()
        .expect("a sub")
        .to_owned();
    let codes = world
        .codes
        .clone()
        .with_pairwise_subjects(world.pairwise.clone());

    let request = asking_for_sub(&world, &tenant.context, &payroll, &known_as).await;
    assert!(
        !codes
            .names_another(&tenant.context, &request, ana.user_id)
            .await
            .expect("compared"),
        "Ana, by her pairwise identifier"
    );
    assert!(
        codes
            .names_another(&tenant.context, &request, bruno.user_id)
            .await
            .expect("compared"),
        "Bruno is someone else"
    );
    // Her user identifier is not how this client knows her.
    let by_user = asking_for_sub(&world, &tenant.context, &payroll, &ana.user_id.to_string()).await;
    assert!(
        codes
            .names_another(&tenant.context, &by_user, ana.user_id)
            .await
            .expect("compared")
    );
    // Without pairwise subjects, a pairwise client's `sub` cannot be
    // compared, and nothing is answered.
    assert!(
        world
            .codes
            .names_another(&tenant.context, &request, ana.user_id)
            .await
            .is_err()
    );
}
