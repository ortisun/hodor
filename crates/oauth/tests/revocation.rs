//! Revocation and introspection, and the register of access tokens, on the
//! in-memory stores.

use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::sealing::testing::FakeSecretBox;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, Clock as _, CorrelationId, PublicKey, SignatureAlgorithm, SignatureVerifier,
    TenantContext, TenantId, Timestamp, UserId,
};
use hodor_keys::api::{KeyAlgorithm, KeyService, RotationPolicy};
use hodor_keys::testing::{FakeKeyProvider, InMemoryKeys};
use hodor_oauth::api::{
    AccessTokenRegister, ApplicationId, ApplicationPorts, ApplicationService, ApplicationSettings,
    AuthenticationMethod, AuthorizationCodePorts, AuthorizationCodeService,
    AuthorizationParameters, BasicCredentials, ClientId, ClientSettings, ClientType, CreateClient,
    CreateResourceServer, FamilyStatus, GrantStatus, GrantType, IssuedTokens, Issuer,
    ResourceServerSettings, ScopeDefinition, SignedInPerson, TokenError, TokenPorts, TokenQuery,
    TokenRequest, TokenService, s256_challenge,
};
use hodor_oauth::testing::{
    AccessTokenRecordStorePorts, DistinctRandom, FakeVerifier, InMemoryAccessTokenRecords,
    InMemoryAuthorizationCodes, InMemoryAuthorizationRequests, InMemoryClientAssertions,
    InMemoryGrants, InMemoryRefreshTokens, InMemoryStores, StandingOf,
    run_access_token_record_contract,
};
use hodor_session::api::SessionId;
use serde_json::{Value, json};
use std::sync::Arc;
use time::Duration;

const REDIRECT: &str = "https://payroll.example.com/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const ISSUER: &str = "https://hodor.example.com/t/acme";
const TOKEN_ENDPOINT: &str = "https://hodor.example.com/t/acme/oauth2/token";
const REVOCATION: &str = "https://hodor.example.com/t/acme/oauth2/revoke";
const INTROSPECTION: &str = "https://hodor.example.com/t/acme/oauth2/introspect";
const AUDIENCE: &str = "https://api.payroll.example.com";

const ISSUER_OF: Issuer<'static> = Issuer {
    issuer: ISSUER,
    token_endpoint: TOKEN_ENDPOINT,
};

/// Checks both the stand-in signatures of client assertions and those of
/// the fake key provider, which signs the tenant's access tokens here.
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
    clock: Arc<FixedClock>,
    grants: InMemoryGrants,
    families: InMemoryRefreshTokens,
    records: InMemoryAccessTokenRecords,
    codes: AuthorizationCodeService,
    applications: ApplicationService,
    keys: KeyService,
    tokens: TokenService,
}

fn world() -> World {
    let units = InMemoryUnitOfWorkFactory::default();
    let stores = InMemoryStores::default();
    let requests = InMemoryAuthorizationRequests::new(&stores.clients);
    let grants = InMemoryGrants::new(&stores.clients);
    let code_store = InMemoryAuthorizationCodes::new(&grants);
    let families = InMemoryRefreshTokens::new(&grants);
    let records = InMemoryAccessTokenRecords::new(&stores.clients);
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
        secrets: Arc::new(FakeSecretBox),
        codes: codes.clone(),
        keys: keys.clone(),
        verifier: Arc::new(BothFakes),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
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
        clock,
        grants,
        families,
        records,
        codes,
        applications,
        keys,
        tokens,
    }
}

/// A tenant with an active signing key, an application for the clients
/// that ask for tokens, and the application that owns the resource server
/// those tokens are for.
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
    world
        .applications
        .create_resource_server(
            &context,
            CreateResourceServer {
                application_id: resource_owner.id(),
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
    Tenant {
        context,
        application: application.id(),
        resource_owner: resource_owner.id(),
    }
}

/// How a client proves who it is in the requests of a test.
#[derive(Clone)]
struct Credentials {
    id: ClientId,
    secret: Option<String>,
}

impl Credentials {
    fn basic(&self) -> Option<BasicCredentials> {
        self.secret.as_ref().map(|secret| BasicCredentials {
            client_id: self.id.to_string(),
            secret: secret.clone().into(),
        })
    }

    fn fields(&self) -> Vec<(String, String)> {
        if self.secret.is_some() {
            Vec::new()
        } else {
            vec![("client_id".to_owned(), self.id.to_string())]
        }
    }
}

async fn new_client(
    world: &World,
    tenant: &TenantContext,
    application: ApplicationId,
    client_type: ClientType,
    grants: Vec<GrantType>,
) -> Credentials {
    let redirects = if grants.contains(&GrantType::AuthorizationCode) {
        vec![REDIRECT.to_owned()]
    } else {
        Vec::new()
    };
    let mut settings = ClientSettings::new("Payroll", client_type, grants, redirects);
    if client_type == ClientType::Confidential {
        settings.authentication_method = AuthenticationMethod::ClientSecretBasic;
    }
    settings.allowed_scopes = vec![
        "openid".to_owned(),
        "offline_access".to_owned(),
        "read".to_owned(),
    ];
    let (client, secret) = world
        .applications
        .create_client(
            tenant,
            CreateClient {
                application_id: application,
                client_type,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client");
    Credentials {
        id: client.id(),
        secret: secret.map(|secret| secret.expose().to_owned()),
    }
}

/// A confidential client allowed codes and refresh tokens.
async fn confidential(world: &World, tenant: &Tenant) -> Credentials {
    new_client(
        world,
        &tenant.context,
        tenant.application,
        ClientType::Confidential,
        vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
    )
    .await
}

/// A confidential client of the application that owns the resource server.
async fn resource_server_client(world: &World, tenant: &Tenant) -> Credentials {
    new_client(
        world,
        &tenant.context,
        tenant.resource_owner,
        ClientType::Confidential,
        vec![GrantType::ClientCredentials],
    )
    .await
}

/// The tokens for a code issued to `client` for `scope`, for the resource
/// server.
async fn signed_in(
    world: &World,
    tenant: &TenantContext,
    client: &Credentials,
    scope: &str,
) -> IssuedTokens {
    let challenge = s256_challenge(VERIFIER, &FakeDigest);
    let id = client.id.to_string();
    let pairs = [
        ("response_type", "code"),
        ("client_id", id.as_str()),
        ("redirect_uri", REDIRECT),
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
        .check(tenant, &parameters)
        .await
        .expect("storage")
        .expect("a valid request");
    let person = SignedInPerson {
        user_id: UserId::generate(),
        session_id: SessionId::generate(),
        signed_in_at: world.clock.now() - Duration::minutes(2),
        methods: vec!["password".to_owned()],
        acr: Some("urn:hodor:acr:single-factor".to_owned()),
    };
    let code = world
        .codes
        .issue_code(tenant, &request, &person, Caller::system())
        .await
        .expect("code");
    let mut form = vec![
        ("grant_type".to_owned(), "authorization_code".to_owned()),
        ("code".to_owned(), code.expose().to_owned()),
        ("redirect_uri".to_owned(), REDIRECT.to_owned()),
        ("code_verifier".to_owned(), VERIFIER.to_owned()),
    ];
    form.extend(client.fields());
    ask(world, tenant, client, form).await.expect("tokens")
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

async fn refresh(
    world: &World,
    tenant: &TenantContext,
    client: &Credentials,
    token: &str,
) -> Result<IssuedTokens, TokenError> {
    let mut form = vec![
        ("grant_type".to_owned(), "refresh_token".to_owned()),
        ("refresh_token".to_owned(), token.to_owned()),
    ];
    form.extend(client.fields());
    ask(world, tenant, client, form).await
}

fn query(client: &Credentials, token: &str, hint: Option<&str>) -> TokenQuery {
    let mut form = vec![("token".to_owned(), token.to_owned())];
    if let Some(hint) = hint {
        form.push(("token_type_hint".to_owned(), hint.to_owned()));
    }
    form.extend(client.fields());
    TokenQuery::parse(client.basic(), form).expect("a query")
}

async fn introspect(
    world: &World,
    tenant: &TenantContext,
    client: &Credentials,
    token: &str,
) -> Result<Value, TokenError> {
    world
        .tokens
        .introspect(tenant, ISSUER_OF, INTROSPECTION, query(client, token, None))
        .await
        .expect("storage")
}

async fn active(world: &World, tenant: &TenantContext, client: &Credentials, token: &str) -> bool {
    let answer = introspect(world, tenant, client, token)
        .await
        .expect("answered");
    match answer.get("active") {
        Some(Value::Bool(true)) => true,
        Some(Value::Bool(false)) => {
            assert_eq!(answer, json!({"active": false}), "nothing more");
            false
        }
        other => panic!("not an introspection answer: {other:?}"),
    }
}

async fn revoke(world: &World, tenant: &TenantContext, client: &Credentials, token: &str) {
    world
        .tokens
        .revoke(
            tenant,
            ISSUER_OF,
            REVOCATION,
            query(client, token, None),
            CorrelationId::generate(),
        )
        .await
        .expect("storage")
        .expect("answered");
}

fn access(tokens: &IssuedTokens) -> String {
    tokens.access_token.expose().clone()
}

fn refresh_token_of(tokens: &IssuedTokens) -> String {
    tokens
        .refresh_token
        .as_ref()
        .expect("a refresh token")
        .expose()
        .clone()
}

#[tokio::test]
async fn the_in_memory_register_passes_the_contract() {
    let units = InMemoryUnitOfWorkFactory::default();
    let stores = InMemoryStores::default();
    let records = InMemoryAccessTokenRecords::new(&stores.clients);
    run_access_token_record_contract(AccessTokenRecordStorePorts {
        units_of_work: &units,
        applications: &stores.applications,
        clients: &stores.clients,
        access_tokens: &records,
    })
    .await;
}

#[tokio::test]
async fn every_access_token_issued_is_recorded_with_its_grant_and_family() {
    let world = world();
    let tenant = tenant(&world).await;
    let client = confidential(&world, &tenant).await;
    let first = signed_in(&world, &tenant.context, &client, "openid read").await;
    let second = refresh(&world, &tenant.context, &client, &refresh_token_of(&first))
        .await
        .expect("refreshed");
    let machine = new_client(
        &world,
        &tenant.context,
        tenant.application,
        ClientType::Confidential,
        vec![GrantType::ClientCredentials],
    )
    .await;
    ask(
        &world,
        &tenant.context,
        &machine,
        vec![("grant_type".to_owned(), "client_credentials".to_owned())],
    )
    .await
    .expect("client credentials");

    let records = world.records.all(tenant.context.tenant_id());
    assert_eq!(records.len(), 3);
    let family = world.families.all(tenant.context.tenant_id())[0].clone();
    let of_code = records
        .iter()
        .find(|record| record.client_id == client.id && record.family_id.is_none())
        .expect("the code's token");
    assert_eq!(of_code.grant_id, Some(family.grant_id));
    let of_refresh = records
        .iter()
        .find(|record| record.family_id == Some(family.id))
        .expect("the refresh's token");
    assert_eq!(of_refresh.grant_id, Some(family.grant_id));
    let of_machine = records
        .iter()
        .find(|record| record.client_id == machine.id)
        .expect("the client's own token");
    assert_eq!((of_machine.grant_id, of_machine.family_id), (None, None));
    assert!(records.iter().all(|record| record.revoked_at.is_none()));
    let _ = second;
}

#[tokio::test]
async fn an_active_access_token_is_answered_with_what_it_says() {
    let world = world();
    let tenant = tenant(&world).await;
    let client = confidential(&world, &tenant).await;
    let tokens = signed_in(&world, &tenant.context, &client, "openid read").await;
    let answer = introspect(&world, &tenant.context, &client, &access(&tokens))
        .await
        .expect("answered");
    assert_eq!(answer["active"], true);
    assert_eq!(answer["scope"], "openid read");
    assert_eq!(answer["client_id"], client.id.to_string());
    assert_eq!(answer["iss"], ISSUER);
    assert_eq!(answer["token_type"], "Bearer");
    assert_eq!(answer["aud"], json!([AUDIENCE, ISSUER]));
    assert!(answer["sub"].is_string());
    assert!(answer["exp"].as_i64() > answer["iat"].as_i64());
}

#[tokio::test]
async fn a_revoked_access_token_is_not_active() {
    let world = world();
    let tenant = tenant(&world).await;
    let client = confidential(&world, &tenant).await;
    let tokens = signed_in(&world, &tenant.context, &client, "openid read").await;
    let token = access(&tokens);
    assert!(active(&world, &tenant.context, &client, &token).await);

    revoke(&world, &tenant.context, &client, &token).await;
    assert!(!active(&world, &tenant.context, &client, &token).await);
    let record = world.records.all(tenant.context.tenant_id())[0].clone();
    assert_eq!(
        record.revocation_reason.as_deref(),
        Some("revoked_by_client")
    );

    // The refresh token of its grant stays: only the access token went.
    assert!(active(&world, &tenant.context, &client, &refresh_token_of(&tokens)).await);
    // A second revocation does nothing more, and is answered the same.
    revoke(&world, &tenant.context, &client, &token).await;
}

#[tokio::test]
async fn revoking_a_refresh_token_ends_its_family_its_grant_and_their_access_tokens() {
    let world = world();
    let tenant = tenant(&world).await;
    let client = confidential(&world, &tenant).await;
    let first = signed_in(&world, &tenant.context, &client, "openid read").await;
    let second = refresh(&world, &tenant.context, &client, &refresh_token_of(&first))
        .await
        .expect("refreshed");
    let newest = refresh_token_of(&second);

    revoke(&world, &tenant.context, &client, &newest).await;

    let family = world.families.all(tenant.context.tenant_id())[0].clone();
    assert_eq!(family.status, FamilyStatus::Revoked);
    assert_eq!(
        family.revocation_reason.as_deref(),
        Some("revoked_by_client")
    );
    let grant = world.grants.all(tenant.context.tenant_id())[0].clone();
    assert_eq!(grant.status, GrantStatus::Revoked);
    for token in [access(&first), access(&second), newest.clone()] {
        assert!(!active(&world, &tenant.context, &client, &token).await);
    }
    assert_eq!(
        refresh(&world, &tenant.context, &client, &newest)
            .await
            .expect_err("refused")
            .error,
        "invalid_grant"
    );
}

#[tokio::test]
async fn reusing_a_refresh_token_makes_the_access_tokens_of_its_family_inactive() {
    let world = world();
    let tenant = tenant(&world).await;
    let client = confidential(&world, &tenant).await;
    let first = signed_in(&world, &tenant.context, &client, "openid read").await;
    let used = refresh_token_of(&first);
    let second = refresh(&world, &tenant.context, &client, &used)
        .await
        .expect("refreshed");
    assert!(active(&world, &tenant.context, &client, &access(&second)).await);

    // Presented again after the retry window: reuse, which revokes.
    world.clock.advance(Duration::minutes(1));
    refresh(&world, &tenant.context, &client, &used)
        .await
        .expect_err("reused");
    assert!(!active(&world, &tenant.context, &client, &access(&second)).await);
    assert!(!active(&world, &tenant.context, &client, &access(&first)).await);
}

#[tokio::test]
async fn a_refresh_token_is_active_only_while_it_is_the_newest_of_a_standing_family() {
    let world = world();
    let tenant = tenant(&world).await;
    let client = confidential(&world, &tenant).await;
    let first = signed_in(
        &world,
        &tenant.context,
        &client,
        "openid offline_access read",
    )
    .await;
    let one = refresh_token_of(&first);
    let answer = introspect(&world, &tenant.context, &client, &one)
        .await
        .expect("answered");
    assert_eq!(answer["active"], true);
    assert_eq!(answer["token_type"], "refresh_token");
    assert_eq!(answer["scope"], "openid offline_access read");
    assert_eq!(answer["client_id"], client.id.to_string());
    assert_eq!(answer["aud"], ISSUER);
    assert_eq!(answer["iat"], world.clock.now().unix_timestamp());

    world.clock.advance(Duration::minutes(1));
    let second = refresh(&world, &tenant.context, &client, &one)
        .await
        .expect("refreshed");
    assert!(
        !active(&world, &tenant.context, &client, &one).await,
        "a rotated token, even within the retry window"
    );
    assert!(active(&world, &tenant.context, &client, &refresh_token_of(&second)).await);
}

#[tokio::test]
async fn a_client_cannot_introspect_or_revoke_another_client_s_tokens() {
    let world = world();
    let tenant = tenant(&world).await;
    let owner = confidential(&world, &tenant).await;
    let other = confidential(&world, &tenant).await;
    let tokens = signed_in(&world, &tenant.context, &owner, "openid read").await;
    let (token, refresh_token) = (access(&tokens), refresh_token_of(&tokens));

    assert!(!active(&world, &tenant.context, &other, &token).await);
    assert!(!active(&world, &tenant.context, &other, &refresh_token).await);

    // Answered as for any token, and nothing is done.
    revoke(&world, &tenant.context, &other, &token).await;
    revoke(&world, &tenant.context, &other, &refresh_token).await;
    assert!(active(&world, &tenant.context, &owner, &token).await);
    assert!(active(&world, &tenant.context, &owner, &refresh_token).await);
    assert_eq!(
        world.families.all(tenant.context.tenant_id())[0].status,
        FamilyStatus::Active,
        "another client's revocation does not end the family"
    );
}

#[tokio::test]
async fn the_resource_server_s_client_introspects_the_tokens_meant_for_it() {
    let world = world();
    let tenant = tenant(&world).await;
    let client = confidential(&world, &tenant).await;
    let interface = resource_server_client(&world, &tenant).await;
    let for_interface = signed_in(&world, &tenant.context, &client, "openid read").await;
    assert!(active(&world, &tenant.context, &interface, &access(&for_interface)).await);
    assert!(
        !active(
            &world,
            &tenant.context,
            &interface,
            &refresh_token_of(&for_interface)
        )
        .await,
        "but never a refresh token of another client"
    );
}

#[tokio::test]
async fn a_public_client_may_revoke_its_tokens_but_not_introspect() {
    let world = world();
    let tenant = tenant(&world).await;
    let public = new_client(
        &world,
        &tenant.context,
        tenant.application,
        ClientType::Public,
        vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
    )
    .await;
    let tokens = signed_in(&world, &tenant.context, &public, "openid read").await;
    let error = introspect(&world, &tenant.context, &public, &access(&tokens))
        .await
        .expect_err("refused");
    assert_eq!(error.error, "invalid_client");

    revoke(&world, &tenant.context, &public, &refresh_token_of(&tokens)).await;
    assert_eq!(
        world.families.all(tenant.context.tenant_id())[0].status,
        FamilyStatus::Revoked
    );
}

#[tokio::test]
async fn a_client_s_own_token_from_client_credentials_can_be_revoked() {
    let world = world();
    let tenant = tenant(&world).await;
    let machine = resource_server_client(&world, &tenant).await;
    let tokens = ask(
        &world,
        &tenant.context,
        &machine,
        vec![("grant_type".to_owned(), "client_credentials".to_owned())],
    )
    .await
    .expect("client credentials");
    let answer = introspect(&world, &tenant.context, &machine, &access(&tokens))
        .await
        .expect("answered");
    assert_eq!(answer["active"], true);
    assert_eq!(answer["sub"], machine.id.to_string());
    revoke(&world, &tenant.context, &machine, &access(&tokens)).await;
    assert!(!active(&world, &tenant.context, &machine, &access(&tokens)).await);
}

#[tokio::test]
async fn malformed_unknown_and_expired_tokens_are_not_active_and_revoke_nothing() {
    let world = world();
    let tenant = tenant(&world).await;
    let client = confidential(&world, &tenant).await;
    let tokens = signed_in(&world, &tenant.context, &client, "openid read").await;
    for token in ["not a token".to_owned(), "a.b.c".to_owned(), "A".repeat(43)] {
        assert!(!active(&world, &tenant.context, &client, &token).await);
        revoke(&world, &tenant.context, &client, &token).await;
    }
    world.clock.advance(Duration::hours(2));
    assert!(
        !active(&world, &tenant.context, &client, &access(&tokens)).await,
        "an expired access token"
    );
    revoke(&world, &tenant.context, &client, &access(&tokens)).await;
    assert!(
        world
            .records
            .all(tenant.context.tenant_id())
            .iter()
            .all(|record| record.revoked_at.is_none()),
        "an expired token is nothing to revoke"
    );
}

#[tokio::test]
async fn a_token_of_one_tenant_is_nothing_in_another() {
    let world = world();
    let acme = tenant(&world).await;
    let globex = tenant(&world).await;
    let client = confidential(&world, &acme).await;
    let tokens = signed_in(&world, &acme.context, &client, "openid read").await;
    let globex_client = confidential(&world, &globex).await;
    for token in [access(&tokens), refresh_token_of(&tokens)] {
        assert!(!active(&world, &globex.context, &globex_client, &token).await);
        revoke(&world, &globex.context, &globex_client, &token).await;
        assert!(active(&world, &acme.context, &client, &token).await);
    }
    // The client of one tenant is unknown in the other.
    let error = introspect(&world, &globex.context, &client, &access(&tokens))
        .await
        .expect_err("refused");
    assert_eq!(error.error, "invalid_client");
}

#[tokio::test]
async fn the_register_says_a_token_is_in_force_only_with_its_grant_and_family() {
    let world = world();
    let tenant = tenant(&world).await;
    let client = confidential(&world, &tenant).await;
    let first = signed_in(&world, &tenant.context, &client, "openid read").await;
    let register: AccessTokenRegister = world.tokens.register();
    let record = world.records.all(tenant.context.tenant_id())[0].clone();
    let id = client.id.to_string();
    assert!(
        register
            .in_force(&tenant.context, &record.token_id, &id)
            .await
            .expect("asked")
    );
    assert!(
        !register
            .in_force(&tenant.context, &record.token_id, "another client")
            .await
            .expect("asked"),
        "a token is in force only for the client it was issued to"
    );
    assert!(
        !register
            .in_force(&tenant.context, "an unknown jti", &id)
            .await
            .expect("asked"),
        "a token without a record is not in force"
    );
    revoke(&world, &tenant.context, &client, &refresh_token_of(&first)).await;
    assert!(
        !register
            .in_force(&tenant.context, &record.token_id, &id)
            .await
            .expect("asked"),
        "its grant was revoked"
    );
}
