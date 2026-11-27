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
    InMemoryGrants, InMemoryRefreshTokens, InMemoryStores, MembershipsOf, StandingOf,
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
    units: InMemoryUnitOfWorkFactory,
    standing: StandingOf,
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
    let tokens = TokenService::new(TokenPorts {
        units_of_work: Arc::new(units.clone()),
        applications: Arc::new(stores.applications.clone()),
        clients: Arc::new(stores.clients.clone()),
        resource_servers: Arc::new(stores.resource_servers.clone()),
        grants: Arc::new(grants.clone()),
        assertions: Arc::new(InMemoryClientAssertions::new(&stores.clients)),
        refresh_tokens: Arc::new(families.clone()),
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
        standing,
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
        .check(
            tenant,
            "https://hodor.example.com/t/acme",
            &parameters,
            &hodor_oauth::api::PushedRequestPolicy::default(),
        )
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

/// A client of the application that owns the resource server, allowed
/// client credentials, acting as `principal`.
async fn workload_client(world: &World, tenant: &Tenant, principal: UserId) -> Credentials {
    let mut settings = ClientSettings::new(
        "Nightly export",
        ClientType::Confidential,
        vec![GrantType::ClientCredentials],
        Vec::new(),
    );
    settings.authentication_method = AuthenticationMethod::ClientSecretBasic;
    settings.allowed_scopes = vec!["read".to_owned()];
    settings.principal = Some(principal);
    let (client, secret) = world
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
    Credentials {
        id: client.id(),
        secret: secret.map(|secret| secret.expose().to_owned()),
    }
}

fn client_credentials() -> Vec<(String, String)> {
    vec![("grant_type".to_owned(), "client_credentials".to_owned())]
}

#[tokio::test]
async fn a_client_that_acts_as_a_workload_gets_tokens_about_it_while_it_may_act() {
    let world = world();
    let tenant = tenant(&world).await;
    let workload = UserId::generate();
    world.standing.workload(workload, "service_account");
    let machine = workload_client(&world, &tenant, workload).await;
    let tokens = ask(&world, &tenant.context, &machine, client_credentials())
        .await
        .expect("client credentials");
    let answer = introspect(&world, &tenant.context, &machine, &access(&tokens))
        .await
        .expect("answered");
    assert_eq!(answer["active"], true);
    assert_eq!(
        answer["sub"],
        workload.to_string(),
        "the workload is the subject"
    );
    assert_eq!(answer["client_id"], machine.id.to_string());
    assert_eq!(answer["principal_kind"], "service_account");
    let record = world
        .records
        .all(tenant.context.tenant_id())
        .into_iter()
        .find(|record| record.client_id == machine.id)
        .expect("recorded");
    assert_eq!(record.principal_id, Some(workload));

    // A client without a principal is answered as before.
    let plain = resource_server_client(&world, &tenant).await;
    let own = ask(&world, &tenant.context, &plain, client_credentials())
        .await
        .expect("client credentials");
    let answer = introspect(&world, &tenant.context, &plain, &access(&own))
        .await
        .expect("answered");
    assert_eq!(answer["sub"], plain.id.to_string());
    assert!(answer.get("principal_kind").is_none(), "{answer}");

    // A workload that may no longer act stops its tokens at once, and its
    // clients get no new ones.
    world.standing.bar(workload);
    assert!(!active(&world, &tenant.context, &machine, &access(&tokens)).await);
    let refused = ask(&world, &tenant.context, &machine, client_credentials())
        .await
        .expect_err("refused");
    assert_eq!(refused.error, "invalid_client");
    assert!(active(&world, &tenant.context, &plain, &access(&own)).await);

    // A principal that is not a workload, such as a person, is refused too.
    let person = workload_client(&world, &tenant, UserId::generate()).await;
    let refused = ask(&world, &tenant.context, &person, client_credentials())
        .await
        .expect_err("refused");
    assert_eq!(refused.error, "invalid_client");
}

#[tokio::test]
async fn the_tokens_of_a_workload_are_revoked_with_it_and_stay_revoked() {
    let world = world();
    let tenant = tenant(&world).await;
    let (workload, other) = (UserId::generate(), UserId::generate());
    world.standing.workload(workload, "agent");
    world.standing.workload(other, "service_account");
    let machine = workload_client(&world, &tenant, workload).await;
    let neighbour = workload_client(&world, &tenant, other).await;
    let first = ask(&world, &tenant.context, &machine, client_credentials())
        .await
        .expect("client credentials");
    let second = ask(&world, &tenant.context, &machine, client_credentials())
        .await
        .expect("client credentials");
    let theirs = ask(&world, &tenant.context, &neighbour, client_credentials())
        .await
        .expect("client credentials");
    let answer = introspect(&world, &tenant.context, &machine, &access(&first))
        .await
        .expect("answered");
    assert_eq!(answer["principal_kind"], "agent");

    let mut uow = hodor_kernel::UnitOfWorkFactory::begin(&world.units, &tenant.context)
        .await
        .expect("begin");
    let revoked = world
        .tokens
        .workload_tokens()
        .revoke_in(
            uow.as_mut(),
            workload,
            "workload_disabled",
            Caller::system(),
        )
        .await
        .expect("revoked");
    uow.commit().await.expect("commit");
    assert_eq!(revoked, 2);
    for token in [&first, &second] {
        assert!(
            !active(&world, &tenant.context, &machine, &access(token)).await,
            "revoked, though the workload may still act"
        );
    }
    assert!(active(&world, &tenant.context, &neighbour, &access(&theirs)).await);
    let events = world.units.committed_event_types();
    assert_eq!(
        events
            .iter()
            .filter(|event| *event == "oauth.access_token_revoked")
            .count(),
        2
    );
    // New tokens are issued while the workload may act.
    let third = ask(&world, &tenant.context, &machine, client_credentials())
        .await
        .expect("client credentials");
    assert!(active(&world, &tenant.context, &machine, &access(&third)).await);
}

const LEDGER: &str = "urn:example:ledger";
const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// The ledger, a second resource server that also defines `read`, on the
/// application of the clients.
async fn ledger(world: &World, tenant: &Tenant) {
    world
        .applications
        .create_resource_server(
            &tenant.context,
            CreateResourceServer {
                application_id: tenant.application,
                audience: LEDGER.to_owned(),
                settings: ResourceServerSettings {
                    name: "Ledger".to_owned(),
                    scopes: vec![ScopeDefinition {
                        name: "read".to_owned(),
                        description: "Read the ledger".to_owned(),
                    }],
                },
            },
            Caller::system(),
        )
        .await
        .expect("resource server");
}

/// An agent's client of the application that owns the resource server,
/// allowed client credentials and token exchange with `rules`.
async fn agent_client(
    world: &World,
    tenant: &Tenant,
    agent: UserId,
    rules: &[(&str, &str)],
) -> Credentials {
    let mut settings = ClientSettings::new(
        "Assistant",
        ClientType::Confidential,
        vec![GrantType::ClientCredentials, GrantType::TokenExchange],
        Vec::new(),
    );
    settings.authentication_method = AuthenticationMethod::ClientSecretBasic;
    settings.allowed_scopes = vec!["read".to_owned()];
    settings.principal = Some(agent);
    settings.exchange_rules = rules
        .iter()
        .map(|(from, to)| hodor_oauth::api::ExchangeRule {
            subject_audience: (*from).to_owned(),
            audience: (*to).to_owned(),
        })
        .collect();
    let (client, secret) = world
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
    Credentials {
        id: client.id(),
        secret: secret.map(|secret| secret.expose().to_owned()),
    }
}

async fn exchange(
    world: &World,
    tenant: &TenantContext,
    client: &Credentials,
    subject: &str,
    actor: &str,
    extra: &[(&str, &str)],
) -> Result<IssuedTokens, TokenError> {
    let mut form = vec![
        ("grant_type".to_owned(), TOKEN_EXCHANGE.to_owned()),
        ("subject_token".to_owned(), subject.to_owned()),
        (
            "subject_token_type".to_owned(),
            ACCESS_TOKEN_TYPE.to_owned(),
        ),
        ("actor_token".to_owned(), actor.to_owned()),
        ("actor_token_type".to_owned(), ACCESS_TOKEN_TYPE.to_owned()),
    ];
    form.extend(
        extra
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
    );
    ask(world, tenant, client, form).await
}

/// A tenant with the ledger, a person's tokens, and an agent with its
/// client and its own token.
struct Exchanging {
    tenant: Tenant,
    person: IssuedTokens,
    agent: UserId,
    client: Credentials,
    actor: String,
}

async fn exchanging(world: &World, rules: &[(&str, &str)]) -> Exchanging {
    let tenant = tenant(world).await;
    ledger(world, &tenant).await;
    let code_client = confidential(world, &tenant).await;
    let person = signed_in(world, &tenant.context, &code_client, "openid read").await;
    let agent = UserId::generate();
    world.standing.workload(agent, "agent");
    let client = agent_client(world, &tenant, agent, rules).await;
    let actor = ask(world, &tenant.context, &client, client_credentials())
        .await
        .expect("the agent's own token");
    Exchanging {
        tenant,
        person,
        agent,
        client,
        actor: access(&actor),
    }
}

#[tokio::test]
async fn an_agent_exchanges_a_persons_token_for_one_it_holds_on_their_behalf() {
    let world = world();
    let setup = exchanging(&world, &[(AUDIENCE, LEDGER)]).await;
    let issued = exchange(
        &world,
        &setup.tenant.context,
        &setup.client,
        &access(&setup.person),
        &setup.actor,
        &[("audience", LEDGER)],
    )
    .await
    .expect("exchanged");
    assert_eq!(issued.issued_token_type, Some(ACCESS_TOKEN_TYPE));
    assert!(issued.refresh_token.is_none() && issued.id_token.is_none());
    assert_eq!(issued.scope, "read", "openid is never exchanged");
    let answer = introspect(
        &world,
        &setup.tenant.context,
        &setup.client,
        &access(&issued),
    )
    .await
    .expect("answered");
    assert_eq!(answer["active"], true, "{answer}");
    assert_eq!(answer["aud"], LEDGER);
    assert_eq!(answer["client_id"], setup.client.id.to_string());
    assert_eq!(answer["act"]["sub"], setup.agent.to_string());
    assert_eq!(answer["act"]["principal_kind"], "agent");
    assert!(
        answer.get("principal_kind").is_none(),
        "the subject is a person"
    );
    assert!(
        world
            .units
            .committed_event_types()
            .iter()
            .any(|event| event == "oauth.token_exchanged")
    );
    let record = world
        .records
        .all(setup.tenant.context.tenant_id())
        .into_iter()
        .find(|record| record.parent_token_id.is_some())
        .expect("recorded with its parent");
    assert_eq!(record.principal_id, Some(setup.agent));
    assert!(record.grant_id.is_some(), "the person's grant");
}

#[tokio::test]
async fn an_exchange_for_a_wider_scope_or_another_audience_is_refused() {
    let world = world();
    let setup = exchanging(&world, &[(AUDIENCE, LEDGER), (AUDIENCE, "urn:nowhere")]).await;
    let subject = access(&setup.person);
    let refused = |extra: &'static [(&'static str, &'static str)]| {
        exchange(
            &world,
            &setup.tenant.context,
            &setup.client,
            &subject,
            &setup.actor,
            extra,
        )
    };
    for (extra, error) in [
        (
            &[("audience", LEDGER), ("scope", "read write")][..],
            "invalid_scope",
        ),
        (
            &[("audience", LEDGER), ("scope", "openid")][..],
            "invalid_scope",
        ),
        (&[("audience", AUDIENCE)][..], "invalid_target"),
        (&[("audience", "urn:nowhere")][..], "invalid_target"),
        (&[][..], "invalid_target"),
        (
            &[("audience", LEDGER), ("resource", LEDGER)][..],
            "invalid_target",
        ),
        (
            &[
                ("audience", LEDGER),
                (
                    "requested_token_type",
                    "urn:ietf:params:oauth:token-type:id_token",
                ),
            ][..],
            "invalid_request",
        ),
    ] {
        let answer = refused(extra).await.expect_err("refused");
        assert_eq!(answer.error, error, "{extra:?}");
    }
}

#[tokio::test]
async fn a_chain_past_three_actors_is_refused() {
    let world = world();
    let setup = exchanging(&world, &[(AUDIENCE, LEDGER), (LEDGER, LEDGER)]).await;
    let mut subject = access(&setup.person);
    for hop in 1..=3 {
        let issued = exchange(
            &world,
            &setup.tenant.context,
            &setup.client,
            &subject,
            &setup.actor,
            &[("audience", LEDGER)],
        )
        .await
        .unwrap_or_else(|error| panic!("hop {hop}: {error:?}"));
        subject = access(&issued);
    }
    let answer = introspect(&world, &setup.tenant.context, &setup.client, &subject)
        .await
        .expect("answered");
    assert_eq!(answer["act"]["act"]["act"]["sub"], setup.agent.to_string());
    let refused = exchange(
        &world,
        &setup.tenant.context,
        &setup.client,
        &subject,
        &setup.actor,
        &[("audience", LEDGER)],
    )
    .await
    .expect_err("a fourth actor");
    assert_eq!(refused.error, "invalid_request");
}

#[tokio::test]
async fn an_exchanged_token_stops_with_the_agent_down_the_chain() {
    let world = world();
    let setup = exchanging(&world, &[(AUDIENCE, LEDGER), (LEDGER, LEDGER)]).await;
    let first = exchange(
        &world,
        &setup.tenant.context,
        &setup.client,
        &access(&setup.person),
        &setup.actor,
        &[("audience", LEDGER)],
    )
    .await
    .expect("exchanged");
    let second = exchange(
        &world,
        &setup.tenant.context,
        &setup.client,
        &access(&first),
        &setup.actor,
        &[("audience", LEDGER)],
    )
    .await
    .expect("exchanged again");
    for token in [&first, &second] {
        assert!(active(&world, &setup.tenant.context, &setup.client, &access(token)).await);
    }
    // Disabling the agent stops every token it holds for the person, down
    // the chain.
    world.standing.bar(setup.agent);
    for token in [&first, &second] {
        assert!(
            !active(&world, &setup.tenant.context, &setup.client, &access(token)).await,
            "the agent may no longer act"
        );
    }
}

#[tokio::test]
async fn revoking_the_subject_token_stops_what_was_exchanged_from_it() {
    let world = world();
    let tenant = tenant(&world).await;
    ledger(&world, &tenant).await;
    let code_client = confidential(&world, &tenant).await;
    let person = signed_in(&world, &tenant.context, &code_client, "openid read").await;
    let agent = UserId::generate();
    world.standing.workload(agent, "agent");
    let client = agent_client(&world, &tenant, agent, &[(AUDIENCE, LEDGER)]).await;
    let actor = access(
        &ask(&world, &tenant.context, &client, client_credentials())
            .await
            .expect("the agent's token"),
    );
    let issued = exchange(
        &world,
        &tenant.context,
        &client,
        &access(&person),
        &actor,
        &[("audience", LEDGER)],
    )
    .await
    .expect("exchanged");
    assert!(active(&world, &tenant.context, &client, &access(&issued)).await);
    revoke(&world, &tenant.context, &code_client, &access(&person)).await;
    assert!(!active(&world, &tenant.context, &client, &access(&issued)).await);
    // And ending the person's grant stops a fresh one too.
    let again = signed_in(&world, &tenant.context, &code_client, "openid read").await;
    let issued = exchange(
        &world,
        &tenant.context,
        &client,
        &access(&again),
        &actor,
        &[("audience", LEDGER)],
    )
    .await
    .expect("exchanged");
    revoke(
        &world,
        &tenant.context,
        &code_client,
        &refresh_token_of(&again),
    )
    .await;
    assert!(!active(&world, &tenant.context, &client, &access(&issued)).await);
}

#[tokio::test]
async fn only_an_agents_own_token_acts_and_only_a_persons_is_exchanged() {
    let world = world();
    let setup = exchanging(&world, &[(AUDIENCE, LEDGER)]).await;
    // A service account's client may not exchange at all.
    let account = UserId::generate();
    world.standing.workload(account, "service_account");
    let account_client = agent_client(&world, &setup.tenant, account, &[(AUDIENCE, LEDGER)]).await;
    let account_token = access(
        &ask(
            &world,
            &setup.tenant.context,
            &account_client,
            client_credentials(),
        )
        .await
        .expect("its own token"),
    );
    let refused = exchange(
        &world,
        &setup.tenant.context,
        &account_client,
        &access(&setup.person),
        &account_token,
        &[("audience", LEDGER)],
    )
    .await
    .expect_err("not an agent");
    assert_eq!(refused.error, "unauthorized_client");

    // Another agent's token is no actor for this client, and a workload's
    // token, or the agent's own, is no subject.
    let other = UserId::generate();
    world.standing.workload(other, "agent");
    let other_client = agent_client(&world, &setup.tenant, other, &[(AUDIENCE, LEDGER)]).await;
    let other_token = access(
        &ask(
            &world,
            &setup.tenant.context,
            &other_client,
            client_credentials(),
        )
        .await
        .expect("its own token"),
    );
    for (subject, actor) in [
        (access(&setup.person), other_token.clone()),
        (access(&setup.person), access(&setup.person)),
        (account_token.clone(), setup.actor.clone()),
        (setup.actor.clone(), setup.actor.clone()),
        ("not a token".to_owned(), setup.actor.clone()),
    ] {
        let refused = exchange(
            &world,
            &setup.tenant.context,
            &setup.client,
            &subject,
            &actor,
            &[("audience", LEDGER)],
        )
        .await
        .expect_err("refused");
        assert_eq!(refused.error, "invalid_request");
    }

    // Without both tokens, or with another kind, the request is refused.
    let missing = ask(
        &world,
        &setup.tenant.context,
        &setup.client,
        vec![
            ("grant_type".to_owned(), TOKEN_EXCHANGE.to_owned()),
            ("subject_token".to_owned(), access(&setup.person)),
            (
                "subject_token_type".to_owned(),
                ACCESS_TOKEN_TYPE.to_owned(),
            ),
            ("audience".to_owned(), LEDGER.to_owned()),
        ],
    )
    .await
    .expect_err("no actor");
    assert_eq!(missing.error, "invalid_request");
}
