//! Refresh tokens and client credentials at the token endpoint, on the
//! in-memory stores.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::sealing::testing::FakeSecretBox;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, Clock as _, CorrelationId, TenantContext, TenantId, Timestamp, UserId};
use hodor_keys::api::{KeyAlgorithm, KeyService, RotationPolicy};
use hodor_keys::testing::{FakeKeyProvider, InMemoryKeys};
use hodor_oauth::api::{
    ApplicationId, ApplicationPorts, ApplicationService, ApplicationSettings, AuthenticationMethod,
    AuthorizationCodePorts, AuthorizationCodeService, AuthorizationParameters, BasicCredentials,
    ClientId, ClientSettings, ClientType, CreateClient, CreateResourceServer, FamilyStatus,
    GrantStatus, GrantType, IssuedTokens, Issuer, ResourceServerSettings, ScopeDefinition,
    SignedInPerson, TokenError, TokenPorts, TokenRequest, TokenService, s256_challenge,
};
use hodor_oauth::testing::{
    DistinctRandom, FakeVerifier, InMemoryAuthorizationCodes, InMemoryAuthorizationRequests,
    InMemoryClientAssertions, InMemoryGrants, InMemoryRefreshTokens, InMemoryStores,
    RefreshStorePorts, StandingOf, run_refresh_token_contract,
};
use hodor_session::api::SessionId;
use serde_json::Value;
use std::sync::Arc;
use time::Duration;

const REDIRECT: &str = "https://payroll.example.com/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const ISSUER: &str = "https://hodor.example.com/t/acme";
const ENDPOINT: &str = "https://hodor.example.com/t/acme/oauth2/token";
const AUDIENCE: &str = "https://api.payroll.example.com";
const OTHER_AUDIENCE: &str = "urn:example:billing";

const ISSUER_OF: Issuer<'static> = Issuer {
    issuer: ISSUER,
    token_endpoint: ENDPOINT,
};

struct World {
    units: InMemoryUnitOfWorkFactory,
    clock: Arc<FixedClock>,
    grants: InMemoryGrants,
    families: InMemoryRefreshTokens,
    standing: StandingOf,
    codes: AuthorizationCodeService,
    applications: ApplicationService,
    keys: KeyService,
    tokens: TokenService,
}

fn world_with_window(window: Duration) -> World {
    let units = InMemoryUnitOfWorkFactory::default();
    let stores = InMemoryStores::default();
    let requests = InMemoryAuthorizationRequests::new(&stores.clients);
    let grants = InMemoryGrants::new(&stores.clients);
    let code_store = InMemoryAuthorizationCodes::new(&grants);
    let families = InMemoryRefreshTokens::new(&grants);
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
        standing: Arc::new(standing.clone()),
        secrets: Arc::new(FakeSecretBox),
        codes: codes.clone(),
        keys: keys.clone(),
        verifier: Arc::new(FakeVerifier),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    })
    .with_retry_window(window)
    .expect("a window within bounds");
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
        grants,
        families,
        standing,
        codes,
        applications,
        keys,
        tokens,
    }
}

fn world() -> World {
    world_with_window(Duration::seconds(10))
}

/// A tenant with an active signing key, a first-party application and two
/// resource servers.
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
                name: "Payroll".to_owned(),
                first_party: true,
            },
            Caller::system(),
        )
        .await
        .expect("application");
    for (audience, scope) in [(AUDIENCE, "read"), (OTHER_AUDIENCE, "invoices")] {
        let owner = world
            .applications
            .create_application(
                &tenant,
                ApplicationSettings {
                    name: format!("Owner of {scope}"),
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
                    application_id: owner.id(),
                    audience: audience.to_owned(),
                    settings: ResourceServerSettings {
                        name: format!("{scope} interface"),
                        scopes: vec![ScopeDefinition {
                            name: scope.to_owned(),
                            description: format!("{scope} things"),
                        }],
                    },
                },
                Caller::system(),
            )
            .await
            .expect("resource server");
    }
    (tenant, application.id())
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

    /// The form fields that name the client, for a public one.
    fn fields(&self) -> Vec<(String, String)> {
        if self.secret.is_some() {
            Vec::new()
        } else {
            vec![("client_id".to_owned(), self.id.to_string())]
        }
    }
}

async fn client(
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
        "invoices".to_owned(),
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

/// A public client allowed the refresh token grant.
async fn refreshing_client(
    world: &World,
    tenant: &TenantContext,
    application: ApplicationId,
) -> Credentials {
    client(
        world,
        tenant,
        application,
        ClientType::Public,
        vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
    )
    .await
}

fn person(world: &World) -> SignedInPerson {
    SignedInPerson {
        user_id: UserId::generate(),
        session_id: SessionId::generate(),
        signed_in_at: world.clock.now() - Duration::minutes(2),
        methods: vec!["password".to_owned()],
    }
}

/// The tokens for a code issued to `client` for `scope`, and the person.
async fn signed_in(
    world: &World,
    tenant: &TenantContext,
    client: &Credentials,
    scope: &str,
) -> (IssuedTokens, SignedInPerson) {
    let challenge = s256_challenge(VERIFIER, &FakeDigest);
    let id = client.id.to_string();
    let pairs = [
        ("response_type", "code"),
        ("client_id", id.as_str()),
        ("redirect_uri", REDIRECT),
        ("scope", scope),
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
    let person = person(world);
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
    let tokens = ask(world, tenant, client, form).await.expect("tokens");
    (tokens, person)
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
    extra: &[(&str, &str)],
) -> Result<IssuedTokens, TokenError> {
    let mut form = vec![
        ("grant_type".to_owned(), "refresh_token".to_owned()),
        ("refresh_token".to_owned(), token.to_owned()),
    ];
    form.extend(
        extra
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
    );
    form.extend(client.fields());
    ask(world, tenant, client, form).await
}

fn refresh_token(tokens: &IssuedTokens) -> String {
    tokens
        .refresh_token
        .as_ref()
        .expect("a refresh token")
        .expose()
        .clone()
}

fn claims(tokens: &IssuedTokens) -> Value {
    let token = tokens.access_token.expose().clone();
    let part = token.split('.').nth(1).expect("claims").to_owned();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("json")
}

fn error_of(result: Result<IssuedTokens, TokenError>) -> &'static str {
    result.expect_err("refused").error
}

fn event_types(world: &World) -> Vec<String> {
    world
        .units
        .committed_events()
        .iter()
        .map(|event| event.event_type.clone())
        .collect()
}

#[tokio::test]
async fn the_in_memory_store_passes_the_contract() {
    let units = InMemoryUnitOfWorkFactory::default();
    let stores = InMemoryStores::default();
    let grants = InMemoryGrants::new(&stores.clients);
    let families = InMemoryRefreshTokens::new(&grants);
    run_refresh_token_contract(RefreshStorePorts {
        units_of_work: &units,
        applications: &stores.applications,
        clients: &stores.clients,
        grants: &grants,
        refresh_tokens: &families,
    })
    .await;
}

#[tokio::test]
async fn a_code_comes_with_a_refresh_token_that_moves_at_every_use() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    let client = refreshing_client(&world, &tenant, application).await;
    let (first, person) = signed_in(&world, &tenant, &client, "openid read").await;
    let one = refresh_token(&first);
    assert_eq!(one.len(), 43);

    world.clock.advance(Duration::minutes(10));
    let second = refresh(&world, &tenant, &client, &one, &[])
        .await
        .expect("refreshed");
    let two = refresh_token(&second);
    assert_ne!(one, two, "a new refresh token at every use");
    let claims = claims(&second);
    assert_eq!(claims["sub"], person.user_id.to_string());
    assert_eq!(claims["scope"], "openid read");
    assert_eq!(
        claims["aud"],
        serde_json::json!([AUDIENCE, ISSUER]),
        "with openid, the issuer too, for UserInfo"
    );
    assert_eq!(
        claims["auth_time"].as_i64(),
        Some(person.signed_in_at.unix_timestamp())
    );
    assert_eq!(second.scope, "openid read");

    let third = refresh(&world, &tenant, &client, &two, &[])
        .await
        .expect("refreshed again");
    assert_ne!(refresh_token(&third), two);

    let families = world.families.all(tenant.tenant_id());
    assert_eq!(families.len(), 1);
    assert_eq!(families[0].generation, 3);
    let types = event_types(&world);
    assert!(types.contains(&"oauth.refresh_token_family_started".to_owned()));
    assert_eq!(
        types
            .iter()
            .filter(|kind| *kind == "oauth.refresh_token_rotated")
            .count(),
        2
    );
    let payloads: String = world
        .units
        .committed_events()
        .iter()
        .map(|event| event.payload.to_string())
        .collect();
    for token in [&one, &two] {
        assert!(
            !payloads.contains(token.as_str()),
            "no event carries a token"
        );
    }
}

#[tokio::test]
async fn a_refresh_token_used_before_revokes_its_family_and_grant() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    let client = refreshing_client(&world, &tenant, application).await;
    let (first, _) = signed_in(&world, &tenant, &client, "openid read").await;
    let one = refresh_token(&first);
    let second = refresh(&world, &tenant, &client, &one, &[])
        .await
        .expect("refreshed");
    let two = refresh_token(&second);

    world.clock.advance(Duration::seconds(11));
    assert_eq!(
        error_of(refresh(&world, &tenant, &client, &one, &[]).await),
        "invalid_grant",
        "outside the window, the old token is reuse"
    );
    let family = &world.families.all(tenant.tenant_id())[0];
    assert_eq!(family.status, FamilyStatus::Revoked);
    assert_eq!(
        family.revocation_reason.as_deref(),
        Some("refresh_token_reused")
    );
    let grant = &world.grants.all(tenant.tenant_id())[0];
    assert_eq!(grant.status, GrantStatus::Revoked, "the grant with it");
    assert_eq!(
        error_of(refresh(&world, &tenant, &client, &two, &[]).await),
        "invalid_grant",
        "the newest token of the family is refused too"
    );
    let types = event_types(&world);
    assert!(types.contains(&"oauth.refresh_token_family_revoked".to_owned()));
    assert!(types.contains(&"oauth.grant_revoked".to_owned()));
}

#[tokio::test]
async fn the_same_request_retried_within_the_window_gets_the_same_refresh_token() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    let client = refreshing_client(&world, &tenant, application).await;
    let (first, _) = signed_in(&world, &tenant, &client, "openid read").await;
    let one = refresh_token(&first);
    let second = refresh(&world, &tenant, &client, &one, &[])
        .await
        .expect("refreshed");

    world.clock.advance(Duration::seconds(3));
    let again = refresh(&world, &tenant, &client, &one, &[])
        .await
        .expect("the same request, retried");
    assert_eq!(
        refresh_token(&again),
        refresh_token(&second),
        "the same next refresh token"
    );
    assert_ne!(
        claims(&again)["jti"],
        claims(&second)["jti"],
        "a new access token"
    );
    assert_eq!(world.families.all(tenant.tenant_id())[0].generation, 2);

    // The family goes on from there.
    let third = refresh(&world, &tenant, &client, &refresh_token(&second), &[])
        .await
        .expect("the newest token still works");
    // A retry of the first token now names a family that moved again.
    assert_eq!(
        error_of(refresh(&world, &tenant, &client, &one, &[]).await),
        "invalid_grant"
    );
    assert_eq!(
        world.families.all(tenant.tenant_id())[0].status,
        FamilyStatus::Revoked
    );
    assert_eq!(
        error_of(refresh(&world, &tenant, &client, &refresh_token(&third), &[]).await),
        "invalid_grant"
    );
}

#[tokio::test]
async fn a_retry_asking_for_something_else_is_reuse() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    let client = refreshing_client(&world, &tenant, application).await;
    let (first, _) = signed_in(&world, &tenant, &client, "openid read").await;
    let one = refresh_token(&first);
    refresh(&world, &tenant, &client, &one, &[])
        .await
        .expect("refreshed");
    assert_eq!(
        error_of(refresh(&world, &tenant, &client, &one, &[("scope", "read")]).await),
        "invalid_grant"
    );
    assert_eq!(
        world.families.all(tenant.tenant_id())[0].status,
        FamilyStatus::Revoked
    );
}

#[tokio::test]
async fn a_window_of_zero_turns_retries_off() {
    let world = world_with_window(Duration::ZERO);
    let (tenant, application) = tenant(&world).await;
    let client = refreshing_client(&world, &tenant, application).await;
    let (first, _) = signed_in(&world, &tenant, &client, "openid read").await;
    let one = refresh_token(&first);
    refresh(&world, &tenant, &client, &one, &[])
        .await
        .expect("refreshed");
    assert_eq!(
        error_of(refresh(&world, &tenant, &client, &one, &[]).await),
        "invalid_grant"
    );
    assert!(
        world
            .tokens
            .clone()
            .with_retry_window(Duration::seconds(61))
            .is_err(),
        "more than 60 seconds is refused"
    );
    assert!(
        world
            .tokens
            .clone()
            .with_retry_window(Duration::seconds(-1))
            .is_err()
    );
}

#[tokio::test]
async fn a_refresh_may_narrow_its_scopes_and_audiences_but_never_widen_them() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    let client = refreshing_client(&world, &tenant, application).await;
    let (first, _) = signed_in(&world, &tenant, &client, "openid read invoices").await;
    assert_eq!(
        claims(&first)["aud"],
        serde_json::json!([AUDIENCE, OTHER_AUDIENCE, ISSUER])
    );
    let one = refresh_token(&first);

    let narrow = refresh(
        &world,
        &tenant,
        &client,
        &one,
        &[("scope", "invoices"), ("resource", OTHER_AUDIENCE)],
    )
    .await
    .expect("narrowed");
    assert_eq!(narrow.scope, "invoices");
    assert_eq!(claims(&narrow)["aud"], OTHER_AUDIENCE);

    let two = refresh_token(&narrow);
    assert_eq!(
        error_of(refresh(&world, &tenant, &client, &two, &[("scope", "read write")]).await),
        "invalid_scope"
    );
    assert_eq!(
        error_of(
            refresh(
                &world,
                &tenant,
                &client,
                &two,
                &[("resource", "https://elsewhere.example.com")]
            )
            .await
        ),
        "invalid_target"
    );
    let all = refresh(&world, &tenant, &client, &two, &[])
        .await
        .expect("all the family's scopes again");
    assert_eq!(all.scope, "openid read invoices");
}

#[tokio::test]
async fn a_refresh_token_presented_by_another_client_has_leaked() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    let client = refreshing_client(&world, &tenant, application).await;
    let thief = refreshing_client(&world, &tenant, application).await;
    let (first, _) = signed_in(&world, &tenant, &client, "openid read").await;
    let one = refresh_token(&first);
    assert_eq!(
        error_of(refresh(&world, &tenant, &thief, &one, &[]).await),
        "invalid_grant"
    );
    let family = &world.families.all(tenant.tenant_id())[0];
    assert_eq!(family.status, FamilyStatus::Revoked);
    assert_eq!(family.revocation_reason.as_deref(), Some("other_client"));
    assert_eq!(
        error_of(refresh(&world, &tenant, &client, &one, &[]).await),
        "invalid_grant"
    );
}

#[tokio::test]
async fn a_family_without_offline_access_ends_with_its_session() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    let client = refreshing_client(&world, &tenant, application).await;
    let (online, online_person) = signed_in(&world, &tenant, &client, "openid read").await;
    let (offline, offline_person) =
        signed_in(&world, &tenant, &client, "openid offline_access read").await;

    world.standing.end_session(online_person.session_id);
    world.standing.end_session(offline_person.session_id);
    assert_eq!(
        error_of(refresh(&world, &tenant, &client, &refresh_token(&online), &[]).await),
        "invalid_grant"
    );
    let still = refresh(&world, &tenant, &client, &refresh_token(&offline), &[])
        .await
        .expect("offline access outlives the session");

    world.standing.bar(offline_person.user_id);
    assert_eq!(
        error_of(refresh(&world, &tenant, &client, &refresh_token(&still), &[]).await),
        "invalid_grant",
        "a person who may no longer sign in gets no tokens"
    );
}

#[tokio::test]
async fn a_family_ends_after_its_idle_time_and_its_lifetime() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    let client = refreshing_client(&world, &tenant, application).await;
    let (first, _) = signed_in(&world, &tenant, &client, "openid offline_access read").await;
    world.clock.advance(Duration::days(7));
    assert_eq!(
        error_of(refresh(&world, &tenant, &client, &refresh_token(&first), &[]).await),
        "invalid_grant",
        "unused for the idle time"
    );

    let (first, _) = signed_in(&world, &tenant, &client, "openid offline_access read").await;
    let mut token = refresh_token(&first);
    for _ in 0..4 {
        world.clock.advance(Duration::days(6));
        let next = refresh(&world, &tenant, &client, &token, &[])
            .await
            .expect("used in time");
        token = refresh_token(&next);
    }
    world.clock.advance(Duration::days(6));
    assert_eq!(
        error_of(refresh(&world, &tenant, &client, &token, &[]).await),
        "invalid_grant",
        "30 days after it started, used or not"
    );
}

#[tokio::test]
async fn only_a_client_allowed_refresh_tokens_gets_and_uses_them() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    let plain = client(
        &world,
        &tenant,
        application,
        ClientType::Public,
        vec![GrantType::AuthorizationCode],
    )
    .await;
    let (tokens, _) = signed_in(&world, &tenant, &plain, "openid read").await;
    assert!(tokens.refresh_token.is_none());

    let refreshing = refreshing_client(&world, &tenant, application).await;
    let (tokens, _) = signed_in(&world, &tenant, &refreshing, "openid read").await;
    assert_eq!(
        error_of(refresh(&world, &tenant, &plain, &refresh_token(&tokens), &[]).await),
        "unauthorized_client"
    );
    for malformed in ["", "short", &"!".repeat(43)] {
        assert_eq!(
            error_of(refresh(&world, &tenant, &refreshing, malformed, &[]).await),
            "invalid_grant"
        );
    }
}

#[tokio::test]
async fn a_refresh_token_of_one_tenant_finds_nothing_in_another() {
    let world = world();
    let (acme, application) = tenant(&world).await;
    let (globex, globex_application) = tenant(&world).await;
    let client = refreshing_client(&world, &acme, application).await;
    let other = refreshing_client(&world, &globex, globex_application).await;
    let (tokens, _) = signed_in(&world, &acme, &client, "openid read").await;
    let token = refresh_token(&tokens);
    assert_eq!(
        error_of(refresh(&world, &globex, &other, &token, &[]).await),
        "invalid_grant"
    );
    assert_eq!(
        world.families.all(acme.tenant_id())[0].status,
        FamilyStatus::Active,
        "nothing happened to the family in its own tenant"
    );
    refresh(&world, &acme, &client, &token, &[])
        .await
        .expect("still good where it belongs");
}

#[tokio::test]
async fn a_confidential_client_gets_a_token_for_itself() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    let service = client(
        &world,
        &tenant,
        application,
        ClientType::Confidential,
        vec![GrantType::ClientCredentials],
    )
    .await;
    let grant = |extra: &[(&str, &str)]| {
        let mut form = vec![("grant_type".to_owned(), "client_credentials".to_owned())];
        form.extend(
            extra
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
        );
        form
    };

    let tokens = ask(&world, &tenant, &service, grant(&[]))
        .await
        .expect("every scope it is allowed");
    assert!(tokens.refresh_token.is_none(), "no refresh token");
    assert_eq!(tokens.scope, "read invoices");
    let token = claims(&tokens);
    assert_eq!(token["sub"], service.id.to_string());
    assert_eq!(token["client_id"], service.id.to_string());
    assert_eq!(token["aud"], serde_json::json!([AUDIENCE, OTHER_AUDIENCE]));
    assert!(token.get("auth_time").is_none());

    let one = ask(&world, &tenant, &service, grant(&[("scope", "read")]))
        .await
        .expect("one scope");
    assert_eq!(claims(&one)["aud"], AUDIENCE);
    let through = ask(
        &world,
        &tenant,
        &service,
        grant(&[("resource", OTHER_AUDIENCE)]),
    )
    .await
    .expect("one resource");
    assert_eq!(through.scope, "invoices");

    for (extra, error) in [
        (vec![("scope", "openid")], "invalid_scope"),
        (vec![("scope", "write")], "invalid_scope"),
        (
            vec![("scope", "read"), ("resource", OTHER_AUDIENCE)],
            "invalid_scope",
        ),
        (
            vec![("resource", "https://elsewhere.example.com")],
            "invalid_target",
        ),
    ] {
        assert_eq!(
            error_of(ask(&world, &tenant, &service, grant(&extra)).await),
            error,
            "{extra:?}"
        );
    }
    assert!(event_types(&world).contains(&"oauth.client_access_token_issued".to_owned()));
}

#[tokio::test]
async fn a_client_not_allowed_client_credentials_is_refused() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    let public = client(
        &world,
        &tenant,
        application,
        ClientType::Public,
        vec![GrantType::AuthorizationCode],
    )
    .await;
    let mut form = vec![("grant_type".to_owned(), "client_credentials".to_owned())];
    form.extend(public.fields());
    assert_eq!(
        error_of(ask(&world, &tenant, &public, form).await),
        "unauthorized_client"
    );
    let confidential = client(
        &world,
        &tenant,
        application,
        ClientType::Confidential,
        vec![GrantType::AuthorizationCode],
    )
    .await;
    assert_eq!(
        error_of(
            ask(
                &world,
                &tenant,
                &confidential,
                vec![("grant_type".to_owned(), "client_credentials".to_owned())]
            )
            .await
        ),
        "unauthorized_client"
    );
}
