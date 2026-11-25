//! Claim mappers: the use cases of an administrator, checked when a mapper
//! is saved, and the claims they add at the token endpoint, on the
//! in-memory stores.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::sealing::testing::FakeSecretBox;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, Clock as _, CorrelationId, DomainError, GroupId, OrganizationId, TenantContext,
    TenantId, Timestamp, UserId,
};
use hodor_keys::api::{KeyAlgorithm, KeyService, RotationPolicy};
use hodor_keys::testing::{FakeKeyProvider, InMemoryKeys};
use hodor_oauth::api::{
    ApplicationId, ApplicationPorts, ApplicationService, ApplicationSettings, AuthenticationMethod,
    AuthorizationCodePorts, AuthorizationCodeService, AuthorizationParameters, BasicCredentials,
    ClaimMapperPorts, ClaimMapperService, ClaimMapperSettings, ClaimMapping, ClaimSource,
    ClaimTarget, ClientId, ClientSettings, ClientType, CreateClient, CreateResourceServer,
    GrantType, IssuedTokens, Issuer, OrganizationAttribute, PersonAttribute, PersonAttributes,
    ResourceServerSettings, ScopeDefinition, SignedInPerson, TokenPorts, TokenRequest,
    TokenService, s256_challenge,
};
use hodor_oauth::testing::{
    ClaimMapperStorePorts, ClaimSourcesOf, DistinctRandom, FakeVerifier,
    InMemoryAccessTokenRecords, InMemoryAuthorizationCodes, InMemoryAuthorizationRequests,
    InMemoryClaimMappers, InMemoryClientAssertions, InMemoryGrants, InMemoryRefreshTokens,
    InMemoryStores, MembershipsOf, StandingOf, run_claim_mapper_contract,
};
use hodor_session::api::SessionId;
use serde_json::{Value, json};
use std::sync::Arc;
use time::Duration;

const REDIRECT: &str = "https://payroll.example.com/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const ISSUER: &str = "https://hodor.example.com/t/acme";
const ENDPOINT: &str = "https://hodor.example.com/t/acme/oauth2/token";
const AUDIENCE: &str = "https://api.payroll.example.com";

const ISSUER_OF: Issuer<'static> = Issuer {
    issuer: ISSUER,
    token_endpoint: ENDPOINT,
};

struct World {
    units: InMemoryUnitOfWorkFactory,
    clock: Arc<FixedClock>,
    memberships: MembershipsOf,
    sources: ClaimSourcesOf,
    codes: AuthorizationCodeService,
    applications: ApplicationService,
    mappers: ClaimMapperService,
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
    let mapper_store = InMemoryClaimMappers::new(&stores.clients);
    let memberships = MembershipsOf::default();
    let sources = ClaimSourcesOf::default();
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
        memberships: Arc::new(memberships.clone()),
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
        refresh_tokens: Arc::new(families),
        access_tokens: Arc::new(InMemoryAccessTokenRecords::new(&stores.clients)),
        standing: Arc::new(StandingOf::default()),
        memberships: Arc::new(memberships.clone()),
        mapping: ClaimMapping::new(
            Arc::new(units.clone()),
            Arc::new(mapper_store.clone()),
            Arc::new(memberships.clone()),
            Arc::new(sources.clone()),
        ),
        secrets: Arc::new(FakeSecretBox),
        codes: codes.clone(),
        keys: keys.clone(),
        verifier: Arc::new(FakeVerifier),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    let mappers = ClaimMapperService::new(ClaimMapperPorts {
        units_of_work: Arc::new(units.clone()),
        clients: Arc::new(stores.clients.clone()),
        mappers: Arc::new(mapper_store),
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
        clock,
        memberships,
        sources,
        codes,
        applications,
        mappers,
        keys,
        tokens,
    }
}

/// A tenant with an active signing key, a first-party application and a
/// resource server.
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
    world
        .applications
        .create_resource_server(
            &tenant,
            CreateResourceServer {
                application_id: application.id(),
                audience: AUDIENCE.to_owned(),
                settings: ResourceServerSettings {
                    name: "Payroll interface".to_owned(),
                    scopes: vec![ScopeDefinition {
                        name: "read".to_owned(),
                        description: "read things".to_owned(),
                    }],
                },
            },
            Caller::system(),
        )
        .await
        .expect("resource server");
    (tenant, application.id())
}

#[derive(Clone)]
struct Credentials {
    id: ClientId,
    secret: Option<String>,
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
    settings.allowed_scopes = ["openid", "profile", "read", "groups"]
        .map(str::to_owned)
        .to_vec();
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

async fn web_client(
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
        acr: Some("urn:hodor:acr:single-factor".to_owned()),
    }
}

async fn ask(
    world: &World,
    tenant: &TenantContext,
    client: &Credentials,
    mut pairs: Vec<(String, String)>,
) -> IssuedTokens {
    let basic = client.secret.as_ref().map(|secret| BasicCredentials {
        client_id: client.id.to_string(),
        secret: secret.clone().into(),
    });
    if basic.is_none() {
        pairs.push(("client_id".to_owned(), client.id.to_string()));
    }
    let request = TokenRequest::parse(basic, pairs).expect("a request");
    world
        .tokens
        .token(tenant, ISSUER_OF, request, CorrelationId::generate())
        .await
        .expect("storage")
        .expect("tokens")
}

/// The tokens for a code issued to `client` for `person`.
async fn signed_in(
    world: &World,
    tenant: &TenantContext,
    client: &Credentials,
    scope: &str,
    extra: &[(&str, &str)],
    person: &SignedInPerson,
) -> IssuedTokens {
    let challenge = s256_challenge(VERIFIER, &FakeDigest);
    let id = client.id.to_string();
    let mut pairs = vec![
        ("response_type", "code"),
        ("client_id", id.as_str()),
        ("redirect_uri", REDIRECT),
        ("scope", scope),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ];
    pairs.extend_from_slice(extra);
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
    let code = world
        .codes
        .issue_code(tenant, &request, person, Caller::system())
        .await
        .expect("code");
    ask(
        world,
        tenant,
        client,
        vec![
            ("grant_type".to_owned(), "authorization_code".to_owned()),
            ("code".to_owned(), code.expose().to_owned()),
            ("redirect_uri".to_owned(), REDIRECT.to_owned()),
            ("code_verifier".to_owned(), VERIFIER.to_owned()),
        ],
    )
    .await
}

fn decoded(token: &str) -> Value {
    let part = token.split('.').nth(1).expect("claims").to_owned();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("json")
}

fn access(tokens: &IssuedTokens) -> Value {
    decoded(tokens.access_token.expose())
}

fn id_token(tokens: &IssuedTokens) -> Value {
    decoded(tokens.id_token.as_ref().expect("an ID token").expose())
}

fn mapping(claim: &str, targets: &[ClaimTarget], source: ClaimSource) -> ClaimMapperSettings {
    ClaimMapperSettings {
        claim: claim.to_owned(),
        targets: targets.to_vec(),
        scope: None,
        source,
    }
}

async fn add(
    world: &World,
    tenant: &TenantContext,
    client: ClientId,
    settings: ClaimMapperSettings,
) -> Result<hodor_oauth::api::ClaimMapper, DomainError> {
    world
        .mappers
        .create(tenant, client, settings, Caller::system())
        .await
}

#[tokio::test]
async fn the_in_memory_store_passes_the_contract() {
    let units = InMemoryUnitOfWorkFactory::default();
    let stores = InMemoryStores::default();
    let mappers = InMemoryClaimMappers::new(&stores.clients);
    run_claim_mapper_contract(ClaimMapperStorePorts {
        units_of_work: &units,
        applications: &stores.applications,
        clients: &stores.clients,
        mappers: &mappers,
    })
    .await;
}

#[tokio::test]
async fn a_mapper_that_names_sub_iss_or_acr_is_refused_and_nothing_is_stored() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    let web = web_client(&world, &tenant, application).await;
    for name in ["sub", "iss", "acr", "Sub"] {
        let refused = add(
            &world,
            &tenant,
            web.id,
            mapping(name, &[ClaimTarget::IdToken], ClaimSource::Groups),
        )
        .await
        .expect_err("refused");
        assert_eq!(refused.code(), "oauth.claim_mapper_name_reserved", "{name}");
    }
    assert!(
        world
            .mappers
            .mappers(&tenant, web.id)
            .await
            .expect("list")
            .is_empty()
    );
    assert!(
        !world
            .units
            .committed_event_types()
            .iter()
            .any(|event| event.starts_with("oauth.claim_mapper")),
        "nothing recorded"
    );
}

#[tokio::test]
async fn a_token_past_the_bound_is_refused_when_the_mapper_is_saved() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    let web = web_client(&world, &tenant, application).await;
    let both = [ClaimTarget::IdToken, ClaimTarget::AccessToken];
    add(
        &world,
        &tenant,
        web.id,
        mapping("teams", &both, ClaimSource::Groups),
    )
    .await
    .expect("one mapper of the groups fits");
    let refused = add(
        &world,
        &tenant,
        web.id,
        mapping(
            "full_name",
            &[ClaimTarget::AccessToken],
            ClaimSource::Attribute(PersonAttribute::DisplayName),
        ),
    )
    .await
    .expect_err("refused when saved");
    assert_eq!(refused.code(), "oauth.claim_mapper_token_too_large");
    let fits = add(
        &world,
        &tenant,
        web.id,
        mapping(
            "full_name",
            &[ClaimTarget::UserInfo],
            ClaimSource::Attribute(PersonAttribute::DisplayName),
        ),
    )
    .await
    .expect("another target has room");

    // Replacing is checked again, with the other mappers.
    let refused = world
        .mappers
        .replace(
            &tenant,
            web.id,
            fits.id(),
            mapping(
                "full_name",
                &[ClaimTarget::IdToken],
                ClaimSource::Attribute(PersonAttribute::DisplayName),
            ),
            Caller::system(),
        )
        .await
        .expect_err("refused when saved");
    assert_eq!(refused.code(), "oauth.claim_mapper_token_too_large");
    let listed = world.mappers.mappers(&tenant, web.id).await.expect("list");
    assert_eq!(listed.len(), 2);
    assert_eq!(
        listed[0].settings().targets,
        [ClaimTarget::UserInfo],
        "a refused replacement changes nothing"
    );

    // The bound held: a person in a hundred groups with the longest name
    // signs in, and nothing is refused.
    let ana = person(&world);
    world
        .memberships
        .set_groups(ana.user_id, (0..100).map(|_| GroupId::generate()).collect());
    world.sources.set_attributes(
        tenant.tenant_id(),
        ana.user_id,
        PersonAttributes {
            display_name: Some("名".repeat(200)),
            ..PersonAttributes::default()
        },
    );
    let tokens = signed_in(&world, &tenant, &web, "openid", &[], &ana).await;
    assert_eq!(
        id_token(&tokens)["teams"].as_array().map(Vec::len),
        Some(100)
    );
    assert!(
        id_token(&tokens).get("full_name").is_none(),
        "only at UserInfo"
    );
}

#[tokio::test]
async fn an_administrator_creates_reads_replaces_and_deletes_a_mapper() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    let web = web_client(&world, &tenant, application).await;
    let mut scoped = mapping(
        "full_name",
        &[ClaimTarget::AccessToken],
        ClaimSource::Attribute(PersonAttribute::DisplayName),
    );
    scoped.scope = Some("invoices".to_owned());
    assert_eq!(
        add(&world, &tenant, web.id, scoped.clone())
            .await
            .expect_err("refused")
            .code(),
        "oauth.claim_mapper_scope_not_allowed"
    );
    scoped.scope = Some("profile".to_owned());
    let mapper = add(&world, &tenant, web.id, scoped).await.expect("created");
    assert_eq!(
        add(
            &world,
            &tenant,
            web.id,
            mapping("FULL_NAME", &[ClaimTarget::UserInfo], ClaimSource::Groups)
        )
        .await
        .expect_err("refused")
        .code(),
        "oauth.claim_mapper_name_taken"
    );
    assert_eq!(
        add(
            &world,
            &tenant,
            ClientId::generate(),
            mapping("team", &[ClaimTarget::UserInfo], ClaimSource::Groups)
        )
        .await
        .expect_err("refused")
        .code(),
        "oauth.client_not_found"
    );
    assert_eq!(
        world
            .mappers
            .mapper(&tenant, web.id, mapper.id())
            .await
            .expect("read"),
        mapper
    );
    let replaced = world
        .mappers
        .replace(
            &tenant,
            web.id,
            mapper.id(),
            mapping(
                "login",
                &[ClaimTarget::IdToken],
                ClaimSource::Attribute(PersonAttribute::Username),
            ),
            Caller::system(),
        )
        .await
        .expect("replaced");
    assert_eq!(replaced.settings().claim, "login");
    assert_eq!(
        world
            .mappers
            .mapper(&tenant, web.id, mapper.id())
            .await
            .expect("read"),
        replaced,
        "what is answered is what is stored"
    );
    world
        .mappers
        .replace(
            &tenant,
            web.id,
            mapper.id(),
            mapping(
                "login",
                &[ClaimTarget::IdToken, ClaimTarget::UserInfo],
                ClaimSource::Attribute(PersonAttribute::Username),
            ),
            Caller::system(),
        )
        .await
        .expect("replaced twice");

    // Another tenant sees nothing, and changes nothing.
    let other = TenantContext::assume(TenantId::generate());
    for refused in [
        world
            .mappers
            .mappers(&other, web.id)
            .await
            .expect_err("refused"),
        world
            .mappers
            .mapper(&other, web.id, mapper.id())
            .await
            .expect_err("refused"),
        world
            .mappers
            .delete(&other, web.id, mapper.id(), Caller::system())
            .await
            .expect_err("refused"),
    ] {
        assert_eq!(refused.code(), "oauth.client_not_found");
    }

    world
        .mappers
        .delete(&tenant, web.id, mapper.id(), Caller::system())
        .await
        .expect("deleted");
    assert_eq!(
        world
            .mappers
            .delete(&tenant, web.id, mapper.id(), Caller::system())
            .await
            .expect_err("gone")
            .code(),
        "oauth.claim_mapper_not_found"
    );
    let events: Vec<String> = world
        .units
        .committed_event_types()
        .into_iter()
        .filter(|event| event.starts_with("oauth.claim_mapper"))
        .collect();
    assert_eq!(
        events,
        [
            "oauth.claim_mapper_created",
            "oauth.claim_mapper_changed",
            "oauth.claim_mapper_changed",
            "oauth.claim_mapper_deleted",
        ]
    );
}

#[tokio::test]
async fn a_mapper_puts_a_group_into_the_id_token_and_each_source_is_read_at_issue() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    let web = web_client(&world, &tenant, application).await;
    let finance = GroupId::generate();
    let acme = OrganizationId::generate();
    let id = [ClaimTarget::IdToken];
    let access_token = [ClaimTarget::AccessToken];
    let both = [ClaimTarget::IdToken, ClaimTarget::AccessToken];
    for settings in [
        mapping("in_finance", &both, ClaimSource::GroupMember(finance)),
        mapping("teams", &access_token, ClaimSource::Groups),
        mapping(
            "full_name",
            &id,
            ClaimSource::Attribute(PersonAttribute::DisplayName),
        ),
        mapping("mail", &id, ClaimSource::Attribute(PersonAttribute::Email)),
        mapping(
            "company",
            &id,
            ClaimSource::Organization(OrganizationAttribute::Name),
        ),
        mapping(
            "plan",
            &access_token,
            ClaimSource::Constant(json!({"tier": "gold"})),
        ),
        ClaimMapperSettings {
            scope: Some("profile".to_owned()),
            ..mapping(
                "login",
                &id,
                ClaimSource::Attribute(PersonAttribute::Username),
            )
        },
    ] {
        add(&world, &tenant, web.id, settings)
            .await
            .expect("created");
    }
    let ana = person(&world);
    world.memberships.set_groups(ana.user_id, vec![finance]);
    world.memberships.join(ana.user_id, acme);
    world
        .sources
        .name_organization(tenant.tenant_id(), acme, "Acme Brasil");
    world.sources.set_attributes(
        tenant.tenant_id(),
        ana.user_id,
        PersonAttributes {
            display_name: Some("Ana Silva".to_owned()),
            username: Some("ana".to_owned()),
            email: None,
            locale: None,
        },
    );
    let organization = acme.to_string();
    let tokens = signed_in(
        &world,
        &tenant,
        &web,
        "openid read",
        &[("organization", organization.as_str())],
        &ana,
    )
    .await;
    let claims = id_token(&tokens);
    assert_eq!(claims["in_finance"], true, "the group, in the ID token");
    assert!(claims.get("teams").is_none(), "only in the access token");
    assert_eq!(claims["full_name"], "Ana Silva");
    assert_eq!(claims["company"], "Acme Brasil");
    assert!(claims.get("mail").is_none(), "Ana has no address");
    assert!(claims.get("login").is_none(), "its scope was not asked for");
    assert!(claims.get("plan").is_none(), "only in the access token");
    assert_eq!(
        claims["sub"],
        ana.user_id.to_string(),
        "Hodor's own claims stay"
    );
    assert_eq!(claims["org_id"], organization);
    let token = access(&tokens);
    assert_eq!(token["in_finance"], true);
    assert_eq!(token["plan"], json!({"tier": "gold"}));
    assert_eq!(token["teams"], json!([finance.to_string()]));
    assert!(token.get("company").is_none(), "only in the ID token");

    // Taken out of the group, Ana loses it from the next token.
    world.memberships.set_groups(ana.user_id, Vec::new());
    let refresh_token = tokens
        .refresh_token
        .expect("a refresh token")
        .expose()
        .clone();
    let refreshed = ask(
        &world,
        &tenant,
        &web,
        vec![
            ("grant_type".to_owned(), "refresh_token".to_owned()),
            ("refresh_token".to_owned(), refresh_token),
        ],
    )
    .await;
    assert_eq!(access(&refreshed)["in_finance"], false);
    assert_eq!(access(&refreshed)["teams"], json!([]));
    assert_eq!(access(&refreshed)["plan"], json!({"tier": "gold"}));

    // With a mapper of its scope asked for, the username is written.
    let tokens = signed_in(&world, &tenant, &web, "openid profile", &[], &ana).await;
    assert_eq!(id_token(&tokens)["login"], "ana");
    assert!(
        id_token(&tokens).get("company").is_none(),
        "no organization this time"
    );
}

#[tokio::test]
async fn client_credentials_carry_no_mapped_claim() {
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
    add(
        &world,
        &tenant,
        service.id,
        mapping(
            "plan",
            &[ClaimTarget::AccessToken],
            ClaimSource::Constant(json!("gold")),
        ),
    )
    .await
    .expect("created");
    let tokens = ask(
        &world,
        &tenant,
        &service,
        vec![("grant_type".to_owned(), "client_credentials".to_owned())],
    )
    .await;
    assert!(access(&tokens).get("plan").is_none(), "nobody signed in");
}

#[tokio::test]
async fn a_mapper_reads_only_its_own_tenant() {
    let world = world();
    let (tenant, application) = tenant(&world).await;
    let web = web_client(&world, &tenant, application).await;
    add(
        &world,
        &tenant,
        web.id,
        mapping(
            "full_name",
            &[ClaimTarget::IdToken],
            ClaimSource::Attribute(PersonAttribute::DisplayName),
        ),
    )
    .await
    .expect("created");
    let ana = person(&world);
    // The same user identifier has a name in another tenant only.
    world.sources.set_attributes(
        TenantId::generate(),
        ana.user_id,
        PersonAttributes {
            display_name: Some("Someone else".to_owned()),
            ..PersonAttributes::default()
        },
    );
    let tokens = signed_in(&world, &tenant, &web, "openid", &[], &ana).await;
    assert!(id_token(&tokens).get("full_name").is_none());
}
