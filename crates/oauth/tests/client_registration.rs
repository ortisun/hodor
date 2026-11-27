//! Client registration: the settings an administrator sets, initial
//! access tokens, and the admission the registration endpoint asks for,
//! on the in-memory stores.

use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, ErrorKind, TenantContext, TenantId, Timestamp, UnitOfWorkFactory as _};
use hodor_oauth::api::{
    AllowedBy, ApplicationId, ApplicationPorts, ApplicationService, ApplicationSettings,
    ClientRegistrationPorts, ClientRegistrationService, GrantType, InitialAccessTokenStatus,
    NewInitialAccessToken, RegistrationPolicy, RegistrationSettings, RegistrationWay,
};
use hodor_oauth::testing::{
    ClientRegistrationStorePorts, DistinctRandom, InMemoryClientRegistrations,
    InMemoryInitialAccessTokens, InMemoryStores, run_client_registration_contract,
};
use std::sync::Arc;
use time::Duration;

struct World {
    units: InMemoryUnitOfWorkFactory,
    clock: Arc<FixedClock>,
    applications: ApplicationService,
    registration: ClientRegistrationService,
}

fn world() -> World {
    let units = InMemoryUnitOfWorkFactory::default();
    let stores = InMemoryStores::default();
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + Duration::days(20_000),
    ));
    let registration = ClientRegistrationService::new(ClientRegistrationPorts {
        units_of_work: Arc::new(units.clone()),
        registrations: Arc::new(InMemoryClientRegistrations::new(&stores.applications)),
        tokens: Arc::new(InMemoryInitialAccessTokens::default()),
        applications: Arc::new(stores.applications.clone()),
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
        clock,
        applications,
        registration,
    }
}

fn tenant() -> TenantContext {
    TenantContext::assume(TenantId::generate())
}

impl World {
    async fn application(&self, tenant: &TenantContext, first_party: bool) -> ApplicationId {
        self.applications
            .create_application(
                tenant,
                ApplicationSettings {
                    name: "Partners".to_owned(),
                    first_party,
                },
                Caller::system(),
            )
            .await
            .expect("application")
            .id()
    }

    /// Turns registration on in `tenant` with `ways`, and answers the
    /// application of registered clients.
    async fn turned_on(&self, tenant: &TenantContext, ways: &[RegistrationWay]) -> ApplicationId {
        let application = self.application(tenant, false).await;
        self.registration
            .replace(
                tenant,
                RegistrationSettings {
                    enabled: true,
                    application_id: Some(application),
                    ways: ways.to_vec(),
                    ..RegistrationSettings::default()
                },
                Caller::system(),
            )
            .await
            .expect("on");
        application
    }

    async fn set(&self, tenant: &TenantContext, settings: RegistrationSettings) {
        self.registration
            .replace(tenant, settings, Caller::system())
            .await
            .expect("set");
    }

    async fn token(&self, tenant: &TenantContext, max_registrations: u32) -> (String, String) {
        let (token, value) = self
            .registration
            .issue_token(
                tenant,
                NewInitialAccessToken {
                    name: "Partner portal team".to_owned(),
                    lifetime: Duration::days(7),
                    max_registrations,
                },
                Caller::system(),
            )
            .await
            .expect("token");
        (token.id().to_string(), value.expose().to_owned())
    }

    /// Asks for a registration in `tenant` with `presented`, and commits
    /// what it spent.
    async fn admit(
        &self,
        tenant: &TenantContext,
        presented: Option<&str>,
    ) -> Result<AllowedBy, hodor_kernel::DomainError> {
        let mut uow = self.units.begin(tenant).await.expect("begin");
        let admission = self
            .registration
            .admit(uow.as_mut(), presented, Caller::system())
            .await?;
        uow.commit().await.expect("commit");
        Ok(admission.allowed_by)
    }
}

#[tokio::test]
async fn the_in_memory_stores_pass_the_contract() {
    let units = InMemoryUnitOfWorkFactory::default();
    let stores = InMemoryStores::default();
    run_client_registration_contract(ClientRegistrationStorePorts {
        units_of_work: &units,
        applications: &stores.applications,
        registrations: &InMemoryClientRegistrations::new(&stores.applications),
        tokens: &InMemoryInitialAccessTokens::default(),
    })
    .await;
}

#[tokio::test]
async fn a_tenant_that_never_turned_it_on_has_registration_off_and_nothing_reachable() {
    let world = world();
    let acme = tenant();
    let read = world.registration.settings(&acme).await.expect("read");
    assert!(!read.settings.enabled);
    assert_eq!(read.updated_at, None);
    assert_eq!(read.settings, RegistrationSettings::default());

    // No token can be made, and nobody is admitted, with a token or
    // without.
    let error = world
        .registration
        .issue_token(
            &acme,
            NewInitialAccessToken {
                name: "Too early".to_owned(),
                lifetime: Duration::days(1),
                max_registrations: 1,
            },
            Caller::system(),
        )
        .await
        .expect_err("off");
    assert_eq!(error.code(), "oauth.client_registration_off");
    for presented in [
        None,
        Some("hodor_iat_0000000000000000000000000000000000000000000000000000000000000000"),
    ] {
        let error = world.admit(&acme, presented).await.expect_err("off");
        assert_eq!(error.code(), "oauth.client_registration_off");
        assert_eq!(error.kind(), ErrorKind::NotFound, "answered as no address");
    }
    assert!(world.units.committed_events().is_empty());
}

#[tokio::test]
async fn registration_is_turned_on_with_a_third_party_application_of_the_tenant() {
    let world = world();
    let acme = tenant();
    let globex = tenant();
    let first_party = world.application(&acme, true).await;
    let theirs = world.application(&globex, false).await;
    for (application, detail) in [
        (None, "names no application"),
        (Some(first_party), "first party"),
        (Some(theirs), "no such application"),
        (Some(ApplicationId::generate()), "no such application"),
    ] {
        let error = world
            .registration
            .replace(
                &acme,
                RegistrationSettings {
                    enabled: true,
                    application_id: application,
                    ..RegistrationSettings::default()
                },
                Caller::system(),
            )
            .await
            .expect_err("refused");
        assert_eq!(
            error.code(),
            "oauth.client_registration_application_invalid"
        );
        assert!(
            error.detail().unwrap_or_default().contains(detail),
            "{error:?}"
        );
    }
    assert!(
        !world
            .registration
            .settings(&acme)
            .await
            .expect("read")
            .settings
            .enabled
    );

    let application = world
        .turned_on(&acme, &[RegistrationWay::InitialAccessToken])
        .await;
    let read = world.registration.settings(&acme).await.expect("read");
    assert!(read.settings.enabled);
    assert_eq!(read.settings.application_id, Some(application));
    assert_eq!(read.updated_at, Some(world.clock_now()));
    assert_eq!(
        world
            .units
            .committed_event_types()
            .last()
            .map(String::as_str),
        Some("oauth.client_registration_changed")
    );
    // Globex is as it was.
    assert!(
        !world
            .registration
            .settings(&globex)
            .await
            .expect("read")
            .settings
            .enabled
    );
}

impl World {
    fn clock_now(&self) -> Timestamp {
        use hodor_kernel::Clock as _;
        self.clock.now()
    }
}

#[tokio::test]
async fn settings_are_replaced_as_a_whole_and_an_unchanged_replace_records_nothing() {
    let world = world();
    let acme = tenant();
    let application = world
        .turned_on(&acme, &[RegistrationWay::InitialAccessToken])
        .await;
    let recorded = world.units.committed_events().len();
    let settings = world
        .registration
        .settings(&acme)
        .await
        .expect("read")
        .settings;
    world.set(&acme, settings.clone()).await;
    assert_eq!(world.units.committed_events().len(), recorded);

    let policy = RegistrationPolicy {
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        scopes: vec!["openid".to_owned(), "offline_access".to_owned()],
        hosts: Some(vec!["app.example.com".to_owned()]),
        ..RegistrationPolicy::default()
    };
    world.clock.advance(Duration::hours(1));
    world
        .set(
            &acme,
            RegistrationSettings {
                ways: vec![RegistrationWay::Open],
                max_clients: 1000,
                policy: policy.clone(),
                ..settings
            },
        )
        .await;
    let read = world.registration.settings(&acme).await.expect("read");
    assert_eq!(read.settings.ways, [RegistrationWay::Open]);
    assert_eq!(read.settings.max_clients, 1000);
    assert_eq!(read.settings.policy, policy);
    assert_eq!(read.settings.application_id, Some(application));
    assert_eq!(read.updated_at, Some(world.clock_now()));
    let event = world.units.committed_events().pop().expect("event");
    assert_eq!(event.event_type, "oauth.client_registration_changed");
    assert_eq!(event.payload["enabled"], true);
    assert_eq!(event.payload["ways"], serde_json::json!(["open"]));
    assert_eq!(
        event.payload["policy"]["hosts"],
        serde_json::json!(["app.example.com"])
    );

    // A policy that breaks a rule changes nothing.
    let error = world
        .registration
        .replace(
            &acme,
            RegistrationSettings {
                policy: RegistrationPolicy {
                    grant_types: vec![GrantType::ClientCredentials],
                    ..RegistrationPolicy::default()
                },
                ..read.settings.clone()
            },
            Caller::system(),
        )
        .await
        .expect_err("refused");
    assert_eq!(error.code(), "oauth.client_registration_policy_invalid");
    assert_eq!(
        world
            .registration
            .settings(&acme)
            .await
            .expect("read")
            .settings,
        read.settings
    );
}

#[tokio::test]
async fn a_token_is_made_only_while_registration_allows_tokens() {
    let world = world();
    let acme = tenant();
    let application = world.turned_on(&acme, &[RegistrationWay::Open]).await;
    let new = || NewInitialAccessToken {
        name: "Partner portal team".to_owned(),
        lifetime: Duration::days(7),
        max_registrations: 1,
    };
    let error = world
        .registration
        .issue_token(&acme, new(), Caller::system())
        .await
        .expect_err("not allowed");
    assert_eq!(error.code(), "oauth.initial_access_tokens_not_allowed");
    assert_eq!(error.kind(), ErrorKind::Conflict);

    world
        .set(
            &acme,
            RegistrationSettings {
                enabled: true,
                application_id: Some(application),
                ways: vec![RegistrationWay::InitialAccessToken],
                ..RegistrationSettings::default()
            },
        )
        .await;
    let (made, value) = world
        .registration
        .issue_token(&acme, new(), Caller::system())
        .await
        .expect("made");
    assert!(value.expose().starts_with("hodor_iat_"));
    assert_eq!(
        made.snapshot().hint,
        value.expose()[value.expose().len() - 4..]
    );
    let event = world.units.committed_events().pop().expect("event");
    assert_eq!(event.event_type, "oauth.initial_access_token_issued");
    assert!(!event.payload.to_string().contains(value.expose()));
    assert_eq!(
        world.registration.tokens(&acme).await.expect("list"),
        std::slice::from_ref(&made)
    );
    assert_eq!(
        world
            .registration
            .token(&acme, made.id())
            .await
            .expect("read"),
        made
    );
}

#[tokio::test]
async fn a_tenant_holds_at_most_a_hundred_active_tokens() {
    let world = world();
    let acme = tenant();
    world
        .turned_on(&acme, &[RegistrationWay::InitialAccessToken])
        .await;
    let mut first = None;
    for _ in 0..100 {
        let (id, _) = world.token(&acme, 1).await;
        first.get_or_insert(id);
    }
    let new = || NewInitialAccessToken {
        name: "One too many".to_owned(),
        lifetime: Duration::days(7),
        max_registrations: 1,
    };
    let error = world
        .registration
        .issue_token(&acme, new(), Caller::system())
        .await
        .expect_err("too many");
    assert_eq!(error.code(), "oauth.too_many_initial_access_tokens");
    // A revoked token no longer counts.
    world
        .registration
        .revoke_token(
            &acme,
            first.expect("one").parse().expect("identifier"),
            Caller::system(),
        )
        .await
        .expect("revoked");
    world
        .registration
        .issue_token(&acme, new(), Caller::system())
        .await
        .expect("room again");
}

#[tokio::test]
async fn a_token_allows_its_registrations_and_is_refused_past_its_count() {
    let world = world();
    let acme = tenant();
    world
        .turned_on(&acme, &[RegistrationWay::InitialAccessToken])
        .await;
    let (id, value) = world.token(&acme, 2).await;
    for _ in 0..2 {
        assert_eq!(
            world.admit(&acme, Some(&value)).await.expect("admitted"),
            AllowedBy::InitialAccessToken(id.parse().expect("identifier"))
        );
    }
    let error = world.admit(&acme, Some(&value)).await.expect_err("used up");
    assert_eq!(error.code(), "oauth.initial_access_token_invalid");
    assert_eq!(error.kind(), ErrorKind::Unauthenticated);
    let token = world
        .registration
        .token(&acme, id.parse().expect("identifier"))
        .await
        .expect("read");
    assert_eq!(token.snapshot().registrations, 2);
    assert_eq!(
        token.status(world.clock_now()),
        InitialAccessTokenStatus::UsedUp
    );
    let used: Vec<_> = world
        .units
        .committed_events()
        .into_iter()
        .filter(|event| event.event_type == "oauth.initial_access_token_used")
        .map(|event| event.payload["registrations"].clone())
        .collect();
    assert_eq!(used, [serde_json::json!(1), serde_json::json!(2)]);
}

#[tokio::test]
async fn a_token_past_its_expiry_or_revoked_is_refused_in_one_way() {
    let world = world();
    let acme = tenant();
    world
        .turned_on(&acme, &[RegistrationWay::InitialAccessToken])
        .await;
    let (_, expiring) = world.token(&acme, 5).await;
    let (revoked_id, revoked) = world.token(&acme, 5).await;
    world
        .registration
        .revoke_token(
            &acme,
            revoked_id.parse().expect("identifier"),
            Caller::system(),
        )
        .await
        .expect("revoked");
    // Revoking again changes nothing and records nothing.
    let recorded = world.units.committed_events().len();
    world
        .registration
        .revoke_token(
            &acme,
            revoked_id.parse().expect("identifier"),
            Caller::system(),
        )
        .await
        .expect("again");
    assert_eq!(world.units.committed_events().len(), recorded);

    world.clock.advance(Duration::days(7));
    for presented in [
        expiring.as_str(),
        revoked.as_str(),
        "hodor_iat_0000000000000000000000000000000000000000000000000000000000000000",
        "hodor_iat_short",
        "hodor_ak_0000000000000000000000000000000000000000000000000000000000000000",
        "",
    ] {
        let error = world
            .admit(&acme, Some(presented))
            .await
            .expect_err("refused");
        assert_eq!(
            error.code(),
            "oauth.initial_access_token_invalid",
            "{presented}"
        );
    }
    let error = world
        .registration
        .revoke_token(
            &acme,
            hodor_oauth::api::InitialAccessTokenId::generate(),
            Caller::system(),
        )
        .await
        .expect_err("unknown");
    assert_eq!(error.code(), "oauth.initial_access_token_not_found");
}

#[tokio::test]
async fn a_token_of_another_tenant_is_unknown_and_not_spent() {
    let world = world();
    let acme = tenant();
    let globex = tenant();
    world
        .turned_on(&acme, &[RegistrationWay::InitialAccessToken])
        .await;
    world
        .turned_on(&globex, &[RegistrationWay::InitialAccessToken])
        .await;
    let (id, value) = world.token(&acme, 1).await;
    let error = world
        .admit(&globex, Some(&value))
        .await
        .expect_err("unknown");
    assert_eq!(error.code(), "oauth.initial_access_token_invalid");
    let id = id.parse().expect("identifier");
    assert_eq!(
        world
            .registration
            .token(&globex, id)
            .await
            .expect_err("not Globex's")
            .code(),
        "oauth.initial_access_token_not_found"
    );
    assert!(
        world
            .registration
            .tokens(&globex)
            .await
            .expect("list")
            .is_empty()
    );
    assert_eq!(
        world
            .registration
            .revoke_token(&globex, id, Caller::system())
            .await
            .expect_err("not Globex's")
            .code(),
        "oauth.initial_access_token_not_found"
    );
    // It still allows its registration where it belongs.
    assert_eq!(
        world.admit(&acme, Some(&value)).await.expect("admitted"),
        AllowedBy::InitialAccessToken(id)
    );
}

#[tokio::test]
async fn while_registration_is_off_a_token_is_refused_unspent_and_works_again_once_on() {
    let world = world();
    let acme = tenant();
    let application = world
        .turned_on(&acme, &[RegistrationWay::InitialAccessToken])
        .await;
    let (id, value) = world.token(&acme, 1).await;
    let on = world
        .registration
        .settings(&acme)
        .await
        .expect("read")
        .settings;
    world
        .set(
            &acme,
            RegistrationSettings {
                enabled: false,
                ..on.clone()
            },
        )
        .await;
    let error = world.admit(&acme, Some(&value)).await.expect_err("off");
    assert_eq!(error.code(), "oauth.client_registration_off");
    let token = world
        .registration
        .token(&acme, id.parse().expect("identifier"))
        .await
        .expect("kept");
    assert_eq!(token.snapshot().registrations, 0, "not spent");

    // Registration on without the way of tokens refuses them too.
    world
        .set(
            &acme,
            RegistrationSettings {
                ways: vec![RegistrationWay::Open],
                ..on.clone()
            },
        )
        .await;
    let error = world.admit(&acme, Some(&value)).await.expect_err("way off");
    assert_eq!(error.code(), "oauth.initial_access_token_invalid");

    world.set(&acme, on).await;
    assert_eq!(
        world.admit(&acme, Some(&value)).await.expect("works again"),
        AllowedBy::InitialAccessToken(id.parse().expect("identifier"))
    );
    assert_eq!(
        world
            .registration
            .settings(&acme)
            .await
            .expect("read")
            .settings
            .application_id,
        Some(application)
    );
}

#[tokio::test]
async fn a_request_without_a_token_is_admitted_only_where_registration_is_open() {
    let world = world();
    let acme = tenant();
    let application = world
        .turned_on(&acme, &[RegistrationWay::InitialAccessToken])
        .await;
    let error = world.admit(&acme, None).await.expect_err("not open");
    assert_eq!(error.code(), "oauth.initial_access_token_required");
    assert_eq!(error.kind(), ErrorKind::Unauthenticated);

    world
        .set(
            &acme,
            RegistrationSettings {
                enabled: true,
                application_id: Some(application),
                ways: vec![RegistrationWay::Open],
                ..RegistrationSettings::default()
            },
        )
        .await;
    assert_eq!(
        world.admit(&acme, None).await.expect("open"),
        AllowedBy::Open
    );
    // A request that carries a token is never taken for an open one.
    let error = world
        .admit(
            &acme,
            Some("hodor_iat_0000000000000000000000000000000000000000000000000000000000000000"),
        )
        .await
        .expect_err("a token, so not open");
    assert_eq!(error.code(), "oauth.initial_access_token_invalid");
}

#[tokio::test]
async fn an_admission_answers_the_policy_the_registration_is_checked_against() {
    let world = world();
    let acme = tenant();
    let application = world.application(&acme, false).await;
    let policy = RegistrationPolicy {
        scopes: vec!["openid".to_owned()],
        ..RegistrationPolicy::default()
    };
    world
        .set(
            &acme,
            RegistrationSettings {
                enabled: true,
                application_id: Some(application),
                ways: vec![RegistrationWay::Open],
                policy: policy.clone(),
                ..RegistrationSettings::default()
            },
        )
        .await;
    let mut uow = world.units.begin(&acme).await.expect("begin");
    let admission = world
        .registration
        .admit(uow.as_mut(), None, Caller::system())
        .await
        .expect("open");
    assert_eq!(admission.settings.policy, policy);
    assert_eq!(admission.settings.application_id, Some(application));
}
