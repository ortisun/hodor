//! Back-channel logout on the in-memory stores: the address a client is
//! given, the deliveries a session that ended makes, and the logout tokens
//! the worker's use case signs and sends.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Actor, Caller, Clock as _, CorrelationId, DestinationCheck, DomainError, EventEnvelope,
    EventHandler, EventMetadata, TenantContext, TenantId, Timestamp, UnitOfWorkFactory, UserId,
};
use hodor_keys::api::KeyService;
use hodor_keys::testing::{FakeKeyProvider, InMemoryKeys};
use hodor_oauth::api::{
    ApplicationPorts, ApplicationService, ApplicationSettings, BackChannelLogoutFanOut,
    BackChannelLogoutSender, Client, ClientSettings, ClientType, CreateClient, Grant, GrantId,
    GrantStatus, GrantStore, IdTokenAlgorithm, LogoutDeliverySettings, LogoutDeliveryStatus,
    LogoutOutcome, LogoutRetryPolicy, LogoutSenderPorts, Status,
};
use hodor_oauth::testing::{
    ClientAnswer, DistinctRandom, FakeDestinations, FixedIssuer, InMemoryGrants,
    InMemoryLogoutDeliveries, InMemorySessionClients, InMemoryStores, LogoutDeliveryStorePorts,
    RecordingClients, run_logout_delivery_contract,
};
use hodor_session::api::SessionId;
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use time::Duration;

struct World {
    units: InMemoryUnitOfWorkFactory,
    stores: InMemoryStores,
    grants: InMemoryGrants,
    deliveries: InMemoryLogoutDeliveries,
    applications: ApplicationService,
    fan_out: BackChannelLogoutFanOut,
    clients: RecordingClients,
    clock: Arc<FixedClock>,
    keys: KeyService,
}

fn world() -> World {
    let units = InMemoryUnitOfWorkFactory::default();
    let stores = InMemoryStores::default();
    let grants = InMemoryGrants::new(&stores.clients);
    let deliveries = InMemoryLogoutDeliveries::new(&stores.clients);
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + Duration::days(20_000),
    ));
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(units.clone()),
        applications: Arc::new(stores.applications.clone()),
        clients: Arc::new(stores.clients.clone()),
        resource_servers: Arc::new(stores.resource_servers.clone()),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    })
    .with_destinations(Arc::new(FakeDestinations));
    let fan_out = BackChannelLogoutFanOut::new(
        Arc::new(InMemorySessionClients::new(&grants)),
        Arc::new(stores.clients.clone()),
        Arc::new(stores.applications.clone()),
        Arc::new(deliveries.clone()),
        clock.clone(),
    );
    let keys = KeyService::new(
        Arc::new(units.clone()),
        Arc::new(InMemoryKeys::default()),
        Arc::new(FakeKeyProvider),
        clock.clone(),
    );
    World {
        units,
        stores,
        grants,
        deliveries,
        applications,
        fan_out,
        clients: RecordingClients::default(),
        clock,
        keys,
    }
}

impl World {
    fn sender(&self, settings: LogoutDeliverySettings) -> BackChannelLogoutSender {
        BackChannelLogoutSender::new(
            LogoutSenderPorts {
                units_of_work: Arc::new(self.units.clone()),
                clients: Arc::new(self.stores.clients.clone()),
                deliveries: Arc::new(self.deliveries.clone()),
                due: Arc::new(self.deliveries.clone()),
                issuers: Arc::new(FixedIssuer),
                keys: self.keys.clone(),
                http: Arc::new(self.clients.clone()),
                random: Arc::new(DistinctRandom),
                clock: self.clock.clone(),
            },
            settings,
        )
    }

    async fn application(&self, tenant: &TenantContext) -> hodor_oauth::api::ApplicationId {
        self.applications
            .create_application(
                tenant,
                ApplicationSettings {
                    name: "Payroll".to_owned(),
                    first_party: true,
                },
                Caller::system(),
            )
            .await
            .expect("application")
            .id()
    }

    async fn client(
        &self,
        tenant: &TenantContext,
        application: hodor_oauth::api::ApplicationId,
        address: Option<&str>,
    ) -> Client {
        let mut settings = ClientSettings::new(
            "Payroll web",
            ClientType::Confidential,
            vec![hodor_oauth::api::GrantType::AuthorizationCode],
            vec!["https://payroll.example.com/callback".to_owned()],
        );
        settings.backchannel_logout_uri = address.map(str::to_owned);
        self.applications
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
            .expect("client")
            .0
    }

    /// A code was issued to `client` in `session` for these scopes.
    async fn signed_in(
        &self,
        tenant: &TenantContext,
        client: &Client,
        user: UserId,
        session: SessionId,
        scopes: &[&str],
    ) {
        let mut uow = self.units.begin(tenant).await.expect("begin");
        self.grants
            .insert(
                uow.as_mut(),
                &Grant {
                    id: GrantId::generate(),
                    client_id: client.id(),
                    user_id: user,
                    session_id: session,
                    scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
                    audiences: Vec::new(),
                    organization: None,
                    status: GrantStatus::Active,
                    created_at: self.clock.now(),
                    revoked_at: None,
                    revocation_reason: None,
                },
            )
            .await
            .expect("grant");
        uow.commit().await.expect("commit");
    }

    /// The outbox hands `session.revoked` to the handler, in the event's
    /// tenant.
    async fn session_ended(
        &self,
        tenant: &TenantContext,
        user: UserId,
        session: SessionId,
    ) -> Result<(), DomainError> {
        let event = revoked(tenant.tenant_id(), user, session);
        let mut uow = self.units.begin(tenant).await.expect("begin");
        self.fan_out.handle(uow.as_mut(), &event).await?;
        uow.commit().await.expect("commit");
        Ok(())
    }
}

fn revoked(tenant: TenantId, user: UserId, session: SessionId) -> EventEnvelope {
    EventEnvelope {
        metadata: EventMetadata::new(
            tenant,
            Actor::User(user),
            CorrelationId::generate(),
            &FixedClock::at(Timestamp::UNIX_EPOCH),
        ),
        event_type: "session.revoked".to_owned(),
        payload: json!({
            "session_id": session.to_string(),
            "user_id": user.to_string(),
            "reason": "sign_out",
        }),
    }
}

fn a_tenant() -> TenantContext {
    TenantContext::assume(TenantId::generate())
}

/// The header and the claims of a compact token.
fn parts(token: &str) -> (Value, Value) {
    let mut pieces = token.split('.');
    let mut json = || {
        serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(pieces.next().expect("part"))
                .expect("base64url"),
        )
        .expect("JSON")
    };
    (json(), json())
}

#[tokio::test]
async fn the_store_contract_holds_in_memory() {
    let stores = InMemoryStores::default();
    let grants = InMemoryGrants::new(&stores.clients);
    let deliveries = InMemoryLogoutDeliveries::new(&stores.clients);
    let units = InMemoryUnitOfWorkFactory::default();
    run_logout_delivery_contract(LogoutDeliveryStorePorts {
        units_of_work: &units,
        applications: &stores.applications,
        clients: &stores.clients,
        grants: &grants,
        sessions: &InMemorySessionClients::new(&grants),
        deliveries: &deliveries,
        due: &deliveries,
    })
    .await;
}

#[tokio::test]
async fn every_client_signed_in_to_with_the_session_and_only_those_gets_one_delivery() {
    let world = world();
    let tenant = a_tenant();
    let application = world.application(&tenant).await;
    let payroll = world
        .client(
            &tenant,
            application,
            Some("https://payroll.example.com/logout"),
        )
        .await;
    let billing = world
        .client(
            &tenant,
            application,
            Some("https://billing.example.com/logout"),
        )
        .await;
    let without_address = world.client(&tenant, application, None).await;
    let disabled = world
        .client(&tenant, application, Some("https://old.example.com/logout"))
        .await;
    world
        .applications
        .set_client_status(&tenant, disabled.id(), Status::Disabled, Caller::system())
        .await
        .expect("disabled");
    let not_openid = world
        .client(&tenant, application, Some("https://api.example.com/logout"))
        .await;
    let elsewhere = world
        .client(
            &tenant,
            application,
            Some("https://other.example.com/logout"),
        )
        .await;

    let (ana, session) = (UserId::generate(), SessionId::generate());
    for client in [&payroll, &billing, &without_address, &disabled] {
        world
            .signed_in(&tenant, client, ana, session, &["openid", "email"])
            .await;
    }
    world
        .signed_in(&tenant, &payroll, ana, session, &["openid"])
        .await;
    world
        .signed_in(&tenant, &not_openid, ana, session, &["invoices:read"])
        .await;
    world
        .signed_in(&tenant, &elsewhere, ana, SessionId::generate(), &["openid"])
        .await;

    world
        .session_ended(&tenant, ana, session)
        .await
        .expect("handled");
    // Handled again, as after a failure: nothing is made twice.
    world
        .session_ended(&tenant, ana, session)
        .await
        .expect("handled");

    let mut made: Vec<_> = world
        .deliveries
        .all(tenant.tenant_id())
        .into_iter()
        .map(|delivery| {
            let state = delivery.snapshot().clone();
            assert_eq!(state.session_id, session);
            assert_eq!(state.user_id, ana);
            assert_eq!(state.status, LogoutDeliveryStatus::Pending);
            state.client_id
        })
        .collect();
    made.sort();
    let mut expected = vec![payroll.id(), billing.id()];
    expected.sort();
    assert_eq!(made, expected);
}

#[tokio::test]
async fn a_disabled_application_and_an_event_of_another_tenant_make_nothing() {
    let world = world();
    let tenant = a_tenant();
    let application = world.application(&tenant).await;
    let client = world
        .client(
            &tenant,
            application,
            Some("https://payroll.example.com/logout"),
        )
        .await;
    world
        .applications
        .set_application_status(&tenant, application, Status::Disabled, Caller::system())
        .await
        .expect("disabled");
    let (ana, session) = (UserId::generate(), SessionId::generate());
    world
        .signed_in(&tenant, &client, ana, session, &["openid"])
        .await;
    world
        .session_ended(&tenant, ana, session)
        .await
        .expect("handled");
    assert!(world.deliveries.all(tenant.tenant_id()).is_empty());

    let other = a_tenant();
    let event = revoked(other.tenant_id(), ana, session);
    let mut uow = world.units.begin(&tenant).await.expect("begin");
    assert_eq!(
        world
            .fan_out
            .handle(uow.as_mut(), &event)
            .await
            .expect_err("another tenant's event")
            .code(),
        "oauth.tenant_mismatch"
    );
    assert!(world.fan_out.handles("session.revoked"));
    assert!(!world.fan_out.handles("session.started"));
}

#[tokio::test]
async fn the_logout_token_is_signed_with_the_clients_algorithm_and_names_the_session() {
    let world = world();
    let tenant = a_tenant();
    let application = world.application(&tenant).await;
    let address = "https://payroll.example.com/logout";
    let client = world.client(&tenant, application, Some(address)).await;
    let mut settings = client.snapshot().settings.clone();
    settings.id_token_algorithm = IdTokenAlgorithm::Rs256;
    world
        .applications
        .change_client(&tenant, client.id(), settings, Caller::system())
        .await
        .expect("changed");
    let (ana, session) = (UserId::generate(), SessionId::generate());
    world
        .signed_in(&tenant, &client, ana, session, &["openid"])
        .await;
    world
        .session_ended(&tenant, ana, session)
        .await
        .expect("handled");

    let sender = world.sender(LogoutDeliverySettings::default());
    let leases = sender.lease_due(10).await.expect("leased");
    assert_eq!(leases.len(), 1);
    assert_eq!(leases[0].client(), client.id());
    assert!(
        sender.lease_due(10).await.expect("leased").is_empty(),
        "a leased delivery is not leased twice"
    );
    let outcome = sender
        .send(leases.into_iter().next().expect("lease"))
        .await
        .expect("sent");
    assert_eq!(outcome, LogoutOutcome::Delivered);

    let requests = world.clients.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url, address);
    assert_eq!(
        requests[0].headers,
        [(
            "content-type".to_owned(),
            "application/x-www-form-urlencoded".to_owned()
        )],
        "a form, and no cookie"
    );
    assert!(requests[0].time_limit.is_some());
    let tokens = world.clients.tokens_to(address);
    let (header, claims) = parts(&tokens[0]);
    assert_eq!(header["typ"], "logout+jwt");
    assert_eq!(header["alg"], "RS256");
    assert!(header["kid"].is_string());
    assert_eq!(claims["iss"], FixedIssuer::of(&tenant));
    assert_eq!(claims["aud"], client.id().to_string());
    assert_eq!(claims["sub"], ana.to_string());
    assert_eq!(claims["sid"], session.to_string());
    assert_eq!(
        claims["events"],
        json!({ "http://schemas.openid.net/event/backchannel-logout": {} })
    );
    assert_eq!(
        claims["exp"].as_i64().expect("exp") - claims["iat"].as_i64().expect("iat"),
        120
    );
    assert!(claims.get("nonce").is_none());
    let delivered = world.deliveries.all(tenant.tenant_id());
    assert_eq!(delivered[0].status(), LogoutDeliveryStatus::Delivered);
    assert_eq!(delivered[0].snapshot().last_response_status, Some(200));
}

#[tokio::test]
async fn a_client_that_refuses_is_tried_again_later_with_a_new_token_then_set_aside() {
    let world = world();
    let tenant = a_tenant();
    let application = world.application(&tenant).await;
    let address = "https://payroll.example.com/logout";
    let client = world.client(&tenant, application, Some(address)).await;
    let (ana, session) = (UserId::generate(), SessionId::generate());
    world
        .signed_in(&tenant, &client, ana, session, &["openid"])
        .await;
    world
        .session_ended(&tenant, ana, session)
        .await
        .expect("handled");
    world.clients.answer(address, ClientAnswer::Status(400));
    let sender = world.sender(LogoutDeliverySettings {
        retry: LogoutRetryPolicy::new(3, Duration::seconds(30)).expect("policy"),
        ..LogoutDeliverySettings::default()
    });

    let mut outcomes = Vec::new();
    // The first attempt at once, the second 30 seconds later, the third 60
    // seconds after that; nothing in between.
    for wait in [0, 30, 60] {
        if wait > 0 {
            world.clock.advance(Duration::seconds(wait - 1));
            assert!(
                sender.lease_due(10).await.expect("not yet").is_empty(),
                "not due a second before {wait} seconds"
            );
            world.clock.advance(Duration::seconds(1));
        }
        let leases = sender.lease_due(10).await.expect("due");
        assert_eq!(leases.len(), 1, "due after {wait} seconds");
        for lease in leases {
            outcomes.push(sender.send(lease).await.expect("recorded"));
        }
    }
    assert_eq!(
        outcomes,
        [
            LogoutOutcome::Retrying,
            LogoutOutcome::Retrying,
            LogoutOutcome::SetAside
        ]
    );
    let tokens = world.clients.tokens_to(address);
    assert_eq!(tokens.len(), 3);
    let token_ids: Vec<Value> = tokens
        .iter()
        .map(|token| parts(token).1["jti"].clone())
        .collect();
    assert_ne!(token_ids[0], token_ids[1], "each attempt is signed anew");
    let set_aside = &world.deliveries.all(tenant.tenant_id())[0];
    assert_eq!(set_aside.status(), LogoutDeliveryStatus::SetAside);
    assert_eq!(set_aside.snapshot().attempts, 3);
    assert_eq!(
        set_aside.snapshot().last_error.as_deref(),
        Some("the client answered 400")
    );
    assert!(
        world
            .units
            .committed_event_types()
            .contains(&"oauth.backchannel_logout_set_aside".to_owned())
    );
    world.clock.advance(Duration::days(1));
    assert!(sender.lease_due(10).await.expect("nothing").is_empty());
}

#[tokio::test]
async fn a_client_that_lost_its_address_is_set_aside_without_a_request() {
    let world = world();
    let tenant = a_tenant();
    let application = world.application(&tenant).await;
    let client = world
        .client(
            &tenant,
            application,
            Some("https://payroll.example.com/logout"),
        )
        .await;
    let (ana, session) = (UserId::generate(), SessionId::generate());
    world
        .signed_in(&tenant, &client, ana, session, &["openid"])
        .await;
    world
        .session_ended(&tenant, ana, session)
        .await
        .expect("handled");
    let mut settings = client.snapshot().settings.clone();
    settings.backchannel_logout_uri = None;
    world
        .applications
        .change_client(&tenant, client.id(), settings, Caller::system())
        .await
        .expect("changed");

    let sender = world.sender(LogoutDeliverySettings::default());
    assert!(sender.lease_due(10).await.expect("none").is_empty());
    assert!(world.clients.requests().is_empty());
    let delivery = &world.deliveries.all(tenant.tenant_id())[0];
    assert_eq!(delivery.status(), LogoutDeliveryStatus::SetAside);
    assert_eq!(delivery.snapshot().attempts, 0);
    assert!(
        world
            .units
            .committed_event_types()
            .contains(&"oauth.backchannel_logout_set_aside".to_owned())
    );
}

#[tokio::test]
async fn a_client_never_has_more_in_flight_than_it_may_and_a_failure_is_an_attempt() {
    let world = world();
    let tenant = a_tenant();
    let application = world.application(&tenant).await;
    let address = "https://payroll.example.com/logout";
    let client = world.client(&tenant, application, Some(address)).await;
    let other = world
        .client(
            &tenant,
            application,
            Some("https://billing.example.com/logout"),
        )
        .await;
    let ana = UserId::generate();
    for _ in 0..3 {
        let session = SessionId::generate();
        world
            .signed_in(&tenant, &client, ana, session, &["openid"])
            .await;
        world
            .signed_in(&tenant, &other, ana, session, &["openid"])
            .await;
        world
            .session_ended(&tenant, ana, session)
            .await
            .expect("handled");
    }
    let sender = world.sender(LogoutDeliverySettings {
        in_flight_per_client: 2,
        ..LogoutDeliverySettings::default()
    });
    let leases = sender.lease_due(10).await.expect("leased");
    let to_client = leases
        .iter()
        .filter(|lease| lease.client() == client.id())
        .count();
    assert_eq!(to_client, 2, "two in flight, the third waits");
    assert_eq!(leases.len(), 4);

    world
        .clients
        .answer(address, ClientAnswer::Failure("http.timed_out"));
    for lease in leases {
        sender.send(lease).await.expect("recorded");
    }
    let failed: Vec<_> = world
        .deliveries
        .all(tenant.tenant_id())
        .into_iter()
        .filter(|delivery| {
            delivery.snapshot().client_id == client.id() && delivery.snapshot().attempts == 1
        })
        .collect();
    assert_eq!(failed.len(), 2);
    assert!(
        failed[0]
            .snapshot()
            .last_error
            .as_deref()
            .is_some_and(|reason| reason.starts_with("http.timed_out"))
    );
    assert_eq!(failed[0].snapshot().last_response_status, None);
}

/// A destination check that counts how often it is asked.
#[derive(Default)]
struct Counted(AtomicUsize);

#[async_trait::async_trait]
impl DestinationCheck for Counted {
    async fn check(&self, url: &str) -> Result<(), DomainError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        FakeDestinations.check(url).await
    }
}

#[tokio::test]
async fn an_address_is_checked_when_it_is_set_and_only_then() {
    let world = world();
    let tenant = a_tenant();
    let application = world.application(&tenant).await;
    for (address, code) in [
        (
            "https://localhost/logout",
            "oauth.client_backchannel_logout_uri_forbidden",
        ),
        (
            "https://169.254.169.254/latest",
            "oauth.client_backchannel_logout_uri_forbidden",
        ),
        (
            "https://nowhere.example/logout",
            "oauth.client_backchannel_logout_uri_unresolvable",
        ),
        (
            "http://payroll.example.com/logout",
            "oauth.client_backchannel_logout_uri_invalid",
        ),
        (
            "https://payroll.example.com/logout#here",
            "oauth.client_backchannel_logout_uri_invalid",
        ),
    ] {
        let mut settings = ClientSettings::new(
            "Payroll web",
            ClientType::Confidential,
            vec![hodor_oauth::api::GrantType::AuthorizationCode],
            vec!["https://payroll.example.com/callback".to_owned()],
        );
        settings.backchannel_logout_uri = Some(address.to_owned());
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
            .expect_err(address);
        assert_eq!(error.code(), code, "{address}");
    }

    let counted = Arc::new(Counted::default());
    let service = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(world.units.clone()),
        applications: Arc::new(world.stores.applications.clone()),
        clients: Arc::new(world.stores.clients.clone()),
        resource_servers: Arc::new(world.stores.resource_servers.clone()),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: world.clock.clone(),
    });
    let client = world
        .client(
            &tenant,
            application,
            Some("https://payroll.example.com/logout"),
        )
        .await;
    let mut renamed = client.snapshot().settings.clone();
    renamed.name = "Payroll on the web".to_owned();
    // Without a check, an unchanged address does not stop other changes.
    service
        .change_client(&tenant, client.id(), renamed.clone(), Caller::system())
        .await
        .expect("renamed");
    let mut moved = renamed.clone();
    moved.backchannel_logout_uri = Some("https://payroll.example.com/new-logout".to_owned());
    assert_eq!(
        service
            .change_client(&tenant, client.id(), moved.clone(), Caller::system())
            .await
            .expect_err("no check")
            .code(),
        "oauth.client_backchannel_logout_uri_forbidden",
        "an installation that cannot check an address accepts none"
    );
    let checking = service.with_destinations(counted.clone());
    let mut again = renamed.clone();
    again.name = "Payroll".to_owned();
    checking
        .change_client(&tenant, client.id(), again, Caller::system())
        .await
        .expect("renamed");
    assert_eq!(counted.0.load(Ordering::SeqCst), 0);
    let changed = checking
        .change_client(&tenant, client.id(), moved, Caller::system())
        .await
        .expect("moved");
    assert_eq!(counted.0.load(Ordering::SeqCst), 1);
    assert_eq!(
        changed.backchannel_logout_uri(),
        Some("https://payroll.example.com/new-logout")
    );
}
