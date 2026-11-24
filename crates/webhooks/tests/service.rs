//! The use cases of the webhooks context, against the in-memory ports.

use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::CountingRandom;
use hodor_kernel::sealing::testing::FakeSecretBox;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Actor, Caller, Clock as _, CorrelationId, EventEnvelope, EventHandler, EventMetadata,
    HttpMethod, PageRequest, TenantContext, TenantId, Timestamp, UnitOfWorkFactory, UserId,
};
use hodor_webhooks::api::{
    AttemptOutcome, CATALOG, DeliveryQuery, DeliverySettings, DeliveryStatus, HmacSha256,
    RegisterEndpoint, RetryPolicy, SenderPorts, WebhookFanOut, WebhookSender, WebhookService,
    signature_header, signed_content,
};
use hodor_webhooks::testing::{
    Answer, FakeDestinations, FakeHmac, InMemoryWebhooks, Ports, RecordingEndpoints, run_contract,
};
use std::sync::Arc;
use time::Duration;

const START: Timestamp = Timestamp::UNIX_EPOCH;

struct World {
    units: InMemoryUnitOfWorkFactory,
    store: InMemoryWebhooks,
    clock: Arc<FixedClock>,
    http: RecordingEndpoints,
    service: WebhookService,
    fan_out: WebhookFanOut,
    sender: WebhookSender,
    tenant: TenantContext,
}

fn world_with(settings: DeliverySettings) -> World {
    let units = InMemoryUnitOfWorkFactory::default();
    let store = InMemoryWebhooks::default();
    let clock = Arc::new(FixedClock::at(START));
    let http = RecordingEndpoints::default();
    let service = WebhookService::new(
        Arc::new(units.clone()),
        Arc::new(store.clone()),
        Arc::new(store.clone()),
        Arc::new(FakeSecretBox),
        Arc::new(FakeDestinations),
        Arc::new(CountingRandom::default()),
        clock.clone(),
    );
    let fan_out = WebhookFanOut::new(
        Arc::new(store.clone()),
        Arc::new(store.clone()),
        clock.clone(),
    );
    let sender = WebhookSender::new(
        SenderPorts {
            units_of_work: Arc::new(units.clone()),
            endpoints: Arc::new(store.clone()),
            deliveries: Arc::new(store.clone()),
            due: Arc::new(store.clone()),
            secrets: Arc::new(FakeSecretBox),
            http: Arc::new(http.clone()),
            hmac: Arc::new(FakeHmac),
            clock: clock.clone(),
        },
        settings,
    );
    World {
        units,
        store,
        clock,
        http,
        service,
        fan_out,
        sender,
        tenant: TenantContext::assume(TenantId::generate()),
    }
}

fn world() -> World {
    world_with(DeliverySettings::default())
}

fn caller() -> Caller {
    Caller {
        actor: Actor::User(UserId::generate()),
        correlation_id: CorrelationId::generate(),
    }
}

fn registration(url: &str, event_types: &[&str]) -> RegisterEndpoint {
    RegisterEndpoint {
        url: url.to_owned(),
        description: None,
        event_types: event_types.iter().map(|name| (*name).to_owned()).collect(),
    }
}

impl World {
    async fn register(
        &self,
        url: &str,
        event_types: &[&str],
    ) -> (hodor_webhooks::api::EndpointId, String) {
        let (details, secret) = self
            .service
            .register(&self.tenant, registration(url, event_types), caller())
            .await
            .expect("registered");
        (details.endpoint.id(), secret.expose().clone())
    }

    /// Hands an event of `event_type` in `tenant` to the fan-out, as the
    /// outbox dispatcher does.
    async fn happen(&self, tenant: &TenantContext, event_type: &str) -> EventEnvelope {
        let event = EventEnvelope {
            metadata: EventMetadata::new(
                tenant.tenant_id(),
                Actor::System,
                CorrelationId::generate(),
                self.clock.as_ref(),
            ),
            event_type: event_type.to_owned(),
            payload: serde_json::json!({ "user_id": UserId::generate() }),
        };
        let mut uow = self.units.begin(tenant).await.expect("begin");
        if self.fan_out.handles(event_type) {
            self.fan_out
                .handle(uow.as_mut(), &event)
                .await
                .expect("fan out");
        }
        uow.commit().await.expect("commit");
        event
    }

    /// Leases what is due and sends it, one after the other.
    async fn deliver_due(&self) -> Vec<AttemptOutcome> {
        let mut outcomes = Vec::new();
        for lease in self.sender.lease_due(100).await.expect("lease") {
            outcomes.push(self.sender.send(lease).await.expect("send"));
        }
        outcomes
    }
}

#[tokio::test]
async fn the_in_memory_store_passes_the_contract() {
    let units = InMemoryUnitOfWorkFactory::default();
    let store = InMemoryWebhooks::default();
    run_contract(Ports {
        units_of_work: &units,
        endpoints: &store,
        deliveries: &store,
        due: &store,
    })
    .await;
}

#[tokio::test]
async fn registering_answers_the_secret_once_and_keeps_it_sealed() {
    let world = world();
    let (details, secret) = world
        .service
        .register(
            &world.tenant,
            RegisterEndpoint {
                url: "https://hooks.example.com/hodor".to_owned(),
                description: Some("Our directory".to_owned()),
                event_types: vec!["session.started".to_owned()],
            },
            caller(),
        )
        .await
        .expect("registered");
    assert!(secret.expose().starts_with("whsec_"));
    assert_eq!(details.secrets.len(), 1);
    assert_eq!(details.secrets[0].expires_at, None);

    let stored = world.store.secrets_of(world.tenant.tenant_id());
    assert_eq!(stored.len(), 1);
    assert!(
        !String::from_utf8_lossy(stored[0].sealed.as_bytes()).contains(secret.expose()),
        "only the sealed secret is stored"
    );
    let read = world
        .service
        .get(&world.tenant, details.endpoint.id())
        .await
        .expect("read");
    assert_eq!(read, details);
    assert_eq!(
        world.units.committed_event_types(),
        ["webhooks.endpoint_registered"]
    );
    let event = &world.units.committed_events()[0];
    assert!(!event.payload.to_string().contains("hooks.example.com"));
}

#[tokio::test]
async fn an_address_that_may_not_be_called_is_refused_before_anything_is_stored() {
    let world = world();
    for (url, code) in [
        ("https://127.0.0.1/", "webhooks.endpoint_address_forbidden"),
        (
            "https://169.254.169.254/latest",
            "webhooks.endpoint_address_forbidden",
        ),
        (
            "https://internal.example/in",
            "webhooks.endpoint_address_forbidden",
        ),
        (
            "https://localhost:8443/",
            "webhooks.endpoint_address_forbidden",
        ),
        (
            "https://nowhere.example/",
            "webhooks.endpoint_address_unresolvable",
        ),
        (
            "http://hooks.example.com/",
            "webhooks.endpoint_address_invalid",
        ),
        ("not an address", "webhooks.endpoint_address_invalid"),
    ] {
        let error = world
            .service
            .register(&world.tenant, registration(url, &[]), caller())
            .await
            .expect_err(url);
        assert_eq!(error.code(), code, "{url}");
        assert!(!error.message().contains("127.0.0.1"));
    }
    let error = world
        .service
        .register(
            &world.tenant,
            registration(
                "https://hooks.example.com/",
                &["webhooks.endpoint_registered"],
            ),
            caller(),
        )
        .await
        .expect_err("unknown type");
    assert_eq!(error.code(), "webhooks.event_type_unknown");
    let listed = world
        .service
        .list(&world.tenant, &PageRequest::default())
        .await
        .expect("list");
    assert!(listed.items.is_empty());
    assert!(world.units.committed_events().is_empty());
}

#[tokio::test]
async fn a_tenant_has_at_most_twenty_endpoints() {
    let world = world();
    for number in 0..20 {
        world
            .register(&format!("https://hooks.example.com/{number}"), &[])
            .await;
    }
    let error = world
        .service
        .register(
            &world.tenant,
            registration("https://hooks.example.com/21", &[]),
            caller(),
        )
        .await
        .expect_err("refused");
    assert_eq!(error.code(), "webhooks.too_many_endpoints");

    // Another tenant has its own twenty.
    let other = TenantContext::assume(TenantId::generate());
    assert!(
        world
            .service
            .register(
                &other,
                registration("https://hooks.example.com/21", &[]),
                caller()
            )
            .await
            .is_ok()
    );

    let first = world
        .service
        .list(&world.tenant, &PageRequest::new(Some(15), None))
        .await
        .expect("page");
    assert_eq!(first.items.len(), 15);
    let rest = world
        .service
        .list(
            &world.tenant,
            &PageRequest::new(Some(15), first.next_cursor),
        )
        .await
        .expect("page");
    assert_eq!(rest.items.len(), 5);
    assert_eq!(rest.next_cursor, None);
}

#[tokio::test]
async fn an_event_makes_one_delivery_per_subscribed_endpoint_of_its_tenant_only() {
    let world = world();
    let (started, _) = world
        .register("https://a.example.com/", &["session.started"])
        .await;
    let (both, _) = world
        .register(
            "https://b.example.com/",
            &["session.started", "identity.user_created"],
        )
        .await;
    world
        .register("https://c.example.com/", &["identity.user_created"])
        .await;
    let other = TenantContext::assume(TenantId::generate());
    world
        .service
        .register(
            &other,
            registration("https://d.example.com/", &["session.started"]),
            caller(),
        )
        .await
        .expect("registered");

    let event = world.happen(&world.tenant, "session.started").await;
    world
        .happen(&world.tenant, "authentication.succeeded")
        .await;
    world
        .happen(&world.tenant, "webhooks.endpoint_registered")
        .await;
    world.happen(&world.tenant, "keys.version_created").await;

    let deliveries = world.store.deliveries_of(world.tenant.tenant_id());
    let mut endpoints: Vec<_> = deliveries
        .iter()
        .map(|delivery| delivery.snapshot().endpoint_id)
        .collect();
    endpoints.sort();
    let mut expected = vec![started, both];
    expected.sort();
    assert_eq!(endpoints, expected);
    for delivery in &deliveries {
        let body: serde_json::Value =
            serde_json::from_str(&delivery.snapshot().payload).expect("JSON");
        assert_eq!(body["id"], event.metadata.event_id.to_string());
        assert_eq!(body["type"], "session.started");
        assert_eq!(body["tenant_id"], world.tenant.tenant_id().to_string());
        assert_eq!(body["data"], event.payload);
    }
    assert!(world.store.deliveries_of(other.tenant_id()).is_empty());

    // Handed over again after a failure, it makes no second delivery.
    let mut uow = world.units.begin(&world.tenant).await.expect("begin");
    world
        .fan_out
        .handle(uow.as_mut(), &event)
        .await
        .expect("again");
    uow.commit().await.expect("commit");
    assert_eq!(world.store.deliveries_of(world.tenant.tenant_id()).len(), 2);
}

#[tokio::test]
async fn an_event_handed_over_in_another_tenant_is_refused() {
    let world = world();
    world
        .register("https://a.example.com/", &["session.started"])
        .await;
    let other = TenantContext::assume(TenantId::generate());
    let event = EventEnvelope {
        metadata: EventMetadata::new(
            other.tenant_id(),
            Actor::System,
            CorrelationId::generate(),
            world.clock.as_ref(),
        ),
        event_type: "session.started".to_owned(),
        payload: serde_json::json!({}),
    };
    let mut uow = world.units.begin(&world.tenant).await.expect("begin");
    let error = world
        .fan_out
        .handle(uow.as_mut(), &event)
        .await
        .expect_err("refused");
    assert_eq!(error.code(), "webhooks.tenant_mismatch");
}

#[tokio::test]
async fn a_delivery_is_sent_signed_as_standard_webhooks_say() {
    let world = world();
    let (_, secret) = world
        .register("https://a.example.com/in", &["session.started"])
        .await;
    let event = world.happen(&world.tenant, "session.started").await;
    world.clock.advance(Duration::seconds(3));

    assert_eq!(world.deliver_due().await, [AttemptOutcome::Delivered]);
    let requests = world.http.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method, HttpMethod::Post);
    assert_eq!(request.url, "https://a.example.com/in");
    assert_eq!(request.time_limit, Some(std::time::Duration::from_secs(10)));
    let header = |name: &str| {
        request
            .headers
            .iter()
            .find(|(header, _)| header == name)
            .map(|(_, value)| value.clone())
            .unwrap_or_default()
    };
    let id = event.metadata.event_id.to_string();
    let timestamp = (START + Duration::seconds(3)).unix_timestamp();
    assert_eq!(header("content-type"), "application/json");
    assert_eq!(header("webhook-id"), id);
    assert_eq!(header("webhook-timestamp"), timestamp.to_string());
    let body = String::from_utf8(request.body.clone().expect("body")).expect("text");
    let key = base64_decode(secret.trim_start_matches("whsec_"));
    let expected = FakeHmac.mac(&key, &signed_content(&id, timestamp, &body));
    assert_eq!(header("webhook-signature"), signature_header(&[expected]));

    let delivery = &world.store.deliveries_of(world.tenant.tenant_id())[0];
    assert_eq!(delivery.status(), DeliveryStatus::Delivered);
    assert_eq!(delivery.snapshot().attempts, 1);
    assert_eq!(delivery.snapshot().last_response_status, Some(204));
    assert!(world.deliver_due().await.is_empty(), "delivered once");
}

fn base64_decode(text: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .expect("Base64")
}

#[tokio::test]
async fn a_delivery_that_keeps_failing_waits_longer_each_time_then_is_set_aside() {
    let world = world_with(DeliverySettings {
        retry: RetryPolicy::new(4, Duration::seconds(30)).expect("policy"),
        ..DeliverySettings::default()
    });
    world
        .register("https://down.example.com/", &["session.started"])
        .await;
    world
        .register("https://up.example.com/", &["session.started"])
        .await;
    world
        .http
        .answer("https://down.example.com/", Answer::Status(503));
    world.happen(&world.tenant, "session.started").await;

    let mut waits = Vec::new();
    let mut outcomes = Vec::new();
    for _ in 0..4 {
        let attempted = world.clock.now();
        outcomes.extend(world.deliver_due().await);
        let down = world
            .store
            .deliveries_of(world.tenant.tenant_id())
            .into_iter()
            .find(|delivery| delivery.status() != DeliveryStatus::Delivered)
            .expect("the failing one");
        if down.status() == DeliveryStatus::Pending {
            waits.push((down.snapshot().next_attempt_at - attempted).whole_seconds());
            // Not due a moment before its wait is over.
            world
                .clock
                .advance(down.snapshot().next_attempt_at - attempted - Duration::seconds(1));
            assert!(world.deliver_due().await.is_empty());
            world.clock.advance(Duration::seconds(1));
        }
    }
    assert_eq!(waits, [30, 60, 120]);
    let mut outcomes: Vec<&str> = outcomes.iter().map(|outcome| outcome.as_str()).collect();
    outcomes.sort_unstable();
    assert_eq!(
        outcomes,
        ["delivered", "retrying", "retrying", "retrying", "set_aside"]
    );
    let set_aside = world
        .service
        .deliveries(
            &world.tenant,
            DeliveryQuery {
                endpoint: None,
                status: Some(DeliveryStatus::SetAside),
            },
            &PageRequest::default(),
        )
        .await
        .expect("list");
    assert_eq!(set_aside.items.len(), 1);
    let dead = &set_aside.items[0];
    assert_eq!(dead.snapshot().attempts, 4);
    assert_eq!(dead.snapshot().last_response_status, Some(503));
    assert_eq!(
        dead.snapshot().last_error.as_deref(),
        Some("the endpoint answered 503")
    );
    assert!(
        world
            .units
            .committed_event_types()
            .contains(&"webhooks.delivery_set_aside".to_owned())
    );
    let delivered = world
        .service
        .deliveries(
            &world.tenant,
            DeliveryQuery {
                endpoint: None,
                status: Some(DeliveryStatus::Delivered),
            },
            &PageRequest::default(),
        )
        .await
        .expect("list");
    assert_eq!(delivered.items.len(), 1, "the other endpoint got its event");

    // Nothing more is tried, however long one waits.
    world.clock.advance(Duration::days(2));
    assert!(world.deliver_due().await.is_empty());

    // Asked for again, it is sent again with the same identifier.
    world
        .http
        .answer("https://down.example.com/", Answer::Status(200));
    let again = world
        .service
        .redeliver(&world.tenant, dead.id(), caller())
        .await
        .expect("again");
    assert_eq!(again.status(), DeliveryStatus::Pending);
    assert_eq!(world.deliver_due().await, [AttemptOutcome::Delivered]);
    let ids: Vec<String> = world
        .http
        .requests()
        .iter()
        .filter(|request| request.url == "https://down.example.com/")
        .map(|request| {
            request
                .headers
                .iter()
                .find(|(name, _)| name == "webhook-id")
                .map(|(_, value)| value.clone())
                .unwrap_or_default()
        })
        .collect();
    assert_eq!(ids.len(), 5);
    assert!(ids.iter().all(|id| *id == ids[0]));
    let error = world
        .service
        .redeliver(&world.tenant, dead.id(), caller())
        .await
        .expect_err("delivered now");
    assert_eq!(error.code(), "webhooks.delivery_not_set_aside");
}

#[tokio::test]
async fn an_address_refused_at_delivery_is_a_failed_attempt() {
    let world = world_with(DeliverySettings {
        retry: RetryPolicy::new(1, Duration::seconds(1)).expect("policy"),
        ..DeliverySettings::default()
    });
    world
        .register("https://moved.example.com/", &["session.started"])
        .await;
    // The name now leads inside.
    world.http.answer(
        "https://moved.example.com/",
        Answer::Failure("http.destination_forbidden"),
    );
    world.happen(&world.tenant, "session.started").await;
    assert_eq!(world.deliver_due().await, [AttemptOutcome::SetAside]);
    let delivery = &world.store.deliveries_of(world.tenant.tenant_id())[0];
    assert_eq!(delivery.snapshot().last_response_status, None);
    assert!(
        delivery
            .snapshot()
            .last_error
            .as_deref()
            .is_some_and(|reason| reason.starts_with("http.destination_forbidden"))
    );
}

#[tokio::test]
async fn one_endpoint_never_has_more_than_its_share_in_flight() {
    let world = world_with(DeliverySettings {
        in_flight_per_endpoint: 2,
        ..DeliverySettings::default()
    });
    let (slow, _) = world
        .register("https://slow.example.com/", &["session.started"])
        .await;
    let (fast, _) = world
        .register("https://fast.example.com/", &["session.started"])
        .await;
    for _ in 0..4 {
        world.happen(&world.tenant, "session.started").await;
    }
    let leases = world.sender.lease_due(100).await.expect("lease");
    let to = |endpoint| {
        leases
            .iter()
            .filter(|lease| lease.endpoint() == endpoint)
            .count()
    };
    assert_eq!((to(slow), to(fast)), (2, 2));
    // While those leases run, nothing more of either is leased.
    assert!(world.sender.lease_due(100).await.expect("lease").is_empty());
    // One sent frees a place for its endpoint only.
    let first_fast = leases
        .iter()
        .find(|lease| lease.endpoint() == fast)
        .cloned()
        .expect("a lease");
    assert_eq!(
        world.sender.send(first_fast).await.expect("send"),
        AttemptOutcome::Delivered
    );
    let next = world.sender.lease_due(100).await.expect("lease");
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].endpoint(), fast);
    // A lease that ran out is taken again, as if its worker had stopped.
    world.clock.advance(Duration::seconds(10 + 60));
    assert_eq!(world.sender.lease_due(100).await.expect("lease").len(), 4);
}

#[tokio::test]
async fn a_delivery_recorded_by_another_worker_is_not_recorded_twice() {
    let world = world();
    world
        .register("https://a.example.com/", &["session.started"])
        .await;
    world.happen(&world.tenant, "session.started").await;
    let lease = world.sender.lease_due(1).await.expect("lease").remove(0);
    let again = lease.clone();
    assert_eq!(
        world.sender.send(lease).await.expect("send"),
        AttemptOutcome::Delivered
    );
    assert_eq!(
        world.sender.send(again).await.expect("send"),
        AttemptOutcome::Skipped
    );
    assert_eq!(world.http.requests().len(), 2, "both were sent");
    let delivery = &world.store.deliveries_of(world.tenant.tenant_id())[0];
    assert_eq!(delivery.snapshot().attempts, 1, "recorded once");
}

#[tokio::test]
async fn a_rotation_signs_with_both_secrets_during_the_overlap() {
    let world = world();
    let (endpoint, first) = world
        .register("https://a.example.com/", &["session.started"])
        .await;
    world.clock.advance(Duration::seconds(10));
    let (details, second) = world
        .service
        .rotate_secret(&world.tenant, endpoint, Some(1), caller())
        .await
        .expect("rotated");
    assert_ne!(first, *second.expose());
    let rotated_at = START + Duration::seconds(10);
    assert_eq!(details.secrets.len(), 2);
    assert_eq!(details.secrets[0].expires_at, None);
    assert_eq!(
        details.secrets[1].expires_at,
        Some(rotated_at + Duration::hours(1))
    );

    world.happen(&world.tenant, "session.started").await;
    world.deliver_due().await;
    let signature = |request: &hodor_kernel::HttpRequest| {
        request
            .headers
            .iter()
            .find(|(name, _)| name == "webhook-signature")
            .map(|(_, value)| value.clone())
            .unwrap_or_default()
    };
    let during = signature(&world.http.requests()[0]);
    assert_eq!(during.split(' ').count(), 2);

    // After the overlap, only the new secret signs.
    world.clock.advance(Duration::hours(1));
    world.happen(&world.tenant, "session.started").await;
    world.deliver_due().await;
    let after = signature(&world.http.requests()[1]);
    assert_eq!(after.split(' ').count(), 1);

    // Rotating twice ends the oldest at once: never more than two sign.
    world
        .service
        .rotate_secret(&world.tenant, endpoint, None, caller())
        .await
        .expect("rotated");
    let (details, _) = world
        .service
        .rotate_secret(&world.tenant, endpoint, None, caller())
        .await
        .expect("rotated");
    assert_eq!(details.secrets.len(), 2);
    assert_eq!(
        world
            .units
            .committed_event_types()
            .last()
            .map(String::as_str),
        Some("webhooks.secret_rotated")
    );
    let error = world
        .service
        .rotate_secret(&world.tenant, endpoint, Some(169), caller())
        .await
        .expect_err("too long");
    assert_eq!(error.code(), "webhooks.overlap_invalid");
}

#[tokio::test]
async fn subscriptions_are_replaced_and_an_endpoint_removed_with_its_deliveries() {
    let world = world();
    let (endpoint, _) = world
        .register("https://a.example.com/", &["session.started"])
        .await;
    let details = world
        .service
        .replace_subscriptions(
            &world.tenant,
            endpoint,
            &[
                "session.revoked".to_owned(),
                "oauth.grant_revoked".to_owned(),
            ],
            caller(),
        )
        .await
        .expect("replaced");
    assert!(details.endpoint.is_subscribed_to("session.revoked"));
    assert!(!details.endpoint.is_subscribed_to("session.started"));
    world.happen(&world.tenant, "session.started").await;
    assert!(
        world
            .store
            .deliveries_of(world.tenant.tenant_id())
            .is_empty()
    );
    world.happen(&world.tenant, "session.revoked").await;
    assert_eq!(world.store.deliveries_of(world.tenant.tenant_id()).len(), 1);

    let other = TenantContext::assume(TenantId::generate());
    let error = world
        .service
        .remove(&other, endpoint, caller())
        .await
        .expect_err("not there");
    assert_eq!(error.code(), "webhooks.endpoint_not_found");
    world
        .service
        .remove(&world.tenant, endpoint, caller())
        .await
        .expect("removed");
    assert!(
        world
            .store
            .deliveries_of(world.tenant.tenant_id())
            .is_empty()
    );
    assert!(world.store.secrets_of(world.tenant.tenant_id()).is_empty());
    let error = world
        .service
        .get(&world.tenant, endpoint)
        .await
        .expect_err("gone");
    assert_eq!(error.code(), "webhooks.endpoint_not_found");
    assert_eq!(
        world.units.committed_event_types(),
        [
            "webhooks.endpoint_registered",
            "webhooks.subscriptions_changed",
            "webhooks.endpoint_removed"
        ]
    );
    assert_eq!(world.service.event_types(), CATALOG);
}
