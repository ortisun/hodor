//! The use cases of the notification context, on in-memory ports.

use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{TenantContext, TenantId, Timestamp, UnitOfWorkFactory};
use hodor_notification::api::{
    DeliveryReport, DeliveryService, EnqueueMessage, Locale, MAX_ATTEMPTS, MessageStatus, Notifier,
    Template,
};
use hodor_notification::testing::{InMemoryMessages, Ports, RecordingSender, run_contract};
use std::sync::Arc;
use time::Duration;

struct World {
    units_of_work: Arc<InMemoryUnitOfWorkFactory>,
    messages: InMemoryMessages,
    sender: Arc<RecordingSender>,
    clock: Arc<FixedClock>,
    notifier: Notifier,
    delivery: DeliveryService,
    tenant: TenantContext,
}

fn world() -> World {
    let units_of_work = Arc::new(InMemoryUnitOfWorkFactory::default());
    let messages = InMemoryMessages::default();
    let sender = Arc::new(RecordingSender::default());
    let clock = Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH));
    World {
        notifier: Notifier::new(Arc::new(messages.clone()), clock.clone()),
        delivery: DeliveryService::new(
            units_of_work.clone(),
            Arc::new(messages.clone()),
            Arc::new(messages.clone()),
            sender.clone(),
            clock.clone(),
        ),
        units_of_work,
        messages,
        sender,
        clock,
        tenant: TenantContext::assume(TenantId::generate()),
    }
}

fn recovery(recipient: &str, locale: &str, expires_at: Timestamp) -> EnqueueMessage {
    EnqueueMessage {
        recipient: recipient.to_owned(),
        template: Template::PasswordRecovery,
        locale: Locale::parse(locale).expect("valid locale"),
        variables: [
            ("link", "https://example.com/reset?token=0a1b2c"),
            ("tenant_name", "Example"),
            ("expires_in", "1 hour"),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect(),
        expires_at,
    }
}

impl World {
    async fn enqueue(&self, command: EnqueueMessage) {
        let mut uow = self.units_of_work.begin(&self.tenant).await.expect("begin");
        self.notifier
            .enqueue(uow.as_mut(), command)
            .await
            .expect("enqueue");
        uow.commit().await.expect("commit");
    }

    async fn deliver(&self) -> DeliveryReport {
        self.delivery.deliver_pending(100).await.expect("deliver")
    }

    fn status(&self) -> MessageStatus {
        self.messages.of_tenant(self.tenant.tenant_id())[0]
            .snapshot()
            .status
    }

    fn in_an_hour(&self) -> Timestamp {
        Timestamp::UNIX_EPOCH + Duration::hours(1)
    }
}

#[tokio::test]
async fn the_in_memory_queue_passes_the_contract() {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let messages = InMemoryMessages::default();
    run_contract(Ports {
        units_of_work: &units_of_work,
        queue: &messages,
        pending: &messages,
    })
    .await;
}

#[tokio::test]
async fn a_queued_message_is_written_in_its_language_and_sent() {
    let world = world();
    world
        .enqueue(recovery("pessoa@example.com", "pt-BR", world.in_an_hour()))
        .await;

    let report = world.deliver().await;

    assert_eq!(
        report,
        DeliveryReport {
            sent: 1,
            ..DeliveryReport::default()
        }
    );
    let sent = world.sender.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].recipient, "pessoa@example.com");
    assert_eq!(sent[0].subject, "Escolha uma nova senha para Example");
    assert!(
        sent[0]
            .body
            .contains("https://example.com/reset?token=0a1b2c")
    );
    assert_eq!(world.status(), MessageStatus::Sent);
    assert_eq!(
        world.units_of_work.committed_event_types(),
        ["notification.message_sent"]
    );
}

#[tokio::test]
async fn a_sent_message_is_not_sent_again() {
    let world = world();
    world
        .enqueue(recovery("person@example.com", "en", world.in_an_hour()))
        .await;
    world.deliver().await;

    world.clock.advance(Duration::minutes(10));
    let report = world.deliver().await;

    assert_eq!(report, DeliveryReport::default());
    assert_eq!(world.sender.sent().len(), 1);
}

#[tokio::test]
async fn nothing_about_the_message_contents_reaches_an_event_or_stays_stored() {
    let world = world();
    world
        .enqueue(recovery("person@example.com", "en", world.in_an_hour()))
        .await;
    world.deliver().await;

    let events = format!("{:?}", world.units_of_work.committed_events());
    assert!(!events.contains("0a1b2c"), "{events}");
    assert!(!events.contains("person@example.com"), "{events}");
    let stored = &world.messages.of_tenant(world.tenant.tenant_id())[0];
    assert!(stored.snapshot().variables.is_empty());
}

#[tokio::test]
async fn a_refused_message_waits_and_is_tried_again() {
    let world = world();
    world
        .enqueue(recovery("person@example.com", "en", world.in_an_hour()))
        .await;
    world.sender.refuse(true);

    assert_eq!(world.deliver().await.retrying, 1);
    assert_eq!(world.status(), MessageStatus::Pending);
    assert!(world.units_of_work.committed_event_types().is_empty());

    // Not yet due: nothing is tried.
    world.clock.advance(Duration::seconds(29));
    assert_eq!(world.deliver().await, DeliveryReport::default());

    world.sender.refuse(false);
    world.clock.advance(Duration::seconds(1));
    assert_eq!(world.deliver().await.sent, 1);
    assert_eq!(world.sender.sent().len(), 1);
    let stored = &world.messages.of_tenant(world.tenant.tenant_id())[0];
    assert_eq!(stored.snapshot().attempts, 2);
    assert_eq!(stored.snapshot().last_error, None);
}

#[tokio::test]
async fn a_message_refused_too_many_times_fails_for_good() {
    let world = world();
    world
        .enqueue(recovery(
            "person@example.com",
            "en",
            Timestamp::UNIX_EPOCH + Duration::days(7),
        ))
        .await;
    world.sender.refuse(true);

    let mut failed = 0;
    for _ in 0..MAX_ATTEMPTS {
        failed += world.deliver().await.failed;
        world.clock.advance(Duration::minutes(30));
    }

    assert_eq!(failed, 1);
    assert_eq!(world.status(), MessageStatus::Failed);
    assert_eq!(
        world.units_of_work.committed_event_types(),
        ["notification.message_failed"]
    );
    world.sender.refuse(false);
    assert_eq!(world.deliver().await, DeliveryReport::default());
    assert!(world.sender.sent().is_empty());
}

#[tokio::test]
async fn an_expired_message_is_dropped_without_being_sent() {
    let world = world();
    world
        .enqueue(recovery("person@example.com", "en", world.in_an_hour()))
        .await;
    world.clock.advance(Duration::hours(1));

    let report = world.deliver().await;

    assert_eq!(report.expired, 1);
    assert!(world.sender.sent().is_empty());
    assert_eq!(world.status(), MessageStatus::Expired);
    assert_eq!(
        world.units_of_work.committed_event_types(),
        ["notification.message_failed"]
    );
}

#[tokio::test]
async fn a_message_that_is_not_acceptable_is_not_queued() {
    let world = world();
    let mut command = recovery("person@example.com", "en", world.in_an_hour());
    command.variables.remove("link");
    let mut uow = world
        .units_of_work
        .begin(&world.tenant)
        .await
        .expect("begin");

    let error = world
        .notifier
        .enqueue(uow.as_mut(), command)
        .await
        .expect_err("refused");

    assert_eq!(error.code(), "notification.missing_variable");
    assert!(
        world
            .messages
            .of_tenant(world.tenant.tenant_id())
            .is_empty()
    );
}

#[tokio::test]
async fn messages_of_several_tenants_are_delivered_in_one_pass() {
    let world = world();
    let other = TenantContext::assume(TenantId::generate());
    world
        .enqueue(recovery("first@example.com", "en", world.in_an_hour()))
        .await;
    let mut uow = world.units_of_work.begin(&other).await.expect("begin");
    world
        .notifier
        .enqueue(
            uow.as_mut(),
            recovery("second@example.com", "en", world.in_an_hour()),
        )
        .await
        .expect("enqueue");
    uow.commit().await.expect("commit");

    assert_eq!(world.deliver().await.sent, 2);
    assert_eq!(world.messages.of_tenant(other.tenant_id()).len(), 1);
}

#[tokio::test]
async fn a_message_that_can_never_be_sent_fails_at_once() {
    let world = world();
    world
        .enqueue(recovery(
            "person@unaddressable.example",
            "en",
            world.in_an_hour(),
        ))
        .await;

    let report = world.deliver().await;

    assert_eq!(report.failed, 1);
    assert_eq!(world.status(), MessageStatus::Failed);
    let stored = &world.messages.of_tenant(world.tenant.tenant_id())[0];
    assert_eq!(stored.snapshot().attempts, 0);
    assert!(stored.snapshot().variables.is_empty());
    assert_eq!(
        world.units_of_work.committed_event_types(),
        ["notification.message_failed"]
    );
}
