//! In-memory queue, a recording sender and the contract every message
//! queue passes.

use crate::api::{
    Email, EmailSender, Locale, Message, MessageId, MessageQueue, MessageStatus, PendingMessages,
    Template,
};
use hodor_kernel::{
    DomainError, TenantContext, TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory,
};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use time::Duration;

/// Messages kept in memory. Implements both the queue and the search for
/// pending messages across tenants.
#[derive(Debug, Clone, Default)]
pub struct InMemoryMessages {
    rows: Arc<Mutex<BTreeMap<(TenantId, MessageId), Message>>>,
}

impl InMemoryMessages {
    fn rows(&self) -> std::sync::MutexGuard<'_, BTreeMap<(TenantId, MessageId), Message>> {
        self.rows.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Every stored message of a tenant, in the order they were queued.
    #[must_use]
    pub fn of_tenant(&self, tenant: TenantId) -> Vec<Message> {
        self.rows()
            .iter()
            .filter(|((owner, _), _)| *owner == tenant)
            .map(|(_, message)| message.clone())
            .collect()
    }
}

#[async_trait::async_trait]
impl MessageQueue for InMemoryMessages {
    async fn insert(&self, uow: &mut dyn UnitOfWork, message: &Message) -> Result<(), DomainError> {
        self.rows()
            .insert((uow.tenant().tenant_id(), message.id()), message.clone());
        Ok(())
    }

    async fn take(
        &self,
        uow: &mut dyn UnitOfWork,
        id: MessageId,
    ) -> Result<Option<Message>, DomainError> {
        Ok(self
            .rows()
            .get(&(uow.tenant().tenant_id(), id))
            .filter(|message| message.is_pending())
            .cloned())
    }

    async fn update(&self, uow: &mut dyn UnitOfWork, message: &Message) -> Result<(), DomainError> {
        let key = (uow.tenant().tenant_id(), message.id());
        let mut rows = self.rows();
        if !rows.contains_key(&key) {
            return Err(DomainError::not_found(
                "notification.message_not_found",
                "the message does not exist",
            ));
        }
        rows.insert(key, message.clone());
        Ok(())
    }
}

#[async_trait::async_trait]
impl PendingMessages for InMemoryMessages {
    async fn due(
        &self,
        now: Timestamp,
        limit: u32,
    ) -> Result<Vec<(TenantId, MessageId)>, DomainError> {
        let mut due: Vec<(Timestamp, TenantId, MessageId)> = self
            .rows()
            .iter()
            .filter(|(_, message)| {
                message.is_pending() && message.snapshot().next_attempt_at <= now
            })
            .map(|((tenant, id), message)| (message.snapshot().created_at, *tenant, *id))
            .collect();
        due.sort();
        Ok(due
            .into_iter()
            .take(limit as usize)
            .map(|(_, tenant, id)| (tenant, id))
            .collect())
    }
}

/// A mail server for tests: keeps what it was asked to send, and can be
/// told to refuse everything.
#[derive(Debug, Default)]
pub struct RecordingSender {
    sent: Mutex<Vec<Email>>,
    refusing: AtomicBool,
}

impl RecordingSender {
    /// Everything accepted so far, oldest first.
    #[must_use]
    pub fn sent(&self) -> Vec<Email> {
        self.sent.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// From now on, refuse (`true`) or accept (`false`) every message.
    pub fn refuse(&self, refusing: bool) {
        self.refusing.store(refusing, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl EmailSender for RecordingSender {
    async fn send(&self, email: &Email) -> Result<(), DomainError> {
        if self.refusing.load(Ordering::SeqCst) {
            return Err(DomainError::internal(
                "notification.delivery_failed",
                "the message could not be delivered",
            )
            .with_detail("the mail server is refusing messages"));
        }
        self.sent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(email.clone());
        Ok(())
    }
}

/// The ports under test.
#[derive(Clone)]
pub struct Ports<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The queue under test.
    pub queue: &'a dyn MessageQueue,
    /// The search across tenants under test.
    pub pending: &'a dyn PendingMessages,
}

impl std::fmt::Debug for Ports<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ports").finish_non_exhaustive()
    }
}

/// A fixed, whole-second moment, so that stored timestamps compare equal
/// after a round trip through any storage.
const MOMENT: Timestamp = Timestamp::UNIX_EPOCH;

fn tenant() -> TenantContext {
    TenantContext::assume(TenantId::generate())
}

/// A valid verification message queued at `at`.
///
/// # Panics
///
/// Never: the message is valid.
#[must_use]
pub fn verification_message(recipient: &str, at: Timestamp) -> Message {
    let variables = [
        ("link", "https://example.com/verify?token=0a1b2c"),
        ("tenant_name", "Example"),
        ("expires_in", "24 hours"),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value.to_owned()))
    .collect();
    Message::enqueue(
        recipient,
        Template::EmailVerification,
        Locale::parse("pt-BR").expect("valid locale"),
        variables,
        at + Duration::hours(24),
        at,
    )
    .expect("valid message")
}

async fn insert(ports: &Ports<'_>, tenant: &TenantContext, message: &Message) {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .queue
        .insert(uow.as_mut(), message)
        .await
        .expect("insert");
    uow.commit().await.expect("commit");
}

async fn take(ports: &Ports<'_>, tenant: &TenantContext, id: MessageId) -> Option<Message> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports.queue.take(uow.as_mut(), id).await.expect("take")
}

async fn update(
    ports: &Ports<'_>,
    tenant: &TenantContext,
    message: &Message,
) -> Result<(), DomainError> {
    let mut uow = ports.units_of_work.begin(tenant).await?;
    ports.queue.update(uow.as_mut(), message).await?;
    uow.commit().await
}

async fn due(ports: &Ports<'_>, now: Timestamp) -> Vec<(TenantId, MessageId)> {
    ports.pending.due(now, 1_000).await.expect("due")
}

/// Runs every rule a message queue must obey.
///
/// # Panics
///
/// Panics if the implementation breaks a rule.
pub async fn run_contract(ports: Ports<'_>) {
    a_stored_message_comes_back_as_it_was(&ports).await;
    a_message_is_invisible_to_other_tenants(&ports).await;
    a_message_not_inserted_is_not_stored(&ports).await;
    a_delivered_message_keeps_its_record_and_loses_its_contents(&ports).await;
    a_message_that_is_not_pending_cannot_be_taken(&ports).await;
    updating_a_message_the_tenant_does_not_have_is_refused(&ports).await;
    due_messages_are_found_across_tenants_oldest_first(&ports).await;
    a_message_waiting_for_its_next_try_is_not_due(&ports).await;
    the_search_respects_its_limit(&ports).await;
}

async fn a_stored_message_comes_back_as_it_was(ports: &Ports<'_>) {
    let tenant = tenant();
    let message = verification_message("person@example.com", MOMENT);
    insert(ports, &tenant, &message).await;
    assert_eq!(take(ports, &tenant, message.id()).await, Some(message));
}

async fn a_message_is_invisible_to_other_tenants(ports: &Ports<'_>) {
    let (owner, other) = (tenant(), tenant());
    let message = verification_message("person@example.com", MOMENT);
    insert(ports, &owner, &message).await;
    assert_eq!(take(ports, &other, message.id()).await, None);
    let error = update(ports, &other, &message).await.expect_err("refused");
    assert_eq!(error.code(), "notification.message_not_found");
}

async fn a_message_not_inserted_is_not_stored(ports: &Ports<'_>) {
    assert_eq!(take(ports, &tenant(), MessageId::generate()).await, None);
}

async fn a_delivered_message_keeps_its_record_and_loses_its_contents(ports: &Ports<'_>) {
    let tenant = tenant();
    let mut message = verification_message("person@example.com", MOMENT);
    insert(ports, &tenant, &message).await;
    message
        .record_failure(MOMENT + Duration::seconds(1), "connection refused")
        .expect("pending");
    update(ports, &tenant, &message).await.expect("update");
    let stored = take(ports, &tenant, message.id()).await.expect("pending");
    assert_eq!(stored, message);
    assert_eq!(stored.snapshot().attempts, 1);
    assert_eq!(
        stored.snapshot().last_error.as_deref(),
        Some("connection refused")
    );
    assert!(!stored.snapshot().variables.is_empty());
}

async fn a_message_that_is_not_pending_cannot_be_taken(ports: &Ports<'_>) {
    let tenant = tenant();
    let mut sent = verification_message("sent@example.com", MOMENT);
    let mut expired = verification_message("expired@example.com", MOMENT);
    let mut failed = verification_message("failed@example.com", MOMENT);
    for message in [&sent, &expired, &failed] {
        insert(ports, &tenant, message).await;
    }
    sent.mark_sent(MOMENT + Duration::seconds(2))
        .expect("pending");
    expired.expire().expect("pending");
    failed.fail_for_good("cannot be written").expect("pending");
    assert_eq!(sent.snapshot().status, MessageStatus::Sent);
    for message in [&sent, &expired, &failed] {
        update(ports, &tenant, message).await.expect("update");
        assert_eq!(take(ports, &tenant, message.id()).await, None);
        assert!(
            !due(ports, MOMENT + Duration::days(365))
                .await
                .contains(&(tenant.tenant_id(), message.id()))
        );
    }
}

async fn updating_a_message_the_tenant_does_not_have_is_refused(ports: &Ports<'_>) {
    let message = verification_message("person@example.com", MOMENT);
    let error = update(ports, &tenant(), &message)
        .await
        .expect_err("refused");
    assert_eq!(error.code(), "notification.message_not_found");
}

async fn due_messages_are_found_across_tenants_oldest_first(ports: &Ports<'_>) {
    let (first_tenant, second_tenant) = (tenant(), tenant());
    let later = verification_message("later@example.com", MOMENT + Duration::seconds(20));
    let earlier = verification_message("earlier@example.com", MOMENT + Duration::seconds(10));
    insert(ports, &first_tenant, &later).await;
    insert(ports, &second_tenant, &earlier).await;

    let found = due(ports, MOMENT + Duration::seconds(30)).await;
    let position = |tenant: &TenantContext, message: &Message| {
        found
            .iter()
            .position(|entry| *entry == (tenant.tenant_id(), message.id()))
            .expect("found")
    };
    assert!(position(&second_tenant, &earlier) < position(&first_tenant, &later));

    // Before a message's first try is due, it is not found.
    let found = due(ports, MOMENT + Duration::seconds(15)).await;
    assert!(found.contains(&(second_tenant.tenant_id(), earlier.id())));
    assert!(!found.contains(&(first_tenant.tenant_id(), later.id())));
}

async fn a_message_waiting_for_its_next_try_is_not_due(ports: &Ports<'_>) {
    let tenant = tenant();
    let mut message = verification_message("person@example.com", MOMENT);
    insert(ports, &tenant, &message).await;
    message
        .record_failure(MOMENT, "connection refused")
        .expect("pending");
    update(ports, &tenant, &message).await.expect("update");
    let entry = (tenant.tenant_id(), message.id());
    assert!(
        !due(ports, MOMENT + Duration::seconds(29))
            .await
            .contains(&entry)
    );
    assert!(
        due(ports, MOMENT + Duration::seconds(30))
            .await
            .contains(&entry)
    );
}

async fn the_search_respects_its_limit(ports: &Ports<'_>) {
    let tenant = tenant();
    for index in 0..3 {
        let message = verification_message(&format!("person{index}@example.com"), MOMENT);
        insert(ports, &tenant, &message).await;
    }
    let found = ports
        .pending
        .due(MOMENT + Duration::seconds(1), 2)
        .await
        .expect("due");
    assert_eq!(found.len(), 2);
}
