//! Domain events.
//!
//! A context records what happened as events written to the outbox in the
//! same transaction as the state change. Other contexts react to them later;
//! handlers deduplicate on [`EventMetadata::event_id`].

use crate::clock::{Clock, Timestamp};
use crate::error::DomainError;
use crate::id::{CorrelationId, EventId, TenantId, UserId};
use crate::uow::UnitOfWork;
use serde::{Deserialize, Serialize};

/// Who caused an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum Actor {
    /// A principal acting through an authenticated request.
    User(UserId),
    /// Hodor itself: a scheduled job or an event handler.
    System,
    /// A request that was not authenticated, for example a failed login.
    Anonymous,
}

/// Data carried by every event regardless of its type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventMetadata {
    /// Unique per event.
    pub event_id: EventId,
    /// Tenant the event belongs to.
    pub tenant_id: TenantId,
    /// When the event happened.
    #[serde(with = "time::serde::rfc3339")]
    pub occurred_at: Timestamp,
    /// Who caused it.
    pub actor: Actor,
    /// The request or job that caused it.
    pub correlation_id: CorrelationId,
}

impl EventMetadata {
    /// Creates metadata for an event happening now.
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        actor: Actor,
        correlation_id: CorrelationId,
        clock: &dyn Clock,
    ) -> Self {
        Self {
            event_id: EventId::generate(),
            tenant_id,
            occurred_at: clock.now(),
            actor,
            correlation_id,
        }
    }
}

/// Something that happened in a context and that others may react to.
pub trait DomainEvent: Send + Sync {
    /// Stable name of the event type, `context.event` in snake case
    /// (`identity.user_created`). Part of the published language: renaming
    /// it breaks consumers.
    fn event_type(&self) -> &'static str;
}

/// An event in the form it is stored and delivered: metadata, type name and
/// the event's own data as JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventEnvelope {
    /// Data common to all events.
    pub metadata: EventMetadata,
    /// The event's stable type name.
    pub event_type: String,
    /// The event's own fields.
    pub payload: serde_json::Value,
}

impl EventEnvelope {
    /// Packs an event for the outbox.
    ///
    /// # Errors
    ///
    /// Returns an internal error if the event cannot be represented as JSON,
    /// which indicates a bug in the event type.
    pub fn new<E>(metadata: EventMetadata, event: &E) -> Result<Self, DomainError>
    where
        E: DomainEvent + Serialize,
    {
        let payload = serde_json::to_value(event).map_err(|error| {
            DomainError::internal("event.not_serializable", "the event could not be recorded")
                .with_detail(format!("{}: {error}", event.event_type()))
        })?;
        Ok(Self {
            metadata,
            event_type: event.event_type().to_owned(),
            payload,
        })
    }
}

/// Reacts to events after the transaction that produced them committed.
///
/// A handler runs inside a unit of work of the event's tenant. Changes it
/// makes through that unit of work commit together with the record that the
/// event was delivered, so they happen exactly once. Effects outside the
/// database (an email, a webhook) may be repeated after a failure: such
/// handlers must deduplicate on [`EventMetadata::event_id`].
#[async_trait::async_trait]
pub trait EventHandler: Send + Sync {
    /// Stable name, used in logs and error records.
    fn name(&self) -> &'static str;

    /// Whether this handler wants events of the given type.
    fn handles(&self, event_type: &str) -> bool;

    /// Handles one event.
    ///
    /// # Errors
    ///
    /// An error leaves the event pending; it is retried later with backoff.
    async fn handle(
        &self,
        uow: &mut dyn UnitOfWork,
        event: &EventEnvelope,
    ) -> Result<(), DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::testing::FixedClock;

    #[derive(Serialize)]
    struct UserCreated {
        username: &'static str,
    }

    impl DomainEvent for UserCreated {
        fn event_type(&self) -> &'static str {
            "identity.user_created"
        }
    }

    #[test]
    fn envelope_carries_type_and_payload() {
        let clock = FixedClock::at(Timestamp::UNIX_EPOCH);
        let metadata = EventMetadata::new(
            TenantId::generate(),
            Actor::System,
            CorrelationId::generate(),
            &clock,
        );
        let envelope =
            EventEnvelope::new(metadata, &UserCreated { username: "ana" }).expect("serializable");
        assert_eq!(envelope.event_type, "identity.user_created");
        assert_eq!(envelope.payload, serde_json::json!({ "username": "ana" }));
    }

    #[test]
    fn metadata_takes_its_time_from_the_clock() {
        let clock = FixedClock::at(Timestamp::UNIX_EPOCH);
        let tenant_id = TenantId::generate();
        let metadata =
            EventMetadata::new(tenant_id, Actor::System, CorrelationId::generate(), &clock);
        assert_eq!(metadata.occurred_at, Timestamp::UNIX_EPOCH);
        assert_eq!(metadata.tenant_id, tenant_id);
    }

    #[test]
    fn metadata_round_trips_through_json() {
        let clock = FixedClock::at(Timestamp::UNIX_EPOCH);
        let metadata = EventMetadata::new(
            TenantId::generate(),
            Actor::User(UserId::generate()),
            CorrelationId::generate(),
            &clock,
        );
        let json = serde_json::to_string(&metadata).expect("serializable");
        assert!(json.contains("\"occurred_at\":\"1970-01-01T00:00:00Z\""));
        assert!(json.contains("\"kind\":\"user\""));
        let back: EventMetadata = serde_json::from_str(&json).expect("deserializable");
        assert_eq!(back, metadata);
    }

    #[test]
    fn each_event_gets_its_own_id() {
        let clock = FixedClock::at(Timestamp::UNIX_EPOCH);
        let tenant_id = TenantId::generate();
        let correlation_id = CorrelationId::generate();
        let a = EventMetadata::new(tenant_id, Actor::Anonymous, correlation_id, &clock);
        let b = EventMetadata::new(tenant_id, Actor::Anonymous, correlation_id, &clock);
        assert_ne!(a.event_id, b.event_id);
    }
}
