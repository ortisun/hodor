//! Deliveries: one event on its way to one endpoint, and what each attempt
//! did to it.

use crate::domain::endpoint::EndpointId;
use crate::domain::event::WebhookEvent;
use hodor_kernel::{DomainError, EventId, Timestamp};
use time::Duration;

hodor_kernel::define_id!(
    /// Identifies a delivery.
    DeliveryId
);

/// The largest body a delivery may have, in bytes.
pub const MAX_PAYLOAD_BYTES: usize = 65_536;

/// The longest reason kept for a failed attempt, in characters.
pub const MAX_ERROR_LENGTH: usize = 500;

/// Where a delivery is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeliveryStatus {
    /// Waiting for its next attempt, or being sent.
    Pending,
    /// The endpoint took it.
    Delivered,
    /// Every attempt failed; it waits for someone to ask for it again.
    SetAside,
}

impl DeliveryStatus {
    /// Every status.
    pub const ALL: [Self; 3] = [Self::Pending, Self::Delivered, Self::SetAside];

    /// The name it is stored and shown under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Delivered => "delivered",
            Self::SetAside => "set_aside",
        }
    }

    /// Reads a status by its name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|status| status.as_str() == name)
    }
}

/// How many attempts a delivery gets, and how long it waits between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    max_attempts: u32,
    first_wait: Duration,
}

impl RetryPolicy {
    /// The longest wait between two attempts.
    pub const LONGEST_WAIT: Duration = Duration::hours(1);

    /// Eight attempts, the first wait 30 seconds.
    pub const DEFAULT: Self = Self {
        max_attempts: 8,
        first_wait: Duration::seconds(30),
    };

    /// A policy of `max_attempts` attempts, from 1 to 20, the first wait
    /// `first_wait`, more than nothing and at most an hour.
    ///
    /// # Errors
    ///
    /// Returns `webhooks.retry_policy_invalid` outside those bounds.
    pub fn new(max_attempts: u32, first_wait: Duration) -> Result<Self, DomainError> {
        if !(1..=20).contains(&max_attempts)
            || first_wait <= Duration::ZERO
            || first_wait > Self::LONGEST_WAIT
        {
            return Err(DomainError::invalid(
                "webhooks.retry_policy_invalid",
                "a delivery has 1 to 20 attempts, and the first wait is more than nothing and at \
                 most an hour",
            ));
        }
        Ok(Self {
            max_attempts,
            first_wait,
        })
    }

    /// How many attempts a delivery gets.
    #[must_use]
    pub const fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// The wait after the attempt numbered `attempts`, counted from 1:
    /// the first wait, doubled after each attempt, up to an hour.
    #[must_use]
    pub fn wait_after(&self, attempts: u32) -> Duration {
        let doublings = attempts.saturating_sub(1).min(31);
        let factor = i32::try_from(1_u64 << doublings).unwrap_or(i32::MAX);
        self.first_wait
            .checked_mul(factor)
            .unwrap_or(Self::LONGEST_WAIT)
            .min(Self::LONGEST_WAIT)
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Everything about a delivery, for storage and for reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliverySnapshot {
    /// The delivery's identifier.
    pub id: DeliveryId,
    /// Where it goes.
    pub endpoint_id: EndpointId,
    /// The event it carries.
    pub event_id: EventId,
    /// The event's type.
    pub event_type: String,
    /// The body sent at every attempt.
    pub payload: String,
    /// Where it is.
    pub status: DeliveryStatus,
    /// How many attempts were made.
    pub attempts: u32,
    /// When the next attempt is due.
    pub next_attempt_at: Timestamp,
    /// While a worker sends it, when its lease ends.
    pub leased_until: Option<Timestamp>,
    /// The status of the last answer, if the endpoint answered.
    pub last_response_status: Option<u16>,
    /// Why the last attempt failed.
    pub last_error: Option<String>,
    /// When it was made.
    pub created_at: Timestamp,
    /// When it was delivered or set aside.
    pub finished_at: Option<Timestamp>,
}

/// One event on its way to one endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    state: DeliverySnapshot,
}

fn shortened(reason: &str) -> String {
    reason.chars().take(MAX_ERROR_LENGTH).collect()
}

impl Delivery {
    /// A delivery of `payload`, due at once. A body larger than
    /// [`MAX_PAYLOAD_BYTES`] is never sent: the delivery is set aside at
    /// once, and the event that says so is returned.
    #[must_use]
    pub fn make(
        endpoint_id: EndpointId,
        event_id: EventId,
        event_type: &str,
        payload: String,
        now: Timestamp,
    ) -> (Self, Option<WebhookEvent>) {
        let mut delivery = Self {
            state: DeliverySnapshot {
                id: DeliveryId::generate(),
                endpoint_id,
                event_id,
                event_type: event_type.to_owned(),
                payload,
                status: DeliveryStatus::Pending,
                attempts: 0,
                next_attempt_at: now,
                leased_until: None,
                last_response_status: None,
                last_error: None,
                created_at: now,
                finished_at: None,
            },
        };
        if delivery.state.payload.len() <= MAX_PAYLOAD_BYTES {
            return (delivery, None);
        }
        delivery.state.payload = String::new();
        let event = delivery.set_aside(now, "the body is larger than 64 kibibytes");
        (delivery, Some(event))
    }

    /// Rebuilds a delivery read from storage.
    #[must_use]
    pub const fn from_snapshot(state: DeliverySnapshot) -> Self {
        Self { state }
    }

    /// Everything about it.
    #[must_use]
    pub const fn snapshot(&self) -> &DeliverySnapshot {
        &self.state
    }

    /// Its identifier.
    #[must_use]
    pub const fn id(&self) -> DeliveryId {
        self.state.id
    }

    /// Where it is.
    #[must_use]
    pub const fn status(&self) -> DeliveryStatus {
        self.state.status
    }

    /// Whether it may be leased at `now`: pending, due, and not leased by
    /// anyone whose lease still runs.
    #[must_use]
    pub fn is_due(&self, now: Timestamp) -> bool {
        self.state.status == DeliveryStatus::Pending
            && self.state.next_attempt_at <= now
            && self.state.leased_until.is_none_or(|until| until <= now)
    }

    /// Whether a worker's lease runs at `now`.
    #[must_use]
    pub fn is_leased(&self, now: Timestamp) -> bool {
        self.state.status == DeliveryStatus::Pending
            && self.state.leased_until.is_some_and(|until| until > now)
    }

    /// Leases it to the worker about to send it, until `until`.
    ///
    /// # Errors
    ///
    /// Returns `webhooks.delivery_not_due` unless it is due at `now`.
    pub fn lease(&mut self, now: Timestamp, until: Timestamp) -> Result<(), DomainError> {
        if !self.is_due(now) {
            return Err(DomainError::conflict(
                "webhooks.delivery_not_due",
                "the delivery is not due",
            ));
        }
        self.state.leased_until = Some(until);
        Ok(())
    }

    /// Whether it is still the delivery a worker leased after `attempts`
    /// attempts: pending, leased, and with no attempt recorded since.
    #[must_use]
    pub fn is_as_leased(&self, attempts: u32) -> bool {
        self.state.status == DeliveryStatus::Pending
            && self.state.leased_until.is_some()
            && self.state.attempts == attempts
    }

    /// The endpoint took it.
    pub fn record_success(&mut self, now: Timestamp, status: u16) {
        self.state.attempts += 1;
        self.state.status = DeliveryStatus::Delivered;
        self.state.leased_until = None;
        self.state.last_response_status = Some(status);
        self.state.last_error = None;
        self.state.finished_at = Some(now);
    }

    /// An attempt failed: the next one waits longer, or, after the last,
    /// the delivery is set aside and the event that says so returned.
    pub fn record_failure(
        &mut self,
        now: Timestamp,
        status: Option<u16>,
        reason: &str,
        policy: &RetryPolicy,
    ) -> Option<WebhookEvent> {
        self.state.attempts += 1;
        self.state.leased_until = None;
        self.state.last_response_status = status;
        if self.state.attempts >= policy.max_attempts() {
            return Some(self.set_aside(now, reason));
        }
        self.state.last_error = Some(shortened(reason));
        self.state.next_attempt_at = now + policy.wait_after(self.state.attempts);
        None
    }

    fn set_aside(&mut self, now: Timestamp, reason: &str) -> WebhookEvent {
        self.state.status = DeliveryStatus::SetAside;
        self.state.leased_until = None;
        self.state.last_error = Some(shortened(reason));
        self.state.finished_at = Some(now);
        WebhookEvent::DeliverySetAside {
            delivery_id: self.state.id,
            endpoint_id: self.state.endpoint_id,
            event_id: self.state.event_id,
            attempts: self.state.attempts,
        }
    }

    /// Puts a set-aside delivery back to pending, due at once, with no
    /// attempts.
    ///
    /// # Errors
    ///
    /// Returns `webhooks.delivery_not_set_aside` for any other delivery,
    /// and for one whose body was too large to be sent.
    pub fn redeliver(&mut self, now: Timestamp) -> Result<WebhookEvent, DomainError> {
        if self.state.status != DeliveryStatus::SetAside || self.state.payload.is_empty() {
            return Err(DomainError::conflict(
                "webhooks.delivery_not_set_aside",
                "only a delivery that was set aside can be delivered again",
            ));
        }
        self.state.status = DeliveryStatus::Pending;
        self.state.attempts = 0;
        self.state.next_attempt_at = now;
        self.state.leased_until = None;
        self.state.finished_at = None;
        Ok(WebhookEvent::RedeliveryRequested {
            delivery_id: self.state.id,
            endpoint_id: self.state.endpoint_id,
            event_id: self.state.event_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: Timestamp = Timestamp::UNIX_EPOCH;

    fn delivery() -> Delivery {
        Delivery::make(
            EndpointId::generate(),
            EventId::generate(),
            "session.started",
            "{}".to_owned(),
            NOW,
        )
        .0
    }

    #[test]
    fn waits_double_from_the_first_up_to_an_hour() {
        let policy = RetryPolicy::DEFAULT;
        let waits: Vec<i64> = (1..=9)
            .map(|attempt| policy.wait_after(attempt).whole_seconds())
            .collect();
        assert_eq!(waits, [30, 60, 120, 240, 480, 960, 1_920, 3_600, 3_600]);
        assert_eq!(policy.wait_after(u32::MAX), RetryPolicy::LONGEST_WAIT);
    }

    #[test]
    fn a_policy_out_of_bounds_is_refused() {
        for (attempts, wait) in [
            (0, Duration::seconds(1)),
            (21, Duration::seconds(1)),
            (3, Duration::ZERO),
            (3, Duration::hours(2)),
        ] {
            assert_eq!(
                RetryPolicy::new(attempts, wait)
                    .expect_err("refused")
                    .code(),
                "webhooks.retry_policy_invalid"
            );
        }
        assert!(RetryPolicy::new(20, Duration::milliseconds(1)).is_ok());
    }

    #[test]
    fn a_delivery_is_retried_with_growing_waits_then_set_aside() {
        let policy = RetryPolicy::new(3, Duration::seconds(10)).expect("policy");
        let mut delivery = delivery();
        let mut now = NOW;
        let mut next = Vec::new();
        for _ in 0..2 {
            delivery
                .lease(now, now + Duration::minutes(1))
                .expect("due");
            assert!(delivery.is_leased(now));
            assert!(!delivery.is_due(now), "a leased delivery is not due");
            assert!(
                delivery
                    .record_failure(now, Some(503), "no", &policy)
                    .is_none()
            );
            next.push(delivery.snapshot().next_attempt_at - now);
            assert!(!delivery.is_due(now));
            now = delivery.snapshot().next_attempt_at;
            assert!(delivery.is_due(now));
        }
        assert_eq!(next, [Duration::seconds(10), Duration::seconds(20)]);

        delivery
            .lease(now, now + Duration::minutes(1))
            .expect("due");
        let event = delivery
            .record_failure(now, None, "http.timed_out", &policy)
            .expect("set aside");
        assert_eq!(delivery.status(), DeliveryStatus::SetAside);
        assert_eq!(delivery.snapshot().finished_at, Some(now));
        assert_eq!(
            delivery.snapshot().last_error.as_deref(),
            Some("http.timed_out")
        );
        assert!(matches!(
            event,
            WebhookEvent::DeliverySetAside { attempts: 3, .. }
        ));
        assert!(!delivery.is_due(now + Duration::days(1)));
    }

    #[test]
    fn a_set_aside_delivery_and_only_one_is_delivered_again() {
        let policy = RetryPolicy::new(1, Duration::seconds(1)).expect("policy");
        let mut delivery = delivery();
        assert_eq!(
            delivery.redeliver(NOW).expect_err("pending").code(),
            "webhooks.delivery_not_set_aside"
        );
        delivery
            .lease(NOW, NOW + Duration::minutes(1))
            .expect("due");
        delivery.record_failure(NOW, Some(500), "no", &policy);
        let later = NOW + Duration::hours(3);
        assert!(matches!(
            delivery.redeliver(later).expect("again"),
            WebhookEvent::RedeliveryRequested { .. }
        ));
        assert!(delivery.is_due(later));
        assert_eq!(delivery.snapshot().attempts, 0);
        assert_eq!(delivery.snapshot().finished_at, None);

        delivery
            .lease(later, later + Duration::minutes(1))
            .expect("due");
        delivery.record_success(later, 204);
        assert_eq!(delivery.status(), DeliveryStatus::Delivered);
        assert_eq!(delivery.snapshot().last_response_status, Some(204));
        assert_eq!(
            delivery.redeliver(later).expect_err("delivered").code(),
            "webhooks.delivery_not_set_aside"
        );
    }

    #[test]
    fn a_lease_that_ran_out_lets_another_worker_take_it() {
        let mut delivery = delivery();
        delivery
            .lease(NOW, NOW + Duration::seconds(70))
            .expect("due");
        assert!(delivery.lease(NOW + Duration::seconds(69), NOW).is_err());
        assert!(delivery.is_due(NOW + Duration::seconds(70)));
        assert!(delivery.is_as_leased(0));
        assert!(!delivery.is_as_leased(1));
    }

    #[test]
    fn a_body_too_large_is_set_aside_at_once_and_never_sent() {
        let (mut delivery, event) = Delivery::make(
            EndpointId::generate(),
            EventId::generate(),
            "session.started",
            "x".repeat(MAX_PAYLOAD_BYTES + 1),
            NOW,
        );
        assert!(event.is_some());
        assert_eq!(delivery.status(), DeliveryStatus::SetAside);
        assert!(delivery.snapshot().payload.is_empty());
        assert!(delivery.redeliver(NOW).is_err());

        let (fits, none) = Delivery::make(
            EndpointId::generate(),
            EventId::generate(),
            "session.started",
            "x".repeat(MAX_PAYLOAD_BYTES),
            NOW,
        );
        assert!(none.is_none());
        assert!(fits.is_due(NOW));
    }

    #[test]
    fn reasons_are_kept_short() {
        let policy = RetryPolicy::DEFAULT;
        let mut delivery = delivery();
        delivery.lease(NOW, NOW).expect("due");
        delivery.record_failure(NOW, None, &"é".repeat(800), &policy);
        assert_eq!(
            delivery
                .snapshot()
                .last_error
                .as_deref()
                .map(|reason| reason.chars().count()),
            Some(MAX_ERROR_LENGTH)
        );
        assert!(
            DeliveryStatus::ALL
                .iter()
                .all(|status| DeliveryStatus::from_name(status.as_str()) == Some(*status))
        );
    }
}
