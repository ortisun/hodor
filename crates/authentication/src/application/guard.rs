//! Protection against guessing: counting attempts and locking out.

use crate::application::ports::AttemptStore;
use crate::domain::attempt::{AttemptSubject, LockoutRules};
use crate::domain::event::AuthenticationEvent;
use hodor_kernel::{
    Caller, Clock, Digest, DomainError, ErrorKind, EventEnvelope, EventMetadata, TenantContext,
    Timestamp, UnitOfWorkFactory,
};
use std::sync::Arc;

/// Counts attempts against identifiers and addresses, and refuses attempts
/// while a subject is locked out.
///
/// An attempt is counted when it is admitted, before the password is
/// checked, and the identifier's count is cleared if the attempt turns out
/// to succeed. Counting first is what keeps the limit exact when many
/// attempts arrive at the same moment: only as many as the limit are let
/// through to the password check.
#[derive(Clone)]
pub struct AttemptGuard {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    attempts: Arc<dyn AttemptStore>,
    digest: Arc<dyn Digest>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for AttemptGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttemptGuard").finish_non_exhaustive()
    }
}

fn too_many_attempts(until: Timestamp, now: Timestamp) -> DomainError {
    let seconds = u64::try_from((until - now).whole_seconds().max(1)).unwrap_or(1);
    DomainError::new(
        ErrorKind::RateLimited,
        "authentication.too_many_attempts",
        "too many attempts; try again later",
    )
    .with_retry_after(seconds)
}

impl AttemptGuard {
    /// Wires the guard to its ports.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        attempts: Arc<dyn AttemptStore>,
        digest: Arc<dyn Digest>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            units_of_work,
            attempts,
            digest,
            clock,
        }
    }

    /// Admits one attempt for an identifier from an address, counting it
    /// against both.
    ///
    /// # Errors
    ///
    /// Returns `RateLimited` with code `authentication.too_many_attempts`
    /// and the time to wait if the identifier or the address is locked
    /// out. Nothing is counted in that case, and the caller must not check
    /// any password.
    pub async fn admit(
        &self,
        tenant: &TenantContext,
        rules: &LockoutRules,
        identifier_key: [u8; 32],
        address: Option<&str>,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let mut subjects = vec![AttemptSubject::Identifier(identifier_key)];
        if let Some(address) = address {
            subjects.push(AttemptSubject::Address(
                self.digest.sha256(address.as_bytes()),
            ));
        }
        // Always in the same order, so that two attempts can never wait
        // for each other.
        subjects.sort();
        self.count(tenant, rules, &subjects, caller).await
    }

    /// Admits the start of one sign-in from an address, counting it against
    /// the address's network, apart from any count of passwords. An address
    /// that is not known is not counted.
    ///
    /// # Errors
    ///
    /// Returns `RateLimited` with code `authentication.too_many_attempts`
    /// and the time to wait if too many sign-ins were started from that
    /// network. Nothing is counted in that case, and no sign-in may start.
    pub async fn admit_start(
        &self,
        tenant: &TenantContext,
        address: Option<&str>,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let Some(address) = address else {
            return Ok(());
        };
        let network = format!("start:{}", network_of(address));
        let subject = AttemptSubject::Start(self.digest.sha256(network.as_bytes()));
        self.count(tenant, &LockoutRules::STARTS, &[subject], caller)
            .await
    }

    /// Counts one attempt against each subject, refusing it if any of them
    /// is locked out.
    async fn count(
        &self,
        tenant: &TenantContext,
        rules: &LockoutRules,
        subjects: &[AttemptSubject],
        caller: Caller,
    ) -> Result<(), DomainError> {
        let now = self.clock.now();
        let mut uow = self.units_of_work.begin(tenant).await?;
        let mut counters = Vec::with_capacity(subjects.len());
        for subject in subjects {
            let counter = self.attempts.lock(uow.as_mut(), subject, now).await?;
            if let Some(until) = counter.locked_until(now) {
                return Err(too_many_attempts(until, now));
            }
            counters.push(counter);
        }
        for mut counter in counters {
            if let Some(until) = counter.count(rules, now) {
                let event = AuthenticationEvent::LockedOut {
                    subject: counter.subject().kind(),
                    until,
                };
                let metadata = EventMetadata::new(
                    tenant.tenant_id(),
                    caller.actor,
                    caller.correlation_id,
                    self.clock.as_ref(),
                );
                uow.record_event(EventEnvelope::new(metadata, &event)?);
            }
            self.attempts.save(uow.as_mut(), &counter).await?;
        }
        uow.commit().await
    }

    /// Records that an attempt for an identifier succeeded: its count and
    /// its lockout history are forgotten. The address keeps its count, so
    /// that signing in to one's own account does not buy more guesses.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn succeeded(
        &self,
        tenant: &TenantContext,
        identifier_key: [u8; 32],
    ) -> Result<(), DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.attempts
            .clear(uow.as_mut(), &AttemptSubject::Identifier(identifier_key))
            .await?;
        uow.commit().await
    }
}

/// The network an address belongs to, as counted: a whole IPv6 network of
/// 64 bits, the block one machine is usually given, or one IPv4 address.
/// What is not an address is counted as it is written.
fn network_of(address: &str) -> String {
    match address.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(address)) => match address.to_ipv4_mapped() {
            Some(mapped) => mapped.to_string(),
            None => {
                let [a, b, c, d, ..] = address.segments();
                format!("{a:x}:{b:x}:{c:x}:{d:x}::/64")
            }
        },
        Ok(std::net::IpAddr::V4(address)) => address.to_string(),
        Err(_) => address.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::network_of;

    #[test]
    fn an_ipv6_network_of_64_bits_is_one_address() {
        assert_eq!(network_of("2001:db8:1:2:aaaa::1"), "2001:db8:1:2::/64");
        assert_eq!(network_of("2001:db8:1:2:bbbb::9"), "2001:db8:1:2::/64");
        assert_ne!(network_of("2001:db8:1:3::1"), network_of("2001:db8:1:2::1"));
        assert_eq!(network_of("::ffff:192.0.2.7"), "192.0.2.7");
        assert_eq!(network_of("192.0.2.7"), "192.0.2.7");
        assert_eq!(network_of("not an address"), "not an address");
    }
}
