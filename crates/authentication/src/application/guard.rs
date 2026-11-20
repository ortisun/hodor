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
        let now = self.clock.now();
        let mut subjects = vec![AttemptSubject::Identifier(identifier_key)];
        if let Some(address) = address {
            subjects.push(AttemptSubject::Address(
                self.digest.sha256(address.as_bytes()),
            ));
        }
        // Always in the same order, so that two attempts can never wait
        // for each other.
        subjects.sort();

        let mut uow = self.units_of_work.begin(tenant).await?;
        let mut counters = Vec::with_capacity(subjects.len());
        for subject in &subjects {
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
