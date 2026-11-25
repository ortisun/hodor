//! Authenticator applications: the ports and the use cases.

use crate::domain::totp::{
    SEALING_PURPOSE, SECRET_BYTES, Totp, TotpEnrollment, TotpEvent, TotpId, candidate_steps,
    code_from_mac, parse_code, step_at,
};
use hodor_kernel::{
    Caller, Clock, DomainError, EventEnvelope, EventMetadata, RandomSource, Secret, SecretBox,
    TenantContext, Timestamp, UnitOfWork, UnitOfWorkFactory, UserId,
};
use std::sync::Arc;

/// Computes HMAC-SHA-1, from which the codes of an authenticator
/// application are made. A port, because Hodor implements no
/// cryptography of its own.
pub trait HmacSha1: Send + Sync {
    /// The HMAC-SHA-1 of `message` under `key`.
    fn mac(&self, key: &[u8], message: &[u8]) -> [u8; 20];
}

/// The code an authenticator application shows at `moment` for `secret`,
/// as six digits. What the person's phone computes; used to check codes
/// and by tests that play the part of the phone.
#[must_use]
pub fn totp_code_at(mac: &dyn HmacSha1, secret: &[u8], moment: Timestamp) -> String {
    format!("{:06}", code_of_step(mac, secret, step_at(moment)))
}

fn code_of_step(mac: &dyn HmacSha1, secret: &[u8], step: u64) -> u32 {
    code_from_mac(&mac.mac(secret, &step.to_be_bytes()))
}

/// Stores authenticator applications. Every method works inside the
/// tenant the unit of work is bound to.
#[async_trait::async_trait]
pub trait TotpStore: Send + Sync {
    /// Loads the user's application in use, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn active(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
    ) -> Result<Option<Totp>, DomainError>;

    /// Loads the user's enrollment waiting to be confirmed, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn pending(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
    ) -> Result<Option<Totp>, DomainError>;

    /// Stores a new enrollment, in place of any earlier one of the same
    /// user still waiting to be confirmed.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn replace_pending(
        &self,
        uow: &mut dyn UnitOfWork,
        enrollment: &Totp,
    ) -> Result<(), DomainError>;

    /// Puts a confirmed enrollment in use, removing the application the
    /// user had in use before.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` with code `credential.totp_enrollment_not_found`
    /// if the enrollment is no longer stored as pending.
    async fn activate(&self, uow: &mut dyn UnitOfWork, confirmed: &Totp)
    -> Result<(), DomainError>;

    /// Marks `step` as the last used step of an application in use, only
    /// if it is later than the one stored. Answers whether it was; of two
    /// calls with the same step at the same moment, one answers `true`.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn use_step(
        &self,
        uow: &mut dyn UnitOfWork,
        id: TotpId,
        step: u64,
    ) -> Result<bool, DomainError>;

    /// Removes the user's application in use and enrollment waiting to be
    /// confirmed. Answers whether there was an application in use.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn remove(&self, uow: &mut dyn UnitOfWork, user_id: UserId) -> Result<bool, DomainError>;
}

/// The answer to a code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpCheck {
    /// The code is right and was not used before; it is now used.
    Verified,
    /// Anything else. No reason is given, on purpose.
    Rejected,
}

/// The use cases of authenticator applications. See
/// `docs/architecture/contexts/credential.md`, "Authenticator
/// applications".
#[derive(Clone)]
pub struct TotpService {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    store: Arc<dyn TotpStore>,
    secrets: Arc<dyn SecretBox>,
    mac: Arc<dyn HmacSha1>,
    random: Arc<dyn RandomSource>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for TotpService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpService").finish_non_exhaustive()
    }
}

fn enrollment_not_found() -> DomainError {
    DomainError::not_found(
        "credential.totp_enrollment_not_found",
        "there is no enrollment of an authenticator application waiting to be confirmed; begin again",
    )
}

impl TotpService {
    /// Wires the use cases to their ports.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        store: Arc<dyn TotpStore>,
        secrets: Arc<dyn SecretBox>,
        mac: Arc<dyn HmacSha1>,
        random: Arc<dyn RandomSource>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            units_of_work,
            store,
            secrets,
            mac,
            random,
            clock,
        }
    }

    /// Begins enrolling an authenticator application for a user: makes a
    /// secret and keeps it, sealed, waiting to be confirmed. The secret is
    /// returned once, with its `otpauth://` address naming `issuer` and
    /// `account`, and is not available again.
    ///
    /// # Errors
    ///
    /// Returns an error if the secret cannot be sealed or storage fails.
    pub async fn begin_enrollment(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        issuer: &str,
        account: &str,
    ) -> Result<TotpEnrollment, DomainError> {
        let mut secret = vec![0_u8; SECRET_BYTES];
        self.random.fill(&mut secret);
        let secret = Secret::new(secret);
        let sealed = self.secrets.seal(tenant, SEALING_PURPOSE, &secret).await?;
        let enrollment = Totp::begin(user_id, sealed, self.clock.now());
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.store
            .replace_pending(uow.as_mut(), &enrollment)
            .await?;
        uow.commit().await?;
        Ok(TotpEnrollment::new(
            enrollment.id(),
            secret.expose(),
            issuer,
            account,
        ))
    }

    /// Confirms an enrollment with a code the application shows, and puts
    /// the application in use in place of the one the user had.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` with `credential.totp_enrollment_not_found` when
    /// no enrollment waits or it waited too long, and `Invalid` with
    /// `credential.totp_code_wrong` when the code is not right; the
    /// enrollment then still waits.
    pub async fn confirm_enrollment(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        code: &Secret<String>,
        caller: Caller,
    ) -> Result<(), DomainError> {
        self.confirm(tenant, user_id, None, code, caller).await
    }

    /// Confirms the enrollment `id`, as [`Self::confirm_enrollment`] does,
    /// only while it is the one waiting: an enrollment begun since, by
    /// anyone, is refused as if none waited.
    ///
    /// # Errors
    ///
    /// As [`Self::confirm_enrollment`].
    pub async fn confirm_enrollment_of(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        id: TotpId,
        code: &Secret<String>,
        caller: Caller,
    ) -> Result<(), DomainError> {
        self.confirm(tenant, user_id, Some(id), code, caller).await
    }

    async fn confirm(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        named: Option<TotpId>,
        code: &Secret<String>,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let now = self.clock.now();
        let mut uow = self.units_of_work.begin(tenant).await?;
        let mut enrollment = self
            .store
            .pending(uow.as_mut(), user_id)
            .await?
            .filter(|enrollment| enrollment.can_be_confirmed_at(now))
            .filter(|enrollment| named.is_none_or(|id| enrollment.id() == id))
            .ok_or_else(enrollment_not_found)?;
        let Some(step) = self.matching_step(tenant, &enrollment, code, now).await? else {
            return Err(DomainError::invalid(
                "credential.totp_code_wrong",
                "that is not the code the authenticator application shows",
            ));
        };
        let event = enrollment.confirm(step, now);
        self.store.activate(uow.as_mut(), &enrollment).await?;
        self.record(uow.as_mut(), caller, &event)?;
        uow.commit().await
    }

    /// Checks a code of the user's application in use. A right code is
    /// accepted once: it is marked used in the same call.
    ///
    /// `None` stands for a sign-in whose identifier belongs to nobody; the
    /// answer is then `Rejected`, as for a user without an application.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails or the stored secret does not
    /// open. A wrong code is not an error.
    pub async fn verify(
        &self,
        tenant: &TenantContext,
        user_id: Option<UserId>,
        code: &Secret<String>,
    ) -> Result<TotpCheck, DomainError> {
        let Some(user_id) = user_id else {
            return Ok(TotpCheck::Rejected);
        };
        let now = self.clock.now();
        let mut uow = self.units_of_work.begin(tenant).await?;
        let Some(active) = self.store.active(uow.as_mut(), user_id).await? else {
            return Ok(TotpCheck::Rejected);
        };
        let Some(step) = self.matching_step(tenant, &active, code, now).await? else {
            return Ok(TotpCheck::Rejected);
        };
        if !self.store.use_step(uow.as_mut(), active.id(), step).await? {
            return Ok(TotpCheck::Rejected);
        }
        uow.commit().await?;
        Ok(TotpCheck::Verified)
    }

    /// Whether the user has an application in use.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn has_totp(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
    ) -> Result<bool, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        Ok(self.store.active(uow.as_mut(), user_id).await?.is_some())
    }

    /// Removes the user's application in use and any enrollment waiting
    /// to be confirmed. Answers whether there was an application in use.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn remove(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        caller: Caller,
    ) -> Result<bool, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let removed = self.store.remove(uow.as_mut(), user_id).await?;
        if removed {
            self.record(uow.as_mut(), caller, &TotpEvent::Removed { user_id })?;
        }
        uow.commit().await?;
        Ok(removed)
    }

    /// The step of the code typed, if it is right for this application at
    /// `now` and later than the last step used. Every candidate step is
    /// computed, so the time taken does not depend on which one matches.
    async fn matching_step(
        &self,
        tenant: &TenantContext,
        totp: &Totp,
        code: &Secret<String>,
        now: Timestamp,
    ) -> Result<Option<u64>, DomainError> {
        let Some(typed) = parse_code(code.expose()) else {
            return Ok(None);
        };
        let secret = self
            .secrets
            .open(tenant, SEALING_PURPOSE, &totp.snapshot().sealed_secret)
            .await?;
        let mut matched = None;
        for step in candidate_steps(now) {
            if code_of_step(self.mac.as_ref(), secret.expose(), step) == typed
                && totp.accepts_step(step)
            {
                matched = Some(step);
            }
        }
        Ok(matched)
    }

    fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        caller: Caller,
        event: &TotpEvent,
    ) -> Result<(), DomainError> {
        let metadata = EventMetadata::new(
            uow.tenant().tenant_id(),
            caller.actor,
            caller.correlation_id,
            self.clock.as_ref(),
        );
        uow.record_event(EventEnvelope::new(metadata, event)?);
        Ok(())
    }
}
