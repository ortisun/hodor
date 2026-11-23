//! Recovery codes: the port and the use cases.

use crate::domain::recovery_code::{
    CODES_PER_SET, RANDOM_BYTES, RecoveryCodeEvent, RecoveryCodeSet, RecoveryCodeSetId,
    RecoveryCodes, code_from_bytes, read_code,
};
use hodor_kernel::{
    Caller, Clock, Digest, DomainError, EventEnvelope, EventMetadata, RandomSource, Secret,
    TenantContext, UnitOfWork, UnitOfWorkFactory, UserId,
};
use std::sync::Arc;

/// Stores recovery codes. Every method works inside the tenant the unit of
/// work is bound to.
#[async_trait::async_trait]
pub trait RecoveryCodeStore: Send + Sync {
    /// Stores a set in place of the user's earlier set, if any, whose codes
    /// all stop working.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` with `credential.recovery_codes_conflict` when
    /// another set was stored for the user at the same moment, and an
    /// error if storage fails.
    async fn replace(
        &self,
        uow: &mut dyn UnitOfWork,
        set: &RecoveryCodeSet,
    ) -> Result<(), DomainError>;

    /// Marks the user's code with this hash used, only if it is unused.
    /// Answers whether it was; of many calls with the same code at the
    /// same moment, one answers `true`.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn use_code(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
        code_hash: &[u8; 32],
    ) -> Result<bool, DomainError>;

    /// How many unused codes the user has.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn unused(&self, uow: &mut dyn UnitOfWork, user_id: UserId) -> Result<u32, DomainError>;

    /// Removes the user's set. Answers whether there was one.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn remove(&self, uow: &mut dyn UnitOfWork, user_id: UserId) -> Result<bool, DomainError>;
}

/// The answer to a recovery code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryCodeCheck {
    /// The code is one of the user's and was not used; it is now used.
    Verified {
        /// How many unused codes are left.
        remaining: u32,
    },
    /// Anything else. No reason is given, on purpose.
    Rejected,
}

/// The use cases of recovery codes. See
/// `docs/architecture/contexts/credential.md`, "Recovery codes".
#[derive(Clone)]
pub struct RecoveryCodeService {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    store: Arc<dyn RecoveryCodeStore>,
    digest: Arc<dyn Digest>,
    random: Arc<dyn RandomSource>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for RecoveryCodeService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryCodeService")
            .finish_non_exhaustive()
    }
}

impl RecoveryCodeService {
    /// Wires the use cases to their ports.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        store: Arc<dyn RecoveryCodeStore>,
        digest: Arc<dyn Digest>,
        random: Arc<dyn RandomSource>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            units_of_work,
            store,
            digest,
            random,
            clock,
        }
    }

    /// Makes a set of codes in place of the user's set, if any, and
    /// returns its codes once.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` with `credential.recovery_codes_conflict` when
    /// another set was generated for the user at the same moment, and an
    /// error if storage fails.
    pub async fn generate(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        caller: Caller,
    ) -> Result<RecoveryCodes, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let codes = self.store_new_set(uow.as_mut(), user_id, caller).await?;
        uow.commit().await?;
        Ok(codes)
    }

    /// Makes a set of codes only when the user has no unused code, and
    /// returns its codes once. Asked when a first second factor is
    /// enrolled.
    ///
    /// # Errors
    ///
    /// As [`Self::generate`].
    pub async fn generate_if_none(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        caller: Caller,
    ) -> Result<Option<RecoveryCodes>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        if self.store.unused(uow.as_mut(), user_id).await? > 0 {
            return Ok(None);
        }
        let codes = self.store_new_set(uow.as_mut(), user_id, caller).await?;
        uow.commit().await?;
        Ok(Some(codes))
    }

    /// Checks a recovery code of the user. A right code is accepted once:
    /// it is marked used in the same call.
    ///
    /// `None` stands for a sign-in whose identifier belongs to nobody; the
    /// answer is then `Rejected`, as for a user without codes.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails. A wrong code is not an error.
    pub async fn verify(
        &self,
        tenant: &TenantContext,
        user_id: Option<UserId>,
        code: &Secret<String>,
        caller: Caller,
    ) -> Result<RecoveryCodeCheck, DomainError> {
        let (Some(user_id), Some(read)) = (user_id, read_code(code.expose())) else {
            return Ok(RecoveryCodeCheck::Rejected);
        };
        let hash = self.digest.sha256(read.as_bytes());
        let mut uow = self.units_of_work.begin(tenant).await?;
        if !self.store.use_code(uow.as_mut(), user_id, &hash).await? {
            return Ok(RecoveryCodeCheck::Rejected);
        }
        let remaining = self.store.unused(uow.as_mut(), user_id).await?;
        self.record(
            uow.as_mut(),
            caller,
            &RecoveryCodeEvent::Used { user_id, remaining },
        )?;
        uow.commit().await?;
        Ok(RecoveryCodeCheck::Verified { remaining })
    }

    /// How many unused codes the user has.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn unused(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
    ) -> Result<u32, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.store.unused(uow.as_mut(), user_id).await
    }

    /// Removes the user's set. Answers whether there was one.
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
            self.record(
                uow.as_mut(),
                caller,
                &RecoveryCodeEvent::Removed { user_id },
            )?;
        }
        uow.commit().await?;
        Ok(removed)
    }

    async fn store_new_set(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
        caller: Caller,
    ) -> Result<RecoveryCodes, DomainError> {
        let mut codes = Vec::with_capacity(CODES_PER_SET);
        let mut code_hashes = Vec::with_capacity(CODES_PER_SET);
        while codes.len() < CODES_PER_SET {
            let mut bytes = [0_u8; RANDOM_BYTES];
            self.random.fill(&mut bytes);
            let code = code_from_bytes(&bytes);
            let hash = self
                .digest
                .sha256(read_code(&code).unwrap_or_default().as_bytes());
            // Two equal codes in 80 random bits do not happen; if they
            // did, the set would still hold ten different ones.
            if !code_hashes.contains(&hash) {
                code_hashes.push(hash);
                codes.push(code);
            }
        }
        let set = RecoveryCodeSet {
            id: RecoveryCodeSetId::generate(),
            user_id,
            created_at: self.clock.now(),
            code_hashes,
        };
        self.store.replace(uow, &set).await?;
        self.record(uow, caller, &RecoveryCodeEvent::Generated { user_id })?;
        Ok(RecoveryCodes::new(codes))
    }

    fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        caller: Caller,
        event: &RecoveryCodeEvent,
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
