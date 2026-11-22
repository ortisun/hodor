//! The use cases of the credential context.
//!
//! Hashing is slow on purpose. No use case holds a database transaction
//! open while a hash is being computed: each reads, releases the
//! transaction, hashes, and then writes in a second transaction guarded by
//! the record's version.

use crate::application::ports::{PasswordHasher, PasswordStore};
use crate::domain::event::PasswordEvent;
use crate::domain::password::{
    MAX_PASSWORD_BYTES, PasswordRecord, PasswordRules, check_acceptable,
};
use hodor_kernel::{
    Caller, Clock, DomainError, ErrorKind, EventEnvelope, EventMetadata, Secret, TenantContext,
    UnitOfWork, UnitOfWorkFactory, UserId,
};
use std::sync::Arc;

/// A password being given to a user, with what is needed to judge it.
#[derive(Debug)]
pub struct NewPassword<'a> {
    /// The password.
    pub password: &'a Secret<String>,
    /// The tenant's rules.
    pub rules: PasswordRules,
    /// The user's login identifiers, which the password must not equal.
    pub own_names: &'a [&'a str],
}

/// The answer to "is this the right password?". There is deliberately no
/// answer for "no such user" or "no password set".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordCheck {
    /// The password is right.
    Verified {
        /// Whether it must be changed before the user continues.
        must_change: bool,
    },
    /// Wrong password, no password, or no user: indistinguishable.
    Rejected,
}

/// The use cases of the credential context.
#[derive(Clone)]
pub struct CredentialService {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    passwords: Arc<dyn PasswordStore>,
    hasher: Arc<dyn PasswordHasher>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for CredentialService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialService").finish_non_exhaustive()
    }
}

fn wrong_current_password() -> DomainError {
    DomainError::new(
        ErrorKind::Unauthenticated,
        "credential.current_password_wrong",
        "the current password is not correct",
    )
}

impl CredentialService {
    /// Wires the use cases to their ports.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        passwords: Arc<dyn PasswordStore>,
        hasher: Arc<dyn PasswordHasher>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            units_of_work,
            passwords,
            hasher,
            clock,
        }
    }

    /// Gives a user a password without asking for the current one: at
    /// registration, at recovery, or when an administrator resets it.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` if the password breaks a rule or repeats a recent
    /// one, and `Unavailable` if hashing is overloaded.
    pub async fn set_password(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        new: NewPassword<'_>,
        must_change: bool,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let existing = self.read(tenant, user_id).await?;
        self.store_new(
            tenant,
            user_id,
            existing,
            &new,
            must_change,
            caller,
            PasswordEvent::Set {
                user_id,
                must_change,
            },
        )
        .await
    }

    /// Says whether a password would be accepted for a user, by the same
    /// rules as [`Self::set_password`], without storing anything. Lets a
    /// caller refuse a password before doing something that cannot be
    /// undone.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` if the password breaks a rule or repeats a recent
    /// one, and `Unavailable` if hashing is overloaded.
    pub async fn check_new_password(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        new: NewPassword<'_>,
    ) -> Result<(), DomainError> {
        let existing = self.read(tenant, user_id).await?;
        self.check_new(existing.as_ref(), &new).await
    }

    /// Replaces a user's own password after checking the current one.
    ///
    /// # Errors
    ///
    /// Returns `Unauthenticated` with code `credential.current_password_wrong`
    /// if the current password does not verify or the user has none,
    /// `Invalid` if the new one breaks a rule or repeats a recent one, and
    /// `Unavailable` if hashing is overloaded.
    pub async fn change_password(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        current: &Secret<String>,
        new: NewPassword<'_>,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let Some(existing) = self.read(tenant, user_id).await? else {
            self.hasher.verify_nothing(current).await?;
            return Err(wrong_current_password());
        };
        if !self.hasher.verify(current, existing.hash()).await?.matches {
            return Err(wrong_current_password());
        }
        self.store_new(
            tenant,
            user_id,
            Some(existing),
            &new,
            false,
            caller,
            PasswordEvent::Changed { user_id },
        )
        .await
    }

    /// Answers whether a password is right for a user.
    ///
    /// `user_id` is `None` when the sign-in named nobody. The answer and
    /// the work done are then the same as for a wrong password.
    ///
    /// When the password is right and its stored hash was made with other
    /// parameters than the current ones, the hash is renewed. A failure to
    /// renew does not change the answer.
    ///
    /// # Errors
    ///
    /// Returns `Unavailable` if hashing is overloaded, or an error if
    /// storage fails.
    pub async fn verify_password(
        &self,
        tenant: &TenantContext,
        user_id: Option<UserId>,
        password: &Secret<String>,
    ) -> Result<PasswordCheck, DomainError> {
        // An oversized input cannot be a real password. It is replaced by
        // an empty one so that the usual amount of work is still done, on
        // an input of harmless size.
        if password.expose().len() > MAX_PASSWORD_BYTES {
            self.hasher
                .verify_nothing(&Secret::from(String::new()))
                .await?;
            return Ok(PasswordCheck::Rejected);
        }
        let record = match user_id {
            Some(user_id) => self.read(tenant, user_id).await?,
            None => None,
        };
        let Some(mut record) = record else {
            self.hasher.verify_nothing(password).await?;
            return Ok(PasswordCheck::Rejected);
        };

        let verification = self.hasher.verify(password, record.hash()).await?;
        if !verification.matches {
            return Ok(PasswordCheck::Rejected);
        }
        if verification.needs_renewal {
            // Best effort: the user proved the password, and the next
            // sign-in will try again if this does not go through.
            if let Ok(hash) = self.hasher.hash(password).await {
                record.renew_hash(hash);
                let _ = self.write(tenant, &record, false, None).await;
            }
        }
        Ok(PasswordCheck::Verified {
            must_change: record.must_change(),
        })
    }

    /// Removes a user's password and its history.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn remove_password(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        if self.passwords.delete(uow.as_mut(), user_id).await? {
            self.record_event(uow.as_mut(), caller, &PasswordEvent::Removed { user_id })?;
            uow.commit().await?;
        }
        Ok(())
    }

    /// Says whether a user has a password. For administrators and account
    /// pages, never for a sign-in form.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn has_password(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
    ) -> Result<bool, DomainError> {
        Ok(self.read(tenant, user_id).await?.is_some())
    }

    async fn read(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
    ) -> Result<Option<PasswordRecord>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.passwords.get(uow.as_mut(), user_id).await
    }

    /// Checks a new password against every rule, including the user's
    /// previous passwords.
    async fn check_new(
        &self,
        existing: Option<&PasswordRecord>,
        new: &NewPassword<'_>,
    ) -> Result<(), DomainError> {
        check_acceptable(new.password, &new.rules, new.own_names)?;
        if let Some(record) = existing {
            for barred in record.hashes_barred_from_reuse(new.rules.history_depth) {
                if self.hasher.verify(new.password, barred).await?.matches {
                    return Err(DomainError::invalid(
                        "credential.password_reused",
                        "this password was used recently; choose another",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Checks a new password against every rule, hashes it and stores it.
    #[allow(clippy::too_many_arguments)]
    async fn store_new(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        existing: Option<PasswordRecord>,
        new: &NewPassword<'_>,
        must_change: bool,
        caller: Caller,
        event: PasswordEvent,
    ) -> Result<(), DomainError> {
        self.check_new(existing.as_ref(), new).await?;
        let hash = self.hasher.hash(new.password).await?;
        let now = self.clock.now();
        match existing {
            Some(mut record) => {
                record.replace(hash, must_change, new.rules.history_depth, now);
                self.write(tenant, &record, false, Some((caller, event)))
                    .await
            }
            None => {
                let record = PasswordRecord::new(user_id, hash, must_change, now);
                self.write(tenant, &record, true, Some((caller, event)))
                    .await
            }
        }
    }

    async fn write(
        &self,
        tenant: &TenantContext,
        record: &PasswordRecord,
        first: bool,
        event: Option<(Caller, PasswordEvent)>,
    ) -> Result<(), DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        if first {
            self.passwords.insert(uow.as_mut(), record).await?;
        } else {
            self.passwords.update(uow.as_mut(), record).await?;
        }
        if let Some((caller, event)) = event {
            self.record_event(uow.as_mut(), caller, &event)?;
        }
        uow.commit().await
    }

    fn record_event(
        &self,
        uow: &mut dyn UnitOfWork,
        caller: Caller,
        event: &PasswordEvent,
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
