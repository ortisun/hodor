//! The use cases of the tenant context.

use crate::application::ports::{DirectoryEntry, TenantDirectory, TenantRepository};
use crate::domain::event::TenantEvent;
use crate::domain::settings::{RegistrationPolicy, TenantSettings};
use crate::domain::slug::Slug;
use crate::domain::tenant::Tenant;
use hodor_kernel::{
    Actor, Clock, CorrelationId, DomainError, EventEnvelope, EventMetadata, TenantContext,
    UnitOfWork, UnitOfWorkFactory,
};
use std::sync::Arc;
use time::Duration;

/// What is needed to create a tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateTenant {
    /// The slug to give the tenant. Ignored for the system tenant.
    pub slug: String,
    /// The tenant's display name.
    pub display_name: String,
    /// Whether anyone may register in the tenant.
    pub open_registration: bool,
    /// Create the system tenant, which has the reserved `system` slug.
    pub system: bool,
}

/// The use cases of the tenant context.
#[derive(Clone)]
pub struct TenantService {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    tenants: Arc<dyn TenantRepository>,
    directory: Arc<dyn TenantDirectory>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for TenantService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantService").finish_non_exhaustive()
    }
}

/// Who is acting and on behalf of which request. Carried into the events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caller {
    /// Who causes the change.
    pub actor: Actor,
    /// The request or job that causes it.
    pub correlation_id: CorrelationId,
}

impl TenantService {
    /// Wires the use cases to their ports.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        tenants: Arc<dyn TenantRepository>,
        directory: Arc<dyn TenantDirectory>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            units_of_work,
            tenants,
            directory,
            clock,
        }
    }

    /// Creates and activates a tenant with default settings.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` if the slug or name breaks a rule, and `Conflict`
    /// with code `tenant.slug_taken` if the slug is in use.
    pub async fn create(
        &self,
        command: CreateTenant,
        caller: Caller,
    ) -> Result<Tenant, DomainError> {
        let slug = if command.system {
            Slug::system()
        } else {
            Slug::parse(&command.slug)?
        };
        let now = self.clock.now();
        let (mut tenant, created) = Tenant::create(slug, &command.display_name, now)?;
        let mut events = vec![created];
        if command.open_registration {
            let settings = TenantSettings {
                registration: RegistrationPolicy::Open,
                ..TenantSettings::default()
            };
            events.push(tenant.change_settings(settings, now)?);
        }
        events.push(tenant.activate(now)?);

        // Creating a tenant is where its context begins: the identifier was
        // generated a moment ago, not taken from any request.
        let context = TenantContext::assume(tenant.id());
        let mut uow = self.units_of_work.begin(&context).await?;
        self.tenants.insert(uow.as_mut(), &tenant).await?;
        self.record(uow.as_mut(), caller, &events)?;
        uow.commit().await?;
        Ok(tenant)
    }

    /// Returns the tenant of the given context.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the tenant does not exist.
    pub async fn get(&self, context: &TenantContext) -> Result<Tenant, DomainError> {
        let mut uow = self.units_of_work.begin(context).await?;
        self.load(uow.as_mut()).await
    }

    /// Suspends the tenant, recording why.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` if the tenant is not active, and `Invalid` if the
    /// reason is empty.
    pub async fn suspend(
        &self,
        context: &TenantContext,
        reason: &str,
        caller: Caller,
    ) -> Result<Tenant, DomainError> {
        let now = self.clock.now();
        self.change(context, caller, |tenant| tenant.suspend(reason, now))
            .await
    }

    /// Returns a suspended tenant to active.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` if the tenant is not suspended.
    pub async fn reactivate(
        &self,
        context: &TenantContext,
        caller: Caller,
    ) -> Result<Tenant, DomainError> {
        let now = self.clock.now();
        self.change(context, caller, |tenant| tenant.reactivate(now))
            .await
    }

    /// Schedules the tenant's deletion after a grace period.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` if the tenant is neither active nor suspended, and
    /// `Invalid` if the grace period is shorter than one day.
    pub async fn schedule_deletion(
        &self,
        context: &TenantContext,
        grace: Option<Duration>,
        caller: Caller,
    ) -> Result<Tenant, DomainError> {
        let now = self.clock.now();
        self.change(context, caller, |tenant| {
            tenant.schedule_deletion(grace, now)
        })
        .await
    }

    /// Cancels a scheduled deletion; the tenant becomes suspended.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` if no deletion is pending.
    pub async fn cancel_deletion(
        &self,
        context: &TenantContext,
        caller: Caller,
    ) -> Result<Tenant, DomainError> {
        let now = self.clock.now();
        self.change(context, caller, |tenant| tenant.cancel_deletion(now))
            .await
    }

    /// Replaces the tenant's settings.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` if the settings break a rule.
    pub async fn change_settings(
        &self,
        context: &TenantContext,
        settings: TenantSettings,
        caller: Caller,
    ) -> Result<Tenant, DomainError> {
        let now = self.clock.now();
        self.change(context, caller, |tenant| {
            tenant.change_settings(settings, now)
        })
        .await
    }

    /// Returns what the directory knows about a slug.
    ///
    /// # Errors
    ///
    /// Returns an error if the lookup fails.
    pub async fn find_by_slug(&self, slug: &str) -> Result<Option<DirectoryEntry>, DomainError> {
        self.directory.find_by_slug(slug).await
    }

    /// Returns every tenant, ordered by slug.
    ///
    /// # Errors
    ///
    /// Returns an error if the lookup fails.
    pub async fn list(&self) -> Result<Vec<DirectoryEntry>, DomainError> {
        self.directory.list().await
    }

    /// Loads the tenant, applies one change and stores the result with its
    /// event, all in one unit of work.
    async fn change(
        &self,
        context: &TenantContext,
        caller: Caller,
        apply: impl FnOnce(&mut Tenant) -> Result<TenantEvent, DomainError> + Send,
    ) -> Result<Tenant, DomainError> {
        let mut uow = self.units_of_work.begin(context).await?;
        let mut tenant = self.load(uow.as_mut()).await?;
        let event = apply(&mut tenant)?;
        self.tenants.update(uow.as_mut(), &tenant).await?;
        self.record(uow.as_mut(), caller, &[event])?;
        uow.commit().await?;
        Ok(tenant)
    }

    async fn load(&self, uow: &mut dyn UnitOfWork) -> Result<Tenant, DomainError> {
        self.tenants
            .get(uow)
            .await?
            .ok_or_else(|| DomainError::not_found("tenant.not_found", "the tenant does not exist"))
    }

    fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        caller: Caller,
        events: &[TenantEvent],
    ) -> Result<(), DomainError> {
        let tenant_id = uow.tenant().tenant_id();
        for event in events {
            let metadata = EventMetadata::new(
                tenant_id,
                caller.actor,
                caller.correlation_id,
                self.clock.as_ref(),
            );
            uow.record_event(EventEnvelope::new(metadata, event)?);
        }
        Ok(())
    }
}
