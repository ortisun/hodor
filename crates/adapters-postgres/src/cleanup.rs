//! Cleanup jobs: removing rows that nothing can use any more.
//!
//! Like the outbox, a job finds its work across tenants through a
//! connection as a member of `hodor_platform`, and does the work inside
//! each tenant as the application role. See
//! `docs/architecture/multi-tenancy.md`, "Cross-tenant operations".

use crate::database::Database;
use crate::federation::PgPendingAuthorizationStore;
use crate::oauth_access_token::PgAccessTokenRecordStore;
use crate::uow::PgUnitOfWork;
use hodor_federation::api::PendingAuthorizationStore as _;
use hodor_kernel::{DomainError, TenantContext, TenantId, Timestamp, UnitOfWork as _};
use hodor_oauth::api::AccessTokenRecordStore as _;
use sqlx::PgPool;
use sqlx::types::Uuid;

/// The most tenants one pass looks at.
const TENANTS_PER_PASS: i64 = 100;

/// What one pass of a cleanup job removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CleanupReport {
    /// Tenants that had something to remove.
    pub tenants: u64,
    /// Rows removed.
    pub removed: u64,
}

/// Removes pending authorizations that expired: sign-ins that left for a
/// provider and never came back.
#[derive(Debug, Clone)]
pub struct PendingAuthorizationCleanup {
    platform: PgPool,
    database: Database,
}

impl PendingAuthorizationCleanup {
    /// `platform` must connect as a member of `hodor_platform`; it is used
    /// only to find the tenants that have expired pending authorizations.
    /// They are removed through `database`, as the application role, in
    /// each tenant.
    #[must_use]
    pub const fn new(platform: PgPool, database: Database) -> Self {
        Self { platform, database }
    }

    /// Removes, in each tenant that has some, up to `batch` pending
    /// authorizations that had expired at `now`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be reached.
    pub async fn run(&self, now: Timestamp, batch: u32) -> Result<CleanupReport, DomainError> {
        let tenants: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT DISTINCT tenant_id FROM federation.pending_authorization
             WHERE expires_at <= $1
             LIMIT $2",
        )
        .bind(now)
        .bind(TENANTS_PER_PASS)
        .fetch_all(&self.platform)
        .await
        .map_err(|error| crate::uow::database_error(&error))?;

        let mut report = CleanupReport::default();
        for (tenant_id,) in tenants {
            // The tenant comes from a stored row, not from any request:
            // the worker's job loader is one of the places allowed to
            // establish a tenant context.
            let tenant = TenantContext::assume(TenantId::from_uuid(tenant_id));
            let transaction = self
                .database
                .begin(&tenant)
                .await
                .map_err(|error| crate::uow::database_error(&error))?;
            let mut unit = PgUnitOfWork::new(transaction, tenant.clone());
            let removed = PgPendingAuthorizationStore
                .remove_expired(&mut unit, now, batch)
                .await?;
            Box::new(unit).commit().await?;
            report.tenants += 1;
            report.removed += removed;
        }
        Ok(report)
    }
}

/// Removes the records of access tokens that expired from the register: a
/// token past its `exp` is refused whatever its record says, so the record
/// has nothing left to tell.
#[derive(Debug, Clone)]
pub struct AccessTokenCleanup {
    platform: PgPool,
    database: Database,
}

impl AccessTokenCleanup {
    /// `platform` must connect as a member of `hodor_platform`; it is used
    /// only to find the tenants that have expired records. They are removed
    /// through `database`, as the application role, in each tenant.
    #[must_use]
    pub const fn new(platform: PgPool, database: Database) -> Self {
        Self { platform, database }
    }

    /// Removes, in each tenant that has some, up to `batch` records of
    /// access tokens that had expired at `now`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be reached.
    pub async fn run(&self, now: Timestamp, batch: u32) -> Result<CleanupReport, DomainError> {
        let tenants: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT DISTINCT tenant_id FROM oauth.access_token
             WHERE expires_at <= $1
             LIMIT $2",
        )
        .bind(now)
        .bind(TENANTS_PER_PASS)
        .fetch_all(&self.platform)
        .await
        .map_err(|error| crate::uow::database_error(&error))?;

        let mut report = CleanupReport::default();
        for (tenant_id,) in tenants {
            // The tenant comes from a stored row, not from any request, as
            // for the pending authorizations above.
            let tenant = TenantContext::assume(TenantId::from_uuid(tenant_id));
            let transaction = self
                .database
                .begin(&tenant)
                .await
                .map_err(|error| crate::uow::database_error(&error))?;
            let mut unit = PgUnitOfWork::new(transaction, tenant.clone());
            let removed = PgAccessTokenRecordStore
                .remove_expired(&mut unit, now, batch)
                .await?;
            Box::new(unit).commit().await?;
            report.tenants += 1;
            report.removed += removed;
        }
        Ok(report)
    }
}
