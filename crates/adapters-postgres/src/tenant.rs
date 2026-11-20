//! PostgreSQL storage for the tenant context.
//!
//! See `docs/architecture/contexts/tenant.md`, "Storage".

use crate::database::Database;
use crate::uow::{connection, database_error};
use hodor_kernel::{DomainError, TenantId, Timestamp, UnitOfWork};
use hodor_tenant::api::{
    DirectoryEntry, Slug, Tenant, TenantDirectory, TenantRepository, TenantSettings,
    TenantSnapshot, TenantStatus,
};
use sqlx::types::{Json, Uuid};

const SLUG_CONSTRAINT: &str = "tenant_slug_unique";

/// [`TenantRepository`] on `tenant.tenant`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgTenantRepository;

type TenantRow = (
    Uuid,
    String,
    String,
    String,
    Option<String>,
    Json<TenantSettings>,
    Option<Timestamp>,
    Timestamp,
    Timestamp,
    i32,
);

fn corrupted(what: &str) -> DomainError {
    DomainError::internal(
        "tenant.stored_data_invalid",
        "the tenant could not be loaded",
    )
    .with_detail(what.to_owned())
}

fn to_tenant(row: TenantRow) -> Result<Tenant, DomainError> {
    let (
        id,
        slug,
        display_name,
        status,
        status_reason,
        settings,
        deletion,
        created,
        updated,
        version,
    ) = row;
    Ok(Tenant::from_snapshot(TenantSnapshot {
        id: TenantId::from_uuid(id),
        slug: Slug::from_stored(&slug)?,
        display_name,
        status: TenantStatus::from_stored(&status)?,
        status_reason,
        settings: settings.0,
        deletion_scheduled_for: deletion,
        created_at: created,
        updated_at: updated,
        version: u32::try_from(version).map_err(|_| corrupted("negative version"))?,
    }))
}

fn stored_version(tenant: &Tenant) -> Result<i32, DomainError> {
    i32::try_from(tenant.snapshot().version).map_err(|_| corrupted("version out of range"))
}

#[async_trait::async_trait]
impl TenantRepository for PgTenantRepository {
    async fn insert(&self, uow: &mut dyn UnitOfWork, tenant: &Tenant) -> Result<(), DomainError> {
        let state = tenant.snapshot();
        let version = stored_version(tenant)?;
        let result = sqlx::query(
            "INSERT INTO tenant.tenant
                 (tenant_id, id, slug, display_name, status, status_reason, settings,
                  deletion_scheduled_for, created_at, updated_at, version)
             VALUES ($1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(state.id.as_uuid())
        .bind(state.slug.as_str())
        .bind(&state.display_name)
        .bind(state.status.as_str())
        .bind(&state.status_reason)
        .bind(Json(&state.settings))
        .bind(state.deletion_scheduled_for)
        .bind(state.created_at)
        .bind(state.updated_at)
        .bind(version)
        .execute(connection(uow)?)
        .await;

        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(error)) if error.constraint() == Some(SLUG_CONSTRAINT) => {
                Err(DomainError::conflict(
                    "tenant.slug_taken",
                    "another tenant already has this slug",
                ))
            }
            Err(error) => Err(database_error(&error)),
        }
    }

    async fn get(&self, uow: &mut dyn UnitOfWork) -> Result<Option<Tenant>, DomainError> {
        let tenant_id = uow.tenant().tenant_id();
        let row: Option<TenantRow> = sqlx::query_as(
            "SELECT id, slug, display_name, status, status_reason, settings,
                    deletion_scheduled_for, created_at, updated_at, version
             FROM tenant.tenant
             WHERE tenant_id = $1 AND id = $1",
        )
        .bind(tenant_id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.map(to_tenant).transpose()
    }

    async fn update(&self, uow: &mut dyn UnitOfWork, tenant: &Tenant) -> Result<(), DomainError> {
        let state = tenant.snapshot();
        let version = stored_version(tenant)?;
        // The row is addressed by the unit of work's tenant, never by the
        // aggregate's own identifier alone: a tenant can only update itself.
        let context_tenant = uow.tenant().tenant_id();
        let connection = connection(uow)?;

        let updated = sqlx::query(
            "UPDATE tenant.tenant
             SET display_name = $3, status = $4, status_reason = $5, settings = $6,
                 deletion_scheduled_for = $7, updated_at = $8, version = version + 1
             WHERE tenant_id = $1 AND id = $2 AND version = $9",
        )
        .bind(context_tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(&state.display_name)
        .bind(state.status.as_str())
        .bind(&state.status_reason)
        .bind(Json(&state.settings))
        .bind(state.deletion_scheduled_for)
        .bind(state.updated_at)
        .bind(version)
        .execute(&mut *connection)
        .await
        .map_err(|e| database_error(&e))?
        .rows_affected();
        if updated == 1 {
            return Ok(());
        }

        // Nothing was updated: either the tenant is not there, or someone
        // changed it since it was loaded.
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT FROM tenant.tenant WHERE tenant_id = $1 AND id = $2)",
        )
        .bind(context_tenant.as_uuid())
        .bind(state.id.as_uuid())
        .fetch_one(&mut *connection)
        .await
        .map_err(|e| database_error(&e))?;
        Err(if exists {
            DomainError::conflict(
                "tenant.modified_concurrently",
                "the tenant was changed by someone else; reload and try again",
            )
        } else {
            DomainError::not_found("tenant.not_found", "the tenant does not exist")
        })
    }
}

/// [`TenantDirectory`] on `platform.tenant_directory`.
#[derive(Debug, Clone)]
pub struct PgTenantDirectory {
    database: Database,
}

impl PgTenantDirectory {
    /// Reads the directory through the application role's connection.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }
}

fn to_entry(row: (String, Uuid, String)) -> Result<DirectoryEntry, DomainError> {
    let (slug, tenant_id, status) = row;
    Ok(DirectoryEntry {
        slug: Slug::from_stored(&slug)?,
        tenant_id: TenantId::from_uuid(tenant_id),
        status: TenantStatus::from_stored(&status)?,
    })
}

#[async_trait::async_trait]
impl TenantDirectory for PgTenantDirectory {
    async fn find_by_slug(&self, slug: &str) -> Result<Option<DirectoryEntry>, DomainError> {
        let row: Option<(String, Uuid, String)> = sqlx::query_as(
            "SELECT slug, tenant_id, status FROM platform.tenant_directory WHERE slug = $1",
        )
        .bind(slug)
        .fetch_optional(self.database.pool())
        .await
        .map_err(|e| database_error(&e))?;
        row.map(to_entry).transpose()
    }

    async fn list(&self) -> Result<Vec<DirectoryEntry>, DomainError> {
        let rows: Vec<(String, Uuid, String)> = sqlx::query_as(
            "SELECT slug, tenant_id, status FROM platform.tenant_directory ORDER BY slug",
        )
        .fetch_all(self.database.pool())
        .await
        .map_err(|e| database_error(&e))?;
        rows.into_iter().map(to_entry).collect()
    }
}
