//! PostgreSQL storage of the access control lists of the authorization
//! context.
//!
//! See `docs/architecture/contexts/authorization.md`, "Storage of access
//! control lists".

use crate::uow::{connection, database_error};
use hodor_authorization::api::{
    AccessEntry, AccessEntryFilter, AccessEntryId, AccessListStore, Namespace, PermissionName,
    Subject, SubjectKind,
};
use hodor_kernel::{Cursor, DomainError, Page, PageRequest, Timestamp, UnitOfWork};
use sqlx::types::Uuid;

/// [`AccessListStore`] on `authorization.access_entry`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgAccessListStore;

type EntryRow = (Uuid, String, String, String, String, String, Timestamp);

const COLUMNS: &str =
    "id, namespace, permission, resource_id, principal_kind, principal_id, granted_at";

fn entry_from(row: EntryRow) -> Result<AccessEntry, DomainError> {
    let (id, namespace, permission, resource_id, kind, principal, granted_at) = row;
    let read = || -> Result<AccessEntry, DomainError> {
        AccessEntry::new(
            AccessEntryId::from_uuid(id),
            Namespace::parse(&namespace)?,
            PermissionName::parse(&permission)?,
            &resource_id,
            Subject::new(SubjectKind::parse_principal(&kind)?, &principal)?,
            granted_at,
        )
    };
    read().map_err(|error| {
        DomainError::internal(
            "authorization.stored_data_invalid",
            "the operation could not be completed",
        )
        .with_detail(format!("stored entry is not valid: {}", error.code()))
    })
}

#[async_trait::async_trait]
impl AccessListStore for PgAccessListStore {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        entry: &AccessEntry,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let inserted = sqlx::query(
            "INSERT INTO \"authorization\".access_entry (tenant_id, id, namespace, permission,
                 resource_id, principal_kind, principal_id, granted_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT ON CONSTRAINT access_entry_once DO NOTHING",
        )
        .bind(tenant.as_uuid())
        .bind(entry.id().as_uuid())
        .bind(entry.namespace().as_str())
        .bind(entry.permission().as_str())
        .bind(entry.resource_id())
        .bind(entry.principal().kind().as_str())
        .bind(entry.principal().id())
        .bind(entry.granted_at())
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(inserted.rows_affected() > 0)
    }

    async fn same_as(
        &self,
        uow: &mut dyn UnitOfWork,
        entry: &AccessEntry,
    ) -> Result<Option<AccessEntry>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<EntryRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM \"authorization\".access_entry
             WHERE tenant_id = $1 AND namespace = $2 AND permission = $3 AND resource_id = $4
               AND principal_kind = $5 AND principal_id = $6"
        )))
        .bind(tenant.as_uuid())
        .bind(entry.namespace().as_str())
        .bind(entry.permission().as_str())
        .bind(entry.resource_id())
        .bind(entry.principal().kind().as_str())
        .bind(entry.principal().id())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.map(entry_from).transpose()
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: AccessEntryId,
    ) -> Result<Option<AccessEntry>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<EntryRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM \"authorization\".access_entry
             WHERE tenant_id = $1 AND id = $2"
        )))
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.map(entry_from).transpose()
    }

    async fn remove(
        &self,
        uow: &mut dyn UnitOfWork,
        id: AccessEntryId,
    ) -> Result<Option<AccessEntry>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<EntryRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "DELETE FROM \"authorization\".access_entry
             WHERE tenant_id = $1 AND id = $2
             RETURNING {COLUMNS}"
        )))
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.map(entry_from).transpose()
    }

    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        filter: &AccessEntryFilter,
        page: &PageRequest,
    ) -> Result<Page<AccessEntry>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let after: Option<Uuid> = page
            .cursor()
            .map(|cursor| {
                cursor
                    .as_str()
                    .parse::<AccessEntryId>()
                    .map(|id| id.as_uuid())
                    .map_err(|_| {
                        DomainError::invalid(
                            "request.query_invalid",
                            "the cursor is not one of this list",
                        )
                    })
            })
            .transpose()?;
        let limit = i64::from(page.limit());
        let rows: Vec<EntryRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM \"authorization\".access_entry
             WHERE tenant_id = $1 AND namespace = $2
               AND ($3::text IS NULL OR resource_kind = $3)
               AND ($4::text IS NULL OR resource_id = $4)
               AND ($5::text IS NULL OR (principal_kind = $5 AND principal_id = $6))
               AND ($7::uuid IS NULL OR id > $7)
             ORDER BY id
             LIMIT $8"
        )))
        .bind(tenant.as_uuid())
        .bind(filter.namespace.as_str())
        .bind(filter.resource_kind.as_deref())
        .bind(filter.resource_id.as_deref())
        .bind(filter.principal.as_ref().map(|p| p.kind().as_str()))
        .bind(filter.principal.as_ref().map(Subject::id))
        .bind(after)
        .bind(limit + 1)
        .fetch_all(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        let mut items = rows
            .into_iter()
            .map(entry_from)
            .collect::<Result<Vec<_>, _>>()?;
        let more = items.len() > usize::try_from(page.limit()).unwrap_or(usize::MAX);
        items.truncate(usize::try_from(page.limit()).unwrap_or(usize::MAX));
        let next_cursor = if more {
            items.last().map(|last| Cursor::new(last.id().to_string()))
        } else {
            None
        };
        Ok(Page { items, next_cursor })
    }

    async fn allowing(
        &self,
        uow: &mut dyn UnitOfWork,
        namespace: &Namespace,
        permission: &PermissionName,
        resource_id: &str,
        principals: &[Subject],
        limit: usize,
    ) -> Result<Vec<AccessEntry>, DomainError> {
        if principals.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        let tenant = uow.tenant().tenant_id();
        let kinds: Vec<&str> = principals.iter().map(|p| p.kind().as_str()).collect();
        let ids: Vec<&str> = principals.iter().map(Subject::id).collect();
        let rows: Vec<EntryRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM \"authorization\".access_entry
             WHERE tenant_id = $1 AND namespace = $2 AND resource_kind = $3
               AND resource_id = $4 AND permission = $5
               AND (principal_kind, principal_id) IN (
                   SELECT kind, id FROM unnest($6::text[], $7::text[]) AS asked (kind, id))
             ORDER BY id
             LIMIT $8"
        )))
        .bind(tenant.as_uuid())
        .bind(namespace.as_str())
        .bind(
            permission
                .as_str()
                .split_once(':')
                .map_or("", |(kind, _)| kind),
        )
        .bind(resource_id)
        .bind(permission.as_str())
        .bind(kinds)
        .bind(ids)
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        rows.into_iter().map(entry_from).collect()
    }
}
