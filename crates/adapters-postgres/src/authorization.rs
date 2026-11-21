//! PostgreSQL storage for the authorization context.
//!
//! See `docs/architecture/contexts/authorization.md`, "Storage".

use crate::uow::{connection, database_error};
use hodor_authorization::api::{Role, RoleAssignmentStore};
use hodor_kernel::{DomainError, Timestamp, UnitOfWork, UserId};

/// [`RoleAssignmentStore`] on `authorization.role_assignment`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgRoleAssignmentStore;

#[async_trait::async_trait]
impl RoleAssignmentStore for PgRoleAssignmentStore {
    async fn assign(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
        role: Role,
        now: Timestamp,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let inserted = sqlx::query(
            "INSERT INTO \"authorization\".role_assignment (tenant_id, user_id, role, assigned_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (tenant_id, user_id, role) DO NOTHING",
        )
        .bind(tenant.as_uuid())
        .bind(user_id.as_uuid())
        .bind(role.as_str())
        .bind(now)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(inserted.rows_affected() > 0)
    }

    async fn revoke(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
        role: Role,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let deleted = sqlx::query(
            "DELETE FROM \"authorization\".role_assignment
             WHERE tenant_id = $1 AND user_id = $2 AND role = $3",
        )
        .bind(tenant.as_uuid())
        .bind(user_id.as_uuid())
        .bind(role.as_str())
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(deleted.rows_affected() > 0)
    }

    async fn roles_of(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
    ) -> Result<Vec<Role>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let names: Vec<String> = sqlx::query_scalar(
            "SELECT role FROM \"authorization\".role_assignment
             WHERE tenant_id = $1 AND user_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(user_id.as_uuid())
        .fetch_all(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        let mut roles = names
            .iter()
            .map(|name| {
                Role::from_name(name).map_err(|_| {
                    DomainError::internal(
                        "authorization.stored_data_invalid",
                        "the operation could not be completed",
                    )
                    .with_detail(format!("unknown role `{name}`"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        // Always in the same order, whatever order the rows come in.
        roles.sort();
        Ok(roles)
    }
}
