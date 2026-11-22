//! PostgreSQL storage for the authorization context.
//!
//! See `docs/architecture/contexts/authorization.md`, "Storage".

use crate::uow::{connection, database_error};
use hodor_authorization::api::{
    Action, BindingSettings, EngineBinding, EngineBindingStore, EngineId, Namespace, Role,
    RoleAssignmentStore,
};
use hodor_kernel::{DomainError, Timestamp, UnitOfWork, UserId};
use std::time::Duration;

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

/// [`EngineBindingStore`] on `authorization.engine_binding`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgEngineBindingStore;

type BindingRow = (
    String,
    String,
    i32,
    bool,
    Vec<String>,
    bool,
    Timestamp,
    Timestamp,
);

const BINDING_COLUMNS: &str = "namespace, engine, timeout_milliseconds, sensitive, \
     fail_open_actions, trust_asserted, created_at, updated_at";

fn binding_corrupted(error: &DomainError) -> DomainError {
    DomainError::internal(
        "authorization.stored_data_invalid",
        "the operation could not be completed",
    )
    .with_detail(format!("stored binding is not valid: {}", error.code()))
}

fn binding_from(row: BindingRow) -> Result<EngineBinding, DomainError> {
    let (namespace, engine, timeout, sensitive, actions, trust_asserted, created, updated) = row;
    let read = || -> Result<EngineBinding, DomainError> {
        let mut settings =
            BindingSettings::new(Namespace::parse(&namespace)?, EngineId::parse(&engine)?);
        settings.time_limit = Duration::from_millis(u64::try_from(timeout).unwrap_or(0));
        settings.sensitive = sensitive;
        settings.fail_open_actions = actions
            .iter()
            .map(|action| Action::parse(action))
            .collect::<Result<_, _>>()?;
        settings.trust_asserted = trust_asserted;
        EngineBinding::restore(settings, created, updated)
    };
    read().map_err(|error| binding_corrupted(&error))
}

#[async_trait::async_trait]
impl EngineBindingStore for PgEngineBindingStore {
    async fn put(
        &self,
        uow: &mut dyn UnitOfWork,
        binding: &EngineBinding,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let settings = binding.settings();
        let timeout = i32::try_from(settings.time_limit.as_millis()).map_err(|_| {
            DomainError::internal(
                "authorization.time_limit_invalid",
                "the operation could not be completed",
            )
        })?;
        let actions: Vec<&str> = settings
            .fail_open_actions
            .iter()
            .map(Action::as_str)
            .collect();
        sqlx::query(
            "INSERT INTO \"authorization\".engine_binding (tenant_id, namespace, engine,
                 timeout_milliseconds, sensitive, fail_open_actions, trust_asserted, created_at,
                 updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (tenant_id, namespace) DO UPDATE SET
                 engine = EXCLUDED.engine,
                 timeout_milliseconds = EXCLUDED.timeout_milliseconds,
                 sensitive = EXCLUDED.sensitive,
                 fail_open_actions = EXCLUDED.fail_open_actions,
                 trust_asserted = EXCLUDED.trust_asserted,
                 updated_at = EXCLUDED.updated_at",
        )
        .bind(tenant.as_uuid())
        .bind(binding.namespace().as_str())
        .bind(binding.engine().as_str())
        .bind(timeout)
        .bind(settings.sensitive)
        .bind(&actions)
        .bind(settings.trust_asserted)
        .bind(binding.created_at())
        .bind(binding.updated_at())
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        namespace: &Namespace,
    ) -> Result<Option<EngineBinding>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<BindingRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {BINDING_COLUMNS} FROM \"authorization\".engine_binding
             WHERE tenant_id = $1 AND namespace = $2"
        )))
        .bind(tenant.as_uuid())
        .bind(namespace.as_str())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.map(binding_from).transpose()
    }

    async fn list(&self, uow: &mut dyn UnitOfWork) -> Result<Vec<EngineBinding>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let rows: Vec<BindingRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {BINDING_COLUMNS} FROM \"authorization\".engine_binding
             WHERE tenant_id = $1 ORDER BY namespace"
        )))
        .bind(tenant.as_uuid())
        .fetch_all(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        rows.into_iter().map(binding_from).collect()
    }

    async fn remove(
        &self,
        uow: &mut dyn UnitOfWork,
        namespace: &Namespace,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let deleted = sqlx::query(
            "DELETE FROM \"authorization\".engine_binding
             WHERE tenant_id = $1 AND namespace = $2",
        )
        .bind(tenant.as_uuid())
        .bind(namespace.as_str())
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(deleted.rows_affected() > 0)
    }
}
