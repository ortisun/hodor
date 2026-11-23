//! PostgreSQL storage for the authorization context.
//!
//! See `docs/architecture/contexts/authorization.md`, "Storage".

use crate::uow::{connection, database_error};
use hodor_authorization::api::{
    Action, ApplicationReference, AssignmentScope, BindingSettings, Condition, EngineBinding,
    EngineBindingStore, EngineId, Namespace, NativeRoleStore, PermissionDefinition, PermissionName,
    Role, RoleAssignment, RoleAssignmentStore, RoleContents, RoleDefinition, RoleKey, RoleName,
    Subject, SubjectKind,
};
use hodor_kernel::{DomainError, Timestamp, UnitOfWork, UserId};
use std::collections::BTreeMap;
use std::time::Duration;

/// The namespace of the built-in roles, as stored.
const ADMINISTRATION: &str = "hodor:admin";

/// The reference from an inclusion to the role it includes.
const INCLUDED_ROLE_CONSTRAINT: &str = "role_inclusion_included_exists";

fn corrupted(what: &str, error: &DomainError) -> DomainError {
    DomainError::internal(
        "authorization.stored_data_invalid",
        "the operation could not be completed",
    )
    .with_detail(format!("stored {what} is not valid: {}", error.code()))
}

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
            "INSERT INTO \"authorization\".role_assignment (tenant_id, principal_kind,
                 principal_id, namespace, role, application, assigned_at)
             VALUES ($1, 'user', $2, $3, $4, '', $5)
             ON CONFLICT (tenant_id, principal_kind, principal_id, namespace, role, application)
             DO NOTHING",
        )
        .bind(tenant.as_uuid())
        .bind(user_id.to_string())
        .bind(ADMINISTRATION)
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
             WHERE tenant_id = $1 AND principal_kind = 'user' AND principal_id = $2
               AND namespace = $3 AND role = $4 AND application = ''",
        )
        .bind(tenant.as_uuid())
        .bind(user_id.to_string())
        .bind(ADMINISTRATION)
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
             WHERE tenant_id = $1 AND principal_kind = 'user' AND principal_id = $2
               AND namespace = $3",
        )
        .bind(tenant.as_uuid())
        .bind(user_id.to_string())
        .bind(ADMINISTRATION)
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

/// [`NativeRoleStore`] on `authorization.permission`, `authorization.role`,
/// `authorization.role_permission`, `authorization.role_inclusion`,
/// `authorization.role_revision` and `authorization.role_assignment`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgNativeRoleStore;

type RoleRow = (String, String, String, Timestamp, Timestamp);
type AssignmentRow = (
    String,
    String,
    String,
    String,
    String,
    Option<Timestamp>,
    Option<Timestamp>,
    Timestamp,
);

fn role_key(namespace: &str, name: &str) -> Result<RoleKey, DomainError> {
    Ok(RoleKey::new(
        Namespace::parse(namespace)?,
        RoleName::parse(name)?,
    ))
}

fn assignment_from(row: AssignmentRow) -> Result<RoleAssignment, DomainError> {
    let (kind, principal, namespace, role, application, from, until, assigned_at) = row;
    let read = || -> Result<RoleAssignment, DomainError> {
        let principal = Subject::new(SubjectKind::parse(&kind)?, &principal)?;
        let scope = if application.is_empty() {
            AssignmentScope::Tenant
        } else {
            AssignmentScope::Application(ApplicationReference::parse(&application)?)
        };
        RoleAssignment::new(
            principal,
            role_key(&namespace, &role)?,
            scope,
            from,
            until,
            assigned_at,
        )
    };
    read().map_err(|error| corrupted("assignment", &error))
}

fn scope_column(scope: &AssignmentScope) -> &str {
    scope.application().map_or("", ApplicationReference::as_str)
}

#[async_trait::async_trait]
impl NativeRoleStore for PgNativeRoleStore {
    async fn raise_revision(&self, uow: &mut dyn UnitOfWork) -> Result<u64, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let revision: i64 = sqlx::query_scalar(
            "INSERT INTO \"authorization\".role_revision (tenant_id, revision) VALUES ($1, 1)
             ON CONFLICT (tenant_id) DO UPDATE SET revision = role_revision.revision + 1
             RETURNING revision",
        )
        .bind(tenant.as_uuid())
        .fetch_one(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(u64::try_from(revision).unwrap_or(0))
    }

    async fn revision(&self, uow: &mut dyn UnitOfWork) -> Result<u64, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let revision: Option<i64> = sqlx::query_scalar(
            "SELECT revision FROM \"authorization\".role_revision WHERE tenant_id = $1",
        )
        .bind(tenant.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(revision.map_or(0, |revision| u64::try_from(revision).unwrap_or(0)))
    }

    async fn put_permission(
        &self,
        uow: &mut dyn UnitOfWork,
        permission: &PermissionDefinition,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "INSERT INTO \"authorization\".permission (tenant_id, namespace, name, description,
                 created_at)
             VALUES ($1, $2, $3, $4, now())
             ON CONFLICT (tenant_id, namespace, name) DO UPDATE SET
                 description = EXCLUDED.description",
        )
        .bind(tenant.as_uuid())
        .bind(permission.namespace().as_str())
        .bind(permission.name().as_str())
        .bind(permission.description())
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn remove_permission(
        &self,
        uow: &mut dyn UnitOfWork,
        namespace: &Namespace,
        permission: &PermissionName,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let deleted = sqlx::query(
            "DELETE FROM \"authorization\".permission
             WHERE tenant_id = $1 AND namespace = $2 AND name = $3",
        )
        .bind(tenant.as_uuid())
        .bind(namespace.as_str())
        .bind(permission.as_str())
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(deleted.rows_affected() > 0)
    }

    async fn permissions(
        &self,
        uow: &mut dyn UnitOfWork,
        namespace: &Namespace,
    ) -> Result<Vec<PermissionDefinition>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT name, description FROM \"authorization\".permission
             WHERE tenant_id = $1 AND namespace = $2 ORDER BY name",
        )
        .bind(tenant.as_uuid())
        .bind(namespace.as_str())
        .fetch_all(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        rows.into_iter()
            .map(|(name, description)| {
                PermissionName::parse(&name)
                    .and_then(|name| {
                        PermissionDefinition::new(namespace.clone(), name, &description)
                    })
                    .map_err(|error| corrupted("permission", &error))
            })
            .collect()
    }

    async fn put_role(
        &self,
        uow: &mut dyn UnitOfWork,
        role: &RoleDefinition,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let key = role.key();
        let contents = role.contents();
        sqlx::query(
            "INSERT INTO \"authorization\".role (tenant_id, namespace, name, description,
                 created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (tenant_id, namespace, name) DO UPDATE SET
                 description = EXCLUDED.description,
                 updated_at = EXCLUDED.updated_at",
        )
        .bind(tenant.as_uuid())
        .bind(key.namespace.as_str())
        .bind(key.name.as_str())
        .bind(contents.description.as_str())
        .bind(role.created_at())
        .bind(role.updated_at())
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        for table in ["role_permission", "role_inclusion"] {
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "DELETE FROM \"authorization\".{table}
                 WHERE tenant_id = $1 AND namespace = $2 AND role = $3"
            )))
            .bind(tenant.as_uuid())
            .bind(key.namespace.as_str())
            .bind(key.name.as_str())
            .execute(connection(uow)?)
            .await
            .map_err(|e| database_error(&e))?;
        }
        let permissions: Vec<&str> = contents
            .permissions
            .iter()
            .map(PermissionName::as_str)
            .collect();
        let conditions: Vec<Option<&str>> = contents
            .permissions
            .iter()
            .map(|permission| contents.conditions.get(permission).map(Condition::as_str))
            .collect();
        sqlx::query(
            "INSERT INTO \"authorization\".role_permission
                 (tenant_id, namespace, role, permission, condition)
             SELECT $1, $2, $3, held.permission, held.condition
             FROM unnest($4::text[], $5::text[]) AS held (permission, condition)",
        )
        .bind(tenant.as_uuid())
        .bind(key.namespace.as_str())
        .bind(key.name.as_str())
        .bind(&permissions)
        .bind(&conditions)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        let (namespaces, names): (Vec<&str>, Vec<&str>) = contents
            .includes
            .iter()
            .map(|included| (included.namespace.as_str(), included.name.as_str()))
            .unzip();
        sqlx::query(
            "INSERT INTO \"authorization\".role_inclusion (tenant_id, namespace, role,
                 included_namespace, included_role)
             SELECT $1, $2, $3, included.namespace, included.name
             FROM unnest($4::text[], $5::text[]) AS included (namespace, name)",
        )
        .bind(tenant.as_uuid())
        .bind(key.namespace.as_str())
        .bind(key.name.as_str())
        .bind(&namespaces)
        .bind(&names)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn roles(&self, uow: &mut dyn UnitOfWork) -> Result<Vec<RoleDefinition>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let rows: Vec<RoleRow> = sqlx::query_as(
            "SELECT namespace, name, description, created_at, updated_at
             FROM \"authorization\".role WHERE tenant_id = $1 ORDER BY namespace, name",
        )
        .bind(tenant.as_uuid())
        .fetch_all(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        let held: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
            "SELECT namespace, role, permission, condition FROM \"authorization\".role_permission
             WHERE tenant_id = $1",
        )
        .bind(tenant.as_uuid())
        .fetch_all(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        let included: Vec<(String, String, String, String)> = sqlx::query_as(
            "SELECT namespace, role, included_namespace, included_role
             FROM \"authorization\".role_inclusion WHERE tenant_id = $1",
        )
        .bind(tenant.as_uuid())
        .fetch_all(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;

        let read = || -> Result<Vec<RoleDefinition>, DomainError> {
            let mut contents: BTreeMap<(String, String), RoleContents> = BTreeMap::new();
            for (namespace, name, description, _, _) in &rows {
                contents.insert(
                    (namespace.clone(), name.clone()),
                    RoleContents::unconditional(
                        description,
                        std::collections::BTreeSet::new(),
                        std::collections::BTreeSet::new(),
                    ),
                );
            }
            for (namespace, role, permission, condition) in held {
                if let Some(role) = contents.get_mut(&(namespace, role)) {
                    let permission = PermissionName::parse(&permission)?;
                    if let Some(condition) = condition {
                        role.conditions
                            .insert(permission.clone(), Condition::parse(&condition)?);
                    }
                    role.permissions.insert(permission);
                }
            }
            for (namespace, role, included_namespace, included_role) in included {
                if let Some(role) = contents.get_mut(&(namespace, role)) {
                    role.includes
                        .insert(role_key(&included_namespace, &included_role)?);
                }
            }
            rows.iter()
                .map(|(namespace, name, _, created, updated)| {
                    let role_contents = contents
                        .remove(&(namespace.clone(), name.clone()))
                        .unwrap_or_else(|| {
                            RoleContents::unconditional(
                                "",
                                std::collections::BTreeSet::new(),
                                std::collections::BTreeSet::new(),
                            )
                        });
                    RoleDefinition::restore(
                        role_key(namespace, name)?,
                        role_contents,
                        *created,
                        *updated,
                    )
                })
                .collect()
        };
        read().map_err(|error| corrupted("role", &error))
    }

    async fn remove_role(
        &self,
        uow: &mut dyn UnitOfWork,
        key: &RoleKey,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let deleted = sqlx::query(
            "DELETE FROM \"authorization\".role
             WHERE tenant_id = $1 AND namespace = $2 AND name = $3",
        )
        .bind(tenant.as_uuid())
        .bind(key.namespace.as_str())
        .bind(key.name.as_str())
        .execute(connection(uow)?)
        .await;
        match deleted {
            Ok(deleted) => Ok(deleted.rows_affected() > 0),
            Err(sqlx::Error::Database(error))
                if error.constraint() == Some(INCLUDED_ROLE_CONSTRAINT) =>
            {
                Err(DomainError::conflict(
                    "authorization.role_in_use",
                    "a role that another role includes cannot be removed",
                ))
            }
            Err(error) => Err(database_error(&error)),
        }
    }

    async fn put_assignment(
        &self,
        uow: &mut dyn UnitOfWork,
        assignment: &RoleAssignment,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "INSERT INTO \"authorization\".role_assignment (tenant_id, principal_kind,
                 principal_id, namespace, role, application, valid_from, valid_until,
                 assigned_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (tenant_id, principal_kind, principal_id, namespace, role, application)
             DO UPDATE SET
                 valid_from = EXCLUDED.valid_from,
                 valid_until = EXCLUDED.valid_until,
                 assigned_at = EXCLUDED.assigned_at",
        )
        .bind(tenant.as_uuid())
        .bind(assignment.principal().kind().as_str())
        .bind(assignment.principal().id())
        .bind(assignment.role().namespace.as_str())
        .bind(assignment.role().name.as_str())
        .bind(scope_column(assignment.scope()))
        .bind(assignment.valid_from())
        .bind(assignment.valid_until())
        .bind(assignment.assigned_at())
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn remove_assignment(
        &self,
        uow: &mut dyn UnitOfWork,
        principal: &Subject,
        role: &RoleKey,
        scope: &AssignmentScope,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let deleted = sqlx::query(
            "DELETE FROM \"authorization\".role_assignment
             WHERE tenant_id = $1 AND principal_kind = $2 AND principal_id = $3
               AND namespace = $4 AND role = $5 AND application = $6
               AND namespace <> 'hodor:admin'",
        )
        .bind(tenant.as_uuid())
        .bind(principal.kind().as_str())
        .bind(principal.id())
        .bind(role.namespace.as_str())
        .bind(role.name.as_str())
        .bind(scope_column(scope))
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(deleted.rows_affected() > 0)
    }

    async fn assignments_of(
        &self,
        uow: &mut dyn UnitOfWork,
        principal: &Subject,
    ) -> Result<Vec<RoleAssignment>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let rows: Vec<AssignmentRow> = sqlx::query_as(
            "SELECT principal_kind, principal_id, namespace, role, application, valid_from,
                    valid_until, assigned_at
             FROM \"authorization\".role_assignment
             WHERE tenant_id = $1 AND principal_kind = $2 AND principal_id = $3
               AND namespace <> 'hodor:admin'
             ORDER BY namespace, role, application",
        )
        .bind(tenant.as_uuid())
        .bind(principal.kind().as_str())
        .bind(principal.id())
        .fetch_all(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        rows.into_iter().map(assignment_from).collect()
    }
}
