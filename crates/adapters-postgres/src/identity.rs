//! PostgreSQL storage for the identity context.
//!
//! See `docs/architecture/contexts/identity.md`, "Storage".

use crate::uow::{connection, database_error};
use hodor_identity::api::{
    IdentifierId, IdentifierKind, LoginIdentifier, NormalizedIdentifier, Profile, User, UserKind,
    UserRepository, UserSnapshot, UserStatus,
};
use hodor_kernel::{DomainError, TenantId, Timestamp, UnitOfWork, UserId};
use sqlx::PgConnection;
use sqlx::types::Uuid;

const VALUE_CONSTRAINT: &str = "user_identifier_value_unique";

/// [`UserRepository`] on `identity.user` and `identity.user_identifier`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgUserRepository;

type UserRow = (
    Uuid,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Timestamp,
    Timestamp,
    i32,
);
type IdentifierRow = (
    Uuid,
    String,
    String,
    String,
    Option<Timestamp>,
    bool,
    Timestamp,
);

fn corrupted(what: &str) -> DomainError {
    DomainError::internal(
        "identity.stored_data_invalid",
        "the user could not be loaded",
    )
    .with_detail(what.to_owned())
}

fn identifier_error(error: &sqlx::Error) -> DomainError {
    match error {
        sqlx::Error::Database(database) if database.constraint() == Some(VALUE_CONSTRAINT) => {
            DomainError::conflict(
                "identity.identifier_taken",
                "this login identifier is already in use",
            )
        }
        other => database_error(other),
    }
}

fn stored_version(user: &User) -> Result<i32, DomainError> {
    i32::try_from(user.snapshot().version).map_err(|_| corrupted("version out of range"))
}

async fn load_user(
    connection: &mut PgConnection,
    tenant: TenantId,
    id: Uuid,
) -> Result<Option<User>, DomainError> {
    let row: Option<UserRow> = sqlx::query_as(
        r#"SELECT id, kind, status, status_reason, display_name, locale,
                  created_at, updated_at, version
           FROM identity."user"
           WHERE tenant_id = $1 AND id = $2"#,
    )
    .bind(tenant.as_uuid())
    .bind(id)
    .fetch_optional(&mut *connection)
    .await
    .map_err(|e| database_error(&e))?;
    let Some((
        id,
        kind,
        status,
        status_reason,
        display_name,
        locale,
        created_at,
        updated_at,
        version,
    )) = row
    else {
        return Ok(None);
    };

    let rows: Vec<IdentifierRow> = sqlx::query_as(
        "SELECT id, kind, value_normalized, value_display, verified_at, is_primary, created_at
         FROM identity.user_identifier
         WHERE tenant_id = $1 AND user_id = $2
         ORDER BY created_at, id",
    )
    .bind(tenant.as_uuid())
    .bind(id)
    .fetch_all(&mut *connection)
    .await
    .map_err(|e| database_error(&e))?;
    let identifiers = rows
        .into_iter()
        .map(
            |(id, kind, normalized, display, verified_at, primary, created_at)| {
                Ok(LoginIdentifier {
                    id: IdentifierId::from_uuid(id),
                    value: NormalizedIdentifier::from_stored(
                        IdentifierKind::from_stored(&kind)?,
                        normalized,
                        display,
                    ),
                    verified_at,
                    primary,
                    created_at,
                })
            },
        )
        .collect::<Result<Vec<_>, DomainError>>()?;

    Ok(Some(User::from_snapshot(UserSnapshot {
        id: UserId::from_uuid(id),
        kind: UserKind::from_stored(&kind)?,
        status: UserStatus::from_stored(&status)?,
        status_reason,
        profile: Profile {
            display_name,
            locale,
        },
        identifiers,
        created_at,
        updated_at,
        version: u32::try_from(version).map_err(|_| corrupted("negative version"))?,
    })))
}

async fn insert_identifiers(
    connection: &mut PgConnection,
    tenant: TenantId,
    user: &User,
) -> Result<(), DomainError> {
    for identifier in user.identifiers() {
        sqlx::query(
            "INSERT INTO identity.user_identifier
                 (tenant_id, id, user_id, kind, value_normalized, value_display,
                  verified_at, is_primary, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(tenant.as_uuid())
        .bind(identifier.id.as_uuid())
        .bind(user.id().as_uuid())
        .bind(identifier.value.kind().as_str())
        .bind(identifier.value.normalized())
        .bind(identifier.value.display())
        .bind(identifier.verified_at)
        .bind(identifier.primary)
        .bind(identifier.created_at)
        .execute(&mut *connection)
        .await
        .map_err(|e| identifier_error(&e))?;
    }
    Ok(())
}

#[async_trait::async_trait]
impl UserRepository for PgUserRepository {
    async fn insert(&self, uow: &mut dyn UnitOfWork, user: &User) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = user.snapshot();
        let version = stored_version(user)?;
        let connection = connection(uow)?;
        sqlx::query(
            r#"INSERT INTO identity."user"
                   (tenant_id, id, kind, status, status_reason, display_name, locale,
                    created_at, updated_at, version)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.kind.as_str())
        .bind(state.status.as_str())
        .bind(&state.status_reason)
        .bind(&state.profile.display_name)
        .bind(&state.profile.locale)
        .bind(state.created_at)
        .bind(state.updated_at)
        .bind(version)
        .execute(&mut *connection)
        .await
        .map_err(|e| database_error(&e))?;
        insert_identifiers(connection, tenant, user).await
    }

    async fn get(&self, uow: &mut dyn UnitOfWork, id: UserId) -> Result<Option<User>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        load_user(connection(uow)?, tenant, id.as_uuid()).await
    }

    async fn find_by_identifier(
        &self,
        uow: &mut dyn UnitOfWork,
        identifier: &NormalizedIdentifier,
    ) -> Result<Option<User>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let connection = connection(uow)?;
        let user_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT user_id FROM identity.user_identifier
             WHERE tenant_id = $1 AND kind = $2 AND value_normalized = $3",
        )
        .bind(tenant.as_uuid())
        .bind(identifier.kind().as_str())
        .bind(identifier.normalized())
        .fetch_optional(&mut *connection)
        .await
        .map_err(|e| database_error(&e))?;
        match user_id {
            Some(user_id) => load_user(connection, tenant, user_id).await,
            None => Ok(None),
        }
    }

    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        after: Option<UserId>,
        limit: u32,
    ) -> Result<Vec<User>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let connection = connection(uow)?;
        // Identifiers are made from the time, so their order is the order
        // of creation, and the primary key serves the search.
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM identity.\"user\"
             WHERE tenant_id = $1 AND ($2::uuid IS NULL OR id > $2)
             ORDER BY id
             LIMIT $3",
        )
        .bind(tenant.as_uuid())
        .bind(after.map(|after| after.as_uuid()))
        .bind(i64::from(limit))
        .fetch_all(&mut *connection)
        .await
        .map_err(|e| database_error(&e))?;
        let mut users = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(user) = load_user(connection, tenant, id).await? {
                users.push(user);
            }
        }
        Ok(users)
    }

    async fn update(&self, uow: &mut dyn UnitOfWork, user: &User) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = user.snapshot();
        let version = stored_version(user)?;
        let connection = connection(uow)?;

        let updated = sqlx::query(
            r#"UPDATE identity."user"
               SET status = $3, status_reason = $4, display_name = $5, locale = $6,
                   updated_at = $7, version = version + 1
               WHERE tenant_id = $1 AND id = $2 AND version = $8"#,
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.status.as_str())
        .bind(&state.status_reason)
        .bind(&state.profile.display_name)
        .bind(&state.profile.locale)
        .bind(state.updated_at)
        .bind(version)
        .execute(&mut *connection)
        .await
        .map_err(|e| database_error(&e))?
        .rows_affected();

        if updated == 0 {
            let exists: bool = sqlx::query_scalar(
                r#"SELECT EXISTS (SELECT FROM identity."user" WHERE tenant_id = $1 AND id = $2)"#,
            )
            .bind(tenant.as_uuid())
            .bind(state.id.as_uuid())
            .fetch_one(&mut *connection)
            .await
            .map_err(|e| database_error(&e))?;
            return Err(if exists {
                DomainError::conflict(
                    "identity.user_modified_concurrently",
                    "the user was changed by someone else; reload and try again",
                )
            } else {
                DomainError::not_found("identity.user_not_found", "the user does not exist")
            });
        }

        // The version check above means nobody else changed this user, so
        // its identifiers can simply be replaced. There are at most ten.
        sqlx::query("DELETE FROM identity.user_identifier WHERE tenant_id = $1 AND user_id = $2")
            .bind(tenant.as_uuid())
            .bind(state.id.as_uuid())
            .execute(&mut *connection)
            .await
            .map_err(|e| database_error(&e))?;
        insert_identifiers(connection, tenant, user).await
    }
}
