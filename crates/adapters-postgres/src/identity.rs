//! PostgreSQL storage for the identity context.
//!
//! See `docs/architecture/contexts/identity.md`, "Storage".

use crate::uow::{connection, database_error};
use hodor_identity::api::{
    IdentifierId, IdentifierKind, LoginIdentifier, NormalizedIdentifier, PostalAddress, Profile,
    StandardClaims, User, UserKind, UserRepository, UserSnapshot, UserStatus, WorkloadRepository,
};
use hodor_kernel::{DomainError, TenantId, Timestamp, UnitOfWork, UserId};
use sqlx::postgres::PgRow;
use sqlx::types::Uuid;
use sqlx::{PgConnection, Row};

const VALUE_CONSTRAINT: &str = "user_identifier_value_unique";

/// [`UserRepository`] on `identity.user` and `identity.user_identifier`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgUserRepository;

/// The columns of a user's standard claims, in the order
/// [`bind_claims`] binds them: a literal, so that every statement stays one.
macro_rules! claim_columns {
    () => {
        "given_name, family_name, middle_name, nickname, profile, picture, website, gender, \
         birthdate, zoneinfo, phone_number, phone_number_verified, address_formatted, \
         address_street_address, address_locality, address_region, address_postal_code, \
         address_country"
    };
}
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

fn claims_of(row: &PgRow) -> Result<StandardClaims, sqlx::Error> {
    let text = |column: &str| row.try_get::<Option<String>, _>(column);
    let address = PostalAddress {
        formatted: text("address_formatted")?,
        street_address: text("address_street_address")?,
        locality: text("address_locality")?,
        region: text("address_region")?,
        postal_code: text("address_postal_code")?,
        country: text("address_country")?,
    };
    Ok(StandardClaims {
        given_name: text("given_name")?,
        family_name: text("family_name")?,
        middle_name: text("middle_name")?,
        nickname: text("nickname")?,
        profile: text("profile")?,
        picture: text("picture")?,
        website: text("website")?,
        gender: text("gender")?,
        birthdate: text("birthdate")?,
        zoneinfo: text("zoneinfo")?,
        phone_number: text("phone_number")?,
        phone_number_verified: row.try_get("phone_number_verified")?,
        address: (!address.is_empty()).then_some(address),
    })
}

/// Binds the columns of [`CLAIM_COLUMNS`], in their order.
fn bind_claims<'q>(
    query: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
    claims: &'q StandardClaims,
) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
    let address = claims.address.as_ref();
    let part = |of: fn(&PostalAddress) -> &Option<String>| address.and_then(|a| of(a).as_deref());
    query
        .bind(claims.given_name.as_deref())
        .bind(claims.family_name.as_deref())
        .bind(claims.middle_name.as_deref())
        .bind(claims.nickname.as_deref())
        .bind(claims.profile.as_deref())
        .bind(claims.picture.as_deref())
        .bind(claims.website.as_deref())
        .bind(claims.gender.as_deref())
        .bind(claims.birthdate.as_deref())
        .bind(claims.zoneinfo.as_deref())
        .bind(claims.phone_number.as_deref())
        .bind(claims.phone_number_verified)
        .bind(part(|a| &a.formatted))
        .bind(part(|a| &a.street_address))
        .bind(part(|a| &a.locality))
        .bind(part(|a| &a.region))
        .bind(part(|a| &a.postal_code))
        .bind(part(|a| &a.country))
}

async fn load_user(
    connection: &mut PgConnection,
    tenant: TenantId,
    id: Uuid,
) -> Result<Option<User>, DomainError> {
    let row: Option<PgRow> = sqlx::query(concat!(
        "SELECT id, kind, status, status_reason, display_name, locale, created_at, updated_at, \
         version, ",
        claim_columns!(),
        r#" FROM identity."user" WHERE tenant_id = $1 AND id = $2"#
    ))
    .bind(tenant.as_uuid())
    .bind(id)
    .fetch_optional(&mut *connection)
    .await
    .map_err(|e| database_error(&e))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let read = |error: sqlx::Error| database_error(&error);
    let id: Uuid = row.try_get("id").map_err(read)?;
    let kind: String = row.try_get("kind").map_err(read)?;
    let status: String = row.try_get("status").map_err(read)?;
    let status_reason: Option<String> = row.try_get("status_reason").map_err(read)?;
    let display_name: Option<String> = row.try_get("display_name").map_err(read)?;
    let locale: Option<String> = row.try_get("locale").map_err(read)?;
    let created_at: Timestamp = row.try_get("created_at").map_err(read)?;
    let updated_at: Timestamp = row.try_get("updated_at").map_err(read)?;
    let version: i32 = row.try_get("version").map_err(read)?;
    let claims = claims_of(&row).map_err(read)?;

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
        claims,
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
        let query = sqlx::query(concat!(
            r#"INSERT INTO identity."user"
                   (tenant_id, id, kind, status, status_reason, display_name, locale,
                    created_at, updated_at, version, "#,
            claim_columns!(),
            ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, \
             $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28)"
        ))
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.kind.as_str())
        .bind(state.status.as_str())
        .bind(&state.status_reason)
        .bind(&state.profile.display_name)
        .bind(&state.profile.locale)
        .bind(state.created_at)
        .bind(state.updated_at)
        .bind(version);
        bind_claims(query, &state.claims)
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

        let query = sqlx::query(
            r#"UPDATE identity."user"
               SET status = $3, status_reason = $4, display_name = $5, locale = $6,
                   updated_at = $7, version = version + 1,
                   given_name = $9, family_name = $10, middle_name = $11, nickname = $12,
                   profile = $13, picture = $14, website = $15, gender = $16,
                   birthdate = $17, zoneinfo = $18, phone_number = $19,
                   phone_number_verified = $20, address_formatted = $21,
                   address_street_address = $22, address_locality = $23,
                   address_region = $24, address_postal_code = $25, address_country = $26
               WHERE tenant_id = $1 AND id = $2 AND version = $8"#,
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.status.as_str())
        .bind(&state.status_reason)
        .bind(&state.profile.display_name)
        .bind(&state.profile.locale)
        .bind(state.updated_at)
        .bind(version);
        let updated = bind_claims(query, &state.claims)
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

/// [`WorkloadRepository`] on `identity.user` and `identity.workload_owner`.
///
/// See `docs/architecture/contexts/identity.md`, "Service accounts and
/// agents".
#[derive(Debug, Clone, Copy, Default)]
pub struct PgWorkloadRepository;

fn owner_error(error: &sqlx::Error) -> DomainError {
    match error {
        sqlx::Error::Database(database) if database.is_foreign_key_violation() => {
            DomainError::not_found("identity.user_not_found", "the user does not exist")
        }
        other => database_error(other),
    }
}

#[async_trait::async_trait]
impl WorkloadRepository for PgWorkloadRepository {
    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        kind: UserKind,
        after: Option<UserId>,
        limit: u32,
    ) -> Result<Vec<User>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let connection = connection(uow)?;
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM identity.\"user\"
             WHERE tenant_id = $1 AND kind = $2 AND status <> 'deleted'
               AND ($3::uuid IS NULL OR id > $3)
             ORDER BY id
             LIMIT $4",
        )
        .bind(tenant.as_uuid())
        .bind(kind.as_str())
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

    async fn owners(
        &self,
        uow: &mut dyn UnitOfWork,
        workload: UserId,
    ) -> Result<Vec<UserId>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let owners: Vec<Uuid> = sqlx::query_scalar(
            "SELECT owner_id FROM identity.workload_owner
             WHERE tenant_id = $1 AND workload_id = $2
             ORDER BY added_at, owner_id",
        )
        .bind(tenant.as_uuid())
        .bind(workload.as_uuid())
        .fetch_all(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(owners.into_iter().map(UserId::from_uuid).collect())
    }

    async fn replace_owners(
        &self,
        uow: &mut dyn UnitOfWork,
        workload: UserId,
        owners: &[UserId],
        now: Timestamp,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let connection = connection(uow)?;
        let kept: Vec<Uuid> = owners.iter().map(|owner| owner.as_uuid()).collect();
        sqlx::query(
            "DELETE FROM identity.workload_owner
             WHERE tenant_id = $1 AND workload_id = $2 AND NOT (owner_id = ANY($3))",
        )
        .bind(tenant.as_uuid())
        .bind(workload.as_uuid())
        .bind(&kept)
        .execute(&mut *connection)
        .await
        .map_err(|e| database_error(&e))?;
        sqlx::query(
            "INSERT INTO identity.workload_owner (tenant_id, workload_id, owner_id, added_at)
             SELECT $1, $2, owner, $4 FROM unnest($3::uuid[]) AS owner
             ON CONFLICT (tenant_id, workload_id, owner_id) DO NOTHING",
        )
        .bind(tenant.as_uuid())
        .bind(workload.as_uuid())
        .bind(&kept)
        .bind(now)
        .execute(&mut *connection)
        .await
        .map_err(|e| owner_error(&e))?;
        Ok(())
    }

    async fn forget_owners(
        &self,
        uow: &mut dyn UnitOfWork,
        workload: UserId,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "DELETE FROM identity.workload_owner WHERE tenant_id = $1 AND workload_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(workload.as_uuid())
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }
}
