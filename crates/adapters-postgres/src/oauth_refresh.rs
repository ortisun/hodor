//! PostgreSQL storage for refresh tokens: the families and every token
//! they have had, by its hash.
//!
//! See `docs/architecture/contexts/oauth.md`, "Refresh tokens".

use crate::uow::{connection, database_error};
use hodor_kernel::{DomainError, SealedSecret, Timestamp, UnitOfWork, UserId};
use hodor_oauth::api::{
    ClientId, FamilyStatus, GrantId, RefreshAsk, RefreshFamily, RefreshFamilyId, RefreshTokenHash,
    RefreshTokenRecord, RefreshTokenStore,
};
use hodor_session::api::SessionId;
use sqlx::Row as _;
use sqlx::postgres::PgRow;
use time::Duration;

const FAMILY_GRANT_CONSTRAINT: &str = "refresh_token_family_grant_fk";
const FAMILY_CLIENT_CONSTRAINT: &str = "refresh_token_family_client_fk";

fn corrupted(what: &str) -> DomainError {
    DomainError::internal(
        "oauth.stored_data_invalid",
        "stored OAuth data could not be read",
    )
    .with_detail(what.to_owned())
}

fn get(error: sqlx::Error) -> DomainError {
    database_error(&error)
}

fn hash_of(row: &PgRow, column: &str) -> Result<RefreshTokenHash, DomainError> {
    let bytes: Vec<u8> = row.try_get(column).map_err(get)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| corrupted("a hash is not 32 bytes"))?;
    Ok(RefreshTokenHash::from_stored(bytes))
}

fn family_from(row: &PgRow) -> Result<RefreshFamily, DomainError> {
    let status: String = row.try_get("status").map_err(get)?;
    let idle: i32 = row.try_get("idle_seconds").map_err(get)?;
    Ok(RefreshFamily {
        id: RefreshFamilyId::from_uuid(row.try_get("id").map_err(get)?),
        grant_id: GrantId::from_uuid(row.try_get("grant_id").map_err(get)?),
        client_id: ClientId::from_uuid(row.try_get("client_id").map_err(get)?),
        user_id: UserId::from_uuid(row.try_get("user_id").map_err(get)?),
        session_id: SessionId::from_uuid(row.try_get("session_id").map_err(get)?),
        scopes: row.try_get("scopes").map_err(get)?,
        audiences: row.try_get("audiences").map_err(get)?,
        offline: row.try_get("offline").map_err(get)?,
        signed_in_at: row.try_get("signed_in_at").map_err(get)?,
        methods: row.try_get("methods").map_err(get)?,
        acr: row.try_get("acr").map_err(get)?,
        sealed_secret: SealedSecret::from_stored(row.try_get("sealed_secret").map_err(get)?),
        generation: row.try_get("generation").map_err(get)?,
        current_hash: hash_of(row, "current_hash")?,
        moved_at: row.try_get("moved_at").map_err(get)?,
        moved_for: RefreshAsk {
            scopes: row.try_get("moved_scopes").map_err(get)?,
            resource: row.try_get("moved_resource").map_err(get)?,
        },
        status: FamilyStatus::from_stored(&status)?,
        created_at: row.try_get("created_at").map_err(get)?,
        expires_at: row.try_get("expires_at").map_err(get)?,
        idle: Duration::seconds(i64::from(idle)),
        last_used_at: row.try_get("last_used_at").map_err(get)?,
        revoked_at: row.try_get("revoked_at").map_err(get)?,
        revocation_reason: row.try_get("revocation_reason").map_err(get)?,
    })
}

async fn insert_token(
    uow: &mut dyn UnitOfWork,
    record: &RefreshTokenRecord,
) -> Result<(), DomainError> {
    let tenant = uow.tenant().tenant_id();
    sqlx::query(
        "INSERT INTO oauth.refresh_token (tenant_id, token_hash, family_id, generation, issued_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(tenant.as_uuid())
    .bind(record.hash.as_bytes().as_slice())
    .bind(record.family_id.as_uuid())
    .bind(record.generation)
    .bind(record.issued_at)
    .execute(connection(uow)?)
    .await
    .map_err(get)?;
    Ok(())
}

/// [`RefreshTokenStore`] on `oauth.refresh_token_family` and
/// `oauth.refresh_token`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgRefreshTokenStore;

#[async_trait::async_trait]
impl RefreshTokenStore for PgRefreshTokenStore {
    async fn start(
        &self,
        uow: &mut dyn UnitOfWork,
        family: &RefreshFamily,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let idle = i32::try_from(family.idle.whole_seconds())
            .map_err(|_| corrupted("the idle time does not fit"))?;
        sqlx::query(
            "INSERT INTO oauth.refresh_token_family
                 (tenant_id, id, grant_id, client_id, user_id, session_id, scopes, audiences,
                  offline, signed_in_at, methods, sealed_secret, generation, current_hash,
                  moved_at, moved_scopes, moved_resource, status, created_at, expires_at,
                  idle_seconds, last_used_at, revoked_at, revocation_reason, acr)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
                     $18, $19, $20, $21, $22, $23, $24, $25)",
        )
        .bind(tenant.as_uuid())
        .bind(family.id.as_uuid())
        .bind(family.grant_id.as_uuid())
        .bind(family.client_id.as_uuid())
        .bind(family.user_id.as_uuid())
        .bind(family.session_id.as_uuid())
        .bind(&family.scopes)
        .bind(&family.audiences)
        .bind(family.offline)
        .bind(family.signed_in_at)
        .bind(&family.methods)
        .bind(family.sealed_secret.as_bytes())
        .bind(family.generation)
        .bind(family.current_hash.as_bytes().as_slice())
        .bind(family.moved_at)
        .bind(&family.moved_for.scopes)
        .bind(family.moved_for.resource.as_deref())
        .bind(family.status.as_str())
        .bind(family.created_at)
        .bind(family.expires_at)
        .bind(idle)
        .bind(family.last_used_at)
        .bind(family.revoked_at)
        .bind(family.revocation_reason.as_deref())
        .bind(family.acr.as_deref())
        .execute(connection(uow)?)
        .await
        .map_err(|error| match &error {
            sqlx::Error::Database(database)
                if matches!(
                    database.constraint(),
                    Some(FAMILY_GRANT_CONSTRAINT | FAMILY_CLIENT_CONSTRAINT)
                ) =>
            {
                DomainError::not_found("oauth.grant_not_found", "there is no such grant")
            }
            _ => database_error(&error),
        })?;
        insert_token(uow, &family.first_record()).await
    }

    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &RefreshTokenHash,
    ) -> Result<Option<(RefreshFamily, RefreshTokenRecord)>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row = sqlx::query(
            "SELECT family.id, family.grant_id, family.client_id, family.user_id,
                    family.session_id, family.scopes, family.audiences, family.offline,
                    family.signed_in_at, family.methods, family.sealed_secret, family.generation,
                    family.current_hash, family.moved_at, family.moved_scopes,
                    family.moved_resource, family.status, family.created_at, family.expires_at,
                    family.idle_seconds, family.last_used_at, family.revoked_at,
                    family.revocation_reason, family.acr,
                    token.generation AS token_generation, token.issued_at AS token_issued_at
             FROM oauth.refresh_token AS token
             JOIN oauth.refresh_token_family AS family
               ON family.tenant_id = token.tenant_id AND family.id = token.family_id
             WHERE token.tenant_id = $1 AND token.token_hash = $2",
        )
        .bind(tenant.as_uuid())
        .bind(hash.as_bytes().as_slice())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(get)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let family = family_from(&row)?;
        let record = RefreshTokenRecord {
            hash: *hash,
            family_id: family.id,
            generation: row.try_get("token_generation").map_err(get)?,
            issued_at: row.try_get("token_issued_at").map_err(get)?,
        };
        Ok(Some((family, record)))
    }

    async fn advance(
        &self,
        uow: &mut dyn UnitOfWork,
        family: RefreshFamilyId,
        from_generation: i32,
        next: &RefreshTokenHash,
        asked: &RefreshAsk,
        at: Timestamp,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        // Of two refreshes with the same token at the same moment, the
        // generation in the condition lets one move the family and leaves
        // the other nothing to change.
        let moved = sqlx::query(
            "UPDATE oauth.refresh_token_family
             SET generation = generation + 1, current_hash = $4, moved_at = $5,
                 moved_scopes = $6, moved_resource = $7, last_used_at = $5
             WHERE tenant_id = $1 AND id = $2 AND generation = $3 AND status = 'active'",
        )
        .bind(tenant.as_uuid())
        .bind(family.as_uuid())
        .bind(from_generation)
        .bind(next.as_bytes().as_slice())
        .bind(at)
        .bind(&asked.scopes)
        .bind(asked.resource.as_deref())
        .execute(connection(uow)?)
        .await
        .map_err(get)?;
        if moved.rows_affected() != 1 {
            return Ok(false);
        }
        insert_token(
            uow,
            &RefreshTokenRecord {
                hash: *next,
                family_id: family,
                generation: from_generation + 1,
                issued_at: at,
            },
        )
        .await?;
        Ok(true)
    }

    async fn revoke(
        &self,
        uow: &mut dyn UnitOfWork,
        family: &RefreshFamily,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let changed = sqlx::query(
            "UPDATE oauth.refresh_token_family
             SET status = $3, revoked_at = $4, revocation_reason = $5
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(family.id.as_uuid())
        .bind(family.status.as_str())
        .bind(family.revoked_at)
        .bind(family.revocation_reason.as_deref())
        .execute(connection(uow)?)
        .await
        .map_err(get)?;
        if changed.rows_affected() == 1 {
            Ok(())
        } else {
            Err(DomainError::not_found(
                "oauth.refresh_token_family_not_found",
                "there is no such refresh token family",
            ))
        }
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: RefreshFamilyId,
    ) -> Result<Option<RefreshFamily>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row = sqlx::query(
            "SELECT id, grant_id, client_id, user_id, session_id, scopes, audiences, offline,
                    signed_in_at, methods, sealed_secret, generation, current_hash, moved_at,
                    moved_scopes, moved_resource, status, created_at, expires_at, idle_seconds,
                    last_used_at, revoked_at, revocation_reason, acr
             FROM oauth.refresh_token_family
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(get)?;
        row.as_ref().map(family_from).transpose()
    }
}
