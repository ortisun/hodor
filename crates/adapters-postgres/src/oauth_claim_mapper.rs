//! PostgreSQL storage for the claim mappers of clients.
//!
//! See `docs/architecture/contexts/oauth.md`, "Claim mappers".

use crate::uow::{connection, database_error};
use hodor_kernel::{DomainError, UnitOfWork};
use hodor_oauth::api::{
    ClaimMapper, ClaimMapperId, ClaimMapperSettings, ClaimMapperSnapshot, ClaimMapperStore,
    ClaimSource, ClaimTarget, ClientId,
};
use sqlx::Row as _;
use sqlx::postgres::PgRow;

const CLIENT_CONSTRAINT: &str = "claim_mapper_client_fk";
const CLAIM_CONSTRAINT: &str = "claim_mapper_claim_once";

const COLUMNS: &str =
    "id, client_id, claim, targets, scope, source, created_at, updated_at, version";

fn get(error: sqlx::Error) -> DomainError {
    database_error(&error)
}

fn corrupted(what: &str) -> DomainError {
    DomainError::internal(
        "oauth.stored_data_invalid",
        "stored OAuth data could not be read",
    )
    .with_detail(what.to_owned())
}

/// Translates the refusals of the table's constraints.
fn refused(error: &sqlx::Error) -> DomainError {
    match error {
        sqlx::Error::Database(database) => match database.constraint() {
            Some(CLIENT_CONSTRAINT) => {
                DomainError::not_found("oauth.client_not_found", "there is no such client")
            }
            Some(CLAIM_CONSTRAINT) => DomainError::conflict(
                "oauth.claim_mapper_name_taken",
                "the client already has a mapper of this claim",
            ),
            _ => database_error(error),
        },
        _ => database_error(error),
    }
}

fn mapper_from(row: &PgRow) -> Result<ClaimMapper, DomainError> {
    let targets: Vec<String> = row.try_get("targets").map_err(get)?;
    let source: serde_json::Value = row.try_get("source").map_err(get)?;
    let version: i32 = row.try_get("version").map_err(get)?;
    Ok(ClaimMapper::from_snapshot(ClaimMapperSnapshot {
        id: ClaimMapperId::from_uuid(row.try_get("id").map_err(get)?),
        client_id: ClientId::from_uuid(row.try_get("client_id").map_err(get)?),
        settings: ClaimMapperSettings {
            claim: row.try_get("claim").map_err(get)?,
            targets: targets
                .iter()
                .map(|target| ClaimTarget::parse(target))
                .collect::<Result<_, _>>()
                .map_err(|_| corrupted("a claim mapper's target is unknown"))?,
            scope: row.try_get("scope").map_err(get)?,
            source: ClaimSource::from_json(&source)
                .map_err(|_| corrupted("a claim mapper's source is unknown"))?,
        },
        created_at: row.try_get("created_at").map_err(get)?,
        updated_at: row.try_get("updated_at").map_err(get)?,
        version: u32::try_from(version).map_err(|_| corrupted("negative version"))?,
    }))
}

fn targets_of(mapper: &ClaimMapper) -> Vec<&'static str> {
    mapper
        .settings()
        .targets
        .iter()
        .map(|target| target.as_str())
        .collect()
}

/// [`ClaimMapperStore`] on `oauth.claim_mapper`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgClaimMapperStore;

#[async_trait::async_trait]
impl ClaimMapperStore for PgClaimMapperStore {
    async fn lock_client(
        &self,
        uow: &mut dyn UnitOfWork,
        client_id: ClientId,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row =
            sqlx::query("SELECT 1 FROM oauth.client WHERE tenant_id = $1 AND id = $2 FOR UPDATE")
                .bind(tenant.as_uuid())
                .bind(client_id.as_uuid())
                .fetch_optional(connection(uow)?)
                .await
                .map_err(get)?;
        Ok(row.is_some())
    }

    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        mapper: &ClaimMapper,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = mapper.snapshot();
        sqlx::query(
            "INSERT INTO oauth.claim_mapper
                 (tenant_id, id, client_id, claim, claim_normalized, targets, scope, source,
                  created_at, updated_at, version)
             VALUES ($1, $2, $3, $4, lower($4), $5, $6, $7, $8, $9, 0)",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.client_id.as_uuid())
        .bind(&state.settings.claim)
        .bind(targets_of(mapper))
        .bind(state.settings.scope.as_deref())
        .bind(state.settings.source.to_json())
        .bind(state.created_at)
        .bind(state.updated_at)
        .execute(connection(uow)?)
        .await
        .map_err(|error| refused(&error))?;
        Ok(())
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        mapper: &ClaimMapper,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = mapper.snapshot();
        let version =
            i32::try_from(state.version).map_err(|_| corrupted("version out of range"))?;
        let changed = sqlx::query(
            "UPDATE oauth.claim_mapper
             SET claim = $4, claim_normalized = lower($4), targets = $5, scope = $6,
                 source = $7, updated_at = $8, version = version + 1
             WHERE tenant_id = $1 AND id = $2 AND client_id = $3 AND version = $9",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.client_id.as_uuid())
        .bind(&state.settings.claim)
        .bind(targets_of(mapper))
        .bind(state.settings.scope.as_deref())
        .bind(state.settings.source.to_json())
        .bind(state.updated_at)
        .bind(version)
        .execute(connection(uow)?)
        .await
        .map_err(|error| refused(&error))?
        .rows_affected();
        if changed == 0 {
            return Err(DomainError::conflict(
                "oauth.claim_mapper_modified_concurrently",
                "it was changed by someone else; read it again",
            ));
        }
        Ok(())
    }

    async fn delete(
        &self,
        uow: &mut dyn UnitOfWork,
        client_id: ClientId,
        id: ClaimMapperId,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let deleted = sqlx::query(
            "DELETE FROM oauth.claim_mapper WHERE tenant_id = $1 AND client_id = $2 AND id = $3",
        )
        .bind(tenant.as_uuid())
        .bind(client_id.as_uuid())
        .bind(id.as_uuid())
        .execute(connection(uow)?)
        .await
        .map_err(get)?
        .rows_affected();
        Ok(deleted > 0)
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        client_id: ClientId,
        id: ClaimMapperId,
    ) -> Result<Option<ClaimMapper>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM oauth.claim_mapper
             WHERE tenant_id = $1 AND client_id = $2 AND id = $3"
        )))
        .bind(tenant.as_uuid())
        .bind(client_id.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(get)?
        .as_ref()
        .map(mapper_from)
        .transpose()
    }

    async fn list_for_client(
        &self,
        uow: &mut dyn UnitOfWork,
        client_id: ClientId,
    ) -> Result<Vec<ClaimMapper>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM oauth.claim_mapper
             WHERE tenant_id = $1 AND client_id = $2
             ORDER BY claim"
        )))
        .bind(tenant.as_uuid())
        .bind(client_id.as_uuid())
        .fetch_all(connection(uow)?)
        .await
        .map_err(get)?
        .iter()
        .map(mapper_from)
        .collect()
    }
}
