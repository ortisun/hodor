//! PostgreSQL storage for the keys context.
//!
//! See `docs/architecture/contexts/keys.md`, "Storage".

use crate::uow::{connection, database_error};
use hodor_kernel::{DomainError, PublicKey, Timestamp, UnitOfWork};
use hodor_keys::api::{
    KeyAlgorithm, KeyMaterial, KeyState, KeyStore, KeyUse, KeyVersion, KeyVersionId,
    KeyVersionSnapshot, SealingStateStore,
};
use sqlx::Row as _;
use sqlx::postgres::PgRow;
use sqlx::types::Uuid;

/// [`KeyStore`] on `keys.key_version`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgKeyStore;

const COLUMNS: &str = "id, algorithm, state, provider, key_material, public_rsa_modulus,
     public_rsa_exponent, public_p256_x, public_p256_y, public_ed25519, created_at, activated_at,
     retiring_at, retire_after, retired_at, revoked_at, revocation_reason";

fn corrupted(what: &str) -> DomainError {
    DomainError::internal(
        "keys.stored_data_invalid",
        "the key version could not be loaded",
    )
    .with_detail(what.to_owned())
}

fn to_version(row: &PgRow) -> Result<KeyVersion, DomainError> {
    let get = |error: sqlx::Error| database_error(&error);
    let bytes = |column: &str| row.try_get::<Option<Vec<u8>>, _>(column).map_err(get);
    let public_key = match (
        bytes("public_rsa_modulus")?,
        bytes("public_rsa_exponent")?,
        bytes("public_p256_x")?,
        bytes("public_p256_y")?,
        bytes("public_ed25519")?,
    ) {
        (Some(modulus), Some(exponent), None, None, None) => {
            Some(PublicKey::Rsa { modulus, exponent })
        }
        (None, None, Some(x), Some(y), None) => Some(PublicKey::P256 { x, y }),
        (None, None, None, None, Some(x)) => Some(PublicKey::Ed25519 { x }),
        (None, None, None, None, None) => None,
        _ => return Err(corrupted("the public key columns do not form one key")),
    };
    let time = |column: &str| row.try_get::<Option<Timestamp>, _>(column).map_err(get);
    Ok(KeyVersion::from_snapshot(KeyVersionSnapshot {
        id: KeyVersionId::from_uuid(row.try_get::<Uuid, _>("id").map_err(get)?),
        algorithm: KeyAlgorithm::from_stored(&row.try_get::<String, _>("algorithm").map_err(get)?)?,
        state: KeyState::from_stored(&row.try_get::<String, _>("state").map_err(get)?)?,
        provider: row.try_get("provider").map_err(get)?,
        material: KeyMaterial::from_stored(row.try_get("key_material").map_err(get)?),
        public_key,
        created_at: row.try_get("created_at").map_err(get)?,
        activated_at: time("activated_at")?,
        retiring_at: time("retiring_at")?,
        retire_after: time("retire_after")?,
        retired_at: time("retired_at")?,
        revoked_at: time("revoked_at")?,
        revocation_reason: row.try_get("revocation_reason").map_err(get)?,
    }))
}

/// The public key as its five columns: modulus, exponent, x and y of a
/// P-256 point, and an Ed25519 key.
type PublicColumns<'a> = (
    Option<&'a [u8]>,
    Option<&'a [u8]>,
    Option<&'a [u8]>,
    Option<&'a [u8]>,
    Option<&'a [u8]>,
);

fn public_columns(key: Option<&PublicKey>) -> PublicColumns<'_> {
    match key {
        Some(PublicKey::Rsa { modulus, exponent }) => (
            Some(modulus.as_slice()),
            Some(exponent.as_slice()),
            None,
            None,
            None,
        ),
        Some(PublicKey::P256 { x, y }) => {
            (None, None, Some(x.as_slice()), Some(y.as_slice()), None)
        }
        Some(PublicKey::Ed25519 { x }) => (None, None, None, None, Some(x.as_slice())),
        None => (None, None, None, None, None),
    }
}

#[async_trait::async_trait]
impl KeyStore for PgKeyStore {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        version: &KeyVersion,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = version.snapshot();
        let (modulus, exponent, x, y, ed25519) = public_columns(state.public_key.as_ref());
        sqlx::query(
            "INSERT INTO keys.key_version
                 (tenant_id, id, key_use, algorithm, state, provider, key_material,
                  public_rsa_modulus, public_rsa_exponent, public_p256_x, public_p256_y,
                  public_ed25519, created_at, activated_at, retiring_at, retire_after,
                  retired_at, revoked_at, revocation_reason)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
                     $17, $18, $19)",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(version.key_use().as_str())
        .bind(state.algorithm.as_str())
        .bind(state.state.as_str())
        .bind(&state.provider)
        .bind(state.material.as_bytes())
        .bind(modulus)
        .bind(exponent)
        .bind(x)
        .bind(y)
        .bind(ed25519)
        .bind(state.created_at)
        .bind(state.activated_at)
        .bind(state.retiring_at)
        .bind(state.retire_after)
        .bind(state.retired_at)
        .bind(state.revoked_at)
        .bind(&state.revocation_reason)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: KeyVersionId,
    ) -> Result<Option<KeyVersion>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM keys.key_version WHERE tenant_id = $1 AND id = $2"
        )))
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.as_ref().map(to_version).transpose()
    }

    async fn list_for_use(
        &self,
        uow: &mut dyn UnitOfWork,
        key_use: KeyUse,
    ) -> Result<Vec<KeyVersion>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM keys.key_version
             WHERE tenant_id = $1 AND key_use = $2
             ORDER BY created_at DESC, id DESC"
        )))
        .bind(tenant.as_uuid())
        .bind(key_use.as_str())
        .fetch_all(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        rows.iter().map(to_version).collect()
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        version: &KeyVersion,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = version.snapshot();
        // Only the lifecycle: the key, its algorithm and its public key are
        // written once, by `insert`.
        let result = sqlx::query(
            "UPDATE keys.key_version
             SET state = $3, activated_at = $4, retiring_at = $5, retire_after = $6,
                 retired_at = $7, revoked_at = $8, revocation_reason = $9
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.state.as_str())
        .bind(state.activated_at)
        .bind(state.retiring_at)
        .bind(state.retire_after)
        .bind(state.retired_at)
        .bind(state.revoked_at)
        .bind(&state.revocation_reason)
        .execute(connection(uow)?)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(database) if database.is_unique_violation() => {
                DomainError::conflict(
                    "keys.activation_conflict",
                    "another key version was activated at the same time",
                )
            }
            _ => database_error(&e),
        })?;
        if result.rows_affected() == 0 {
            return Err(DomainError::not_found(
                "keys.version_not_found",
                "the key version does not exist",
            ));
        }
        Ok(())
    }
}

/// [`SealingStateStore`] on `keys.sealing_state`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgSealingStateStore;

#[async_trait::async_trait]
impl SealingStateStore for PgSealingStateStore {
    async fn first_format_refused(&self, uow: &mut dyn UnitOfWork) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<(Uuid,)> =
            sqlx::query_as("SELECT tenant_id FROM keys.sealing_state WHERE tenant_id = $1")
                .bind(tenant.as_uuid())
                .fetch_optional(connection(uow)?)
                .await
                .map_err(|e| database_error(&e))?;
        Ok(row.is_some())
    }

    async fn refuse_first_format(
        &self,
        uow: &mut dyn UnitOfWork,
        at: Timestamp,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "INSERT INTO keys.sealing_state (tenant_id, first_format_refused_at)
             VALUES ($1, $2)
             ON CONFLICT (tenant_id) DO NOTHING",
        )
        .bind(tenant.as_uuid())
        .bind(at)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }
}
