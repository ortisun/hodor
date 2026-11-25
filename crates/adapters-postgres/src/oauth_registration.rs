//! PostgreSQL storage for client registration: the settings of each
//! tenant, and its initial access tokens, of which only the SHA-256 is
//! kept.
//!
//! See `docs/architecture/contexts/oauth.md`, "Client registration".

use crate::uow::{connection, database_error};
use hodor_kernel::{DomainError, Timestamp, UnitOfWork};
use hodor_oauth::api::{
    ApplicationId, ClientRegistration, ClientRegistrationSnapshot, ClientRegistrationStore,
    InitialAccessToken, InitialAccessTokenHash, InitialAccessTokenId, InitialAccessTokenSnapshot,
    InitialAccessTokenStore, RegistrationPolicy, RegistrationSettings, ways_from_stored,
};
use sqlx::Row as _;
use sqlx::postgres::PgRow;

const APPLICATION_CONSTRAINT: &str = "client_registration_application_fk";
const SETTINGS_KEY: &str = "client_registration_pkey";

const SETTINGS_COLUMNS: &str =
    "enabled, application_id, ways, max_clients, policy, created_at, updated_at, version";
const TOKEN_COLUMNS: &str = "id, token_hash, hint, name, max_registrations, registrations, \
     created_at, expires_at, last_used_at, revoked_at";

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

fn modified() -> DomainError {
    DomainError::conflict(
        "oauth.client_registration_modified_concurrently",
        "it was changed by someone else; read it again",
    )
}

/// Translates the refusals of the settings' constraints.
fn refused(error: &sqlx::Error) -> DomainError {
    match error {
        sqlx::Error::Database(database) => match database.constraint() {
            Some(APPLICATION_CONSTRAINT) => DomainError::invalid(
                "oauth.client_registration_application_invalid",
                "registered clients belong to one application of the tenant",
            ),
            Some(SETTINGS_KEY) => modified(),
            _ => database_error(error),
        },
        _ => database_error(error),
    }
}

fn registration_from(row: &PgRow) -> Result<ClientRegistration, DomainError> {
    let ways: Vec<String> = row.try_get("ways").map_err(get)?;
    let policy: serde_json::Value = row.try_get("policy").map_err(get)?;
    let max_clients: i32 = row.try_get("max_clients").map_err(get)?;
    let version: i32 = row.try_get("version").map_err(get)?;
    let application: Option<sqlx::types::Uuid> = row.try_get("application_id").map_err(get)?;
    Ok(ClientRegistration::from_snapshot(
        ClientRegistrationSnapshot {
            settings: RegistrationSettings {
                enabled: row.try_get("enabled").map_err(get)?,
                application_id: application.map(ApplicationId::from_uuid),
                ways: ways_from_stored(&ways)?,
                max_clients: u32::try_from(max_clients)
                    .map_err(|_| corrupted("a negative bound of clients"))?,
                policy: RegistrationPolicy::from_json(&policy)
                    .map_err(|_| corrupted("a registration policy that does not read"))?,
            },
            created_at: row.try_get("created_at").map_err(get)?,
            updated_at: row.try_get("updated_at").map_err(get)?,
            version: u32::try_from(version).map_err(|_| corrupted("negative version"))?,
        },
    ))
}

fn ways_of(settings: &RegistrationSettings) -> Vec<&'static str> {
    settings.way_names()
}

fn bound_of(settings: &RegistrationSettings) -> Result<i32, DomainError> {
    i32::try_from(settings.max_clients).map_err(|_| corrupted("a bound of clients out of range"))
}

/// [`ClientRegistrationStore`] on `oauth.client_registration`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgClientRegistrationStore;

impl PgClientRegistrationStore {
    async fn read(
        uow: &mut dyn UnitOfWork,
        locking: bool,
    ) -> Result<Option<ClientRegistration>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let lock = if locking { " FOR UPDATE" } else { "" };
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {SETTINGS_COLUMNS} FROM oauth.client_registration WHERE tenant_id = $1{lock}"
        )))
        .bind(tenant.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(get)?
        .as_ref()
        .map(registration_from)
        .transpose()
    }
}

#[async_trait::async_trait]
impl ClientRegistrationStore for PgClientRegistrationStore {
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
    ) -> Result<Option<ClientRegistration>, DomainError> {
        Self::read(uow, false).await
    }

    async fn lock(
        &self,
        uow: &mut dyn UnitOfWork,
    ) -> Result<Option<ClientRegistration>, DomainError> {
        Self::read(uow, true).await
    }

    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        registration: &ClientRegistration,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = registration.snapshot();
        let settings = &state.settings;
        sqlx::query(
            "INSERT INTO oauth.client_registration
                 (tenant_id, enabled, application_id, ways, max_clients, policy, created_at,
                  updated_at, version)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0)",
        )
        .bind(tenant.as_uuid())
        .bind(settings.enabled)
        .bind(settings.application_id.map(|id| id.as_uuid()))
        .bind(ways_of(settings))
        .bind(bound_of(settings)?)
        .bind(settings.policy.to_json())
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
        registration: &ClientRegistration,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = registration.snapshot();
        let settings = &state.settings;
        let version =
            i32::try_from(state.version).map_err(|_| corrupted("version out of range"))?;
        let changed = sqlx::query(
            "UPDATE oauth.client_registration
             SET enabled = $2, application_id = $3, ways = $4, max_clients = $5, policy = $6,
                 updated_at = $7, version = version + 1
             WHERE tenant_id = $1 AND version = $8",
        )
        .bind(tenant.as_uuid())
        .bind(settings.enabled)
        .bind(settings.application_id.map(|id| id.as_uuid()))
        .bind(ways_of(settings))
        .bind(bound_of(settings)?)
        .bind(settings.policy.to_json())
        .bind(state.updated_at)
        .bind(version)
        .execute(connection(uow)?)
        .await
        .map_err(|error| refused(&error))?
        .rows_affected();
        if changed == 0 {
            return Err(modified());
        }
        Ok(())
    }
}

fn token_from(row: &PgRow) -> Result<InitialAccessToken, DomainError> {
    let hash: Vec<u8> = row.try_get("token_hash").map_err(get)?;
    let hash: [u8; 32] = hash
        .try_into()
        .map_err(|_| corrupted("a token's hash is not 32 bytes"))?;
    let count = |column: &str| -> Result<u32, DomainError> {
        let value: i32 = row.try_get(column).map_err(get)?;
        u32::try_from(value).map_err(|_| corrupted("a negative count of registrations"))
    };
    Ok(InitialAccessToken::from_snapshot(
        InitialAccessTokenSnapshot {
            id: InitialAccessTokenId::from_uuid(row.try_get("id").map_err(get)?),
            token_hash: InitialAccessTokenHash::from_stored(hash),
            hint: row.try_get("hint").map_err(get)?,
            name: row.try_get("name").map_err(get)?,
            max_registrations: count("max_registrations")?,
            registrations: count("registrations")?,
            created_at: row.try_get("created_at").map_err(get)?,
            expires_at: row.try_get("expires_at").map_err(get)?,
            last_used_at: row.try_get("last_used_at").map_err(get)?,
            revoked_at: row.try_get("revoked_at").map_err(get)?,
        },
    ))
}

fn count_of(value: u32) -> Result<i32, DomainError> {
    i32::try_from(value).map_err(|_| corrupted("a count of registrations out of range"))
}

/// [`InitialAccessTokenStore`] on `oauth.initial_access_token`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgInitialAccessTokenStore;

#[async_trait::async_trait]
impl InitialAccessTokenStore for PgInitialAccessTokenStore {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        token: &InitialAccessToken,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = token.snapshot();
        sqlx::query(
            "INSERT INTO oauth.initial_access_token
                 (tenant_id, id, token_hash, hint, name, max_registrations, registrations,
                  created_at, expires_at, last_used_at, revoked_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.token_hash.as_bytes().as_slice())
        .bind(&state.hint)
        .bind(&state.name)
        .bind(count_of(state.max_registrations)?)
        .bind(count_of(state.registrations)?)
        .bind(state.created_at)
        .bind(state.expires_at)
        .bind(state.last_used_at)
        .bind(state.revoked_at)
        .execute(connection(uow)?)
        .await
        .map_err(get)?;
        Ok(())
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: InitialAccessTokenId,
    ) -> Result<Option<InitialAccessToken>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {TOKEN_COLUMNS} FROM oauth.initial_access_token
             WHERE tenant_id = $1 AND id = $2"
        )))
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(get)?
        .as_ref()
        .map(token_from)
        .transpose()
    }

    async fn lock_by_hash(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &InitialAccessTokenHash,
    ) -> Result<Option<InitialAccessToken>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {TOKEN_COLUMNS} FROM oauth.initial_access_token
             WHERE tenant_id = $1 AND token_hash = $2
             FOR UPDATE"
        )))
        .bind(tenant.as_uuid())
        .bind(hash.as_bytes().as_slice())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(get)?
        .as_ref()
        .map(token_from)
        .transpose()
    }

    async fn list(&self, uow: &mut dyn UnitOfWork) -> Result<Vec<InitialAccessToken>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {TOKEN_COLUMNS} FROM oauth.initial_access_token
             WHERE tenant_id = $1
             ORDER BY created_at DESC, id DESC"
        )))
        .bind(tenant.as_uuid())
        .fetch_all(connection(uow)?)
        .await
        .map_err(get)?
        .iter()
        .map(token_from)
        .collect()
    }

    async fn count_active(
        &self,
        uow: &mut dyn UnitOfWork,
        now: Timestamp,
    ) -> Result<usize, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM oauth.initial_access_token
             WHERE tenant_id = $1 AND revoked_at IS NULL AND expires_at > $2
               AND registrations < max_registrations",
        )
        .bind(tenant.as_uuid())
        .bind(now)
        .fetch_one(connection(uow)?)
        .await
        .map_err(get)?;
        usize::try_from(count).map_err(|_| corrupted("a negative count"))
    }

    async fn record_use(
        &self,
        uow: &mut dyn UnitOfWork,
        token: &InitialAccessToken,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = token.snapshot();
        sqlx::query(
            "UPDATE oauth.initial_access_token
             SET registrations = $3, last_used_at = $4
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(count_of(state.registrations)?)
        .bind(state.last_used_at)
        .execute(connection(uow)?)
        .await
        .map_err(get)?;
        Ok(())
    }

    async fn revoke(
        &self,
        uow: &mut dyn UnitOfWork,
        id: InitialAccessTokenId,
        at: Timestamp,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let revoked = sqlx::query(
            "UPDATE oauth.initial_access_token SET revoked_at = $3
             WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL",
        )
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .bind(at)
        .execute(connection(uow)?)
        .await
        .map_err(get)?
        .rows_affected();
        Ok(revoked > 0)
    }
}
