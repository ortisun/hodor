//! PostgreSQL storage for consent: what a person agreed to for a client,
//! and the history of it.
//!
//! See `docs/architecture/contexts/oauth.md`, "Consent".

use crate::uow::{connection, database_error};
use hodor_kernel::{DomainError, Timestamp, UnitOfWork, UserId};
use hodor_oauth::api::{ClientId, Consent, ConsentActor, ConsentHistoryEntry, ConsentStore};
use sqlx::Row as _;
use sqlx::postgres::PgRow;
use sqlx::types::Uuid;

const CONSENT_CLIENT_CONSTRAINT: &str = "consent_client_fk";
const HISTORY_CLIENT_CONSTRAINT: &str = "consent_history_client_fk";

fn get(error: sqlx::Error) -> DomainError {
    database_error(&error)
}

fn refused(error: &sqlx::Error, constraint: &str) -> DomainError {
    match error {
        sqlx::Error::Database(database) if database.constraint() == Some(constraint) => {
            DomainError::not_found("oauth.client_not_found", "there is no such client")
        }
        _ => database_error(error),
    }
}

fn consent_from(row: &PgRow) -> Result<Consent, DomainError> {
    let by: Option<String> = row.try_get("withdrawn_by").map_err(get)?;
    Ok(Consent {
        user_id: UserId::from_uuid(row.try_get("user_id").map_err(get)?),
        client_id: ClientId::from_uuid(row.try_get("client_id").map_err(get)?),
        scopes: row.try_get("scopes").map_err(get)?,
        audiences: row.try_get("audiences").map_err(get)?,
        given_at: row.try_get("given_at").map_err(get)?,
        expires_at: row.try_get("expires_at").map_err(get)?,
        withdrawn_at: row.try_get("withdrawn_at").map_err(get)?,
        withdrawn_by: by.as_deref().map(ConsentActor::from_stored).transpose()?,
    })
}

/// [`ConsentStore`] on `oauth.consent` and `oauth.consent_history`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgConsentStore;

#[async_trait::async_trait]
impl ConsentStore for PgConsentStore {
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        user: UserId,
        client: ClientId,
    ) -> Result<Option<Consent>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "SELECT user_id, client_id, scopes, audiences, given_at, expires_at, withdrawn_at,
                    withdrawn_by
             FROM oauth.consent
             WHERE tenant_id = $1 AND user_id = $2 AND client_id = $3",
        )
        .bind(tenant.as_uuid())
        .bind(user.as_uuid())
        .bind(client.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(get)?
        .as_ref()
        .map(consent_from)
        .transpose()
    }

    async fn save(&self, uow: &mut dyn UnitOfWork, consent: &Consent) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "INSERT INTO oauth.consent
                 (tenant_id, user_id, client_id, scopes, audiences, given_at, expires_at,
                  withdrawn_at, withdrawn_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (tenant_id, user_id, client_id) DO UPDATE SET
                 scopes = EXCLUDED.scopes, audiences = EXCLUDED.audiences,
                 given_at = EXCLUDED.given_at, expires_at = EXCLUDED.expires_at,
                 withdrawn_at = EXCLUDED.withdrawn_at, withdrawn_by = EXCLUDED.withdrawn_by",
        )
        .bind(tenant.as_uuid())
        .bind(consent.user_id.as_uuid())
        .bind(consent.client_id.as_uuid())
        .bind(&consent.scopes)
        .bind(&consent.audiences)
        .bind(consent.given_at)
        .bind(consent.expires_at)
        .bind(consent.withdrawn_at)
        .bind(consent.withdrawn_by.map(ConsentActor::as_str))
        .execute(connection(uow)?)
        .await
        .map_err(|e| refused(&e, CONSENT_CLIENT_CONSTRAINT))?;
        Ok(())
    }

    async fn list_standing(
        &self,
        uow: &mut dyn UnitOfWork,
        user: UserId,
        now: Timestamp,
    ) -> Result<Vec<Consent>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "SELECT user_id, client_id, scopes, audiences, given_at, expires_at, withdrawn_at,
                    withdrawn_by
             FROM oauth.consent
             WHERE tenant_id = $1 AND user_id = $2 AND withdrawn_at IS NULL AND expires_at > $3
             ORDER BY given_at DESC, client_id",
        )
        .bind(tenant.as_uuid())
        .bind(user.as_uuid())
        .bind(now)
        .fetch_all(connection(uow)?)
        .await
        .map_err(get)?
        .iter()
        .map(consent_from)
        .collect()
    }

    async fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        entry: &ConsentHistoryEntry,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "INSERT INTO oauth.consent_history
                 (tenant_id, id, user_id, client_id, action, scopes, audiences, by_whom, at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(tenant.as_uuid())
        .bind(Uuid::now_v7())
        .bind(entry.user_id.as_uuid())
        .bind(entry.client_id.as_uuid())
        .bind(entry.action.as_str())
        .bind(&entry.scopes)
        .bind(&entry.audiences)
        .bind(entry.by.as_str())
        .bind(entry.at)
        .execute(connection(uow)?)
        .await
        .map_err(|e| refused(&e, HISTORY_CLIENT_CONSTRAINT))?;
        Ok(())
    }
}
