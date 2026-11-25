//! PostgreSQL storage for back-channel logout: the clients of a session,
//! read from its grants, and the logout deliveries.
//!
//! See `docs/architecture/contexts/oauth.md`, "Back-channel logout".

use crate::uow::{connection, database_error};
use hodor_kernel::{DomainError, TenantId, Timestamp, UnitOfWork, UserId};
use hodor_oauth::api::{
    ClientId, DueLogoutDeliveries, LogoutDelivery, LogoutDeliveryId, LogoutDeliverySnapshot,
    LogoutDeliveryStatus, LogoutDeliveryStore, OPENID_SCOPE, SessionClients,
};
use hodor_session::api::SessionId;
use sqlx::PgPool;
use sqlx::types::Uuid;

/// [`SessionClients`] on `oauth.authorization_grant`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgSessionClients;

/// [`LogoutDeliveryStore`] on `oauth.logout_delivery`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgLogoutDeliveryStore;

fn corrupted(what: &str) -> DomainError {
    DomainError::internal(
        "oauth.stored_data_invalid",
        "stored OAuth data could not be read",
    )
    .with_detail(what.to_owned())
}

#[async_trait::async_trait]
impl SessionClients for PgSessionClients {
    async fn clients_of(
        &self,
        uow: &mut dyn UnitOfWork,
        session: SessionId,
    ) -> Result<Vec<ClientId>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let rows: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT DISTINCT client_id FROM oauth.authorization_grant
             WHERE tenant_id = $1 AND session_id = $2 AND $3 = ANY (scopes)
             ORDER BY client_id",
        )
        .bind(tenant.as_uuid())
        .bind(session.as_uuid())
        .bind(OPENID_SCOPE)
        .fetch_all(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(rows
            .into_iter()
            .map(|(id,)| ClientId::from_uuid(id))
            .collect())
    }
}

type DeliveryRow = (
    Uuid,
    Uuid,
    Uuid,
    Uuid,
    String,
    i32,
    Timestamp,
    Option<Timestamp>,
    Option<i32>,
    Option<String>,
    Timestamp,
    Option<Timestamp>,
);

/// A statement that reads deliveries, written whole from literals.
macro_rules! select_deliveries {
    ($rest:literal) => {
        concat!(
            "SELECT id, client_id, session_id, user_id, status, attempts, next_attempt_at,
                    leased_until, last_response_status, last_error, created_at, finished_at
             FROM oauth.logout_delivery ",
            $rest
        )
    };
}

fn delivery_from(row: DeliveryRow) -> Result<LogoutDelivery, DomainError> {
    let (
        id,
        client_id,
        session_id,
        user_id,
        status,
        attempts,
        next_attempt_at,
        leased_until,
        last_response_status,
        last_error,
        created_at,
        finished_at,
    ) = row;
    Ok(LogoutDelivery::from_snapshot(LogoutDeliverySnapshot {
        id: LogoutDeliveryId::from_uuid(id),
        client_id: ClientId::from_uuid(client_id),
        session_id: SessionId::from_uuid(session_id),
        user_id: UserId::from_uuid(user_id),
        status: LogoutDeliveryStatus::from_name(&status)
            .ok_or_else(|| corrupted("unknown logout delivery status"))?,
        attempts: u32::try_from(attempts).map_err(|_| corrupted("negative attempts"))?,
        next_attempt_at,
        leased_until,
        last_response_status: last_response_status
            .map(u16::try_from)
            .transpose()
            .map_err(|_| corrupted("status out of range"))?,
        last_error,
        created_at,
        finished_at,
    }))
}

/// Whether a read holds the row, and how.
#[derive(Clone, Copy)]
enum Hold {
    No,
    Wait,
    Skip,
}

async fn read_delivery(
    uow: &mut dyn UnitOfWork,
    id: LogoutDeliveryId,
    hold: Hold,
) -> Result<Option<LogoutDelivery>, DomainError> {
    let tenant = uow.tenant().tenant_id();
    let statement = match hold {
        Hold::No => select_deliveries!("WHERE tenant_id = $1 AND id = $2"),
        Hold::Wait => select_deliveries!("WHERE tenant_id = $1 AND id = $2 FOR UPDATE"),
        Hold::Skip => {
            select_deliveries!("WHERE tenant_id = $1 AND id = $2 FOR UPDATE SKIP LOCKED")
        }
    };
    let row: Option<DeliveryRow> = sqlx::query_as(statement)
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
    row.map(delivery_from).transpose()
}

#[async_trait::async_trait]
impl LogoutDeliveryStore for PgLogoutDeliveryStore {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        delivery: &LogoutDelivery,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = delivery.snapshot();
        let inserted = sqlx::query(
            "INSERT INTO oauth.logout_delivery
                 (tenant_id, id, client_id, session_id, user_id, status, attempts,
                  next_attempt_at, leased_until, last_response_status, last_error, created_at,
                  finished_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
             ON CONFLICT ON CONSTRAINT logout_delivery_once_per_client_and_session DO NOTHING",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.client_id.as_uuid())
        .bind(state.session_id.as_uuid())
        .bind(state.user_id.as_uuid())
        .bind(state.status.as_str())
        .bind(i32::try_from(state.attempts).unwrap_or(i32::MAX))
        .bind(state.next_attempt_at)
        .bind(state.leased_until)
        .bind(state.last_response_status.map(i32::from))
        .bind(state.last_error.as_deref())
        .bind(state.created_at)
        .bind(state.finished_at)
        .execute(connection(uow)?)
        .await;
        match inserted {
            Ok(done) => Ok(done.rows_affected() > 0),
            Err(sqlx::Error::Database(error)) if error.is_foreign_key_violation() => Err(
                DomainError::not_found("oauth.client_not_found", "there is no such client"),
            ),
            Err(error) => Err(database_error(&error)),
        }
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: LogoutDeliveryId,
    ) -> Result<Option<LogoutDelivery>, DomainError> {
        read_delivery(uow, id, Hold::No).await
    }

    async fn take(
        &self,
        uow: &mut dyn UnitOfWork,
        id: LogoutDeliveryId,
    ) -> Result<Option<LogoutDelivery>, DomainError> {
        // A delivery another worker holds is skipped, not waited for.
        read_delivery(uow, id, Hold::Skip).await
    }

    async fn lock(
        &self,
        uow: &mut dyn UnitOfWork,
        id: LogoutDeliveryId,
    ) -> Result<Option<LogoutDelivery>, DomainError> {
        read_delivery(uow, id, Hold::Wait).await
    }

    async fn hold_client(
        &self,
        uow: &mut dyn UnitOfWork,
        client: ClientId,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        // `NO KEY UPDATE`: another worker counting the same client waits,
        // while a delivery being made for the client, which only takes a
        // share of its key, does not.
        let held: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM oauth.client WHERE tenant_id = $1 AND id = $2 FOR NO KEY UPDATE",
        )
        .bind(tenant.as_uuid())
        .bind(client.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(held.is_some())
    }

    async fn leased(
        &self,
        uow: &mut dyn UnitOfWork,
        client: ClientId,
        now: Timestamp,
    ) -> Result<u32, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let (count,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM oauth.logout_delivery
             WHERE tenant_id = $1 AND client_id = $2 AND status = 'pending'
               AND leased_until IS NOT NULL AND leased_until > $3",
        )
        .bind(tenant.as_uuid())
        .bind(client.as_uuid())
        .bind(now)
        .fetch_one(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        delivery: &LogoutDelivery,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = delivery.snapshot();
        let updated = sqlx::query(
            "UPDATE oauth.logout_delivery
             SET status = $3, attempts = $4, next_attempt_at = $5, leased_until = $6,
                 last_response_status = $7, last_error = $8, finished_at = $9
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.status.as_str())
        .bind(i32::try_from(state.attempts).unwrap_or(i32::MAX))
        .bind(state.next_attempt_at)
        .bind(state.leased_until)
        .bind(state.last_response_status.map(i32::from))
        .bind(state.last_error.as_deref())
        .bind(state.finished_at)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        if updated.rows_affected() == 0 {
            return Err(DomainError::not_found(
                "oauth.logout_delivery_not_found",
                "there is no such logout delivery",
            ));
        }
        Ok(())
    }
}

/// [`DueLogoutDeliveries`] on `oauth.logout_delivery`, across tenants.
#[derive(Debug, Clone)]
pub struct PgDueLogoutDeliveries {
    platform: PgPool,
}

impl PgDueLogoutDeliveries {
    /// `platform` must connect as a member of `hodor_platform`; it is used
    /// only to find the deliveries that are due. Each is then leased and
    /// recorded through the application role, bound to its tenant.
    #[must_use]
    pub const fn new(platform: PgPool) -> Self {
        Self { platform }
    }
}

#[async_trait::async_trait]
impl DueLogoutDeliveries for PgDueLogoutDeliveries {
    async fn due(
        &self,
        now: Timestamp,
        limit: u32,
    ) -> Result<Vec<(TenantId, LogoutDeliveryId)>, DomainError> {
        let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT tenant_id, id
             FROM oauth.logout_delivery
             WHERE status = 'pending' AND next_attempt_at <= $1
               AND (leased_until IS NULL OR leased_until <= $1)
             ORDER BY next_attempt_at, id
             LIMIT $2",
        )
        .bind(now)
        .bind(i64::from(limit))
        .fetch_all(&self.platform)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(rows
            .into_iter()
            .map(|(tenant, id)| (TenantId::from_uuid(tenant), LogoutDeliveryId::from_uuid(id)))
            .collect())
    }
}
