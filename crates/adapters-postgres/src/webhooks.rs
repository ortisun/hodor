//! PostgreSQL storage for the webhooks context.
//!
//! See `docs/architecture/contexts/webhooks.md`, "Storage".

use crate::uow::{connection, database_error};
use hodor_kernel::{DomainError, EventId, SealedSecret, TenantId, Timestamp, UnitOfWork};
use hodor_webhooks::api::{
    Delivery, DeliveryId, DeliveryQuery, DeliverySnapshot, DeliveryStatus, DeliveryStore,
    DueDeliveries, Endpoint, EndpointId, EndpointSnapshot, EndpointStore, SigningSecret,
    SigningSecretId, event_types,
};
use sqlx::PgPool;
use sqlx::types::Uuid;

/// [`EndpointStore`] on `webhooks.endpoint`, `webhooks.subscription` and
/// `webhooks.signing_secret`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgEndpointStore;

/// [`DeliveryStore`] on `webhooks.delivery`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgDeliveryStore;

fn corrupted(what: &str) -> DomainError {
    DomainError::internal(
        "webhooks.stored_data_invalid",
        "a webhook could not be loaded",
    )
    .with_detail(what.to_owned())
}

fn endpoint_not_found() -> DomainError {
    DomainError::not_found(
        "webhooks.endpoint_not_found",
        "there is no such webhook endpoint",
    )
}

/// A foreign key that names an endpoint the tenant does not have.
fn reference_error(error: &sqlx::Error) -> DomainError {
    if let sqlx::Error::Database(database) = error
        && database.is_foreign_key_violation()
    {
        return endpoint_not_found();
    }
    database_error(error)
}

type EndpointRow = (
    Uuid,
    String,
    Option<String>,
    Timestamp,
    Timestamp,
    i32,
    Vec<String>,
);

/// A statement that reads endpoints with their subscriptions, written
/// whole from literals.
macro_rules! select_endpoints {
    ($rest:literal) => {
        concat!(
            "SELECT e.id, e.url, e.description, e.created_at, e.updated_at, e.version,
                    COALESCE(ARRAY(SELECT s.event_type FROM webhooks.subscription s
                                   WHERE s.tenant_id = e.tenant_id AND s.endpoint_id = e.id
                                   ORDER BY s.event_type), '{}')
             FROM webhooks.endpoint e ",
            $rest
        )
    };
}

fn endpoint_from(row: EndpointRow) -> Result<Endpoint, DomainError> {
    let (id, url, description, created_at, updated_at, version, types) = row;
    Ok(Endpoint::from_snapshot(EndpointSnapshot {
        id: EndpointId::from_uuid(id),
        url,
        description,
        event_types: event_types(&types).map_err(|_| corrupted("unknown event type"))?,
        created_at,
        updated_at,
        version: u32::try_from(version).map_err(|_| corrupted("negative version"))?,
    }))
}

type SecretRow = (Uuid, Uuid, Vec<u8>, Timestamp, Option<Timestamp>);

fn secret_from(row: SecretRow) -> SigningSecret {
    let (id, endpoint_id, sealed, created_at, expires_at) = row;
    SigningSecret {
        id: SigningSecretId::from_uuid(id),
        endpoint_id: EndpointId::from_uuid(endpoint_id),
        sealed: SealedSecret::from_stored(sealed),
        created_at,
        expires_at,
    }
}

async fn write_subscriptions(
    uow: &mut dyn UnitOfWork,
    endpoint: &Endpoint,
) -> Result<(), DomainError> {
    let tenant = uow.tenant().tenant_id();
    let types: Vec<&str> = endpoint
        .snapshot()
        .event_types
        .iter()
        .map(|event_type| event_type.as_str())
        .collect();
    sqlx::query("DELETE FROM webhooks.subscription WHERE tenant_id = $1 AND endpoint_id = $2")
        .bind(tenant.as_uuid())
        .bind(endpoint.id().as_uuid())
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
    sqlx::query(
        "INSERT INTO webhooks.subscription (tenant_id, endpoint_id, event_type)
         SELECT $1, $2, unnest($3::text[])",
    )
    .bind(tenant.as_uuid())
    .bind(endpoint.id().as_uuid())
    .bind(&types)
    .execute(connection(uow)?)
    .await
    .map_err(|e| database_error(&e))?;
    Ok(())
}

async fn read_endpoint(
    uow: &mut dyn UnitOfWork,
    id: EndpointId,
    lock: bool,
) -> Result<Option<Endpoint>, DomainError> {
    let tenant = uow.tenant().tenant_id();
    let statement = if lock {
        select_endpoints!("WHERE e.tenant_id = $1 AND e.id = $2 FOR UPDATE")
    } else {
        select_endpoints!("WHERE e.tenant_id = $1 AND e.id = $2")
    };
    let row: Option<EndpointRow> = sqlx::query_as(statement)
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
    row.map(endpoint_from).transpose()
}

#[async_trait::async_trait]
impl EndpointStore for PgEndpointStore {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        endpoint: &Endpoint,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = endpoint.snapshot();
        sqlx::query(
            "INSERT INTO webhooks.endpoint
                 (tenant_id, id, url, description, created_at, updated_at, version)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(&state.url)
        .bind(state.description.as_deref())
        .bind(state.created_at)
        .bind(state.updated_at)
        .bind(i32::try_from(state.version).unwrap_or(i32::MAX))
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        write_subscriptions(uow, endpoint).await
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: EndpointId,
    ) -> Result<Option<Endpoint>, DomainError> {
        read_endpoint(uow, id, false).await
    }

    async fn lock(
        &self,
        uow: &mut dyn UnitOfWork,
        id: EndpointId,
    ) -> Result<Option<Endpoint>, DomainError> {
        read_endpoint(uow, id, true).await
    }

    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        after: Option<EndpointId>,
        limit: u32,
    ) -> Result<Vec<Endpoint>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let statement = select_endpoints!(
            "WHERE e.tenant_id = $1 AND ($2::uuid IS NULL OR e.id > $2) ORDER BY e.id LIMIT $3"
        );
        let rows: Vec<EndpointRow> = sqlx::query_as(statement)
            .bind(tenant.as_uuid())
            .bind(after.map(|id| id.as_uuid()))
            .bind(i64::from(limit))
            .fetch_all(connection(uow)?)
            .await
            .map_err(|e| database_error(&e))?;
        rows.into_iter().map(endpoint_from).collect()
    }

    async fn count(&self, uow: &mut dyn UnitOfWork) -> Result<u32, DomainError> {
        let tenant = uow.tenant().tenant_id();
        // Two registrations in one tenant count one after the other.
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended('webhooks.endpoints:' || $1::text, 0))",
        )
        .bind(tenant.as_uuid())
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        let (count,): (i64,) =
            sqlx::query_as("SELECT count(*) FROM webhooks.endpoint WHERE tenant_id = $1")
                .bind(tenant.as_uuid())
                .fetch_one(connection(uow)?)
                .await
                .map_err(|e| database_error(&e))?;
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        endpoint: &Endpoint,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = endpoint.snapshot();
        let changed = sqlx::query(
            "UPDATE webhooks.endpoint
             SET description = $3, updated_at = $4, version = version + 1
             WHERE tenant_id = $1 AND id = $2 AND version = $5",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.description.as_deref())
        .bind(state.updated_at)
        .bind(i32::try_from(state.version).unwrap_or(i32::MAX))
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        if changed.rows_affected() == 0 {
            let exists = read_endpoint(uow, state.id, false).await?.is_some();
            return Err(if exists {
                DomainError::conflict(
                    "webhooks.endpoint_changed",
                    "the endpoint changed meanwhile; read it again",
                )
            } else {
                endpoint_not_found()
            });
        }
        write_subscriptions(uow, endpoint).await
    }

    async fn remove(&self, uow: &mut dyn UnitOfWork, id: EndpointId) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let removed = sqlx::query("DELETE FROM webhooks.endpoint WHERE tenant_id = $1 AND id = $2")
            .bind(tenant.as_uuid())
            .bind(id.as_uuid())
            .execute(connection(uow)?)
            .await
            .map_err(|e| database_error(&e))?;
        Ok(removed.rows_affected() > 0)
    }

    async fn subscribed_to(
        &self,
        uow: &mut dyn UnitOfWork,
        event_type: &str,
    ) -> Result<Vec<EndpointId>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let rows: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT endpoint_id FROM webhooks.subscription
             WHERE tenant_id = $1 AND event_type = $2
             ORDER BY endpoint_id",
        )
        .bind(tenant.as_uuid())
        .bind(event_type)
        .fetch_all(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(rows
            .into_iter()
            .map(|(id,)| EndpointId::from_uuid(id))
            .collect())
    }

    async fn add_secret(
        &self,
        uow: &mut dyn UnitOfWork,
        secret: &SigningSecret,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "INSERT INTO webhooks.signing_secret
                 (tenant_id, id, endpoint_id, sealed_secret, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(tenant.as_uuid())
        .bind(secret.id.as_uuid())
        .bind(secret.endpoint_id.as_uuid())
        .bind(secret.sealed.as_bytes())
        .bind(secret.created_at)
        .bind(secret.expires_at)
        .execute(connection(uow)?)
        .await
        .map_err(|e| reference_error(&e))?;
        Ok(())
    }

    async fn secrets(
        &self,
        uow: &mut dyn UnitOfWork,
        endpoint: EndpointId,
    ) -> Result<Vec<SigningSecret>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let rows: Vec<SecretRow> = sqlx::query_as(
            "SELECT id, endpoint_id, sealed_secret, created_at, expires_at
             FROM webhooks.signing_secret
             WHERE tenant_id = $1 AND endpoint_id = $2
             ORDER BY created_at DESC, id DESC",
        )
        .bind(tenant.as_uuid())
        .bind(endpoint.as_uuid())
        .fetch_all(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(rows.into_iter().map(secret_from).collect())
    }

    async fn end_secret(
        &self,
        uow: &mut dyn UnitOfWork,
        id: SigningSecretId,
        expires_at: Timestamp,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "UPDATE webhooks.signing_secret SET expires_at = $3
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .bind(expires_at)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn remove_ended_secrets(
        &self,
        uow: &mut dyn UnitOfWork,
        endpoint: EndpointId,
        now: Timestamp,
    ) -> Result<u64, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let removed = sqlx::query(
            "DELETE FROM webhooks.signing_secret
             WHERE tenant_id = $1 AND endpoint_id = $2 AND expires_at <= $3",
        )
        .bind(tenant.as_uuid())
        .bind(endpoint.as_uuid())
        .bind(now)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(removed.rows_affected())
    }
}

type DeliveryRow = (
    Uuid,
    Uuid,
    Uuid,
    String,
    String,
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
            "SELECT id, endpoint_id, event_id, event_type, payload, status, attempts,
                    next_attempt_at, leased_until, last_response_status, last_error, created_at,
                    finished_at
             FROM webhooks.delivery ",
            $rest
        )
    };
}

/// How a delivery is read: as it is, held, or held unless someone else
/// holds it.
#[derive(Clone, Copy)]
enum Hold {
    No,
    Wait,
    Skip,
}

fn delivery_from(row: DeliveryRow) -> Result<Delivery, DomainError> {
    let (
        id,
        endpoint_id,
        event_id,
        event_type,
        payload,
        status,
        attempts,
        next_attempt_at,
        leased_until,
        last_response_status,
        last_error,
        created_at,
        finished_at,
    ) = row;
    Ok(Delivery::from_snapshot(DeliverySnapshot {
        id: DeliveryId::from_uuid(id),
        endpoint_id: EndpointId::from_uuid(endpoint_id),
        event_id: EventId::from_uuid(event_id),
        event_type,
        payload,
        status: DeliveryStatus::from_name(&status).ok_or_else(|| corrupted("unknown status"))?,
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

async fn read_delivery(
    uow: &mut dyn UnitOfWork,
    id: DeliveryId,
    hold: Hold,
) -> Result<Option<Delivery>, DomainError> {
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
impl DeliveryStore for PgDeliveryStore {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        delivery: &Delivery,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = delivery.snapshot();
        let inserted = sqlx::query(
            "INSERT INTO webhooks.delivery
                 (tenant_id, id, endpoint_id, event_id, event_type, payload, status, attempts,
                  next_attempt_at, leased_until, last_response_status, last_error, created_at,
                  finished_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
             ON CONFLICT ON CONSTRAINT delivery_once_per_endpoint_and_event DO NOTHING",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.endpoint_id.as_uuid())
        .bind(state.event_id.as_uuid())
        .bind(&state.event_type)
        .bind(&state.payload)
        .bind(state.status.as_str())
        .bind(i32::try_from(state.attempts).unwrap_or(i32::MAX))
        .bind(state.next_attempt_at)
        .bind(state.leased_until)
        .bind(state.last_response_status.map(i32::from))
        .bind(state.last_error.as_deref())
        .bind(state.created_at)
        .bind(state.finished_at)
        .execute(connection(uow)?)
        .await
        .map_err(|e| reference_error(&e))?;
        Ok(inserted.rows_affected() > 0)
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: DeliveryId,
    ) -> Result<Option<Delivery>, DomainError> {
        read_delivery(uow, id, Hold::No).await
    }

    async fn take(
        &self,
        uow: &mut dyn UnitOfWork,
        id: DeliveryId,
    ) -> Result<Option<Delivery>, DomainError> {
        // A delivery another worker holds is skipped, not waited for.
        read_delivery(uow, id, Hold::Skip).await
    }

    async fn lock(
        &self,
        uow: &mut dyn UnitOfWork,
        id: DeliveryId,
    ) -> Result<Option<Delivery>, DomainError> {
        read_delivery(uow, id, Hold::Wait).await
    }

    async fn leased(
        &self,
        uow: &mut dyn UnitOfWork,
        endpoint: EndpointId,
        now: Timestamp,
    ) -> Result<u32, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let (count,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM webhooks.delivery
             WHERE tenant_id = $1 AND endpoint_id = $2 AND status = 'pending'
               AND leased_until IS NOT NULL AND leased_until > $3",
        )
        .bind(tenant.as_uuid())
        .bind(endpoint.as_uuid())
        .bind(now)
        .fetch_one(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        delivery: &Delivery,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = delivery.snapshot();
        let updated = sqlx::query(
            "UPDATE webhooks.delivery
             SET payload = $3, status = $4, attempts = $5, next_attempt_at = $6,
                 leased_until = $7, last_response_status = $8, last_error = $9,
                 finished_at = $10
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(&state.payload)
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
                "webhooks.delivery_not_found",
                "there is no such webhook delivery",
            ));
        }
        Ok(())
    }

    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        query: DeliveryQuery,
        after: Option<DeliveryId>,
        limit: u32,
    ) -> Result<Vec<Delivery>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let statement = select_deliveries!(
            "WHERE tenant_id = $1
               AND ($2::uuid IS NULL OR endpoint_id = $2)
               AND ($3::text IS NULL OR status = $3)
               AND ($4::uuid IS NULL OR id < $4)
             ORDER BY id DESC LIMIT $5"
        );
        let rows: Vec<DeliveryRow> = sqlx::query_as(statement)
            .bind(tenant.as_uuid())
            .bind(query.endpoint.map(|id| id.as_uuid()))
            .bind(query.status.map(DeliveryStatus::as_str))
            .bind(after.map(|id| id.as_uuid()))
            .bind(i64::from(limit))
            .fetch_all(connection(uow)?)
            .await
            .map_err(|e| database_error(&e))?;
        rows.into_iter().map(delivery_from).collect()
    }
}

/// [`DueDeliveries`] on `webhooks.delivery`, across tenants.
#[derive(Debug, Clone)]
pub struct PgDueDeliveries {
    platform: PgPool,
}

impl PgDueDeliveries {
    /// `platform` must connect as a member of `hodor_platform`; it is used
    /// only to find the deliveries that are due. Each is then leased and
    /// recorded through the application role, bound to its tenant.
    #[must_use]
    pub const fn new(platform: PgPool) -> Self {
        Self { platform }
    }
}

#[async_trait::async_trait]
impl DueDeliveries for PgDueDeliveries {
    async fn due(
        &self,
        now: Timestamp,
        limit: u32,
    ) -> Result<Vec<(TenantId, DeliveryId)>, DomainError> {
        let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT tenant_id, id
             FROM webhooks.delivery
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
            .map(|(tenant, id)| (TenantId::from_uuid(tenant), DeliveryId::from_uuid(id)))
            .collect())
    }
}
