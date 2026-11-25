//! PostgreSQL storage for trust domains of the keys context.
//!
//! See `docs/architecture/contexts/keys.md`, "Trust domains" and
//! "`keys.trust_domain`".

use crate::uow::{connection, database_error};
use hodor_kernel::{DomainError, TenantId, Timestamp, UnitOfWork};
use hodor_keys::api::{
    DueRefreshes, TrustBundle, TrustDomain, TrustDomainId, TrustDomainName, TrustDomainSnapshot,
    TrustDomainStore, TrustSource,
};
use sqlx::PgPool;
use sqlx::types::Uuid;

/// [`TrustDomainStore`] on `keys.trust_domain`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgTrustDomainStore;

const NAME_CONSTRAINT: &str = "trust_domain_name_unique";

const COLUMNS: &str = "id, name, source, bundle_endpoint_url, bundle, bundle_changed_at,
     fetched_at, next_refresh_at, leased_until, failing_since, last_error, created_at,
     updated_at, version";

type Row = (
    Uuid,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<Timestamp>,
    Option<Timestamp>,
    Option<Timestamp>,
    Option<Timestamp>,
    Option<Timestamp>,
    Option<String>,
    Timestamp,
    Timestamp,
    i32,
);

fn corrupted(what: &str) -> DomainError {
    DomainError::internal(
        "keys.stored_data_invalid",
        "the trust domain could not be loaded",
    )
    .with_detail(what.to_owned())
}

fn to_domain(row: Row) -> Result<TrustDomain, DomainError> {
    let (
        id,
        name,
        source,
        bundle_endpoint_url,
        bundle,
        bundle_changed_at,
        fetched_at,
        next_refresh_at,
        leased_until,
        failing_since,
        last_error,
        created_at,
        updated_at,
        version,
    ) = row;
    Ok(TrustDomain::from_snapshot(TrustDomainSnapshot {
        id: TrustDomainId::from_uuid(id),
        name: TrustDomainName::parse(&name).map_err(|_| corrupted("the name"))?,
        source: TrustSource::parse(&source).map_err(|_| corrupted("the source"))?,
        bundle_endpoint_url,
        bundle: bundle
            .as_deref()
            .map(TrustBundle::from_stored)
            .transpose()?,
        bundle_changed_at,
        fetched_at,
        next_refresh_at,
        leased_until,
        failing_since,
        last_error,
        created_at,
        updated_at,
        version: u32::try_from(version).map_err(|_| corrupted("a negative version"))?,
    }))
}

/// How a read holds the row it reads.
#[derive(Debug, Clone, Copy)]
enum Hold {
    Not,
    Wait,
    Skip,
}

async fn read_one(
    uow: &mut dyn UnitOfWork,
    id: TrustDomainId,
    hold: Hold,
) -> Result<Option<TrustDomain>, DomainError> {
    let tenant = uow.tenant().tenant_id();
    let suffix = match hold {
        Hold::Not => "",
        Hold::Wait => " FOR UPDATE",
        Hold::Skip => " FOR UPDATE SKIP LOCKED",
    };
    let statement =
        format!("SELECT {COLUMNS} FROM keys.trust_domain WHERE tenant_id = $1 AND id = $2{suffix}");
    let row: Option<Row> = sqlx::query_as(sqlx::AssertSqlSafe(statement))
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
    row.map(to_domain).transpose()
}

fn whole(number: Option<u64>) -> Option<i64> {
    number.and_then(|number| i64::try_from(number).ok())
}

#[async_trait::async_trait]
impl TrustDomainStore for PgTrustDomainStore {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        domain: &TrustDomain,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = domain.snapshot();
        let bundle = state.bundle.as_ref();
        let inserted = sqlx::query(
            "INSERT INTO keys.trust_domain
                 (tenant_id, id, name, source, bundle_endpoint_url, bundle, bundle_sequence,
                  bundle_refresh_hint_seconds, bundle_changed_at, fetched_at, next_refresh_at,
                  leased_until, failing_since, last_error, created_at, updated_at, version)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.name.as_str())
        .bind(state.source.as_str())
        .bind(state.bundle_endpoint_url.as_deref())
        .bind(bundle.map(TrustBundle::document))
        .bind(whole(bundle.and_then(TrustBundle::sequence)))
        .bind(whole(bundle.and_then(TrustBundle::refresh_hint)))
        .bind(state.bundle_changed_at)
        .bind(state.fetched_at)
        .bind(state.next_refresh_at)
        .bind(state.leased_until)
        .bind(state.failing_since)
        .bind(state.last_error.as_deref())
        .bind(state.created_at)
        .bind(state.updated_at)
        .bind(i32::try_from(state.version).unwrap_or(i32::MAX))
        .execute(connection(uow)?)
        .await;
        match inserted {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(error)) if error.constraint() == Some(NAME_CONSTRAINT) => {
                Err(DomainError::conflict(
                    "keys.trust_domain_name_taken",
                    "the tenant already has a trust domain of that name",
                ))
            }
            Err(error) => Err(database_error(&error)),
        }
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: TrustDomainId,
    ) -> Result<Option<TrustDomain>, DomainError> {
        read_one(uow, id, Hold::Not).await
    }

    async fn find_by_name(
        &self,
        uow: &mut dyn UnitOfWork,
        name: &str,
    ) -> Result<Option<TrustDomain>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let statement =
            format!("SELECT {COLUMNS} FROM keys.trust_domain WHERE tenant_id = $1 AND name = $2");
        let row: Option<Row> = sqlx::query_as(sqlx::AssertSqlSafe(statement))
            .bind(tenant.as_uuid())
            .bind(name)
            .fetch_optional(connection(uow)?)
            .await
            .map_err(|e| database_error(&e))?;
        row.map(to_domain).transpose()
    }

    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        after: Option<TrustDomainId>,
        limit: u32,
    ) -> Result<Vec<TrustDomain>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let statement = format!(
            "SELECT {COLUMNS} FROM keys.trust_domain
             WHERE tenant_id = $1 AND ($2::uuid IS NULL OR id > $2)
             ORDER BY id LIMIT $3"
        );
        let rows: Vec<Row> = sqlx::query_as(sqlx::AssertSqlSafe(statement))
            .bind(tenant.as_uuid())
            .bind(after.map(|id| id.as_uuid()))
            .bind(i64::from(limit))
            .fetch_all(connection(uow)?)
            .await
            .map_err(|e| database_error(&e))?;
        rows.into_iter().map(to_domain).collect()
    }

    async fn count(&self, uow: &mut dyn UnitOfWork) -> Result<u32, DomainError> {
        let tenant = uow.tenant().tenant_id();
        // Two additions in one tenant count one after the other.
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended('keys.trust_domains:' || $1::text, 0))",
        )
        .bind(tenant.as_uuid())
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        let (count,): (i64,) =
            sqlx::query_as("SELECT count(*) FROM keys.trust_domain WHERE tenant_id = $1")
                .bind(tenant.as_uuid())
                .fetch_one(connection(uow)?)
                .await
                .map_err(|e| database_error(&e))?;
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        domain: &TrustDomain,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = domain.snapshot();
        let bundle = state.bundle.as_ref();
        // The name and the time it was added never change.
        let changed = sqlx::query(
            "UPDATE keys.trust_domain
             SET source = $3, bundle_endpoint_url = $4, bundle = $5, bundle_sequence = $6,
                 bundle_refresh_hint_seconds = $7, bundle_changed_at = $8, fetched_at = $9,
                 next_refresh_at = $10, leased_until = $11, failing_since = $12,
                 last_error = $13, updated_at = $14, version = version + 1
             WHERE tenant_id = $1 AND id = $2 AND version = $15",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.source.as_str())
        .bind(state.bundle_endpoint_url.as_deref())
        .bind(bundle.map(TrustBundle::document))
        .bind(whole(bundle.and_then(TrustBundle::sequence)))
        .bind(whole(bundle.and_then(TrustBundle::refresh_hint)))
        .bind(state.bundle_changed_at)
        .bind(state.fetched_at)
        .bind(state.next_refresh_at)
        .bind(state.leased_until)
        .bind(state.failing_since)
        .bind(state.last_error.as_deref())
        .bind(state.updated_at)
        .bind(i32::try_from(state.version).unwrap_or(i32::MAX))
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        if changed.rows_affected() == 0 {
            let exists = read_one(uow, state.id, Hold::Not).await?.is_some();
            return Err(if exists {
                DomainError::conflict(
                    "keys.trust_domain_changed",
                    "the trust domain changed meanwhile; read it again",
                )
            } else {
                DomainError::not_found(
                    "keys.trust_domain_not_found",
                    "there is no such trust domain",
                )
            });
        }
        Ok(())
    }

    async fn remove(
        &self,
        uow: &mut dyn UnitOfWork,
        id: TrustDomainId,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let removed = sqlx::query("DELETE FROM keys.trust_domain WHERE tenant_id = $1 AND id = $2")
            .bind(tenant.as_uuid())
            .bind(id.as_uuid())
            .execute(connection(uow)?)
            .await
            .map_err(|e| database_error(&e))?;
        Ok(removed.rows_affected() > 0)
    }

    async fn take(
        &self,
        uow: &mut dyn UnitOfWork,
        id: TrustDomainId,
    ) -> Result<Option<TrustDomain>, DomainError> {
        // A trust domain another worker holds is skipped, not waited for.
        read_one(uow, id, Hold::Skip).await
    }

    async fn lock(
        &self,
        uow: &mut dyn UnitOfWork,
        id: TrustDomainId,
    ) -> Result<Option<TrustDomain>, DomainError> {
        read_one(uow, id, Hold::Wait).await
    }
}

/// [`DueRefreshes`] over every tenant's trust domains, through the platform
/// connection.
#[derive(Debug, Clone)]
pub struct PgDueRefreshes {
    platform: PgPool,
}

impl PgDueRefreshes {
    /// `platform` must connect as a member of `hodor_platform`; it is used
    /// only to find the trust domains whose bundle is due. Each is then
    /// leased and recorded through the application role, bound to its
    /// tenant.
    #[must_use]
    pub const fn new(platform: PgPool) -> Self {
        Self { platform }
    }
}

#[async_trait::async_trait]
impl DueRefreshes for PgDueRefreshes {
    async fn due(
        &self,
        now: Timestamp,
        limit: u32,
    ) -> Result<Vec<(TenantId, TrustDomainId)>, DomainError> {
        let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT tenant_id, id
             FROM keys.trust_domain
             WHERE source = 'bundle_endpoint' AND next_refresh_at <= $1
               AND (leased_until IS NULL OR leased_until <= $1)
             ORDER BY next_refresh_at, id
             LIMIT $2",
        )
        .bind(now)
        .bind(i64::from(limit))
        .fetch_all(&self.platform)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(rows
            .into_iter()
            .map(|(tenant, id)| (TenantId::from_uuid(tenant), TrustDomainId::from_uuid(id)))
            .collect())
    }
}
