//! The record of decisions in PostgreSQL, and the job that keeps its
//! partitions and its retention.
//!
//! See `docs/architecture/contexts/authorization.md`, "Storage of the
//! record".

use crate::database::Database;
use crate::uow::{PgUnitOfWork, connection, database_error};
use hodor_authorization::api::{
    DecisionFilter, DecisionId, DecisionLogMode, DecisionLogSettings, DecisionLogStore,
    DecisionRecord, Effect, MaskPath, SubjectKind,
};
use hodor_kernel::{
    Cursor, DomainError, Page, PageRequest, TenantContext, TenantId, Timestamp, UnitOfWork,
};
use sqlx::types::{Json, Uuid};
use sqlx::{PgPool, Postgres, QueryBuilder, Row};

/// The days the job prepares ahead of today.
pub const DAYS_PREPARED_AHEAD: i32 = 7;
/// The most tenants one pass of the retention job looks at.
const TENANTS_PER_PASS: i64 = 100;

/// The record of decisions and its settings, under row-level security.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgDecisionLogStore;

fn corrupt() -> DomainError {
    DomainError::internal(
        "authorization.decision_log_corrupt",
        "a stored record of decisions could not be read",
    )
}

fn effect_name(effect: Effect) -> &'static str {
    match effect {
        Effect::Allow => "allow",
        Effect::Deny => "deny",
        Effect::Indeterminate => "indeterminate",
    }
}

fn effect_of(name: &str) -> Result<Effect, DomainError> {
    match name {
        "allow" => Ok(Effect::Allow),
        "deny" => Ok(Effect::Deny),
        "indeterminate" => Ok(Effect::Indeterminate),
        _ => Err(corrupt()),
    }
}

fn kind_name(kind: SubjectKind) -> &'static str {
    match kind {
        SubjectKind::User => "user",
        SubjectKind::Client => "client",
        SubjectKind::Group => "group",
    }
}

fn invalid_cursor() -> DomainError {
    DomainError::invalid(
        "request.query_invalid",
        "the cursor is not one of this list",
    )
}

/// A cursor names the last record of a page by its time, in microseconds
/// since 1970, and its identifier.
fn cursor_of(record: &DecisionRecord) -> Cursor {
    let micros = record.decided_at.unix_timestamp_nanos() / 1_000;
    Cursor::new(format!("{micros}.{}", record.decision_id.as_uuid()))
}

fn read_cursor(cursor: &Cursor) -> Result<(Timestamp, Uuid), DomainError> {
    let (micros, id) = cursor.as_str().split_once('.').ok_or_else(invalid_cursor)?;
    let micros: i128 = micros.parse().map_err(|_| invalid_cursor())?;
    let at = Timestamp::from_unix_timestamp_nanos(micros * 1_000).map_err(|_| invalid_cursor())?;
    let id = Uuid::parse_str(id).map_err(|_| invalid_cursor())?;
    Ok((at, id))
}

#[async_trait::async_trait]
impl DecisionLogStore for PgDecisionLogStore {
    async fn settings(
        &self,
        uow: &mut dyn UnitOfWork,
    ) -> Result<Option<DecisionLogSettings>, DomainError> {
        let row: Option<(String, Option<i16>, Vec<String>, i16)> = sqlx::query_as(
            "SELECT mode, allow_percent, masks, retention_days
             FROM \"authorization\".decision_log_setting",
        )
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        let Some((mode, share, masks, retention)) = row else {
            return Ok(None);
        };
        let share = share
            .map(|share| u8::try_from(share).map_err(|_| corrupt()))
            .transpose()?;
        let mode = DecisionLogMode::parse(&mode, share).map_err(|_| corrupt())?;
        let masks = masks
            .iter()
            .map(|mask| MaskPath::parse(mask).map_err(|_| corrupt()))
            .collect::<Result<Vec<_>, _>>()?;
        let retention = u16::try_from(retention).map_err(|_| corrupt())?;
        DecisionLogSettings::new(mode, masks, retention)
            .map(Some)
            .map_err(|_| corrupt())
    }

    async fn put_settings(
        &self,
        uow: &mut dyn UnitOfWork,
        settings: &DecisionLogSettings,
        now: Timestamp,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let masks: Vec<&str> = settings.masks().iter().map(MaskPath::as_str).collect();
        sqlx::query(
            "INSERT INTO \"authorization\".decision_log_setting
                 (tenant_id, mode, allow_percent, masks, retention_days, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (tenant_id) DO UPDATE SET
                 mode = EXCLUDED.mode,
                 allow_percent = EXCLUDED.allow_percent,
                 masks = EXCLUDED.masks,
                 retention_days = EXCLUDED.retention_days,
                 updated_at = EXCLUDED.updated_at",
        )
        .bind(tenant.as_uuid())
        .bind(settings.mode().as_str())
        .bind(settings.mode().allow_percent().map(i16::from))
        .bind(&masks)
        .bind(i16::try_from(settings.retention_days()).map_err(|_| corrupt())?)
        .bind(now)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn append(
        &self,
        uow: &mut dyn UnitOfWork,
        records: &[DecisionRecord],
    ) -> Result<(), DomainError> {
        if records.is_empty() {
            return Ok(());
        }
        let tenant = uow.tenant().tenant_id();
        let mut query: QueryBuilder<Postgres> = QueryBuilder::new(
            "INSERT INTO \"authorization\".decision_log (tenant_id, decided_at, decision_id,
                 namespace, subject_kind, subject_id, action, resource_type, resource_id,
                 effect, reason, engine, policy_version, duration_us, input, masked) ",
        );
        query.push_values(records, |mut row, record| {
            row.push_bind(tenant.as_uuid())
                .push_bind(record.decided_at)
                .push_bind(record.decision_id.as_uuid())
                .push_bind(record.namespace.clone())
                .push_bind(kind_name(record.subject_kind))
                .push_bind(record.subject_id.clone())
                .push_bind(record.action.clone())
                .push_bind(record.resource_type.clone())
                .push_bind(record.resource_id.clone())
                .push_bind(effect_name(record.effect))
                .push_bind(record.reason.clone())
                .push_bind(record.engine.clone())
                .push_bind(record.policy_version.clone())
                .push_bind(i64::try_from(record.duration_microseconds).unwrap_or(i64::MAX))
                .push_bind(Json(record.input.clone()))
                .push_bind(record.masked.clone());
        });
        query.push(" ON CONFLICT DO NOTHING");
        query
            .build()
            .execute(connection(uow)?)
            .await
            .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn page(
        &self,
        uow: &mut dyn UnitOfWork,
        filter: &DecisionFilter,
        page: &PageRequest,
    ) -> Result<Page<DecisionRecord>, DomainError> {
        let after = page.cursor().map(read_cursor).transpose()?;
        let mut query: QueryBuilder<Postgres> = QueryBuilder::new(
            "SELECT decided_at, decision_id, namespace, subject_kind, subject_id, action,
                 resource_type, resource_id, effect, reason, engine, policy_version,
                 duration_us, input, masked
             FROM \"authorization\".decision_log WHERE true",
        );
        if let Some(from) = filter.from {
            query.push(" AND decided_at >= ").push_bind(from);
        }
        if let Some(to) = filter.to {
            query.push(" AND decided_at < ").push_bind(to);
        }
        if let Some(effect) = filter.effect {
            query.push(" AND effect = ").push_bind(effect_name(effect));
        }
        if let Some(namespace) = &filter.namespace {
            query.push(" AND namespace = ").push_bind(namespace.clone());
        }
        if let Some((kind, id)) = &filter.subject {
            query
                .push(" AND subject_kind = ")
                .push_bind(kind_name(*kind))
                .push(" AND subject_id = ")
                .push_bind(id.clone());
        }
        if let Some((at, id)) = after {
            query
                .push(" AND (decided_at, decision_id) < (")
                .push_bind(at)
                .push(", ")
                .push_bind(id)
                .push(")");
        }
        let limit = i64::from(page.limit());
        query
            .push(" ORDER BY decided_at DESC, decision_id DESC LIMIT ")
            .push_bind(limit + 1);
        let rows = query
            .build()
            .fetch_all(connection(uow)?)
            .await
            .map_err(|e| database_error(&e))?;
        let mut items = rows.iter().map(record_of).collect::<Result<Vec<_>, _>>()?;
        let more = items.len() > usize::try_from(page.limit()).unwrap_or(usize::MAX);
        if more {
            items.pop();
        }
        let next_cursor = if more {
            items.last().map(cursor_of)
        } else {
            None
        };
        Ok(Page { items, next_cursor })
    }
}

fn record_of(row: &sqlx::postgres::PgRow) -> Result<DecisionRecord, DomainError> {
    let read = |e: sqlx::Error| database_error(&e);
    let kind: String = row.try_get("subject_kind").map_err(read)?;
    let effect: String = row.try_get("effect").map_err(read)?;
    let duration: i64 = row.try_get("duration_us").map_err(read)?;
    let Json(input): Json<serde_json::Value> = row.try_get("input").map_err(read)?;
    Ok(DecisionRecord {
        decision_id: DecisionId::from_uuid(row.try_get("decision_id").map_err(read)?),
        namespace: row.try_get("namespace").map_err(read)?,
        subject_kind: SubjectKind::parse(&kind).map_err(|_| corrupt())?,
        subject_id: row.try_get("subject_id").map_err(read)?,
        action: row.try_get("action").map_err(read)?,
        resource_type: row.try_get("resource_type").map_err(read)?,
        resource_id: row.try_get("resource_id").map_err(read)?,
        effect: effect_of(&effect)?,
        reason: row.try_get("reason").map_err(read)?,
        engine: row.try_get("engine").map_err(read)?,
        policy_version: row.try_get("policy_version").map_err(read)?,
        decided_at: row.try_get("decided_at").map_err(read)?,
        duration_microseconds: u64::try_from(duration).map_err(|_| corrupt())?,
        input,
        masked: row.try_get("masked").map_err(read)?,
    })
}

/// What one pass of the maintenance job did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecisionLogMaintenanceReport {
    /// Partitions created.
    pub created: u32,
    /// Partitions dropped, past the longest retention.
    pub dropped: u32,
    /// Tenants that had records past their retention.
    pub tenants: u64,
    /// Records removed, recorded and uploaded alike.
    pub removed: u64,
}

/// Prepares the partitions of the record of decisions, drops the oldest
/// and removes each tenant's records past its retention.
#[derive(Debug, Clone)]
pub struct DecisionLogMaintenance {
    platform: PgPool,
    database: Database,
}

impl DecisionLogMaintenance {
    /// `platform` must connect as a member of `hodor_platform`: it calls
    /// the function that prepares and drops partitions, and finds the
    /// tenants with old records. They are removed through `database`, as
    /// the application role, in each tenant.
    #[must_use]
    pub const fn new(platform: PgPool, database: Database) -> Self {
        Self { platform, database }
    }

    /// One pass at `now`: up to `batch` records removed per tenant and
    /// table.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be reached.
    pub async fn run(
        &self,
        now: Timestamp,
        batch: u32,
    ) -> Result<DecisionLogMaintenanceReport, DomainError> {
        let (created, dropped): (i32, i32) = sqlx::query_as(
            "SELECT created, dropped
             FROM \"authorization\".maintain_decision_log_partitions($1::date, $2, $3)",
        )
        .bind(now)
        .bind(DAYS_PREPARED_AHEAD)
        .bind(i32::from(hodor_authorization::api::MAX_RETENTION_DAYS))
        .fetch_one(&self.platform)
        .await
        .map_err(|e| database_error(&e))?;
        let mut report = DecisionLogMaintenanceReport {
            created: u32::try_from(created).unwrap_or(0),
            dropped: u32::try_from(dropped).unwrap_or(0),
            ..DecisionLogMaintenanceReport::default()
        };

        let tenants: Vec<(Uuid,)> = sqlx::query_as(
            "WITH owners AS (
                 SELECT DISTINCT tenant_id FROM \"authorization\".decision_log
                 UNION
                 SELECT DISTINCT tenant_id FROM \"authorization\".policy_agent_decision
             )
             SELECT owners.tenant_id
             FROM owners
             LEFT JOIN \"authorization\".decision_log_setting setting USING (tenant_id)
             WHERE EXISTS (
                 SELECT FROM \"authorization\".decision_log record
                 WHERE record.tenant_id = owners.tenant_id
                   AND record.decided_at < $1 - make_interval(days =>
                       COALESCE(setting.retention_days, $2))
             ) OR EXISTS (
                 SELECT FROM \"authorization\".policy_agent_decision uploaded
                 WHERE uploaded.tenant_id = owners.tenant_id
                   AND COALESCE(uploaded.decided_at, uploaded.received_at) < $1 - make_interval(
                       days => COALESCE(setting.retention_days, $2))
             )
             LIMIT $3",
        )
        .bind(now)
        .bind(i32::from(hodor_authorization::api::DEFAULT_RETENTION_DAYS))
        .bind(TENANTS_PER_PASS)
        .fetch_all(&self.platform)
        .await
        .map_err(|e| database_error(&e))?;

        for (tenant_id,) in tenants {
            // The tenant comes from a stored row, not from any request: the
            // worker's job loader is one of the places allowed to establish
            // a tenant context.
            let tenant = TenantContext::assume(TenantId::from_uuid(tenant_id));
            let transaction = self
                .database
                .begin(&tenant)
                .await
                .map_err(|e| database_error(&e))?;
            let mut unit = PgUnitOfWork::new(transaction, tenant.clone());
            let retention = PgDecisionLogStore
                .settings(&mut unit)
                .await?
                .unwrap_or_default()
                .retention_days();
            let before = now - time::Duration::days(i64::from(retention));
            let limit = i64::from(batch);
            let recorded = sqlx::query(
                "DELETE FROM \"authorization\".decision_log
                 WHERE (decided_at, decision_id) IN (
                     SELECT decided_at, decision_id FROM \"authorization\".decision_log
                     WHERE decided_at < $1 ORDER BY decided_at LIMIT $2)",
            )
            .bind(before)
            .bind(limit)
            .execute(connection(&mut unit)?)
            .await
            .map_err(|e| database_error(&e))?
            .rows_affected();
            let uploaded = sqlx::query(
                "DELETE FROM \"authorization\".policy_agent_decision
                 WHERE (instance_id, decision_id) IN (
                     SELECT instance_id, decision_id FROM \"authorization\".policy_agent_decision
                     WHERE COALESCE(decided_at, received_at) < $1 LIMIT $2)",
            )
            .bind(before)
            .bind(limit)
            .execute(connection(&mut unit)?)
            .await
            .map_err(|e| database_error(&e))?
            .rows_affected();
            Box::new(unit).commit().await?;
            report.tenants += 1;
            report.removed += recorded + uploaded;
        }
        Ok(report)
    }
}
