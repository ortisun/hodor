//! PostgreSQL storage for the bundles of Open Policy Agent.
//!
//! See `docs/architecture/contexts/authorization.md`, "Storage of
//! bundles".

use crate::database::Database;
use crate::uow::{connection, database_error};
use hodor_authorization_opa::api::{
    Author, BundleStore, Instance, InstanceId, InstanceName, InstanceStatus, InstanceStatusStore,
    InstanceStore, PublishedBundle, UploadedDecision, UploadedDecisionStore,
};
use hodor_kernel::{DomainError, TenantId, Timestamp, UnitOfWork};
use sqlx::types::Uuid;

fn corrupted(error: &DomainError) -> DomainError {
    DomainError::internal(
        "authorization.policy_bundle_corrupted",
        "the operation could not be completed",
    )
    .with_detail(error.to_string())
}

/// [`InstanceStore`] on `platform.policy_agent_instance`, through the
/// application role's connection.
#[derive(Debug, Clone)]
pub struct PgInstanceStore {
    database: Database,
}

impl PgInstanceStore {
    /// A store over `database`.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }
}

type InstanceRow = (Uuid, String, Option<Uuid>, Timestamp, Option<Timestamp>);

const INSTANCE_COLUMNS: &str = "id, name, tenant_id, registered_at, disabled_at";

fn to_instance(row: InstanceRow) -> Result<Instance, DomainError> {
    let (id, name, tenant, registered_at, disabled_at) = row;
    let name = InstanceName::parse(&name).map_err(|e| corrupted(&e))?;
    Ok(Instance::from_stored(
        InstanceId::from_uuid(id),
        name,
        tenant.map(TenantId::from_uuid),
        registered_at,
        disabled_at,
    ))
}

#[async_trait::async_trait]
impl InstanceStore for PgInstanceStore {
    async fn add(&self, instance: &Instance, credential: [u8; 32]) -> Result<(), DomainError> {
        let result = sqlx::query(
            "INSERT INTO platform.policy_agent_instance
                 (id, name, tenant_id, credential_digest, registered_at, disabled_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(instance.id().as_uuid())
        .bind(instance.name().as_str())
        .bind(instance.tenant().map(|tenant| tenant.as_uuid()))
        .bind(credential.as_slice())
        .bind(instance.registered_at())
        .bind(instance.disabled_at())
        .execute(self.database.pool())
        .await;
        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(database)) if database.is_unique_violation() => {
                Err(DomainError::conflict(
                    "authorization.policy_agent_instance_exists",
                    "an instance of this name exists",
                ))
            }
            Err(error) => Err(database_error(&error)),
        }
    }

    async fn find_by_credential(
        &self,
        credential: [u8; 32],
    ) -> Result<Option<Instance>, DomainError> {
        let row: Option<InstanceRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {INSTANCE_COLUMNS} FROM platform.policy_agent_instance
             WHERE credential_digest = $1"
        )))
        .bind(credential.as_slice())
        .fetch_optional(self.database.pool())
        .await
        .map_err(|e| database_error(&e))?;
        row.map(to_instance).transpose()
    }

    async fn find_by_name(&self, name: &InstanceName) -> Result<Option<Instance>, DomainError> {
        let row: Option<InstanceRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {INSTANCE_COLUMNS} FROM platform.policy_agent_instance WHERE name = $1"
        )))
        .bind(name.as_str())
        .fetch_optional(self.database.pool())
        .await
        .map_err(|e| database_error(&e))?;
        row.map(to_instance).transpose()
    }

    async fn list(&self) -> Result<Vec<Instance>, DomainError> {
        let rows: Vec<InstanceRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {INSTANCE_COLUMNS} FROM platform.policy_agent_instance ORDER BY name"
        )))
        .fetch_all(self.database.pool())
        .await
        .map_err(|e| database_error(&e))?;
        rows.into_iter().map(to_instance).collect()
    }

    async fn disable(&self, name: &InstanceName, at: Timestamp) -> Result<bool, DomainError> {
        let done = sqlx::query(
            "UPDATE platform.policy_agent_instance SET disabled_at = $2
             WHERE name = $1 AND disabled_at IS NULL",
        )
        .bind(name.as_str())
        .bind(at)
        .execute(self.database.pool())
        .await
        .map_err(|e| database_error(&e))?;
        Ok(done.rows_affected() > 0)
    }
}

/// [`BundleStore`] on `authorization.policy_bundle`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgBundleStore;

type BundleRow = (i64, String, Vec<u8>, Vec<u8>, Timestamp);

fn to_bundle(row: BundleRow) -> Result<PublishedBundle, DomainError> {
    let (revision, author, archive, digest, published_at) = row;
    let invalid = || {
        corrupted(&DomainError::invalid(
            "authorization.policy_bundle_row",
            "a stored bundle is not valid",
        ))
    };
    Ok(PublishedBundle {
        revision: u64::try_from(revision).map_err(|_| invalid())?,
        author: Author::parse(&author).map_err(|e| corrupted(&e))?,
        archive,
        digest: digest.try_into().map_err(|_| invalid())?,
        published_at,
    })
}

#[async_trait::async_trait]
impl BundleStore for PgBundleStore {
    async fn append(
        &self,
        uow: &mut dyn UnitOfWork,
        bundle: &PublishedBundle,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let revision = i64::try_from(bundle.revision).map_err(|_| {
            DomainError::invalid(
                "authorization.bundle_revision_invalid",
                "the revision is too large",
            )
        })?;
        let result = sqlx::query(
            "INSERT INTO \"authorization\".policy_bundle
                 (tenant_id, revision, written_by, archive, digest, published_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(tenant.as_uuid())
        .bind(revision)
        .bind(bundle.author.as_str())
        .bind(bundle.archive.as_slice())
        .bind(bundle.digest.as_slice())
        .bind(bundle.published_at)
        .execute(connection(uow)?)
        .await;
        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(database)) if database.is_unique_violation() => {
                Err(DomainError::conflict(
                    "authorization.bundle_revision_taken",
                    "another publication took this revision",
                ))
            }
            Err(error) => Err(database_error(&error)),
        }
    }

    async fn latest(
        &self,
        uow: &mut dyn UnitOfWork,
    ) -> Result<Option<PublishedBundle>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<BundleRow> = sqlx::query_as(
            "SELECT revision, written_by, archive, digest, published_at
             FROM \"authorization\".policy_bundle
             WHERE tenant_id = $1 ORDER BY revision DESC LIMIT 1",
        )
        .bind(tenant.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.map(to_bundle).transpose()
    }

    async fn latest_revision(
        &self,
        uow: &mut dyn UnitOfWork,
    ) -> Result<Option<(u64, Timestamp)>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<(i64, Timestamp)> = sqlx::query_as(
            "SELECT revision, published_at FROM \"authorization\".policy_bundle
             WHERE tenant_id = $1 ORDER BY revision DESC LIMIT 1",
        )
        .bind(tenant.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.map(|(revision, at)| {
            u64::try_from(revision)
                .map(|revision| (revision, at))
                .map_err(|_| {
                    corrupted(&DomainError::invalid(
                        "authorization.policy_bundle_row",
                        "a stored bundle is not valid",
                    ))
                })
        })
        .transpose()
    }
}

/// [`InstanceStatusStore`] on `authorization.policy_agent_status`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgInstanceStatusStore;

type StatusRow = (
    Uuid,
    Option<String>,
    Option<Timestamp>,
    Option<String>,
    Timestamp,
);

#[async_trait::async_trait]
impl InstanceStatusStore for PgInstanceStatusStore {
    async fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        status: &InstanceStatus,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "INSERT INTO \"authorization\".policy_agent_status
                 (tenant_id, instance_id, active_revision, last_activation, last_error, reported_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (tenant_id, instance_id) DO UPDATE SET
                 active_revision = EXCLUDED.active_revision,
                 last_activation = EXCLUDED.last_activation,
                 last_error = EXCLUDED.last_error,
                 reported_at = EXCLUDED.reported_at",
        )
        .bind(tenant.as_uuid())
        .bind(status.instance.as_uuid())
        .bind(status.active_revision.as_deref())
        .bind(status.last_activation)
        .bind(status.error.as_deref())
        .bind(status.reported_at)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn list(&self, uow: &mut dyn UnitOfWork) -> Result<Vec<InstanceStatus>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let rows: Vec<StatusRow> = sqlx::query_as(
            "SELECT instance_id, active_revision, last_activation, last_error, reported_at
             FROM \"authorization\".policy_agent_status
             WHERE tenant_id = $1 ORDER BY reported_at, instance_id",
        )
        .bind(tenant.as_uuid())
        .fetch_all(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(rows
            .into_iter()
            .map(
                |(instance, active_revision, last_activation, error, reported_at)| InstanceStatus {
                    instance: InstanceId::from_uuid(instance),
                    active_revision,
                    last_activation,
                    error,
                    reported_at,
                },
            )
            .collect())
    }
}

/// [`UploadedDecisionStore`] on `authorization.policy_agent_decision`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgUploadedDecisionStore;

type DecisionRow = (
    Uuid,
    String,
    String,
    Option<String>,
    Option<bool>,
    Option<Timestamp>,
    Timestamp,
);

#[async_trait::async_trait]
impl UploadedDecisionStore for PgUploadedDecisionStore {
    async fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        decisions: &[UploadedDecision],
    ) -> Result<u64, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut new = 0;
        for decision in decisions {
            let done = sqlx::query(
                "INSERT INTO \"authorization\".policy_agent_decision
                     (tenant_id, instance_id, decision_id, path, revision, allowed, decided_at,
                      received_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT (tenant_id, instance_id, decision_id) DO NOTHING",
            )
            .bind(tenant.as_uuid())
            .bind(decision.instance.as_uuid())
            .bind(&decision.decision_id)
            .bind(&decision.path)
            .bind(decision.revision.as_deref())
            .bind(decision.allowed)
            .bind(decision.decided_at)
            .bind(decision.received_at)
            .execute(connection(uow)?)
            .await
            .map_err(|e| database_error(&e))?;
            new += done.rows_affected();
        }
        Ok(new)
    }

    async fn latest(
        &self,
        uow: &mut dyn UnitOfWork,
        limit: u32,
    ) -> Result<Vec<UploadedDecision>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let rows: Vec<DecisionRow> = sqlx::query_as(
            "SELECT instance_id, decision_id, path, revision, allowed, decided_at, received_at
             FROM \"authorization\".policy_agent_decision
             WHERE tenant_id = $1 ORDER BY received_at DESC, decision_id DESC LIMIT $2",
        )
        .bind(tenant.as_uuid())
        .bind(i64::from(limit))
        .fetch_all(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(rows
            .into_iter()
            .map(
                |(instance, decision_id, path, revision, allowed, decided_at, received_at)| {
                    UploadedDecision {
                        instance: InstanceId::from_uuid(instance),
                        decision_id,
                        path,
                        revision,
                        allowed,
                        decided_at,
                        received_at,
                    }
                },
            )
            .collect())
    }
}
