//! PostgreSQL storage for the policy lifecycle, and the worker's job that
//! checks, tests and simulates what waits.
//!
//! See `docs/architecture/contexts/authorization.md`, "The policy
//! lifecycle".

use crate::uow::{connection, database_error};
use hodor_authorization_opa::api::{
    Author, BundleFile, PolicyChecker, PolicyService, PolicyVersion, PolicyVersionStore,
    PublicationStore, Report, SimulatedAnswer, Simulation, SimulationId, SimulationState,
    SimulationStore, VersionState,
};
use hodor_kernel::{DomainError, TenantContext, TenantId, Timestamp, UnitOfWork};
use serde_json::{Value, json};
use sqlx::PgPool;
use sqlx::types::{Json, Uuid};
use std::sync::Arc;

fn corrupted(detail: impl Into<String>) -> DomainError {
    DomainError::internal(
        "authorization.policy_version_corrupted",
        "the operation could not be completed",
    )
    .with_detail(detail.into())
}

fn signed(value: u64) -> Result<i64, DomainError> {
    i64::try_from(value).map_err(|_| {
        DomainError::invalid(
            "authorization.policy_version_number_invalid",
            "the number is too large",
        )
    })
}

fn unsigned(value: i64) -> Result<u64, DomainError> {
    u64::try_from(value).map_err(|_| corrupted("a stored number is negative"))
}

/// The files as stored: `[{"path": …, "contents": …}]`, all text.
fn files_to_json(files: &[BundleFile]) -> Result<Value, DomainError> {
    files
        .iter()
        .map(|file| {
            let contents = std::str::from_utf8(&file.contents).map_err(|_| {
                DomainError::invalid(
                    "authorization.bundle_file_invalid",
                    "a file of the bundle is refused",
                )
            })?;
            Ok(json!({"path": file.path, "contents": contents}))
        })
        .collect::<Result<Vec<Value>, DomainError>>()
        .map(Value::Array)
}

fn files_from_json(value: &Value) -> Result<Vec<BundleFile>, DomainError> {
    value
        .as_array()
        .ok_or_else(|| corrupted("files are not a list"))?
        .iter()
        .map(|file| {
            let path = file.get("path").and_then(Value::as_str);
            let contents = file.get("contents").and_then(Value::as_str);
            match (path, contents) {
                (Some(path), Some(contents)) => Ok(BundleFile {
                    path: path.to_owned(),
                    contents: contents.as_bytes().to_vec(),
                }),
                _ => Err(corrupted("a file is not a path and contents")),
            }
        })
        .collect()
}

type VersionRow = (
    i64,
    String,
    Option<Json<Value>>,
    Vec<u8>,
    String,
    Option<Json<Report>>,
    Timestamp,
    Timestamp,
);

fn to_version(row: VersionRow) -> Result<PolicyVersion, DomainError> {
    let (number, author, files, digest, state, report, drafted_at, changed_at) = row;
    Ok(PolicyVersion {
        number: unsigned(number)?,
        author: Author::parse(&author).map_err(|e| corrupted(e.to_string()))?,
        files: match files {
            Some(Json(files)) => files_from_json(&files)?,
            None => Vec::new(),
        },
        digest: digest
            .try_into()
            .map_err(|_| corrupted("a digest is not 32 bytes"))?,
        state: VersionState::parse(&state).map_err(|e| corrupted(e.to_string()))?,
        report: report.map(|Json(report)| report),
        drafted_at,
        changed_at,
    })
}

/// [`PolicyVersionStore`] on `authorization.policy_version`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgPolicyVersionStore;

#[async_trait::async_trait]
impl PolicyVersionStore for PgPolicyVersionStore {
    async fn create(
        &self,
        uow: &mut dyn UnitOfWork,
        version: &PolicyVersion,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let result = sqlx::query(
            "INSERT INTO \"authorization\".policy_version
                 (tenant_id, number, written_by, files, digest, state, report,
                  drafted_at, changed_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(tenant.as_uuid())
        .bind(signed(version.number)?)
        .bind(version.author.as_str())
        .bind(Json(files_to_json(&version.files)?))
        .bind(version.digest.as_slice())
        .bind(version.state.as_str())
        .bind(version.report.as_ref().map(Json))
        .bind(version.drafted_at)
        .bind(version.changed_at)
        .execute(connection(uow)?)
        .await;
        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(database)) if database.is_unique_violation() => {
                Err(DomainError::conflict(
                    "authorization.policy_version_taken",
                    "another draft took this number",
                ))
            }
            Err(error) => Err(database_error(&error)),
        }
    }

    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        number: u64,
    ) -> Result<Option<PolicyVersion>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<VersionRow> = sqlx::query_as(
            "SELECT number, written_by, files, digest, state, report, drafted_at, changed_at FROM \"authorization\".policy_version
             WHERE tenant_id = $1 AND number = $2",
        )
        .bind(tenant.as_uuid())
        .bind(signed(number)?)
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.map(to_version).transpose()
    }

    async fn latest_number(&self, uow: &mut dyn UnitOfWork) -> Result<Option<u64>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let (latest,): (Option<i64>,) = sqlx::query_as(
            "SELECT max(number) FROM \"authorization\".policy_version WHERE tenant_id = $1",
        )
        .bind(tenant.as_uuid())
        .fetch_one(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        latest.map(unsigned).transpose()
    }

    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        limit: u32,
    ) -> Result<Vec<PolicyVersion>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let rows: Vec<VersionRow> = sqlx::query_as(
            "SELECT number, written_by, NULL::jsonb, digest, state, report, drafted_at, changed_at FROM \"authorization\".policy_version
             WHERE tenant_id = $1 ORDER BY number DESC LIMIT $2",
        )
        .bind(tenant.as_uuid())
        .bind(i64::from(limit))
        .fetch_all(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        rows.into_iter().map(to_version).collect()
    }

    async fn waiting(
        &self,
        uow: &mut dyn UnitOfWork,
        limit: u32,
    ) -> Result<Vec<PolicyVersion>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let rows: Vec<VersionRow> = sqlx::query_as(
            "SELECT number, written_by, files, digest, state, report, drafted_at, changed_at FROM \"authorization\".policy_version
             WHERE tenant_id = $1 AND state IN ('validating', 'testing')
             ORDER BY changed_at, number LIMIT $2",
        )
        .bind(tenant.as_uuid())
        .bind(i64::from(limit))
        .fetch_all(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        rows.into_iter().map(to_version).collect()
    }

    async fn transition(
        &self,
        uow: &mut dyn UnitOfWork,
        number: u64,
        from: VersionState,
        to: VersionState,
        report: Option<&Report>,
        at: Timestamp,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let changed = sqlx::query(
            "UPDATE \"authorization\".policy_version
             SET state = $4, report = $5, changed_at = $6
             WHERE tenant_id = $1 AND number = $2 AND state = $3",
        )
        .bind(tenant.as_uuid())
        .bind(signed(number)?)
        .bind(from.as_str())
        .bind(to.as_str())
        .bind(report.map(Json))
        .bind(at)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(changed.rows_affected() == 1)
    }
}

/// [`PublicationStore`] on `authorization.policy_publication`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgPublicationStore;

#[async_trait::async_trait]
impl PublicationStore for PgPublicationStore {
    async fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        revision: u64,
        version: u64,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let result = sqlx::query(
            "INSERT INTO \"authorization\".policy_publication (tenant_id, revision, version)
             VALUES ($1, $2, $3)",
        )
        .bind(tenant.as_uuid())
        .bind(signed(revision)?)
        .bind(signed(version)?)
        .execute(connection(uow)?)
        .await;
        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(database)) if database.is_unique_violation() => {
                Err(DomainError::conflict(
                    "authorization.policy_publication_taken",
                    "this revision is recorded already",
                ))
            }
            Err(error) => Err(database_error(&error)),
        }
    }

    async fn version_of(
        &self,
        uow: &mut dyn UnitOfWork,
        revision: u64,
    ) -> Result<Option<u64>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT version FROM \"authorization\".policy_publication
             WHERE tenant_id = $1 AND revision = $2",
        )
        .bind(tenant.as_uuid())
        .bind(signed(revision)?)
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.map(|(version,)| unsigned(version)).transpose()
    }

    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        limit: u32,
    ) -> Result<Vec<(u64, u64)>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let rows: Vec<(i64, i64)> = sqlx::query_as(
            "SELECT revision, version FROM \"authorization\".policy_publication
             WHERE tenant_id = $1 ORDER BY revision DESC LIMIT $2",
        )
        .bind(tenant.as_uuid())
        .bind(i64::from(limit))
        .fetch_all(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        rows.into_iter()
            .map(|(revision, version)| Ok((unsigned(revision)?, unsigned(version)?)))
            .collect()
    }
}

type SimulationRow = (
    Uuid,
    i64,
    String,
    Option<Json<Vec<Value>>>,
    Option<i64>,
    Option<Json<Vec<SimulatedAnswer>>>,
    Option<Json<Report>>,
    String,
    Timestamp,
    Option<Timestamp>,
);

fn to_simulation(row: SimulationRow) -> Result<Simulation, DomainError> {
    let (id, version, namespace, inputs, compared_with, results, report, state, asked_at, done_at) =
        row;
    Ok(Simulation {
        id: SimulationId::from_uuid(id),
        version: unsigned(version)?,
        namespace,
        inputs: inputs.map(|Json(inputs)| inputs).unwrap_or_default(),
        compared_with: compared_with.map(unsigned).transpose()?,
        results: results.map(|Json(results)| results).unwrap_or_default(),
        report: report.map(|Json(report)| report),
        state: SimulationState::parse(&state).map_err(|e| corrupted(e.to_string()))?,
        asked_at,
        done_at,
    })
}

/// [`SimulationStore`] on `authorization.policy_simulation`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgSimulationStore;

#[async_trait::async_trait]
impl SimulationStore for PgSimulationStore {
    async fn create(
        &self,
        uow: &mut dyn UnitOfWork,
        simulation: &Simulation,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "INSERT INTO \"authorization\".policy_simulation
                 (tenant_id, id, version, namespace, inputs, state, asked_at)
             VALUES ($1, $2, $3, $4, $5, 'waiting', $6)",
        )
        .bind(tenant.as_uuid())
        .bind(simulation.id.as_uuid())
        .bind(signed(simulation.version)?)
        .bind(&simulation.namespace)
        .bind(Json(&simulation.inputs))
        .bind(simulation.asked_at)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        id: SimulationId,
    ) -> Result<Option<Simulation>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<SimulationRow> = sqlx::query_as(
            "SELECT id, version, namespace, inputs, compared_with, results, report, state, asked_at, done_at FROM \"authorization\".policy_simulation
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.map(to_simulation).transpose()
    }

    async fn waiting(
        &self,
        uow: &mut dyn UnitOfWork,
        limit: u32,
    ) -> Result<Vec<Simulation>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let rows: Vec<SimulationRow> = sqlx::query_as(
            "SELECT id, version, namespace, inputs, compared_with, results, report, state, asked_at, done_at FROM \"authorization\".policy_simulation
             WHERE tenant_id = $1 AND state = 'waiting' ORDER BY asked_at LIMIT $2",
        )
        .bind(tenant.as_uuid())
        .bind(i64::from(limit))
        .fetch_all(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        rows.into_iter().map(to_simulation).collect()
    }

    async fn finish(
        &self,
        uow: &mut dyn UnitOfWork,
        id: SimulationId,
        state: SimulationState,
        compared_with: Option<u64>,
        results: &[SimulatedAnswer],
        report: Option<&Report>,
        at: Timestamp,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let changed = sqlx::query(
            "UPDATE \"authorization\".policy_simulation
             SET state = $3, compared_with = $4, results = $5, report = $6, done_at = $7,
                 inputs = NULL
             WHERE tenant_id = $1 AND id = $2 AND state = 'waiting'",
        )
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .bind(state.as_str())
        .bind(compared_with.map(signed).transpose()?)
        .bind(Json(results))
        .bind(report.map(Json))
        .bind(at)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(changed.rows_affected() == 1)
    }
}

/// The most tenants one pass of the job looks at.
const TENANTS_PER_PASS: i64 = 100;

/// The advisory lock a pass holds: one number for the whole installation,
/// "hodorpol" in ASCII.
const CHECK_LOCK: i64 = 0x686f_646f_7270_6f6c;

/// What one pass of the policy check job did.
#[derive(Debug, Default)]
pub struct PolicyCheckPass {
    /// Whether another worker held the lock, so that this pass did nothing.
    pub skipped: bool,
    /// Tenants that had something waiting.
    pub tenants: u64,
    /// Versions validated or tested.
    pub versions: u64,
    /// Simulations done or failed.
    pub simulations: u64,
    /// The tenants whose work could not run, and why; it waits for the
    /// next pass.
    pub failures: Vec<(TenantId, DomainError)>,
    /// Whether some tenant may have more waiting than one pass does.
    pub full: bool,
}

/// Checks, tests and simulates what waits in each tenant, with the `opa`
/// binary, one worker at a time.
#[derive(Clone)]
pub struct PolicyCheckJob {
    platform: PgPool,
    policies: PolicyService,
    checker: Arc<dyn PolicyChecker>,
}

impl std::fmt::Debug for PolicyCheckJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyCheckJob").finish_non_exhaustive()
    }
}

impl PolicyCheckJob {
    /// `platform` must connect as a member of `hodor_platform`; it is used
    /// only for the lock and to find the tenants that have something
    /// waiting. The work is done by `policies`, inside each tenant.
    #[must_use]
    pub fn new(platform: PgPool, policies: PolicyService, checker: Arc<dyn PolicyChecker>) -> Self {
        Self {
            platform,
            policies,
            checker,
        }
    }

    /// Runs one pass, unless another worker is running one.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be reached.
    pub async fn run(&self) -> Result<PolicyCheckPass, DomainError> {
        let mut lock = self
            .platform
            .begin()
            .await
            .map_err(|error| database_error(&error))?;
        let (held,): (bool,) = sqlx::query_as("SELECT pg_try_advisory_xact_lock($1)")
            .bind(CHECK_LOCK)
            .fetch_one(&mut *lock)
            .await
            .map_err(|error| database_error(&error))?;
        if !held {
            return Ok(PolicyCheckPass {
                skipped: true,
                ..PolicyCheckPass::default()
            });
        }
        let tenants: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT tenant_id FROM (
                 SELECT tenant_id FROM \"authorization\".policy_version
                 WHERE state IN ('validating', 'testing')
                 UNION
                 SELECT tenant_id FROM \"authorization\".policy_simulation
                 WHERE state = 'waiting'
             ) waiting ORDER BY tenant_id LIMIT $1",
        )
        .bind(TENANTS_PER_PASS)
        .fetch_all(&mut *lock)
        .await
        .map_err(|error| database_error(&error))?;
        let mut pass = PolicyCheckPass {
            full: i64::try_from(tenants.len()).unwrap_or(i64::MAX) >= TENANTS_PER_PASS,
            ..PolicyCheckPass::default()
        };
        for (tenant_id,) in tenants {
            pass.tenants += 1;
            // The tenant comes from a stored row, not from any request: the
            // worker's job loader is one of the places allowed to establish
            // a tenant context.
            let tenant = TenantContext::assume(TenantId::from_uuid(tenant_id));
            match self
                .policies
                .run_waiting(&tenant, self.checker.as_ref())
                .await
            {
                Ok(work) => {
                    pass.versions += work.versions;
                    pass.simulations += work.simulations;
                    pass.full |= work.was_full();
                }
                Err(error) => pass.failures.push((tenant.tenant_id(), error)),
            }
        }
        lock.commit()
            .await
            .map_err(|error| database_error(&error))?;
        Ok(pass)
    }
}
