//! The rotation job: one step of rotation in every tenant that has
//! something due, by one worker at a time.
//!
//! Like the outbox and the cleanup jobs, the job finds its work across
//! tenants through a connection as a member of `hodor_platform`, and the
//! work is done inside each tenant by the keys context, as the
//! application role. See `docs/architecture/contexts/keys.md`, "Two
//! workers, one rotation".

use hodor_kernel::{Caller, DomainError, TenantContext, TenantId, Timestamp};
use hodor_keys::api::{KeyAlgorithm, KeyService, RotationPolicy, RotationReport};
use sqlx::PgPool;
use sqlx::types::Uuid;

/// The most tenants one pass looks at.
const TENANTS_PER_PASS: i64 = 100;

/// The advisory lock a pass holds: one number for the whole installation,
/// "hodorkey" in ASCII.
const ROTATION_LOCK: i64 = 0x686f_646f_726b_6579;

/// What one pass of the rotation job did.
#[derive(Debug, Clone, Default)]
pub struct RotationPass {
    /// Whether another worker held the lock, so that this pass did nothing.
    pub skipped: bool,
    /// Tenants that had something due.
    pub tenants: u64,
    /// The tenants whose step failed, and why; they are tried again on the
    /// next pass.
    pub failures: Vec<(TenantId, DomainError)>,
    /// What the steps changed, added up.
    pub changes: RotationReport,
}

impl RotationPass {
    /// Whether the pass looked at as many tenants as it may, so that more
    /// may be waiting.
    #[must_use]
    pub fn was_full(&self) -> bool {
        self.tenants >= TENANTS_PER_PASS.unsigned_abs()
    }
}

/// Runs a step of rotation in each tenant that has something due.
#[derive(Debug, Clone)]
pub struct KeyRotationJob {
    platform: PgPool,
    keys: KeyService,
    policy: RotationPolicy,
}

impl KeyRotationJob {
    /// `platform` must connect as a member of `hodor_platform`; it is used
    /// only for the lock and to find the tenants that have something due.
    /// The steps are run by `keys`, inside each tenant.
    #[must_use]
    pub const fn new(platform: PgPool, keys: KeyService, policy: RotationPolicy) -> Self {
        Self {
            platform,
            keys,
            policy,
        }
    }

    /// Runs one pass at `now`, unless another worker is running one.
    ///
    /// A step that fails in one tenant is recorded in the pass, and the pass
    /// goes on with the others.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be reached.
    pub async fn run(&self, now: Timestamp) -> Result<RotationPass, DomainError> {
        // The lock lives as long as this transaction, and so ends with it
        // whatever happens to the pass.
        let mut lock = self
            .platform
            .begin()
            .await
            .map_err(|error| crate::uow::database_error(&error))?;
        let (held,): (bool,) = sqlx::query_as("SELECT pg_try_advisory_xact_lock($1)")
            .bind(ROTATION_LOCK)
            .fetch_one(&mut *lock)
            .await
            .map_err(|error| crate::uow::database_error(&error))?;
        if !held {
            return Ok(RotationPass {
                skipped: true,
                ..RotationPass::default()
            });
        }

        let tenants = self.due(&mut lock, now).await?;
        let mut pass = RotationPass::default();
        for tenant_id in tenants {
            pass.tenants += 1;
            // The tenant comes from a stored row, not from any request: the
            // worker's job loader is one of the places allowed to establish
            // a tenant context.
            let tenant = TenantContext::assume(TenantId::from_uuid(tenant_id));
            match self
                .keys
                .rotate_due(&tenant, &self.policy, Caller::system())
                .await
            {
                Ok(report) => pass.changes.add(report),
                Err(error) => pass.failures.push((tenant.tenant_id(), error)),
            }
        }
        lock.commit()
            .await
            .map_err(|error| crate::uow::database_error(&error))?;
        Ok(pass)
    }

    /// The active tenants that have something due at `now`: what
    /// `KeySet::rotation_plan` would find, asked of every tenant at once.
    async fn due(
        &self,
        lock: &mut sqlx::PgConnection,
        now: Timestamp,
    ) -> Result<Vec<Uuid>, DomainError> {
        let policy = &self.policy;
        let rows: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT d.tenant_id FROM platform.tenant_directory d
             WHERE d.status = 'active' AND (
                 -- The default algorithm signs nothing.
                 NOT EXISTS (
                     SELECT 1 FROM keys.key_version v
                     WHERE v.tenant_id = d.tenant_id AND v.key_use = 'sig'
                       AND v.algorithm = $1 AND v.state = 'active')
                 -- A replaced version may retire.
                 OR EXISTS (
                     SELECT 1 FROM keys.key_version v
                     WHERE v.tenant_id = d.tenant_id AND v.key_use = 'sig'
                       AND v.state = 'retiring' AND v.retire_after <= $2)
                 -- An active version needs its successor made, or activated.
                 OR EXISTS (
                     SELECT 1 FROM keys.key_version a
                     WHERE a.tenant_id = d.tenant_id AND a.key_use = 'sig'
                       AND a.state = 'active' AND a.activated_at <= $3
                       AND (
                           NOT EXISTS (
                               SELECT 1 FROM keys.key_version p
                               WHERE p.tenant_id = a.tenant_id AND p.key_use = 'sig'
                                 AND p.algorithm = a.algorithm AND p.state = 'pending')
                           OR (a.activated_at <= $4 AND EXISTS (
                               SELECT 1 FROM keys.key_version p
                               WHERE p.tenant_id = a.tenant_id AND p.key_use = 'sig'
                                 AND p.algorithm = a.algorithm AND p.state = 'pending'
                                 AND p.created_at <= $5))))
             )
             ORDER BY d.tenant_id
             LIMIT $6",
        )
        .bind(KeyAlgorithm::DEFAULT_SIGNING.as_str())
        .bind(now)
        .bind(now - (policy.period() - policy.publication()))
        .bind(now - policy.period())
        .bind(now - policy.publication())
        .bind(TENANTS_PER_PASS)
        .fetch_all(lock)
        .await
        .map_err(|error| crate::uow::database_error(&error))?;
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }
}
