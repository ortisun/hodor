//! Cleanup jobs: removing rows that nothing can use any more.
//!
//! Like the outbox, a job finds its work across tenants through a
//! connection as a member of `hodor_platform`, and does the work inside
//! each tenant as the application role. See
//! `docs/architecture/multi-tenancy.md`, "Cross-tenant operations".

use crate::database::Database;
use crate::federation::PgPendingAuthorizationStore;
use crate::oauth_access_token::PgAccessTokenRecordStore;
use crate::uow::PgUnitOfWork;
use hodor_federation::api::PendingAuthorizationStore as _;
use hodor_kernel::{DomainError, TenantContext, TenantId, Timestamp, UnitOfWork as _};
use hodor_oauth::api::AccessTokenRecordStore as _;
use sqlx::PgPool;
use sqlx::types::Uuid;

/// The most tenants one pass looks at.
const TENANTS_PER_PASS: i64 = 100;

/// What one pass of a cleanup job removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CleanupReport {
    /// Tenants that had something to remove.
    pub tenants: u64,
    /// Rows removed.
    pub removed: u64,
}

/// Removes pending authorizations that expired: sign-ins that left for a
/// provider and never came back.
#[derive(Debug, Clone)]
pub struct PendingAuthorizationCleanup {
    platform: PgPool,
    database: Database,
}

impl PendingAuthorizationCleanup {
    /// `platform` must connect as a member of `hodor_platform`; it is used
    /// only to find the tenants that have expired pending authorizations.
    /// They are removed through `database`, as the application role, in
    /// each tenant.
    #[must_use]
    pub const fn new(platform: PgPool, database: Database) -> Self {
        Self { platform, database }
    }

    /// Removes, in each tenant that has some, up to `batch` pending
    /// authorizations that had expired at `now`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be reached.
    pub async fn run(&self, now: Timestamp, batch: u32) -> Result<CleanupReport, DomainError> {
        let tenants: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT DISTINCT tenant_id FROM federation.pending_authorization
             WHERE expires_at <= $1
             LIMIT $2",
        )
        .bind(now)
        .bind(TENANTS_PER_PASS)
        .fetch_all(&self.platform)
        .await
        .map_err(|error| crate::uow::database_error(&error))?;

        let mut report = CleanupReport::default();
        for (tenant_id,) in tenants {
            // The tenant comes from a stored row, not from any request:
            // the worker's job loader is one of the places allowed to
            // establish a tenant context.
            let tenant = TenantContext::assume(TenantId::from_uuid(tenant_id));
            let transaction = self
                .database
                .begin(&tenant)
                .await
                .map_err(|error| crate::uow::database_error(&error))?;
            let mut unit = PgUnitOfWork::new(transaction, tenant.clone());
            let removed = PgPendingAuthorizationStore
                .remove_expired(&mut unit, now, batch)
                .await?;
            Box::new(unit).commit().await?;
            report.tenants += 1;
            report.removed += removed;
        }
        Ok(report)
    }
}

/// Removes the records of access tokens that expired from the register: a
/// token past its `exp` is refused whatever its record says, so the record
/// has nothing left to tell.
#[derive(Debug, Clone)]
pub struct AccessTokenCleanup {
    platform: PgPool,
    database: Database,
}

impl AccessTokenCleanup {
    /// `platform` must connect as a member of `hodor_platform`; it is used
    /// only to find the tenants that have expired records. They are removed
    /// through `database`, as the application role, in each tenant.
    #[must_use]
    pub const fn new(platform: PgPool, database: Database) -> Self {
        Self { platform, database }
    }

    /// Removes, in each tenant that has some, up to `batch` records of
    /// access tokens that had expired at `now`.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be reached.
    pub async fn run(&self, now: Timestamp, batch: u32) -> Result<CleanupReport, DomainError> {
        let tenants: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT DISTINCT tenant_id FROM oauth.access_token
             WHERE expires_at <= $1
             LIMIT $2",
        )
        .bind(now)
        .bind(TENANTS_PER_PASS)
        .fetch_all(&self.platform)
        .await
        .map_err(|error| crate::uow::database_error(&error))?;

        let mut report = CleanupReport::default();
        for (tenant_id,) in tenants {
            // The tenant comes from a stored row, not from any request, as
            // for the pending authorizations above.
            let tenant = TenantContext::assume(TenantId::from_uuid(tenant_id));
            let transaction = self
                .database
                .begin(&tenant)
                .await
                .map_err(|error| crate::uow::database_error(&error))?;
            let mut unit = PgUnitOfWork::new(transaction, tenant.clone());
            let removed = PgAccessTokenRecordStore
                .remove_expired(&mut unit, now, batch)
                .await?;
            Box::new(unit).commit().await?;
            report.tenants += 1;
            report.removed += removed;
        }
        Ok(report)
    }
}

/// The kinds of row [`ExpiredRowCleanup`] removes once they stopped being
/// useful and their retention has passed. `docs/operations/deployment.md`,
/// under "Cleanup", says what each is and why removing it changes no
/// answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExpiredKind {
    /// Sessions that were ended or expired, idle or absolute.
    Sessions,
    /// Sign-ins in progress that expired.
    SignIns,
    /// Registration and recovery links that were used, replaced or expired.
    VerificationTokens,
    /// Messages that were sent, failed or expired.
    Messages,
    /// Security key and passkey registrations never finished.
    WebauthnRegistrations,
    /// Authorization requests kept while a person signed in.
    AuthorizationRequests,
    /// Authorization codes that expired.
    AuthorizationCodes,
    /// Grants that were revoked, with their codes, families and records.
    RevokedGrants,
    /// Refresh token families that expired or were revoked.
    RefreshTokenFamilies,
    /// Remembered `jti` of client assertions that expired.
    ClientAssertions,
    /// Consents withdrawn or expired. Their history stays.
    Consents,
    /// Access tokens of the administration interface that expired or were
    /// revoked.
    AdministrationAccessTokens,
    /// Webhook deliveries that were delivered or set aside.
    WebhookDeliveries,
}

/// The query that finds tenants with rows to remove (`$1` the moment
/// before which a row may go, `$2` how many tenants), and the one that
/// removes a batch in one tenant (`$1` that moment, `$2` the tenant, `$3`
/// the batch). Both are written whole, from literals, never assembled at
/// run time.
macro_rules! expired_rows {
    ($table:literal, $condition:literal) => {
        (
            concat!(
                "SELECT DISTINCT tenant_id FROM ",
                $table,
                " WHERE ",
                $condition,
                " LIMIT $2"
            ),
            concat!(
                "WITH chosen AS (SELECT ctid AS place FROM ",
                $table,
                " WHERE tenant_id = $2 AND ",
                $condition,
                " LIMIT $3 FOR UPDATE SKIP LOCKED) DELETE FROM ",
                $table,
                " WHERE tenant_id = $2 AND ctid IN (SELECT place FROM chosen)"
            ),
        )
    };
}

impl ExpiredKind {
    /// Every kind, in the order the worker starts their jobs.
    pub const ALL: [Self; 13] = [
        Self::Sessions,
        Self::SignIns,
        Self::VerificationTokens,
        Self::Messages,
        Self::WebauthnRegistrations,
        Self::AuthorizationRequests,
        Self::AuthorizationCodes,
        Self::RevokedGrants,
        Self::RefreshTokenFamilies,
        Self::ClientAssertions,
        Self::Consents,
        Self::AdministrationAccessTokens,
        Self::WebhookDeliveries,
    ];

    /// The kind's name, in settings, metrics and logs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sessions => "sessions",
            Self::SignIns => "sign_ins",
            Self::VerificationTokens => "verification_tokens",
            Self::Messages => "messages",
            Self::WebauthnRegistrations => "webauthn_registrations",
            Self::AuthorizationRequests => "authorization_requests",
            Self::AuthorizationCodes => "authorization_codes",
            Self::RevokedGrants => "revoked_grants",
            Self::RefreshTokenFamilies => "refresh_token_families",
            Self::ClientAssertions => "client_assertions",
            Self::Consents => "consents",
            Self::AdministrationAccessTokens => "administration_access_tokens",
            Self::WebhookDeliveries => "webhook_deliveries",
        }
    }

    /// How many days a row is kept after it stopped being useful, unless
    /// the operator says otherwise.
    #[must_use]
    pub const fn default_retention_days(self) -> u32 {
        match self {
            Self::WebauthnRegistrations | Self::AuthorizationRequests | Self::ClientAssertions => 0,
            Self::SignIns | Self::AuthorizationCodes => 1,
            Self::Sessions | Self::VerificationTokens => 7,
            Self::Messages
            | Self::RevokedGrants
            | Self::RefreshTokenFamilies
            | Self::Consents
            | Self::AdministrationAccessTokens
            | Self::WebhookDeliveries => 30,
        }
    }

    const fn queries(self) -> (&'static str, &'static str) {
        match self {
            Self::Sessions => expired_rows!(
                "session.session",
                "(revoked_at <= $1 OR absolute_expires_at <= $1 \
                 OR last_activity_at + idle_timeout_seconds * interval '1 second' <= $1)"
            ),
            Self::SignIns => expired_rows!("authentication.transaction", "expires_at <= $1"),
            Self::VerificationTokens => expired_rows!(
                "authentication.verification_token",
                "(used_at <= $1 OR replaced_at <= $1 OR expires_at <= $1)"
            ),
            Self::Messages => expired_rows!(
                "notification.message",
                "status <> 'pending' AND COALESCE(sent_at, expires_at) <= $1"
            ),
            Self::WebauthnRegistrations => {
                expired_rows!("credential.webauthn_registration", "expires_at <= $1")
            }
            Self::AuthorizationRequests => {
                expired_rows!("oauth.authorization_request", "expires_at <= $1")
            }
            Self::AuthorizationCodes => {
                expired_rows!("oauth.authorization_code", "expires_at <= $1")
            }
            Self::RevokedGrants => expired_rows!(
                "oauth.authorization_grant",
                "status = 'revoked' AND revoked_at <= $1"
            ),
            Self::RefreshTokenFamilies => expired_rows!(
                "oauth.refresh_token_family",
                "(expires_at <= $1 OR (status = 'revoked' AND revoked_at <= $1))"
            ),
            Self::ClientAssertions => expired_rows!("oauth.client_assertion", "expires_at <= $1"),
            Self::Consents => {
                expired_rows!("oauth.consent", "(withdrawn_at <= $1 OR expires_at <= $1)")
            }
            Self::AdministrationAccessTokens => expired_rows!(
                "credential.access_token",
                "(expires_at <= $1 OR revoked_at <= $1)"
            ),
            Self::WebhookDeliveries => expired_rows!(
                "webhooks.delivery",
                "status <> 'pending' AND finished_at <= $1"
            ),
        }
    }
}

impl std::fmt::Display for ExpiredKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::str::FromStr for ExpiredKind {
    type Err = String;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.name() == name)
            .ok_or_else(|| format!("`{name}` is not a kind of row the cleanup removes"))
    }
}

/// Removes the rows of one [`ExpiredKind`] that stopped being useful more
/// than its retention ago.
#[derive(Debug, Clone)]
pub struct ExpiredRowCleanup {
    kind: ExpiredKind,
    retention: time::Duration,
    platform: PgPool,
    database: Database,
}

impl ExpiredRowCleanup {
    /// `platform` must connect as a member of `hodor_platform`; it is used
    /// only to find the tenants that have rows to remove. They are removed
    /// through `database`, as the application role, in each tenant.
    #[must_use]
    pub fn new(
        kind: ExpiredKind,
        retention_days: u32,
        platform: PgPool,
        database: Database,
    ) -> Self {
        Self {
            kind,
            retention: time::Duration::days(i64::from(retention_days)),
            platform,
            database,
        }
    }

    /// The kind of row this job removes.
    #[must_use]
    pub const fn kind(&self) -> ExpiredKind {
        self.kind
    }

    /// Removes, in each tenant that has some, up to `batch` rows that
    /// stopped being useful before `now` less the retention.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be reached.
    pub async fn run(&self, now: Timestamp, batch: u32) -> Result<CleanupReport, DomainError> {
        let before = now - self.retention;
        let (find, remove) = self.kind.queries();
        let tenants: Vec<(Uuid,)> = sqlx::query_as(find)
            .bind(before)
            .bind(TENANTS_PER_PASS)
            .fetch_all(&self.platform)
            .await
            .map_err(|error| crate::uow::database_error(&error))?;

        let mut report = CleanupReport::default();
        for (tenant_id,) in tenants {
            // The tenant comes from a stored row, not from any request, as
            // for the pending authorizations above.
            let tenant = TenantContext::assume(TenantId::from_uuid(tenant_id));
            let mut transaction = self
                .database
                .begin(&tenant)
                .await
                .map_err(|error| crate::uow::database_error(&error))?;
            let removed = sqlx::query(remove)
                .bind(before)
                .bind(tenant_id)
                .bind(i64::from(batch))
                .execute(transaction.connection())
                .await
                .map_err(|error| crate::uow::database_error(&error))?
                .rows_affected();
            transaction
                .commit()
                .await
                .map_err(|error| crate::uow::database_error(&error))?;
            report.tenants += 1;
            report.removed += removed;
        }
        Ok(report)
    }
}
