//! Sealing every stored secret again as new secrets are sealed now.
//!
//! What `hodor-cli secrets reseal` runs, one tenant at a time. See
//! `docs/security/secrets-at-rest.md`, "Sealing everything again".

use crate::database::Database;
use crate::uow::database_error;
use hodor_kernel::{DomainError, SealedSecret, SecretBox, TenantContext};
use sqlx::types::Uuid;

/// The rows read at a time.
const PAGE: i64 = 100;

/// A column that holds sealed secrets, and the purpose they are sealed for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedColumn {
    /// The table, with its schema.
    pub table: &'static str,
    /// The column that, with the tenant, names a row: a `uuid`.
    pub key: &'static str,
    /// The column of sealed secrets: a `bytea`.
    pub column: &'static str,
    /// The purpose its secrets are sealed for.
    pub purpose: &'static str,
}

/// Every column that holds sealed secrets. A test of the schema fails when
/// a `bytea` column is neither here nor among the columns known to hold no
/// secret.
pub const SEALED_COLUMNS: &[SealedColumn] = &[
    SealedColumn {
        table: "federation.identity_provider",
        key: "id",
        column: "client_secret",
        purpose: hodor_federation::api::CLIENT_SECRET_PURPOSE,
    },
    SealedColumn {
        table: "federation.pending_authorization",
        key: "transaction_id",
        column: "code_verifier",
        purpose: hodor_federation::api::CODE_VERIFIER_PURPOSE,
    },
    SealedColumn {
        table: "credential.totp",
        key: "id",
        column: "sealed_secret",
        purpose: hodor_credential::api::TOTP_SEALING_PURPOSE,
    },
];

/// What sealing a tenant's secrets again did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResealReport {
    /// Secrets sealed again.
    pub resealed: u64,
    /// Secrets already sealed as new secrets are, or changed by someone
    /// else while this ran.
    pub current: u64,
    /// Secrets that needed it and did not open. They stay as they were.
    pub unreadable: u64,
}

impl ResealReport {
    /// Whether everything is sealed as new secrets are: nothing was left
    /// unreadable.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.unreadable == 0
    }
}

/// Seals again, in `tenant`, every secret `secrets` says needs it. Each
/// row is its own transaction and is written only if it still holds what
/// was read, so stopping loses nothing and running again does what is
/// left.
///
/// # Errors
///
/// Returns an error if the database cannot be reached or a secret cannot
/// be sealed. A secret that does not open is counted, not an error.
pub async fn reseal_tenant(
    database: &Database,
    secrets: &dyn SecretBox,
    tenant: &TenantContext,
) -> Result<ResealReport, DomainError> {
    let mut report = ResealReport::default();
    for column in SEALED_COLUMNS {
        reseal_column(database, secrets, tenant, column, &mut report).await?;
    }
    Ok(report)
}

async fn reseal_column(
    database: &Database,
    secrets: &dyn SecretBox,
    tenant: &TenantContext,
    column: &SealedColumn,
    report: &mut ResealReport,
) -> Result<(), DomainError> {
    let SealedColumn {
        table,
        key,
        column: sealed_column,
        purpose,
    } = *column;
    let select = format!(
        "SELECT {key}, {sealed_column} FROM {table}
         WHERE tenant_id = $1 AND ($2::uuid IS NULL OR {key} > $2)
         ORDER BY {key} LIMIT $3"
    );
    let update = format!(
        "UPDATE {table} SET {sealed_column} = $3
         WHERE tenant_id = $1 AND {key} = $2 AND {sealed_column} = $4"
    );
    let mut after: Option<Uuid> = None;
    loop {
        let mut transaction = database
            .begin(tenant)
            .await
            .map_err(|e| database_error(&e))?;
        let rows: Vec<(Uuid, Vec<u8>)> = sqlx::query_as(sqlx::AssertSqlSafe(select.clone()))
            .bind(tenant.tenant_id().as_uuid())
            .bind(after)
            .bind(PAGE)
            .fetch_all(transaction.connection())
            .await
            .map_err(|e| database_error(&e))?;
        transaction.commit().await.map_err(|e| database_error(&e))?;
        let Some((last, _)) = rows.last() else {
            return Ok(());
        };
        after = Some(*last);

        for (row, stored) in rows {
            let sealed = SealedSecret::from_stored(stored);
            if !secrets.needs_resealing(tenant, &sealed).await? {
                report.current += 1;
                continue;
            }
            let secret = match secrets.open(tenant, purpose, &sealed).await {
                Ok(secret) => secret,
                Err(error) if error.code() == "secret.unreadable" => {
                    report.unreadable += 1;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let resealed = secrets.seal(tenant, purpose, &secret).await?;
            let mut transaction = database
                .begin(tenant)
                .await
                .map_err(|e| database_error(&e))?;
            let written = sqlx::query(sqlx::AssertSqlSafe(update.clone()))
                .bind(tenant.tenant_id().as_uuid())
                .bind(row)
                .bind(resealed.as_bytes())
                .bind(sealed.as_bytes())
                .execute(transaction.connection())
                .await
                .map_err(|e| database_error(&e))?
                .rows_affected();
            transaction.commit().await.map_err(|e| database_error(&e))?;
            if written == 1 {
                report.resealed += 1;
            } else {
                report.current += 1;
            }
        }
    }
}
