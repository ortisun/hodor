//! PostgreSQL storage for the credential context.
//!
//! See `docs/architecture/contexts/credential.md`, "Storage".

use crate::uow::{connection, database_error};
use hodor_credential::api::{
    AccessToken, AccessTokenHash, AccessTokenId, AccessTokenSnapshot, AccessTokenStore, Challenge,
    CoseAlgorithm, HistoricHash, PasswordHash, PasswordRecord, PasswordStore, PendingRegistration,
    PendingRegistrationSnapshot, RecoveryCodeSet, RecoveryCodeStore, Totp, TotpId, TotpSnapshot,
    TotpStatus, TotpStore, WebAuthnCredential, WebAuthnCredentialId, WebAuthnCredentialSnapshot,
    WebAuthnRegistrationId, WebAuthnStore,
};
use hodor_kernel::{DomainError, SealedSecret, TenantId, Timestamp, UnitOfWork, UserId};
use sqlx::PgConnection;
use sqlx::types::Uuid;

/// [`PasswordStore`] on `credential.password` and
/// `credential.password_history`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgPasswordStore;

fn out_of_range(what: &str) -> DomainError {
    DomainError::internal(
        "credential.stored_data_invalid",
        "the operation could not be completed",
    )
    .with_detail(what.to_owned())
}

fn stored_version(record: &PasswordRecord) -> Result<i32, DomainError> {
    i32::try_from(record.version()).map_err(|_| out_of_range("version out of range"))
}

async fn insert_history(
    connection: &mut PgConnection,
    tenant: TenantId,
    record: &PasswordRecord,
) -> Result<(), DomainError> {
    for (position, entry) in record.history().iter().enumerate() {
        let position = i16::try_from(position).map_err(|_| out_of_range("history too long"))?;
        sqlx::query(
            "INSERT INTO credential.password_history
                 (tenant_id, id, user_id, position, password_hash, replaced_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(tenant.as_uuid())
        .bind(Uuid::now_v7())
        .bind(record.user_id().as_uuid())
        .bind(position)
        .bind(entry.hash.as_str())
        .bind(entry.replaced_at)
        .execute(&mut *connection)
        .await
        .map_err(|e| database_error(&e))?;
    }
    Ok(())
}

#[async_trait::async_trait]
impl PasswordStore for PgPasswordStore {
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
    ) -> Result<Option<PasswordRecord>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let connection = connection(uow)?;
        let row: Option<(String, bool, Timestamp, i32)> = sqlx::query_as(
            "SELECT password_hash, must_change, changed_at, version
             FROM credential.password
             WHERE tenant_id = $1 AND user_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(user_id.as_uuid())
        .fetch_optional(&mut *connection)
        .await
        .map_err(|e| database_error(&e))?;
        let Some((hash, must_change, changed_at, version)) = row else {
            return Ok(None);
        };

        let history: Vec<(String, Timestamp)> = sqlx::query_as(
            "SELECT password_hash, replaced_at
             FROM credential.password_history
             WHERE tenant_id = $1 AND user_id = $2
             ORDER BY position",
        )
        .bind(tenant.as_uuid())
        .bind(user_id.as_uuid())
        .fetch_all(&mut *connection)
        .await
        .map_err(|e| database_error(&e))?;

        Ok(Some(PasswordRecord::from_stored(
            user_id,
            PasswordHash::new(hash),
            must_change,
            changed_at,
            history
                .into_iter()
                .map(|(hash, replaced_at)| HistoricHash {
                    hash: PasswordHash::new(hash),
                    replaced_at,
                })
                .collect(),
            u32::try_from(version).map_err(|_| out_of_range("negative version"))?,
        )))
    }

    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        record: &PasswordRecord,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let version = stored_version(record)?;
        let connection = connection(uow)?;
        // `ON CONFLICT DO NOTHING` rather than catching the error: a failed
        // statement would abort the whole transaction.
        let inserted = sqlx::query(
            "INSERT INTO credential.password
                 (tenant_id, user_id, password_hash, must_change, changed_at, version)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (tenant_id, user_id) DO NOTHING",
        )
        .bind(tenant.as_uuid())
        .bind(record.user_id().as_uuid())
        .bind(record.hash().as_str())
        .bind(record.must_change())
        .bind(record.changed_at())
        .bind(version)
        .execute(&mut *connection)
        .await
        .map_err(|e| database_error(&e))?
        .rows_affected();
        if inserted == 0 {
            return Err(DomainError::conflict(
                "credential.password_exists",
                "the user already has a password",
            ));
        }
        insert_history(connection, tenant, record).await
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        record: &PasswordRecord,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let version = stored_version(record)?;
        let connection = connection(uow)?;

        let updated = sqlx::query(
            "UPDATE credential.password
             SET password_hash = $3, must_change = $4, changed_at = $5, version = version + 1
             WHERE tenant_id = $1 AND user_id = $2 AND version = $6",
        )
        .bind(tenant.as_uuid())
        .bind(record.user_id().as_uuid())
        .bind(record.hash().as_str())
        .bind(record.must_change())
        .bind(record.changed_at())
        .bind(version)
        .execute(&mut *connection)
        .await
        .map_err(|e| database_error(&e))?
        .rows_affected();

        if updated == 0 {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT FROM credential.password WHERE tenant_id = $1 AND user_id = $2)",
            )
            .bind(tenant.as_uuid())
            .bind(record.user_id().as_uuid())
            .fetch_one(&mut *connection)
            .await
            .map_err(|e| database_error(&e))?;
            return Err(if exists {
                DomainError::conflict(
                    "credential.password_modified_concurrently",
                    "the password was changed by someone else; try again",
                )
            } else {
                DomainError::not_found("credential.password_not_found", "the user has no password")
            });
        }

        // The version check means nobody else changed this record, so its
        // short history can simply be replaced.
        sqlx::query(
            "DELETE FROM credential.password_history WHERE tenant_id = $1 AND user_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(record.user_id().as_uuid())
        .execute(&mut *connection)
        .await
        .map_err(|e| database_error(&e))?;
        insert_history(connection, tenant, record).await
    }

    async fn delete(&self, uow: &mut dyn UnitOfWork, user_id: UserId) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let deleted =
            sqlx::query("DELETE FROM credential.password WHERE tenant_id = $1 AND user_id = $2")
                .bind(tenant.as_uuid())
                .bind(user_id.as_uuid())
                .execute(connection(uow)?)
                .await
                .map_err(|e| database_error(&e))?
                .rows_affected();
        Ok(deleted > 0)
    }
}

/// [`AccessTokenStore`] on `credential.access_token`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgAccessTokenStore;

const TOKEN_COLUMNS: &str =
    "id, user_id, token_hash, description, created_at, expires_at, revoked_at";

type TokenRow = (
    Uuid,
    Uuid,
    Vec<u8>,
    String,
    Timestamp,
    Timestamp,
    Option<Timestamp>,
);

fn to_token(row: TokenRow) -> Result<AccessToken, DomainError> {
    let (id, user_id, token_hash, description, created_at, expires_at, revoked_at) = row;
    let hash: [u8; 32] = token_hash
        .try_into()
        .map_err(|_| out_of_range("token hash is not 32 bytes"))?;
    Ok(AccessToken::from_snapshot(AccessTokenSnapshot {
        id: AccessTokenId::from_uuid(id),
        user_id: UserId::from_uuid(user_id),
        token_hash: AccessTokenHash::from_stored(hash),
        description,
        created_at,
        expires_at,
        revoked_at,
    }))
}

#[async_trait::async_trait]
impl AccessTokenStore for PgAccessTokenStore {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        token: &AccessToken,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = token.snapshot();
        sqlx::query(
            "INSERT INTO credential.access_token
                 (tenant_id, id, user_id, token_hash, description, created_at, expires_at,
                  revoked_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.user_id.as_uuid())
        .bind(state.token_hash.as_bytes().as_slice())
        .bind(&state.description)
        .bind(state.created_at)
        .bind(state.expires_at)
        .bind(state.revoked_at)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: AccessTokenId,
    ) -> Result<Option<AccessToken>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<TokenRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {TOKEN_COLUMNS} FROM credential.access_token WHERE tenant_id = $1 AND id = $2"
        )))
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.map(to_token).transpose()
    }

    async fn find_by_hash(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &AccessTokenHash,
    ) -> Result<Option<AccessToken>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<TokenRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {TOKEN_COLUMNS} FROM credential.access_token
             WHERE tenant_id = $1 AND token_hash = $2"
        )))
        .bind(tenant.as_uuid())
        .bind(hash.as_bytes().as_slice())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.map(to_token).transpose()
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        token: &AccessToken,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = token.snapshot();
        // Only the revocation can change; everything else about a token
        // is fixed when it is issued.
        let updated = sqlx::query(
            "UPDATE credential.access_token SET revoked_at = $3
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.revoked_at)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        if updated.rows_affected() == 0 {
            return Err(DomainError::not_found(
                "credential.access_token_not_found",
                "the access token does not exist",
            ));
        }
        Ok(())
    }
}

/// [`TotpStore`] on `credential.totp`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgTotpStore;

const TOTP_COLUMNS: &str =
    "id, user_id, status, sealed_secret, created_at, confirmed_at, last_used_step";

type TotpRow = (
    Uuid,
    Uuid,
    String,
    Vec<u8>,
    Timestamp,
    Option<Timestamp>,
    Option<i64>,
);

fn to_totp(row: TotpRow) -> Result<Totp, DomainError> {
    let (id, user_id, status, sealed_secret, created_at, confirmed_at, last_used_step) = row;
    Ok(Totp::from_snapshot(TotpSnapshot {
        id: TotpId::from_uuid(id),
        user_id: UserId::from_uuid(user_id),
        status: TotpStatus::parse(&status).ok_or_else(|| out_of_range("unknown status"))?,
        sealed_secret: SealedSecret::from_stored(sealed_secret),
        created_at,
        confirmed_at,
        last_used_step: last_used_step
            .map(u64::try_from)
            .transpose()
            .map_err(|_| out_of_range("negative step"))?,
    }))
}

fn stored_step(step: u64) -> Result<i64, DomainError> {
    i64::try_from(step).map_err(|_| out_of_range("step out of range"))
}

impl PgTotpStore {
    async fn by_status(
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
        status: TotpStatus,
    ) -> Result<Option<Totp>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<TotpRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {TOTP_COLUMNS} FROM credential.totp
             WHERE tenant_id = $1 AND user_id = $2 AND status = $3"
        )))
        .bind(tenant.as_uuid())
        .bind(user_id.as_uuid())
        .bind(status.as_str())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.map(to_totp).transpose()
    }
}

#[async_trait::async_trait]
impl TotpStore for PgTotpStore {
    async fn active(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
    ) -> Result<Option<Totp>, DomainError> {
        Self::by_status(uow, user_id, TotpStatus::Active).await
    }

    async fn pending(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
    ) -> Result<Option<Totp>, DomainError> {
        Self::by_status(uow, user_id, TotpStatus::Pending).await
    }

    async fn replace_pending(
        &self,
        uow: &mut dyn UnitOfWork,
        enrollment: &Totp,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = enrollment.snapshot();
        sqlx::query(
            "DELETE FROM credential.totp
             WHERE tenant_id = $1 AND user_id = $2 AND status = 'pending'",
        )
        .bind(tenant.as_uuid())
        .bind(state.user_id.as_uuid())
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        sqlx::query(
            "INSERT INTO credential.totp
                 (tenant_id, id, user_id, status, sealed_secret, created_at, confirmed_at,
                  last_used_step)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.user_id.as_uuid())
        .bind(state.status.as_str())
        .bind(state.sealed_secret.as_bytes())
        .bind(state.created_at)
        .bind(state.confirmed_at)
        .bind(state.last_used_step.map(stored_step).transpose()?)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn activate(
        &self,
        uow: &mut dyn UnitOfWork,
        confirmed: &Totp,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = confirmed.snapshot();
        // The enrollment is locked first. A second confirmation of the same
        // enrollment waits here, then finds it no longer pending and
        // changes nothing.
        let waiting: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM credential.totp
             WHERE tenant_id = $1 AND id = $2 AND status = 'pending'
             FOR UPDATE",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        if waiting.is_none() {
            return Err(DomainError::not_found(
                "credential.totp_enrollment_not_found",
                "there is no enrollment of an authenticator application waiting to be confirmed; begin again",
            ));
        }
        sqlx::query(
            "DELETE FROM credential.totp
             WHERE tenant_id = $1 AND user_id = $2 AND status = 'active'",
        )
        .bind(tenant.as_uuid())
        .bind(state.user_id.as_uuid())
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        let updated = sqlx::query(
            "UPDATE credential.totp
             SET status = 'active', confirmed_at = $3, last_used_step = $4
             WHERE tenant_id = $1 AND id = $2 AND status = 'pending'",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.confirmed_at)
        .bind(state.last_used_step.map(stored_step).transpose()?)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        if updated.rows_affected() == 0 {
            return Err(DomainError::not_found(
                "credential.totp_enrollment_not_found",
                "there is no enrollment of an authenticator application waiting to be confirmed; begin again",
            ));
        }
        Ok(())
    }

    async fn use_step(
        &self,
        uow: &mut dyn UnitOfWork,
        id: TotpId,
        step: u64,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        // One statement: of two requests with the same step, the row lock
        // makes the second see the first one's step and change nothing.
        let updated = sqlx::query(
            "UPDATE credential.totp SET last_used_step = $3
             WHERE tenant_id = $1 AND id = $2 AND status = 'active'
               AND (last_used_step IS NULL OR last_used_step < $3)",
        )
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .bind(stored_step(step)?)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(updated.rows_affected() == 1)
    }

    async fn remove(&self, uow: &mut dyn UnitOfWork, user_id: UserId) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let had: Option<(i64,)> = sqlx::query_as(
            "WITH gone AS (
                 DELETE FROM credential.totp WHERE tenant_id = $1 AND user_id = $2
                 RETURNING status
             )
             SELECT count(*) FROM gone WHERE status = 'active'",
        )
        .bind(tenant.as_uuid())
        .bind(user_id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(had.is_some_and(|(count,)| count > 0))
    }
}

/// [`WebAuthnStore`] on `credential.webauthn_credential` and
/// `credential.webauthn_registration`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgWebAuthnStore;

const CREDENTIAL_CONSTRAINT: &str = "webauthn_credential_id_unique";

const WEBAUTHN_COLUMNS: &str = "id, user_id, credential_id, public_key, algorithm, sign_count,
     backup_eligible, backed_up, discoverable, transports, name, created_at, last_used_at";

type WebAuthnRow = (
    Uuid,
    Uuid,
    Vec<u8>,
    Vec<u8>,
    i32,
    i64,
    bool,
    bool,
    Option<bool>,
    Vec<String>,
    String,
    Timestamp,
    Option<Timestamp>,
);

fn to_webauthn(row: WebAuthnRow) -> Result<WebAuthnCredential, DomainError> {
    let (
        id,
        user_id,
        credential_id,
        public_key,
        algorithm,
        sign_count,
        backup_eligible,
        backed_up,
        discoverable,
        transports,
        name,
        created_at,
        last_used_at,
    ) = row;
    Ok(WebAuthnCredential::from_snapshot(
        WebAuthnCredentialSnapshot {
            id: WebAuthnCredentialId::from_uuid(id),
            user_id: UserId::from_uuid(user_id),
            credential_id,
            public_key,
            algorithm: CoseAlgorithm::from_code(i64::from(algorithm))
                .ok_or_else(|| out_of_range("unknown WebAuthn algorithm"))?,
            sign_count: u32::try_from(sign_count)
                .map_err(|_| out_of_range("WebAuthn counter out of range"))?,
            backup_eligible,
            backed_up,
            discoverable,
            transports,
            name,
            created_at,
            last_used_at,
        },
    ))
}

#[async_trait::async_trait]
impl WebAuthnStore for PgWebAuthnStore {
    async fn insert_registration(
        &self,
        uow: &mut dyn UnitOfWork,
        registration: &PendingRegistration,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = registration.snapshot();
        sqlx::query(
            "INSERT INTO credential.webauthn_registration
                 (tenant_id, id, user_id, challenge, passkey, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.user_id.as_uuid())
        .bind(state.challenge.0.as_slice())
        .bind(state.passkey)
        .bind(state.created_at)
        .bind(state.expires_at)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn take_registration(
        &self,
        uow: &mut dyn UnitOfWork,
        id: WebAuthnRegistrationId,
    ) -> Result<Option<PendingRegistration>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        // Deleting and returning in one statement: of any number of
        // requests at once, one gets the row.
        let row: Option<(Uuid, Vec<u8>, bool, Timestamp, Timestamp)> = sqlx::query_as(
            "DELETE FROM credential.webauthn_registration
             WHERE tenant_id = $1 AND id = $2
             RETURNING user_id, challenge, passkey, created_at, expires_at",
        )
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.map(|(user_id, challenge, passkey, created_at, expires_at)| {
            let challenge: [u8; 32] = challenge
                .try_into()
                .map_err(|_| out_of_range("challenge is not 32 bytes"))?;
            Ok(PendingRegistration::from_snapshot(
                PendingRegistrationSnapshot {
                    id,
                    user_id: UserId::from_uuid(user_id),
                    challenge: Challenge(challenge),
                    passkey,
                    created_at,
                    expires_at,
                },
            ))
        })
        .transpose()
    }

    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        credential: &WebAuthnCredential,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = credential.snapshot();
        let result = sqlx::query(
            "INSERT INTO credential.webauthn_credential
                 (tenant_id, id, user_id, credential_id, public_key, algorithm, sign_count,
                  backup_eligible, backed_up, discoverable, transports, name, created_at,
                  last_used_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.user_id.as_uuid())
        .bind(&state.credential_id)
        .bind(&state.public_key)
        .bind(state.algorithm.code())
        .bind(i64::from(state.sign_count))
        .bind(state.backup_eligible)
        .bind(state.backed_up)
        .bind(state.discoverable)
        .bind(&state.transports)
        .bind(&state.name)
        .bind(state.created_at)
        .bind(state.last_used_at)
        .execute(connection(uow)?)
        .await;
        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(error))
                if error.constraint() == Some(CREDENTIAL_CONSTRAINT) =>
            {
                Err(DomainError::conflict(
                    "credential.webauthn_credential_exists",
                    "this security key is already registered",
                ))
            }
            Err(error) => Err(database_error(&error)),
        }
    }

    async fn list_for_user(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
    ) -> Result<Vec<WebAuthnCredential>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let rows: Vec<WebAuthnRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {WEBAUTHN_COLUMNS} FROM credential.webauthn_credential
             WHERE tenant_id = $1 AND user_id = $2
             ORDER BY created_at, id"
        )))
        .bind(tenant.as_uuid())
        .bind(user_id.as_uuid())
        .fetch_all(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        rows.into_iter().map(to_webauthn).collect()
    }

    async fn find_by_credential_id(
        &self,
        uow: &mut dyn UnitOfWork,
        credential_id: &[u8],
    ) -> Result<Option<WebAuthnCredential>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<WebAuthnRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {WEBAUTHN_COLUMNS} FROM credential.webauthn_credential
             WHERE tenant_id = $1 AND credential_id = $2"
        )))
        .bind(tenant.as_uuid())
        .bind(credential_id)
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.map(to_webauthn).transpose()
    }

    async fn record_use(
        &self,
        uow: &mut dyn UnitOfWork,
        credential: &WebAuthnCredential,
        previous_count: u32,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = credential.snapshot();
        let updated = sqlx::query(
            "UPDATE credential.webauthn_credential
             SET sign_count = $3, backed_up = $4, last_used_at = $5
             WHERE tenant_id = $1 AND id = $2 AND sign_count = $6",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(i64::from(state.sign_count))
        .bind(state.backed_up)
        .bind(state.last_used_at)
        .bind(i64::from(previous_count))
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(updated.rows_affected() == 1)
    }

    async fn rename(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
        id: WebAuthnCredentialId,
        name: &str,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let updated = sqlx::query(
            "UPDATE credential.webauthn_credential SET name = $4
             WHERE tenant_id = $1 AND id = $2 AND user_id = $3",
        )
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .bind(user_id.as_uuid())
        .bind(name)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(updated.rows_affected() == 1)
    }

    async fn remove(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
        id: WebAuthnCredentialId,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let removed = sqlx::query(
            "DELETE FROM credential.webauthn_credential
             WHERE tenant_id = $1 AND id = $2 AND user_id = $3",
        )
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .bind(user_id.as_uuid())
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(removed.rows_affected() == 1)
    }
}

/// [`RecoveryCodeStore`] on `credential.recovery_code_set` and
/// `credential.recovery_code`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgRecoveryCodeStore;

#[async_trait::async_trait]
impl RecoveryCodeStore for PgRecoveryCodeStore {
    async fn replace(
        &self,
        uow: &mut dyn UnitOfWork,
        set: &RecoveryCodeSet,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        // The earlier set goes with its codes. Of two sets stored at the
        // same moment, the second waits here or at the insert below, then
        // meets the first one's row and is refused.
        sqlx::query(
            "DELETE FROM credential.recovery_code_set WHERE tenant_id = $1 AND user_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(set.user_id.as_uuid())
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        sqlx::query(
            "INSERT INTO credential.recovery_code_set (tenant_id, id, user_id, created_at)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(tenant.as_uuid())
        .bind(set.id.as_uuid())
        .bind(set.user_id.as_uuid())
        .bind(set.created_at)
        .execute(connection(uow)?)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(database) if database.is_unique_violation() => {
                DomainError::conflict(
                    "credential.recovery_codes_conflict",
                    "another set of recovery codes was generated at the same time; ask again",
                )
            }
            _ => database_error(&e),
        })?;
        let ids: Vec<Uuid> = set.code_hashes.iter().map(|_| Uuid::now_v7()).collect();
        let hashes: Vec<Vec<u8>> = set.code_hashes.iter().map(|hash| hash.to_vec()).collect();
        sqlx::query(
            "INSERT INTO credential.recovery_code (tenant_id, id, set_id, code_hash)
             SELECT $1, id, $2, code_hash FROM unnest($3::uuid[], $4::bytea[]) AS code (id, code_hash)",
        )
        .bind(tenant.as_uuid())
        .bind(set.id.as_uuid())
        .bind(&ids)
        .bind(&hashes)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn use_code(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
        code_hash: &[u8; 32],
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        // One statement: of many requests with the same code, the row lock
        // makes every one after the first see it used and change nothing.
        let updated = sqlx::query(
            "UPDATE credential.recovery_code AS code SET used_at = now()
             FROM credential.recovery_code_set AS code_set
             WHERE code.tenant_id = $1 AND code_set.tenant_id = $1
               AND code_set.id = code.set_id AND code_set.user_id = $2
               AND code.code_hash = $3 AND code.used_at IS NULL",
        )
        .bind(tenant.as_uuid())
        .bind(user_id.as_uuid())
        .bind(code_hash.as_slice())
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(updated.rows_affected() == 1)
    }

    async fn unused(&self, uow: &mut dyn UnitOfWork, user_id: UserId) -> Result<u32, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let (count,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM credential.recovery_code AS code
             JOIN credential.recovery_code_set AS code_set
               ON code_set.tenant_id = code.tenant_id AND code_set.id = code.set_id
             WHERE code.tenant_id = $1 AND code_set.user_id = $2 AND code.used_at IS NULL",
        )
        .bind(tenant.as_uuid())
        .bind(user_id.as_uuid())
        .fetch_one(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        u32::try_from(count).map_err(|_| out_of_range("count out of range"))
    }

    async fn remove(&self, uow: &mut dyn UnitOfWork, user_id: UserId) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let removed = sqlx::query(
            "DELETE FROM credential.recovery_code_set WHERE tenant_id = $1 AND user_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(user_id.as_uuid())
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(removed.rows_affected() > 0)
    }
}
