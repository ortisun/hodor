//! PostgreSQL storage for the authentication context.
//!
//! See `docs/architecture/contexts/authentication.md`, "Storage".

use crate::uow::{connection, database_error};
use hodor_authentication::api::{
    AttemptCounter, AttemptStore, AttemptSubject, AuthTransaction, TokenPurpose, TransactionId,
    TransactionSnapshot, TransactionStatus, TransactionStore, VerificationToken,
    VerificationTokenHash, VerificationTokenId, VerificationTokenSnapshot, VerificationTokenStore,
};
use hodor_kernel::{DomainError, Timestamp, UnitOfWork, UserId};
use hodor_session::api::{Assurance, ClientInfo, SessionId};
use sqlx::Row as _;
use sqlx::postgres::PgRow;
use sqlx::types::Uuid;

/// [`AttemptStore`] on `authentication.attempt_counter`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgAttemptStore;

fn corrupted(what: &str) -> DomainError {
    DomainError::internal(
        "authentication.stored_data_invalid",
        "the operation could not be completed",
    )
    .with_detail(what.to_owned())
}

fn stored(value: u32) -> Result<i32, DomainError> {
    i32::try_from(value).map_err(|_| corrupted("counter out of range"))
}

#[async_trait::async_trait]
impl AttemptStore for PgAttemptStore {
    async fn lock(
        &self,
        uow: &mut dyn UnitOfWork,
        subject: &AttemptSubject,
        now: Timestamp,
    ) -> Result<AttemptCounter, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let connection = connection(uow)?;
        // One statement creates the row if it is missing, locks it, and
        // returns it. The update that changes nothing is what takes the
        // lock when the row already exists; a second transaction asking
        // for the same subject waits here until this one ends.
        //
        // Doing this in two statements, an insert and then a locking
        // select, leaves a gap: a concurrent clear can delete the row in
        // between, and the select then finds nothing.
        let (failures, window_started_at, lockouts, locked_until): (
            i32,
            Timestamp,
            i32,
            Option<Timestamp>,
        ) = sqlx::query_as(
            "INSERT INTO authentication.attempt_counter AS counter
                     (tenant_id, subject_kind, subject_key, failures, window_started_at, lockouts)
                 VALUES ($1, $2, $3, 0, $4, 0)
                 ON CONFLICT (tenant_id, subject_kind, subject_key)
                 DO UPDATE SET failures = counter.failures
                 RETURNING failures, window_started_at, lockouts, locked_until",
        )
        .bind(tenant.as_uuid())
        .bind(subject.kind())
        .bind(subject.key().as_slice())
        .bind(now)
        .fetch_one(&mut *connection)
        .await
        .map_err(|e| database_error(&e))?;

        Ok(AttemptCounter::from_stored(
            *subject,
            u32::try_from(failures).map_err(|_| corrupted("negative failures"))?,
            window_started_at,
            u32::try_from(lockouts).map_err(|_| corrupted("negative lockouts"))?,
            locked_until,
        ))
    }

    async fn save(
        &self,
        uow: &mut dyn UnitOfWork,
        counter: &AttemptCounter,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let subject = counter.subject();
        sqlx::query(
            "UPDATE authentication.attempt_counter
             SET failures = $4, window_started_at = $5, lockouts = $6, locked_until = $7
             WHERE tenant_id = $1 AND subject_kind = $2 AND subject_key = $3",
        )
        .bind(tenant.as_uuid())
        .bind(subject.kind())
        .bind(subject.key().as_slice())
        .bind(stored(counter.failures())?)
        .bind(counter.window_started_at())
        .bind(stored(counter.lockouts())?)
        .bind(counter.stored_locked_until())
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn clear(
        &self,
        uow: &mut dyn UnitOfWork,
        subject: &AttemptSubject,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "DELETE FROM authentication.attempt_counter
             WHERE tenant_id = $1 AND subject_kind = $2 AND subject_key = $3",
        )
        .bind(tenant.as_uuid())
        .bind(subject.kind())
        .bind(subject.key().as_slice())
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }
}

/// [`TransactionStore`] on `authentication.transaction`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgTransactionStore;

fn unsigned(value: i32, what: &str) -> Result<u32, DomainError> {
    u32::try_from(value).map_err(|_| corrupted(what))
}

fn bytes_32(value: Vec<u8>, what: &str) -> Result<[u8; 32], DomainError> {
    <[u8; 32]>::try_from(value).map_err(|_| corrupted(what))
}

fn to_transaction(row: &PgRow) -> Result<AuthTransaction, DomainError> {
    let get = |error: sqlx::Error| database_error(&error);
    let flow_version: i32 = row.try_get("flow_version").map_err(get)?;
    let current_step: i32 = row.try_get("current_step").map_err(get)?;
    let candidate: Option<Uuid> = row.try_get("candidate_user_id").map_err(get)?;
    let identifier_key: Option<Vec<u8>> = row.try_get("identifier_key").map_err(get)?;
    let challenge: Option<Vec<u8>> = row.try_get("challenge").map_err(get)?;
    let rejections: i32 = row.try_get("rejections").map_err(get)?;
    let status: String = row.try_get("status").map_err(get)?;
    let binding: Vec<u8> = row.try_get("binding").map_err(get)?;
    let version: i32 = row.try_get("version").map_err(get)?;
    let demanded: Option<String> = row.try_get("demanded_assurance").map_err(get)?;
    let raised: Option<Uuid> = row.try_get("raised_session_id").map_err(get)?;
    Ok(AuthTransaction::from_snapshot(TransactionSnapshot {
        id: TransactionId::from_uuid(row.try_get("id").map_err(get)?),
        flow_name: row.try_get("flow_name").map_err(get)?,
        flow_version: unsigned(flow_version, "negative flow version")?,
        current_step: usize::try_from(current_step).map_err(|_| corrupted("negative step"))?,
        identified: row.try_get("identified").map_err(get)?,
        candidate: candidate.map(UserId::from_uuid),
        identifier_key: identifier_key
            .map(|key| bytes_32(key, "identifier key is not 32 bytes"))
            .transpose()?,
        satisfied_methods: row.try_get("satisfied_methods").map_err(get)?,
        carried_methods: row.try_get("carried_methods").map_err(get)?,
        demanded: demanded
            .as_deref()
            .map(Assurance::from_stored)
            .transpose()?,
        raised_session: raised.map(SessionId::from_uuid),
        challenge: challenge
            .map(|challenge| bytes_32(challenge, "challenge is not 32 bytes"))
            .transpose()?,
        rejections: unsigned(rejections, "negative rejections")?,
        status: TransactionStatus::from_stored(&status)?,
        started_at: row.try_get("started_at").map_err(get)?,
        expires_at: row.try_get("expires_at").map_err(get)?,
        client: ClientInfo {
            address: row.try_get("client_address").map_err(get)?,
            description: row.try_get("client_description").map_err(get)?,
        },
        binding: bytes_32(binding, "binding is not 32 bytes")?,
        version: unsigned(version, "negative version")?,
    }))
}

#[async_trait::async_trait]
impl TransactionStore for PgTransactionStore {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        transaction: &AuthTransaction,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = transaction.snapshot();
        sqlx::query(
            "INSERT INTO authentication.transaction
                 (tenant_id, id, flow_name, flow_version, current_step, identified, candidate_user_id,
                  identifier_key, satisfied_methods, rejections, status, started_at, expires_at,
                  client_address, client_description, binding, version, challenge, carried_methods,
                  demanded_assurance, raised_session_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
                     $18, $19, $20, $21)",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(&state.flow_name)
        .bind(stored(state.flow_version)?)
        .bind(i32::try_from(state.current_step).map_err(|_| corrupted("step out of range"))?)
        .bind(state.identified)
        .bind(state.candidate.map(|user| user.as_uuid()))
        .bind(state.identifier_key.map(|key| key.to_vec()))
        .bind(&state.satisfied_methods)
        .bind(stored(state.rejections)?)
        .bind(state.status.as_str())
        .bind(state.started_at)
        .bind(state.expires_at)
        .bind(&state.client.address)
        .bind(&state.client.description)
        .bind(state.binding.as_slice())
        .bind(stored(state.version)?)
        .bind(state.challenge.map(|challenge| challenge.to_vec()))
        .bind(&state.carried_methods)
        .bind(state.demanded.map(Assurance::as_str))
        .bind(state.raised_session.map(|session| session.as_uuid()))
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: TransactionId,
    ) -> Result<Option<AuthTransaction>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<PgRow> = sqlx::query(
            "SELECT id, flow_name, flow_version, current_step, identified, candidate_user_id,
                    identifier_key, satisfied_methods, challenge, rejections, status, started_at,
                    expires_at, client_address, client_description, binding, version,
                    carried_methods, demanded_assurance, raised_session_id
             FROM authentication.transaction
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.as_ref().map(to_transaction).transpose()
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        transaction: &AuthTransaction,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = transaction.snapshot();
        let connection = connection(uow)?;
        let updated = sqlx::query(
            "UPDATE authentication.transaction
             SET current_step = $3, identified = $4, candidate_user_id = $5, identifier_key = $6,
                 satisfied_methods = $7, rejections = $8, status = $9, challenge = $11,
                 version = version + 1
             WHERE tenant_id = $1 AND id = $2 AND version = $10",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(i32::try_from(state.current_step).map_err(|_| corrupted("step out of range"))?)
        .bind(state.identified)
        .bind(state.candidate.map(|user| user.as_uuid()))
        .bind(state.identifier_key.map(|key| key.to_vec()))
        .bind(&state.satisfied_methods)
        .bind(stored(state.rejections)?)
        .bind(state.status.as_str())
        .bind(stored(state.version)?)
        .bind(state.challenge.map(|challenge| challenge.to_vec()))
        .execute(&mut *connection)
        .await
        .map_err(|e| database_error(&e))?
        .rows_affected();
        if updated == 1 {
            return Ok(());
        }
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT FROM authentication.transaction WHERE tenant_id = $1 AND id = $2)",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .fetch_one(&mut *connection)
        .await
        .map_err(|e| database_error(&e))?;
        Err(if exists {
            DomainError::conflict(
                "authentication.transaction_modified_concurrently",
                "this sign-in was advanced by another request",
            )
        } else {
            DomainError::not_found(
                "authentication.transaction_not_found",
                "this sign-in does not exist; start again",
            )
        })
    }
}

/// [`VerificationTokenStore`] on `authentication.verification_token`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgVerificationTokenStore;

const TOKEN_COLUMNS: &str = "id, purpose, token_hash, email, user_id, locale, created_at, \
                             expires_at, used_at, replaced_at";

type TokenRow = (
    Uuid,
    String,
    Vec<u8>,
    String,
    Option<Uuid>,
    String,
    Timestamp,
    Timestamp,
    Option<Timestamp>,
    Option<Timestamp>,
);

fn to_token(row: TokenRow) -> Result<VerificationToken, DomainError> {
    let (
        id,
        purpose,
        token_hash,
        email,
        user_id,
        locale,
        created_at,
        expires_at,
        used_at,
        replaced_at,
    ) = row;
    let hash: [u8; 32] = token_hash
        .try_into()
        .map_err(|_| corrupted("token hash is not 32 bytes"))?;
    Ok(VerificationToken::from_snapshot(
        VerificationTokenSnapshot {
            id: VerificationTokenId::from_uuid(id),
            purpose: TokenPurpose::from_stored(&purpose)
                .map_err(|_| corrupted("unknown token purpose"))?,
            token_hash: VerificationTokenHash::from_stored(hash),
            email,
            user_id: user_id.map(UserId::from_uuid),
            locale,
            created_at,
            expires_at,
            used_at,
            replaced_at,
        },
    ))
}

#[async_trait::async_trait]
impl VerificationTokenStore for PgVerificationTokenStore {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        token: &VerificationToken,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = token.snapshot();
        sqlx::query(
            "INSERT INTO authentication.verification_token
                 (tenant_id, id, purpose, token_hash, email, user_id, locale, created_at,
                  expires_at, used_at, replaced_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.purpose.as_str())
        .bind(state.token_hash.as_bytes().as_slice())
        .bind(&state.email)
        .bind(state.user_id.map(|user| user.as_uuid()))
        .bind(&state.locale)
        .bind(state.created_at)
        .bind(state.expires_at)
        .bind(state.used_at)
        .bind(state.replaced_at)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn replace_earlier(
        &self,
        uow: &mut dyn UnitOfWork,
        purpose: TokenPurpose,
        email: &str,
        now: Timestamp,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "UPDATE authentication.verification_token
             SET replaced_at = $4
             WHERE tenant_id = $1 AND purpose = $2 AND email = $3
               AND used_at IS NULL AND replaced_at IS NULL",
        )
        .bind(tenant.as_uuid())
        .bind(purpose.as_str())
        .bind(email)
        .bind(now)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &VerificationTokenHash,
        purpose: TokenPurpose,
    ) -> Result<Option<VerificationToken>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<TokenRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {TOKEN_COLUMNS} FROM authentication.verification_token
             WHERE tenant_id = $1 AND token_hash = $2 AND purpose = $3"
        )))
        .bind(tenant.as_uuid())
        .bind(hash.as_bytes().as_slice())
        .bind(purpose.as_str())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.map(to_token).transpose()
    }

    async fn use_up(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &VerificationTokenHash,
        purpose: TokenPurpose,
        now: Timestamp,
    ) -> Result<Option<VerificationToken>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        // One statement checks that the token is good and marks it used.
        // Of several transactions doing this at once, the first locks the
        // row; the others wait, then see `used_at` set and change nothing.
        let row: Option<TokenRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "UPDATE authentication.verification_token
             SET used_at = $4
             WHERE tenant_id = $1 AND token_hash = $2 AND purpose = $3
               AND used_at IS NULL AND replaced_at IS NULL AND expires_at > $4
             RETURNING {TOKEN_COLUMNS}"
        )))
        .bind(tenant.as_uuid())
        .bind(hash.as_bytes().as_slice())
        .bind(purpose.as_str())
        .bind(now)
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.map(to_token).transpose()
    }
}
