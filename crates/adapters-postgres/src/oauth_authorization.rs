//! PostgreSQL storage for the authorization endpoint: pending requests,
//! grants and authorization codes.
//!
//! See `docs/architecture/contexts/oauth.md`, "Authorization endpoint".

use crate::uow::{connection, database_error};
use hodor_kernel::{DomainError, Timestamp, UnitOfWork, UserId};
use hodor_oauth::api::{
    AuthorizationCode, AuthorizationCodeStore, AuthorizationRequest, AuthorizationRequestStore,
    ClientId, CodeHash, ConsentAnswer, ConsentWait, Grant, GrantId, GrantStatus, GrantStore,
    PendingAuthorization, PendingAuthorizationId,
};
use hodor_session::api::SessionId;
use sqlx::Row as _;
use sqlx::postgres::PgRow;
use sqlx::types::{Json, Uuid};

const REQUEST_CLIENT_CONSTRAINT: &str = "authorization_request_client_fk";
const GRANT_CLIENT_CONSTRAINT: &str = "authorization_grant_client_fk";
const CODE_GRANT_CONSTRAINT: &str = "authorization_code_grant_fk";

fn corrupted(what: &str) -> DomainError {
    DomainError::internal(
        "oauth.stored_data_invalid",
        "stored OAuth data could not be read",
    )
    .with_detail(what.to_owned())
}

fn get(error: sqlx::Error) -> DomainError {
    database_error(&error)
}

fn client_not_found() -> DomainError {
    DomainError::not_found("oauth.client_not_found", "there is no such client")
}

fn grant_not_found() -> DomainError {
    DomainError::not_found("oauth.grant_not_found", "there is no such grant")
}

fn hash_of(row: &PgRow, column: &str) -> Result<[u8; 32], DomainError> {
    let bytes: Vec<u8> = row.try_get(column).map_err(get)?;
    bytes
        .try_into()
        .map_err(|_| corrupted("a hash is not 32 bytes"))
}

/// Maps a violated reference to its error, and anything else to a
/// failure of storage.
fn refused(error: sqlx::Error, constraint: &str, missing: fn() -> DomainError) -> DomainError {
    match &error {
        sqlx::Error::Database(database) if database.constraint() == Some(constraint) => missing(),
        _ => database_error(&error),
    }
}

/// [`AuthorizationRequestStore`] on `oauth.authorization_request`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgAuthorizationRequestStore;

#[async_trait::async_trait]
impl AuthorizationRequestStore for PgAuthorizationRequestStore {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        pending: &PendingAuthorization,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "INSERT INTO oauth.authorization_request
                 (tenant_id, id, secret_hash, client_id, request, received_at, expires_at,
                  consent_user_id, consent_session_id, consent_answer)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(tenant.as_uuid())
        .bind(pending.id.as_uuid())
        .bind(pending.secret_hash.as_slice())
        .bind(pending.request.client_id.as_uuid())
        .bind(Json(&pending.request))
        .bind(pending.received_at)
        .bind(pending.expires_at)
        .bind(pending.consent.map(|wait| wait.user_id.as_uuid()))
        .bind(pending.consent.map(|wait| wait.session_id.as_uuid()))
        .bind(
            pending
                .consent
                .and_then(|wait| wait.answer)
                .map(ConsentAnswer::as_str),
        )
        .execute(connection(uow)?)
        .await
        .map_err(|e| refused(e, REQUEST_CLIENT_CONSTRAINT, client_not_found))?;
        Ok(())
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: PendingAuthorizationId,
    ) -> Result<Option<PendingAuthorization>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row = sqlx::query(
            "SELECT id, secret_hash, request, received_at, expires_at, consent_user_id,
                    consent_session_id, consent_answer
             FROM oauth.authorization_request
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(get)?;
        row.map(|row| {
            let Json(request): Json<AuthorizationRequest> = row.try_get("request").map_err(get)?;
            let user: Option<Uuid> = row.try_get("consent_user_id").map_err(get)?;
            let session: Option<Uuid> = row.try_get("consent_session_id").map_err(get)?;
            let answer: Option<String> = row.try_get("consent_answer").map_err(get)?;
            let consent = match (user, session) {
                (Some(user), Some(session)) => Some(ConsentWait {
                    user_id: UserId::from_uuid(user),
                    session_id: SessionId::from_uuid(session),
                    answer: answer
                        .as_deref()
                        .map(ConsentAnswer::from_stored)
                        .transpose()?,
                }),
                _ => None,
            };
            Ok(PendingAuthorization {
                id: PendingAuthorizationId::from_uuid(row.try_get("id").map_err(get)?),
                secret_hash: hash_of(&row, "secret_hash")?,
                request,
                received_at: row.try_get("received_at").map_err(get)?,
                expires_at: row.try_get("expires_at").map_err(get)?,
                consent,
            })
        })
        .transpose()
    }

    async fn remove(
        &self,
        uow: &mut dyn UnitOfWork,
        id: PendingAuthorizationId,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let removed =
            sqlx::query("DELETE FROM oauth.authorization_request WHERE tenant_id = $1 AND id = $2")
                .bind(tenant.as_uuid())
                .bind(id.as_uuid())
                .execute(connection(uow)?)
                .await
                .map_err(get)?;
        Ok(removed.rows_affected() == 1)
    }

    async fn answer(
        &self,
        uow: &mut dyn UnitOfWork,
        id: PendingAuthorizationId,
        answer: ConsentAnswer,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let answered = sqlx::query(
            "UPDATE oauth.authorization_request SET consent_answer = $3
             WHERE tenant_id = $1 AND id = $2
               AND consent_user_id IS NOT NULL AND consent_answer IS NULL",
        )
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .bind(answer.as_str())
        .execute(connection(uow)?)
        .await
        .map_err(get)?;
        Ok(answered.rows_affected() == 1)
    }
}

/// [`GrantStore`] on `oauth.authorization_grant`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgGrantStore;

fn grant_from(row: &PgRow) -> Result<Grant, DomainError> {
    let status: String = row.try_get("status").map_err(get)?;
    Ok(Grant {
        id: GrantId::from_uuid(row.try_get("id").map_err(get)?),
        client_id: ClientId::from_uuid(row.try_get("client_id").map_err(get)?),
        user_id: UserId::from_uuid(row.try_get("user_id").map_err(get)?),
        session_id: SessionId::from_uuid(row.try_get("session_id").map_err(get)?),
        scopes: row.try_get("scopes").map_err(get)?,
        audiences: row.try_get("audiences").map_err(get)?,
        status: GrantStatus::from_stored(&status)?,
        created_at: row.try_get("created_at").map_err(get)?,
        revoked_at: row.try_get("revoked_at").map_err(get)?,
        revocation_reason: row.try_get("revocation_reason").map_err(get)?,
    })
}

#[async_trait::async_trait]
impl GrantStore for PgGrantStore {
    async fn insert(&self, uow: &mut dyn UnitOfWork, grant: &Grant) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "INSERT INTO oauth.authorization_grant
                 (tenant_id, id, client_id, user_id, session_id, scopes, audiences, status,
                  created_at, revoked_at, revocation_reason)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(tenant.as_uuid())
        .bind(grant.id.as_uuid())
        .bind(grant.client_id.as_uuid())
        .bind(grant.user_id.as_uuid())
        .bind(grant.session_id.as_uuid())
        .bind(&grant.scopes)
        .bind(&grant.audiences)
        .bind(grant.status.as_str())
        .bind(grant.created_at)
        .bind(grant.revoked_at)
        .bind(grant.revocation_reason.as_deref())
        .execute(connection(uow)?)
        .await
        .map_err(|e| refused(e, GRANT_CLIENT_CONSTRAINT, client_not_found))?;
        Ok(())
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: GrantId,
    ) -> Result<Option<Grant>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "SELECT id, client_id, user_id, session_id, scopes, audiences, status, created_at,
                    revoked_at, revocation_reason
             FROM oauth.authorization_grant
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(get)?
        .as_ref()
        .map(grant_from)
        .transpose()
    }

    async fn update(&self, uow: &mut dyn UnitOfWork, grant: &Grant) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let updated = sqlx::query(
            "UPDATE oauth.authorization_grant
             SET status = $3, revoked_at = $4, revocation_reason = $5
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(grant.id.as_uuid())
        .bind(grant.status.as_str())
        .bind(grant.revoked_at)
        .bind(grant.revocation_reason.as_deref())
        .execute(connection(uow)?)
        .await
        .map_err(get)?;
        if updated.rows_affected() == 1 {
            Ok(())
        } else {
            Err(grant_not_found())
        }
    }

    async fn list_active_for(
        &self,
        uow: &mut dyn UnitOfWork,
        user: UserId,
        client: ClientId,
    ) -> Result<Vec<Grant>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "SELECT id, client_id, user_id, session_id, scopes, audiences, status, created_at,
                    revoked_at, revocation_reason
             FROM oauth.authorization_grant
             WHERE tenant_id = $1 AND user_id = $2 AND client_id = $3 AND status = 'active'
             ORDER BY created_at, id",
        )
        .bind(tenant.as_uuid())
        .bind(user.as_uuid())
        .bind(client.as_uuid())
        .fetch_all(connection(uow)?)
        .await
        .map_err(get)?
        .iter()
        .map(grant_from)
        .collect()
    }
}

/// [`AuthorizationCodeStore`] on `oauth.authorization_code`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgAuthorizationCodeStore;

fn code_from(row: &PgRow) -> Result<AuthorizationCode, DomainError> {
    let session: Uuid = row.try_get("session_id").map_err(get)?;
    Ok(AuthorizationCode {
        hash: CodeHash::from_stored(hash_of(row, "code_hash")?),
        grant_id: GrantId::from_uuid(row.try_get("grant_id").map_err(get)?),
        client_id: ClientId::from_uuid(row.try_get("client_id").map_err(get)?),
        redirect_uri: row.try_get("redirect_uri").map_err(get)?,
        scopes: row.try_get("scopes").map_err(get)?,
        audiences: row.try_get("audiences").map_err(get)?,
        code_challenge: row.try_get("code_challenge").map_err(get)?,
        nonce: row.try_get("nonce").map_err(get)?,
        session_id: SessionId::from_uuid(session),
        user_id: UserId::from_uuid(row.try_get("user_id").map_err(get)?),
        signed_in_at: row.try_get("signed_in_at").map_err(get)?,
        methods: row.try_get("methods").map_err(get)?,
        acr: row.try_get("acr").map_err(get)?,
        issued_at: row.try_get("issued_at").map_err(get)?,
        expires_at: row.try_get("expires_at").map_err(get)?,
        redeemed_at: row.try_get("redeemed_at").map_err(get)?,
    })
}

#[async_trait::async_trait]
impl AuthorizationCodeStore for PgAuthorizationCodeStore {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        code: &AuthorizationCode,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "INSERT INTO oauth.authorization_code
                 (tenant_id, code_hash, grant_id, client_id, redirect_uri, scopes, audiences,
                  code_challenge, nonce, session_id, user_id, signed_in_at, methods, issued_at,
                  expires_at, redeemed_at, acr)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)",
        )
        .bind(tenant.as_uuid())
        .bind(code.hash.as_bytes().as_slice())
        .bind(code.grant_id.as_uuid())
        .bind(code.client_id.as_uuid())
        .bind(&code.redirect_uri)
        .bind(&code.scopes)
        .bind(&code.audiences)
        .bind(code.code_challenge.as_deref())
        .bind(code.nonce.as_deref())
        .bind(code.session_id.as_uuid())
        .bind(code.user_id.as_uuid())
        .bind(code.signed_in_at)
        .bind(&code.methods)
        .bind(code.issued_at)
        .bind(code.expires_at)
        .bind(code.redeemed_at)
        .bind(code.acr.as_deref())
        .execute(connection(uow)?)
        .await
        .map_err(|e| refused(e, CODE_GRANT_CONSTRAINT, grant_not_found))?;
        Ok(())
    }

    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &CodeHash,
    ) -> Result<Option<AuthorizationCode>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "SELECT code_hash, grant_id, client_id, redirect_uri, scopes, audiences,
                    code_challenge, nonce, session_id, user_id, signed_in_at, methods,
                    issued_at, expires_at, redeemed_at, acr
             FROM oauth.authorization_code
             WHERE tenant_id = $1 AND code_hash = $2",
        )
        .bind(tenant.as_uuid())
        .bind(hash.as_bytes().as_slice())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(get)?
        .as_ref()
        .map(code_from)
        .transpose()
    }

    async fn redeem(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &CodeHash,
        at: Timestamp,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let updated = sqlx::query(
            "UPDATE oauth.authorization_code SET redeemed_at = $3
             WHERE tenant_id = $1 AND code_hash = $2 AND redeemed_at IS NULL",
        )
        .bind(tenant.as_uuid())
        .bind(hash.as_bytes().as_slice())
        .bind(at)
        .execute(connection(uow)?)
        .await
        .map_err(get)?;
        Ok(updated.rows_affected() == 1)
    }
}
