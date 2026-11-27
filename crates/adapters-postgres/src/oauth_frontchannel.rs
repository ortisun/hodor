//! PostgreSQL storage for front-channel logout: the frames kept for the
//! signed-out page of one sign-out, found by the hash of their handle.
//!
//! See `docs/architecture/contexts/oauth.md`, "Front-channel logout".

use crate::uow::{connection, database_error};
use hodor_kernel::{DomainError, Timestamp, UnitOfWork};
use hodor_oauth::api::{
    FrontChannelLogout, FrontChannelLogoutId, FrontChannelLogoutStore, HandleHash,
};
use hodor_session::api::SessionId;
use sqlx::types::Uuid;

/// [`FrontChannelLogoutStore`] on `oauth.frontchannel_logout`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgFrontChannelLogoutStore;

fn corrupted(what: &str) -> DomainError {
    DomainError::internal(
        "oauth.stored_data_invalid",
        "stored OAuth data could not be read",
    )
    .with_detail(what.to_owned())
}

type FramesRow = (Uuid, Vec<u8>, Uuid, Vec<String>, Timestamp, Timestamp);

#[async_trait::async_trait]
impl FrontChannelLogoutStore for PgFrontChannelLogoutStore {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        kept: &FrontChannelLogout,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "INSERT INTO oauth.frontchannel_logout
                 (tenant_id, id, handle_hash, session_id, frames, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(tenant.as_uuid())
        .bind(kept.id.as_uuid())
        .bind(kept.handle_hash.as_bytes().as_slice())
        .bind(kept.session_id.as_uuid())
        .bind(&kept.frames)
        .bind(kept.created_at)
        .bind(kept.expires_at)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(())
    }

    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &HandleHash,
    ) -> Result<Option<FrontChannelLogout>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<FramesRow> = sqlx::query_as(
            "SELECT id, handle_hash, session_id, frames, created_at, expires_at
             FROM oauth.frontchannel_logout
             WHERE tenant_id = $1 AND handle_hash = $2",
        )
        .bind(tenant.as_uuid())
        .bind(hash.as_bytes().as_slice())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.map(
            |(id, handle_hash, session_id, frames, created_at, expires_at)| {
                Ok(FrontChannelLogout {
                    id: FrontChannelLogoutId::from_uuid(id),
                    handle_hash: HandleHash::from_stored(
                        handle_hash
                            .try_into()
                            .map_err(|_| corrupted("a handle hash that is not 32 bytes"))?,
                    ),
                    session_id: SessionId::from_uuid(session_id),
                    frames,
                    created_at,
                    expires_at,
                })
            },
        )
        .transpose()
    }
}
