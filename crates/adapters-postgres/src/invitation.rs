//! PostgreSQL storage for invitations to organizations.
//!
//! See `docs/architecture/contexts/identity.md`, "Invitations".

use crate::uow::{connection, database_error};
use hodor_identity::api::{
    Invitation, InvitationId, InvitationRepository, InvitationStatus, UnitId,
};
use hodor_kernel::{DomainError, OrganizationId, Timestamp, UnitOfWork, UserId};
use sqlx::types::Uuid;

/// [`InvitationRepository`] on `identity.organization_invitation`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgInvitationRepository;

type InvitationRow = (
    Uuid,
    Uuid,
    String,
    Vec<Uuid>,
    Vec<u8>,
    String,
    Timestamp,
    Timestamp,
    Option<Uuid>,
    Option<Timestamp>,
    Option<Timestamp>,
);

const COLUMNS: &str = "id, organization_id, email, unit_ids, token_hash, status, created_at, \
                       expires_at, accepted_by, accepted_at, withdrawn_at";

fn invitation_from(row: InvitationRow) -> Result<Invitation, DomainError> {
    let (
        id,
        organization,
        email,
        units,
        hash,
        status,
        created_at,
        expires_at,
        by,
        accepted_at,
        withdrawn_at,
    ) = row;
    let stored = || {
        DomainError::internal(
            "identity.stored_data_invalid",
            "the invitation could not be loaded",
        )
    };
    Ok(Invitation {
        id: InvitationId::from_uuid(id),
        organization: OrganizationId::from_uuid(organization),
        email,
        units: units.into_iter().map(UnitId::from_uuid).collect(),
        token_hash: hash.try_into().map_err(|_| stored())?,
        status: InvitationStatus::from_stored(&status)?,
        created_at,
        expires_at,
        accepted: by.map(UserId::from_uuid).zip(accepted_at),
        withdrawn_at,
    })
}

#[async_trait::async_trait]
impl InvitationRepository for PgInvitationRepository {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        invitation: &Invitation,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let units: Vec<Uuid> = invitation.units.iter().map(|unit| unit.as_uuid()).collect();
        sqlx::query(
            "INSERT INTO identity.organization_invitation
                 (tenant_id, id, organization_id, email, unit_ids, token_hash, status, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(tenant.as_uuid())
        .bind(invitation.id.as_uuid())
        .bind(invitation.organization.as_uuid())
        .bind(&invitation.email)
        .bind(&units)
        .bind(&invitation.token_hash[..])
        .bind(invitation.status.as_str())
        .bind(invitation.created_at)
        .bind(invitation.expires_at)
        .execute(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        Ok(())
    }

    async fn withdraw_pending(
        &self,
        uow: &mut dyn UnitOfWork,
        organization: OrganizationId,
        email: &str,
        now: Timestamp,
    ) -> Result<Option<InvitationId>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<(Uuid,)> = sqlx::query_as(
            "UPDATE identity.organization_invitation
             SET status = 'withdrawn', withdrawn_at = $4
             WHERE tenant_id = $1 AND organization_id = $2 AND email = $3 AND status = 'pending'
             RETURNING id",
        )
        .bind(tenant.as_uuid())
        .bind(organization.as_uuid())
        .bind(email)
        .bind(now)
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        Ok(row.map(|(id,)| InvitationId::from_uuid(id)))
    }

    async fn withdraw(
        &self,
        uow: &mut dyn UnitOfWork,
        organization: OrganizationId,
        id: InvitationId,
        now: Timestamp,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let changed = sqlx::query(
            "UPDATE identity.organization_invitation
             SET status = 'withdrawn', withdrawn_at = $4
             WHERE tenant_id = $1 AND organization_id = $2 AND id = $3 AND status = 'pending'",
        )
        .bind(tenant.as_uuid())
        .bind(organization.as_uuid())
        .bind(id.as_uuid())
        .bind(now)
        .execute(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?
        .rows_affected();
        Ok(changed == 1)
    }

    async fn find_by_hash(
        &self,
        uow: &mut dyn UnitOfWork,
        token_hash: &[u8; 32],
    ) -> Result<Option<Invitation>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let row: Option<InvitationRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM identity.organization_invitation
             WHERE tenant_id = $1 AND token_hash = $2"
        )))
        .bind(tenant.as_uuid())
        .bind(&token_hash[..])
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        row.map(invitation_from).transpose()
    }

    async fn use_up(
        &self,
        uow: &mut dyn UnitOfWork,
        id: InvitationId,
        user: UserId,
        now: Timestamp,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        // One conditional statement: of requests at the same moment, the
        // first to change the row wins and the others find it accepted.
        let changed = sqlx::query(
            "UPDATE identity.organization_invitation
             SET status = 'accepted', accepted_by = $3, accepted_at = $4
             WHERE tenant_id = $1 AND id = $2 AND status = 'pending' AND expires_at > $4",
        )
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .bind(user.as_uuid())
        .bind(now)
        .execute(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?
        .rows_affected();
        Ok(changed == 1)
    }

    async fn pending(
        &self,
        uow: &mut dyn UnitOfWork,
        organization: OrganizationId,
    ) -> Result<Vec<Invitation>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let rows: Vec<InvitationRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM identity.organization_invitation
             WHERE tenant_id = $1 AND organization_id = $2 AND status = 'pending'
             ORDER BY id DESC"
        )))
        .bind(tenant.as_uuid())
        .bind(organization.as_uuid())
        .fetch_all(connection(uow)?)
        .await
        .map_err(|error| database_error(&error))?;
        rows.into_iter().map(invitation_from).collect()
    }
}
