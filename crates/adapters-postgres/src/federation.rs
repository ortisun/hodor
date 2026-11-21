//! PostgreSQL storage for the federation context.
//!
//! See `docs/architecture/contexts/federation.md`, "Storage".

use crate::uow::{connection, database_error};
use hodor_federation::api::{
    Alias, ExternalIdentity, IdentityProvider, LinkStore, ProviderId, ProviderKind,
    ProviderSettings, ProviderSnapshot, ProviderStatus, ProviderStore, Subject,
};
use hodor_kernel::{DomainError, SealedSecret, Timestamp, UnitOfWork, UserId};
use sqlx::Row as _;
use sqlx::postgres::PgRow;

const ALIAS_CONSTRAINT: &str = "identity_provider_alias_unique";
const PROVIDER_CONSTRAINT: &str = "external_identity_provider_fk";

fn corrupted(what: &str) -> DomainError {
    DomainError::internal(
        "federation.stored_data_invalid",
        "a stored identity provider could not be read",
    )
    .with_detail(what.to_owned())
}

fn provider_from(row: &PgRow) -> Result<IdentityProvider, DomainError> {
    let get = |error: sqlx::Error| database_error(&error);
    let alias: String = row.try_get("alias").map_err(get)?;
    let kind: String = row.try_get("kind").map_err(get)?;
    let status: String = row.try_get("status").map_err(get)?;
    let version: i32 = row.try_get("version").map_err(get)?;
    Ok(IdentityProvider::from_snapshot(ProviderSnapshot {
        id: ProviderId::from_uuid(row.try_get("id").map_err(get)?),
        alias: Alias::parse(&alias).map_err(|_| corrupted("alias"))?,
        kind: ProviderKind::from_stored(&kind)?,
        settings: ProviderSettings {
            display_name: row.try_get("display_name").map_err(get)?,
            issuer: row.try_get("issuer").map_err(get)?,
            client_id: row.try_get("client_id").map_err(get)?,
            scopes: row.try_get("scopes").map_err(get)?,
            creates_users: row.try_get("creates_users").map_err(get)?,
        },
        client_secret: SealedSecret::from_stored(row.try_get("client_secret").map_err(get)?),
        status: ProviderStatus::from_stored(&status)?,
        created_at: row.try_get("created_at").map_err(get)?,
        updated_at: row.try_get("updated_at").map_err(get)?,
        version: u32::try_from(version).map_err(|_| corrupted("negative version"))?,
    }))
}

fn link_from(row: &PgRow) -> Result<ExternalIdentity, DomainError> {
    let get = |error: sqlx::Error| database_error(&error);
    let subject: String = row.try_get("subject").map_err(get)?;
    Ok(ExternalIdentity {
        provider_id: ProviderId::from_uuid(row.try_get("provider_id").map_err(get)?),
        subject: Subject::parse(&subject).map_err(|_| corrupted("subject"))?,
        user_id: UserId::from_uuid(row.try_get("user_id").map_err(get)?),
        linked_at: row.try_get("linked_at").map_err(get)?,
        last_used_at: row.try_get("last_used_at").map_err(get)?,
    })
}

/// [`ProviderStore`] on `federation.identity_provider`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgProviderStore;

#[async_trait::async_trait]
impl ProviderStore for PgProviderStore {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        provider: &IdentityProvider,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = provider.snapshot();
        let inserted = sqlx::query(
            "INSERT INTO federation.identity_provider
                 (tenant_id, id, alias, kind, display_name, issuer, client_id, client_secret,
                  scopes, creates_users, status, created_at, updated_at, version)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 0)",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.alias.as_str())
        .bind(state.kind.as_str())
        .bind(&state.settings.display_name)
        .bind(&state.settings.issuer)
        .bind(&state.settings.client_id)
        .bind(state.client_secret.as_bytes())
        .bind(&state.settings.scopes)
        .bind(state.settings.creates_users)
        .bind(state.status.as_str())
        .bind(state.created_at)
        .bind(state.updated_at)
        .execute(connection(uow)?)
        .await;
        match inserted {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(error)) if error.constraint() == Some(ALIAS_CONSTRAINT) => {
                Err(DomainError::conflict(
                    "federation.alias_taken",
                    "this tenant already has an identity provider with this alias",
                ))
            }
            Err(error) => Err(database_error(&error)),
        }
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        provider: &IdentityProvider,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = provider.snapshot();
        let version =
            i32::try_from(state.version).map_err(|_| corrupted("version out of range"))?;
        // The alias and the kind never change, so they are not written.
        let updated = sqlx::query(
            "UPDATE federation.identity_provider
             SET display_name = $3, issuer = $4, client_id = $5, client_secret = $6,
                 scopes = $7, creates_users = $8, status = $9, updated_at = $10,
                 version = version + 1
             WHERE tenant_id = $1 AND id = $2 AND version = $11",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(&state.settings.display_name)
        .bind(&state.settings.issuer)
        .bind(&state.settings.client_id)
        .bind(state.client_secret.as_bytes())
        .bind(&state.settings.scopes)
        .bind(state.settings.creates_users)
        .bind(state.status.as_str())
        .bind(state.updated_at)
        .bind(version)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        if updated.rows_affected() == 1 {
            Ok(())
        } else {
            Err(DomainError::conflict(
                "federation.provider_modified_concurrently",
                "the identity provider was changed by someone else; read it again",
            ))
        }
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: ProviderId,
    ) -> Result<Option<IdentityProvider>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "SELECT id, alias, kind, display_name, issuer, client_id, client_secret,
                    scopes, creates_users, status, created_at, updated_at, version
             FROM federation.identity_provider
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?
        .as_ref()
        .map(provider_from)
        .transpose()
    }

    async fn find_by_alias(
        &self,
        uow: &mut dyn UnitOfWork,
        alias: &Alias,
    ) -> Result<Option<IdentityProvider>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "SELECT id, alias, kind, display_name, issuer, client_id, client_secret,
                    scopes, creates_users, status, created_at, updated_at, version
             FROM federation.identity_provider
             WHERE tenant_id = $1 AND alias = $2",
        )
        .bind(tenant.as_uuid())
        .bind(alias.as_str())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?
        .as_ref()
        .map(provider_from)
        .transpose()
    }

    async fn list(&self, uow: &mut dyn UnitOfWork) -> Result<Vec<IdentityProvider>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "SELECT id, alias, kind, display_name, issuer, client_id, client_secret,
                    scopes, creates_users, status, created_at, updated_at, version
             FROM federation.identity_provider
             WHERE tenant_id = $1 ORDER BY alias COLLATE \"C\"",
        )
        .bind(tenant.as_uuid())
        .fetch_all(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?
        .iter()
        .map(provider_from)
        .collect()
    }
}

/// [`LinkStore`] on `federation.external_identity`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgLinkStore;

#[async_trait::async_trait]
impl LinkStore for PgLinkStore {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        link: &ExternalIdentity,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        // Row-level security hides other tenants' providers from the
        // foreign key check too, so a provider of another tenant is
        // refused here like one that does not exist.
        let inserted = sqlx::query(
            "INSERT INTO federation.external_identity
                 (tenant_id, provider_id, subject, user_id, linked_at, last_used_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (tenant_id, provider_id, subject) DO NOTHING",
        )
        .bind(tenant.as_uuid())
        .bind(link.provider_id.as_uuid())
        .bind(link.subject.expose())
        .bind(link.user_id.as_uuid())
        .bind(link.linked_at)
        .bind(link.last_used_at)
        .execute(connection(uow)?)
        .await;
        match inserted {
            Ok(done) => Ok(done.rows_affected() == 1),
            Err(sqlx::Error::Database(error))
                if error.constraint() == Some(PROVIDER_CONSTRAINT) =>
            {
                Err(DomainError::not_found(
                    "federation.provider_not_found",
                    "there is no such identity provider",
                ))
            }
            Err(error) => Err(database_error(&error)),
        }
    }

    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        provider_id: ProviderId,
        subject: &Subject,
    ) -> Result<Option<ExternalIdentity>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "SELECT provider_id, subject, user_id, linked_at, last_used_at
             FROM federation.external_identity
             WHERE tenant_id = $1 AND provider_id = $2 AND subject = $3",
        )
        .bind(tenant.as_uuid())
        .bind(provider_id.as_uuid())
        .bind(subject.expose())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?
        .as_ref()
        .map(link_from)
        .transpose()
    }

    async fn mark_used(
        &self,
        uow: &mut dyn UnitOfWork,
        provider_id: ProviderId,
        subject: &Subject,
        now: Timestamp,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let updated = sqlx::query(
            "UPDATE federation.external_identity SET last_used_at = $4
             WHERE tenant_id = $1 AND provider_id = $2 AND subject = $3",
        )
        .bind(tenant.as_uuid())
        .bind(provider_id.as_uuid())
        .bind(subject.expose())
        .bind(now)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(updated.rows_affected() == 1)
    }

    async fn list_for_user(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
    ) -> Result<Vec<ExternalIdentity>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        sqlx::query(
            "SELECT provider_id, subject, user_id, linked_at, last_used_at
             FROM federation.external_identity
             WHERE tenant_id = $1 AND user_id = $2
             ORDER BY linked_at, provider_id, subject",
        )
        .bind(tenant.as_uuid())
        .bind(user_id.as_uuid())
        .fetch_all(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?
        .iter()
        .map(link_from)
        .collect()
    }

    async fn remove(
        &self,
        uow: &mut dyn UnitOfWork,
        provider_id: ProviderId,
        subject: &Subject,
    ) -> Result<Option<UserId>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let removed: Option<sqlx::types::Uuid> = sqlx::query_scalar(
            "DELETE FROM federation.external_identity
             WHERE tenant_id = $1 AND provider_id = $2 AND subject = $3
             RETURNING user_id",
        )
        .bind(tenant.as_uuid())
        .bind(provider_id.as_uuid())
        .bind(subject.expose())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(removed.map(UserId::from_uuid))
    }
}
