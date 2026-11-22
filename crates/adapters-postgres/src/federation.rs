//! PostgreSQL storage for the federation context.
//!
//! See `docs/architecture/contexts/federation.md`, "Storage".

use crate::uow::{connection, database_error};
use hodor_authentication::api::TransactionId;
use hodor_federation::api::{
    Alias, DirectorySettings, ExternalIdentity, IdentityProvider, LinkStore, PendingAuthorization,
    PendingAuthorizationStore, ProviderId, ProviderKind, ProviderSettings, ProviderSnapshot,
    ProviderStatus, ProviderStore, SamlAnswer, SamlSettings, Subject,
};
use hodor_kernel::{DomainError, SealedSecret, Timestamp, UnitOfWork, UserId};
use sqlx::Row as _;
use sqlx::postgres::PgRow;

const ALIAS_CONSTRAINT: &str = "identity_provider_alias_unique";
const PROVIDER_CONSTRAINT: &str = "external_identity_provider_fk";
const PENDING_PROVIDER_CONSTRAINT: &str = "pending_authorization_provider_fk";

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
            trusts_email: row.try_get("trusts_email").map_err(get)?,
            directory: match row
                .try_get::<Option<String>, _>("directory_base")
                .map_err(get)?
            {
                Some(base) => Some(DirectorySettings {
                    base,
                    filter: row.try_get("directory_filter").map_err(get)?,
                    subject_attribute: row.try_get("directory_subject_attribute").map_err(get)?,
                    email_attribute: row.try_get("directory_email_attribute").map_err(get)?,
                    name_attribute: row.try_get("directory_name_attribute").map_err(get)?,
                }),
                None => None,
            },
            saml: match row
                .try_get::<Option<String>, _>("saml_single_sign_on_address")
                .map_err(get)?
            {
                Some(single_sign_on_address) => Some(SamlSettings {
                    single_sign_on_address,
                    certificate: row.try_get("saml_certificate").map_err(get)?,
                    email_attribute: row.try_get("saml_email_attribute").map_err(get)?,
                    name_attribute: row.try_get("saml_name_attribute").map_err(get)?,
                }),
                None => None,
            },
        },
        client_secret: SealedSecret::from_stored(row.try_get("client_secret").map_err(get)?),
        status: ProviderStatus::from_stored(&status)?,
        created_at: row.try_get("created_at").map_err(get)?,
        updated_at: row.try_get("updated_at").map_err(get)?,
        version: u32::try_from(version).map_err(|_| corrupted("negative version"))?,
    }))
}

/// One part of a provider's SAML settings, for a column that is empty for
/// every other kind.
fn saml_part(state: &ProviderSnapshot, part: fn(&SamlSettings) -> &String) -> Option<String> {
    state.settings.saml.as_ref().map(|saml| part(saml).clone())
}

/// A pending authorization as it is stored.
fn pending_from(row: &PgRow) -> Result<PendingAuthorization, DomainError> {
    let get = |error: sqlx::Error| database_error(&error);
    let state_hash: Vec<u8> = row.try_get("state_hash").map_err(get)?;
    let subject: Option<String> = row.try_get("saml_subject").map_err(get)?;
    let refusal: Option<String> = row.try_get("saml_refusal").map_err(get)?;
    let saml_answer = match (subject, refusal) {
        (None, None) => None,
        (Some(subject), None) => Some(SamlAnswer::Verified {
            subject: Subject::parse(&subject).map_err(|_| corrupted("SAML subject"))?,
            email: row.try_get("saml_email").map_err(get)?,
            name: row.try_get("saml_name").map_err(get)?,
        }),
        // A name this version does not know is still a refusal: refusing is
        // what fails safe, and an error would stop the sign-in from being
        // taken at all.
        (None, Some(refusal)) => Some(SamlAnswer::Refused {
            reason: SamlAnswer::refusal_named(&refusal).unwrap_or("unknown_refusal"),
        }),
        (Some(_), Some(_)) => return Err(corrupted("SAML answer")),
    };
    Ok(PendingAuthorization {
        transaction_id: TransactionId::from_uuid(row.try_get("transaction_id").map_err(get)?),
        provider_id: ProviderId::from_uuid(row.try_get("provider_id").map_err(get)?),
        state_hash: state_hash.try_into().map_err(|_| corrupted("state hash"))?,
        nonce: row.try_get("nonce").map_err(get)?,
        code_verifier: SealedSecret::from_stored(row.try_get("code_verifier").map_err(get)?),
        redirect_uri: row.try_get("redirect_uri").map_err(get)?,
        expires_at: row.try_get("expires_at").map_err(get)?,
        saml_answer,
        saml_receipt_hash: row
            .try_get::<Option<Vec<u8>>, _>("saml_receipt_hash")
            .map_err(get)?
            .map(|hash| hash.try_into().map_err(|_| corrupted("receipt hash")))
            .transpose()?,
    })
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
                  scopes, creates_users, trusts_email, status, created_at, updated_at, version,
                    directory_base, directory_filter, directory_subject_attribute,
                    directory_email_attribute, directory_name_attribute,
                    saml_single_sign_on_address, saml_certificate, saml_email_attribute,
                    saml_name_attribute)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 0,
                     $15, $16, $17, $18, $19, $20, $21, $22, $23)",
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
        .bind(state.settings.trusts_email)
        .bind(state.status.as_str())
        .bind(state.created_at)
        .bind(state.updated_at)
        .bind(state.settings.directory.as_ref().map(|d| d.base.clone()))
        .bind(state.settings.directory.as_ref().map(|d| d.filter.clone()))
        .bind(
            state
                .settings
                .directory
                .as_ref()
                .map(|d| d.subject_attribute.clone()),
        )
        .bind(
            state
                .settings
                .directory
                .as_ref()
                .map(|d| d.email_attribute.clone()),
        )
        .bind(
            state
                .settings
                .directory
                .as_ref()
                .map(|d| d.name_attribute.clone()),
        )
        .bind(saml_part(state, |s| &s.single_sign_on_address))
        .bind(saml_part(state, |s| &s.certificate))
        .bind(saml_part(state, |s| &s.email_attribute))
        .bind(saml_part(state, |s| &s.name_attribute))
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
                 scopes = $7, creates_users = $8, trusts_email = $9, status = $10,
                 updated_at = $11, version = version + 1,
                 directory_base = $13, directory_filter = $14,
                 directory_subject_attribute = $15, directory_email_attribute = $16,
                 directory_name_attribute = $17,
                 saml_single_sign_on_address = $18, saml_certificate = $19,
                 saml_email_attribute = $20, saml_name_attribute = $21
             WHERE tenant_id = $1 AND id = $2 AND version = $12",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(&state.settings.display_name)
        .bind(&state.settings.issuer)
        .bind(&state.settings.client_id)
        .bind(state.client_secret.as_bytes())
        .bind(&state.settings.scopes)
        .bind(state.settings.creates_users)
        .bind(state.settings.trusts_email)
        .bind(state.status.as_str())
        .bind(state.updated_at)
        .bind(version)
        .bind(state.settings.directory.as_ref().map(|d| d.base.clone()))
        .bind(state.settings.directory.as_ref().map(|d| d.filter.clone()))
        .bind(
            state
                .settings
                .directory
                .as_ref()
                .map(|d| d.subject_attribute.clone()),
        )
        .bind(
            state
                .settings
                .directory
                .as_ref()
                .map(|d| d.email_attribute.clone()),
        )
        .bind(
            state
                .settings
                .directory
                .as_ref()
                .map(|d| d.name_attribute.clone()),
        )
        .bind(saml_part(state, |s| &s.single_sign_on_address))
        .bind(saml_part(state, |s| &s.certificate))
        .bind(saml_part(state, |s| &s.email_attribute))
        .bind(saml_part(state, |s| &s.name_attribute))
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
                    scopes, creates_users, trusts_email, status, created_at, updated_at, version,
                    directory_base, directory_filter, directory_subject_attribute,
                    directory_email_attribute, directory_name_attribute,
                    saml_single_sign_on_address, saml_certificate, saml_email_attribute,
                    saml_name_attribute
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
                    scopes, creates_users, trusts_email, status, created_at, updated_at, version,
                    directory_base, directory_filter, directory_subject_attribute,
                    directory_email_attribute, directory_name_attribute,
                    saml_single_sign_on_address, saml_certificate, saml_email_attribute,
                    saml_name_attribute
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
                    scopes, creates_users, trusts_email, status, created_at, updated_at, version,
                    directory_base, directory_filter, directory_subject_attribute,
                    directory_email_attribute, directory_name_attribute,
                    saml_single_sign_on_address, saml_certificate, saml_email_attribute,
                    saml_name_attribute
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

/// [`PendingAuthorizationStore`] on `federation.pending_authorization`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgPendingAuthorizationStore;

#[async_trait::async_trait]
impl PendingAuthorizationStore for PgPendingAuthorizationStore {
    async fn put(
        &self,
        uow: &mut dyn UnitOfWork,
        pending: &PendingAuthorization,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let stored = sqlx::query(
            "INSERT INTO federation.pending_authorization
                 (tenant_id, transaction_id, provider_id, state_hash, nonce, code_verifier,
                  redirect_uri, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (tenant_id, transaction_id) DO UPDATE
             SET provider_id = EXCLUDED.provider_id, state_hash = EXCLUDED.state_hash,
                 nonce = EXCLUDED.nonce, code_verifier = EXCLUDED.code_verifier,
                 redirect_uri = EXCLUDED.redirect_uri, expires_at = EXCLUDED.expires_at,
                 saml_subject = NULL, saml_email = NULL, saml_name = NULL,
                 saml_refusal = NULL, saml_receipt_hash = NULL",
        )
        .bind(tenant.as_uuid())
        .bind(pending.transaction_id.as_uuid())
        .bind(pending.provider_id.as_uuid())
        .bind(pending.state_hash.as_slice())
        .bind(&pending.nonce)
        .bind(pending.code_verifier.as_bytes())
        .bind(&pending.redirect_uri)
        .bind(pending.expires_at)
        .execute(connection(uow)?)
        .await;
        match stored {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(error))
                if error.constraint() == Some(PENDING_PROVIDER_CONSTRAINT) =>
            {
                Err(DomainError::not_found(
                    "federation.provider_not_found",
                    "there is no such identity provider",
                ))
            }
            Err(error) => Err(database_error(&error)),
        }
    }

    async fn take(
        &self,
        uow: &mut dyn UnitOfWork,
        transaction_id: TransactionId,
    ) -> Result<Option<PendingAuthorization>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        // One statement: of several callers at the same moment, one
        // deletes the row and gets it back.
        let row = sqlx::query(
            "DELETE FROM federation.pending_authorization
             WHERE tenant_id = $1 AND transaction_id = $2
             RETURNING transaction_id, provider_id, state_hash, nonce, code_verifier,
                       redirect_uri, expires_at, saml_subject, saml_email, saml_name,
                       saml_refusal, saml_receipt_hash",
        )
        .bind(tenant.as_uuid())
        .bind(transaction_id.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.as_ref().map(pending_from).transpose()
    }

    async fn claim(
        &self,
        uow: &mut dyn UnitOfWork,
        provider_id: ProviderId,
        state_hash: [u8; 32],
        receipt_hash: [u8; 32],
        now: Timestamp,
    ) -> Result<Option<PendingAuthorization>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        // One statement: of several responses at the same moment, one
        // claims the pending authorization and gets it back.
        let row = sqlx::query(
            "UPDATE federation.pending_authorization
             SET saml_receipt_hash = $5
             WHERE tenant_id = $1 AND provider_id = $2 AND state_hash = $3
               AND expires_at > $4 AND saml_receipt_hash IS NULL
             RETURNING transaction_id, provider_id, state_hash, nonce, code_verifier,
                       redirect_uri, expires_at, saml_subject, saml_email, saml_name,
                       saml_refusal, saml_receipt_hash",
        )
        .bind(tenant.as_uuid())
        .bind(provider_id.as_uuid())
        .bind(state_hash.as_slice())
        .bind(now)
        .bind(receipt_hash.as_slice())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        row.as_ref().map(pending_from).transpose()
    }

    async fn answer(
        &self,
        uow: &mut dyn UnitOfWork,
        provider_id: ProviderId,
        state_hash: [u8; 32],
        receipt_hash: [u8; 32],
        answer: &SamlAnswer,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let (subject, email, name, refusal) = match answer {
            SamlAnswer::Verified {
                subject,
                email,
                name,
            } => (
                Some(subject.expose()),
                email.as_deref(),
                name.as_deref(),
                None,
            ),
            SamlAnswer::Refused { reason } => (None, None, None, Some(*reason)),
        };
        // Only the response that claimed it answers it, and once.
        let kept = sqlx::query(
            "UPDATE federation.pending_authorization
             SET saml_subject = $5, saml_email = $6, saml_name = $7, saml_refusal = $8
             WHERE tenant_id = $1 AND provider_id = $2 AND state_hash = $3
               AND saml_receipt_hash = $4
               AND saml_subject IS NULL AND saml_refusal IS NULL",
        )
        .bind(tenant.as_uuid())
        .bind(provider_id.as_uuid())
        .bind(state_hash.as_slice())
        .bind(receipt_hash.as_slice())
        .bind(subject)
        .bind(email)
        .bind(name)
        .bind(refusal)
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(kept.rows_affected() > 0)
    }

    async fn remove_expired(
        &self,
        uow: &mut dyn UnitOfWork,
        now: Timestamp,
        limit: u32,
    ) -> Result<u64, DomainError> {
        let tenant = uow.tenant().tenant_id();
        // A batch at a time, so that one pass holds no lock for long. The
        // batch is chosen once, in a common table expression that locks
        // what it chooses: a limited subquery inside `IN` may be scanned
        // again for every row, and its limit then applies to each scan.
        let removed = sqlx::query(
            "WITH chosen AS (
                 SELECT transaction_id FROM federation.pending_authorization
                 WHERE tenant_id = $1 AND expires_at <= $2
                 LIMIT $3
                 FOR UPDATE SKIP LOCKED
             )
             DELETE FROM federation.pending_authorization AS pending
             USING chosen
             WHERE pending.tenant_id = $1 AND pending.transaction_id = chosen.transaction_id",
        )
        .bind(tenant.as_uuid())
        .bind(now)
        .bind(i64::from(limit))
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        Ok(removed.rows_affected())
    }
}
