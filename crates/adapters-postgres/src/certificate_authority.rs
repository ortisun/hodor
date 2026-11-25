//! PostgreSQL storage for the certificate authority of a tenant.
//!
//! See `docs/architecture/contexts/keys.md`, "The certificate authority of
//! a tenant" and "`keys.certificate_authority`".

use crate::uow::{connection, database_error};
use hodor_kernel::{DomainError, PublicKey, Timestamp, UnitOfWork};
use hodor_keys::api::{
    AuthorityId, AuthorityKey, AuthorityKind, AuthorityState, AuthorityStore, CertificateAuthority,
    CertificateAuthoritySnapshot, IssuedCertificate, KeyMaterial, KeyVersionId, TrustDomainName,
};
use sqlx::types::Uuid;
use sqlx::{FromRow, postgres::PgRow};

/// [`AuthorityStore`] on `keys.certificate_authority`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PgAuthorityStore;

const PRIMARY_KEY: &str = "certificate_authority_pkey";

const COLUMNS: &str = "id, kind, state, trust_domains, common_name, lifetime_days,
     intermediate_lifetime_days, for_development, key_id, provider, key_material, public_p256_x,
     public_p256_y, certificate_signing_request, certificate, serial_number, not_before,
     not_after, certificate_sha256, chain, created_at, activated_at, updated_at, version";

#[derive(FromRow)]
struct Row {
    id: Uuid,
    kind: String,
    state: String,
    trust_domains: Vec<String>,
    common_name: String,
    lifetime_days: Option<i32>,
    intermediate_lifetime_days: i32,
    for_development: bool,
    key_id: Uuid,
    provider: String,
    key_material: Vec<u8>,
    public_p256_x: Vec<u8>,
    public_p256_y: Vec<u8>,
    certificate_signing_request: Option<Vec<u8>>,
    certificate: Option<Vec<u8>>,
    serial_number: Option<String>,
    not_before: Option<Timestamp>,
    not_after: Option<Timestamp>,
    certificate_sha256: Option<String>,
    chain: Vec<Vec<u8>>,
    created_at: Timestamp,
    activated_at: Option<Timestamp>,
    updated_at: Timestamp,
    version: i32,
}

fn corrupted(what: &str) -> DomainError {
    DomainError::internal(
        "keys.stored_data_invalid",
        "the certificate authority could not be loaded",
    )
    .with_detail(what.to_owned())
}

fn days(value: i32) -> Result<u32, DomainError> {
    u32::try_from(value).map_err(|_| corrupted("a negative number of days"))
}

fn to_authority(row: Row) -> Result<CertificateAuthority, DomainError> {
    let certificate = match (
        row.certificate,
        row.serial_number,
        row.not_before,
        row.not_after,
        row.certificate_sha256,
    ) {
        (Some(der), Some(serial_number), Some(not_before), Some(not_after), Some(sha256)) => {
            Some(IssuedCertificate {
                der,
                serial_number,
                not_before,
                not_after,
                sha256,
            })
        }
        (None, None, None, None, None) => None,
        _ => return Err(corrupted("a part of the certificate")),
    };
    Ok(CertificateAuthority::from_snapshot(
        CertificateAuthoritySnapshot {
            id: AuthorityId::from_uuid(row.id),
            kind: AuthorityKind::parse(&row.kind).map_err(|_| corrupted("the kind"))?,
            state: AuthorityState::parse(&row.state)?,
            trust_domains: row
                .trust_domains
                .iter()
                .map(|name| TrustDomainName::parse(name))
                .collect::<Result<_, _>>()
                .map_err(|_| corrupted("a trust domain"))?,
            common_name: row.common_name,
            lifetime_days: row.lifetime_days.map(days).transpose()?,
            intermediate_lifetime_days: days(row.intermediate_lifetime_days)?,
            for_development: row.for_development,
            key: AuthorityKey {
                id: KeyVersionId::from_uuid(row.key_id),
                provider: row.provider,
                material: KeyMaterial::from_stored(row.key_material),
                public_key: PublicKey::P256 {
                    x: row.public_p256_x,
                    y: row.public_p256_y,
                },
            },
            certificate_signing_request: row.certificate_signing_request,
            certificate,
            chain: row.chain,
            created_at: row.created_at,
            activated_at: row.activated_at,
            updated_at: row.updated_at,
            version: u32::try_from(row.version).map_err(|_| corrupted("a negative version"))?,
        },
    ))
}

async fn read(
    uow: &mut dyn UnitOfWork,
    hold: bool,
) -> Result<Option<CertificateAuthority>, DomainError> {
    let tenant = uow.tenant().tenant_id();
    let suffix = if hold { " FOR UPDATE" } else { "" };
    let statement =
        format!("SELECT {COLUMNS} FROM keys.certificate_authority WHERE tenant_id = $1{suffix}");
    let row: Option<PgRow> = sqlx::query(sqlx::AssertSqlSafe(statement))
        .bind(tenant.as_uuid())
        .fetch_optional(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
    row.map(|row| {
        Row::from_row(&row)
            .map_err(|e| database_error(&e))
            .and_then(to_authority)
    })
    .transpose()
}

fn coordinates(key: &PublicKey) -> Result<(&[u8], &[u8]), DomainError> {
    match key {
        PublicKey::P256 { x, y } => Ok((x, y)),
        PublicKey::Rsa { .. } => Err(DomainError::internal(
            "keys.stored_data_invalid",
            "an authority's key is on P-256",
        )),
    }
}

fn whole(value: Option<u32>) -> Option<i32> {
    value.and_then(|value| i32::try_from(value).ok())
}

#[async_trait::async_trait]
impl AuthorityStore for PgAuthorityStore {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        authority: &CertificateAuthority,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = authority.snapshot();
        let (x, y) = coordinates(&state.key.public_key)?;
        let certificate = state.certificate.as_ref();
        let names: Vec<&str> = state
            .trust_domains
            .iter()
            .map(TrustDomainName::as_str)
            .collect();
        let inserted = sqlx::query(
            "INSERT INTO keys.certificate_authority
                 (tenant_id, id, kind, state, trust_domains, common_name, lifetime_days,
                  intermediate_lifetime_days, for_development, key_id, provider, key_material,
                  public_p256_x, public_p256_y, certificate_signing_request, certificate,
                  serial_number, not_before, not_after, certificate_sha256, chain, created_at,
                  activated_at, updated_at, version)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
                     $18, $19, $20, $21, $22, $23, $24, $25)",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.kind.as_str())
        .bind(state.state.as_str())
        .bind(&names)
        .bind(&state.common_name)
        .bind(whole(state.lifetime_days))
        .bind(whole(Some(state.intermediate_lifetime_days)))
        .bind(state.for_development)
        .bind(state.key.id.as_uuid())
        .bind(&state.key.provider)
        .bind(state.key.material.as_bytes())
        .bind(x)
        .bind(y)
        .bind(state.certificate_signing_request.as_deref())
        .bind(certificate.map(|issued| issued.der.as_slice()))
        .bind(certificate.map(|issued| issued.serial_number.as_str()))
        .bind(certificate.map(|issued| issued.not_before))
        .bind(certificate.map(|issued| issued.not_after))
        .bind(certificate.map(|issued| issued.sha256.as_str()))
        .bind(&state.chain)
        .bind(state.created_at)
        .bind(state.activated_at)
        .bind(state.updated_at)
        .bind(i32::try_from(state.version).unwrap_or(i32::MAX))
        .execute(connection(uow)?)
        .await;
        match inserted {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(error)) if error.constraint() == Some(PRIMARY_KEY) => {
                Err(DomainError::conflict(
                    "keys.authority_exists",
                    "the tenant has a certificate authority already",
                ))
            }
            Err(error) => Err(database_error(&error)),
        }
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
    ) -> Result<Option<CertificateAuthority>, DomainError> {
        read(uow, false).await
    }

    async fn lock(
        &self,
        uow: &mut dyn UnitOfWork,
    ) -> Result<Option<CertificateAuthority>, DomainError> {
        read(uow, true).await
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        authority: &CertificateAuthority,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let state = authority.snapshot();
        let certificate = state.certificate.as_ref();
        // The kind, the trust domains and the key never change.
        let changed = sqlx::query(
            "UPDATE keys.certificate_authority
             SET state = $3, certificate = $4, serial_number = $5, not_before = $6,
                 not_after = $7, certificate_sha256 = $8, chain = $9, activated_at = $10,
                 updated_at = $11, version = version + 1
             WHERE tenant_id = $1 AND id = $2 AND version = $12",
        )
        .bind(tenant.as_uuid())
        .bind(state.id.as_uuid())
        .bind(state.state.as_str())
        .bind(certificate.map(|issued| issued.der.as_slice()))
        .bind(certificate.map(|issued| issued.serial_number.as_str()))
        .bind(certificate.map(|issued| issued.not_before))
        .bind(certificate.map(|issued| issued.not_after))
        .bind(certificate.map(|issued| issued.sha256.as_str()))
        .bind(&state.chain)
        .bind(state.activated_at)
        .bind(state.updated_at)
        .bind(i32::try_from(state.version).unwrap_or(i32::MAX))
        .execute(connection(uow)?)
        .await
        .map_err(|e| database_error(&e))?;
        if changed.rows_affected() == 0 {
            return Err(if read(uow, false).await?.is_some() {
                DomainError::conflict(
                    "keys.authority_changed",
                    "the certificate authority changed meanwhile; read it again",
                )
            } else {
                DomainError::not_found(
                    "keys.authority_not_found",
                    "the tenant has no certificate authority",
                )
            });
        }
        Ok(())
    }

    async fn remove(&self, uow: &mut dyn UnitOfWork) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let removed = sqlx::query("DELETE FROM keys.certificate_authority WHERE tenant_id = $1")
            .bind(tenant.as_uuid())
            .execute(connection(uow)?)
            .await
            .map_err(|e| database_error(&e))?;
        Ok(removed.rows_affected() > 0)
    }
}
