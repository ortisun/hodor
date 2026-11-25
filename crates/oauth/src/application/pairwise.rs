//! The identifiers a client knows a person and a session by: the user and
//! session identifiers for a public client, and for a pairwise client the
//! pairwise identifiers of its sector, made with the tenant's pairwise
//! secret.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Pairwise subject
//! identifiers".

use crate::application::ports::PairwiseSecretStore;
use crate::domain::client::Client;
use crate::domain::pairwise::{HmacSha256, PAIRWISE_SECRET_PURPOSE, PairwiseSecret, SubjectType};
use hodor_kernel::{
    Clock, DomainError, RandomSource, SecretBox, TenantContext, UnitOfWorkFactory, UserId,
};
use hodor_session::api::SessionId;
use std::fmt;
use std::sync::Arc;

/// The ports [`PairwiseSubjects`] works through.
#[derive(Clone)]
pub struct PairwisePorts {
    /// Starts units of work.
    pub units_of_work: Arc<dyn UnitOfWorkFactory>,
    /// Keeps the tenant's sealed pairwise secret.
    pub secrets: Arc<dyn PairwiseSecretStore>,
    /// Seals and opens it.
    pub secret_box: Arc<dyn SecretBox>,
    /// HMAC-SHA-256.
    pub mac: Arc<dyn HmacSha256>,
    /// The bytes of a new secret.
    pub random: Arc<dyn RandomSource>,
    /// The time.
    pub clock: Arc<dyn Clock>,
}

impl fmt::Debug for PairwisePorts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairwisePorts").finish_non_exhaustive()
    }
}

/// Names a person and a session as a client knows them.
#[derive(Clone)]
pub struct PairwiseSubjects {
    ports: PairwisePorts,
}

impl fmt::Debug for PairwiseSubjects {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairwiseSubjects").finish_non_exhaustive()
    }
}

fn unavailable() -> DomainError {
    DomainError::internal(
        "oauth.pairwise_unavailable",
        "this service cannot name a person to a pairwise client",
    )
}

fn no_sector() -> DomainError {
    DomainError::internal(
        "oauth.client_sector_missing",
        "a pairwise client has no sector",
    )
}

impl PairwiseSubjects {
    /// Wires the use case to its ports.
    #[must_use]
    pub const fn new(ports: PairwisePorts) -> Self {
        Self { ports }
    }

    /// The `sub` by which `client` knows the person `user`.
    ///
    /// # Errors
    ///
    /// Returns an error if the tenant's pairwise secret cannot be read or
    /// made.
    pub async fn subject(
        &self,
        tenant: &TenantContext,
        client: &Client,
        user: UserId,
    ) -> Result<String, DomainError> {
        let Some(sector) = sector(client)? else {
            return Ok(user.to_string());
        };
        let secret = self.secret(tenant).await?;
        Ok(secret.subject(
            self.ports.mac.as_ref(),
            tenant.tenant_id(),
            &sector,
            user.as_uuid().as_bytes(),
        ))
    }

    /// The `sid` by which `client` knows the session `session`.
    ///
    /// # Errors
    ///
    /// Returns an error if the tenant's pairwise secret cannot be read or
    /// made.
    pub async fn session(
        &self,
        tenant: &TenantContext,
        client: &Client,
        session: SessionId,
    ) -> Result<String, DomainError> {
        let Some(sector) = sector(client)? else {
            return Ok(session.to_string());
        };
        let secret = self.secret(tenant).await?;
        Ok(secret.session(
            self.ports.mac.as_ref(),
            tenant.tenant_id(),
            &sector,
            session.as_uuid().as_bytes(),
        ))
    }

    /// The tenant's pairwise secret, made and stored the first time it is
    /// needed. Of two servers that make it at once, both use the one
    /// stored first. A stored secret that does not open is an error, never
    /// a reason to make another.
    async fn secret(&self, tenant: &TenantContext) -> Result<PairwiseSecret, DomainError> {
        let ports = &self.ports;
        let mut uow = ports.units_of_work.begin(tenant).await?;
        let found = ports.secrets.find(uow.as_mut()).await?;
        drop(uow);
        let sealed = if let Some(sealed) = found {
            sealed
        } else {
            let made = PairwiseSecret::generate(ports.random.as_ref());
            let sealed = ports
                .secret_box
                .seal(tenant, PAIRWISE_SECRET_PURPOSE, made.as_secret())
                .await?;
            let mut uow = ports.units_of_work.begin(tenant).await?;
            ports
                .secrets
                .insert_unless_present(uow.as_mut(), &sealed, ports.clock.now())
                .await?;
            // Whichever was stored first.
            let stored = ports.secrets.find(uow.as_mut()).await?;
            uow.commit().await?;
            stored.ok_or_else(|| {
                DomainError::internal(
                    "oauth.pairwise_secret_missing",
                    "the tenant's pairwise secret was not stored",
                )
            })?
        };
        let opened = ports
            .secret_box
            .open(tenant, PAIRWISE_SECRET_PURPOSE, &sealed)
            .await?;
        PairwiseSecret::from_opened(opened)
    }
}

/// The sector of a pairwise client; none for a public one.
fn sector(client: &Client) -> Result<Option<String>, DomainError> {
    match client.subject_type() {
        SubjectType::Public => Ok(None),
        SubjectType::Pairwise => client.sector().map(Some).ok_or_else(no_sector),
    }
}

/// The `sub` by which `client` knows `user`, through `pairwise` when the
/// client is pairwise. A service given no [`PairwiseSubjects`] refuses to
/// name a person to a pairwise client rather than give it the user
/// identifier.
pub(crate) async fn subject_for(
    pairwise: Option<&PairwiseSubjects>,
    tenant: &TenantContext,
    client: &Client,
    user: UserId,
) -> Result<String, DomainError> {
    match (client.subject_type(), pairwise) {
        (SubjectType::Public, _) => Ok(user.to_string()),
        (SubjectType::Pairwise, Some(pairwise)) => pairwise.subject(tenant, client, user).await,
        (SubjectType::Pairwise, None) => Err(unavailable()),
    }
}

/// The `sid` by which `client` knows `session`, as [`subject_for`] does.
pub(crate) async fn session_for(
    pairwise: Option<&PairwiseSubjects>,
    tenant: &TenantContext,
    client: &Client,
    session: SessionId,
) -> Result<String, DomainError> {
    match (client.subject_type(), pairwise) {
        (SubjectType::Public, _) => Ok(session.to_string()),
        (SubjectType::Pairwise, Some(pairwise)) => pairwise.session(tenant, client, session).await,
        (SubjectType::Pairwise, None) => Err(unavailable()),
    }
}
