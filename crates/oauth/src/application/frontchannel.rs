//! Front-channel logout: the frames that tell, through the person's
//! browser, every client of a session that ended there, kept on the server
//! for the signed-out page and read back by the hash of their handle.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Front-channel
//! logout", and Decision 0081.

use crate::application::backchannel::ports::SessionClients;
use crate::application::pairwise::{PairwiseSubjects, session_for};
use crate::application::ports::{ApplicationStore, ClientStore};
use crate::domain::frontchannel::{FrontChannelLogout, HandleHash, SignedOutHandle, frame_address};
use hodor_kernel::{
    Clock, Digest, DomainError, RandomSource, TenantContext, UnitOfWork, UnitOfWorkFactory,
};
use hodor_session::api::SessionId;
use std::fmt;
use std::sync::Arc;

/// Keeps the frames of a tenant's sign-outs. Every method works inside the
/// tenant the unit of work is bound to.
#[async_trait::async_trait]
pub trait FrontChannelLogoutStore: Send + Sync {
    /// Stores the frames of one sign-out.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        kept: &FrontChannelLogout,
    ) -> Result<(), DomainError>;

    /// The frames kept under `hash` in the tenant, live or not.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &HandleHash,
    ) -> Result<Option<FrontChannelLogout>, DomainError>;
}

/// The ports [`FrontChannelLogoutService`] works through.
#[derive(Clone)]
pub struct FrontChannelLogoutPorts {
    /// Starts units of work.
    pub units_of_work: Arc<dyn UnitOfWorkFactory>,
    /// The clients signed in to with a session.
    pub sessions: Arc<dyn SessionClients>,
    /// Stores clients.
    pub clients: Arc<dyn ClientStore>,
    /// Stores applications.
    pub applications: Arc<dyn ApplicationStore>,
    /// Keeps the frames.
    pub store: Arc<dyn FrontChannelLogoutStore>,
    /// The hash of a handle.
    pub digest: Arc<dyn Digest>,
    /// The handle.
    pub random: Arc<dyn RandomSource>,
    /// The time.
    pub clock: Arc<dyn Clock>,
}

impl fmt::Debug for FrontChannelLogoutPorts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrontChannelLogoutPorts")
            .finish_non_exhaustive()
    }
}

/// The use cases of front-channel logout.
#[derive(Clone)]
pub struct FrontChannelLogoutService {
    ports: FrontChannelLogoutPorts,
    pairwise: Option<PairwiseSubjects>,
}

impl fmt::Debug for FrontChannelLogoutService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrontChannelLogoutService")
            .finish_non_exhaustive()
    }
}

impl FrontChannelLogoutService {
    /// Wires the use cases to their ports.
    #[must_use]
    pub const fn new(ports: FrontChannelLogoutPorts) -> Self {
        Self {
            ports,
            pairwise: None,
        }
    }

    /// Names the session to a pairwise client by its pairwise `sid`,
    /// through `pairwise`. Without it, a pairwise client gets no frame:
    /// it would otherwise be given the `sid` other clients know.
    #[must_use]
    pub fn with_pairwise_subjects(mut self, pairwise: PairwiseSubjects) -> Self {
        self.pairwise = Some(pairwise);
        self
    }

    /// The addresses of the frames that tell the clients of `session`,
    /// which just ended in its browser, at the tenant whose issuer is
    /// `issuer`: one for each client signed in to with it that has a
    /// front-channel logout address and is enabled with its application.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn frames_for(
        &self,
        tenant: &TenantContext,
        issuer: &str,
        session: SessionId,
    ) -> Result<Vec<String>, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let mut told = Vec::new();
        for client_id in self
            .ports
            .sessions
            .clients_of(uow.as_mut(), session)
            .await?
        {
            let Some(client) = self.ports.clients.get(uow.as_mut(), client_id).await? else {
                continue;
            };
            let Some(uri) = client.frontchannel_logout_uri().map(str::to_owned) else {
                continue;
            };
            if !client.is_enabled() {
                continue;
            }
            let enabled = self
                .ports
                .applications
                .get(uow.as_mut(), client.application_id())
                .await?
                .is_some_and(|application| application.is_enabled());
            if enabled {
                told.push((client, uri));
            }
        }
        drop(uow);
        let mut frames = Vec::with_capacity(told.len());
        for (client, uri) in told {
            match session_for(self.pairwise.as_ref(), tenant, &client, session).await {
                Ok(sid) => frames.push(frame_address(&uri, issuer, &sid)),
                // A pairwise client this service cannot name the session
                // to is not framed, rather than told another client's `sid`.
                Err(error) if error.code() == "oauth.pairwise_unavailable" => {}
                Err(error) => return Err(error),
            }
        }
        Ok(frames)
    }

    /// Makes and keeps the frames of `session`, which just ended in its
    /// browser, and answers the handle the browser gets for them; `None`
    /// when no client is to be told, and nothing is kept.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn sign_out(
        &self,
        tenant: &TenantContext,
        issuer: &str,
        session: SessionId,
    ) -> Result<Option<SignedOutHandle>, DomainError> {
        let frames = self.frames_for(tenant, issuer, session).await?;
        let Some((kept, handle)) = FrontChannelLogout::keep(
            session,
            frames,
            self.ports.clock.now(),
            self.ports.random.as_ref(),
            self.ports.digest.as_ref(),
        ) else {
            return Ok(None);
        };
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        self.ports.store.insert(uow.as_mut(), &kept).await?;
        uow.commit().await?;
        Ok(Some(handle))
    }

    /// The frames kept under the handle the browser `presented`, while
    /// they live; none for a handle that is unknown, expired, of another
    /// tenant or not a handle at all.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn frames(
        &self,
        tenant: &TenantContext,
        presented: &str,
    ) -> Result<Vec<String>, DomainError> {
        let Some(hash) = HandleHash::of_presented(presented, self.ports.digest.as_ref()) else {
            return Ok(Vec::new());
        };
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let found = self.ports.store.find(uow.as_mut(), &hash).await?;
        Ok(found
            .filter(|kept| kept.is_live_at(self.ports.clock.now()))
            .map(|kept| kept.frames)
            .unwrap_or_default())
    }
}
