//! What the OAuth context needs to know of a person or a workload,
//! answered by the session and identity contexts: the OAuth context
//! depends on neither.
//!
//! See `docs/architecture/contexts/oauth.md`, "Refresh tokens", "The
//! organization of a sign-in" and "Clients that act as a workload".

use hodor_adapters_postgres::{
    Database, PgGroupPolicy, PgGroupRepository, PgInvitationRepository, PgOrganizationRepository,
    PgUserRepository,
};
use hodor_identity::api::{GroupService, IdentityService, OrganizationService};
use hodor_kernel::{Clock, DomainError, ErrorKind, GroupId, OrganizationId, TenantContext, UserId};
use hodor_oauth::api::{PersonMemberships, PersonStanding};
use hodor_session::api::{SessionId, SessionService};
use std::sync::Arc;

/// [`PersonStanding`] over the session and identity services.
#[derive(Clone)]
pub(crate) struct ServerStanding {
    /// The sessions of people.
    pub(crate) sessions: SessionService,
    /// The people.
    pub(crate) identity: IdentityService,
}

impl std::fmt::Debug for ServerStanding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerStanding").finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl PersonStanding for ServerStanding {
    async fn session_is_active(
        &self,
        tenant: &TenantContext,
        user: UserId,
        session: SessionId,
    ) -> Result<bool, DomainError> {
        // Only the active sessions of the person are listed.
        Ok(self
            .sessions
            .list_for_user(tenant, user)
            .await?
            .iter()
            .any(|active| active.id() == session))
    }

    async fn may_sign_in(&self, tenant: &TenantContext, user: UserId) -> Result<bool, DomainError> {
        match self.identity.get(tenant, user).await {
            Ok(person) => Ok(person.may_sign_in()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    async fn workload_that_may_act(
        &self,
        tenant: &TenantContext,
        principal: UserId,
    ) -> Result<Option<&'static str>, DomainError> {
        match self.identity.get(tenant, principal).await {
            Ok(user) => Ok(user
                .is_workload_that_may_act()
                .then(|| user.kind().as_str())),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
}

/// [`PersonMemberships`] over the group and organization services.
#[derive(Clone)]
pub(crate) struct ServerMemberships {
    groups: GroupService,
    organizations: OrganizationService,
}

impl ServerMemberships {
    /// Over the tables of `database`.
    pub(crate) fn over(database: &Database, clock: Arc<dyn Clock>) -> Self {
        let units = Arc::new(database.clone());
        Self {
            groups: GroupService::new(
                units.clone(),
                Arc::new(PgGroupRepository),
                Arc::new(PgUserRepository),
                Arc::new(PgGroupPolicy),
                clock.clone(),
            ),
            organizations: OrganizationService::new(
                units,
                Arc::new(PgOrganizationRepository),
                Arc::new(PgInvitationRepository),
                Arc::new(PgUserRepository),
                clock,
            ),
        }
    }
}

impl std::fmt::Debug for ServerMemberships {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerMemberships").finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl PersonMemberships for ServerMemberships {
    async fn is_member(
        &self,
        tenant: &TenantContext,
        user: UserId,
        organization: OrganizationId,
    ) -> Result<bool, DomainError> {
        Ok(self
            .organizations
            .organizations_of(tenant, user)
            .await?
            .iter()
            .any(|membership| membership.organization == organization))
    }

    async fn effective_groups(
        &self,
        tenant: &TenantContext,
        user: UserId,
    ) -> Result<Vec<GroupId>, DomainError> {
        Ok(self
            .groups
            .effective_groups(tenant, user)
            .await?
            .into_iter()
            .collect())
    }
}
