//! What the OAuth context needs to know of a person or a workload,
//! answered by the session and identity contexts: the OAuth context
//! depends on neither.
//!
//! See `docs/architecture/contexts/oauth.md`, "Refresh tokens", "The
//! organization of a sign-in", "Clients that act as a workload" and
//! "Claim mappers".

use hodor_adapters_postgres::{
    Database, PgGroupPolicy, PgGroupRepository, PgInvitationRepository, PgOrganizationRepository,
    PgUserRepository,
};
use hodor_identity::api::{GroupService, IdentifierKind, IdentityService, OrganizationService};
use hodor_kernel::{Clock, DomainError, ErrorKind, GroupId, OrganizationId, TenantContext, UserId};
use hodor_oauth::api::{PersonAttributes, PersonClaimSources, PersonMemberships, PersonStanding};
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

/// [`PersonClaimSources`] over the identity context: what the claim
/// mappers of a client read of a person and of an organization.
#[derive(Clone)]
pub(crate) struct ServerClaimSources {
    identity: IdentityService,
    organizations: OrganizationService,
}

impl ServerClaimSources {
    /// Over the tables of `database`.
    pub(crate) fn over(database: &Database, clock: Arc<dyn Clock>) -> Self {
        let units = Arc::new(database.clone());
        Self {
            identity: IdentityService::new(
                units.clone(),
                Arc::new(PgUserRepository),
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

impl std::fmt::Debug for ServerClaimSources {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerClaimSources").finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl PersonClaimSources for ServerClaimSources {
    async fn attributes(
        &self,
        tenant: &TenantContext,
        user: UserId,
    ) -> Result<PersonAttributes, DomainError> {
        let user = match self.identity.get(tenant, user).await {
            Ok(user) => user,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Ok(PersonAttributes::default());
            }
            Err(error) => return Err(error),
        };
        let profile = &user.snapshot().profile;
        Ok(PersonAttributes {
            display_name: profile.display_name.clone(),
            username: user
                .primary_identifier(IdentifierKind::Username)
                .map(|identifier| identifier.value.display().to_owned()),
            email: user
                .primary_identifier(IdentifierKind::Email)
                .map(|identifier| {
                    (
                        identifier.value.display().to_owned(),
                        identifier.is_verified(),
                    )
                }),
            locale: profile.locale.clone(),
            claims: user.snapshot().claims.clone(),
        })
    }

    async fn organization_name(
        &self,
        tenant: &TenantContext,
        organization: OrganizationId,
    ) -> Result<Option<String>, DomainError> {
        match self.organizations.get(tenant, organization).await {
            Ok(found) => Ok(Some(found.name().as_str().to_owned())),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
}
