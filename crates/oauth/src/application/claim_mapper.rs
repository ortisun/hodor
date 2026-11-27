//! The use cases of claim mappers: an administrator's changes, checked
//! with the client's other mappers, and the claims they add to a token
//! when it is issued.

use crate::application::ports::{
    ClaimMapperStore, ClientStore, PersonClaimSources, PersonMemberships,
};
use crate::domain::claim_mapper::{
    ClaimMapper, ClaimMapperId, ClaimMapperSettings, ClaimTarget, PersonAttributes, PersonFacts,
    check_together, mapped_claims, needs,
};
use crate::domain::client::{Client, ClientId};
use crate::domain::event::OauthEvent;
use hodor_kernel::{
    Caller, Clock, DomainError, EventEnvelope, EventMetadata, OrganizationId, TenantContext,
    UnitOfWork, UnitOfWorkFactory, UserId,
};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

fn client_not_found() -> DomainError {
    DomainError::not_found("oauth.client_not_found", "there is no such client")
}

fn mapper_not_found() -> DomainError {
    DomainError::not_found(
        "oauth.claim_mapper_not_found",
        "the client has no such claim mapper",
    )
}

/// The ports [`ClaimMapperService`] works through.
#[derive(Clone)]
pub struct ClaimMapperPorts {
    /// Starts units of work.
    pub units_of_work: Arc<dyn UnitOfWorkFactory>,
    /// Stores clients, for the scopes a mapper may name.
    pub clients: Arc<dyn ClientStore>,
    /// Stores the mappers.
    pub mappers: Arc<dyn ClaimMapperStore>,
    /// The time.
    pub clock: Arc<dyn Clock>,
}

impl fmt::Debug for ClaimMapperPorts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClaimMapperPorts").finish_non_exhaustive()
    }
}

/// The use cases of claim mappers.
#[derive(Clone)]
pub struct ClaimMapperService {
    ports: ClaimMapperPorts,
}

impl fmt::Debug for ClaimMapperService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClaimMapperService").finish_non_exhaustive()
    }
}

impl ClaimMapperService {
    /// Wires the use cases to their ports.
    #[must_use]
    pub const fn new(ports: ClaimMapperPorts) -> Self {
        Self { ports }
    }

    fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        caller: Caller,
        event: &OauthEvent,
    ) -> Result<(), DomainError> {
        let metadata = EventMetadata::new(
            uow.tenant().tenant_id(),
            caller.actor,
            caller.correlation_id,
            self.ports.clock.as_ref(),
        );
        uow.record_event(EventEnvelope::new(metadata, event)?);
        Ok(())
    }

    /// Locks the client and loads it with its mappers.
    async fn locked_client(
        &self,
        uow: &mut dyn UnitOfWork,
        client_id: ClientId,
    ) -> Result<(Client, Vec<ClaimMapper>), DomainError> {
        if !self.ports.mappers.lock_client(uow, client_id).await? {
            return Err(client_not_found());
        }
        let client = self
            .ports
            .clients
            .get(uow, client_id)
            .await?
            .ok_or_else(client_not_found)?;
        let mappers = self.ports.mappers.list_for_client(uow, client_id).await?;
        Ok((client, mappers))
    }

    /// Adds a mapper to a client, checked with every other mapper of the
    /// client under a lock of the client.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_not_found`, an `Invalid` error naming the rule
    /// broken, `oauth.claim_mapper_token_too_large`, or a conflict for a
    /// claim the client maps already or a twenty-first mapper.
    pub async fn create(
        &self,
        tenant: &TenantContext,
        client_id: ClientId,
        settings: ClaimMapperSettings,
        caller: Caller,
    ) -> Result<ClaimMapper, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let (client, existing) = self.locked_client(uow.as_mut(), client_id).await?;
        let (mapper, event) = ClaimMapper::create(
            client_id,
            settings,
            &client.snapshot().settings.allowed_scopes,
            self.ports.clock.now(),
        )?;
        let mut together: Vec<&ClaimMapperSettings> =
            existing.iter().map(ClaimMapper::settings).collect();
        together.push(mapper.settings());
        check_together(&together)?;
        self.ports.mappers.insert(uow.as_mut(), &mapper).await?;
        self.record(uow.as_mut(), caller, &event)?;
        uow.commit().await?;
        Ok(mapper)
    }

    /// Replaces a mapper's settings, checked again with every other mapper
    /// of the client under a lock of the client.
    ///
    /// # Errors
    ///
    /// As [`Self::create`], and `oauth.claim_mapper_not_found`.
    pub async fn replace(
        &self,
        tenant: &TenantContext,
        client_id: ClientId,
        id: ClaimMapperId,
        settings: ClaimMapperSettings,
        caller: Caller,
    ) -> Result<ClaimMapper, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let (client, existing) = self.locked_client(uow.as_mut(), client_id).await?;
        let mut mapper = existing
            .iter()
            .find(|mapper| mapper.id() == id)
            .cloned()
            .ok_or_else(mapper_not_found)?;
        let event = mapper.replace(
            settings,
            &client.snapshot().settings.allowed_scopes,
            self.ports.clock.now(),
        )?;
        let mut together: Vec<&ClaimMapperSettings> = existing
            .iter()
            .filter(|other| other.id() != id)
            .map(ClaimMapper::settings)
            .collect();
        together.push(mapper.settings());
        check_together(&together)?;
        self.ports.mappers.update(uow.as_mut(), &mapper).await?;
        self.record(uow.as_mut(), caller, &event)?;
        uow.commit().await?;
        Ok(ClaimMapper::from_snapshot(
            crate::domain::claim_mapper::ClaimMapperSnapshot {
                version: mapper.snapshot().version + 1,
                ..mapper.snapshot().clone()
            },
        ))
    }

    /// Deletes a mapper.
    ///
    /// # Errors
    ///
    /// Returns `oauth.claim_mapper_not_found` if the client has no such
    /// mapper, and `oauth.client_not_found` if the tenant has no such
    /// client.
    pub async fn delete(
        &self,
        tenant: &TenantContext,
        client_id: ClientId,
        id: ClaimMapperId,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let (_, existing) = self.locked_client(uow.as_mut(), client_id).await?;
        let mapper = existing
            .iter()
            .find(|mapper| mapper.id() == id)
            .ok_or_else(mapper_not_found)?;
        if !self
            .ports
            .mappers
            .delete(uow.as_mut(), client_id, id)
            .await?
        {
            return Err(mapper_not_found());
        }
        self.record(uow.as_mut(), caller, &mapper.deleted())?;
        uow.commit().await?;
        Ok(())
    }

    /// A mapper of a client.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_not_found` or `oauth.claim_mapper_not_found`.
    pub async fn mapper(
        &self,
        tenant: &TenantContext,
        client_id: ClientId,
        id: ClaimMapperId,
    ) -> Result<ClaimMapper, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        if self
            .ports
            .clients
            .get(uow.as_mut(), client_id)
            .await?
            .is_none()
        {
            return Err(client_not_found());
        }
        self.ports
            .mappers
            .get(uow.as_mut(), client_id, id)
            .await?
            .ok_or_else(mapper_not_found)
    }

    /// Every mapper of a client, by claim name.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_not_found` if the tenant has no such client.
    pub async fn mappers(
        &self,
        tenant: &TenantContext,
        client_id: ClientId,
    ) -> Result<Vec<ClaimMapper>, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        if self
            .ports
            .clients
            .get(uow.as_mut(), client_id)
            .await?
            .is_none()
        {
            return Err(client_not_found());
        }
        self.ports
            .mappers
            .list_for_client(uow.as_mut(), client_id)
            .await
    }
}

/// The claims the mappers of a client add to each target of one issue.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MappedClaims {
    by_target: BTreeMap<ClaimTarget, Map<String, Value>>,
}

impl MappedClaims {
    /// What is added to `target`; nothing for a target not read.
    #[must_use]
    pub fn of(&self, target: ClaimTarget) -> Map<String, Value> {
        self.by_target.get(&target).cloned().unwrap_or_default()
    }
}

/// Reads the claims a client's mappers add to the tokens of one issue,
/// for the token endpoint and UserInfo.
#[derive(Clone)]
pub struct ClaimMapping {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    mappers: Arc<dyn ClaimMapperStore>,
    memberships: Arc<dyn PersonMemberships>,
    sources: Arc<dyn PersonClaimSources>,
}

impl fmt::Debug for ClaimMapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClaimMapping").finish_non_exhaustive()
    }
}

/// The token being issued that the mappers write into.
#[derive(Debug, Clone, Copy)]
pub struct MappedToken<'a> {
    /// The client it is issued to.
    pub client_id: ClientId,
    /// The person it is about.
    pub user_id: UserId,
    /// Its scopes.
    pub scopes: &'a [String],
    /// The organization of the sign-in, if any.
    pub organization: Option<OrganizationId>,
}

impl ClaimMapping {
    /// Reads mappers from `mappers`, and what they need from `memberships`
    /// and `sources`.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        mappers: Arc<dyn ClaimMapperStore>,
        memberships: Arc<dyn PersonMemberships>,
        sources: Arc<dyn PersonClaimSources>,
    ) -> Self {
        Self {
            units_of_work,
            mappers,
            memberships,
            sources,
        }
    }

    /// What Hodor knows of `user`, for the claims a client asks for
    /// through the `claims` parameter: the attributes the mappers read,
    /// with when the person was last changed. Empty for a user the tenant
    /// does not have.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn person(
        &self,
        tenant: &TenantContext,
        user: UserId,
    ) -> Result<PersonAttributes, DomainError> {
        self.sources.attributes(tenant, user).await
    }

    /// The claims the client's mappers add to each of `targets` of
    /// `token`, reading only what the mappers that apply need, now.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn read(
        &self,
        tenant: &TenantContext,
        token: MappedToken<'_>,
        targets: &[ClaimTarget],
    ) -> Result<MappedClaims, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let mappers = self
            .mappers
            .list_for_client(uow.as_mut(), token.client_id)
            .await?;
        drop(uow);
        if mappers.is_empty() {
            return Ok(MappedClaims::default());
        }
        let needed = needs(&mappers, targets, token.scopes);
        let mut facts = PersonFacts {
            organization: token.organization,
            ..PersonFacts::default()
        };
        if needed.attributes {
            facts.attributes = self.sources.attributes(tenant, token.user_id).await?;
        }
        if needed.groups {
            facts.groups = self
                .memberships
                .effective_groups(tenant, token.user_id)
                .await?;
        }
        if needed.organization_name
            && let Some(organization) = token.organization
        {
            facts.organization_name = self.sources.organization_name(tenant, organization).await?;
        }
        Ok(MappedClaims {
            by_target: targets
                .iter()
                .map(|target| {
                    (
                        *target,
                        mapped_claims(&mappers, *target, token.scopes, &facts),
                    )
                })
                .collect(),
        })
    }
}
