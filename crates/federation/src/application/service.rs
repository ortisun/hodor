//! The use cases of the federation context.

use crate::application::ports::{LinkStore, ProviderStore};
use crate::domain::event::FederationEvent;
use crate::domain::link::{ExternalIdentity, Subject};
use crate::domain::provider::{
    Alias, IdentityProvider, MAX_PROVIDERS, ProviderId, ProviderKind, ProviderSettings,
    ProviderStatus,
};
use hodor_kernel::{
    Caller, Clock, DomainError, EventEnvelope, EventMetadata, Secret, SecretBox, TenantContext,
    UnitOfWork, UnitOfWorkFactory, UserId,
};
use std::sync::Arc;

/// The purpose client secrets are sealed for.
const CLIENT_SECRET: &str = "federation.client_secret";
const MAX_SECRET_BYTES: usize = 4096;

/// What is needed to add a provider.
#[derive(Debug)]
pub struct CreateProvider {
    /// Its name in addresses.
    pub alias: String,
    /// How Hodor talks to it.
    pub kind: ProviderKind,
    /// What an administrator decided about it.
    pub settings: ProviderSettings,
    /// What Hodor proves who it is with.
    pub client_secret: Secret<String>,
}

/// New settings for a provider.
#[derive(Debug)]
pub struct ChangeProvider {
    /// The provider.
    pub id: ProviderId,
    /// Its settings from now on.
    pub settings: ProviderSettings,
}

/// The use cases of the federation context.
#[derive(Clone)]
pub struct FederationService {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    providers: Arc<dyn ProviderStore>,
    links: Arc<dyn LinkStore>,
    secrets: Arc<dyn SecretBox>,
    clock: Arc<dyn Clock>,
    /// Hosts with ports whose issuer may be plain HTTP. Empty anywhere
    /// real.
    development_hosts: Arc<[String]>,
}

impl std::fmt::Debug for FederationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FederationService").finish_non_exhaustive()
    }
}

fn provider_not_found() -> DomainError {
    DomainError::not_found(
        "federation.provider_not_found",
        "there is no such identity provider",
    )
}

impl FederationService {
    /// Wires the use cases to their ports.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        providers: Arc<dyn ProviderStore>,
        links: Arc<dyn LinkStore>,
        secrets: Arc<dyn SecretBox>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            units_of_work,
            providers,
            links,
            secrets,
            clock,
            development_hosts: Arc::from(Vec::new()),
        }
    }

    /// The same use cases, accepting a plain HTTP issuer at these hosts,
    /// each written as `host:port`. For a development stack on one
    /// machine.
    #[must_use]
    pub fn allowing_development_hosts(mut self, hosts: &[String]) -> Self {
        self.development_hosts = Arc::from(hosts.to_vec());
        self
    }

    fn seal(
        &self,
        tenant: &TenantContext,
        secret: &Secret<String>,
    ) -> Result<hodor_kernel::SealedSecret, DomainError> {
        let bytes = secret.expose().as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_SECRET_BYTES {
            return Err(DomainError::invalid(
                "federation.client_secret_invalid",
                "a client secret is 1 to 4096 bytes",
            ));
        }
        self.secrets
            .seal(tenant, CLIENT_SECRET, &Secret::new(bytes.to_vec()))
    }

    /// Adds an identity provider to the tenant, enabled.
    ///
    /// # Errors
    ///
    /// Returns an `Invalid` error if a value breaks its rule, and
    /// `Conflict` if the alias is taken or the tenant has too many
    /// providers.
    pub async fn create_provider(
        &self,
        tenant: &TenantContext,
        command: CreateProvider,
        caller: Caller,
    ) -> Result<IdentityProvider, DomainError> {
        let alias = Alias::parse(&command.alias)?;
        let settings = command.settings.checked_allowing(&self.development_hosts)?;
        let sealed = self.seal(tenant, &command.client_secret)?;
        let provider = IdentityProvider::create(
            alias,
            command.kind,
            settings,
            sealed,
            &self.development_hosts,
            self.clock.now(),
        )?;

        let mut uow = self.units_of_work.begin(tenant).await?;
        if self.providers.list(uow.as_mut()).await?.len() >= MAX_PROVIDERS {
            return Err(DomainError::conflict(
                "federation.too_many_providers",
                "this tenant already has as many identity providers as it may",
            ));
        }
        self.providers.insert(uow.as_mut(), &provider).await?;
        let event = FederationEvent::ProviderCreated {
            provider_id: provider.id(),
            alias: provider.alias().as_str().to_owned(),
            kind: provider.snapshot().kind.as_str(),
        };
        self.record(uow.as_mut(), caller, &event)?;
        uow.commit().await?;
        Ok(provider)
    }

    /// Loads a provider, lets `change` act on it, and stores it with the
    /// event `change` answers with, if any.
    async fn change_with(
        &self,
        tenant: &TenantContext,
        id: ProviderId,
        caller: Caller,
        change: impl FnOnce(&mut IdentityProvider) -> Result<Option<FederationEvent>, DomainError>
        + Send,
    ) -> Result<IdentityProvider, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let mut provider = self
            .providers
            .get(uow.as_mut(), id)
            .await?
            .ok_or_else(provider_not_found)?;
        if let Some(event) = change(&mut provider)? {
            self.providers.update(uow.as_mut(), &provider).await?;
            self.record(uow.as_mut(), caller, &event)?;
            uow.commit().await?;
        }
        Ok(provider)
    }

    /// Changes a provider's settings. Settings equal to the current ones
    /// change nothing and announce nothing.
    ///
    /// # Errors
    ///
    /// Returns `NotFound`, an `Invalid` error if a setting breaks its
    /// rule, or `Conflict` if someone else changed the provider first.
    pub async fn change_provider(
        &self,
        tenant: &TenantContext,
        command: ChangeProvider,
        caller: Caller,
    ) -> Result<IdentityProvider, DomainError> {
        let now = self.clock.now();
        let development_hosts = self.development_hosts.clone();
        self.change_with(tenant, command.id, caller, |provider| {
            Ok(provider
                .change(command.settings, &development_hosts, now)?
                .then(|| FederationEvent::ProviderChanged {
                    provider_id: provider.id(),
                    alias: provider.alias().as_str().to_owned(),
                }))
        })
        .await
    }

    /// Replaces a provider's client secret.
    ///
    /// # Errors
    ///
    /// Returns `NotFound`, `Invalid` for an unusable secret, or
    /// `Conflict` if someone else changed the provider first.
    pub async fn change_provider_secret(
        &self,
        tenant: &TenantContext,
        id: ProviderId,
        client_secret: &Secret<String>,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let sealed = self.seal(tenant, client_secret)?;
        let now = self.clock.now();
        self.change_with(tenant, id, caller, |provider| {
            provider.change_secret(sealed, now);
            Ok(Some(FederationEvent::ProviderSecretChanged {
                provider_id: provider.id(),
                alias: provider.alias().as_str().to_owned(),
            }))
        })
        .await
        .map(|_| ())
    }

    /// Enables or disables a provider. Setting the status it already has
    /// changes nothing and announces nothing.
    ///
    /// # Errors
    ///
    /// Returns `NotFound`, or `Conflict` if someone else changed the
    /// provider first.
    pub async fn set_provider_status(
        &self,
        tenant: &TenantContext,
        id: ProviderId,
        status: ProviderStatus,
        caller: Caller,
    ) -> Result<IdentityProvider, DomainError> {
        let now = self.clock.now();
        self.change_with(tenant, id, caller, |provider| {
            let (provider_id, alias) = (provider.id(), provider.alias().as_str().to_owned());
            let event = match status {
                ProviderStatus::Enabled => FederationEvent::ProviderEnabled { provider_id, alias },
                ProviderStatus::Disabled => {
                    FederationEvent::ProviderDisabled { provider_id, alias }
                }
            };
            Ok(provider.set_status(status, now).then_some(event))
        })
        .await
    }

    /// The provider with this identifier.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the tenant has none.
    pub async fn provider(
        &self,
        tenant: &TenantContext,
        id: ProviderId,
    ) -> Result<IdentityProvider, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.providers
            .get(uow.as_mut(), id)
            .await?
            .ok_or_else(provider_not_found)
    }

    /// The provider with this alias. An alias that could not be one is
    /// answered like one nobody has.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the tenant has none.
    pub async fn provider_by_alias(
        &self,
        tenant: &TenantContext,
        alias: &str,
    ) -> Result<IdentityProvider, DomainError> {
        let alias = Alias::parse(alias).map_err(|_| provider_not_found())?;
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.providers
            .find_by_alias(uow.as_mut(), &alias)
            .await?
            .ok_or_else(provider_not_found)
    }

    /// The tenant's providers, ordered by alias.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn providers(
        &self,
        tenant: &TenantContext,
    ) -> Result<Vec<IdentityProvider>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.providers.list(uow.as_mut()).await
    }

    /// The client secret of a provider, to present to the provider. For
    /// the code that talks to the provider and for nothing else: it is
    /// never returned by an interface.
    ///
    /// # Errors
    ///
    /// Returns `secret.unreadable` if it cannot be opened.
    pub fn client_secret(
        &self,
        tenant: &TenantContext,
        provider: &IdentityProvider,
    ) -> Result<Secret<String>, DomainError> {
        let opened =
            self.secrets
                .open(tenant, CLIENT_SECRET, &provider.snapshot().client_secret)?;
        String::from_utf8(opened.expose().clone())
            .map(Secret::new)
            .map_err(|_| hodor_kernel::sealing::unreadable("the client secret is not text"))
    }

    /// Whose a provider's subject is, if anyone's. Found by the provider
    /// and the subject, and by nothing else.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn find_user(
        &self,
        uow: &mut dyn UnitOfWork,
        provider_id: ProviderId,
        subject: &Subject,
    ) -> Result<Option<UserId>, DomainError> {
        Ok(self
            .links
            .find(uow, provider_id, subject)
            .await?
            .map(|link| link.user_id))
    }

    /// Records that an external identity belongs to a user, in the
    /// caller's unit of work, so that it is stored together with whatever
    /// else the caller is doing, such as creating the user.
    ///
    /// # Errors
    ///
    /// Returns `federation.identity_already_linked` if it already belongs
    /// to anyone, and `NotFound` if the tenant has no such provider.
    pub async fn link(
        &self,
        uow: &mut dyn UnitOfWork,
        provider_id: ProviderId,
        subject: Subject,
        user_id: UserId,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let now = self.clock.now();
        let link = ExternalIdentity {
            provider_id,
            subject,
            user_id,
            linked_at: now,
            last_used_at: now,
        };
        if !self.links.insert(uow, &link).await? {
            return Err(DomainError::conflict(
                "federation.identity_already_linked",
                "this external identity already belongs to a user",
            ));
        }
        self.record(
            uow,
            caller,
            &FederationEvent::IdentityLinked {
                provider_id,
                user_id,
            },
        )
    }

    /// Records that a link just signed its user in.
    ///
    /// # Errors
    ///
    /// Returns `federation.link_not_found` if there is no such link.
    pub async fn mark_used(
        &self,
        uow: &mut dyn UnitOfWork,
        provider_id: ProviderId,
        subject: &Subject,
    ) -> Result<(), DomainError> {
        if self
            .links
            .mark_used(uow, provider_id, subject, self.clock.now())
            .await?
        {
            Ok(())
        } else {
            Err(link_not_found())
        }
    }

    /// The external identities of a user, oldest link first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn links_of(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
    ) -> Result<Vec<ExternalIdentity>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.links.list_for_user(uow.as_mut(), user_id).await
    }

    /// Removes a link.
    ///
    /// # Errors
    ///
    /// Returns `federation.link_not_found` if there is no such link.
    pub async fn unlink(
        &self,
        tenant: &TenantContext,
        provider_id: ProviderId,
        subject: &Subject,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let user_id = self
            .links
            .remove(uow.as_mut(), provider_id, subject)
            .await?
            .ok_or_else(link_not_found)?;
        self.record(
            uow.as_mut(),
            caller,
            &FederationEvent::IdentityUnlinked {
                provider_id,
                user_id,
            },
        )?;
        uow.commit().await
    }

    fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        caller: Caller,
        event: &FederationEvent,
    ) -> Result<(), DomainError> {
        let metadata = EventMetadata::new(
            uow.tenant().tenant_id(),
            caller.actor,
            caller.correlation_id,
            self.clock.as_ref(),
        );
        uow.record_event(EventEnvelope::new(metadata, event)?);
        Ok(())
    }
}

fn link_not_found() -> DomainError {
    DomainError::not_found("federation.link_not_found", "there is no such link")
}
