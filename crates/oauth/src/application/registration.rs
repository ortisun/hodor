//! The use cases of client registration: an administrator's settings and
//! initial access tokens, and the admission the registration endpoint asks
//! for before it registers a client.
//!
//! See `docs/architecture/contexts/oauth.md`, "Client registration".

use crate::application::ports::{
    ApplicationStore, ClientRegistrationStore, InitialAccessTokenStore,
};
use crate::domain::event::OauthEvent;
use crate::domain::initial_access_token::{
    InitialAccessToken, InitialAccessTokenHash, InitialAccessTokenId, InitialAccessTokenValue,
    MAX_ACTIVE_INITIAL_ACCESS_TOKENS, NewInitialAccessToken, token_invalid,
};
use crate::domain::registration::{
    ClientRegistration, RegistrationSettings, RegistrationWay, application_invalid,
};
use hodor_kernel::{
    Caller, Clock, Digest, DomainError, ErrorKind, EventEnvelope, EventMetadata, RandomSource,
    TenantContext, Timestamp, UnitOfWork, UnitOfWorkFactory,
};
use std::fmt;
use std::sync::Arc;

fn token_not_found() -> DomainError {
    DomainError::not_found(
        "oauth.initial_access_token_not_found",
        "there is no such initial access token",
    )
}

/// The refusal of anything of registration while it is off. Its kind is
/// `NotFound`, so that the registration endpoint answers as an address
/// that does not exist.
fn registration_off() -> DomainError {
    DomainError::not_found(
        "oauth.client_registration_off",
        "clients may not register themselves in this tenant",
    )
}

/// The ports [`ClientRegistrationService`] works through.
#[derive(Clone)]
pub struct ClientRegistrationPorts {
    /// Starts units of work.
    pub units_of_work: Arc<dyn UnitOfWorkFactory>,
    /// Stores the settings.
    pub registrations: Arc<dyn ClientRegistrationStore>,
    /// Stores initial access tokens.
    pub tokens: Arc<dyn InitialAccessTokenStore>,
    /// Stores applications, for the one the settings name.
    pub applications: Arc<dyn ApplicationStore>,
    /// SHA-256, for the hash of a token.
    pub digest: Arc<dyn Digest>,
    /// The random bytes of a token.
    pub random: Arc<dyn RandomSource>,
    /// The time.
    pub clock: Arc<dyn Clock>,
}

impl fmt::Debug for ClientRegistrationPorts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientRegistrationPorts")
            .finish_non_exhaustive()
    }
}

/// The settings in force in a tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationInForce {
    /// The settings; the defaults, off, when the tenant never set them.
    pub settings: RegistrationSettings,
    /// When they were last replaced, or `None` when they never were.
    pub updated_at: Option<Timestamp>,
}

impl RegistrationInForce {
    fn of(stored: Option<&ClientRegistration>) -> Self {
        match stored {
            Some(registration) => Self {
                settings: registration.settings().clone(),
                updated_at: Some(registration.snapshot().updated_at),
            },
            None => Self {
                settings: RegistrationSettings::default(),
                updated_at: None,
            },
        }
    }
}

/// How a registration was allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowedBy {
    /// By this initial access token, which it spent one registration of.
    InitialAccessToken(InitialAccessTokenId),
    /// By nobody: the tenant allows open registration.
    Open,
}

/// What [`ClientRegistrationService::admit`] answers: the settings the
/// registration is checked against, and how it was allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission {
    /// The settings in force, the policy among them.
    pub settings: RegistrationSettings,
    /// How it was allowed.
    pub allowed_by: AllowedBy,
}

/// The use cases of client registration.
#[derive(Clone)]
pub struct ClientRegistrationService {
    ports: ClientRegistrationPorts,
}

impl fmt::Debug for ClientRegistrationService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientRegistrationService")
            .finish_non_exhaustive()
    }
}

impl ClientRegistrationService {
    /// Wires the use cases to their ports.
    #[must_use]
    pub const fn new(ports: ClientRegistrationPorts) -> Self {
        Self { ports }
    }

    /// The time now, by the clock the use cases read, for saying where a
    /// token is in its life.
    #[must_use]
    pub fn now(&self) -> Timestamp {
        self.ports.clock.now()
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

    /// The settings in force in the tenant.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn settings(
        &self,
        tenant: &TenantContext,
    ) -> Result<RegistrationInForce, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let stored = self.ports.registrations.get(uow.as_mut()).await?;
        Ok(RegistrationInForce::of(stored.as_ref()))
    }

    /// Replaces the tenant's settings as a whole, every rule checked at
    /// once. Settings equal to the current ones change nothing.
    ///
    /// # Errors
    ///
    /// Returns an `Invalid` error naming the rule broken, among them
    /// `oauth.client_registration_application_invalid` for an application
    /// that is not one of the tenant's or is first party, or
    /// `oauth.client_registration_modified_concurrently`.
    pub async fn replace(
        &self,
        tenant: &TenantContext,
        settings: RegistrationSettings,
        caller: Caller,
    ) -> Result<RegistrationInForce, DomainError> {
        let settings = settings.checked()?;
        let now = self.ports.clock.now();
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        if let Some(id) = settings.application_id {
            let application = self
                .ports
                .applications
                .get(uow.as_mut(), id)
                .await?
                .ok_or_else(|| application_invalid("the tenant has no such application"))?;
            if application.snapshot().settings.first_party {
                return Err(application_invalid(
                    "the application is first party, and a registered client never is",
                ));
            }
        }
        let (registration, event) = match self.ports.registrations.get(uow.as_mut()).await? {
            None => {
                let (registration, event) = ClientRegistration::create(settings, now)?;
                self.ports
                    .registrations
                    .insert(uow.as_mut(), &registration)
                    .await?;
                (registration, Some(event))
            }
            Some(mut registration) => {
                let event = registration.replace(settings, now)?;
                if event.is_some() {
                    self.ports
                        .registrations
                        .update(uow.as_mut(), &registration)
                        .await?;
                }
                (registration, event)
            }
        };
        if let Some(event) = event {
            self.record(uow.as_mut(), caller, &event)?;
            uow.commit().await?;
        }
        Ok(RegistrationInForce::of(Some(&registration)))
    }

    /// Makes an initial access token, returned once with the token itself.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_registration_off` while registration is off,
    /// `oauth.initial_access_tokens_not_allowed` when it does not allow
    /// tokens, `oauth.too_many_initial_access_tokens` for a hundred and
    /// first active token, or an `Invalid` error for a name, a lifetime or
    /// a number of registrations that breaks its rule.
    pub async fn issue_token(
        &self,
        tenant: &TenantContext,
        new: NewInitialAccessToken,
        caller: Caller,
    ) -> Result<(InitialAccessToken, InitialAccessTokenValue), DomainError> {
        let now = self.ports.clock.now();
        let (token, value, event) = InitialAccessToken::create(
            new,
            now,
            self.ports.random.as_ref(),
            self.ports.digest.as_ref(),
        )?;
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        // The settings' row stays locked until the token is stored, so
        // that two tokens made at once cannot pass the bound together, and
        // a token is never made just as registration is turned off.
        let settings =
            RegistrationInForce::of(self.ports.registrations.lock(uow.as_mut()).await?.as_ref())
                .settings;
        if !settings.enabled {
            return Err(DomainError::conflict(
                "oauth.client_registration_off",
                "registration is off in this tenant, so no initial access token can be made",
            ));
        }
        if !settings.allows(RegistrationWay::InitialAccessToken) {
            return Err(DomainError::conflict(
                "oauth.initial_access_tokens_not_allowed",
                "this tenant's registration does not allow initial access tokens",
            ));
        }
        if self.ports.tokens.count_active(uow.as_mut(), now).await?
            >= MAX_ACTIVE_INITIAL_ACCESS_TOKENS
        {
            return Err(DomainError::conflict(
                "oauth.too_many_initial_access_tokens",
                "this tenant already holds as many active initial access tokens as it may",
            ));
        }
        self.ports.tokens.insert(uow.as_mut(), &token).await?;
        self.record(uow.as_mut(), caller, &event)?;
        uow.commit().await?;
        Ok((token, value))
    }

    /// Revokes a token at once. Revoking a revoked token changes nothing.
    ///
    /// # Errors
    ///
    /// Returns `oauth.initial_access_token_not_found` if the tenant has no
    /// such token.
    pub async fn revoke_token(
        &self,
        tenant: &TenantContext,
        id: InitialAccessTokenId,
        caller: Caller,
    ) -> Result<InitialAccessToken, DomainError> {
        let now = self.ports.clock.now();
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let mut token = self
            .ports
            .tokens
            .get(uow.as_mut(), id)
            .await?
            .ok_or_else(token_not_found)?;
        if let Some(event) = token.revoke(now)
            && self.ports.tokens.revoke(uow.as_mut(), id, now).await?
        {
            self.record(uow.as_mut(), caller, &event)?;
            uow.commit().await?;
        }
        Ok(token)
    }

    /// A token of the tenant; never the token itself.
    ///
    /// # Errors
    ///
    /// Returns `oauth.initial_access_token_not_found` if the tenant has no
    /// such token.
    pub async fn token(
        &self,
        tenant: &TenantContext,
        id: InitialAccessTokenId,
    ) -> Result<InitialAccessToken, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        self.ports
            .tokens
            .get(uow.as_mut(), id)
            .await?
            .ok_or_else(token_not_found)
    }

    /// Every token of the tenant, newest first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn tokens(
        &self,
        tenant: &TenantContext,
    ) -> Result<Vec<InitialAccessToken>, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        self.ports.tokens.list(uow.as_mut()).await
    }

    /// The settings in force, with their row locked until the unit of work
    /// ends: what the registration endpoint takes first in the unit of work
    /// that stores a registration, so that its bounds are counted while no
    /// other registration of the tenant is stored.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn lock_settings(
        &self,
        uow: &mut dyn UnitOfWork,
    ) -> Result<RegistrationSettings, DomainError> {
        Ok(RegistrationInForce::of(self.ports.registrations.lock(uow).await?.as_ref()).settings)
    }

    /// Decides whether a registration may go ahead without spending
    /// anything: the token found and good, or open registration.
    async fn decide(
        &self,
        uow: &mut dyn UnitOfWork,
        presented: Option<&str>,
    ) -> Result<(RegistrationSettings, Option<InitialAccessToken>), DomainError> {
        let settings =
            RegistrationInForce::of(self.ports.registrations.get(uow).await?.as_ref()).settings;
        if !settings.enabled {
            return Err(registration_off());
        }
        let Some(presented) = presented else {
            if settings.allows(RegistrationWay::Open) {
                return Ok((settings, None));
            }
            return Err(DomainError::new(
                ErrorKind::Unauthenticated,
                "oauth.initial_access_token_required",
                "this tenant's registration needs an initial access token",
            ));
        };
        if !settings.allows(RegistrationWay::InitialAccessToken) {
            return Err(token_invalid());
        }
        let hash = InitialAccessTokenHash::of_presented(presented, self.ports.digest.as_ref())
            .ok_or_else(token_invalid)?;
        let token = self
            .ports
            .tokens
            .lock_by_hash(uow, &hash)
            .await?
            .ok_or_else(token_invalid)?;
        if !token.is_active(self.ports.clock.now()) {
            return Err(token_invalid());
        }
        Ok((settings, Some(token)))
    }

    /// Whether a registration would be admitted, spending nothing and
    /// recording nothing: what the registration endpoint asks before it
    /// calls any address a registration names, in a unit of work it never
    /// commits. Answers the settings in force.
    ///
    /// # Errors
    ///
    /// As [`Self::admit`].
    pub async fn may_register(
        &self,
        uow: &mut dyn UnitOfWork,
        presented: Option<&str>,
    ) -> Result<RegistrationSettings, DomainError> {
        self.decide(uow, presented)
            .await
            .map(|(settings, _)| settings)
    }

    /// Whether a registration may go ahead, for the registration endpoint,
    /// inside the unit of work in which it registers the client, so that a
    /// registration refused afterwards spends nothing. `presented` is the
    /// bearer token of the request, if it carries one: a request that
    /// carries one is allowed by that token or by nothing.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_registration_off`, a `NotFound` error, while
    /// registration is off; `oauth.initial_access_token_invalid` for a
    /// token that is not good in this tenant, whatever the reason, or one
    /// presented where registration does not allow tokens; and
    /// `oauth.initial_access_token_required` for a request without one
    /// where registration is not open. The last two are `Unauthenticated`.
    pub async fn admit(
        &self,
        uow: &mut dyn UnitOfWork,
        presented: Option<&str>,
        caller: Caller,
    ) -> Result<Admission, DomainError> {
        let (settings, token) = self.decide(uow, presented).await?;
        let Some(mut token) = token else {
            return Ok(Admission {
                settings,
                allowed_by: AllowedBy::Open,
            });
        };
        let event = token.spend(self.ports.clock.now())?;
        self.ports.tokens.record_use(uow, &token).await?;
        self.record(uow, caller, &event)?;
        Ok(Admission {
            settings,
            allowed_by: AllowedBy::InitialAccessToken(token.id()),
        })
    }
}
