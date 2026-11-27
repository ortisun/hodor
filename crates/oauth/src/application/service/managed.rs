//! Managing a registration (RFC 7592): a registered client reads, changes
//! and removes itself with its registration access token.
//!
//! See `docs/architecture/contexts/oauth.md`, "Managing a registration",
//! and Decision 0084.

use super::ApplicationService;
use super::registered::check_against;
use crate::application::registration::ClientRegistrationService;
use crate::domain::client::{Client, ClientId};
use crate::domain::client_metadata::{
    client_secret_mismatch, has_software_statement, read_change, read_client_metadata,
    software_statement_unapproved,
};
use crate::domain::event::OauthEvent;
use crate::domain::key::ClientKey;
use crate::domain::registration::RegistrationSettings;
use crate::domain::registration_token::RegistrationAccessTokenValue;
use crate::domain::secret::ClientSecretValue;
use hodor_kernel::{Caller, DomainError, ErrorKind, TenantContext, UnitOfWork};

/// Which registration a request names, and the token it presents.
#[derive(Clone)]
pub struct ManageRegistration {
    /// The client of the address, or `None` when the address names nothing
    /// that could be a client.
    pub client_id: Option<ClientId>,
    /// The bearer token of the request, if it carries one.
    pub access_token: Option<String>,
}

impl std::fmt::Debug for ManageRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the token.
        f.debug_struct("ManageRegistration")
            .field("client_id", &self.client_id)
            .field("carries_token", &self.access_token.is_some())
            .finish()
    }
}

/// A change of a registration: which one, and the client's metadata.
#[derive(Debug, Clone)]
pub struct ChangeRegistration {
    /// The registration and the token.
    pub registration: ManageRegistration,
    /// The body: the client's metadata, as JSON.
    pub body: serde_json::Value,
}

/// A registration changed, with what the client is given once.
#[derive(Debug)]
pub struct ChangedRegistration {
    /// The client, as stored.
    pub client: Client,
    /// A first secret, when the change moved the client to a method that
    /// takes one and it held none that worked.
    pub secret: Option<ClientSecretValue>,
    /// Its new registration access token; the one it was changed with no
    /// longer works.
    pub access_token: RegistrationAccessTokenValue,
}

fn token_required() -> DomainError {
    DomainError::new(
        ErrorKind::Unauthenticated,
        "oauth.registration_access_token_required",
        "managing a registration takes its registration access token",
    )
}

fn token_invalid() -> DomainError {
    DomainError::new(
        ErrorKind::Unauthenticated,
        "oauth.registration_access_token_invalid",
        "the registration access token is not good for this registration",
    )
}

fn modified() -> DomainError {
    DomainError::conflict(
        "oauth.client_modified_concurrently",
        "the client was changed while the change of its registration was checked; send it again",
    )
}

impl ApplicationService {
    /// Admits a request at a registration client address, inside `uow`:
    /// registration is on, and the token is the one the client of the
    /// address holds. With `lock`, the client's row stays locked until the
    /// unit of work ends. Every way the token can fail is one refusal.
    async fn admit_management(
        &self,
        registration: &ClientRegistrationService,
        uow: &mut dyn UnitOfWork,
        request: &ManageRegistration,
        lock: bool,
    ) -> Result<(RegistrationSettings, Client), DomainError> {
        let settings = registration.may_manage(uow).await?;
        let Some(presented) = request.access_token.as_deref() else {
            return Err(token_required());
        };
        let Some(id) = request.client_id else {
            return Err(token_invalid());
        };
        let client = if lock {
            self.clients.lock(uow, id).await?
        } else {
            self.clients.get(uow, id).await?
        };
        match client {
            Some(client) if client.accepts_registration_token(presented, self.digest.as_ref()) => {
                Ok((settings, client))
            }
            _ => Err(token_invalid()),
        }
    }

    /// Reads a registration. The client is answered with the token it was
    /// sent, which is its current one; nothing is replaced or recorded.
    ///
    /// # Errors
    ///
    /// `oauth.client_registration_off` (`NotFound`) while registration is
    /// off, and `oauth.registration_access_token_required` or
    /// `oauth.registration_access_token_invalid` (`Unauthenticated`).
    pub async fn read_registration(
        &self,
        registration: &ClientRegistrationService,
        tenant: &TenantContext,
        request: &ManageRegistration,
    ) -> Result<Client, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let (_, client) = self
            .admit_management(registration, uow.as_mut(), request, false)
            .await?;
        Ok(client)
    }

    /// Changes a registration, as `docs/architecture/contexts/oauth.md`,
    /// "Changing", says: admitted, the body read as a registration and
    /// checked as an administrator's change and against the policy, the
    /// new addresses Hodor calls checked, then stored under a lock of the
    /// client's row with a new registration access token.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::read_registration`], and those of a
    /// registration's members and of the policy;
    /// `oauth.registration_client_id_mismatch`,
    /// `oauth.registration_client_secret_mismatch`,
    /// `oauth.software_statement_unapproved`; `Unauthenticated` when the
    /// token was replaced by another change in the meantime, and
    /// `oauth.client_modified_concurrently` when an administrator changed
    /// the client.
    pub async fn change_registration(
        &self,
        registration: &ClientRegistrationService,
        tenant: &TenantContext,
        command: ChangeRegistration,
        caller: Caller,
    ) -> Result<ChangedRegistration, DomainError> {
        let now = self.clock.now();
        // Admitted in a unit of work that is dropped: nothing is read of
        // the body, and nothing called, for a request without a good token.
        let (settings, current) = {
            let mut uow = self.units_of_work.begin(tenant).await?;
            self.admit_management(registration, uow.as_mut(), &command.registration, false)
                .await?
        };

        if has_software_statement(&command.body) {
            return Err(software_statement_unapproved());
        }
        if let Some(secret) = read_change(&command.body, current.id())?
            && !current.accepts_secret(&secret, self.digest.as_ref(), now)
        {
            return Err(client_secret_mismatch());
        }
        let metadata = read_client_metadata(&command.body, &settings.policy)?;
        let before = &current.snapshot().settings;
        let mut settings_asked = metadata.settings;
        // What a registration never sets stays as it is.
        settings_asked.token_policy = before.token_policy;
        settings_asked.require_pkce = before.require_pkce;
        settings_asked.principal = before.principal;
        settings_asked
            .exchange_rules
            .clone_from(&before.exchange_rules);
        settings_asked.spiffe_id.clone_from(&before.spiffe_id);
        settings_asked
            .linkerd_identity
            .clone_from(&before.linkerd_identity);
        let keys = metadata
            .keys
            .iter()
            .map(|jwk| ClientKey::parse(jwk, now))
            .collect::<Result<Vec<_>, _>>()?;
        let mut client = current.clone();
        let mut events = client.change_registration(settings_asked, keys, now)?;
        check_against(&settings, &client)?;

        // Only now that the token is good are the new addresses called.
        self.check_changed_addresses(before, &client.snapshot().settings)
            .await?;

        let mut uow = self.units_of_work.begin(tenant).await?;
        // The row stays locked until the change is stored: a second change
        // with the same token waits here, then finds it replaced.
        let (settings, locked) = self
            .admit_management(registration, uow.as_mut(), &command.registration, true)
            .await?;
        if locked.snapshot().version != current.snapshot().version {
            return Err(modified());
        }
        check_against(&settings, &client)?;
        let secret = match client.ensure_secret(now, self.random.as_ref(), self.digest.as_ref())? {
            Some((secret, event)) => {
                events.push(event);
                Some(secret)
            }
            None => None,
        };
        let access_token =
            client.issue_registration_token(self.random.as_ref(), self.digest.as_ref())?;
        self.clients.update(uow.as_mut(), &client).await?;
        events.push(OauthEvent::RegisteredClientChanged {
            client_id: client.id(),
            application_id: client.application_id(),
        });
        self.record(uow.as_mut(), caller, &events)?;
        uow.commit().await?;
        Ok(ChangedRegistration {
            client,
            secret,
            access_token,
        })
    }

    /// Removes a registration: the client is deleted, with everything
    /// stored that names it, in one unit of work under a lock of its row.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::read_registration`]; a client removed already
    /// is unknown, and so `Unauthenticated`.
    pub async fn remove_registration(
        &self,
        registration: &ClientRegistrationService,
        tenant: &TenantContext,
        request: &ManageRegistration,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let (_, client) = self
            .admit_management(registration, uow.as_mut(), request, true)
            .await?;
        if !self.clients.delete(uow.as_mut(), client.id()).await? {
            return Err(token_invalid());
        }
        self.record(
            uow.as_mut(),
            caller,
            &[OauthEvent::RegisteredClientRemoved {
                client_id: client.id(),
                application_id: client.application_id(),
            }],
        )?;
        uow.commit().await
    }
}
