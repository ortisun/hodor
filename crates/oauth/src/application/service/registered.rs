//! The registration endpoint's use case: a client that registers itself.
//!
//! See `docs/architecture/contexts/oauth.md`, "The registration endpoint",
//! and Decision 0080.

use super::ApplicationService;
use crate::application::registration::{AllowedBy, ClientRegistrationService};
use crate::domain::client::{Client, SelfRegistration};
use crate::domain::client_metadata::{
    has_software_statement, read_client_metadata, software_statement_unapproved,
};
use crate::domain::event::OauthEvent;
use crate::domain::key::ClientKey;
use crate::domain::pairwise::SubjectType;
use crate::domain::registration::{
    RegistrationRequest, RegistrationSettings, RegistrationWay, check_redirect_hosts,
    check_registration,
};
use crate::domain::secret::{ClientSecret, ClientSecretValue};
use hodor_kernel::{Caller, DomainError, ErrorKind, TenantContext, Timestamp, UnitOfWork};
use time::Duration;

/// The most clients one address may register in a tenant within
/// [`REGISTRATION_WINDOW`].
pub const MOST_REGISTRATIONS_PER_ADDRESS: usize = 10;

/// The window the registrations of an address are counted in.
pub const REGISTRATION_WINDOW: Duration = Duration::seconds(60);

/// What the registration endpoint was sent.
#[derive(Clone)]
pub struct RegisterClient {
    /// The body: the client's metadata, as JSON.
    pub body: serde_json::Value,
    /// The bearer token of the request, if it carries one.
    pub initial_access_token: Option<String>,
    /// The SHA-256 of the address the request came from, if it is known.
    pub address_hash: Option<[u8; 32]>,
}

impl std::fmt::Debug for RegisterClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the token.
        f.debug_struct("RegisterClient")
            .field("carries_token", &self.initial_access_token.is_some())
            .finish_non_exhaustive()
    }
}

fn too_many_registrations() -> DomainError {
    DomainError::new(
        ErrorKind::RateLimited,
        "oauth.too_many_registrations",
        "this address registered as many clients as it may in a minute; try again later",
    )
    .with_retry_after(60)
}

fn too_many_registered_clients() -> DomainError {
    DomainError::new(
        ErrorKind::Forbidden,
        "oauth.too_many_registered_clients",
        "the application of registered clients holds as many clients as it may",
    )
}

/// Every address a registration names, whatever its member, for the
/// policy's hosts.
fn addresses_of(client: &Client) -> Vec<&str> {
    let settings = &client.snapshot().settings;
    settings
        .redirect_uris
        .iter()
        .chain(&settings.post_logout_redirect_uris)
        .chain(&settings.request_uris)
        .map(String::as_str)
        .chain(settings.backchannel_logout_uri.as_deref())
        .chain(settings.jwks_uri.as_deref())
        .chain(settings.sector_identifier_uri.as_deref())
        .chain(settings.display_uris().into_iter().map(|(_, uri)| uri))
        .collect()
}

/// Checks what a client names against the tenant's policy, the hosts of
/// its redirect addresses first.
fn check_against(settings: &RegistrationSettings, client: &Client) -> Result<(), DomainError> {
    let checked = &client.snapshot().settings;
    check_redirect_hosts(&settings.policy, &checked.redirect_uris)?;
    check_registration(
        &settings.policy,
        &RegistrationRequest {
            grant_types: &checked.grant_types,
            response_types: &checked.response_types,
            scopes: &checked.allowed_scopes,
            authentication_method: checked.authentication_method,
            subject_type: checked.subject_type,
            addresses: &addresses_of(client),
        },
    )
}

impl ApplicationService {
    /// Fewer than [`MOST_REGISTRATIONS_PER_ADDRESS`] clients registered
    /// from this address within the window ending `now`.
    async fn check_registrations_from(
        &self,
        uow: &mut dyn UnitOfWork,
        address_hash: Option<&[u8; 32]>,
        now: Timestamp,
    ) -> Result<(), DomainError> {
        let since = now - REGISTRATION_WINDOW;
        if self
            .clients
            .count_registered_since(uow, address_hash, since)
            .await?
            >= MOST_REGISTRATIONS_PER_ADDRESS
        {
            return Err(too_many_registrations());
        }
        Ok(())
    }

    /// Registers a client at the registration endpoint, as
    /// `docs/architecture/contexts/oauth.md`, "What a registration goes
    /// through", says: admitted without spending, read and checked as an
    /// administrator's client and against the policy, its addresses checked
    /// by the guarded outbound client, then stored under the bounds, its
    /// initial access token spent in the same unit of work. Returns the
    /// client and its first secret, once, if its method takes one.
    ///
    /// # Errors
    ///
    /// `oauth.client_registration_off` (`NotFound`),
    /// `oauth.initial_access_token_required` and
    /// `oauth.initial_access_token_invalid` (`Unauthenticated`),
    /// `oauth.too_many_registrations` (`RateLimited`),
    /// `oauth.software_statement_unapproved`,
    /// `oauth.client_metadata_invalid`,
    /// `oauth.registration_member_not_supported`, every `Invalid` error of
    /// a client's settings and keys and of the policy,
    /// `oauth.too_many_registered_clients` (`Forbidden`), and
    /// `oauth.client_registration_modified_concurrently` when the settings
    /// changed their application while the registration was checked.
    pub async fn register_client(
        &self,
        registration: &ClientRegistrationService,
        tenant: &TenantContext,
        command: RegisterClient,
        caller: Caller,
    ) -> Result<(Client, Option<ClientSecretValue>), DomainError> {
        let presented = command.initial_access_token.as_deref();
        let address = command.address_hash.as_ref();
        let now = self.clock.now();

        // Admitted, spending nothing, in a unit of work that is dropped
        // without being committed: nothing is called for a caller who may
        // not register.
        let settings = {
            let mut uow = self.units_of_work.begin(tenant).await?;
            let settings = registration.may_register(uow.as_mut(), presented).await?;
            self.check_registrations_from(uow.as_mut(), address, now)
                .await?;
            settings
        };
        let Some(application_id) = settings.application_id else {
            return Err(DomainError::internal(
                "oauth.client_registration_application_missing",
                "registration is on and names no application",
            ));
        };

        if has_software_statement(&command.body) {
            return Err(software_statement_unapproved());
        }
        let metadata = read_client_metadata(&command.body, &settings.policy)?;
        let (mut client, secret) = Client::create(
            application_id,
            metadata.client_type,
            metadata.settings,
            ClientSecret::DEFAULT_LIFETIME,
            now,
            self.random.as_ref(),
            self.digest.as_ref(),
        )?;
        let mut events = client.created_events();
        for jwk in &metadata.keys {
            let key = ClientKey::parse(jwk, now)?;
            events.push(client.add_key(key, now)?);
        }
        let client = client.registered_from(SelfRegistration {
            address_hash: command.address_hash,
        });
        check_against(&settings, &client)?;

        // Only now that the caller may register are its addresses called.
        if let Some(url) = client.backchannel_logout_uri() {
            self.check_backchannel_address(url).await?;
        }
        if let Some(url) = client.jwks_uri() {
            self.check_jwks_address(url).await?;
        }
        let checked = &client.snapshot().settings;
        self.check_request_addresses(&checked.request_uris.iter().collect::<Vec<_>>())
            .await?;
        if checked.subject_type == SubjectType::Pairwise {
            self.check_sector_address(checked).await?;
        }

        let mut uow = self.units_of_work.begin(tenant).await?;
        // The settings stay locked until the client is stored, so that two
        // registrations at once cannot pass a bound together.
        let locked = registration.lock_settings(uow.as_mut()).await?;
        if locked.enabled {
            if locked.application_id != Some(application_id) {
                return Err(DomainError::conflict(
                    "oauth.client_registration_modified_concurrently",
                    "the registration settings changed while the registration was checked",
                ));
            }
            check_against(&locked, &client)?;
            if self
                .clients
                .count_for_application(uow.as_mut(), application_id)
                .await?
                >= usize::try_from(locked.max_clients).unwrap_or(usize::MAX)
            {
                return Err(too_many_registered_clients());
            }
            self.check_registrations_from(uow.as_mut(), address, now)
                .await?;
        }
        // Refuses registration turned off since, and spends the token.
        let admission = registration.admit(uow.as_mut(), presented, caller).await?;
        self.clients.insert(uow.as_mut(), &client).await?;
        let (way, token_id) = match admission.allowed_by {
            AllowedBy::InitialAccessToken(id) => {
                (RegistrationWay::InitialAccessToken.as_str(), Some(id))
            }
            AllowedBy::Open => (RegistrationWay::Open.as_str(), None),
        };
        events.push(OauthEvent::ClientRegistered {
            client_id: client.id(),
            application_id,
            way,
            token_id,
        });
        self.record(uow.as_mut(), caller, &events)?;
        uow.commit().await?;
        Ok((client, secret))
    }
}
