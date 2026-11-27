//! The use cases of applications, clients and resource servers.

use crate::application::ports::{ApplicationStore, ClientStore, ResourceServerStore};
use crate::domain::application::{
    Application, ApplicationId, ApplicationSettings, MAX_APPLICATIONS, Status,
};
use crate::domain::client::{Client, ClientId, ClientSettings, ClientType, MAX_CLIENTS};
use crate::domain::event::OauthEvent;
use crate::domain::forwarded::WorkloadIdentity;
use crate::domain::key::ClientKey;
use crate::domain::pairwise::{
    MAX_SECTOR_DOCUMENT_BYTES, SECTOR_DOCUMENT_TIME_LIMIT, SubjectType, check_sector_document,
};
use crate::domain::resource_server::{
    Audience, ResourceServer, ResourceServerId, ResourceServerSettings,
};
use crate::domain::secret::{ClientSecret, ClientSecretId, ClientSecretValue};
use hodor_kernel::{
    Caller, Clock, DestinationCheck, Digest, DomainError, EventEnvelope, EventMetadata, HttpClient,
    HttpRequest, RandomSource, TenantContext, UnitOfWork, UnitOfWorkFactory, UserId,
};
use std::sync::Arc;
use time::Duration;

/// What is needed to create a client.
#[derive(Debug, Clone)]
pub struct CreateClient {
    /// The application it belongs to.
    pub application_id: ApplicationId,
    /// Whether it can keep a secret. Never changes.
    pub client_type: ClientType,
    /// What an administrator decided about it.
    pub settings: ClientSettings,
    /// How long its first secret lives, if it gets one; a year unless
    /// given.
    pub secret_lifetime: Option<Duration>,
}

/// What is needed to give a client a new secret.
#[derive(Debug, Clone, Copy)]
pub struct RotateSecret {
    /// How long the new secret lives.
    pub lifetime: Duration,
    /// How much longer the newest previous secret keeps working.
    pub keep_previous_for: Duration,
}

/// What is needed to register a resource server.
#[derive(Debug, Clone)]
pub struct CreateResourceServer {
    /// The application that exposes it.
    pub application_id: ApplicationId,
    /// The audience of its tokens, as given.
    pub audience: String,
    /// Its name and scopes.
    pub settings: ResourceServerSettings,
}

/// A client, its application and that application's resource server,
/// read together: what a resource server of Hodor's checks of the client a
/// token was issued to.
#[derive(Debug, Clone)]
pub struct ClientWithApplication {
    /// The client.
    pub client: Client,
    /// Its application, if the tenant still has it.
    pub application: Option<Application>,
    /// The application's resource server, if it has one.
    pub resource_server: Option<ResourceServer>,
}

fn application_not_found() -> DomainError {
    DomainError::not_found(
        "oauth.application_not_found",
        "there is no such application",
    )
}

/// What the guarded client said of a back-channel logout address, in the
/// OAuth context's words.
fn refused_address(error: DomainError) -> DomainError {
    match error.code() {
        "http.url_invalid" => DomainError::invalid(
            "oauth.client_backchannel_logout_uri_invalid",
            "a back-channel logout address is an HTTPS address of at most 2000 characters, with \
             a host and without a name and password or a fragment",
        ),
        "http.destination_forbidden" => DomainError::invalid(
            "oauth.client_backchannel_logout_uri_forbidden",
            "the address leads somewhere Hodor may not call: it must be public",
        ),
        "http.unreachable" => DomainError::invalid(
            "oauth.client_backchannel_logout_uri_unresolvable",
            "the address's name does not resolve to any address",
        ),
        _ => error,
    }
}

/// What the guarded client's check said of a sector identifier address,
/// in the OAuth context's words.
fn refused_sector_address(error: DomainError) -> DomainError {
    match error.code() {
        "http.url_invalid" => crate::domain::pairwise::sector_uri_invalid(
            "the guarded client cannot call the address",
        ),
        "http.destination_forbidden" => sector_forbidden(),
        "http.unreachable" => DomainError::invalid(
            "oauth.client_sector_identifier_uri_unresolvable",
            "the address's name does not resolve to any address",
        ),
        _ => error,
    }
}

/// What fetching a sector identifier document failed with, in the OAuth
/// context's words.
fn refused_sector_fetch(error: DomainError) -> DomainError {
    match error.code() {
        "http.url_invalid" => crate::domain::pairwise::sector_uri_invalid(
            "the guarded client cannot call the address",
        ),
        "http.destination_forbidden" => sector_forbidden(),
        _ => sector_unreachable(),
    }
}

/// What the guarded client said of a request object address, in the
/// OAuth context's words.
fn refused_request_address(error: DomainError) -> DomainError {
    match error.code() {
        "http.url_invalid" => crate::domain::request_uri::request_uri_invalid(
            "the guarded client cannot call the address",
        ),
        "http.destination_forbidden" => request_address_forbidden(),
        "http.unreachable" => DomainError::invalid(
            "oauth.client_request_uri_unresolvable",
            "the address's name does not resolve to any address",
        ),
        _ => error,
    }
}

fn request_address_forbidden() -> DomainError {
    DomainError::invalid(
        "oauth.client_request_uri_forbidden",
        "the address leads somewhere Hodor may not call: it must be public",
    )
}

/// What the guarded client said of a key set address, in the OAuth
/// context's words.
fn refused_jwks_address(error: DomainError) -> DomainError {
    match error.code() {
        "http.url_invalid" => DomainError::invalid(
            "oauth.client_jwks_uri_invalid",
            "a key set address is an HTTPS address of at most 2000 characters, with a host and \
             without a name and password or a fragment, for a client using `private_key_jwt` only",
        )
        .with_detail("the guarded client cannot call the address"),
        "http.destination_forbidden" => jwks_address_forbidden(),
        "http.unreachable" => DomainError::invalid(
            "oauth.client_jwks_uri_unresolvable",
            "the address's name does not resolve to any address",
        ),
        _ => error,
    }
}

fn jwks_address_forbidden() -> DomainError {
    DomainError::invalid(
        "oauth.client_jwks_uri_forbidden",
        "the address leads somewhere Hodor may not call: it must be public",
    )
}

fn sector_forbidden() -> DomainError {
    DomainError::invalid(
        "oauth.client_sector_identifier_uri_forbidden",
        "the address leads somewhere Hodor may not call: it must be public",
    )
}

fn sector_unreachable() -> DomainError {
    DomainError::invalid(
        "oauth.client_sector_identifier_uri_unreachable",
        "the sector identifier address did not answer its document: no answer in 10 seconds, a \
         status other than 2xx, or more than 64 kibibytes",
    )
}

fn client_not_found() -> DomainError {
    DomainError::not_found("oauth.client_not_found", "there is no such client")
}

fn resource_server_not_found() -> DomainError {
    DomainError::not_found(
        "oauth.resource_server_not_found",
        "there is no such resource server",
    )
}

/// The use cases of applications, clients and resource servers.
#[derive(Clone)]
pub struct ApplicationService {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    applications: Arc<dyn ApplicationStore>,
    clients: Arc<dyn ClientStore>,
    resource_servers: Arc<dyn ResourceServerStore>,
    digest: Arc<dyn Digest>,
    random: Arc<dyn RandomSource>,
    clock: Arc<dyn Clock>,
    destinations: Option<Arc<dyn DestinationCheck>>,
    sector_documents: Option<Arc<dyn HttpClient>>,
}

impl std::fmt::Debug for ApplicationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApplicationService").finish_non_exhaustive()
    }
}

/// The ports [`ApplicationService`] works through.
#[derive(Clone)]
pub struct ApplicationPorts {
    /// Starts units of work.
    pub units_of_work: Arc<dyn UnitOfWorkFactory>,
    /// Stores applications.
    pub applications: Arc<dyn ApplicationStore>,
    /// Stores clients.
    pub clients: Arc<dyn ClientStore>,
    /// Stores resource servers.
    pub resource_servers: Arc<dyn ResourceServerStore>,
    /// SHA-256.
    pub digest: Arc<dyn Digest>,
    /// The random bytes of secrets.
    pub random: Arc<dyn RandomSource>,
    /// The time.
    pub clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for ApplicationPorts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApplicationPorts").finish_non_exhaustive()
    }
}

impl ApplicationService {
    /// Wires the use cases to their ports.
    #[must_use]
    pub fn new(ports: ApplicationPorts) -> Self {
        Self {
            units_of_work: ports.units_of_work,
            applications: ports.applications,
            clients: ports.clients,
            resource_servers: ports.resource_servers,
            digest: ports.digest,
            random: ports.random,
            clock: ports.clock,
            destinations: None,
            sector_documents: None,
        }
    }

    /// Checks back-channel logout addresses through `destinations`, the
    /// guarded outbound client, when they are set. Without it, no client
    /// can be given one.
    #[must_use]
    pub fn with_destinations(mut self, destinations: Arc<dyn DestinationCheck>) -> Self {
        self.destinations = Some(destinations);
        self
    }

    /// Fetches sector identifier addresses through `http`, the guarded
    /// outbound client, when they are set. Without it, no client can be
    /// given one.
    #[must_use]
    pub fn with_sector_documents(mut self, http: Arc<dyn HttpClient>) -> Self {
        self.sector_documents = Some(http);
        self
    }

    /// Checks a pairwise client's sector identifier address and fetches its
    /// document, which must list every redirect address of the client. See
    /// `docs/architecture/contexts/oauth.md`, "The sector identifier
    /// address".
    async fn check_sector_address(&self, settings: &ClientSettings) -> Result<(), DomainError> {
        let Some(url) = settings.sector_identifier_uri.as_deref() else {
            return Ok(());
        };
        let (Some(destinations), Some(http)) = (&self.destinations, &self.sector_documents) else {
            return Err(DomainError::invalid(
                "oauth.client_sector_identifier_uri_forbidden",
                "this installation cannot fetch a sector identifier address, so it accepts none",
            ));
        };
        destinations
            .check(url)
            .await
            .map_err(refused_sector_address)?;
        let request = HttpRequest::get(url)
            .header("accept", "application/json")
            .within(SECTOR_DOCUMENT_TIME_LIMIT);
        let response = http.send(request).await.map_err(refused_sector_fetch)?;
        if !response.is_success() || response.body.len() > MAX_SECTOR_DOCUMENT_BYTES {
            return Err(sector_unreachable());
        }
        check_sector_document(&response.body, &settings.redirect_uris)
    }

    /// Whether each of `addresses`, request object addresses new to a
    /// client, could be called now. See `docs/architecture/contexts/oauth.md`,
    /// "Request object addresses".
    async fn check_request_addresses(&self, addresses: &[&String]) -> Result<(), DomainError> {
        if addresses.is_empty() {
            return Ok(());
        }
        let Some(destinations) = &self.destinations else {
            return Err(request_address_forbidden());
        };
        for address in addresses {
            destinations
                .check(address)
                .await
                .map_err(refused_request_address)?;
        }
        Ok(())
    }

    /// Whether a key set address could be called now. Nothing is fetched:
    /// a client may publish its keys after it is saved. See
    /// `docs/architecture/contexts/oauth.md`, "Keys at the client's
    /// address".
    async fn check_jwks_address(&self, url: &str) -> Result<(), DomainError> {
        let Some(destinations) = &self.destinations else {
            return Err(jwks_address_forbidden());
        };
        destinations.check(url).await.map_err(refused_jwks_address)
    }

    /// Whether a back-channel logout address could be called now. See
    /// `docs/architecture/contexts/oauth.md`, "The back-channel logout
    /// address".
    async fn check_backchannel_address(&self, url: &str) -> Result<(), DomainError> {
        let Some(destinations) = &self.destinations else {
            return Err(DomainError::invalid(
                "oauth.client_backchannel_logout_uri_forbidden",
                "this installation cannot check a back-channel logout address, so it accepts none",
            ));
        };
        destinations.check(url).await.map_err(refused_address)
    }

    fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        caller: Caller,
        events: &[OauthEvent],
    ) -> Result<(), DomainError> {
        for event in events {
            let metadata = EventMetadata::new(
                uow.tenant().tenant_id(),
                caller.actor,
                caller.correlation_id,
                self.clock.as_ref(),
            );
            uow.record_event(EventEnvelope::new(metadata, event)?);
        }
        Ok(())
    }

    // Applications.

    /// Registers an application in the tenant, enabled.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` for a name that breaks its rule and
    /// `oauth.too_many_applications` if the tenant has 100.
    pub async fn create_application(
        &self,
        tenant: &TenantContext,
        settings: ApplicationSettings,
        caller: Caller,
    ) -> Result<Application, DomainError> {
        let application = Application::create(settings, self.clock.now())?;
        let mut uow = self.units_of_work.begin(tenant).await?;
        if self.applications.list(uow.as_mut()).await?.len() >= MAX_APPLICATIONS {
            return Err(DomainError::conflict(
                "oauth.too_many_applications",
                "this tenant already has as many applications as it may",
            ));
        }
        self.applications.insert(uow.as_mut(), &application).await?;
        let event = OauthEvent::ApplicationCreated {
            application_id: application.id(),
            name: application.name().to_owned(),
        };
        self.record(uow.as_mut(), caller, &[event])?;
        uow.commit().await?;
        Ok(application)
    }

    async fn change_application_with(
        &self,
        tenant: &TenantContext,
        id: ApplicationId,
        caller: Caller,
        change: impl FnOnce(&mut Application) -> Result<Option<OauthEvent>, DomainError> + Send,
    ) -> Result<Application, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let mut application = self
            .applications
            .get(uow.as_mut(), id)
            .await?
            .ok_or_else(application_not_found)?;
        if let Some(event) = change(&mut application)? {
            self.applications.update(uow.as_mut(), &application).await?;
            self.record(uow.as_mut(), caller, &[event])?;
            uow.commit().await?;
        }
        Ok(application)
    }

    /// Changes an application's name and whether it is first party.
    /// Settings equal to the current ones change nothing.
    ///
    /// # Errors
    ///
    /// Returns `NotFound`, `Invalid`, or `Conflict` if someone else
    /// changed it first.
    pub async fn change_application(
        &self,
        tenant: &TenantContext,
        id: ApplicationId,
        settings: ApplicationSettings,
        caller: Caller,
    ) -> Result<Application, DomainError> {
        let now = self.clock.now();
        self.change_application_with(tenant, id, caller, |application| {
            Ok(application
                .change(settings, now)?
                .then(|| OauthEvent::ApplicationChanged {
                    application_id: application.id(),
                    name: application.name().to_owned(),
                }))
        })
        .await
    }

    /// Enables or disables an application. The clients of a disabled
    /// application get no tokens.
    ///
    /// # Errors
    ///
    /// Returns `NotFound`, or `Conflict` if someone else changed it first.
    pub async fn set_application_status(
        &self,
        tenant: &TenantContext,
        id: ApplicationId,
        status: Status,
        caller: Caller,
    ) -> Result<Application, DomainError> {
        let now = self.clock.now();
        self.change_application_with(tenant, id, caller, |application| {
            let application_id = application.id();
            Ok(application.set_status(status, now).then_some(match status {
                Status::Enabled => OauthEvent::ApplicationEnabled { application_id },
                Status::Disabled => OauthEvent::ApplicationDisabled { application_id },
            }))
        })
        .await
    }

    /// The application with this identifier.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the tenant has none.
    pub async fn application(
        &self,
        tenant: &TenantContext,
        id: ApplicationId,
    ) -> Result<Application, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.applications
            .get(uow.as_mut(), id)
            .await?
            .ok_or_else(application_not_found)
    }

    /// The tenant's applications, oldest first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn applications(
        &self,
        tenant: &TenantContext,
    ) -> Result<Vec<Application>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.applications.list(uow.as_mut()).await
    }

    // Clients.

    /// The service account a workload's identity names in the tenant: the
    /// principal the tenant's enabled clients bound to it act as, if any.
    /// An identity binds the clients of one service account only
    /// (Decision 0058), so there is at most one.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn service_account_of(
        &self,
        tenant: &TenantContext,
        identity: &WorkloadIdentity,
    ) -> Result<Option<UserId>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        Ok(self
            .clients
            .bound_to(uow.as_mut(), identity)
            .await?
            .into_iter()
            .filter(Client::is_enabled)
            .find_map(|client| client.principal()))
    }

    /// Creates a client of an application, enabled. A confidential client
    /// with a secret method gets its first secret, returned once.
    ///
    /// # Errors
    ///
    /// Returns `oauth.application_not_found`, an `Invalid` error if a
    /// setting breaks its rule, and `oauth.too_many_clients` if the
    /// application has 20.
    pub async fn create_client(
        &self,
        tenant: &TenantContext,
        command: CreateClient,
        caller: Caller,
    ) -> Result<(Client, Option<ClientSecretValue>), DomainError> {
        let (client, secret) = Client::create(
            command.application_id,
            command.client_type,
            command.settings,
            command
                .secret_lifetime
                .unwrap_or(ClientSecret::DEFAULT_LIFETIME),
            self.clock.now(),
            self.random.as_ref(),
            self.digest.as_ref(),
        )?;
        if let Some(url) = client.backchannel_logout_uri() {
            self.check_backchannel_address(url).await?;
        }
        if let Some(url) = client.jwks_uri() {
            self.check_jwks_address(url).await?;
        }
        let settings = &client.snapshot().settings;
        self.check_request_addresses(&settings.request_uris.iter().collect::<Vec<_>>())
            .await?;
        if settings.subject_type == SubjectType::Pairwise {
            self.check_sector_address(settings).await?;
        }
        let mut uow = self.units_of_work.begin(tenant).await?;
        if self
            .applications
            .get(uow.as_mut(), command.application_id)
            .await?
            .is_none()
        {
            return Err(application_not_found());
        }
        let existing = self
            .clients
            .list_for_application(uow.as_mut(), command.application_id)
            .await?;
        if existing.len() >= MAX_CLIENTS {
            return Err(DomainError::conflict(
                "oauth.too_many_clients",
                "this application already has as many clients as it may",
            ));
        }
        self.clients.insert(uow.as_mut(), &client).await?;
        self.record(uow.as_mut(), caller, &client.created_events())?;
        uow.commit().await?;
        Ok((client, secret))
    }

    async fn change_client_with<T: Send>(
        &self,
        tenant: &TenantContext,
        id: ClientId,
        caller: Caller,
        change: impl FnOnce(&mut Client) -> Result<(T, Vec<OauthEvent>), DomainError> + Send,
    ) -> Result<(Client, T), DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let mut client = self
            .clients
            .get(uow.as_mut(), id)
            .await?
            .ok_or_else(client_not_found)?;
        let (answer, events) = change(&mut client)?;
        if !events.is_empty() {
            self.clients.update(uow.as_mut(), &client).await?;
            self.record(uow.as_mut(), caller, &events)?;
            uow.commit().await?;
        }
        Ok((client, answer))
    }

    /// Replaces a client's settings, all checked again. Settings equal to
    /// the current ones change nothing.
    ///
    /// # Errors
    ///
    /// Returns `NotFound`, an `Invalid` error if a setting breaks its
    /// rule, or `Conflict` if someone else changed it first.
    pub async fn change_client(
        &self,
        tenant: &TenantContext,
        id: ClientId,
        settings: ClientSettings,
        caller: Caller,
    ) -> Result<Client, DomainError> {
        // Only a new or changed back-channel logout address is checked: a
        // name that leads elsewhere since does not stop other changes.
        let current = self.client(tenant, id).await?;
        let settings = settings.checked(current.client_type())?;
        if let Some(url) = settings.backchannel_logout_uri.as_deref()
            && current.backchannel_logout_uri() != Some(url)
        {
            self.check_backchannel_address(url).await?;
        }
        // Only a request object address new to the client is checked.
        let new_addresses: Vec<&String> = settings
            .request_uris
            .iter()
            .filter(|address| !current.snapshot().settings.request_uris.contains(address))
            .collect();
        self.check_request_addresses(&new_addresses).await?;
        // So is only a new or changed key set address.
        if let Some(url) = settings.jwks_uri.as_deref()
            && current.jwks_uri() != Some(url)
        {
            self.check_jwks_address(url).await?;
        }
        // The sector identifier document is fetched again only when what it
        // vouches for changes: its address, the redirect addresses it must
        // list, or the client becoming pairwise.
        let before = &current.snapshot().settings;
        if settings.subject_type == SubjectType::Pairwise
            && (before.subject_type != SubjectType::Pairwise
                || before.sector_identifier_uri != settings.sector_identifier_uri
                || before.redirect_uris != settings.redirect_uris)
        {
            self.check_sector_address(&settings).await?;
        }
        let now = self.clock.now();
        self.change_client_with(tenant, id, caller, |client| {
            Ok(((), client.change(settings, now)?))
        })
        .await
        .map(|(client, ())| client)
    }

    /// Gives a client a new secret, returned once, and shortens or ends
    /// its previous ones.
    ///
    /// # Errors
    ///
    /// Returns `NotFound`, `oauth.client_secret_not_allowed` for a client
    /// without a secret method, `Invalid` for a lifetime or an overlap
    /// that is not acceptable, or `Conflict`.
    pub async fn rotate_client_secret(
        &self,
        tenant: &TenantContext,
        id: ClientId,
        command: RotateSecret,
        caller: Caller,
    ) -> Result<ClientSecretValue, DomainError> {
        let now = self.clock.now();
        let (random, digest) = (self.random.clone(), self.digest.clone());
        self.change_client_with(tenant, id, caller, move |client| {
            client.rotate_secret(
                command.lifetime,
                command.keep_previous_for,
                now,
                random.as_ref(),
                digest.as_ref(),
            )
        })
        .await
        .map(|(_, secret)| secret)
    }

    /// Ends one secret of a client at once.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` for an unknown client or secret, or `Conflict`.
    pub async fn revoke_client_secret(
        &self,
        tenant: &TenantContext,
        id: ClientId,
        secret_id: ClientSecretId,
        caller: Caller,
    ) -> Result<Client, DomainError> {
        let now = self.clock.now();
        self.change_client_with(tenant, id, caller, |client| {
            Ok(((), vec![client.revoke_secret(secret_id, now)?]))
        })
        .await
        .map(|(client, ())| client)
    }

    /// Adds a public key, given as a JSON Web Key, to a client using
    /// `private_key_jwt`.
    ///
    /// # Errors
    ///
    /// Returns `NotFound`, `oauth.client_key_invalid`,
    /// `oauth.client_key_not_allowed`, `oauth.client_key_taken`,
    /// `oauth.client_too_many_keys`, or `Conflict`.
    pub async fn add_client_key(
        &self,
        tenant: &TenantContext,
        id: ClientId,
        jwk: &str,
        caller: Caller,
    ) -> Result<Client, DomainError> {
        let now = self.clock.now();
        let key = ClientKey::parse(jwk, now)?;
        self.change_client_with(tenant, id, caller, |client| {
            Ok(((), vec![client.add_key(key, now)?]))
        })
        .await
        .map(|(client, ())| client)
    }

    /// Removes the key of a client with this `kid`.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` for an unknown client or key, or `Conflict`.
    pub async fn remove_client_key(
        &self,
        tenant: &TenantContext,
        id: ClientId,
        key_id: &str,
        caller: Caller,
    ) -> Result<Client, DomainError> {
        let now = self.clock.now();
        self.change_client_with(tenant, id, caller, |client| {
            Ok(((), vec![client.remove_key(key_id, now)?]))
        })
        .await
        .map(|(client, ())| client)
    }

    /// Enables or disables a client.
    ///
    /// # Errors
    ///
    /// Returns `NotFound`, or `Conflict`.
    pub async fn set_client_status(
        &self,
        tenant: &TenantContext,
        id: ClientId,
        status: Status,
        caller: Caller,
    ) -> Result<Client, DomainError> {
        let now = self.clock.now();
        self.change_client_with(tenant, id, caller, |client| {
            Ok(((), client.set_status(status, now).into_iter().collect()))
        })
        .await
        .map(|(client, ())| client)
    }

    /// The client with this identifier.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the tenant has none.
    pub async fn client(
        &self,
        tenant: &TenantContext,
        id: ClientId,
    ) -> Result<Client, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.clients
            .get(uow.as_mut(), id)
            .await?
            .ok_or_else(client_not_found)
    }

    /// The client with this identifier, its application and that
    /// application's resource server, in one transaction.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the tenant has no such client, and an error if
    /// storage fails.
    pub async fn client_with_application(
        &self,
        tenant: &TenantContext,
        id: ClientId,
    ) -> Result<ClientWithApplication, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let client = self
            .clients
            .get(uow.as_mut(), id)
            .await?
            .ok_or_else(client_not_found)?;
        let application_id = client.snapshot().application_id;
        let application = self.applications.get(uow.as_mut(), application_id).await?;
        let resource_server = match application {
            Some(_) => {
                self.resource_servers
                    .find_by_application(uow.as_mut(), application_id)
                    .await?
            }
            None => None,
        };
        Ok(ClientWithApplication {
            client,
            application,
            resource_server,
        })
    }

    /// The application with this identifier and its resource server, in one
    /// transaction.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the tenant has no such application, and an
    /// error if storage fails.
    pub async fn application_with_resource_server(
        &self,
        tenant: &TenantContext,
        id: ApplicationId,
    ) -> Result<(Application, Option<ResourceServer>), DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let application = self
            .applications
            .get(uow.as_mut(), id)
            .await?
            .ok_or_else(application_not_found)?;
        let resource_server = self
            .resource_servers
            .find_by_application(uow.as_mut(), id)
            .await?;
        Ok((application, resource_server))
    }

    /// The clients of an application, oldest first.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the tenant has no such application.
    pub async fn clients(
        &self,
        tenant: &TenantContext,
        application_id: ApplicationId,
    ) -> Result<Vec<Client>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        if self
            .applications
            .get(uow.as_mut(), application_id)
            .await?
            .is_none()
        {
            return Err(application_not_found());
        }
        self.clients
            .list_for_application(uow.as_mut(), application_id)
            .await
    }

    // Resource servers.

    /// Registers the resource server of an application.
    ///
    /// # Errors
    ///
    /// Returns `oauth.application_not_found`, `oauth.audience_invalid` or
    /// another `Invalid` error, `oauth.audience_taken` and
    /// `oauth.application_has_resource_server`.
    pub async fn create_resource_server(
        &self,
        tenant: &TenantContext,
        command: CreateResourceServer,
        caller: Caller,
    ) -> Result<ResourceServer, DomainError> {
        let server = ResourceServer::create(
            command.application_id,
            Audience::parse(&command.audience)?,
            command.settings,
            self.clock.now(),
        )?;
        let mut uow = self.units_of_work.begin(tenant).await?;
        if self
            .applications
            .get(uow.as_mut(), command.application_id)
            .await?
            .is_none()
        {
            return Err(application_not_found());
        }
        self.resource_servers.insert(uow.as_mut(), &server).await?;
        self.record(uow.as_mut(), caller, &[server.created_event()])?;
        uow.commit().await?;
        Ok(server)
    }

    /// Replaces a resource server's name and scopes. The audience never
    /// changes.
    ///
    /// # Errors
    ///
    /// Returns `NotFound`, an `Invalid` error, or `Conflict`.
    pub async fn change_resource_server(
        &self,
        tenant: &TenantContext,
        id: ResourceServerId,
        settings: ResourceServerSettings,
        caller: Caller,
    ) -> Result<ResourceServer, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let mut server = self
            .resource_servers
            .get(uow.as_mut(), id)
            .await?
            .ok_or_else(resource_server_not_found)?;
        if let Some(event) = server.change(settings, self.clock.now())? {
            self.resource_servers.update(uow.as_mut(), &server).await?;
            self.record(uow.as_mut(), caller, &[event])?;
            uow.commit().await?;
        }
        Ok(server)
    }

    /// The resource server with this identifier.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the tenant has none.
    pub async fn resource_server(
        &self,
        tenant: &TenantContext,
        id: ResourceServerId,
    ) -> Result<ResourceServer, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.resource_servers
            .get(uow.as_mut(), id)
            .await?
            .ok_or_else(resource_server_not_found)
    }

    /// The resource server whose audience is, character for character,
    /// `audience`.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the tenant has none, including for a value
    /// that cannot be an audience.
    pub async fn resource_server_by_audience(
        &self,
        tenant: &TenantContext,
        audience: &str,
    ) -> Result<ResourceServer, DomainError> {
        let audience = Audience::parse(audience).map_err(|_| resource_server_not_found())?;
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.resource_servers
            .find_by_audience(uow.as_mut(), &audience)
            .await?
            .ok_or_else(resource_server_not_found)
    }

    /// The resource server of an application, if it has one: an
    /// application has at most one.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn resource_server_of(
        &self,
        tenant: &TenantContext,
        application_id: ApplicationId,
    ) -> Result<Option<ResourceServer>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.resource_servers
            .find_by_application(uow.as_mut(), application_id)
            .await
    }

    /// The tenant's resource servers, oldest first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn resource_servers(
        &self,
        tenant: &TenantContext,
    ) -> Result<Vec<ResourceServer>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.resource_servers.list(uow.as_mut()).await
    }
}
