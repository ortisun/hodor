//! What the OAuth context needs from storage. Every method works inside
//! the tenant the unit of work is bound to.

use crate::domain::application::{Application, ApplicationId};
use crate::domain::client::{Client, ClientId};
use crate::domain::resource_server::{Audience, ResourceServer, ResourceServerId};
use hodor_kernel::{DomainError, UnitOfWork};

/// Stores applications.
#[async_trait::async_trait]
pub trait ApplicationStore: Send + Sync {
    /// Stores a new application.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        application: &Application,
    ) -> Result<(), DomainError>;

    /// Stores a changed application, if its stored version is the one it
    /// was read with. The stored version becomes one more.
    ///
    /// # Errors
    ///
    /// Returns `oauth.application_modified_concurrently` otherwise.
    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        application: &Application,
    ) -> Result<(), DomainError>;

    /// The application with this identifier, if the tenant has it.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: ApplicationId,
    ) -> Result<Option<Application>, DomainError>;

    /// The tenant's applications, oldest first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn list(&self, uow: &mut dyn UnitOfWork) -> Result<Vec<Application>, DomainError>;
}

/// Stores clients, with their secrets and keys.
#[async_trait::async_trait]
pub trait ClientStore: Send + Sync {
    /// Stores a new client of an application of the tenant.
    ///
    /// # Errors
    ///
    /// Returns `oauth.application_not_found` if the tenant has no such
    /// application.
    async fn insert(&self, uow: &mut dyn UnitOfWork, client: &Client) -> Result<(), DomainError>;

    /// Stores a changed client with its secrets and keys, if its stored
    /// version is the one it was read with. The stored version becomes one
    /// more.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_modified_concurrently` otherwise.
    async fn update(&self, uow: &mut dyn UnitOfWork, client: &Client) -> Result<(), DomainError>;

    /// The client with this identifier, if the tenant has it.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: ClientId,
    ) -> Result<Option<Client>, DomainError>;

    /// The clients of an application, oldest first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn list_for_application(
        &self,
        uow: &mut dyn UnitOfWork,
        application_id: ApplicationId,
    ) -> Result<Vec<Client>, DomainError>;
}

/// Stores resource servers.
#[async_trait::async_trait]
pub trait ResourceServerStore: Send + Sync {
    /// Stores a new resource server of an application of the tenant.
    ///
    /// # Errors
    ///
    /// Returns `oauth.audience_taken` if the tenant has a resource server
    /// with this audience, `oauth.application_has_resource_server` if the
    /// application has one, and `oauth.application_not_found` if the tenant
    /// has no such application.
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        server: &ResourceServer,
    ) -> Result<(), DomainError>;

    /// Stores a changed resource server, if its stored version is the one
    /// it was read with. The stored version becomes one more.
    ///
    /// # Errors
    ///
    /// Returns `oauth.resource_server_modified_concurrently` otherwise.
    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        server: &ResourceServer,
    ) -> Result<(), DomainError>;

    /// The resource server with this identifier, if the tenant has it.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: ResourceServerId,
    ) -> Result<Option<ResourceServer>, DomainError>;

    /// The resource server with this audience, if the tenant has it.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn find_by_audience(
        &self,
        uow: &mut dyn UnitOfWork,
        audience: &Audience,
    ) -> Result<Option<ResourceServer>, DomainError>;

    /// The tenant's resource servers, oldest first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn list(&self, uow: &mut dyn UnitOfWork) -> Result<Vec<ResourceServer>, DomainError>;
}
