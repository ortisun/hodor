//! What back-channel logout needs from storage and from the composition
//! root. Outbound HTTP is a port of the kernel, signing the keys context's.

use crate::domain::backchannel::{LogoutDelivery, LogoutDeliveryId};
use crate::domain::client::ClientId;
use hodor_kernel::{DomainError, TenantContext, TenantId, Timestamp, UnitOfWork};
use hodor_session::api::SessionId;

/// The clients a person signed in to with a session. Works inside the
/// tenant the unit of work is bound to.
#[async_trait::async_trait]
pub trait SessionClients: Send + Sync {
    /// Every client with a grant made in `session` whose scopes hold
    /// `openid`, whatever the grant's status, each once.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn clients_of(
        &self,
        uow: &mut dyn UnitOfWork,
        session: SessionId,
    ) -> Result<Vec<ClientId>, DomainError>;
}

/// Stores the logout deliveries of a tenant. Every method works inside the
/// tenant the unit of work is bound to.
#[async_trait::async_trait]
pub trait LogoutDeliveryStore: Send + Sync {
    /// Stores a new delivery, unless the client already has one for the
    /// same session. Answers whether it was stored.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_not_found` if the tenant has no such client.
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        delivery: &LogoutDelivery,
    ) -> Result<bool, DomainError>;

    /// Reads a delivery of the tenant.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: LogoutDeliveryId,
    ) -> Result<Option<LogoutDelivery>, DomainError>;

    /// Takes a delivery for a lease: holds it until the unit of work ends.
    /// Finds nothing if another unit of work holds it: it is skipped, not
    /// waited for.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn take(
        &self,
        uow: &mut dyn UnitOfWork,
        id: LogoutDeliveryId,
    ) -> Result<Option<LogoutDelivery>, DomainError>;

    /// Reads a delivery and holds it until the unit of work ends, waiting
    /// for whoever holds it now.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn lock(
        &self,
        uow: &mut dyn UnitOfWork,
        id: LogoutDeliveryId,
    ) -> Result<Option<LogoutDelivery>, DomainError>;

    /// Holds a client until the unit of work ends, so that whoever else
    /// counts its leased deliveries waits. Answers whether the tenant has
    /// the client.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn hold_client(
        &self,
        uow: &mut dyn UnitOfWork,
        client: ClientId,
    ) -> Result<bool, DomainError>;

    /// How many deliveries of a client are pending and leased past `now`.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn leased(
        &self,
        uow: &mut dyn UnitOfWork,
        client: ClientId,
        now: Timestamp,
    ) -> Result<u32, DomainError>;

    /// Stores what happened to a delivery.
    ///
    /// # Errors
    ///
    /// Returns `oauth.logout_delivery_not_found` if the tenant has no such
    /// delivery.
    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        delivery: &LogoutDelivery,
    ) -> Result<(), DomainError>;
}

/// Finds logout deliveries that are due, across tenants. Not bound to a
/// tenant; only the worker is given it.
#[async_trait::async_trait]
pub trait DueLogoutDeliveries: Send + Sync {
    /// Up to `limit` pending deliveries due at `now` and not leased past
    /// it, the longest waiting first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn due(
        &self,
        now: Timestamp,
        limit: u32,
    ) -> Result<Vec<(TenantId, LogoutDeliveryId)>, DomainError>;
}

/// The issuer of a tenant, `{public address}/t/{slug}`, for the worker,
/// which has no request to read it from.
#[async_trait::async_trait]
pub trait TenantIssuer: Send + Sync {
    /// The issuer of `tenant`.
    ///
    /// # Errors
    ///
    /// Returns an error if the tenant cannot be read.
    async fn issuer(&self, tenant: &TenantContext) -> Result<String, DomainError>;
}
