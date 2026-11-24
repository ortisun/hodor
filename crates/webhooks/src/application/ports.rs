//! What the webhooks context needs from storage and from cryptography.
//! Outbound HTTP, the check of an address and the secret box are ports of
//! the kernel.

use crate::domain::delivery::{Delivery, DeliveryId, DeliveryStatus};
use crate::domain::endpoint::{Endpoint, EndpointId};
use crate::domain::secret::{SigningSecret, SigningSecretId};
use hodor_kernel::{DomainError, TenantId, Timestamp, UnitOfWork};

/// Stores the endpoints of a tenant, their subscriptions and their sealed
/// secrets. Every method works inside the tenant the unit of work is bound
/// to.
#[async_trait::async_trait]
pub trait EndpointStore: Send + Sync {
    /// Stores a new endpoint with its subscriptions.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        endpoint: &Endpoint,
    ) -> Result<(), DomainError>;

    /// Reads an endpoint of the tenant.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: EndpointId,
    ) -> Result<Option<Endpoint>, DomainError>;

    /// Reads an endpoint and holds it until the unit of work ends, so that
    /// whatever else holds it waits: rotations of its secret, and the
    /// counting of its leased deliveries.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn lock(
        &self,
        uow: &mut dyn UnitOfWork,
        id: EndpointId,
    ) -> Result<Option<Endpoint>, DomainError>;

    /// Up to `limit` endpoints of the tenant whose identifier comes after
    /// `after`, in the order of their identifiers.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        after: Option<EndpointId>,
        limit: u32,
    ) -> Result<Vec<Endpoint>, DomainError>;

    /// How many endpoints the tenant has. Until the unit of work ends, a
    /// second count of the same tenant waits, so that two registrations
    /// count one after the other.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn count(&self, uow: &mut dyn UnitOfWork) -> Result<u32, DomainError>;

    /// Stores a changed endpoint and replaces its subscriptions, if it
    /// still has the version it was read at.
    ///
    /// # Errors
    ///
    /// Returns `webhooks.endpoint_changed` if it changed meanwhile, and
    /// `webhooks.endpoint_not_found` if the tenant has no such endpoint.
    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        endpoint: &Endpoint,
    ) -> Result<(), DomainError>;

    /// Removes an endpoint with its subscriptions, secrets and deliveries.
    /// Answers whether there was one.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn remove(&self, uow: &mut dyn UnitOfWork, id: EndpointId) -> Result<bool, DomainError>;

    /// The endpoints of the tenant subscribed to `event_type`.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn subscribed_to(
        &self,
        uow: &mut dyn UnitOfWork,
        event_type: &str,
    ) -> Result<Vec<EndpointId>, DomainError>;

    /// Stores a new secret of an endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails, or if the tenant has no such
    /// endpoint.
    async fn add_secret(
        &self,
        uow: &mut dyn UnitOfWork,
        secret: &SigningSecret,
    ) -> Result<(), DomainError>;

    /// Every stored secret of an endpoint, newest first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn secrets(
        &self,
        uow: &mut dyn UnitOfWork,
        endpoint: EndpointId,
    ) -> Result<Vec<SigningSecret>, DomainError>;

    /// Sets when a secret stops signing.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn end_secret(
        &self,
        uow: &mut dyn UnitOfWork,
        id: SigningSecretId,
        expires_at: Timestamp,
    ) -> Result<(), DomainError>;

    /// Removes the secrets of an endpoint that stopped signing at `now`.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn remove_ended_secrets(
        &self,
        uow: &mut dyn UnitOfWork,
        endpoint: EndpointId,
        now: Timestamp,
    ) -> Result<u64, DomainError>;
}

/// Which deliveries to list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeliveryQuery {
    /// Only those of this endpoint.
    pub endpoint: Option<EndpointId>,
    /// Only those in this status.
    pub status: Option<DeliveryStatus>,
}

/// Stores the deliveries of a tenant. Every method works inside the tenant
/// the unit of work is bound to.
#[async_trait::async_trait]
pub trait DeliveryStore: Send + Sync {
    /// Stores a new delivery, unless the endpoint already has one of the
    /// same event. Answers whether it was stored.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails, or if the tenant has no such
    /// endpoint.
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        delivery: &Delivery,
    ) -> Result<bool, DomainError>;

    /// Reads a delivery of the tenant.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: DeliveryId,
    ) -> Result<Option<Delivery>, DomainError>;

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
        id: DeliveryId,
    ) -> Result<Option<Delivery>, DomainError>;

    /// Reads a delivery and holds it until the unit of work ends, waiting
    /// for whoever holds it now.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn lock(
        &self,
        uow: &mut dyn UnitOfWork,
        id: DeliveryId,
    ) -> Result<Option<Delivery>, DomainError>;

    /// How many deliveries of an endpoint are pending and leased past
    /// `now`.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn leased(
        &self,
        uow: &mut dyn UnitOfWork,
        endpoint: EndpointId,
        now: Timestamp,
    ) -> Result<u32, DomainError>;

    /// Stores what happened to a delivery.
    ///
    /// # Errors
    ///
    /// Returns `webhooks.delivery_not_found` if the tenant has no such
    /// delivery.
    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        delivery: &Delivery,
    ) -> Result<(), DomainError>;

    /// Up to `limit` deliveries of the tenant that match `query`, newest
    /// first, starting after `after`.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        query: DeliveryQuery,
        after: Option<DeliveryId>,
        limit: u32,
    ) -> Result<Vec<Delivery>, DomainError>;
}

/// Finds deliveries that are due, across tenants. The one port of this
/// context that is not bound to a tenant; only the worker is given it.
#[async_trait::async_trait]
pub trait DueDeliveries: Send + Sync {
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
    ) -> Result<Vec<(TenantId, DeliveryId)>, DomainError>;
}

/// HMAC-SHA256.
pub trait HmacSha256: Send + Sync {
    /// The HMAC-SHA256 of `message` under `key`.
    fn mac(&self, key: &[u8], message: &[u8]) -> [u8; 32];
}
