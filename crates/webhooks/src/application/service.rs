//! The use cases administrators call: endpoints, their subscriptions and
//! secrets, and deliveries.

use crate::application::ports::{DeliveryQuery, DeliveryStore, EndpointStore};
use crate::domain::catalog::CATALOG;
use crate::domain::delivery::{Delivery, DeliveryId};
use crate::domain::endpoint::{Endpoint, EndpointId, MAX_ENDPOINTS};
use crate::domain::event::WebhookEvent;
use crate::domain::secret::{
    SECRET_BYTES, SIGNING_SECRET_PURPOSE, SigningSecret, SigningSecretId, overlap, rotation,
    written,
};
use hodor_kernel::{
    Caller, Clock, Cursor, DestinationCheck, DomainError, EventEnvelope, EventMetadata, Page,
    PageRequest, RandomSource, Secret, SecretBox, TenantContext, Timestamp, UnitOfWork,
    UnitOfWorkFactory,
};
use std::sync::Arc;

/// What an administrator gives to register an endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterEndpoint {
    /// Where deliveries are sent.
    pub url: String,
    /// What the administrator writes about it.
    pub description: Option<String>,
    /// The event types it receives.
    pub event_types: Vec<String>,
}

/// When a secret in force started and stops signing. Never the secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretInForce {
    /// When it was made.
    pub created_at: Timestamp,
    /// When it stops signing; `None` for the current secret.
    pub expires_at: Option<Timestamp>,
}

/// An endpoint, with the secrets that sign for it now, newest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointDetails {
    /// The endpoint.
    pub endpoint: Endpoint,
    /// Its secrets in force.
    pub secrets: Vec<SecretInForce>,
}

/// The use cases of administrators.
#[derive(Clone)]
pub struct WebhookService {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    endpoints: Arc<dyn EndpointStore>,
    deliveries: Arc<dyn DeliveryStore>,
    secrets: Arc<dyn SecretBox>,
    destinations: Arc<dyn DestinationCheck>,
    random: Arc<dyn RandomSource>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for WebhookService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookService").finish_non_exhaustive()
    }
}

fn endpoint_not_found() -> DomainError {
    DomainError::not_found(
        "webhooks.endpoint_not_found",
        "there is no such webhook endpoint",
    )
}

fn delivery_not_found() -> DomainError {
    DomainError::not_found(
        "webhooks.delivery_not_found",
        "there is no such webhook delivery",
    )
}

/// Turns what the destination check says into what an administrator is
/// told. The message never repeats what the name resolved to.
fn refused_address(error: DomainError) -> DomainError {
    match error.code() {
        "http.url_invalid" => DomainError::invalid(
            "webhooks.endpoint_address_invalid",
            "an endpoint's address is an HTTPS address of at most 1000 characters, without a \
             name and password or a fragment",
        ),
        "http.destination_forbidden" => DomainError::invalid(
            "webhooks.endpoint_address_forbidden",
            "the address leads somewhere Hodor may not call: it must be public",
        ),
        "http.unreachable" => DomainError::invalid(
            "webhooks.endpoint_address_unresolvable",
            "the address's name does not resolve to any address",
        ),
        _ => error,
    }
}

/// The cursor of a page whose last item has this identifier.
fn cursor_after(id: impl ToString) -> Cursor {
    Cursor::new(id.to_string())
}

fn page_after<T: std::str::FromStr>(page: &PageRequest) -> Result<Option<T>, DomainError> {
    page.cursor()
        .map(|cursor| {
            cursor.as_str().parse().map_err(|_| {
                DomainError::invalid("request.cursor_invalid", "the cursor is not valid")
            })
        })
        .transpose()
}

impl WebhookService {
    /// Wires the use cases to their ports.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        endpoints: Arc<dyn EndpointStore>,
        deliveries: Arc<dyn DeliveryStore>,
        secrets: Arc<dyn SecretBox>,
        destinations: Arc<dyn DestinationCheck>,
        random: Arc<dyn RandomSource>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            units_of_work,
            endpoints,
            deliveries,
            secrets,
            destinations,
            random,
            clock,
        }
    }

    /// The event types an endpoint can be subscribed to.
    #[must_use]
    pub const fn event_types(&self) -> &'static [&'static str] {
        CATALOG
    }

    /// Makes a secret for an endpoint and seals it. Answers it sealed, for
    /// storage, and written, to be shown once.
    async fn new_secret(
        &self,
        tenant: &TenantContext,
        endpoint: EndpointId,
        now: Timestamp,
    ) -> Result<(SigningSecret, Secret<String>), DomainError> {
        let mut drawn = vec![0_u8; SECRET_BYTES];
        self.random.fill(&mut drawn);
        // Moved, not copied: the secret's bytes are zeroized when it drops.
        let bytes = Secret::new(drawn);
        let sealed = self
            .secrets
            .seal(tenant, SIGNING_SECRET_PURPOSE, &bytes)
            .await?;
        Ok((
            SigningSecret {
                id: SigningSecretId::generate(),
                endpoint_id: endpoint,
                sealed,
                created_at: now,
                expires_at: None,
            },
            written(bytes.expose()),
        ))
    }

    async fn details(
        &self,
        uow: &mut dyn UnitOfWork,
        endpoint: Endpoint,
    ) -> Result<EndpointDetails, DomainError> {
        let now = self.clock.now();
        let secrets = self
            .endpoints
            .secrets(uow, endpoint.id())
            .await?
            .into_iter()
            .filter(|secret| secret.is_in_force(now))
            .map(|secret| SecretInForce {
                created_at: secret.created_at,
                expires_at: secret.expires_at,
            })
            .collect();
        Ok(EndpointDetails { endpoint, secrets })
    }

    fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        caller: Caller,
        event: &WebhookEvent,
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

    /// Registers an endpoint. Its address is checked before anything is
    /// stored. Answers the endpoint and its secret, which is never shown
    /// again.
    ///
    /// # Errors
    ///
    /// Returns `webhooks.endpoint_address_invalid`,
    /// `webhooks.endpoint_address_forbidden`,
    /// `webhooks.endpoint_address_unresolvable`,
    /// `webhooks.description_invalid`, `webhooks.event_type_unknown`, or
    /// `webhooks.too_many_endpoints` for a tenant that has 20 already.
    pub async fn register(
        &self,
        tenant: &TenantContext,
        command: RegisterEndpoint,
        caller: Caller,
    ) -> Result<(EndpointDetails, Secret<String>), DomainError> {
        let now = self.clock.now();
        let endpoint =
            Endpoint::register(&command.url, command.description, &command.event_types, now)?;
        self.destinations
            .check(endpoint.url())
            .await
            .map_err(refused_address)?;
        let (secret, shown) = self.new_secret(tenant, endpoint.id(), now).await?;

        let mut uow = self.units_of_work.begin(tenant).await?;
        if self.endpoints.count(uow.as_mut()).await? >= MAX_ENDPOINTS {
            return Err(DomainError::conflict(
                "webhooks.too_many_endpoints",
                "a tenant has at most 20 webhook endpoints",
            ));
        }
        self.endpoints.insert(uow.as_mut(), &endpoint).await?;
        self.endpoints.add_secret(uow.as_mut(), &secret).await?;
        self.record(
            uow.as_mut(),
            caller,
            &WebhookEvent::EndpointRegistered {
                endpoint_id: endpoint.id(),
                event_types: endpoint.snapshot().event_types.iter().copied().collect(),
            },
        )?;
        let details = self.details(uow.as_mut(), endpoint).await?;
        uow.commit().await?;
        Ok((details, shown))
    }

    /// Reads an endpoint of the tenant.
    ///
    /// # Errors
    ///
    /// Returns `webhooks.endpoint_not_found`.
    pub async fn get(
        &self,
        tenant: &TenantContext,
        id: EndpointId,
    ) -> Result<EndpointDetails, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let endpoint = self
            .endpoints
            .get(uow.as_mut(), id)
            .await?
            .ok_or_else(endpoint_not_found)?;
        self.details(uow.as_mut(), endpoint).await
    }

    /// The tenant's endpoints, a page at a time.
    ///
    /// # Errors
    ///
    /// Returns `request.cursor_invalid` for a cursor this did not give.
    pub async fn list(
        &self,
        tenant: &TenantContext,
        page: &PageRequest,
    ) -> Result<Page<EndpointDetails>, DomainError> {
        let after = page_after(page)?;
        let mut uow = self.units_of_work.begin(tenant).await?;
        let mut found = self
            .endpoints
            .list(uow.as_mut(), after, page.limit() + 1)
            .await?;
        let more = found.len() > page.limit() as usize;
        found.truncate(page.limit() as usize);
        let next_cursor = more
            .then(|| found.last().map(|last| cursor_after(last.id())))
            .flatten();
        let mut items = Vec::with_capacity(found.len());
        for endpoint in found {
            items.push(self.details(uow.as_mut(), endpoint).await?);
        }
        Ok(Page { items, next_cursor })
    }

    /// Replaces the event types an endpoint receives.
    ///
    /// # Errors
    ///
    /// Returns `webhooks.endpoint_not_found`, `webhooks.event_type_unknown`
    /// or `webhooks.endpoint_changed`.
    pub async fn replace_subscriptions(
        &self,
        tenant: &TenantContext,
        id: EndpointId,
        event_types: &[String],
        caller: Caller,
    ) -> Result<EndpointDetails, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let mut endpoint = self
            .endpoints
            .get(uow.as_mut(), id)
            .await?
            .ok_or_else(endpoint_not_found)?;
        endpoint.replace_subscriptions(event_types, self.clock.now())?;
        self.endpoints.update(uow.as_mut(), &endpoint).await?;
        self.record(
            uow.as_mut(),
            caller,
            &WebhookEvent::SubscriptionsChanged {
                endpoint_id: id,
                event_types: endpoint.snapshot().event_types.iter().copied().collect(),
            },
        )?;
        let details = self.details(uow.as_mut(), endpoint).await?;
        uow.commit().await?;
        Ok(details)
    }

    /// Gives an endpoint a new secret. The secret it replaces keeps signing
    /// for `overlap_hours`, 24 unless given; an older one still signing
    /// stops at once. Answers the new secret, which is never shown again.
    ///
    /// # Errors
    ///
    /// Returns `webhooks.endpoint_not_found` or `webhooks.overlap_invalid`.
    pub async fn rotate_secret(
        &self,
        tenant: &TenantContext,
        id: EndpointId,
        overlap_hours: Option<u32>,
        caller: Caller,
    ) -> Result<(EndpointDetails, Secret<String>), DomainError> {
        let overlap = overlap(overlap_hours)?;
        let now = self.clock.now();
        let (secret, shown) = self.new_secret(tenant, id, now).await?;

        let mut uow = self.units_of_work.begin(tenant).await?;
        // Two rotations of one endpoint happen one after the other.
        let endpoint = self
            .endpoints
            .lock(uow.as_mut(), id)
            .await?
            .ok_or_else(endpoint_not_found)?;
        let existing = self.endpoints.secrets(uow.as_mut(), id).await?;
        let ends = rotation(&existing, now, overlap);
        for (ending, at) in &ends {
            self.endpoints
                .end_secret(uow.as_mut(), *ending, *at)
                .await?;
        }
        self.endpoints
            .remove_ended_secrets(uow.as_mut(), id, now)
            .await?;
        self.endpoints.add_secret(uow.as_mut(), &secret).await?;
        self.record(
            uow.as_mut(),
            caller,
            &WebhookEvent::SecretRotated {
                endpoint_id: id,
                previous_expires_at: ends.first().map(|(_, at)| *at).filter(|at| *at > now),
            },
        )?;
        let details = self.details(uow.as_mut(), endpoint).await?;
        uow.commit().await?;
        Ok((details, shown))
    }

    /// Removes an endpoint, with its subscriptions, secrets and deliveries.
    ///
    /// # Errors
    ///
    /// Returns `webhooks.endpoint_not_found`.
    pub async fn remove(
        &self,
        tenant: &TenantContext,
        id: EndpointId,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        if !self.endpoints.remove(uow.as_mut(), id).await? {
            return Err(endpoint_not_found());
        }
        self.record(
            uow.as_mut(),
            caller,
            &WebhookEvent::EndpointRemoved { endpoint_id: id },
        )?;
        uow.commit().await
    }

    /// The tenant's deliveries that match `query`, newest first, a page at
    /// a time.
    ///
    /// # Errors
    ///
    /// Returns `request.cursor_invalid` for a cursor this did not give.
    pub async fn deliveries(
        &self,
        tenant: &TenantContext,
        query: DeliveryQuery,
        page: &PageRequest,
    ) -> Result<Page<Delivery>, DomainError> {
        let after = page_after(page)?;
        let mut uow = self.units_of_work.begin(tenant).await?;
        let mut found = self
            .deliveries
            .list(uow.as_mut(), query, after, page.limit() + 1)
            .await?;
        let more = found.len() > page.limit() as usize;
        found.truncate(page.limit() as usize);
        let next_cursor = more
            .then(|| found.last().map(|last| cursor_after(last.id())))
            .flatten();
        Ok(Page {
            items: found,
            next_cursor,
        })
    }

    /// Puts a set-aside delivery back to pending, due at once.
    ///
    /// # Errors
    ///
    /// Returns `webhooks.delivery_not_found` or
    /// `webhooks.delivery_not_set_aside`.
    pub async fn redeliver(
        &self,
        tenant: &TenantContext,
        id: DeliveryId,
        caller: Caller,
    ) -> Result<Delivery, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let mut delivery = self
            .deliveries
            .lock(uow.as_mut(), id)
            .await?
            .ok_or_else(delivery_not_found)?;
        let event = delivery.redeliver(self.clock.now())?;
        self.deliveries.update(uow.as_mut(), &delivery).await?;
        self.record(uow.as_mut(), caller, &event)?;
        uow.commit().await?;
        Ok(delivery)
    }
}
