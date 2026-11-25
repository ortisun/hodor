//! Sending deliveries: what the worker runs.
//!
//! A delivery is sent in three steps, and no transaction is open while an
//! endpoint answers: a short one leases it, the request is made, another
//! short one records what happened. See
//! `docs/architecture/contexts/webhooks.md`, "Leases, and one slow
//! endpoint".

use crate::application::ports::{DeliveryStore, DueDeliveries, EndpointStore, HmacSha256};
use crate::domain::delivery::{DeliveryId, RetryPolicy};
use crate::domain::endpoint::EndpointId;
use crate::domain::secret::{SIGNING_SECRET_PURPOSE, SigningSecret};
use crate::domain::signature::{signature_header, signed_content};
use hodor_kernel::{
    Caller, Clock, DomainError, EventEnvelope, EventId, EventMetadata, HttpClient, HttpRequest,
    SecretBox, TenantContext, Timestamp, UnitOfWorkFactory,
};
use std::sync::Arc;
use std::time::Duration;

/// How deliveries are sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliverySettings {
    /// Attempts and the waits between them.
    pub retry: RetryPolicy,
    /// The longest one attempt may take.
    pub time_limit: Duration,
    /// The most deliveries leased at once to one endpoint, across every
    /// worker.
    pub in_flight_per_endpoint: u32,
}

impl DeliverySettings {
    /// How much longer than an attempt's time limit a lease lasts.
    pub const LEASE_MARGIN: Duration = Duration::from_secs(60);
}

impl Default for DeliverySettings {
    fn default() -> Self {
        Self {
            retry: RetryPolicy::DEFAULT,
            time_limit: Duration::from_secs(10),
            in_flight_per_endpoint: 4,
        }
    }
}

/// A delivery leased to this worker, with what sending it takes.
#[derive(Debug, Clone)]
pub struct Lease {
    tenant: TenantContext,
    delivery: DeliveryId,
    endpoint: EndpointId,
    url: String,
    event_id: EventId,
    payload: String,
    attempts: u32,
    secrets: Vec<SigningSecret>,
}

impl Lease {
    /// The delivery leased.
    #[must_use]
    pub const fn delivery(&self) -> DeliveryId {
        self.delivery
    }

    /// The endpoint it goes to.
    #[must_use]
    pub const fn endpoint(&self) -> EndpointId {
        self.endpoint
    }
}

/// What one attempt did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// The endpoint took it.
    Delivered,
    /// It failed and will be tried again.
    Retrying,
    /// It failed for the last time and was set aside.
    SetAside,
    /// The delivery was no longer as it was leased: another worker had
    /// recorded it, or it was removed.
    Skipped,
}

impl AttemptOutcome {
    /// The outcome's name, in metrics and logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Retrying => "retrying",
            Self::SetAside => "set_aside",
            Self::Skipped => "skipped",
        }
    }
}

/// Leases deliveries that are due and sends them.
#[derive(Clone)]
pub struct WebhookSender {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    endpoints: Arc<dyn EndpointStore>,
    deliveries: Arc<dyn DeliveryStore>,
    due: Arc<dyn DueDeliveries>,
    secrets: Arc<dyn SecretBox>,
    http: Arc<dyn HttpClient>,
    hmac: Arc<dyn HmacSha256>,
    clock: Arc<dyn Clock>,
    settings: DeliverySettings,
}

impl std::fmt::Debug for WebhookSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookSender")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

/// The ports of [`WebhookSender`].
#[derive(Clone)]
pub struct SenderPorts {
    /// Starts units of work.
    pub units_of_work: Arc<dyn UnitOfWorkFactory>,
    /// The endpoints and their secrets.
    pub endpoints: Arc<dyn EndpointStore>,
    /// The deliveries.
    pub deliveries: Arc<dyn DeliveryStore>,
    /// The search for due deliveries across tenants.
    pub due: Arc<dyn DueDeliveries>,
    /// Opens the secrets.
    pub secrets: Arc<dyn SecretBox>,
    /// The guarded outbound client.
    pub http: Arc<dyn HttpClient>,
    /// Signs.
    pub hmac: Arc<dyn HmacSha256>,
    /// The time.
    pub clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for SenderPorts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SenderPorts").finish_non_exhaustive()
    }
}

fn lease_length(settings: &DeliverySettings) -> time::Duration {
    let length = settings.time_limit + DeliverySettings::LEASE_MARGIN;
    time::Duration::try_from(length).unwrap_or(time::Duration::hours(1))
}

/// What an error says about an attempt, without the address: the guarded
/// client's messages never repeat it.
fn reason(error: &DomainError) -> String {
    format!("{}: {}", error.code(), error.message())
}

impl WebhookSender {
    /// Wires the use case to its ports.
    #[must_use]
    pub fn new(ports: SenderPorts, settings: DeliverySettings) -> Self {
        Self {
            units_of_work: ports.units_of_work,
            endpoints: ports.endpoints,
            deliveries: ports.deliveries,
            due: ports.due,
            secrets: ports.secrets,
            http: ports.http,
            hmac: ports.hmac,
            clock: ports.clock,
            settings,
        }
    }

    /// How deliveries are sent.
    #[must_use]
    pub const fn settings(&self) -> &DeliverySettings {
        &self.settings
    }

    /// Leases up to `limit` deliveries that are due, across tenants. A
    /// delivery whose endpoint has as many in flight as it may, or that
    /// another worker holds, is left for later.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn lease_due(&self, limit: u32) -> Result<Vec<Lease>, DomainError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let now = self.clock.now();
        // More than asked for are looked at, since some will be left for
        // later; never more than a few pages.
        let candidates = self.due.due(now, limit.saturating_mul(4)).await?;
        let mut leases = Vec::new();
        for (tenant_id, delivery) in candidates {
            if leases.len() >= limit as usize {
                break;
            }
            // The worker's job loader is one of the places allowed to
            // establish a tenant context: the tenant comes from the stored
            // delivery, not from any request.
            let tenant = TenantContext::assume(tenant_id);
            if let Some(lease) = self.lease_one(&tenant, delivery, now).await? {
                leases.push(lease);
            }
        }
        Ok(leases)
    }

    async fn lease_one(
        &self,
        tenant: &TenantContext,
        id: DeliveryId,
        now: Timestamp,
    ) -> Result<Option<Lease>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let Some(seen) = self.deliveries.get(uow.as_mut(), id).await? else {
            return Ok(None);
        };
        // The endpoint first, then the delivery: removing an endpoint
        // takes them in the same order.
        let endpoint_id = seen.snapshot().endpoint_id;
        let Some(endpoint) = self.endpoints.lock(uow.as_mut(), endpoint_id).await? else {
            return Ok(None);
        };
        let Some(mut delivery) = self.deliveries.take(uow.as_mut(), id).await? else {
            return Ok(None);
        };
        if !delivery.is_due(now) {
            return Ok(None);
        }
        let in_flight = self
            .deliveries
            .leased(uow.as_mut(), endpoint_id, now)
            .await?;
        if in_flight >= self.settings.in_flight_per_endpoint {
            return Ok(None);
        }
        delivery.lease(now, now + lease_length(&self.settings))?;
        self.deliveries.update(uow.as_mut(), &delivery).await?;
        let secrets = self
            .endpoints
            .secrets(uow.as_mut(), endpoint_id)
            .await?
            .into_iter()
            .filter(|secret| secret.is_in_force(now))
            .collect();
        uow.commit().await?;
        let state = delivery.snapshot();
        Ok(Some(Lease {
            tenant: tenant.clone(),
            delivery: id,
            endpoint: endpoint_id,
            url: endpoint.url().to_owned(),
            event_id: state.event_id,
            payload: state.payload.clone(),
            attempts: state.attempts,
            secrets,
        }))
    }

    /// Signs the delivery with every secret in force, sends it, and records
    /// what happened.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails. An endpoint that refuses, does
    /// not answer, or may not be called is not an error here: it is a
    /// failed attempt.
    pub async fn send(&self, lease: Lease) -> Result<AttemptOutcome, DomainError> {
        let attempt = match self.request(&lease).await {
            Ok(request) => self.http.send(request).await,
            Err(error) => Err(error),
        };
        let now = self.clock.now();

        let mut uow = self.units_of_work.begin(&lease.tenant).await?;
        let Some(mut delivery) = self.deliveries.lock(uow.as_mut(), lease.delivery).await? else {
            return Ok(AttemptOutcome::Skipped);
        };
        if !delivery.is_as_leased(lease.attempts) {
            return Ok(AttemptOutcome::Skipped);
        }
        let (outcome, set_aside) = match attempt {
            Ok(response) if response.is_success() => {
                delivery.record_success(now, response.status);
                (AttemptOutcome::Delivered, None)
            }
            Ok(response) => {
                let reason = format!("the endpoint answered {}", response.status);
                let event = delivery.record_failure(
                    now,
                    Some(response.status),
                    &reason,
                    &self.settings.retry,
                );
                (outcome_of(event.as_ref()), event)
            }
            Err(error) => {
                let event =
                    delivery.record_failure(now, None, &reason(&error), &self.settings.retry);
                (outcome_of(event.as_ref()), event)
            }
        };
        self.deliveries.update(uow.as_mut(), &delivery).await?;
        if let Some(event) = set_aside {
            let caller = Caller::system();
            let metadata = EventMetadata::new(
                lease.tenant.tenant_id(),
                caller.actor,
                caller.correlation_id,
                self.clock.as_ref(),
            );
            uow.record_event(EventEnvelope::new(metadata, &event)?);
        }
        uow.commit().await?;
        Ok(outcome)
    }

    /// The signed request of a lease. A secret that does not open fails the
    /// attempt, as an endpoint that does not answer would.
    async fn request(&self, lease: &Lease) -> Result<HttpRequest, DomainError> {
        let webhook_id = lease.event_id.to_string();
        let timestamp = self.clock.now().unix_timestamp();
        let content = signed_content(&webhook_id, timestamp, &lease.payload);
        let mut signatures = Vec::with_capacity(lease.secrets.len());
        for secret in &lease.secrets {
            let key = self
                .secrets
                .open(&lease.tenant, SIGNING_SECRET_PURPOSE, &secret.sealed)
                .await?;
            signatures.push(self.hmac.mac(key.expose(), &content));
        }
        if signatures.is_empty() {
            return Err(DomainError::internal(
                "webhooks.no_secret",
                "the endpoint has no secret to sign with",
            ));
        }
        Ok(HttpRequest::post(
            lease.url.clone(),
            "application/json",
            lease.payload.clone().into_bytes(),
        )
        .header("webhook-id", webhook_id)
        .header("webhook-timestamp", timestamp.to_string())
        .header("webhook-signature", signature_header(&signatures))
        .within(self.settings.time_limit))
    }
}

const fn outcome_of(set_aside: Option<&crate::domain::event::WebhookEvent>) -> AttemptOutcome {
    if set_aside.is_some() {
        AttemptOutcome::SetAside
    } else {
        AttemptOutcome::Retrying
    }
}
