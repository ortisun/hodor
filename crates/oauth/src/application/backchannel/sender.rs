//! Sending logout tokens: what the worker runs.
//!
//! A delivery is sent in three steps, and no transaction is open while a
//! client answers: a short one leases it, the token is signed and the
//! request made, another short one records what happened. The rules are
//! those of webhooks; see `docs/architecture/contexts/oauth.md`,
//! "Deliveries and retries".

use crate::application::backchannel::ports::{
    DueLogoutDeliveries, LogoutDeliveryStore, TenantIssuer,
};
use crate::application::pairwise::{PairwiseSubjects, session_for, subject_for};
use crate::application::ports::ClientStore;
use crate::domain::backchannel::{
    LogoutDeliveryId, LogoutRetryPolicy, LogoutTokenSubject, logout_token_claims,
    logout_token_header,
};
use crate::domain::client::{Client, ClientId, IdTokenAlgorithm};
use crate::domain::token::{compact, signing_input};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::{
    Caller, Clock, DomainError, EventEnvelope, EventMetadata, HttpClient, HttpRequest,
    RandomSource, TenantContext, Timestamp, UnitOfWork, UnitOfWorkFactory, UserId,
};
use hodor_keys::api::KeyService;
use hodor_session::api::SessionId;
use std::sync::Arc;
use std::time::Duration;

/// How logout tokens are sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogoutDeliverySettings {
    /// Attempts and the waits between them.
    pub retry: LogoutRetryPolicy,
    /// The longest one attempt may take.
    pub time_limit: Duration,
    /// The most deliveries leased at once to one client, across every
    /// worker.
    pub in_flight_per_client: u32,
}

impl LogoutDeliverySettings {
    /// How much longer than an attempt's time limit a lease lasts.
    pub const LEASE_MARGIN: Duration = Duration::from_secs(60);
    /// How many deliveries one worker sends at once.
    pub const CONCURRENCY: u32 = 16;
}

impl Default for LogoutDeliverySettings {
    fn default() -> Self {
        Self {
            retry: LogoutRetryPolicy::DEFAULT,
            time_limit: Duration::from_secs(10),
            in_flight_per_client: 4,
        }
    }
}

/// A logout delivery leased to this worker, with what sending it takes.
#[derive(Debug, Clone)]
pub struct LogoutLease {
    tenant: TenantContext,
    delivery: LogoutDeliveryId,
    client: Client,
    client_id: ClientId,
    url: String,
    algorithm: IdTokenAlgorithm,
    session_id: SessionId,
    user_id: UserId,
    attempts: u32,
}

impl LogoutLease {
    /// The delivery leased.
    #[must_use]
    pub const fn delivery(&self) -> LogoutDeliveryId {
        self.delivery
    }

    /// The client it goes to.
    #[must_use]
    pub const fn client(&self) -> ClientId {
        self.client_id
    }
}

/// What one attempt did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogoutOutcome {
    /// The client took it.
    Delivered,
    /// It failed and will be tried again.
    Retrying,
    /// It failed for the last time and was set aside.
    SetAside,
    /// The delivery was no longer as it was leased: another worker had
    /// recorded it, or it was removed.
    Skipped,
}

impl LogoutOutcome {
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

/// The ports of [`BackChannelLogoutSender`].
#[derive(Clone)]
pub struct LogoutSenderPorts {
    /// Starts units of work.
    pub units_of_work: Arc<dyn UnitOfWorkFactory>,
    /// The clients, for their addresses and algorithms.
    pub clients: Arc<dyn ClientStore>,
    /// The deliveries.
    pub deliveries: Arc<dyn LogoutDeliveryStore>,
    /// The search for due deliveries across tenants.
    pub due: Arc<dyn DueLogoutDeliveries>,
    /// The issuer of each tenant.
    pub issuers: Arc<dyn TenantIssuer>,
    /// Signs with the tenant's keys.
    pub keys: KeyService,
    /// The guarded outbound client.
    pub http: Arc<dyn HttpClient>,
    /// The random bytes of each `jti`.
    pub random: Arc<dyn RandomSource>,
    /// The time.
    pub clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for LogoutSenderPorts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogoutSenderPorts").finish_non_exhaustive()
    }
}

/// Leases logout deliveries that are due, signs a logout token for each and
/// sends it.
#[derive(Clone)]
pub struct BackChannelLogoutSender {
    ports: LogoutSenderPorts,
    settings: LogoutDeliverySettings,
    pairwise: Option<PairwiseSubjects>,
}

impl std::fmt::Debug for BackChannelLogoutSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackChannelLogoutSender")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

fn lease_length(settings: &LogoutDeliverySettings) -> time::Duration {
    let length = settings.time_limit + LogoutDeliverySettings::LEASE_MARGIN;
    time::Duration::try_from(length).unwrap_or(time::Duration::hours(1))
}

/// What an error says about an attempt, without the address: the guarded
/// client's messages never repeat it.
fn reason(error: &DomainError) -> String {
    format!("{}: {}", error.code(), error.message())
}

/// The bytes of a `jti`.
const TOKEN_ID_BYTES: usize = 16;

impl BackChannelLogoutSender {
    /// Wires the use case to its ports.
    #[must_use]
    pub const fn new(ports: LogoutSenderPorts, settings: LogoutDeliverySettings) -> Self {
        Self {
            ports,
            settings,
            pairwise: None,
        }
    }

    /// Names the person and the session to pairwise clients through
    /// `pairwise`. Without it, an attempt for a pairwise client fails
    /// rather than give it the user identifier.
    #[must_use]
    pub fn with_pairwise_subjects(mut self, pairwise: PairwiseSubjects) -> Self {
        self.pairwise = Some(pairwise);
        self
    }

    /// How logout tokens are sent.
    #[must_use]
    pub const fn settings(&self) -> &LogoutDeliverySettings {
        &self.settings
    }

    /// Leases up to `limit` deliveries that are due, across tenants. A
    /// delivery whose client has as many in flight as it may, or that
    /// another worker holds, is left for later; one whose client can no
    /// longer be sent to is set aside.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn lease_due(&self, limit: u32) -> Result<Vec<LogoutLease>, DomainError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let now = self.ports.clock.now();
        let candidates = self.ports.due.due(now, limit.saturating_mul(4)).await?;
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
        id: LogoutDeliveryId,
        now: Timestamp,
    ) -> Result<Option<LogoutLease>, DomainError> {
        let ports = &self.ports;
        let mut uow = ports.units_of_work.begin(tenant).await?;
        let Some(seen) = ports.deliveries.get(uow.as_mut(), id).await? else {
            return Ok(None);
        };
        // The client first, then the delivery, so that two workers count
        // a client's leases one after the other.
        let client_id = seen.snapshot().client_id;
        if !ports
            .deliveries
            .hold_client(uow.as_mut(), client_id)
            .await?
        {
            return Ok(None);
        }
        let Some(mut delivery) = ports.deliveries.take(uow.as_mut(), id).await? else {
            return Ok(None);
        };
        if !delivery.is_due(now) {
            return Ok(None);
        }
        let client = ports.clients.get(uow.as_mut(), client_id).await?;
        let target = client.and_then(|client| {
            let url = client.backchannel_logout_uri()?.to_owned();
            let algorithm = client.snapshot().settings.id_token_algorithm;
            client.is_enabled().then_some((url, algorithm, client))
        });
        let Some((url, algorithm, client)) = target else {
            let event = delivery.set_aside(
                now,
                "the client has no back-channel logout address, or is disabled",
            );
            ports.deliveries.update(uow.as_mut(), &delivery).await?;
            record(uow.as_mut(), tenant, &event, ports.clock.as_ref())?;
            uow.commit().await?;
            return Ok(None);
        };
        let in_flight = ports
            .deliveries
            .leased(uow.as_mut(), client_id, now)
            .await?;
        if in_flight >= self.settings.in_flight_per_client {
            return Ok(None);
        }
        delivery.lease(now, now + lease_length(&self.settings))?;
        ports.deliveries.update(uow.as_mut(), &delivery).await?;
        uow.commit().await?;
        let state = delivery.snapshot();
        Ok(Some(LogoutLease {
            tenant: tenant.clone(),
            delivery: id,
            client,
            client_id,
            url,
            algorithm,
            session_id: state.session_id,
            user_id: state.user_id,
            attempts: state.attempts,
        }))
    }

    /// Signs a logout token for the lease, sends it, and records what
    /// happened.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails. A client that refuses, does not
    /// answer, or may not be called is not an error here: it is a failed
    /// attempt, and so is a token that could not be signed.
    pub async fn send(&self, lease: LogoutLease) -> Result<LogoutOutcome, DomainError> {
        let attempt = match self.request(&lease).await {
            Ok(request) => self.ports.http.send(request).await,
            Err(error) => Err(error),
        };
        let now = self.ports.clock.now();

        let mut uow = self.ports.units_of_work.begin(&lease.tenant).await?;
        let Some(mut delivery) = self
            .ports
            .deliveries
            .lock(uow.as_mut(), lease.delivery)
            .await?
        else {
            return Ok(LogoutOutcome::Skipped);
        };
        if !delivery.is_as_leased(lease.attempts) {
            return Ok(LogoutOutcome::Skipped);
        }
        let retry = &self.settings.retry;
        let set_aside = match attempt {
            Ok(response) if response.is_success() => {
                delivery.record_success(now, response.status);
                None
            }
            Ok(response) => {
                let reason = format!("the client answered {}", response.status);
                delivery.record_failure(now, Some(response.status), &reason, retry)
            }
            Err(error) => delivery.record_failure(now, None, &reason(&error), retry),
        };
        self.ports
            .deliveries
            .update(uow.as_mut(), &delivery)
            .await?;
        let outcome = match (&set_aside, delivery.status()) {
            (Some(event), _) => {
                record(
                    uow.as_mut(),
                    &lease.tenant,
                    event,
                    self.ports.clock.as_ref(),
                )?;
                LogoutOutcome::SetAside
            }
            (None, crate::domain::backchannel::LogoutDeliveryStatus::Delivered) => {
                LogoutOutcome::Delivered
            }
            (None, _) => LogoutOutcome::Retrying,
        };
        uow.commit().await?;
        Ok(outcome)
    }

    /// The signed request of a lease: a logout token signed now, with a
    /// `jti` of its own, posted in a form.
    async fn request(&self, lease: &LogoutLease) -> Result<HttpRequest, DomainError> {
        let issuer = self.ports.issuers.issuer(&lease.tenant).await?;
        let mut drawn = [0_u8; TOKEN_ID_BYTES];
        self.ports.random.fill(&mut drawn);
        let token_id = URL_SAFE_NO_PAD.encode(drawn);
        // The person and the session as the client knows them, computed at
        // each attempt: pairwise for a pairwise client.
        let pairwise = self.pairwise.as_ref();
        let subject = subject_for(pairwise, &lease.tenant, &lease.client, lease.user_id).await?;
        let session = session_for(pairwise, &lease.tenant, &lease.client, lease.session_id).await?;
        let claims = logout_token_claims(
            LogoutTokenSubject {
                issuer: &issuer,
                client_id: lease.client_id,
                subject: &subject,
                session: &session,
            },
            self.ports.clock.now(),
            &token_id,
        );
        let algorithm = lease.algorithm.key_algorithm();
        let message = |key_id: hodor_keys::api::KeyVersionId| {
            let header = logout_token_header(algorithm.as_str(), &key_id.to_string());
            signing_input(&header, &claims).into_bytes()
        };
        let keys = &self.ports.keys;
        // A tenant that has never signed with the client's algorithm gets
        // its first key of it now, as the token endpoint would give it.
        let signed = match keys
            .sign_naming_key(&lease.tenant, algorithm, &message)
            .await
        {
            Err(error) if error.code() == "keys.no_active_version" => {
                keys.ensure_active(&lease.tenant, algorithm, Caller::system())
                    .await?;
                keys.sign_naming_key(&lease.tenant, algorithm, &message)
                    .await?
            }
            signed => signed?,
        };
        let token = compact(&signed.0, &signed.1.bytes);
        // A compact token is base64url and dots: nothing in it needs
        // escaping in a form.
        let body = format!("logout_token={token}");
        Ok(HttpRequest::post(
            lease.url.clone(),
            "application/x-www-form-urlencoded",
            body.into_bytes(),
        )
        .within(self.settings.time_limit))
    }
}

fn record(
    uow: &mut dyn UnitOfWork,
    tenant: &TenantContext,
    event: &crate::domain::event::OauthEvent,
    clock: &dyn Clock,
) -> Result<(), DomainError> {
    let caller = Caller::system();
    let metadata = EventMetadata::new(
        tenant.tenant_id(),
        caller.actor,
        caller.correlation_id,
        clock,
    );
    uow.record_event(EventEnvelope::new(metadata, event)?);
    Ok(())
}
