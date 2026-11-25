//! The commands for webhook endpoints and their deliveries.
//!
//! Specified in `docs/architecture/contexts/webhooks.md`, "Command-line
//! tool". The use cases are the webhooks context's own, so a value the
//! administration interface refuses is refused here with the same code.

use crate::{caller, existing};
use clap::Subcommand;
use hodor_adapters_crypto::OsRandom;
use hodor_adapters_http::{GuardedHttpClient, OutboundPolicy};
use hodor_adapters_postgres::{
    Database, PgDeliveryStore, PgEndpointStore, PgTenantDirectory, PgTenantRepository,
};
use hodor_kernel::{
    DomainError, PageRequest, SealedSecret, Secret, SecretBox, SystemClock, TenantContext,
};
use hodor_tenant::api::TenantService;
use hodor_webhooks::api::{
    CATALOG, Delivery, DeliveryId, DeliveryQuery, DeliveryStatus, EndpointDetails, EndpointId,
    RegisterEndpoint, WebhookService,
};
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;

/// How many deliveries `deliveries` prints, the newest first.
const DELIVERIES_SHOWN: u32 = 100;

#[derive(Subcommand)]
pub(crate) enum WebhookCommand {
    /// Print the event types an endpoint can receive, one a line.
    EventTypes,
    /// Register an endpoint, and print its secret once.
    Add {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// Where deliveries are sent: an HTTPS address.
        #[arg(long)]
        url: String,
        /// An event type it receives; given once for each.
        #[arg(long = "event", required = true)]
        events: Vec<String>,
        /// What the administrator writes about it.
        #[arg(long)]
        description: Option<String>,
    },
    /// List the tenant's endpoints, oldest first.
    List {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
    },
    /// Replace the event types an endpoint receives.
    Subscribe {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The endpoint's identifier.
        #[arg(long)]
        id: EndpointId,
        /// An event type it receives; given once for each.
        #[arg(long = "event", required = true)]
        events: Vec<String>,
    },
    /// Give an endpoint a new secret, printed once; the previous one keeps
    /// signing for an overlap.
    RotateSecret {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The endpoint's identifier.
        #[arg(long)]
        id: EndpointId,
        /// How long the previous secret keeps signing, 0 to 168 hours; 24
        /// unless given.
        #[arg(long)]
        overlap_hours: Option<u32>,
    },
    /// Remove an endpoint, with its secrets and deliveries.
    Remove {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The endpoint's identifier.
        #[arg(long)]
        id: EndpointId,
    },
    /// List the latest deliveries, newest first.
    Deliveries {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// Only those of this endpoint.
        #[arg(long)]
        endpoint: Option<EndpointId>,
        /// Only those in this status: `pending`, `delivered` or `set_aside`.
        #[arg(long)]
        status: Option<String>,
    },
    /// Deliver a set-aside delivery again.
    Redeliver {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The delivery's identifier.
        #[arg(long)]
        delivery: DeliveryId,
    },
}

/// What the tool knows of the installation, as the server has it.
pub(crate) struct Installation<'a> {
    /// `HODOR_SECRET_KEYS`, which sealing a new secret needs.
    pub(crate) secret_keys: Option<String>,
    /// `HODOR_OUTBOUND_DEVELOPMENT_HOSTS`: empty anywhere real.
    pub(crate) development_hosts: &'a [String],
}

/// Stands in for the keys when none were given: nothing is sealed, so
/// registering an endpoint and rotating a secret are refused, and every
/// other command works.
struct NoKeys;

fn keys_missing() -> DomainError {
    DomainError::invalid(
        "secret.keys_missing",
        "HODOR_SECRET_KEYS or --secret-keys is required: an endpoint's secret is kept encrypted",
    )
}

#[async_trait::async_trait]
impl SecretBox for NoKeys {
    async fn seal(
        &self,
        _tenant: &TenantContext,
        _purpose: &str,
        _secret: &Secret<Vec<u8>>,
    ) -> Result<SealedSecret, DomainError> {
        Err(keys_missing())
    }

    async fn open(
        &self,
        _tenant: &TenantContext,
        _purpose: &str,
        _sealed: &SealedSecret,
    ) -> Result<Secret<Vec<u8>>, DomainError> {
        Err(keys_missing())
    }

    async fn needs_resealing(
        &self,
        _tenant: &TenantContext,
        _sealed: &SealedSecret,
    ) -> Result<bool, DomainError> {
        Err(keys_missing())
    }
}

fn written(at: time::OffsetDateTime) -> String {
    at.format(&Rfc3339).unwrap_or_else(|_| at.to_string())
}

/// The event types an endpoint receives, separated by commas.
fn types_of(details: &EndpointDetails) -> String {
    let types: Vec<&str> = details
        .endpoint
        .snapshot()
        .event_types
        .iter()
        .map(|known| known.as_str())
        .collect();
    types.join(",")
}

fn endpoint_line(details: &EndpointDetails) -> String {
    let state = details.endpoint.snapshot();
    format!("{} {} {}", state.id, state.url, types_of(details))
}

fn delivery_line(delivery: &Delivery) -> String {
    let state = delivery.snapshot();
    format!(
        "{} {} {} {} {}",
        state.id,
        state.status.as_str(),
        state.attempts,
        state.event_type,
        state.event_id
    )
}

fn status_named(name: &str) -> Result<DeliveryStatus, DomainError> {
    DeliveryStatus::from_name(name).ok_or_else(|| {
        DomainError::invalid(
            "request.query_invalid",
            "the status is pending, delivered or set_aside",
        )
    })
}

/// Runs one command against the tenant it names.
pub(crate) async fn run(
    database: &Database,
    installation: Installation<'_>,
    command: WebhookCommand,
) -> Result<String, DomainError> {
    let tenant = match &command {
        WebhookCommand::EventTypes => return Ok(CATALOG.join("\n")),
        WebhookCommand::Add { tenant, .. }
        | WebhookCommand::List { tenant }
        | WebhookCommand::Subscribe { tenant, .. }
        | WebhookCommand::RotateSecret { tenant, .. }
        | WebhookCommand::Remove { tenant, .. }
        | WebhookCommand::Deliveries { tenant, .. }
        | WebhookCommand::Redeliver { tenant, .. } => tenant.clone(),
    };
    let units = || Arc::new(database.clone());
    let tenants = TenantService::new(
        units(),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.clone())),
        Arc::new(SystemClock),
    );
    let context = TenantContext::assume(existing(&tenants, &tenant).await?.tenant_id);
    let secrets: Arc<dyn SecretBox> = match installation.secret_keys {
        Some(setting) => crate::secret_box(database, setting)?,
        None => Arc::new(NoKeys),
    };
    let destinations = GuardedHttpClient::new(OutboundPolicy {
        development_hosts: installation
            .development_hosts
            .iter()
            .map(|host| host.trim().to_owned())
            .filter(|host| !host.is_empty())
            .collect(),
        ..OutboundPolicy::default()
    })?;
    let service = WebhookService::new(
        units(),
        Arc::new(PgEndpointStore),
        Arc::new(PgDeliveryStore),
        secrets,
        Arc::new(destinations),
        Arc::new(OsRandom),
        Arc::new(SystemClock),
    );

    match command {
        WebhookCommand::EventTypes => Ok(String::new()),
        WebhookCommand::Add {
            url,
            events,
            description,
            ..
        } => {
            let (details, secret) = service
                .register(
                    &context,
                    RegisterEndpoint {
                        url,
                        description,
                        event_types: events,
                    },
                    caller(),
                )
                .await?;
            let state = details.endpoint.snapshot();
            Ok(format!(
                "created {} {}\nsecret {}",
                state.id,
                state.url,
                secret.expose()
            ))
        }
        WebhookCommand::List { .. } => {
            let mut lines = Vec::new();
            let mut page = PageRequest::new(Some(PageRequest::MAX_LIMIT), None);
            loop {
                let found = service.list(&context, &page).await?;
                lines.extend(found.items.iter().map(endpoint_line));
                match found.next_cursor {
                    Some(cursor) => {
                        page = PageRequest::new(Some(PageRequest::MAX_LIMIT), Some(cursor));
                    }
                    None => break,
                }
            }
            Ok(lines.join("\n"))
        }
        WebhookCommand::Subscribe { id, events, .. } => {
            let details = service
                .replace_subscriptions(&context, id, &events, caller())
                .await?;
            Ok(format!("subscribed {id} {}", types_of(&details)))
        }
        WebhookCommand::RotateSecret {
            id, overlap_hours, ..
        } => {
            let (details, secret) = service
                .rotate_secret(&context, id, overlap_hours, caller())
                .await?;
            let mut said = format!("secret {}", secret.expose());
            if let Some(until) = details.secrets.iter().find_map(|kept| kept.expires_at) {
                said.push_str(&format!("\nprevious-until {}", written(until)));
            }
            Ok(said)
        }
        WebhookCommand::Remove { id, .. } => {
            service.remove(&context, id, caller()).await?;
            Ok(format!("removed {id}"))
        }
        WebhookCommand::Deliveries {
            endpoint, status, ..
        } => {
            let query = DeliveryQuery {
                endpoint,
                status: status.as_deref().map(status_named).transpose()?,
            };
            let found = service
                .deliveries(
                    &context,
                    query,
                    &PageRequest::new(Some(DELIVERIES_SHOWN), None),
                )
                .await?;
            Ok(found
                .items
                .iter()
                .map(delivery_line)
                .collect::<Vec<_>>()
                .join("\n"))
        }
        WebhookCommand::Redeliver { delivery, .. } => {
            let delivery = service.redeliver(&context, delivery, caller()).await?;
            Ok(format!(
                "{} {}",
                delivery.snapshot().status.as_str(),
                delivery.id()
            ))
        }
    }
}
