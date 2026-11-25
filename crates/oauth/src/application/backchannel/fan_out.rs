//! The outbox handler: one logout delivery for every client signed in to
//! with a session that ended.

use crate::application::backchannel::ports::{LogoutDeliveryStore, SessionClients};
use crate::application::ports::{ApplicationStore, ClientStore};
use crate::domain::backchannel::{LogoutDelivery, SESSION_REVOKED};
use hodor_kernel::{Clock, DomainError, EventEnvelope, EventHandler, UnitOfWork, UserId};
use hodor_session::api::SessionId;
use std::sync::Arc;

/// Makes the logout deliveries of a session that ended, inside the
/// transaction in which the outbox dispatcher marks `session.revoked`
/// dispatched: an ended session leads to its deliveries exactly once.
/// Nothing leaves the database here; the worker's loop sends them.
#[derive(Clone)]
pub struct BackChannelLogoutFanOut {
    sessions: Arc<dyn SessionClients>,
    clients: Arc<dyn ClientStore>,
    applications: Arc<dyn ApplicationStore>,
    deliveries: Arc<dyn LogoutDeliveryStore>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for BackChannelLogoutFanOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackChannelLogoutFanOut")
            .finish_non_exhaustive()
    }
}

fn unreadable(field: &'static str) -> DomainError {
    DomainError::internal(
        "oauth.session_event_unreadable",
        "a session event could not be read",
    )
    .with_detail(field)
}

/// The session and the person a `session.revoked` names.
fn ended_session(event: &EventEnvelope) -> Result<(SessionId, UserId), DomainError> {
    let read = |field: &'static str| {
        event
            .payload
            .get(field)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| unreadable(field))
    };
    let session = read("session_id")?
        .parse()
        .map_err(|_| unreadable("session_id"))?;
    let user = read("user_id")?
        .parse()
        .map_err(|_| unreadable("user_id"))?;
    Ok((session, user))
}

impl BackChannelLogoutFanOut {
    /// Wires the handler to its ports.
    #[must_use]
    pub fn new(
        sessions: Arc<dyn SessionClients>,
        clients: Arc<dyn ClientStore>,
        applications: Arc<dyn ApplicationStore>,
        deliveries: Arc<dyn LogoutDeliveryStore>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            sessions,
            clients,
            applications,
            deliveries,
            clock,
        }
    }
}

#[async_trait::async_trait]
impl EventHandler for BackChannelLogoutFanOut {
    fn name(&self) -> &'static str {
        "oauth_backchannel_logout"
    }

    fn handles(&self, event_type: &str) -> bool {
        event_type == SESSION_REVOKED
    }

    async fn handle(
        &self,
        uow: &mut dyn UnitOfWork,
        event: &EventEnvelope,
    ) -> Result<(), DomainError> {
        // The unit of work is the event's tenant: only its grants and
        // clients are found, whatever the event says.
        if event.metadata.tenant_id != uow.tenant().tenant_id() {
            return Err(DomainError::internal(
                "oauth.tenant_mismatch",
                "an event was handed over in another tenant",
            ));
        }
        let (session, user) = ended_session(event)?;
        let now = self.clock.now();
        for client_id in self.sessions.clients_of(uow, session).await? {
            let Some(client) = self.clients.get(uow, client_id).await? else {
                continue;
            };
            if client.backchannel_logout_uri().is_none() || !client.is_enabled() {
                continue;
            }
            let enabled = self
                .applications
                .get(uow, client.application_id())
                .await?
                .is_some_and(|application| application.is_enabled());
            if !enabled {
                continue;
            }
            // Handled again after a failure, the event finds its deliveries
            // made and makes none twice.
            self.deliveries
                .insert(uow, &LogoutDelivery::make(client_id, session, user, now))
                .await?;
        }
        Ok(())
    }
}
