//! The use cases of the end-session endpoint: checking a logout request,
//! and checking again, at the finish, where it sends the person back to.

use crate::application::ports::{ApplicationStore, ClientStore};
use crate::application::userinfo::published_keys;
use crate::domain::client::ClientId;
use crate::domain::logout::{
    LogoutParameters, LogoutRequest, ReturnAddress, check_id_token_hint, check_request,
    check_shape, refusal, still_returns,
};
use hodor_kernel::{DomainError, SignatureVerifier, TenantContext, UnitOfWork, UnitOfWorkFactory};
use hodor_keys::api::KeyService;
use std::fmt;
use std::sync::Arc;

/// The ports [`LogoutService`] works through.
#[derive(Clone)]
pub struct LogoutPorts {
    /// Starts units of work.
    pub units_of_work: Arc<dyn UnitOfWorkFactory>,
    /// Stores applications.
    pub applications: Arc<dyn ApplicationStore>,
    /// Stores clients.
    pub clients: Arc<dyn ClientStore>,
    /// Lists the tenant's published keys, to check a hint.
    pub keys: KeyService,
    /// Checks a hint's signature.
    pub verifier: Arc<dyn SignatureVerifier>,
}

impl fmt::Debug for LogoutPorts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LogoutPorts").finish_non_exhaustive()
    }
}

/// The use cases of the end-session endpoint.
#[derive(Clone)]
pub struct LogoutService {
    ports: LogoutPorts,
}

impl fmt::Debug for LogoutService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LogoutService").finish_non_exhaustive()
    }
}

/// Why a logout request was refused: the code of Hodor's page, and the
/// reason for the logs when there is more to say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogoutRefusal {
    /// The code the page names.
    pub code: &'static str,
    /// What failed, for the logs only.
    pub reason: Option<&'static str>,
}

impl From<&'static str> for LogoutRefusal {
    fn from(code: &'static str) -> Self {
        Self { code, reason: None }
    }
}

impl LogoutService {
    /// Wires the use cases to their ports.
    #[must_use]
    pub const fn new(ports: LogoutPorts) -> Self {
        Self { ports }
    }

    async fn load(
        &self,
        uow: &mut dyn UnitOfWork,
        id: ClientId,
    ) -> Result<
        Option<(
            crate::domain::client::Client,
            Option<crate::domain::application::Application>,
        )>,
        DomainError,
    > {
        let Some(client) = self.ports.clients.get(uow, id).await? else {
            return Ok(None);
        };
        let application = self
            .ports
            .applications
            .get(uow, client.application_id())
            .await?;
        Ok(Some((client, application)))
    }

    /// Checks a logout request of the tenant whose issuer is `issuer`.
    ///
    /// # Errors
    ///
    /// The outer error is a failure of storage; the inner one is the
    /// refusal, answered with Hodor's own page.
    pub async fn check(
        &self,
        tenant: &TenantContext,
        issuer: &str,
        parameters: &LogoutParameters,
    ) -> Result<Result<LogoutRequest, LogoutRefusal>, DomainError> {
        let named = match check_shape(parameters) {
            Ok(named) => named,
            Err(code) => return Ok(Err(code.into())),
        };
        let hint = match parameters.id_token_hint() {
            None => None,
            Some(token) => {
                let keys = published_keys(&self.ports.keys, tenant).await?;
                match check_id_token_hint(token, issuer, &keys, self.ports.verifier.as_ref()) {
                    Ok(hint) => Some(hint),
                    Err(reason) => {
                        return Ok(Err(LogoutRefusal {
                            code: refusal::ID_TOKEN_HINT_INVALID,
                            reason: Some(reason),
                        }));
                    }
                }
            }
        };
        let wanted = named.or_else(|| hint.as_ref().map(|hint| hint.client_id));
        let loaded = match wanted {
            Some(id) => {
                let mut uow = self.ports.units_of_work.begin(tenant).await?;
                self.load(uow.as_mut(), id).await?
            }
            None => None,
        };
        let client = loaded
            .as_ref()
            .map(|(client, application)| (client, application.as_ref()));
        Ok(check_request(parameters, named, hint, client).map_err(LogoutRefusal::from))
    }

    /// Whether a return address kept while the person was asked still
    /// holds: its client still gets tokens and the address is still one of
    /// the client's.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn still_returns(
        &self,
        tenant: &TenantContext,
        kept: &ReturnAddress,
    ) -> Result<bool, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let loaded = self.load(uow.as_mut(), kept.client_id).await?;
        Ok(still_returns(
            kept,
            loaded
                .as_ref()
                .map(|(client, application)| (client, application.as_ref())),
        ))
    }
}
