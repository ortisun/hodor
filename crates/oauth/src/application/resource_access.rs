//! Who calls one of Hodor's own resource servers, such as the
//! Authorization API, with an access token of the tenant.
//!
//! Specified in `docs/architecture/contexts/authorization.md`, "Who may
//! ask". The token is checked as UserInfo checks one; what the caller may
//! then do is the resource server's to decide.

use crate::application::introspection::AccessTokenRegister;
use crate::application::service::ApplicationService;
use crate::application::userinfo::published_keys;
use crate::domain::application::ApplicationId;
use crate::domain::client::ClientId;
use crate::domain::forwarded::{ForwardedIdentity, presented_thumbprint};
use crate::domain::openid::{BearerRefusal, read_access_token};
use crate::domain::resource_server::ResourceServer;
use hodor_kernel::{Clock, Digest, DomainError, ErrorKind, SignatureVerifier, TenantContext};
use hodor_keys::api::KeyService;
use std::fmt;
use std::sync::Arc;

/// The ports [`ResourceAccessService`] works through.
#[derive(Clone)]
pub struct ResourceAccessPorts {
    /// Lists the tenant's published keys.
    pub keys: KeyService,
    /// Checks the access token's signature.
    pub verifier: Arc<dyn SignatureVerifier>,
    /// Whether the token is still in force.
    pub register: AccessTokenRegister,
    /// Reads the token's client, its application and its resource server.
    pub applications: ApplicationService,
    /// SHA-256, for the thumbprint of a forwarded certificate.
    pub digest: Arc<dyn Digest>,
    /// The time.
    pub clock: Arc<dyn Clock>,
}

impl fmt::Debug for ResourceAccessPorts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResourceAccessPorts")
            .finish_non_exhaustive()
    }
}

/// The caller an access token names, once every check passed.
#[derive(Debug, Clone)]
pub struct ResourceCaller {
    /// The client the token was issued to.
    pub client_id: ClientId,
    /// The application that client belongs to.
    pub application_id: ApplicationId,
    /// The token's subject: a user's identifier, a pairwise one for a
    /// pairwise client, or the client's own.
    pub subject: String,
    /// The token's scopes.
    pub scopes: Vec<String>,
    /// The resource server of the client's application, if it has one.
    pub resource_server: Option<ResourceServer>,
    /// The token's `principal_kind`, `service_account` or `agent`, when
    /// its client acts as a workload: `subject` then names that workload.
    pub principal_kind: Option<String>,
}

impl ResourceCaller {
    /// Whether the token holds `scope`.
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|given| given == scope)
    }
}

/// Checks the access tokens presented to one of Hodor's own resource
/// servers.
#[derive(Clone)]
pub struct ResourceAccessService {
    ports: ResourceAccessPorts,
}

impl fmt::Debug for ResourceAccessService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResourceAccessService")
            .finish_non_exhaustive()
    }
}

impl ResourceAccessService {
    /// Wires the use case to its ports.
    #[must_use]
    pub const fn new(ports: ResourceAccessPorts) -> Self {
        Self { ports }
    }

    /// The caller `token` names, if it is a token of the tenant whose
    /// issuer is `issuer`, for `audience`, presented with its certificate
    /// when it is bound to one, as a trusted proxy `forwarded` it, still in
    /// force, issued to an enabled client of an enabled application.
    ///
    /// # Errors
    ///
    /// The outer error is a failure of storage; the inner one is why the
    /// token is refused. No scope is checked here.
    pub async fn caller(
        &self,
        tenant: &TenantContext,
        issuer: &str,
        audience: &str,
        token: Option<&str>,
        forwarded: Option<&ForwardedIdentity>,
    ) -> Result<Result<ResourceCaller, BearerRefusal>, DomainError> {
        use BearerRefusal::InvalidToken;
        let Some(token) = token else {
            return Ok(Err(BearerRefusal::Missing));
        };
        let keys = published_keys(&self.ports.keys, tenant).await?;
        let read = match read_access_token(
            token,
            issuer,
            &keys,
            self.ports.clock.now(),
            self.ports.verifier.as_ref(),
        ) {
            Ok(read) => read,
            Err(reason) => return Ok(Err(InvalidToken(reason))),
        };
        let presented = presented_thumbprint(forwarded, self.ports.digest.as_ref());
        if let Err(reason) = read.check_certificate(presented.as_ref()) {
            return Ok(Err(InvalidToken(reason)));
        }
        if !read.audiences.iter().any(|given| given == audience) {
            return Ok(Err(InvalidToken(
                "the token is not for this resource server",
            )));
        }
        if !self
            .ports
            .register
            .in_force(tenant, &read.token_id, &read.client_id)
            .await?
        {
            return Ok(Err(InvalidToken("the token is not in force")));
        }
        let Ok(client_id) = read.client_id.parse::<ClientId>() else {
            return Ok(Err(InvalidToken("the token names no client of the tenant")));
        };
        // The client, its application and its resource server are read in
        // one transaction.
        let found = match self
            .ports
            .applications
            .client_with_application(tenant, client_id)
            .await
        {
            Ok(found) => found,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Ok(Err(InvalidToken("the client does not exist")));
            }
            Err(error) => return Err(error),
        };
        if !found.client.is_enabled() {
            return Ok(Err(InvalidToken("the client is disabled")));
        }
        let application_id = found.client.snapshot().application_id;
        let Some(application) = found.application else {
            return Ok(Err(InvalidToken("the application does not exist")));
        };
        if !application.is_enabled() {
            return Ok(Err(InvalidToken("the application is disabled")));
        }
        let resource_server = found.resource_server;
        Ok(Ok(ResourceCaller {
            client_id,
            application_id,
            subject: read.subject,
            scopes: read.scopes,
            resource_server,
            principal_kind: read.principal_kind,
        }))
    }
}
