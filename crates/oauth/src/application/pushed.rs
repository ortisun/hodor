//! The use case of the pushed request endpoint: the client proves who it
//! is as at the token endpoint, and its request is checked and kept.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Pushed
//! authorization requests".

use crate::application::token::{Issuer, TokenService};
use crate::domain::pushed::{PushedAnswer, PushedRequest, PushedRequestPolicy};
use crate::domain::token::TokenError;
use hodor_kernel::{DomainError, TenantContext};

impl TokenService {
    /// Answers a request to the pushed request endpoint at `endpoint`,
    /// whose address an assertion may name as its audience. `policy` is
    /// the tenant's.
    ///
    /// # Errors
    ///
    /// The outer error is a failure of storage; the inner one is the
    /// refusal, to be answered as JSON.
    pub async fn push(
        &self,
        tenant: &TenantContext,
        issuer: Issuer<'_>,
        endpoint: &str,
        request: PushedRequest,
        policy: &PushedRequestPolicy,
    ) -> Result<Result<PushedAnswer, TokenError>, DomainError> {
        let client = match self
            .authenticate(tenant, issuer, endpoint, &request.client)
            .await?
        {
            Ok(client) => client,
            Err(refusal) => return Ok(Err(refusal)),
        };
        self.ports
            .codes
            .push(tenant, issuer.issuer, &client, request.parameters, policy)
            .await
    }
}
