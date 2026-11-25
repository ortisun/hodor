//! The use cases of the authorization endpoint: checking a request,
//! keeping it while the person signs in, issuing a code, and redeeming one.

use crate::application::ports::{
    ApplicationStore, AuthorizationCodeStore, AuthorizationRequestStore, ClientStore, GrantStore,
    PersonMemberships, ResourceServerStore,
};
use crate::domain::authorization::{
    AuthorizationCode, AuthorizationParameters, AuthorizationRefusal, AuthorizationRequest,
    BrowserSecret, CodeHash, CodePresentation, CodeRefusal, CodeValue, Grant, PendingAuthorization,
    PendingAuthorizationId, SignedInPerson, check_request,
};
use crate::domain::consent::ConsentWait;
use crate::domain::event::OauthEvent;
use crate::domain::request_object::RequestObjectCheck;
use hodor_kernel::{
    Caller, Clock, Digest, DomainError, EventEnvelope, EventMetadata, RandomSource,
    SignatureVerifier, TenantContext, Timestamp, UnitOfWork, UnitOfWorkFactory, UserId,
};
use std::sync::Arc;

/// The ports [`AuthorizationCodeService`] works through.
#[derive(Clone)]
pub struct AuthorizationCodePorts {
    /// Starts units of work.
    pub units_of_work: Arc<dyn UnitOfWorkFactory>,
    /// Stores applications.
    pub applications: Arc<dyn ApplicationStore>,
    /// Stores clients.
    pub clients: Arc<dyn ClientStore>,
    /// Stores resource servers.
    pub resource_servers: Arc<dyn ResourceServerStore>,
    /// Stores pending requests.
    pub requests: Arc<dyn AuthorizationRequestStore>,
    /// Stores grants.
    pub grants: Arc<dyn GrantStore>,
    /// Stores codes.
    pub codes: Arc<dyn AuthorizationCodeStore>,
    /// Whether a person is a member of the organization a request names.
    pub memberships: Arc<dyn PersonMemberships>,
    /// Checks the signature of a request object.
    pub verifier: Arc<dyn SignatureVerifier>,
    /// SHA-256.
    pub digest: Arc<dyn Digest>,
    /// The random bytes of codes and secrets.
    pub random: Arc<dyn RandomSource>,
    /// The time.
    pub clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for AuthorizationCodePorts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizationCodePorts")
            .finish_non_exhaustive()
    }
}

/// A pending request that was resumed, with when it arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumedRequest {
    /// The request.
    pub request: AuthorizationRequest,
    /// When it arrived, for deciding whether the sign-in was new.
    pub received_at: Timestamp,
    /// When it waited for a person's consent: whose, and their answer.
    pub consent: Option<ConsentWait>,
}

/// What a redeemed code was issued for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedeemedCode {
    /// The code as it was stored, now redeemed.
    pub code: AuthorizationCode,
}

fn refused(reason: CodeRefusal) -> DomainError {
    DomainError::invalid(
        "oauth.code_refused",
        "the authorization code cannot be redeemed",
    )
    .with_detail(reason.as_str())
}

fn unknown_code() -> DomainError {
    DomainError::invalid(
        "oauth.code_refused",
        "the authorization code cannot be redeemed",
    )
    .with_detail("unknown")
}

/// The use cases of the authorization endpoint.
#[derive(Clone)]
pub struct AuthorizationCodeService {
    ports: AuthorizationCodePorts,
}

impl std::fmt::Debug for AuthorizationCodeService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizationCodeService")
            .finish_non_exhaustive()
    }
}

impl AuthorizationCodeService {
    /// Wires the use cases to their ports.
    #[must_use]
    pub const fn new(ports: AuthorizationCodePorts) -> Self {
        Self { ports }
    }

    /// The time now, as the service sees it.
    #[must_use]
    pub fn now(&self) -> Timestamp {
        self.ports.clock.now()
    }

    fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        caller: Caller,
        events: &[OauthEvent],
    ) -> Result<(), DomainError> {
        for event in events {
            let metadata = EventMetadata::new(
                uow.tenant().tenant_id(),
                caller.actor,
                caller.correlation_id,
                self.ports.clock.as_ref(),
            );
            uow.record_event(EventEnvelope::new(metadata, event)?);
        }
        Ok(())
    }

    /// Checks a request against the client it names in this tenant, whose
    /// issuer is `issuer`, its request object first when it has one.
    ///
    /// # Errors
    ///
    /// The outer error is a failure of storage; the inner one is the
    /// refusal, to be answered as it says.
    pub async fn check(
        &self,
        tenant: &TenantContext,
        issuer: &str,
        parameters: &AuthorizationParameters,
    ) -> Result<Result<AuthorizationRequest, AuthorizationRefusal>, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let client = match parameters.client_id() {
            Some(id) => self.ports.clients.get(uow.as_mut(), id).await?,
            None => None,
        };
        let application = match &client {
            Some(client) => {
                self.ports
                    .applications
                    .get(uow.as_mut(), client.application_id())
                    .await?
            }
            None => None,
        };
        let servers = if client.is_some() {
            self.ports.resource_servers.list(uow.as_mut()).await?
        } else {
            Vec::new()
        };
        Ok(check_request(
            parameters,
            client.as_ref(),
            application.as_ref(),
            &servers,
            RequestObjectCheck {
                issuer,
                now: self.ports.clock.now(),
                verifier: self.ports.verifier.as_ref(),
            },
        ))
    }

    /// Keeps a checked request while its person signs in. The browser gets
    /// the identifier and the secret.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn hold(
        &self,
        tenant: &TenantContext,
        request: AuthorizationRequest,
    ) -> Result<(PendingAuthorizationId, BrowserSecret), DomainError> {
        let (pending, secret) = PendingAuthorization::hold(
            request,
            self.ports.clock.now(),
            self.ports.random.as_ref(),
            self.ports.digest.as_ref(),
        );
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        self.ports.requests.insert(uow.as_mut(), &pending).await?;
        uow.commit().await?;
        Ok((pending.id, secret))
    }

    /// Takes the pending request this browser holds, once. `None` when
    /// there is none, the secret is wrong or its ten minutes are over.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn resume(
        &self,
        tenant: &TenantContext,
        id: PendingAuthorizationId,
        secret: &str,
    ) -> Result<Option<ResumedRequest>, DomainError> {
        let now = self.ports.clock.now();
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let Some(pending) = self.ports.requests.get(uow.as_mut(), id).await? else {
            return Ok(None);
        };
        if !pending.belongs_to(secret, self.ports.digest.as_ref()) {
            // Not this browser's: the request stays for its own.
            return Ok(None);
        }
        if !self.ports.requests.remove(uow.as_mut(), id).await? {
            // Resumed by another request at the same moment.
            return Ok(None);
        }
        // Taken for good, an expired one as well.
        uow.commit().await?;
        if !pending.is_live_at(now) {
            return Ok(None);
        }
        Ok(Some(ResumedRequest {
            request: pending.request,
            received_at: pending.received_at,
            consent: pending.consent,
        }))
    }

    /// Whether `user` may sign in for the organization `request` names: a
    /// member of it. A request that names none admits everyone. An
    /// organization the tenant does not have admits nobody, so that the
    /// answer does not tell which ones exist.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn admits(
        &self,
        tenant: &TenantContext,
        request: &AuthorizationRequest,
        user: UserId,
    ) -> Result<bool, DomainError> {
        match request.organization {
            None => Ok(true),
            Some(organization) => {
                self.ports
                    .memberships
                    .is_member(tenant, user, organization)
                    .await
            }
        }
    }

    /// Makes the grant and the code for a checked request and the person
    /// signed in.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn issue_code(
        &self,
        tenant: &TenantContext,
        request: &AuthorizationRequest,
        person: &SignedInPerson,
        caller: Caller,
    ) -> Result<CodeValue, DomainError> {
        let now = self.ports.clock.now();
        let grant = Grant::make(request, person, now);
        let (code, value) = AuthorizationCode::issue(
            &grant,
            request,
            person,
            now,
            self.ports.random.as_ref(),
            self.ports.digest.as_ref(),
        );
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        self.ports.grants.insert(uow.as_mut(), &grant).await?;
        self.ports.codes.insert(uow.as_mut(), &code).await?;
        self.record(uow.as_mut(), caller, &[code.issued_event()])?;
        uow.commit().await?;
        Ok(value)
    }

    /// Revokes every active grant of a person, for every client, with
    /// `reason`, in the caller's unit of work: what deprovisioning a person
    /// does. Their refresh token families and access tokens stop being in
    /// force with the grants. Answers how many were revoked.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails. After an error the unit of work
    /// must be abandoned.
    pub async fn revoke_grants_of_in(
        &self,
        uow: &mut dyn UnitOfWork,
        user: UserId,
        reason: &'static str,
        caller: Caller,
    ) -> Result<usize, DomainError> {
        let now = self.ports.clock.now();
        let mut revoked = 0;
        for mut grant in self.ports.grants.list_active_of(uow, user).await? {
            if let Some(event) = grant.revoke(reason, now) {
                self.ports.grants.update(uow, &grant).await?;
                self.record(uow, caller, &[event])?;
                revoked += 1;
            }
        }
        Ok(revoked)
    }

    async fn revoke_grant(
        &self,
        uow: &mut dyn UnitOfWork,
        code: &AuthorizationCode,
        caller: Caller,
    ) -> Result<(), DomainError> {
        if let Some(mut grant) = self.ports.grants.get(uow, code.grant_id).await?
            && let Some(event) = grant.revoke("code_reused", self.ports.clock.now())
        {
            self.ports.grants.update(uow, &grant).await?;
            self.record(uow, caller, &[event])?;
        }
        Ok(())
    }

    /// Redeems a code, once. A second redemption, by anyone, revokes the
    /// grant the code was issued under.
    ///
    /// # Errors
    ///
    /// Returns `oauth.code_refused`, with the reason as its detail, for
    /// every code that cannot be redeemed; the client is told
    /// `invalid_grant` whatever the reason.
    pub async fn redeem_code(
        &self,
        tenant: &TenantContext,
        presented_code: &str,
        presentation: CodePresentation<'_>,
        caller: Caller,
    ) -> Result<RedeemedCode, DomainError> {
        let digest = self.ports.digest.as_ref();
        let Some(hash) = CodeHash::of_presented(presented_code, digest) else {
            return Err(unknown_code());
        };
        let now = self.ports.clock.now();
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let Some(mut code) = self.ports.codes.find(uow.as_mut(), &hash).await? else {
            return Err(unknown_code());
        };
        match code.check_redemption(presentation, now, digest) {
            Ok(()) => {}
            Err(CodeRefusal::AlreadyRedeemed) => {
                self.revoke_grant(uow.as_mut(), &code, caller).await?;
                uow.commit().await?;
                return Err(refused(CodeRefusal::AlreadyRedeemed));
            }
            Err(reason) => return Err(refused(reason)),
        }
        if !self.ports.codes.redeem(uow.as_mut(), &hash, now).await? {
            // Another redemption won the race: this one is the second.
            self.revoke_grant(uow.as_mut(), &code, caller).await?;
            uow.commit().await?;
            return Err(refused(CodeRefusal::AlreadyRedeemed));
        }
        uow.commit().await?;
        code.redeemed_at = Some(now);
        Ok(RedeemedCode { code })
    }
}
