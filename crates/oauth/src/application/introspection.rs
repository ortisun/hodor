//! The use cases of the revocation and introspection endpoints, and the
//! register of access tokens they and UserInfo ask.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Revocation,
//! introspection and metadata".

use crate::application::ports::{
    AccessTokenRecordStore, GrantStore, PersonStanding, RefreshTokenStore,
};
use crate::application::token::{Issuer, TokenService};
use crate::application::userinfo::published_keys;
use crate::domain::authorization::GrantStatus;
use crate::domain::client::{Client, ClientType};
use crate::domain::event::OauthEvent;
use crate::domain::introspection::{
    ActiveRefreshToken, REVOKED_BY_CLIENT, TokenQuery, active_access_token, active_refresh_token,
    inactive,
};
use crate::domain::openid::read_access_token;
use crate::domain::refresh::{FamilyStatus, RefreshTokenHash};
use crate::domain::token::TokenError;
use hodor_kernel::{
    Actor, Caller, Clock, CorrelationId, DomainError, EventEnvelope, EventMetadata, TenantContext,
    UnitOfWork, UnitOfWorkFactory, UserId,
};
use serde_json::Value;
use std::fmt;
use std::sync::Arc;

/// Whether access tokens are still in force: the register, and the grants,
/// refresh token families and workloads its records name.
#[derive(Clone)]
pub struct AccessTokenRegister {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    access_tokens: Arc<dyn AccessTokenRecordStore>,
    grants: Arc<dyn GrantStore>,
    refresh_tokens: Arc<dyn RefreshTokenStore>,
    standing: Arc<dyn PersonStanding>,
}

impl fmt::Debug for AccessTokenRegister {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessTokenRegister")
            .finish_non_exhaustive()
    }
}

impl AccessTokenRegister {
    /// The register on its stores.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        access_tokens: Arc<dyn AccessTokenRecordStore>,
        grants: Arc<dyn GrantStore>,
        refresh_tokens: Arc<dyn RefreshTokenStore>,
        standing: Arc<dyn PersonStanding>,
    ) -> Self {
        Self {
            units_of_work,
            access_tokens,
            grants,
            refresh_tokens,
            standing,
        }
    }

    /// Whether the access token `token_id`, which says it was issued to
    /// `client_id`, is still in force: recorded, not revoked, its grant
    /// and family still active, and the workload it was issued for, if
    /// any, still one that may act.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn in_force(
        &self,
        tenant: &TenantContext,
        token_id: &str,
        client_id: &str,
    ) -> Result<bool, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let Some(record) = self.access_tokens.find(uow.as_mut(), token_id).await? else {
            return Ok(false);
        };
        if record.revoked_at.is_some() || record.client_id.to_string() != client_id {
            return Ok(false);
        }
        if let Some(grant) = record.grant_id {
            let grant = self.grants.get(uow.as_mut(), grant).await?;
            if !grant.is_some_and(|grant| grant.status == GrantStatus::Active) {
                return Ok(false);
            }
        }
        if let Some(family) = record.family_id {
            let family = self.refresh_tokens.get(uow.as_mut(), family).await?;
            if !family.is_some_and(|family| family.status == FamilyStatus::Active) {
                return Ok(false);
            }
        }
        drop(uow);
        if let Some(principal) = record.principal_id {
            return Ok(self
                .standing
                .workload_that_may_act(tenant, principal)
                .await?
                .is_some());
        }
        Ok(true)
    }
}

/// Revokes the access tokens issued for a service account or an agent, when
/// it is disabled or deleted.
#[derive(Clone)]
pub struct WorkloadTokens {
    access_tokens: Arc<dyn AccessTokenRecordStore>,
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for WorkloadTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkloadTokens").finish_non_exhaustive()
    }
}

impl WorkloadTokens {
    /// The use case on the register's store.
    #[must_use]
    pub fn new(access_tokens: Arc<dyn AccessTokenRecordStore>, clock: Arc<dyn Clock>) -> Self {
        Self {
            access_tokens,
            clock,
        }
    }

    /// Revokes every access token issued for `principal` that is not
    /// revoked yet, with `reason`, in the caller's unit of work, and
    /// records `oauth.access_token_revoked` for each. Answers how many.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails. After an error the unit of work
    /// must be abandoned.
    pub async fn revoke_in(
        &self,
        uow: &mut dyn UnitOfWork,
        principal: UserId,
        reason: &'static str,
        caller: Caller,
    ) -> Result<usize, DomainError> {
        let now = self.clock.now();
        let revoked = self
            .access_tokens
            .revoke_for_principal(uow, principal, now, reason)
            .await?;
        let tenant = uow.tenant().tenant_id();
        for (client_id, token_id) in &revoked {
            let metadata = EventMetadata::new(
                tenant,
                caller.actor,
                caller.correlation_id,
                self.clock.as_ref(),
            );
            let event = OauthEvent::AccessTokenRevoked {
                client_id: *client_id,
                token_id: token_id.clone(),
                reason,
            };
            uow.record_event(EventEnvelope::new(metadata, &event)?);
        }
        Ok(revoked.len())
    }
}

impl TokenService {
    /// The register on the service's own stores.
    #[must_use]
    pub fn register(&self) -> AccessTokenRegister {
        AccessTokenRegister::new(
            self.ports.units_of_work.clone(),
            self.ports.access_tokens.clone(),
            self.ports.grants.clone(),
            self.ports.refresh_tokens.clone(),
            self.ports.standing.clone(),
        )
    }

    /// Revoking the tokens of workloads, on the service's own store.
    #[must_use]
    pub fn workload_tokens(&self) -> WorkloadTokens {
        WorkloadTokens::new(self.ports.access_tokens.clone(), self.ports.clock.clone())
    }

    /// Answers a request to the revocation endpoint at `endpoint`. Whatever
    /// the token is, a client that proved who it is is answered the same:
    /// only its own tokens are revoked.
    ///
    /// # Errors
    ///
    /// The outer error is a failure of storage; the inner one is the
    /// refusal, to be answered as it says.
    pub async fn revoke(
        &self,
        tenant: &TenantContext,
        issuer: Issuer<'_>,
        endpoint: &str,
        query: TokenQuery,
        correlation_id: CorrelationId,
    ) -> Result<Result<(), TokenError>, DomainError> {
        let client = match self
            .authenticate(tenant, issuer, endpoint, &query.client)
            .await?
        {
            Ok(client) => client,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let presented = query.token.expose();
        let digest = self.ports.digest.as_ref();
        if let Some(hash) = RefreshTokenHash::of_presented(presented, digest) {
            self.revoke_refresh_token(tenant, &client, &hash, correlation_id)
                .await?;
        } else {
            self.revoke_access_token(tenant, issuer, &client, presented, correlation_id)
                .await?;
        }
        Ok(Ok(()))
    }

    async fn revoke_refresh_token(
        &self,
        tenant: &TenantContext,
        client: &Client,
        hash: &RefreshTokenHash,
        correlation_id: CorrelationId,
    ) -> Result<(), DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let Some((mut family, _)) = self.ports.refresh_tokens.find(uow.as_mut(), hash).await?
        else {
            return Ok(());
        };
        if family.client_id != client.id() {
            // Another client's token: nothing is done, and nothing is told.
            return Ok(());
        }
        let caller = Caller {
            actor: Actor::User(family.user_id),
            correlation_id,
        };
        let now = self.ports.clock.now();
        if let Some(event) = family.revoke(REVOKED_BY_CLIENT, now) {
            self.ports
                .refresh_tokens
                .revoke(uow.as_mut(), &family)
                .await?;
            self.record(uow.as_mut(), tenant, caller, &event)?;
        }
        if let Some(mut grant) = self.ports.grants.get(uow.as_mut(), family.grant_id).await?
            && let Some(event) = grant.revoke(REVOKED_BY_CLIENT, now)
        {
            self.ports.grants.update(uow.as_mut(), &grant).await?;
            self.record(uow.as_mut(), tenant, caller, &event)?;
        }
        uow.commit().await
    }

    async fn revoke_access_token(
        &self,
        tenant: &TenantContext,
        issuer: Issuer<'_>,
        client: &Client,
        presented: &str,
        correlation_id: CorrelationId,
    ) -> Result<(), DomainError> {
        let keys = published_keys(&self.ports.keys, tenant).await?;
        let now = self.ports.clock.now();
        let Ok(token) = read_access_token(
            presented,
            issuer.issuer,
            &keys,
            now,
            self.ports.verifier.as_ref(),
        ) else {
            return Ok(());
        };
        if token.client_id != client.id().to_string() {
            // Another client's token: nothing is done, and nothing is told.
            return Ok(());
        }
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let revoked = self
            .ports
            .access_tokens
            .revoke(
                uow.as_mut(),
                client.id(),
                &token.token_id,
                now,
                REVOKED_BY_CLIENT,
            )
            .await?;
        if revoked {
            let caller = Caller {
                actor: Actor::Anonymous,
                correlation_id,
            };
            let event = OauthEvent::AccessTokenRevoked {
                client_id: client.id(),
                token_id: token.token_id,
                reason: REVOKED_BY_CLIENT,
            };
            self.record(uow.as_mut(), tenant, caller, &event)?;
        }
        uow.commit().await
    }

    /// Answers a request to the introspection endpoint at `endpoint`, as
    /// JSON. A token that is not active, or that the client may not learn
    /// about, is answered `{"active": false}` and nothing more.
    ///
    /// # Errors
    ///
    /// The outer error is a failure of storage; the inner one is the
    /// refusal, to be answered as it says.
    pub async fn introspect(
        &self,
        tenant: &TenantContext,
        issuer: Issuer<'_>,
        endpoint: &str,
        query: TokenQuery,
    ) -> Result<Result<Value, TokenError>, DomainError> {
        let client = match self
            .authenticate(tenant, issuer, endpoint, &query.client)
            .await?
        {
            Ok(client) => client,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if client.client_type() == ClientType::Public {
            return Ok(Err(TokenError::invalid_client(
                "a public client may not introspect",
            )));
        }
        let presented = query.token.expose();
        let digest = self.ports.digest.as_ref();
        let answer = if let Some(hash) = RefreshTokenHash::of_presented(presented, digest) {
            self.introspect_refresh_token(tenant, issuer, &client, &hash)
                .await?
        } else {
            self.introspect_access_token(tenant, issuer, &client, presented)
                .await?
        };
        Ok(Ok(answer.unwrap_or_else(inactive)))
    }

    async fn introspect_refresh_token(
        &self,
        tenant: &TenantContext,
        issuer: Issuer<'_>,
        client: &Client,
        hash: &RefreshTokenHash,
    ) -> Result<Option<Value>, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let Some((family, record)) = self.ports.refresh_tokens.find(uow.as_mut(), hash).await?
        else {
            return Ok(None);
        };
        let grant = self.ports.grants.get(uow.as_mut(), family.grant_id).await?;
        drop(uow);
        let now = self.ports.clock.now();
        let idle_ends = family.last_used_at + family.idle;
        let stands = family.client_id == client.id()
            && record.generation == family.generation
            && family.status == FamilyStatus::Active
            && now < family.expires_at
            && now < idle_ends
            && grant.is_some_and(|grant| grant.status == GrantStatus::Active);
        if !stands
            || !self
                .ports
                .standing
                .may_sign_in(tenant, family.user_id)
                .await?
            || (!family.offline
                && !self
                    .ports
                    .standing
                    .session_is_active(tenant, family.user_id, family.session_id)
                    .await?)
        {
            return Ok(None);
        }
        Ok(Some(active_refresh_token(
            issuer.issuer,
            &ActiveRefreshToken {
                scopes: &family.scopes,
                client_id: family.client_id,
                subject: family.user_id.to_string(),
                expires_at: family.expires_at.min(idle_ends),
                issued_at: record.issued_at,
            },
        )))
    }

    async fn introspect_access_token(
        &self,
        tenant: &TenantContext,
        issuer: Issuer<'_>,
        client: &Client,
        presented: &str,
    ) -> Result<Option<Value>, DomainError> {
        let keys = published_keys(&self.ports.keys, tenant).await?;
        let Ok(token) = read_access_token(
            presented,
            issuer.issuer,
            &keys,
            self.ports.clock.now(),
            self.ports.verifier.as_ref(),
        ) else {
            return Ok(None);
        };
        if token.client_id != client.id().to_string()
            && !self
                .serves_the_audience(tenant, client, &token.audiences)
                .await?
        {
            return Ok(None);
        }
        if !self
            .register()
            .in_force(tenant, &token.token_id, &token.client_id)
            .await?
        {
            return Ok(None);
        }
        Ok(Some(active_access_token(issuer.issuer, &token)))
    }

    /// Whether `client` belongs to the application whose resource server
    /// is one of `audiences`.
    async fn serves_the_audience(
        &self,
        tenant: &TenantContext,
        client: &Client,
        audiences: &[String],
    ) -> Result<bool, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let servers = self.ports.resource_servers.list(uow.as_mut()).await?;
        Ok(servers.iter().any(|server| {
            let snapshot = server.snapshot();
            snapshot.application_id == client.application_id()
                && audiences
                    .iter()
                    .any(|audience| audience == snapshot.audience.as_str())
        }))
    }
}
