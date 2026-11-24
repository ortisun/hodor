//! The use cases of the token endpoint: authenticating the client, and
//! exchanging a code, a refresh token or the client's own credentials for
//! tokens.

use crate::application::authorization::AuthorizationCodeService;
use crate::application::ports::{
    AccessTokenRecordStore, ApplicationStore, ClientAssertionStore, ClientStore, GrantStore,
    PersonMemberships, PersonStanding, RefreshTokenStore, ResourceServerStore,
};
use crate::domain::authorization::{CodePresentation, GrantStatus};
use crate::domain::client::{AuthenticationMethod, Client, ClientId, GrantType, TokenPolicy};
use crate::domain::event::OauthEvent;
use crate::domain::introspection::AccessTokenRecord;
use crate::domain::openid::{asks_for_openid, id_token_claims, id_token_header};
use crate::domain::refresh::{
    DEFAULT_RETRY_WINDOW, FAMILY_SECRET_PURPOSE, FamilySecret, LONGEST_RETRY_WINDOW,
    RefreshDecision, RefreshFamily, RefreshRefusal, RefreshTokenHash,
};
use crate::domain::resource_server::{GROUPS_SCOPE, OPENID_SCOPES};
use crate::domain::token::{
    AssertionAudience, GrantRequest, PresentedClient, TokenError, TokenRequest, TokenSubject,
    access_token_header, assertion_issuer, check_assertion, claims_for, compact, signing_input,
};
use hodor_kernel::{
    Actor, Caller, Clock, CorrelationId, Digest, DomainError, EventEnvelope, EventMetadata,
    GroupId, OrganizationId, RandomSource, Secret, SecretBox, SignatureVerifier, TenantContext,
    UnitOfWork, UnitOfWorkFactory, UserId,
};
use hodor_keys::api::{KeyAlgorithm, KeyService, KeyVersionId, Signature};
use std::fmt;
use std::sync::Arc;
use time::Duration;

/// The ports [`TokenService`] works through.
#[derive(Clone)]
pub struct TokenPorts {
    /// Starts units of work.
    pub units_of_work: Arc<dyn UnitOfWorkFactory>,
    /// Stores applications.
    pub applications: Arc<dyn ApplicationStore>,
    /// Stores clients.
    pub clients: Arc<dyn ClientStore>,
    /// Stores resource servers, for client credentials.
    pub resource_servers: Arc<dyn ResourceServerStore>,
    /// Stores grants.
    pub grants: Arc<dyn GrantStore>,
    /// Remembers the assertions clients have used.
    pub assertions: Arc<dyn ClientAssertionStore>,
    /// Stores refresh token families.
    pub refresh_tokens: Arc<dyn RefreshTokenStore>,
    /// The register of access tokens: a record of each one issued.
    pub access_tokens: Arc<dyn AccessTokenRecordStore>,
    /// Whether a person's session and account still stand.
    pub standing: Arc<dyn PersonStanding>,
    /// The person's organizations and groups, for `org_id` and `groups`.
    pub memberships: Arc<dyn PersonMemberships>,
    /// Seals the secrets of refresh token families.
    pub secrets: Arc<dyn SecretBox>,
    /// Redeems codes.
    pub codes: AuthorizationCodeService,
    /// Signs tokens with the tenant's keys.
    pub keys: KeyService,
    /// Checks the signatures of client assertions.
    pub verifier: Arc<dyn SignatureVerifier>,
    /// SHA-256.
    pub digest: Arc<dyn Digest>,
    /// The random bytes of tokens and token identifiers.
    pub random: Arc<dyn RandomSource>,
    /// The time.
    pub clock: Arc<dyn Clock>,
}

impl fmt::Debug for TokenPorts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenPorts").finish_non_exhaustive()
    }
}

/// What the token endpoint answers with when it issues tokens.
pub struct IssuedTokens {
    /// The access token.
    pub access_token: Secret<String>,
    /// Always `Bearer`.
    pub token_type: &'static str,
    /// How many seconds the access token lives.
    pub expires_in: i64,
    /// The scopes, separated by spaces.
    pub scope: String,
    /// A refresh token, when one was issued.
    pub refresh_token: Option<Secret<String>>,
    /// The ID token, when the scopes hold `openid`.
    pub id_token: Option<Secret<String>>,
}

impl fmt::Debug for IssuedTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedTokens")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

/// Where a tenant's tokens come from: its issuer, and the address of its
/// token endpoint.
#[derive(Debug, Clone, Copy)]
pub struct Issuer<'a> {
    /// `{public address}/t/{slug}`.
    pub issuer: &'a str,
    /// `{issuer}/oauth2/token`.
    pub token_endpoint: &'a str,
}

/// An access token, signed.
struct SignedAccessToken {
    token: String,
    token_id: String,
    expires_at: hodor_kernel::Timestamp,
    lifetime: Duration,
}

/// The use cases of the token endpoint.
#[derive(Clone)]
pub struct TokenService {
    pub(crate) ports: TokenPorts,
    retry_window: Duration,
}

impl fmt::Debug for TokenService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenService")
            .field("retry_window", &self.retry_window)
            .finish_non_exhaustive()
    }
}

/// How many times a refresh looks its token up again after losing a race.
const REFRESH_ATTEMPTS: usize = 2;

fn refusal_error(refusal: RefreshRefusal) -> TokenError {
    match refusal {
        RefreshRefusal::ScopeNotGranted => {
            TokenError::invalid_scope("a scope is not one of the refresh token's")
        }
        RefreshRefusal::ResourceNotGranted => {
            TokenError::invalid_target("the resource is not one of the refresh token's")
        }
        RefreshRefusal::Revoked => TokenError::invalid_grant("the refresh token was revoked"),
        RefreshRefusal::Expired => TokenError::invalid_grant("the refresh token has expired"),
        RefreshRefusal::Idle => TokenError::invalid_grant("the refresh token was not used in time"),
        RefreshRefusal::OtherClient => {
            TokenError::invalid_grant("another client presented the refresh token")
        }
        RefreshRefusal::Reused => TokenError::invalid_grant("the refresh token was used before"),
    }
}

impl TokenService {
    /// Wires the use cases to their ports, with the default retry window.
    #[must_use]
    pub const fn new(ports: TokenPorts) -> Self {
        Self {
            ports,
            retry_window: DEFAULT_RETRY_WINDOW,
        }
    }

    /// The same, with another retry window for refresh tokens.
    ///
    /// # Errors
    ///
    /// Returns `oauth.retry_window_invalid` unless it is 0 to 60 seconds.
    pub fn with_retry_window(mut self, window: Duration) -> Result<Self, DomainError> {
        if window.is_negative() || window > LONGEST_RETRY_WINDOW {
            return Err(DomainError::invalid(
                "oauth.retry_window_invalid",
                "the retry window of refresh tokens is 0 to 60 seconds",
            ));
        }
        self.retry_window = window;
        Ok(self)
    }

    /// Answers a request to the token endpoint.
    ///
    /// # Errors
    ///
    /// The outer error is a failure of storage or of signing; the inner
    /// one is the refusal, to be answered as it says.
    pub async fn token(
        &self,
        tenant: &TenantContext,
        issuer: Issuer<'_>,
        request: TokenRequest,
        correlation_id: CorrelationId,
    ) -> Result<Result<IssuedTokens, TokenError>, DomainError> {
        let client = match self
            .authenticate(tenant, issuer, issuer.token_endpoint, &request.client)
            .await?
        {
            Ok(client) => client,
            Err(refusal) => return Ok(Err(refusal)),
        };
        match request.grant {
            GrantRequest::AuthorizationCode {
                code,
                redirect_uri,
                verifier,
            } => {
                self.exchange_code(
                    tenant,
                    issuer,
                    &client,
                    &code,
                    &redirect_uri,
                    verifier.as_deref(),
                    correlation_id,
                )
                .await
            }
            GrantRequest::RefreshToken {
                refresh_token,
                scope,
                resource,
            } => {
                self.refresh(
                    tenant,
                    issuer,
                    &client,
                    &refresh_token,
                    scope.as_deref(),
                    resource.as_deref(),
                    correlation_id,
                )
                .await
            }
            GrantRequest::ClientCredentials { scope, resource } => {
                self.client_credentials(
                    tenant,
                    issuer,
                    &client,
                    scope.as_deref(),
                    resource.as_deref(),
                    correlation_id,
                )
                .await
            }
        }
    }

    /// Finds the client a request names and checks that it proved who it
    /// is in the way it was registered with.
    pub(crate) async fn authenticate(
        &self,
        tenant: &TenantContext,
        issuer: Issuer<'_>,
        endpoint: &str,
        presented: &PresentedClient,
    ) -> Result<Result<Client, TokenError>, DomainError> {
        let named = match presented {
            PresentedClient::Secret { client_id, .. } | PresentedClient::Public { client_id } => {
                Some(client_id.clone())
            }
            PresentedClient::Assertion {
                assertion,
                client_id,
            } => client_id.clone().or_else(|| assertion_issuer(assertion)),
        };
        let Some(client_id) = named.and_then(|text| text.parse::<ClientId>().ok()) else {
            return Ok(Err(TokenError::invalid_client("the client is unknown")));
        };
        let now = self.ports.clock.now();
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let Some(client) = self.ports.clients.get(uow.as_mut(), client_id).await? else {
            return Ok(Err(TokenError::invalid_client("the client is unknown")));
        };
        let application = self
            .ports
            .applications
            .get(uow.as_mut(), client.application_id())
            .await?;
        if !client.is_enabled() || !application.is_some_and(|application| application.is_enabled())
        {
            return Ok(Err(TokenError::invalid_client(
                "the client or its application is disabled",
            )));
        }
        let registered = client.snapshot().settings.authentication_method;
        if presented.method() != registered {
            return Ok(Err(TokenError::invalid_client(
                "the client used another method than its own",
            )));
        }
        match presented {
            PresentedClient::Secret { secret, .. } => {
                if !client.accepts_secret(secret.expose(), self.ports.digest.as_ref(), now) {
                    return Ok(Err(TokenError::invalid_client("the secret is wrong")));
                }
            }
            PresentedClient::Public { .. } => {
                // A public client proves nothing; PKCE holds it instead.
                debug_assert_eq!(registered, AuthenticationMethod::None);
            }
            PresentedClient::Assertion { assertion, .. } => {
                let audience = AssertionAudience {
                    issuer: issuer.issuer,
                    token_endpoint: issuer.token_endpoint,
                    endpoint,
                };
                let checked = match check_assertion(
                    assertion,
                    &client,
                    audience,
                    now,
                    self.ports.verifier.as_ref(),
                ) {
                    Ok(checked) => checked,
                    Err(reason) => return Ok(Err(TokenError::invalid_client(reason))),
                };
                let first = self
                    .ports
                    .assertions
                    .remember(
                        uow.as_mut(),
                        client.id(),
                        &checked.assertion_id,
                        checked.expires_at,
                    )
                    .await?;
                if !first {
                    return Ok(Err(TokenError::invalid_client(
                        "the assertion was used before",
                    )));
                }
                uow.commit().await?;
            }
        }
        Ok(Ok(client))
    }

    /// Signs an access token about `subject` for `client`.
    async fn sign(
        &self,
        tenant: &TenantContext,
        issuer: Issuer<'_>,
        client: &Client,
        subject: &TokenSubject,
    ) -> Result<Result<SignedAccessToken, TokenError>, DomainError> {
        let lifetime = client.snapshot().settings.token_policy.access_token;
        if lifetime > TokenPolicy::LONGEST_SIGNED_LIFETIME {
            // The token policy refuses such a lifetime; this is a last guard.
            return Ok(Err(TokenError::server_error(
                "the access token would outlive the rotation overlap",
            )));
        }
        let now = self.ports.clock.now();
        let claims = claims_for(
            issuer.issuer,
            subject,
            client.id(),
            lifetime,
            now,
            self.ports.random.as_ref(),
        );
        let algorithm = KeyAlgorithm::DEFAULT_SIGNING;
        let Some((message, signature)) = self
            .signed(tenant, algorithm, |key_id| {
                let header = access_token_header(algorithm.as_str(), &key_id.to_string());
                signing_input(&header, &claims.claims).into_bytes()
            })
            .await?
        else {
            return Ok(Err(TokenError::server_error(
                "the tenant has no active signing key",
            )));
        };
        Ok(Ok(SignedAccessToken {
            token: compact(&message, &signature.bytes),
            token_id: claims.token_id,
            expires_at: claims.expires_at,
            lifetime,
        }))
    }

    /// Signs the ID token for a redeemed `code`, issued with
    /// `access_token`.
    async fn sign_id_token(
        &self,
        tenant: &TenantContext,
        issuer: Issuer<'_>,
        client: &Client,
        code: &crate::domain::authorization::AuthorizationCode,
        organization: Option<OrganizationId>,
        access_token: &str,
    ) -> Result<Result<Secret<String>, TokenError>, DomainError> {
        let lifetime = client.snapshot().settings.token_policy.id_token;
        if lifetime > TokenPolicy::LONGEST_SIGNED_LIFETIME {
            return Ok(Err(TokenError::server_error(
                "the ID token would outlive the rotation overlap",
            )));
        }
        let claims = id_token_claims(
            issuer.issuer,
            code,
            organization,
            client.id(),
            lifetime,
            self.ports.clock.now(),
            access_token,
            self.ports.digest.as_ref(),
        );
        let algorithm = client
            .snapshot()
            .settings
            .id_token_algorithm
            .key_algorithm();
        let signed = self
            .signed(tenant, algorithm, |key_id| {
                let header = id_token_header(algorithm.as_str(), &key_id.to_string());
                signing_input(&header, &claims).into_bytes()
            })
            .await?;
        Ok(match signed {
            Some((message, signature)) => Ok(Secret::from(compact(&message, &signature.bytes))),
            None => Err(TokenError::server_error(
                "the tenant has no active signing key",
            )),
        })
    }

    /// Signs `message` with the tenant's active key of `algorithm`. A tenant
    /// that has none, because it was made a moment ago or has never signed
    /// with the algorithm, gets its first one at once from the keys
    /// context, as rotation would have given it. `None` only if even then
    /// there is no key to sign with.
    async fn signed<F>(
        &self,
        tenant: &TenantContext,
        algorithm: KeyAlgorithm,
        message: F,
    ) -> Result<Option<(Vec<u8>, Signature)>, DomainError>
    where
        F: Fn(KeyVersionId) -> Vec<u8> + Send + Sync,
    {
        let keys = &self.ports.keys;
        match keys.sign_naming_key(tenant, algorithm, &message).await {
            Ok(signed) => return Ok(Some(signed)),
            Err(error) if error.code() == "keys.no_active_version" => {}
            Err(error) => return Err(error),
        }
        keys.ensure_active(tenant, algorithm, Caller::system())
            .await?;
        match keys.sign_naming_key(tenant, algorithm, &message).await {
            Ok(signed) => Ok(Some(signed)),
            Err(error) if error.code() == "keys.no_active_version" => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        tenant: &TenantContext,
        caller: Caller,
        event: &OauthEvent,
    ) -> Result<(), DomainError> {
        let metadata = EventMetadata::new(
            tenant.tenant_id(),
            caller.actor,
            caller.correlation_id,
            self.ports.clock.as_ref(),
        );
        uow.record_event(EventEnvelope::new(metadata, event)?);
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "each is one part of the request; grouping them would only rename them"
    )]
    async fn exchange_code(
        &self,
        tenant: &TenantContext,
        issuer: Issuer<'_>,
        client: &Client,
        code: &str,
        redirect_uri: &str,
        verifier: Option<&str>,
        correlation_id: CorrelationId,
    ) -> Result<Result<IssuedTokens, TokenError>, DomainError> {
        let settings = &client.snapshot().settings;
        if !settings.grant_types.contains(&GrantType::AuthorizationCode) {
            return Ok(Err(TokenError::unauthorized_client(
                "the client may not use the authorization code",
            )));
        }
        let anonymous = Caller {
            actor: Actor::Anonymous,
            correlation_id,
        };
        let redeemed = match self
            .ports
            .codes
            .redeem_code(
                tenant,
                code,
                CodePresentation {
                    client_id: client.id(),
                    redirect_uri: Some(redirect_uri),
                    verifier,
                },
                anonymous,
            )
            .await
        {
            Ok(redeemed) => redeemed.code,
            Err(error) if error.code() == "oauth.code_refused" => {
                return Ok(Err(TokenError::invalid_grant("the code was refused")));
            }
            Err(error) => return Err(error),
        };
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let grant = self
            .ports
            .grants
            .get(uow.as_mut(), redeemed.grant_id)
            .await?;
        let Some(grant) = grant.filter(|grant| grant.status == GrantStatus::Active) else {
            return Ok(Err(TokenError::invalid_grant("the grant was revoked")));
        };
        drop(uow);

        let mut subject = TokenSubject::of_code(&redeemed);
        subject.organization = grant.organization;
        subject.groups = self
            .groups_for(tenant, redeemed.user_id, &redeemed.scopes)
            .await?;
        let signed = match self.sign(tenant, issuer, client, &subject).await? {
            Ok(signed) => signed,
            Err(refusal) => return Ok(Err(refusal)),
        };

        let id_token = if asks_for_openid(&redeemed.scopes) {
            match self
                .sign_id_token(
                    tenant,
                    issuer,
                    client,
                    &redeemed,
                    grant.organization,
                    &signed.token,
                )
                .await?
            {
                Ok(id_token) => Some(id_token),
                Err(refusal) => return Ok(Err(refusal)),
            }
        } else {
            None
        };

        // A refresh token comes with the code for a client allowed one.
        let family = if settings.grant_types.contains(&GrantType::RefreshToken) {
            let secret = FamilySecret::generate(self.ports.random.as_ref());
            let sealed = self
                .ports
                .secrets
                .seal(tenant, FAMILY_SECRET_PURPOSE, secret.as_secret())
                .await?;
            Some(RefreshFamily::start(
                &redeemed,
                &settings.token_policy,
                sealed,
                self.ports.clock.now(),
                self.ports.random.as_ref(),
                self.ports.digest.as_ref(),
            ))
        } else {
            None
        };

        let caller = Caller {
            actor: Actor::User(redeemed.user_id),
            correlation_id,
        };
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        if let Some((family, _)) = &family {
            self.ports
                .refresh_tokens
                .start(uow.as_mut(), family)
                .await?;
            self.record(uow.as_mut(), tenant, caller, &family.started_event())?;
        }
        self.ports
            .access_tokens
            .record(
                uow.as_mut(),
                &AccessTokenRecord::issued(
                    signed.token_id.clone(),
                    client.id(),
                    Some(redeemed.grant_id),
                    None,
                    signed.expires_at,
                ),
            )
            .await?;
        let event = OauthEvent::AccessTokenIssued {
            client_id: client.id(),
            grant_id: redeemed.grant_id,
            user_id: redeemed.user_id,
            token_id: signed.token_id.clone(),
            expires_at: signed.expires_at,
        };
        self.record(uow.as_mut(), tenant, caller, &event)?;
        uow.commit().await?;

        Ok(Ok(IssuedTokens {
            access_token: Secret::from(signed.token),
            token_type: "Bearer",
            expires_in: signed.lifetime.whole_seconds(),
            scope: redeemed.scopes.join(" "),
            refresh_token: family.map(|(_, first)| first.into_secret()),
            id_token,
        }))
    }

    /// Revokes `family` for `refusal`, and its grant when the refusal says
    /// so, in `uow`.
    async fn revoke_family(
        &self,
        uow: &mut dyn UnitOfWork,
        tenant: &TenantContext,
        family: &mut RefreshFamily,
        refusal: RefreshRefusal,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let now = self.ports.clock.now();
        if let Some(event) = family.revoke(refusal.as_str(), now) {
            self.ports.refresh_tokens.revoke(uow, family).await?;
            self.record(uow, tenant, caller, &event)?;
        }
        if refusal.revokes_the_grant()
            && let Some(mut grant) = self.ports.grants.get(uow, family.grant_id).await?
            && let Some(event) = grant.revoke(refusal.as_str(), now)
        {
            self.ports.grants.update(uow, &grant).await?;
            self.record(uow, tenant, caller, &event)?;
        }
        Ok(())
    }

    /// Finds the family of `hash` and decides the refresh. A refusal that
    /// revokes is stored before it is answered.
    #[allow(
        clippy::too_many_arguments,
        reason = "each is one part of the request; grouping them would only rename them"
    )]
    async fn decide(
        &self,
        tenant: &TenantContext,
        hash: &RefreshTokenHash,
        client: ClientId,
        scope: Option<&str>,
        resource: Option<&str>,
        caller: Caller,
    ) -> Result<Result<(RefreshFamily, RefreshDecision), TokenError>, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let Some((mut family, record)) = self.ports.refresh_tokens.find(uow.as_mut(), hash).await?
        else {
            return Ok(Err(TokenError::invalid_grant(
                "the refresh token is unknown",
            )));
        };
        let now = self.ports.clock.now();
        match family.decide(
            record.generation,
            client,
            scope,
            resource,
            now,
            self.retry_window,
        ) {
            Ok(decision) => Ok(Ok((family, decision))),
            Err(refusal) => {
                if refusal.revokes_the_family() {
                    self.revoke_family(uow.as_mut(), tenant, &mut family, refusal, caller)
                        .await?;
                    uow.commit().await?;
                }
                Ok(Err(refusal_error(refusal)))
            }
        }
    }

    /// Whether the grant, the person, their membership of the grant's
    /// organization and, without offline access, the session of `family`
    /// still stand. Answers the grant's organization when they do.
    async fn still_stands(
        &self,
        tenant: &TenantContext,
        family: &RefreshFamily,
    ) -> Result<Result<Option<OrganizationId>, TokenError>, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let grant = self.ports.grants.get(uow.as_mut(), family.grant_id).await?;
        drop(uow);
        let Some(grant) = grant.filter(|grant| grant.status == GrantStatus::Active) else {
            return Ok(Err(TokenError::invalid_grant("the grant was revoked")));
        };
        if !self
            .ports
            .standing
            .may_sign_in(tenant, family.user_id)
            .await?
        {
            return Ok(Err(TokenError::invalid_grant(
                "the person may no longer sign in",
            )));
        }
        if let Some(organization) = grant.organization
            && !self
                .ports
                .memberships
                .is_member(tenant, family.user_id, organization)
                .await?
        {
            return Ok(Err(TokenError::invalid_grant(
                "the person is no longer a member of the organization",
            )));
        }
        if !family.offline
            && !self
                .ports
                .standing
                .session_is_active(tenant, family.user_id, family.session_id)
                .await?
        {
            return Ok(Err(TokenError::invalid_grant(
                "the session the refresh token belongs to has ended",
            )));
        }
        Ok(Ok(grant.organization))
    }

    /// The effective groups of `user` when `scopes` hold `groups`, read
    /// now, so that a person taken out of a group loses it from the next
    /// token.
    async fn groups_for(
        &self,
        tenant: &TenantContext,
        user: UserId,
        scopes: &[String],
    ) -> Result<Option<Vec<GroupId>>, DomainError> {
        if !scopes.iter().any(|scope| scope == GROUPS_SCOPE) {
            return Ok(None);
        }
        Ok(Some(
            self.ports
                .memberships
                .effective_groups(tenant, user)
                .await?,
        ))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "each is one part of the request; grouping them would only rename them"
    )]
    async fn refresh(
        &self,
        tenant: &TenantContext,
        issuer: Issuer<'_>,
        client: &Client,
        presented: &Secret<String>,
        scope: Option<&str>,
        resource: Option<&str>,
        correlation_id: CorrelationId,
    ) -> Result<Result<IssuedTokens, TokenError>, DomainError> {
        if !client
            .snapshot()
            .settings
            .grant_types
            .contains(&GrantType::RefreshToken)
        {
            return Ok(Err(TokenError::unauthorized_client(
                "the client may not use refresh tokens",
            )));
        }
        let digest = self.ports.digest.as_ref();
        let Some(hash) = RefreshTokenHash::of_presented(presented.expose(), digest) else {
            return Ok(Err(TokenError::invalid_grant(
                "the refresh token is malformed",
            )));
        };
        let anonymous = Caller {
            actor: Actor::Anonymous,
            correlation_id,
        };
        for _ in 0..REFRESH_ATTEMPTS {
            let (mut family, decision) = match self
                .decide(tenant, &hash, client.id(), scope, resource, anonymous)
                .await?
            {
                Ok(decided) => decided,
                Err(refusal) => return Ok(Err(refusal)),
            };
            let organization = match self.still_stands(tenant, &family).await? {
                Ok(organization) => organization,
                Err(refusal) => return Ok(Err(refusal)),
            };
            let secret = FamilySecret::from_opened(
                self.ports
                    .secrets
                    .open(tenant, FAMILY_SECRET_PURPOSE, &family.sealed_secret)
                    .await?,
            );
            let next = secret.next_after(presented.expose(), digest);
            let caller = Caller {
                actor: Actor::User(family.user_id),
                correlation_id,
            };
            let mut uow = self.ports.units_of_work.begin(tenant).await?;
            let asked = match decision {
                RefreshDecision::Move(asked) => {
                    let moved = self
                        .ports
                        .refresh_tokens
                        .advance(
                            uow.as_mut(),
                            family.id,
                            family.generation,
                            &next.hash(digest),
                            &asked,
                            self.ports.clock.now(),
                        )
                        .await?;
                    if !moved {
                        // Another refresh with the same token moved the
                        // family first: look again, as a retry or reuse.
                        continue;
                    }
                    let event = OauthEvent::RefreshTokenRotated {
                        family_id: family.id,
                        client_id: family.client_id,
                        generation: family.generation + 1,
                    };
                    self.record(uow.as_mut(), tenant, caller, &event)?;
                    asked
                }
                RefreshDecision::Retry(asked) => {
                    if !family.is_newest(&next, digest) {
                        // The family moved again since: this is reuse.
                        self.revoke_family(
                            uow.as_mut(),
                            tenant,
                            &mut family,
                            RefreshRefusal::Reused,
                            anonymous,
                        )
                        .await?;
                        uow.commit().await?;
                        return Ok(Err(refusal_error(RefreshRefusal::Reused)));
                    }
                    asked
                }
            };
            let scopes = if asked.scopes.is_empty() {
                family.scopes.clone()
            } else {
                asked.scopes
            };
            let groups = self.groups_for(tenant, family.user_id, &scopes).await?;
            let subject = TokenSubject {
                subject: family.user_id.to_string(),
                scopes,
                audiences: asked
                    .resource
                    .map_or_else(|| family.audiences.clone(), |resource| vec![resource]),
                signed_in_at: Some(family.signed_in_at),
                acr: family.acr.clone(),
                methods: family.methods.clone(),
                organization,
                groups,
            };
            let signed = match self.sign(tenant, issuer, client, &subject).await? {
                Ok(signed) => signed,
                Err(refusal) => return Ok(Err(refusal)),
            };
            self.ports
                .access_tokens
                .record(
                    uow.as_mut(),
                    &AccessTokenRecord::issued(
                        signed.token_id.clone(),
                        client.id(),
                        Some(family.grant_id),
                        Some(family.id),
                        signed.expires_at,
                    ),
                )
                .await?;
            let event = OauthEvent::AccessTokenIssued {
                client_id: client.id(),
                grant_id: family.grant_id,
                user_id: family.user_id,
                token_id: signed.token_id.clone(),
                expires_at: signed.expires_at,
            };
            self.record(uow.as_mut(), tenant, caller, &event)?;
            uow.commit().await?;
            return Ok(Ok(IssuedTokens {
                access_token: Secret::from(signed.token),
                token_type: "Bearer",
                expires_in: signed.lifetime.whole_seconds(),
                scope: subject.scopes.join(" "),
                refresh_token: Some(next.into_secret()),
                id_token: None,
            }));
        }
        // Lost the race every time: answered as if the token were reused,
        // without revoking, since nothing here shows a theft.
        Ok(Err(TokenError::invalid_grant(
            "the refresh token kept moving while it was used",
        )))
    }

    async fn client_credentials(
        &self,
        tenant: &TenantContext,
        issuer: Issuer<'_>,
        client: &Client,
        scope: Option<&str>,
        resource: Option<&str>,
        correlation_id: CorrelationId,
    ) -> Result<Result<IssuedTokens, TokenError>, DomainError> {
        let settings = &client.snapshot().settings;
        if !settings.grant_types.contains(&GrantType::ClientCredentials) {
            return Ok(Err(TokenError::unauthorized_client(
                "the client may not use client credentials",
            )));
        }
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let servers = self.ports.resource_servers.list(uow.as_mut()).await?;
        drop(uow);

        let targets: Vec<_> = match resource {
            Some(resource) => match servers
                .iter()
                .find(|server| server.snapshot().audience.as_str() == resource)
            {
                Some(server) => vec![server],
                None => {
                    return Ok(Err(TokenError::invalid_target(
                        "the resource is not a resource server of this tenant",
                    )));
                }
            },
            None => servers.iter().collect(),
        };
        let allowed: Vec<&String> = settings
            .allowed_scopes
            .iter()
            .filter(|scope| !OPENID_SCOPES.contains(&scope.as_str()))
            .collect();
        let mut scopes: Vec<String> = Vec::new();
        match scope {
            Some(scope) => {
                for asked in scope.split(' ').filter(|asked| !asked.is_empty()) {
                    if OPENID_SCOPES.contains(&asked) || !allowed.iter().any(|a| *a == asked) {
                        return Ok(Err(TokenError::invalid_scope(
                            "a scope is not allowed to this client, or is about a person",
                        )));
                    }
                    if !targets.iter().any(|server| server.defines(asked)) {
                        return Ok(Err(TokenError::invalid_scope(
                            "a scope is defined by no resource server of the request",
                        )));
                    }
                    if !scopes.iter().any(|known| known == asked) {
                        scopes.push(asked.to_owned());
                    }
                }
            }
            None => {
                scopes = allowed
                    .iter()
                    .filter(|scope| targets.iter().any(|server| server.defines(scope)))
                    .map(|scope| (*scope).clone())
                    .collect();
            }
        }
        if scopes.is_empty() {
            return Ok(Err(TokenError::invalid_scope(
                "the client is allowed no scope of a resource server",
            )));
        }
        let audiences: Vec<String> = targets
            .iter()
            .filter(|server| scopes.iter().any(|scope| server.defines(scope)))
            .map(|server| server.snapshot().audience.as_str().to_owned())
            .collect();
        let subject = TokenSubject {
            subject: client.id().to_string(),
            scopes,
            audiences,
            signed_in_at: None,
            acr: None,
            methods: Vec::new(),
            organization: None,
            groups: None,
        };
        let signed = match self.sign(tenant, issuer, client, &subject).await? {
            Ok(signed) => signed,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let caller = Caller {
            actor: Actor::Anonymous,
            correlation_id,
        };
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        self.ports
            .access_tokens
            .record(
                uow.as_mut(),
                &AccessTokenRecord::issued(
                    signed.token_id.clone(),
                    client.id(),
                    None,
                    None,
                    signed.expires_at,
                ),
            )
            .await?;
        let event = OauthEvent::ClientAccessTokenIssued {
            client_id: client.id(),
            token_id: signed.token_id.clone(),
            expires_at: signed.expires_at,
        };
        self.record(uow.as_mut(), tenant, caller, &event)?;
        uow.commit().await?;
        Ok(Ok(IssuedTokens {
            access_token: Secret::from(signed.token),
            token_type: "Bearer",
            expires_in: signed.lifetime.whole_seconds(),
            scope: subject.scopes.join(" "),
            refresh_token: None,
            id_token: None,
        }))
    }
}
