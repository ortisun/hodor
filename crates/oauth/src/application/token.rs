//! The use cases of the token endpoint: authenticating the client and
//! exchanging a code for an access token.

use crate::application::authorization::AuthorizationCodeService;
use crate::application::ports::{ApplicationStore, ClientAssertionStore, ClientStore, GrantStore};
use crate::domain::authorization::{CodePresentation, GrantStatus};
use crate::domain::client::{AuthenticationMethod, Client, ClientId, GrantType, TokenPolicy};
use crate::domain::event::OauthEvent;
use crate::domain::openid::{asks_for_openid, id_token_claims, id_token_header};
use crate::domain::token::{
    AssertionAudience, GrantRequest, PresentedClient, TokenError, TokenRequest,
    access_token_claims, access_token_header, assertion_issuer, check_assertion, compact,
    signing_input,
};
use hodor_kernel::{
    Actor, Caller, Clock, CorrelationId, Digest, DomainError, EventEnvelope, EventMetadata,
    RandomSource, Secret, SignatureVerifier, TenantContext, UnitOfWorkFactory,
};
use hodor_keys::api::{KeyAlgorithm, KeyService};
use std::fmt;
use std::sync::Arc;

/// The ports [`TokenService`] works through.
#[derive(Clone)]
pub struct TokenPorts {
    /// Starts units of work.
    pub units_of_work: Arc<dyn UnitOfWorkFactory>,
    /// Stores applications.
    pub applications: Arc<dyn ApplicationStore>,
    /// Stores clients.
    pub clients: Arc<dyn ClientStore>,
    /// Stores grants.
    pub grants: Arc<dyn GrantStore>,
    /// Remembers the assertions clients have used.
    pub assertions: Arc<dyn ClientAssertionStore>,
    /// Redeems codes.
    pub codes: AuthorizationCodeService,
    /// Signs tokens with the tenant's keys.
    pub keys: KeyService,
    /// Checks the signatures of client assertions.
    pub verifier: Arc<dyn SignatureVerifier>,
    /// SHA-256.
    pub digest: Arc<dyn Digest>,
    /// The random bytes of token identifiers.
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
    /// A refresh token: Issue-57.
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

/// The use cases of the token endpoint.
#[derive(Clone)]
pub struct TokenService {
    ports: TokenPorts,
}

impl fmt::Debug for TokenService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenService").finish_non_exhaustive()
    }
}

impl TokenService {
    /// Wires the use cases to their ports.
    #[must_use]
    pub const fn new(ports: TokenPorts) -> Self {
        Self { ports }
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
        let client = match self.authenticate(tenant, issuer, &request.client).await? {
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
        }
    }

    /// Finds the client a request names and checks that it proved who it
    /// is in the way it was registered with.
    async fn authenticate(
        &self,
        tenant: &TenantContext,
        issuer: Issuer<'_>,
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
        if !grant.is_some_and(|grant| grant.status == GrantStatus::Active) {
            return Ok(Err(TokenError::invalid_grant("the grant was revoked")));
        }
        drop(uow);

        let lifetime = settings.token_policy.access_token;
        if lifetime > TokenPolicy::LONGEST_SIGNED_LIFETIME {
            // The token policy refuses such a lifetime; this is a last guard.
            return Ok(Err(TokenError::server_error(
                "the access token would outlive the rotation overlap",
            )));
        }
        let now = self.ports.clock.now();
        let claims = access_token_claims(
            issuer.issuer,
            &redeemed,
            client.id(),
            lifetime,
            now,
            self.ports.random.as_ref(),
        );
        let algorithm = KeyAlgorithm::DEFAULT_SIGNING;
        let signed = self
            .ports
            .keys
            .sign_naming_key(tenant, algorithm, |key_id| {
                let header = access_token_header(algorithm.as_str(), &key_id.to_string());
                signing_input(&header, &claims.claims).into_bytes()
            })
            .await;
        let (message, signature) = match signed {
            Ok(signed) => signed,
            Err(error) if error.code() == "keys.no_active_version" => {
                return Ok(Err(TokenError::server_error(
                    "the tenant has no active signing key",
                )));
            }
            Err(error) => return Err(error),
        };
        let access_token = compact(&message, &signature.bytes);

        let id_token = if asks_for_openid(&redeemed.scopes) {
            let id_lifetime = settings.token_policy.id_token;
            if id_lifetime > TokenPolicy::LONGEST_SIGNED_LIFETIME {
                return Ok(Err(TokenError::server_error(
                    "the ID token would outlive the rotation overlap",
                )));
            }
            let id_claims = id_token_claims(
                issuer.issuer,
                &redeemed,
                client.id(),
                id_lifetime,
                now,
                &access_token,
                self.ports.digest.as_ref(),
            );
            let signed = self
                .ports
                .keys
                .sign_naming_key(tenant, algorithm, |key_id| {
                    let header = id_token_header(algorithm.as_str(), &key_id.to_string());
                    signing_input(&header, &id_claims).into_bytes()
                })
                .await;
            let (message, signature) = match signed {
                Ok(signed) => signed,
                Err(error) if error.code() == "keys.no_active_version" => {
                    return Ok(Err(TokenError::server_error(
                        "the tenant has no active signing key",
                    )));
                }
                Err(error) => return Err(error),
            };
            Some(Secret::from(compact(&message, &signature.bytes)))
        } else {
            None
        };

        let caller = Caller {
            actor: Actor::User(redeemed.user_id),
            correlation_id,
        };
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let event = OauthEvent::AccessTokenIssued {
            client_id: client.id(),
            grant_id: redeemed.grant_id,
            user_id: redeemed.user_id,
            token_id: claims.token_id.clone(),
            expires_at: claims.expires_at,
        };
        let metadata = EventMetadata::new(
            tenant.tenant_id(),
            caller.actor,
            caller.correlation_id,
            self.ports.clock.as_ref(),
        );
        uow.record_event(EventEnvelope::new(metadata, &event)?);
        uow.commit().await?;

        Ok(Ok(IssuedTokens {
            access_token: Secret::from(access_token),
            token_type: "Bearer",
            expires_in: lifetime.whole_seconds(),
            scope: redeemed.scopes.join(" "),
            refresh_token: None,
            id_token,
        }))
    }
}
