//! Token exchange (RFC 8693): an agent's client exchanges a person's token
//! for one the agent holds on the person's behalf.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Token exchange".

use crate::application::token::{IssuedTokens, Issuer, TokenService};
use crate::application::userinfo::published_keys;
use crate::domain::client::{Client, GrantType};
use crate::domain::event::OauthEvent;
use crate::domain::exchange::{MAX_ACTORS, act_claim, actors, chain_length, exchanged_scopes};
use crate::domain::introspection::AccessTokenRecord;
use crate::domain::openid::{ReadAccessToken, read_access_token};
use crate::domain::resource_server::{Audience, OPENID_SCOPES};
use crate::domain::token::{ACCESS_TOKEN_TYPE, TokenError, TokenSubject};
use hodor_kernel::{
    Actor, Caller, CorrelationId, DomainError, Secret, TenantContext, Timestamp, UserId,
};

/// What a token exchange asks for, read from the request.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Exchange<'a> {
    /// The person's token.
    pub(crate) subject_token: &'a str,
    /// The agent's own token.
    pub(crate) actor_token: &'a str,
    /// The audience of the new token.
    pub(crate) audience: &'a str,
    /// The scopes asked for.
    pub(crate) scope: Option<&'a str>,
}

/// Every refusal of a token presented in an exchange is this one answer,
/// as RFC 8693, section 2.2.2, asks; the reason is for the logs.
const fn token_refused(reason: &'static str) -> TokenError {
    TokenError::invalid_request(reason)
}

impl TokenService {
    /// Answers `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
    /// for `client`, which proved who it is.
    pub(crate) async fn exchange(
        &self,
        tenant: &TenantContext,
        issuer: Issuer<'_>,
        client: &Client,
        asked: Exchange<'_>,
        correlation_id: CorrelationId,
    ) -> Result<Result<IssuedTokens, TokenError>, DomainError> {
        let settings = &client.snapshot().settings;
        if !settings.grant_types.contains(&GrantType::TokenExchange) {
            return Ok(Err(TokenError::unauthorized_client(
                "the client may not exchange tokens",
            )));
        }
        // The client is an agent's, and the agent must be one that may act.
        let Some(agent) = client.principal() else {
            return Ok(Err(TokenError::unauthorized_client(
                "the client acts as no agent",
            )));
        };
        match self
            .ports
            .standing
            .workload_that_may_act(tenant, agent)
            .await?
        {
            Some("agent") => {}
            Some(_) => {
                return Ok(Err(TokenError::unauthorized_client(
                    "only an agent acts on a person's behalf",
                )));
            }
            None => {
                return Ok(Err(TokenError::invalid_client(
                    "the client's agent may not act",
                )));
            }
        }

        let now = self.ports.clock.now();
        let keys = published_keys(&self.ports.keys, tenant).await?;
        let read = |token: &str| {
            read_access_token(
                token,
                issuer.issuer,
                &keys,
                now,
                self.ports.verifier.as_ref(),
            )
        };
        let register = self.register();

        // The actor: the agent's own token, issued to this client.
        let Ok(actor) = read(asked.actor_token) else {
            return Ok(Err(token_refused(
                "the actor token is not a token of this tenant",
            )));
        };
        if actor.client_id != client.id().to_string()
            || actor.subject != agent.to_string()
            || actor.principal_kind.as_deref() != Some("agent")
            || actor.act.is_some()
            || !register
                .in_force(tenant, &actor.token_id, &actor.client_id)
                .await?
        {
            return Ok(Err(token_refused(
                "the actor token is not the client's agent's own, in force",
            )));
        }

        // The subject: a person's token, in force.
        let Ok(subject) = read(asked.subject_token) else {
            return Ok(Err(token_refused(
                "the subject token is not a token of this tenant",
            )));
        };
        let Some(person) = self.person_of(tenant, &subject).await? else {
            return Ok(Err(token_refused(
                "the subject token is not about a person who may sign in",
            )));
        };
        if !register
            .in_force(tenant, &subject.token_id, &subject.client_id)
            .await?
        {
            return Ok(Err(token_refused("the subject token is not in force")));
        }
        let Some(record) = register.record(tenant, &subject.token_id).await? else {
            return Ok(Err(token_refused("the subject token has no record")));
        };
        // The organization the person signed in for, from the subject
        // token's grant, which the person must still be a member of.
        let organization = match record.grant_id {
            Some(grant_id) => {
                let mut uow = self.ports.units_of_work.begin(tenant).await?;
                let grant = self.ports.grants.get(uow.as_mut(), grant_id).await?;
                drop(uow);
                grant.and_then(|grant| grant.organization)
            }
            None => None,
        };
        if let Some(organization) = organization
            && !self
                .ports
                .memberships
                .is_member(tenant, person, organization)
                .await?
        {
            return Ok(Err(token_refused(
                "the person is no longer a member of the organization",
            )));
        }
        match chain_length(subject.act.as_ref()) {
            Some(length) if length < MAX_ACTORS => {}
            _ => {
                return Ok(Err(token_refused(
                    "the subject token's chain of actors is at its bound",
                )));
            }
        }

        // The policy: a rule pairs the subject token's audiences with the
        // one asked, and the audience is a resource server of the tenant.
        if !settings
            .exchange_rules
            .iter()
            .any(|rule| rule.allows(&subject.audiences, asked.audience))
        {
            return Ok(Err(TokenError::invalid_target(
                "the client may not exchange this token for this audience",
            )));
        }
        let server = match Audience::parse(asked.audience) {
            Ok(audience) => {
                let mut uow = self.ports.units_of_work.begin(tenant).await?;
                self.ports
                    .resource_servers
                    .find_by_audience(uow.as_mut(), &audience)
                    .await?
            }
            Err(_) => None,
        };
        let Some(server) = server else {
            return Ok(Err(TokenError::invalid_target(
                "the audience is not a resource server of this tenant",
            )));
        };
        let scopes = match exchanged_scopes(
            asked.scope,
            &subject.scopes,
            &settings.allowed_scopes,
            |scope| server.defines(scope),
            &OPENID_SCOPES,
        ) {
            Ok(scopes) => scopes,
            Err(refusal) => return Ok(Err(refusal)),
        };

        // The new token is the person's, held by the agent, and never
        // outlives the subject token.
        let act = act_claim(agent, subject.act.as_ref());
        let token_subject = TokenSubject {
            subject: person.to_string(),
            scopes,
            audiences: vec![asked.audience.to_owned()],
            signed_in_at: subject
                .auth_time
                .and_then(|seconds| Timestamp::from_unix_timestamp(seconds).ok()),
            acr: subject.acr.clone(),
            methods: Vec::new(),
            organization,
            // `groups` is one of OpenID Connect's scopes, never exchanged.
            groups: None,
            principal_kind: None,
            act: Some(act.clone()),
            amr: Some(subject.amr.clone().unwrap_or_default()),
        };
        let lifetime = settings
            .token_policy
            .access_token
            .min(subject.expires_at - now);
        let signed = match self
            .sign_living(tenant, issuer, client, &token_subject, lifetime)
            .await?
        {
            Ok(signed) => signed,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let caller = Caller {
            actor: Actor::User(agent),
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
                    record.grant_id,
                    record.family_id,
                    signed.expires_at,
                )
                .for_principal(Some(agent))
                .exchanged_from(&subject.token_id),
            )
            .await?;
        let event = OauthEvent::TokenExchanged {
            client_id: client.id(),
            subject_id: person.to_string(),
            actors: actors(Some(&act)),
            audience: asked.audience.to_owned(),
            token_id: signed.token_id.clone(),
            expires_at: signed.expires_at,
        };
        self.record(uow.as_mut(), tenant, caller, &event)?;
        uow.commit().await?;
        Ok(Ok(IssuedTokens {
            access_token: Secret::from(signed.token),
            token_type: "Bearer",
            expires_in: signed.lifetime.whole_seconds(),
            scope: token_subject.scopes.join(" "),
            refresh_token: None,
            id_token: None,
            issued_token_type: Some(ACCESS_TOKEN_TYPE),
        }))
    }

    /// The person a subject token is about, if it is about a person who may
    /// still sign in: not a workload, not a client acting for itself.
    async fn person_of(
        &self,
        tenant: &TenantContext,
        subject: &ReadAccessToken,
    ) -> Result<Option<UserId>, DomainError> {
        if subject.principal_kind.is_some() || subject.subject == subject.client_id {
            return Ok(None);
        }
        let Ok(person) = subject.subject.parse::<UserId>() else {
            return Ok(None);
        };
        Ok(self
            .ports
            .standing
            .may_sign_in(tenant, person)
            .await?
            .then_some(person))
    }
}
