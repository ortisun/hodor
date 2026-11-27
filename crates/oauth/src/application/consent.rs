//! The use cases of consent: deciding whether to ask, keeping a request
//! while the person is asked, describing it, recording the answer, and
//! listing and withdrawing consents.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Consent".

use crate::application::ports::{
    ApplicationStore, AuthorizationRequestStore, ClientStore, ConsentStore, GrantStore,
    ResourceServerStore,
};
use crate::domain::authorization::{
    AuthorizationRequest, BrowserSecret, PendingAuthorization, PendingAuthorizationId,
    SignedInPerson,
};
use crate::domain::client::{Client, ClientId};
use crate::domain::consent::{
    Consent, ConsentAction, ConsentActor, ConsentAnswer, ConsentHistoryEntry, consented_scopes,
    must_ask,
};
use crate::domain::event::OauthEvent;
use crate::domain::refresh::OFFLINE_ACCESS;
use crate::domain::resource_server::OPENID_SCOPES;
use hodor_kernel::{
    Caller, Clock, Digest, DomainError, EventEnvelope, EventMetadata, RandomSource, TenantContext,
    Timestamp, UnitOfWork, UnitOfWorkFactory, UserId,
};
use hodor_session::api::SessionId;
use std::sync::Arc;

/// The ports [`ConsentService`] works through.
#[derive(Clone)]
pub struct ConsentPorts {
    /// Starts units of work.
    pub units_of_work: Arc<dyn UnitOfWorkFactory>,
    /// Stores consents and their history.
    pub consents: Arc<dyn ConsentStore>,
    /// Stores pending requests.
    pub requests: Arc<dyn AuthorizationRequestStore>,
    /// Stores grants, to revoke those of a withdrawn consent.
    pub grants: Arc<dyn GrantStore>,
    /// Stores clients, for their consent lifetime.
    pub clients: Arc<dyn ClientStore>,
    /// Stores applications, for their names.
    pub applications: Arc<dyn ApplicationStore>,
    /// Stores resource servers, for the descriptions of their scopes.
    pub resource_servers: Arc<dyn ResourceServerStore>,
    /// SHA-256.
    pub digest: Arc<dyn Digest>,
    /// The random bytes of a pending request's secret.
    pub random: Arc<dyn RandomSource>,
    /// The time.
    pub clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for ConsentPorts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsentPorts").finish_non_exhaustive()
    }
}

/// One scope a request asks for, as the consent page shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AskedScope {
    /// A scope of OpenID Connect, which the page words by its name.
    OpenId {
        /// The scope.
        scope: String,
    },
    /// A scope of a resource server, with what its administrator wrote.
    Resource {
        /// The scope.
        scope: String,
        /// What it lets a client do.
        description: String,
        /// The resource server's name.
        resource_server: String,
    },
}

/// What a client that registered itself says of itself, which the consent
/// page shows as the client's own words: no administrator checked it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SelfDescription {
    /// Its home page, `client_uri`.
    pub client_uri: Option<String>,
    /// Its logo, `logo_uri`.
    pub logo_uri: Option<String>,
    /// Its privacy policy, `policy_uri`.
    pub policy_uri: Option<String>,
    /// Its terms of service, `tos_uri`.
    pub tos_uri: Option<String>,
}

/// What a request that waits for consent asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentQuestion {
    /// The name of the client's application; for a client that registered
    /// itself, the client's own name.
    pub application: String,
    /// For a client that registered itself, what it says of itself.
    pub registered: Option<SelfDescription>,
    /// The scopes asked for, without `offline_access`.
    pub scopes: Vec<AskedScope>,
    /// Whether it asks for access while the person is not there.
    pub offline_access: bool,
}

/// A consent as a list shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedConsent {
    /// The consent.
    pub consent: Consent,
    /// The name of the client's application; for a client that registered
    /// itself, the client's own name.
    pub application: String,
    /// The client's login initiation address, if it named one: where the
    /// account page lets the person start a sign-in at it.
    pub initiate_login_uri: Option<String>,
}

/// The name a person knows a client by: its application's, or, for a
/// client that registered itself, its own, since every registered client
/// of a tenant shares one application.
fn shown_name(client: &Client, application: &str) -> String {
    if client.is_registered() {
        client.snapshot().settings.name.clone()
    } else {
        application.to_owned()
    }
}

fn consent_not_found() -> DomainError {
    DomainError::not_found("oauth.consent_not_found", "there is no such consent")
}

/// The use cases of consent.
#[derive(Clone)]
pub struct ConsentService {
    ports: ConsentPorts,
}

impl std::fmt::Debug for ConsentService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsentService").finish_non_exhaustive()
    }
}

impl ConsentService {
    /// Wires the use cases to their ports.
    #[must_use]
    pub const fn new(ports: ConsentPorts) -> Self {
        Self { ports }
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

    /// Whether `person` must be asked before a code is issued for
    /// `request`.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn must_ask(
        &self,
        tenant: &TenantContext,
        request: &AuthorizationRequest,
        person: &SignedInPerson,
    ) -> Result<bool, DomainError> {
        let now = self.ports.clock.now();
        if !must_ask(request, None, now) {
            // Nobody is asked whatever was agreed: nothing to read.
            return Ok(false);
        }
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let standing = self
            .ports
            .consents
            .get(uow.as_mut(), person.user_id, request.client_id)
            .await?;
        Ok(must_ask(request, standing.as_ref(), now))
    }

    /// The scopes consented to for the client of `request`, for `person`,
    /// once a code may be issued: what the `claims` parameter may give
    /// claims of (Decision 0068).
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn consented_scopes(
        &self,
        tenant: &TenantContext,
        request: &AuthorizationRequest,
        person: &SignedInPerson,
    ) -> Result<Vec<String>, DomainError> {
        let now = self.ports.clock.now();
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        if request.first_party {
            let allowed = self
                .ports
                .clients
                .get(uow.as_mut(), request.client_id)
                .await?
                .map(|client| client.snapshot().settings.allowed_scopes.clone())
                .unwrap_or_default();
            return Ok(consented_scopes(request, None, &allowed, now));
        }
        let standing = self
            .ports
            .consents
            .get(uow.as_mut(), person.user_id, request.client_id)
            .await?;
        Ok(consented_scopes(request, standing.as_ref(), &[], now))
    }

    /// Keeps `request` while `person` is asked. The browser gets the
    /// identifier and the secret.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn hold(
        &self,
        tenant: &TenantContext,
        request: AuthorizationRequest,
        person: &SignedInPerson,
    ) -> Result<(PendingAuthorizationId, BrowserSecret), DomainError> {
        let (pending, secret) = PendingAuthorization::hold_for_consent(
            request,
            person,
            self.ports.clock.now(),
            self.ports.random.as_ref(),
            self.ports.digest.as_ref(),
        );
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        self.ports.requests.insert(uow.as_mut(), &pending).await?;
        uow.commit().await?;
        Ok((pending.id, secret))
    }

    /// The pending request this browser holds, when it waits, unanswered,
    /// for the consent of the person signed in with `session` as `user`.
    async fn waiting(
        &self,
        uow: &mut dyn UnitOfWork,
        id: PendingAuthorizationId,
        secret: &str,
        user: UserId,
        session: SessionId,
        now: Timestamp,
    ) -> Result<Option<PendingAuthorization>, DomainError> {
        let Some(pending) = self.ports.requests.get(uow, id).await? else {
            return Ok(None);
        };
        let waits = pending.consent.is_some_and(|wait| {
            wait.user_id == user && wait.session_id == session && wait.answer.is_none()
        });
        let ours = pending.belongs_to(secret, self.ports.digest.as_ref());
        Ok((waits && ours && pending.is_live_at(now)).then_some(pending))
    }

    /// What the request this browser holds asks for, when it waits for the
    /// consent of the person signed in with `session` as `user`.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn describe(
        &self,
        tenant: &TenantContext,
        id: PendingAuthorizationId,
        secret: &str,
        user: UserId,
        session: SessionId,
    ) -> Result<Option<ConsentQuestion>, DomainError> {
        let now = self.ports.clock.now();
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let Some(pending) = self
            .waiting(uow.as_mut(), id, secret, user, session, now)
            .await?
        else {
            return Ok(None);
        };
        let request = &pending.request;
        let Some(client) = self
            .ports
            .clients
            .get(uow.as_mut(), request.client_id)
            .await?
        else {
            return Ok(None);
        };
        let Some(application) = self
            .ports
            .applications
            .get(uow.as_mut(), client.application_id())
            .await?
        else {
            return Ok(None);
        };
        let servers = self.ports.resource_servers.list(uow.as_mut()).await?;
        let mut scopes = Vec::new();
        for scope in &request.scopes {
            if scope == OFFLINE_ACCESS {
                continue;
            }
            if OPENID_SCOPES.contains(&scope.as_str()) {
                scopes.push(AskedScope::OpenId {
                    scope: scope.clone(),
                });
                continue;
            }
            let defined = servers
                .iter()
                .filter(|server| {
                    request
                        .audiences
                        .iter()
                        .any(|audience| audience == server.audience().as_str())
                })
                .find_map(|server| {
                    let settings = &server.snapshot().settings;
                    settings
                        .scopes
                        .iter()
                        .find(|definition| &definition.name == scope)
                        .map(|definition| (definition.description.clone(), settings.name.clone()))
                });
            // A scope is checked against these resource servers when the
            // request arrives; one removed since is shown by its name.
            let (description, resource_server) =
                defined.unwrap_or_else(|| (scope.clone(), String::new()));
            scopes.push(AskedScope::Resource {
                scope: scope.clone(),
                description,
                resource_server,
            });
        }
        let registered = client.is_registered().then(|| {
            let settings = &client.snapshot().settings;
            SelfDescription {
                client_uri: settings.client_uri.clone(),
                logo_uri: settings.logo_uri.clone(),
                policy_uri: settings.policy_uri.clone(),
                tos_uri: settings.tos_uri.clone(),
            }
        });
        Ok(Some(ConsentQuestion {
            application: shown_name(&client, application.name()),
            registered,
            scopes,
            offline_access: request.scopes.iter().any(|scope| scope == OFFLINE_ACCESS),
        }))
    }

    /// Records the person's answer to the request this browser holds, once.
    /// Agreeing records the consent at once. Returns false when there is
    /// no such request waiting for this person's answer.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn answer(
        &self,
        tenant: &TenantContext,
        id: PendingAuthorizationId,
        secret: &str,
        person: &SignedInPerson,
        answer: ConsentAnswer,
        caller: Caller,
    ) -> Result<bool, DomainError> {
        let now = self.ports.clock.now();
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let Some(pending) = self
            .waiting(
                uow.as_mut(),
                id,
                secret,
                person.user_id,
                person.session_id,
                now,
            )
            .await?
        else {
            return Ok(false);
        };
        if !self.ports.requests.answer(uow.as_mut(), id, answer).await? {
            // Answered by another request at the same moment.
            return Ok(false);
        }
        let request = &pending.request;
        match answer {
            ConsentAnswer::Agreed => {
                let Some(client) = self
                    .ports
                    .clients
                    .get(uow.as_mut(), request.client_id)
                    .await?
                else {
                    return Ok(false);
                };
                let existing = self
                    .ports
                    .consents
                    .get(uow.as_mut(), person.user_id, request.client_id)
                    .await?;
                let consent = Consent::give(
                    existing.as_ref(),
                    person.user_id,
                    request,
                    client.snapshot().settings.token_policy.consent,
                    now,
                );
                self.ports.consents.save(uow.as_mut(), &consent).await?;
                self.ports
                    .consents
                    .record(
                        uow.as_mut(),
                        &ConsentHistoryEntry {
                            user_id: person.user_id,
                            client_id: request.client_id,
                            action: ConsentAction::Given,
                            scopes: request.scopes.clone(),
                            audiences: request.audiences.clone(),
                            by: ConsentActor::Person,
                            at: now,
                        },
                    )
                    .await?;
                self.record(uow.as_mut(), caller, &[consent.given_event()])?;
            }
            ConsentAnswer::Refused => {
                self.ports
                    .consents
                    .record(
                        uow.as_mut(),
                        &ConsentHistoryEntry {
                            user_id: person.user_id,
                            client_id: request.client_id,
                            action: ConsentAction::Refused,
                            scopes: request.scopes.clone(),
                            audiences: request.audiences.clone(),
                            by: ConsentActor::Person,
                            at: now,
                        },
                    )
                    .await?;
                self.record(
                    uow.as_mut(),
                    caller,
                    &[OauthEvent::ConsentRefused {
                        client_id: request.client_id,
                        user_id: person.user_id,
                    }],
                )?;
            }
        }
        uow.commit().await?;
        Ok(true)
    }

    /// The person's consents that stand, with their applications' names.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn list(
        &self,
        tenant: &TenantContext,
        user: UserId,
    ) -> Result<Vec<ListedConsent>, DomainError> {
        let now = self.ports.clock.now();
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let consents = self
            .ports
            .consents
            .list_standing(uow.as_mut(), user, now)
            .await?;
        let mut listed = Vec::with_capacity(consents.len());
        for consent in consents {
            let Some(client) = self
                .ports
                .clients
                .get(uow.as_mut(), consent.client_id)
                .await?
            else {
                continue;
            };
            let application = self
                .ports
                .applications
                .get(uow.as_mut(), client.application_id())
                .await?
                .map(|application| shown_name(&client, application.name()))
                .unwrap_or_default();
            let initiate_login_uri = client.snapshot().settings.initiate_login_uri.clone();
            listed.push(ListedConsent {
                consent,
                application,
                initiate_login_uri,
            });
        }
        Ok(listed)
    }

    /// Withdraws the person's consent for the client and revokes every
    /// active grant of theirs for it.
    ///
    /// # Errors
    ///
    /// Returns `oauth.consent_not_found` when the person has no consent
    /// for the client that stands.
    pub async fn withdraw(
        &self,
        tenant: &TenantContext,
        user: UserId,
        client: ClientId,
        by: ConsentActor,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let now = self.ports.clock.now();
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let Some(mut consent) = self.ports.consents.get(uow.as_mut(), user, client).await? else {
            return Err(consent_not_found());
        };
        let Some(withdrawn) = consent.withdraw(by, now) else {
            return Err(consent_not_found());
        };
        self.ports.consents.save(uow.as_mut(), &consent).await?;
        self.ports
            .consents
            .record(
                uow.as_mut(),
                &ConsentHistoryEntry {
                    user_id: user,
                    client_id: client,
                    action: ConsentAction::Withdrawn,
                    scopes: consent.scopes.clone(),
                    audiences: consent.audiences.clone(),
                    by,
                    at: now,
                },
            )
            .await?;
        let mut events = vec![withdrawn];
        for mut grant in self
            .ports
            .grants
            .list_active_for(uow.as_mut(), user, client)
            .await?
        {
            if let Some(event) = grant.revoke("consent_withdrawn", now) {
                self.ports.grants.update(uow.as_mut(), &grant).await?;
                events.push(event);
            }
        }
        self.record(uow.as_mut(), caller, &events)?;
        uow.commit().await
    }
}
