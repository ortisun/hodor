//! The use cases of the authorization endpoint: checking a request,
//! keeping it while the person signs in, issuing a code, and redeeming one.

use crate::application::client_keys::{ClientKeySets, keys_of};
use crate::application::pairwise::{PairwiseSubjects, subject_for};
use crate::application::ports::{
    ApplicationStore, AuthorizationCodeStore, AuthorizationRequestStore, ClientStore, GrantStore,
    PersonMemberships, ResourceServerStore,
};
use crate::application::userinfo::published_keys;
use crate::domain::authorization::{
    AuthorizationCode, AuthorizationError, AuthorizationParameters, AuthorizationRefusal,
    AuthorizationRequest, BrowserSecret, CodeHash, CodePresentation, CodeRefusal, CodeValue, Grant,
    PendingAuthorization, PendingAuthorizationId, SignedInPerson, check_request, trusted_client,
};
use crate::domain::client::Client;
use crate::domain::consent::ConsentWait;
use crate::domain::event::OauthEvent;
use crate::domain::logout::check_id_token_hint;
use crate::domain::pushed::{
    MAX_PUSHED_PER_CLIENT, PushedAnswer, PushedAuthorization, PushedRequestPolicy, Reference,
    ReferenceHash, check_pushed_request, check_reference, pushed_lifetime,
};
use crate::domain::request_object::RequestObjectCheck;
use crate::domain::request_uri::{
    FetchRefusal, REQUEST_OBJECT_ACCEPT, REQUEST_OBJECT_TIME_LIMIT, address_to_fetch,
    fetched_object, refused_fetch, with_fetched_object,
};
use crate::domain::resource_server::ResourceServer;
use crate::domain::token::TokenError;
use hodor_kernel::{
    Caller, Clock, DestinationCheck, Digest, DomainError, EventEnvelope, EventMetadata, HttpClient,
    HttpRequest, RandomSource, SignatureVerifier, TenantContext, Timestamp, UnitOfWork,
    UnitOfWorkFactory, UserId,
};
use hodor_keys::api::KeyService;
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

/// What the authorization endpoint made for an answer: the grant, for
/// every type but `none`, and the code, for a type that returns one. The
/// ID token of a type that returns one is signed from these by
/// [`TokenService::browser_id_token`](crate::api::TokenService::browser_id_token).
#[derive(Debug)]
pub struct AuthorizationAnswer {
    /// The grant made, if any.
    pub grant: Option<Grant>,
    /// The code, if one was issued, once.
    pub code: Option<CodeValue>,
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

/// What fetches a request object at a client's address: the guarded
/// outbound client, which checks the destination and fetches it.
#[derive(Clone)]
struct RequestObjectFetch {
    destinations: Arc<dyn DestinationCheck>,
    http: Arc<dyn HttpClient>,
}

/// The use cases of the authorization endpoint.
#[derive(Clone)]
pub struct AuthorizationCodeService {
    ports: AuthorizationCodePorts,
    hints: Option<KeyService>,
    pairwise: Option<PairwiseSubjects>,
    fetch: Option<RequestObjectFetch>,
    client_keys: Option<ClientKeySets>,
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
        Self {
            ports,
            hints: None,
            pairwise: None,
            fetch: None,
            client_keys: None,
        }
    }

    /// Checks an `id_token_hint` with the tenant's published `keys` and
    /// the ports' verifier. Without the keys, a request with a hint is refused
    /// rather than answered as if it had none.
    #[must_use]
    pub fn with_id_token_hints(mut self, keys: KeyService) -> Self {
        self.hints = Some(keys);
        self
    }

    /// Compares the hint of a pairwise client, and the `sub` its request
    /// asks for through `claims`, with the session's person as that client
    /// knows them, through `pairwise`. Without it, the hint of a pairwise
    /// client never names the session's person, and a request of a pairwise
    /// client that asks for a `sub` cannot be answered.
    #[must_use]
    pub fn with_pairwise_subjects(mut self, pairwise: PairwiseSubjects) -> Self {
        self.pairwise = Some(pairwise);
        self
    }

    /// Fetches request objects at a client's address through `http`, after
    /// checking each address with `destinations`: the guarded outbound
    /// client, limited to 16 kibibytes. Without them, an address a request
    /// names is answered `request_uri_not_supported`.
    #[must_use]
    pub fn with_request_object_addresses(
        mut self,
        destinations: Arc<dyn DestinationCheck>,
        http: Arc<dyn HttpClient>,
    ) -> Self {
        self.fetch = Some(RequestObjectFetch { destinations, http });
        self
    }

    /// Checks the signed request objects of a client with a key set
    /// address against the keys there, fetched and kept by `sets`. Without
    /// it, such a client has no keys, and its signed objects are refused.
    #[must_use]
    pub fn with_client_key_sets(mut self, sets: ClientKeySets) -> Self {
        self.client_keys = Some(sets);
        self
    }

    /// The keys to check the request object of `parameters` with, if it
    /// has one: those of `client`, Hodor's own or at its address.
    async fn object_keys(
        &self,
        tenant: &TenantContext,
        client: Option<&Client>,
        parameters: &AuthorizationParameters,
    ) -> Vec<crate::domain::key::ClientKey> {
        match (client, parameters.once("request")) {
            (Some(client), Some(object)) => {
                keys_of(self.client_keys.as_ref(), tenant, client, Some(object)).await
            }
            _ => Vec::new(),
        }
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
    /// issuer is `issuer`, its request object first when it has one. A
    /// request that names a pushed request by reference takes that pushed
    /// request, once, and is it. `policy` is the tenant's: whether every
    /// client must push its requests.
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
        policy: &PushedRequestPolicy,
    ) -> Result<Result<AuthorizationRequest, AuthorizationRefusal>, DomainError> {
        let now = self.ports.clock.now();
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
        let reference = parameters.reference();
        if reference != Reference::Absent {
            let client = match trusted_client(parameters, client.as_ref(), application.as_ref()) {
                Ok((client, _)) => client,
                Err(refusal) => return Ok(Err(refusal)),
            };
            if let (Reference::Address(_), Some(fetch), Some(application)) =
                (reference, &self.fetch, &application)
            {
                let servers = self.ports.resource_servers.list(uow.as_mut()).await?;
                // Nothing is held in the database while the address is fetched.
                uow.commit().await?;
                return Ok(self
                    .check_at_address(
                        (tenant, issuer),
                        fetch,
                        parameters,
                        (client, application),
                        &servers,
                        policy.requires(Some(client)),
                    )
                    .await);
            }
            let hash = match reference {
                Reference::Pushed(value) => {
                    ReferenceHash::of_presented(value, self.ports.digest.as_ref())
                }
                Reference::Absent | Reference::Address(_) | Reference::Unknown => None,
            };
            let taken = match hash {
                Some(hash) => {
                    self.ports
                        .requests
                        .take_pushed(uow.as_mut(), client.id(), &hash)
                        .await?
                }
                None => None,
            };
            // Taken for good, whatever the answer: a reference is used once.
            uow.commit().await?;
            return Ok(check_reference(parameters, client, taken, now));
        }
        let servers = if client.is_some() {
            self.ports.resource_servers.list(uow.as_mut()).await?
        } else {
            Vec::new()
        };
        // Nothing was written: the reads end here, before a key set address
        // is fetched.
        drop(uow);
        let keys = self.object_keys(tenant, client.as_ref(), parameters).await;
        Ok(check_request(
            parameters,
            client.as_ref(),
            application.as_ref(),
            &servers,
            RequestObjectCheck {
                issuer,
                now,
                keys: &keys,
                verifier: self.ports.verifier.as_ref(),
            },
            policy.requires(client.as_ref()),
        ))
    }

    /// Checks the `id_token_hint` of a checked request, if it has one,
    /// given outside or inside its request object, as an ID token of the tenant whose issuer is `issuer`, issued
    /// to the request's client; the request then keeps its `sub`. A hint
    /// is checked as the end-session endpoint checks its own: by the
    /// tenant's published keys and issuer, its expiry aside.
    ///
    /// # Errors
    ///
    /// The outer error is a failure of storage; the inner one is the
    /// refusal, `invalid_request` at the redirect address, with the reason
    /// for the logs.
    pub async fn check_hint(
        &self,
        tenant: &TenantContext,
        issuer: &str,
        mut request: AuthorizationRequest,
    ) -> Result<Result<AuthorizationRequest, (AuthorizationRefusal, &'static str)>, DomainError>
    {
        let Some(token) = request.given_hint.take() else {
            return Ok(Ok(request));
        };
        let checked = match &self.hints {
            Some(hints) => {
                let keys = published_keys(hints, tenant).await?;
                check_id_token_hint(&token, issuer, &keys, self.ports.verifier.as_ref())
            }
            None => Err("this service cannot check an id_token_hint"),
        };
        Ok(request.hinted(checked))
    }

    /// Whether `user` is the person the request's `id_token_hint` names, as
    /// the request's client knows them: by the user identifier, or for a
    /// pairwise client by its pairwise identifier. A request without a hint
    /// names anyone; a client gone since, or a pairwise one this service
    /// cannot name a person to, nobody.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn hint_names(
        &self,
        tenant: &TenantContext,
        request: &AuthorizationRequest,
        user: UserId,
    ) -> Result<bool, DomainError> {
        if request.id_token_hint.is_none() {
            return Ok(true);
        }
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let client = self
            .ports
            .clients
            .get(uow.as_mut(), request.client_id)
            .await?;
        drop(uow);
        let Some(client) = client else {
            return Ok(false);
        };
        match subject_for(self.pairwise.as_ref(), tenant, &client, user).await {
            Ok(subject) => Ok(request.names_person(&subject)),
            Err(error) if error.code() == "oauth.pairwise_unavailable" => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Checks a request whose `request_uri` is an address of the client's:
    /// the address must be one it registered, may be called, and must
    /// answer a request object within the bounds, with the hash its
    /// fragment gives; what it answered is then checked as a request object
    /// given by value, with the client's keys, those at its key set address
    /// included. See `docs/architecture/contexts/oauth.md`, "Request
    /// objects at a client's address".
    async fn check_at_address(
        &self,
        (tenant, issuer): (&TenantContext, &str),
        fetch: &RequestObjectFetch,
        parameters: &AuthorizationParameters,
        (client, application): (&Client, &crate::domain::application::Application),
        servers: &[ResourceServer],
        pushed_only: bool,
    ) -> Result<AuthorizationRequest, AuthorizationRefusal> {
        let address = address_to_fetch(parameters, client, pushed_only)?;
        let unreachable = || refused_fetch(parameters, client, FetchRefusal::Unreachable);
        // A name can resolve elsewhere since the address was registered,
        // and the guarded client checks again on the resolution it
        // connects with.
        if fetch.destinations.check(address.url).await.is_err() {
            return Err(unreachable());
        }
        let request = HttpRequest::get(address.url)
            .header("accept", REQUEST_OBJECT_ACCEPT)
            .within(REQUEST_OBJECT_TIME_LIMIT);
        let response = match fetch.http.send(request).await {
            Ok(response) => response,
            Err(error) if error.code() == "http.response_too_large" => {
                return Err(refused_fetch(parameters, client, FetchRefusal::TooLarge));
            }
            Err(_) => return Err(unreachable()),
        };
        let object = fetched_object(
            response.status,
            &response.body,
            &address,
            self.ports.digest.as_ref(),
        )
        .map_err(|refusal| refused_fetch(parameters, client, refusal))?;
        let parameters = with_fetched_object(parameters, object);
        let keys = self.object_keys(tenant, Some(client), &parameters).await;
        check_request(
            &parameters,
            Some(client),
            Some(application),
            servers,
            RequestObjectCheck {
                issuer,
                now: self.ports.clock.now(),
                keys: &keys,
                verifier: self.ports.verifier.as_ref(),
            },
            false,
        )
    }

    /// Checks a request `client` pushed, the client that proved who it is
    /// at this tenant, whose issuer is `issuer`, its `id_token_hint`
    /// included, and keeps it for the life `policy` gives, beside at most
    /// four others of the client. The client gets the reference.
    ///
    /// # Errors
    ///
    /// The outer error is a failure of storage; the inner one is the
    /// refusal, to be answered as JSON.
    pub async fn push(
        &self,
        tenant: &TenantContext,
        issuer: &str,
        client: &Client,
        parameters: AuthorizationParameters,
        policy: &PushedRequestPolicy,
    ) -> Result<Result<PushedAnswer, TokenError>, DomainError> {
        let now = self.ports.clock.now();
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let Some(application) = self
            .ports
            .applications
            .get(uow.as_mut(), client.application_id())
            .await?
        else {
            return Ok(Err(TokenError::invalid_client("the client is unknown")));
        };
        let servers = self.ports.resource_servers.list(uow.as_mut()).await?;
        // Nothing was written: the reads end here, before a key set address
        // is fetched, and the hint is checked after every other check, since
        // the pushed request keeps only the `sub` it names.
        drop(uow);
        let keys = self.object_keys(tenant, Some(client), &parameters).await;
        let request = match check_pushed_request(
            parameters,
            client,
            &application,
            &servers,
            RequestObjectCheck {
                issuer,
                now,
                keys: &keys,
                verifier: self.ports.verifier.as_ref(),
            },
        ) {
            Ok(request) => request,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let request = match self.check_hint(tenant, issuer, request).await? {
            Ok(request) => request,
            Err((refusal, reason)) => {
                let (error, description) = match refusal {
                    AuthorizationRefusal::Redirect(error) => (error.error, error.description),
                    AuthorizationRefusal::NotRedirectable(_) => {
                        ("invalid_request", "the id_token_hint is refused")
                    }
                };
                return Ok(Err(TokenError {
                    error,
                    description,
                    reason,
                }));
            }
        };
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let lifetime = pushed_lifetime(policy);
        let (pushed, reference) = PushedAuthorization::push(
            request,
            lifetime,
            now,
            self.ports.random.as_ref(),
            self.ports.digest.as_ref(),
        );
        self.ports
            .requests
            .push(uow.as_mut(), &pushed, MAX_PUSHED_PER_CLIENT)
            .await?;
        uow.commit().await?;
        Ok(Ok(PushedAnswer {
            reference,
            expires_in: lifetime.whole_seconds(),
        }))
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

    /// Whether `request` asked through `claims` for a `sub` that is not
    /// `user` as its client knows them. A client the tenant no longer has
    /// knows nobody.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails, or the client is pairwise and
    /// this service cannot name people to pairwise clients.
    pub async fn names_another(
        &self,
        tenant: &TenantContext,
        request: &AuthorizationRequest,
        user: UserId,
    ) -> Result<bool, DomainError> {
        if request.claims.subject.is_none() {
            return Ok(false);
        }
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let client = self
            .ports
            .clients
            .get(uow.as_mut(), request.client_id)
            .await?;
        drop(uow);
        let Some(client) = client else {
            return Ok(true);
        };
        let subject = subject_for(self.pairwise.as_ref(), tenant, &client, user).await?;
        Ok(request.names_another(&subject))
    }

    /// Makes the grant and the code for a checked request and the person
    /// signed in, the scopes of the request being all that was consented
    /// to.
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
        self.issue_code_consented(tenant, request, person, &request.scopes, caller)
            .await
    }

    /// Makes the grant and the code for a checked request and the person
    /// signed in, when `consented` are the scopes consented to for the
    /// client: the grant gives the claims asked through `claims` that one
    /// of them covers.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn issue_code_consented(
        &self,
        tenant: &TenantContext,
        request: &AuthorizationRequest,
        person: &SignedInPerson,
        consented: &[String],
        caller: Caller,
    ) -> Result<CodeValue, DomainError> {
        let (_, code) = self
            .make(tenant, request, person, consented, true, caller)
            .await?;
        code.ok_or_else(|| {
            DomainError::internal(
                "oauth.code_not_issued",
                "no code was issued for the request",
            )
        })
    }

    /// Whether `request`, checked when it arrived, may still be answered to
    /// its client as the client is now: for a type that returns an access
    /// token, the client must still have the type and the mark, and the
    /// mark still allow every scope. The error to send back, if not; a
    /// client that is gone is the token's to refuse.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn still_answerable(
        &self,
        tenant: &TenantContext,
        request: &AuthorizationRequest,
    ) -> Result<Option<AuthorizationError>, DomainError> {
        if !request.response_type.returns_access_token() {
            return Ok(None);
        }
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let client = self
            .ports
            .clients
            .get(uow.as_mut(), request.client_id)
            .await?;
        drop(uow);
        Ok(client
            .and_then(|client| crate::domain::authorization::still_answerable(&client, request)))
    }

    /// Makes what the request's response type answers with, for the person
    /// signed in, when `consented` are the scopes consented to for the
    /// client: for every type but `none` a grant, which gives the claims
    /// asked through `claims` that one of them covers, and for a type that
    /// returns one a code; `oauth.authorization_code_issued` for a code and
    /// `oauth.id_token_issued` for a type that returns an ID token, all in
    /// one unit of work. `none` makes and stores nothing.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn answer(
        &self,
        tenant: &TenantContext,
        request: &AuthorizationRequest,
        person: &SignedInPerson,
        consented: &[String],
        caller: Caller,
    ) -> Result<AuthorizationAnswer, DomainError> {
        let kind = request.response_type;
        if !kind.makes_grant() {
            return Ok(AuthorizationAnswer {
                grant: None,
                code: None,
            });
        }
        let (grant, code) = self
            .make(
                tenant,
                request,
                person,
                consented,
                kind.returns_code(),
                caller,
            )
            .await?;
        Ok(AuthorizationAnswer {
            grant: Some(grant),
            code,
        })
    }

    async fn make(
        &self,
        tenant: &TenantContext,
        request: &AuthorizationRequest,
        person: &SignedInPerson,
        consented: &[String],
        with_code: bool,
        caller: Caller,
    ) -> Result<(Grant, Option<CodeValue>), DomainError> {
        let now = self.ports.clock.now();
        let mut grant = Grant::make(request, person, now);
        grant.claims = request.claims.given(&request.scopes, consented);
        let issued = with_code.then(|| {
            AuthorizationCode::issue(
                &grant,
                request,
                person,
                now,
                self.ports.random.as_ref(),
                self.ports.digest.as_ref(),
            )
        });
        let mut events = Vec::new();
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        self.ports.grants.insert(uow.as_mut(), &grant).await?;
        if let Some((code, _)) = &issued {
            self.ports.codes.insert(uow.as_mut(), code).await?;
            events.push(code.issued_event());
        }
        if request.response_type.returns_id_token() {
            events.push(OauthEvent::IdTokenIssued {
                client_id: grant.client_id,
                grant_id: grant.id,
                user_id: grant.user_id,
            });
        }
        self.record(uow.as_mut(), caller, &events)?;
        uow.commit().await?;
        Ok((grant, issued.map(|(_, value)| value)))
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
