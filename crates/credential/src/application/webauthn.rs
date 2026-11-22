//! WebAuthn credentials: the port and the use cases.

use crate::domain::webauthn::{
    AssertionCheck, AssertionResponse, Challenge, CreationOptions, PendingRegistration,
    RegistrationResponse, RelyingParty, RequestOptions, WebAuthnCredential, WebAuthnEvent,
    WebAuthnRegistrationId, check_assertion, check_registration, creation_options, request_options,
};
use hodor_kernel::{
    Caller, Clock, Digest, DomainError, EventEnvelope, EventMetadata, RandomSource,
    SignatureVerifier, TenantContext, UnitOfWork, UnitOfWorkFactory, UserId,
};
use std::sync::Arc;

/// Stores WebAuthn credentials and pending registrations. Every method
/// works inside the tenant the unit of work is bound to.
#[async_trait::async_trait]
pub trait WebAuthnStore: Send + Sync {
    /// Stores a pending registration.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn insert_registration(
        &self,
        uow: &mut dyn UnitOfWork,
        registration: &PendingRegistration,
    ) -> Result<(), DomainError>;

    /// Removes a pending registration and returns it, if it was there. Of
    /// any number of callers at once, one gets it.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn take_registration(
        &self,
        uow: &mut dyn UnitOfWork,
        id: WebAuthnRegistrationId,
    ) -> Result<Option<PendingRegistration>, DomainError>;

    /// Stores a new credential.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` with code `credential.webauthn_credential_exists`
    /// if the tenant already has a credential with its identifier.
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        credential: &WebAuthnCredential,
    ) -> Result<(), DomainError>;

    /// A user's credentials, oldest first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn list_for_user(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
    ) -> Result<Vec<WebAuthnCredential>, DomainError>;

    /// Stores the counter, backup state and last use of a credential, only
    /// if its stored counter is still `previous_count`. Returns whether it
    /// was stored.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn record_use(
        &self,
        uow: &mut dyn UnitOfWork,
        credential: &WebAuthnCredential,
        previous_count: u32,
    ) -> Result<bool, DomainError>;
}

/// A registration that was just asked for.
#[derive(Debug, Clone)]
pub struct BegunRegistration {
    /// Refers to it when it is finished.
    pub id: WebAuthnRegistrationId,
    /// What the browser passes to the authenticator.
    pub options: CreationOptions,
}

/// A challenge for a user's credentials.
#[derive(Debug, Clone)]
pub struct AssertionChallenge {
    /// What the answer must sign; to be kept by the caller until the
    /// answer arrives, and used once.
    pub challenge: Challenge,
    /// What the browser passes to the authenticator.
    pub options: RequestOptions,
}

fn registration_not_found() -> DomainError {
    DomainError::not_found(
        "credential.webauthn_registration_not_found",
        "this registration does not exist or has expired; start again",
    )
}

/// The use cases of WebAuthn credentials.
#[derive(Clone)]
pub struct WebAuthnService {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    store: Arc<dyn WebAuthnStore>,
    relying_party: RelyingParty,
    digest: Arc<dyn Digest>,
    verifier: Arc<dyn SignatureVerifier>,
    random: Arc<dyn RandomSource>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for WebAuthnService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebAuthnService")
            .field("relying_party", &self.relying_party)
            .finish_non_exhaustive()
    }
}

impl WebAuthnService {
    /// Wires the use cases to their ports, for the relying party named by
    /// the installation's public address.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        store: Arc<dyn WebAuthnStore>,
        relying_party: RelyingParty,
        digest: Arc<dyn Digest>,
        verifier: Arc<dyn SignatureVerifier>,
        random: Arc<dyn RandomSource>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            units_of_work,
            store,
            relying_party,
            digest,
            verifier,
            random,
            clock,
        }
    }

    /// Begins a registration for a user, who is named to the authenticator
    /// by `name` and `display_name`.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn begin_registration(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        name: &str,
        display_name: &str,
    ) -> Result<BegunRegistration, DomainError> {
        let pending = PendingRegistration::begin(user_id, self.random.as_ref(), self.clock.now());
        let mut uow = self.units_of_work.begin(tenant).await?;
        let existing = self.store.list_for_user(uow.as_mut(), user_id).await?;
        self.store
            .insert_registration(uow.as_mut(), &pending)
            .await?;
        uow.commit().await?;
        Ok(BegunRegistration {
            id: pending.snapshot().id,
            options: creation_options(&self.relying_party, &pending, name, display_name, &existing),
        })
    }

    /// Finishes a registration with what the authenticator answered. The
    /// registration is used up first, whatever follows.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the registration is unknown, another user's,
    /// used or expired; `Invalid` with code
    /// `credential.webauthn_registration_refused` if the answer fails a
    /// check; `Conflict` if the tenant already has the credential.
    pub async fn finish_registration(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        id: WebAuthnRegistrationId,
        response: RegistrationResponse,
        caller: Caller,
    ) -> Result<WebAuthnCredential, DomainError> {
        let now = self.clock.now();
        let mut uow = self.units_of_work.begin(tenant).await?;
        let pending = self.store.take_registration(uow.as_mut(), id).await?;
        uow.commit().await?;
        let pending = pending
            .filter(|pending| pending.is_good_for(user_id, now))
            .ok_or_else(registration_not_found)?;
        let credential = check_registration(
            &self.relying_party,
            &pending,
            response,
            self.digest.as_ref(),
            now,
        )
        .map_err(|refusal| refusal.registration_error())?;

        let mut uow = self.units_of_work.begin(tenant).await?;
        self.store.insert(uow.as_mut(), &credential).await?;
        self.record(uow.as_mut(), caller, &credential.registered_event())?;
        uow.commit().await?;
        Ok(credential)
    }

    /// Whether a user has at least one credential.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn has_credentials(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
    ) -> Result<bool, DomainError> {
        Ok(!self.list(tenant, user_id).await?.is_empty())
    }

    /// A user's credentials, oldest first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn list(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
    ) -> Result<Vec<WebAuthnCredential>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.store.list_for_user(uow.as_mut(), user_id).await
    }

    /// Makes a challenge that a user's credentials may answer.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn challenge(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
    ) -> Result<AssertionChallenge, DomainError> {
        let credentials = self.list(tenant, user_id).await?;
        let challenge = Challenge::generate(self.random.as_ref());
        Ok(AssertionChallenge {
            options: request_options(&self.relying_party, &challenge, &credentials),
            challenge,
        })
    }

    /// Checks an answer to `challenge` for a user. `true` only if every
    /// check passes; the new counter is then stored.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails. A wrong answer is `false`.
    pub async fn verify(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        challenge: &Challenge,
        response: &AssertionResponse,
    ) -> Result<bool, DomainError> {
        let credentials = self.list(tenant, user_id).await?;
        let Some(mut credential) = credentials
            .into_iter()
            .find(|credential| credential.snapshot().credential_id == response.credential_id)
        else {
            return Ok(false);
        };
        let previous = credential.snapshot().sign_count;
        let check = check_assertion(
            &self.relying_party,
            challenge,
            &credential,
            response,
            self.digest.as_ref(),
            self.verifier.as_ref(),
        );
        match check {
            AssertionCheck::Refused(_) => Ok(false),
            AssertionCheck::CounterNotIncreased => {
                let mut uow = self.units_of_work.begin(tenant).await?;
                let event = WebAuthnEvent::CounterNotIncreased {
                    user_id,
                    credential_id: credential.id(),
                };
                self.record(uow.as_mut(), Caller::system(), &event)?;
                uow.commit().await?;
                Ok(false)
            }
            AssertionCheck::Verified {
                sign_count,
                backed_up,
            } => {
                credential.record_use(sign_count, backed_up, self.clock.now());
                let mut uow = self.units_of_work.begin(tenant).await?;
                // Two answers at once with the same counter: one is stored,
                // the other is a copy.
                let stored = self
                    .store
                    .record_use(uow.as_mut(), &credential, previous)
                    .await?;
                uow.commit().await?;
                Ok(stored)
            }
        }
    }

    fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        caller: Caller,
        event: &WebAuthnEvent,
    ) -> Result<(), DomainError> {
        let metadata = EventMetadata::new(
            uow.tenant().tenant_id(),
            caller.actor,
            caller.correlation_id,
            self.clock.as_ref(),
        );
        uow.record_event(EventEnvelope::new(metadata, event)?);
        Ok(())
    }
}
