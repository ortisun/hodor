//! The use cases of the authentication context: running a sign-in.

use crate::application::ports::TransactionStore;
use crate::domain::authenticator::{ExternalInput, StepInput};
use crate::domain::engine::{FlowEngine, Progress, Submitted};
use crate::domain::enrollment::Enrolled;
use crate::domain::event::AuthenticationEvent;
use crate::domain::flow::AuthFlow;
use crate::domain::transaction::{AuthTransaction, TransactionId, TransactionState};
use hodor_identity::api::{IdentifierKind, IdentityService};
use hodor_kernel::{
    Caller, Clock, Digest, DomainError, ErrorKind, EventEnvelope, EventMetadata, RandomSource,
    Secret, TenantContext, UnitOfWork, UnitOfWorkFactory, UserId,
};
use hodor_session::api::{
    Assurance, ClientInfo, Session, SessionId, SessionService, SessionTimeouts, SessionToken,
    StartSession,
};
use hodor_tenant::api::{SecondFactorPolicy, TenantService};
use std::sync::Arc;
use time::Duration;

/// Where a sign-in stands after an operation.
#[derive(Debug)]
pub enum SignIn {
    /// A step is waiting for input.
    Pending {
        /// Refers to the sign-in.
        transaction_id: TransactionId,
        /// The key of the step that is expected.
        step: String,
        /// The recovery codes made with a second factor the last step put
        /// in use, to be shown once; empty otherwise.
        recovery_codes: Vec<Secret<String>>,
    },
    /// The last input was rejected; the same step is expected again.
    Rejected {
        /// Refers to the sign-in.
        transaction_id: TransactionId,
        /// The key of the step that is expected.
        step: String,
        /// How many more rejections the sign-in tolerates.
        attempts_left: u32,
    },
    /// The sign-in has failed and a new one must be started.
    Failed,
    /// The sign-in completed and a session started.
    Completed {
        /// The session that started.
        session: Box<Session>,
        /// Its token, to be handed to the browser. Not available again.
        token: SessionToken,
        /// The recovery codes made with a second factor the last step put
        /// in use, to be shown once; empty otherwise.
        recovery_codes: Vec<Secret<String>>,
    },
}

/// A sign-in that was just started.
#[derive(Debug)]
pub struct StartedSignIn {
    /// Refers to the sign-in.
    pub transaction_id: TransactionId,
    /// The secret that every later operation on this sign-in must present.
    /// Given to the browser that started it and to nobody else; not
    /// available again.
    pub secret: Secret<String>,
    /// The key of the first step.
    pub step: String,
}

/// What a step-up is asked to do: raise this session of this person,
/// carrying the methods that still count, to the assurance an application
/// asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepUpRequest {
    /// The session to raise.
    pub session_id: SessionId,
    /// Whose session it is.
    pub user_id: UserId,
    /// The methods of the session that still count.
    pub carried: Vec<String>,
    /// The assurance the application asked for, if it asked for one.
    pub demanded: Option<Assurance>,
}

/// What starting a step-up led to.
#[derive(Debug)]
pub enum StepUp {
    /// The step-up waits for its first step.
    Started(StartedSignIn),
    /// The person cannot reach what the step-up must reach with the
    /// factors they have; nothing was started.
    Unreachable,
    /// What is carried reaches it already; nothing was started.
    NotNeeded,
}

/// The use cases of the authentication context.
#[derive(Clone)]
pub struct AuthenticationService {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    transactions: Arc<dyn TransactionStore>,
    engine: FlowEngine,
    flow: Arc<AuthFlow>,
    identity: IdentityService,
    sessions: SessionService,
    tenants: TenantService,
    digest: Arc<dyn Digest>,
    random: Arc<dyn RandomSource>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for AuthenticationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticationService")
            .field("flow", &self.flow.name)
            .finish_non_exhaustive()
    }
}

fn not_found() -> DomainError {
    DomainError::not_found(
        "authentication.transaction_not_found",
        "this sign-in does not exist; start again",
    )
}

impl AuthenticationService {
    /// Wires the use cases to their ports and to the contexts they ask.
    ///
    /// # Errors
    ///
    /// Returns an `Invalid` error if the flow is not valid for the engine.
    /// An invalid flow is never run.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        transactions: Arc<dyn TransactionStore>,
        engine: FlowEngine,
        flow: AuthFlow,
        identity: IdentityService,
        sessions: SessionService,
        tenants: TenantService,
        digest: Arc<dyn Digest>,
        random: Arc<dyn RandomSource>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, DomainError> {
        engine.validate(&flow)?;
        Ok(Self {
            units_of_work,
            transactions,
            engine,
            flow: Arc::new(flow),
            identity,
            sessions,
            tenants,
            digest,
            random,
            clock,
        })
    }

    /// Starts a sign-in. Returns its identifier, the secret that binds it
    /// to whoever started it, and the first step.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn start(
        &self,
        tenant: &TenantContext,
        client: ClientInfo,
    ) -> Result<StartedSignIn, DomainError> {
        let mut bytes = [0_u8; 32];
        self.random.fill(&mut bytes);
        let secret: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        let binding = self.digest.sha256(secret.as_bytes());

        let transaction = AuthTransaction::start(&self.flow, client, binding, self.clock.now());
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.transactions.insert(uow.as_mut(), &transaction).await?;
        uow.commit().await?;
        Ok(StartedSignIn {
            transaction_id: transaction.id(),
            secret: Secret::from(secret),
            step: self.pending_step(&transaction)?,
        })
    }

    /// Starts a step-up of a session, as
    /// `docs/architecture/contexts/authentication.md`, "Step-up", says.
    ///
    /// # Errors
    ///
    /// Returns an error if storage or an authenticator fails.
    pub async fn start_step_up(
        &self,
        tenant: &TenantContext,
        client: ClientInfo,
        request: StepUpRequest,
    ) -> Result<StepUp, DomainError> {
        let user = match self.identity.get(tenant, request.user_id).await {
            Ok(user) if user.may_sign_in() => user,
            Ok(_) => return Ok(StepUp::Unreachable),
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(StepUp::Unreachable),
            Err(error) => return Err(error),
        };
        // Counted as the identifier step counts what is typed, so that a
        // step-up shares the counts of the person's own identifier.
        let counted = user
            .primary_identifier(IdentifierKind::Email)
            .or_else(|| user.primary_identifier(IdentifierKind::Username))
            .map_or_else(
                || format!("user:{}", user.id()),
                |identifier| {
                    format!(
                        "{}:{}",
                        identifier.value.kind().as_str(),
                        identifier.value.normalized()
                    )
                },
            );
        let mut bytes = [0_u8; 32];
        self.random.fill(&mut bytes);
        let secret: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        let binding = self.digest.sha256(secret.as_bytes());
        let satisfied = self.engine.satisfied_by(&self.flow, &request.carried);
        let mut transaction = AuthTransaction::start_step_up(
            &self.flow,
            client,
            binding,
            self.clock.now(),
            request.session_id,
            request.user_id,
            self.digest.sha256(counted.as_bytes()),
            request.carried,
            satisfied,
            request.demanded,
        );
        let demanded = self.demanded(tenant, &transaction).await?;
        let must_reach = self.flow.minimum_assurance.max(demanded);
        if !self
            .engine
            .reachable(tenant, &self.flow, &transaction, must_reach)
            .await?
        {
            return Ok(StepUp::Unreachable);
        }
        self.engine
            .settle(tenant, &self.flow, &mut transaction, demanded)
            .await?;
        if transaction.all_steps_satisfied(&self.flow) {
            return Ok(StepUp::NotNeeded);
        }
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.transactions.insert(uow.as_mut(), &transaction).await?;
        uow.commit().await?;
        Ok(StepUp::Started(StartedSignIn {
            transaction_id: transaction.id(),
            secret: Secret::from(secret),
            step: self.pending_step(&transaction)?,
        }))
    }

    /// The assurance a list of methods amounts to, or `None` when none of
    /// them proves anything: the one table of methods and factors, for
    /// the other contexts.
    #[must_use]
    pub fn assurance_of(&self, methods: &[String]) -> Option<Assurance> {
        self.engine.assurance_of_methods(methods)
    }

    /// The alternatives a sign-in of the tenant may take at its start, in
    /// the order of the flow, for the pages to offer.
    ///
    /// # Errors
    ///
    /// Returns an error if the tenant's settings cannot be read.
    pub async fn alternatives(&self, tenant: &TenantContext) -> Result<Vec<String>, DomainError> {
        self.engine.offered_alternatives(tenant, &self.flow).await
    }

    /// Says which step a sign-in is waiting for, so that its page can be
    /// shown again.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if there is no such sign-in, and `Conflict` if it
    /// is no longer in progress.
    pub async fn describe(
        &self,
        tenant: &TenantContext,
        id: TransactionId,
        secret: &str,
    ) -> Result<SignIn, DomainError> {
        let transaction = self.load(tenant, id, secret).await?;
        transaction.require_in_progress(self.clock.now())?;
        self.pending(&transaction)
    }

    /// Asks the current step of a sign-in, or an alternative while no step
    /// has been satisfied, for a challenge, with what the person gave in
    /// `asked`, and returns what the browser needs to answer it. For the
    /// email alternatives this sends the code or the link.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if there is no such sign-in, `Conflict` if it is
    /// not in progress or was advanced by another request meanwhile,
    /// `Invalid` if the step is not the current step or needs no challenge,
    /// `Forbidden` for an alternative the tenant does not offer, and
    /// `RateLimited` when too much was asked.
    pub async fn challenge(
        &self,
        tenant: &TenantContext,
        id: TransactionId,
        secret: &str,
        asked: ExternalInput,
    ) -> Result<serde_json::Value, DomainError> {
        let mut transaction = self.load(tenant, id, secret).await?;
        let options = self
            .engine
            .challenge(
                tenant,
                &self.flow,
                &mut transaction,
                &asked,
                self.clock.now(),
            )
            .await?;
        self.store(tenant, &transaction, None).await?;
        Ok(options)
    }

    /// Runs the current step of a sign-in with what was submitted.
    ///
    /// The step's authenticator runs with no database transaction open.
    /// The result is then stored against the version that was read; if
    /// another request advanced the sign-in meanwhile, this one is refused.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if there is no such sign-in, `Conflict` if it is
    /// not in progress or was advanced by another request, `Invalid` if
    /// the input is for another step, `RateLimited` when attempts are
    /// being limited, and `Unavailable` when a dependency is.
    pub async fn submit(
        &self,
        tenant: &TenantContext,
        id: TransactionId,
        secret: &str,
        input: StepInput,
    ) -> Result<SignIn, DomainError> {
        let mut transaction = self.load(tenant, id, secret).await?;
        let now = self.clock.now();
        let step = input.step_key().to_owned();
        let step = step.as_str();
        let demanded = self.demanded(tenant, &transaction).await?;
        let Submitted { progress, enrolled } = self
            .engine
            .submit_step(tenant, &self.flow, &mut transaction, &input, demanded, now)
            .await?;
        // The factor is in use already, whatever becomes of the sign-in.
        let recovery_codes = match enrolled {
            Some(enrolled) => self.enrolled(tenant, &transaction, enrolled).await?,
            None => Vec::new(),
        };

        match progress {
            Progress::Next { .. } => {
                self.store(tenant, &transaction, None).await?;
                let mut pending = self.pending(&transaction)?;
                if let SignIn::Pending {
                    recovery_codes: shown,
                    ..
                } = &mut pending
                {
                    *shown = recovery_codes;
                }
                Ok(pending)
            }
            Progress::Rejected { attempts_left } => {
                self.store(tenant, &transaction, Some(self.failed(step, &transaction)))
                    .await?;
                // The step the sign-in is waiting for, which is not the
                // one that was tried when an alternative was rejected.
                Ok(SignIn::Rejected {
                    transaction_id: transaction.id(),
                    step: self.pending_step(&transaction)?,
                    attempts_left,
                })
            }
            Progress::Failed => {
                self.store(tenant, &transaction, Some(self.failed(step, &transaction)))
                    .await?;
                Ok(SignIn::Failed)
            }
            Progress::ReadyToComplete => match self.complete(tenant, transaction, step).await? {
                SignIn::Completed { session, token, .. } => Ok(SignIn::Completed {
                    session,
                    token,
                    recovery_codes,
                }),
                other => Ok(other),
            },
        }
    }

    /// Records that the enrollment step put a factor in use, and answers
    /// the recovery codes made with it.
    async fn enrolled(
        &self,
        tenant: &TenantContext,
        transaction: &AuthTransaction,
        enrolled: Enrolled,
    ) -> Result<Vec<Secret<String>>, DomainError> {
        if let Some(user_id) = transaction.candidate() {
            let mut uow = self.units_of_work.begin(tenant).await?;
            let event = AuthenticationEvent::SecondFactorEnrolled {
                user_id,
                kind: enrolled.kind.as_str(),
            };
            self.record(uow.as_mut(), &event)?;
            uow.commit().await?;
        }
        Ok(enrolled.recovery_codes)
    }

    /// Ends a sign-in. Ending one that has already ended changes nothing.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if there is no such sign-in.
    pub async fn cancel(
        &self,
        tenant: &TenantContext,
        id: TransactionId,
        secret: &str,
    ) -> Result<(), DomainError> {
        let mut transaction = self.load(tenant, id, secret).await?;
        if transaction.state_at(self.clock.now()) == TransactionState::InProgress {
            transaction.cancel();
            self.store(tenant, &transaction, None).await?;
        }
        Ok(())
    }

    /// Completes a sign-in whose last step was just satisfied.
    async fn complete(
        &self,
        tenant: &TenantContext,
        mut transaction: AuthTransaction,
        last_step: &str,
    ) -> Result<SignIn, DomainError> {
        let now = self.clock.now();
        // The last check, made at the moment of completion: the user must
        // be allowed to sign in now, whatever was true at earlier steps.
        let allowed = match transaction.candidate() {
            Some(user_id) => self.may_sign_in(tenant, user_id).await?,
            None => false,
        };
        // What the sign-in must reach is read again: the tenant's policy
        // as it is now, whatever it was at earlier steps.
        let must_reach = self
            .flow
            .minimum_assurance
            .max(self.demanded(tenant, &transaction).await?);
        let assurance = self
            .engine
            .assurance(&transaction)
            .filter(|reached| *reached >= must_reach);
        let (Some(assurance), true) = (assurance, allowed) else {
            transaction.cancel();
            self.store(
                tenant,
                &transaction,
                Some(self.failed(last_step, &transaction)),
            )
            .await?;
            return Ok(SignIn::Failed);
        };

        // Marking the transaction completed is guarded by its version, so
        // only one request gets past this point.
        let user_id = transaction.complete(&self.flow, now)?;
        self.store(tenant, &transaction, None).await?;

        let methods = transaction.snapshot().satisfied_methods.clone();
        let started = match transaction.snapshot().raised_session {
            // A step-up raises its session, only while it is still active
            // and still the person's.
            Some(session_id) => match self
                .sessions
                .raise(
                    tenant,
                    user_id,
                    session_id,
                    &methods,
                    assurance,
                    Caller::system(),
                )
                .await
            {
                Ok(raised) => raised,
                Err(error) if error.kind() == ErrorKind::NotFound => return Ok(SignIn::Failed),
                Err(error) => return Err(error),
            },
            None => {
                self.start_session(tenant, &transaction, user_id, assurance, methods.clone())
                    .await?
            }
        };
        let (session, token) = started;

        let mut uow = self.units_of_work.begin(tenant).await?;
        let event = AuthenticationEvent::Succeeded {
            user_id,
            session_id: session.id().to_string(),
            methods,
        };
        self.record(uow.as_mut(), &event)?;
        uow.commit().await?;
        Ok(SignIn::Completed {
            session: Box::new(session),
            token,
            recovery_codes: Vec::new(),
        })
    }

    async fn start_session(
        &self,
        tenant: &TenantContext,
        transaction: &AuthTransaction,
        user_id: UserId,
        assurance: Assurance,
        methods: Vec<String>,
    ) -> Result<(Session, SessionToken), DomainError> {
        let policy = self
            .tenants
            .get(tenant)
            .await?
            .snapshot()
            .settings
            .session
            .clone();
        let command = StartSession {
            user_id,
            assurance,
            methods,
            timeouts: SessionTimeouts {
                idle: Duration::seconds(i64::from(policy.idle_timeout_seconds)),
                absolute: Duration::seconds(i64::from(policy.absolute_timeout_seconds)),
            },
            client: transaction.snapshot().client.clone(),
        };
        self.sessions.start(tenant, command, Caller::system()).await
    }

    /// The assurance a sign-in must reach beyond the flow's own minimum:
    /// the tenant's policy, raised by what an application asked of a
    /// step-up.
    async fn demanded(
        &self,
        tenant: &TenantContext,
        transaction: &AuthTransaction,
    ) -> Result<Assurance, DomainError> {
        let policy = self
            .tenants
            .get(tenant)
            .await?
            .snapshot()
            .settings
            .authentication
            .second_factor;
        let by_policy = match policy {
            SecondFactorPolicy::NotRequired => Assurance::SingleFactor,
            SecondFactorPolicy::Required => Assurance::MultiFactor,
        };
        Ok(transaction
            .snapshot()
            .demanded
            .map_or(by_policy, |asked| asked.max(by_policy)))
    }

    async fn may_sign_in(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
    ) -> Result<bool, DomainError> {
        match self.identity.get(tenant, user_id).await {
            Ok(user) => Ok(user.may_sign_in()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Loads a sign-in for whoever presents its secret. A wrong secret is
    /// answered exactly like a sign-in that does not exist.
    async fn load(
        &self,
        tenant: &TenantContext,
        id: TransactionId,
        secret: &str,
    ) -> Result<AuthTransaction, DomainError> {
        let presented = self.digest.sha256(secret.as_bytes());
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.transactions
            .get(uow.as_mut(), id)
            .await?
            .filter(|transaction| transaction.is_bound_to(&presented))
            .ok_or_else(not_found)
    }

    async fn store(
        &self,
        tenant: &TenantContext,
        transaction: &AuthTransaction,
        event: Option<AuthenticationEvent>,
    ) -> Result<(), DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.transactions.update(uow.as_mut(), transaction).await?;
        if let Some(event) = event {
            self.record(uow.as_mut(), &event)?;
        }
        uow.commit().await
    }

    fn pending_step(&self, transaction: &AuthTransaction) -> Result<String, DomainError> {
        self.flow
            .steps
            .get(transaction.snapshot().current_step)
            .map(|step| step.key.clone())
            .ok_or_else(|| {
                DomainError::conflict(
                    "authentication.no_step_pending",
                    "every step of this sign-in is already satisfied",
                )
            })
    }

    fn pending(&self, transaction: &AuthTransaction) -> Result<SignIn, DomainError> {
        Ok(SignIn::Pending {
            transaction_id: transaction.id(),
            step: self.pending_step(transaction)?,
            recovery_codes: Vec::new(),
        })
    }

    #[allow(clippy::unused_self)]
    fn failed(&self, step: &str, transaction: &AuthTransaction) -> AuthenticationEvent {
        AuthenticationEvent::Failed {
            step: step.to_owned(),
            user_id: transaction.candidate(),
        }
    }

    fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        event: &AuthenticationEvent,
    ) -> Result<(), DomainError> {
        let caller = Caller::system();
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
