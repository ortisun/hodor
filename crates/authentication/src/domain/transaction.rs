//! A sign-in in progress.

use crate::domain::flow::AuthFlow;
use hodor_kernel::{DomainError, Timestamp, UserId};
use hodor_session::api::{Assurance, ClientInfo, SessionId};
use time::Duration;

hodor_kernel::define_id!(
    /// Refers to a sign-in in progress. Useless once the sign-in ends.
    TransactionId
);

/// What is recorded about how a transaction ended, or that it has not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionStatus {
    /// Still running.
    InProgress,
    /// Every step was satisfied and a session was started.
    Completed,
    /// Too many steps were rejected.
    Failed,
    /// Ended by the person or the caller.
    Cancelled,
}

impl TransactionStatus {
    /// The name used in storage.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InProgress => "in_progress",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    /// Reads a status from its stored name.
    ///
    /// # Errors
    ///
    /// Returns an internal error for an unknown name.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        match value {
            "in_progress" => Ok(Self::InProgress),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            other => Err(DomainError::internal(
                "authentication.stored_data_invalid",
                "the sign-in could not be loaded",
            )
            .with_detail(format!("unknown stored transaction status `{other}`"))),
        }
    }
}

/// Where a transaction stands at a given moment: its recorded status, or
/// expired if it ran out of time while in progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
    /// Accepting the current step.
    InProgress,
    /// Completed.
    Completed,
    /// Failed.
    Failed,
    /// Cancelled.
    Cancelled,
    /// Ran out of time.
    Expired,
}

/// The state of a transaction as it is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionSnapshot {
    /// The transaction's identifier.
    pub id: TransactionId,
    /// The flow being executed.
    pub flow_name: String,
    /// The version of that flow.
    pub flow_version: u32,
    /// The position of the next step to satisfy.
    pub current_step: usize,
    /// Whether the identifier step has run.
    pub identified: bool,
    /// Who is trying to sign in. Empty before the identifier step, and
    /// when the identifier belongs to nobody.
    pub candidate: Option<UserId>,
    /// A digest of the normalized identifier typed.
    pub identifier_key: Option<[u8; 32]>,
    /// The methods satisfied so far in this transaction.
    pub satisfied_methods: Vec<String>,
    /// For a step-up only: the methods the session proved earlier that
    /// still count.
    pub carried_methods: Vec<String>,
    /// For a step-up only: the assurance the application asked for.
    pub demanded: Option<Assurance>,
    /// For a step-up only: the session it raises instead of starting one.
    pub raised_session: Option<SessionId>,
    /// The challenge the current step asked for, if it needs one. Used
    /// once: submitting the step removes it.
    pub challenge: Option<[u8; 32]>,
    /// How many times a step was rejected.
    pub rejections: u32,
    /// How the transaction ended, or that it has not.
    pub status: TransactionStatus,
    /// When it started.
    pub started_at: Timestamp,
    /// When it runs out of time.
    pub expires_at: Timestamp,
    /// Where the sign-in comes from; passed on to the session.
    pub client: ClientInfo,
    /// The SHA-256 hash of the secret held by the browser that started the
    /// sign-in.
    pub binding: [u8; 32],
    /// Incremented on every stored change, for optimistic locking.
    pub version: u32,
}

/// One execution of a flow: the server-side record of how far a sign-in
/// has got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthTransaction {
    state: TransactionSnapshot,
}

fn not_active() -> DomainError {
    DomainError::conflict(
        "authentication.transaction_not_active",
        "this sign-in is no longer in progress; start again",
    )
}

impl AuthTransaction {
    /// How long a sign-in may take from start to finish.
    pub const LIFETIME: Duration = Duration::minutes(10);
    /// How many rejected steps a transaction tolerates before it fails.
    pub const MAX_REJECTIONS: u32 = 5;

    /// Starts a transaction for a flow, bound to the hash of a secret that
    /// only the browser starting the sign-in holds.
    #[must_use]
    pub fn start(flow: &AuthFlow, client: ClientInfo, binding: [u8; 32], now: Timestamp) -> Self {
        Self {
            state: TransactionSnapshot {
                id: TransactionId::generate(),
                flow_name: flow.name.clone(),
                flow_version: flow.version,
                current_step: 0,
                identified: false,
                candidate: None,
                identifier_key: None,
                satisfied_methods: Vec::new(),
                carried_methods: Vec::new(),
                demanded: None,
                raised_session: None,
                challenge: None,
                rejections: 0,
                status: TransactionStatus::InProgress,
                started_at: now,
                expires_at: now + Self::LIFETIME,
                client,
                binding,
                version: 0,
            },
        }
    }

    /// Starts a step-up of `session`, for its user: the identifier is known
    /// as `identifier_key`, the `carried` methods count already, and the
    /// first `satisfied_steps` steps of the flow are satisfied. See
    /// `docs/architecture/contexts/authentication.md`, "Step-up".
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn start_step_up(
        flow: &AuthFlow,
        client: ClientInfo,
        binding: [u8; 32],
        now: Timestamp,
        session: SessionId,
        user: UserId,
        identifier_key: [u8; 32],
        carried: Vec<String>,
        satisfied_steps: usize,
        demanded: Option<Assurance>,
    ) -> Self {
        let mut transaction = Self::start(flow, client, binding, now);
        let state = &mut transaction.state;
        state.current_step = satisfied_steps;
        state.identified = true;
        state.candidate = Some(user);
        state.identifier_key = Some(identifier_key);
        state.carried_methods = carried;
        state.demanded = demanded;
        state.raised_session = Some(session);
        transaction
    }

    /// The methods that count for the assurance of the sign-in: those
    /// carried from the session and those satisfied in this transaction.
    #[must_use]
    pub fn counted_methods(&self) -> Vec<String> {
        let mut methods = self.state.carried_methods.clone();
        for method in &self.state.satisfied_methods {
            if !methods.contains(method) {
                methods.push(method.clone());
            }
        }
        methods
    }

    /// Rebuilds a transaction from stored state.
    #[must_use]
    pub const fn from_snapshot(state: TransactionSnapshot) -> Self {
        Self { state }
    }

    /// The transaction's current state, for storage and for reading.
    #[must_use]
    pub const fn snapshot(&self) -> &TransactionSnapshot {
        &self.state
    }

    /// The transaction's identifier.
    #[must_use]
    pub const fn id(&self) -> TransactionId {
        self.state.id
    }

    /// Who is trying to sign in, if the identifier belongs to someone.
    #[must_use]
    pub const fn candidate(&self) -> Option<UserId> {
        self.state.candidate
    }

    /// Whether the given hash is that of the secret this transaction was
    /// started with.
    #[must_use]
    pub fn is_bound_to(&self, binding: &[u8; 32]) -> bool {
        &self.state.binding == binding
    }

    /// Where the transaction stands at `now`.
    #[must_use]
    pub fn state_at(&self, now: Timestamp) -> TransactionState {
        match self.state.status {
            TransactionStatus::Completed => TransactionState::Completed,
            TransactionStatus::Failed => TransactionState::Failed,
            TransactionStatus::Cancelled => TransactionState::Cancelled,
            TransactionStatus::InProgress if now >= self.state.expires_at => {
                TransactionState::Expired
            }
            TransactionStatus::InProgress => TransactionState::InProgress,
        }
    }

    /// Whether every step of `flow` has been satisfied, so that the
    /// transaction can be completed.
    #[must_use]
    pub fn all_steps_satisfied(&self, flow: &AuthFlow) -> bool {
        self.state.current_step >= flow.steps.len()
    }

    /// Fails unless the transaction is accepting steps at `now`.
    ///
    /// # Errors
    ///
    /// Returns a `Conflict` error if the transaction has ended or expired.
    pub fn require_in_progress(&self, now: Timestamp) -> Result<(), DomainError> {
        if self.state_at(now) == TransactionState::InProgress {
            Ok(())
        } else {
            Err(not_active())
        }
    }

    /// The challenge the current step asked for, if any.
    #[must_use]
    pub const fn challenge(&self) -> Option<&[u8; 32]> {
        self.state.challenge.as_ref()
    }

    /// Keeps the challenge the current step asked for, in place of any
    /// earlier one.
    pub(crate) fn record_challenge(&mut self, challenge: [u8; 32]) {
        self.state.challenge = Some(challenge);
    }

    /// Records the outcome of the identifier step and moves on.
    pub(crate) fn record_identified(
        &mut self,
        candidate: Option<UserId>,
        identifier_key: [u8; 32],
    ) {
        self.state.challenge = None;
        self.state.identified = true;
        self.state.candidate = candidate;
        self.state.identifier_key = Some(identifier_key);
        self.state.current_step += 1;
    }

    /// Records a satisfied step and moves on.
    pub(crate) fn record_satisfied(&mut self, method: Option<&str>) {
        self.state.challenge = None;
        if let Some(method) = method
            && !self.state.satisfied_methods.iter().any(|m| m == method)
        {
            self.state.satisfied_methods.push(method.to_owned());
        }
        self.state.current_step += 1;
    }

    /// Records that the current step is passed over and moves on.
    pub(crate) fn record_passed_over(&mut self) {
        self.state.current_step += 1;
    }

    /// Records an alternative that established who is signing in and
    /// proved it: the flow's first `steps`, its required ones, are done.
    pub(crate) fn record_authenticated(
        &mut self,
        user: UserId,
        method: Option<&str>,
        steps: usize,
    ) {
        self.state.challenge = None;
        self.state.identified = true;
        self.state.candidate = Some(user);
        // No identifier was typed: a second factor that follows counts its
        // attempts by the person instead.
        self.state.identifier_key = Some(person_attempt_key(user));
        if let Some(method) = method
            && !self.state.satisfied_methods.iter().any(|m| m == method)
        {
            self.state.satisfied_methods.push(method.to_owned());
        }
        self.state.current_step = steps;
    }

    /// Records a rejected step. The transaction does not move on, and
    /// fails once it has tolerated enough. Returns how many more
    /// rejections it tolerates.
    pub(crate) fn record_rejection(&mut self) -> u32 {
        self.state.challenge = None;
        self.state.rejections += 1;
        if self.state.rejections >= Self::MAX_REJECTIONS {
            self.state.status = TransactionStatus::Failed;
        }
        Self::MAX_REJECTIONS.saturating_sub(self.state.rejections)
    }

    /// Marks the transaction completed. The caller starts the session.
    ///
    /// # Errors
    ///
    /// Returns a `Conflict` error unless the transaction is in progress,
    /// every step of the flow is satisfied and a candidate is known.
    pub fn complete(&mut self, flow: &AuthFlow, now: Timestamp) -> Result<UserId, DomainError> {
        self.require_in_progress(now)?;
        let candidate = self
            .state
            .candidate
            .filter(|_| self.all_steps_satisfied(flow))
            .ok_or_else(|| {
                DomainError::conflict(
                    "authentication.transaction_incomplete",
                    "this sign-in is not finished",
                )
            })?;
        self.state.status = TransactionStatus::Completed;
        Ok(candidate)
    }

    /// Ends the transaction on request. Does nothing if it already ended.
    pub fn cancel(&mut self) {
        if self.state.status == TransactionStatus::InProgress {
            self.state.status = TransactionStatus::Cancelled;
        }
    }
}

/// The key a second factor's attempts are counted by when an alternative
/// identified the person and no identifier was typed: a fixed prefix and
/// the person's identifier, which no SHA-256 of an identifier is.
#[must_use]
pub(crate) fn person_attempt_key(user: UserId) -> [u8; 32] {
    let mut key = [0_u8; 32];
    key[..16].copy_from_slice(b"attempts of user");
    key[16..].copy_from_slice(user.as_uuid().as_bytes());
    key
}
