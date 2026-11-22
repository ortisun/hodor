//! A sign-in in progress.

use crate::domain::flow::AuthFlow;
use hodor_kernel::{DomainError, Timestamp, UserId};
use hodor_session::api::ClientInfo;
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
    /// The methods satisfied so far.
    pub satisfied_methods: Vec<String>,
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

    /// Records the outcome of the identifier step and moves on.
    pub(crate) fn record_identified(
        &mut self,
        candidate: Option<UserId>,
        identifier_key: [u8; 32],
    ) {
        self.state.identified = true;
        self.state.candidate = candidate;
        self.state.identifier_key = Some(identifier_key);
        self.state.current_step += 1;
    }

    /// Records a satisfied step and moves on.
    pub(crate) fn record_satisfied(&mut self, method: Option<&str>) {
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
        self.state.identified = true;
        self.state.candidate = Some(user);
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
