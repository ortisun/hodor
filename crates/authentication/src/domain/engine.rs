//! The engine that interprets flows.

use crate::domain::authenticator::{Authenticator, Factor, StepInput, StepOutcome};
use crate::domain::flow::{AuthFlow, FlowStep};
use crate::domain::transaction::{AuthTransaction, TransactionStatus};
use hodor_kernel::{DomainError, TenantContext, Timestamp};
use hodor_session::api::Assurance;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// What submitting a step led to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    /// The step was satisfied; this step comes next.
    Next {
        /// The key of the next step.
        step: String,
    },
    /// The step was satisfied and it was the last one. The transaction can
    /// be completed.
    ReadyToComplete,
    /// The step was rejected. The same step is expected again.
    Rejected {
        /// How many more rejections the transaction tolerates.
        attempts_left: u32,
    },
    /// The step was rejected once too often. The transaction has failed.
    Failed,
}

/// Interprets flows: checks that a flow is valid and advances
/// transactions through it.
///
/// There is no hand-written sign-in procedure. Every flow, including the
/// built-in one, runs through this engine.
#[derive(Clone, Default)]
pub struct FlowEngine {
    authenticators: BTreeMap<&'static str, Arc<dyn Authenticator>>,
}

impl std::fmt::Debug for FlowEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlowEngine")
            .field(
                "authenticators",
                &self.authenticators.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

fn invalid_flow(reason: impl Into<String>) -> DomainError {
    DomainError::invalid("authentication.flow_invalid", reason.into())
}

impl FlowEngine {
    /// Creates an engine that knows no authenticators.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes an authenticator available to flows. A later registration of
    /// the same kind replaces the earlier one.
    #[must_use]
    pub fn with(mut self, authenticator: Arc<dyn Authenticator>) -> Self {
        self.authenticators
            .insert(authenticator.kind(), authenticator);
        self
    }

    /// Checks a flow against the rules of the specification. The engine
    /// never runs a flow that does not pass.
    ///
    /// # Errors
    ///
    /// Returns an `Invalid` error naming the first rule that is broken.
    pub fn validate(&self, flow: &AuthFlow) -> Result<(), DomainError> {
        if flow.steps.is_empty() {
            return Err(invalid_flow("a flow has at least one step"));
        }
        let mut keys = BTreeSet::new();
        let mut factors = BTreeSet::new();
        let mut identified = false;
        for step in &flow.steps {
            if !keys.insert(step.key.as_str()) {
                return Err(invalid_flow(format!(
                    "the step key `{}` appears twice",
                    step.key
                )));
            }
            let traits = self.authenticator(step)?.traits();
            if traits.factor.is_some() && !identified {
                return Err(invalid_flow(format!(
                    "the step `{}` proves an identity before any step has established whose",
                    step.key
                )));
            }
            identified |= traits.identifies;
            factors.extend(traits.factor);
        }
        if !identified {
            return Err(invalid_flow("no step establishes who is signing in"));
        }
        if assurance_of(&factors) < Some(flow.minimum_assurance) {
            return Err(invalid_flow(
                "the steps do not reach the flow's minimum assurance",
            ));
        }
        Ok(())
    }

    /// Runs the current step of a transaction with what was submitted and
    /// records the result in the transaction. The caller stores it.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` if the transaction is not in progress, `Invalid`
    /// if the input is for another step, and whatever error the
    /// authenticator reports when the step could not be performed at all.
    /// In every error case the transaction is left unchanged.
    pub async fn submit(
        &self,
        tenant: &TenantContext,
        flow: &AuthFlow,
        transaction: &mut AuthTransaction,
        input: &StepInput,
        now: Timestamp,
    ) -> Result<Progress, DomainError> {
        transaction.require_in_progress(now)?;
        let step = flow
            .steps
            .get(transaction.snapshot().current_step)
            .ok_or_else(|| {
                DomainError::conflict(
                    "authentication.no_step_pending",
                    "every step of this sign-in is already satisfied",
                )
            })?;
        if step.key != input.step_key() {
            return Err(DomainError::invalid(
                "authentication.unexpected_step",
                format!("this sign-in is waiting for the `{}` step", step.key),
            ));
        }

        let authenticator = self.authenticator(step)?;
        match authenticator.perform(tenant, transaction, input).await? {
            StepOutcome::Identified {
                candidate,
                identifier_key,
            } => transaction.record_identified(candidate, identifier_key),
            StepOutcome::Proven => transaction.record_satisfied(authenticator.traits().method),
            StepOutcome::Rejected => {
                let attempts_left = transaction.record_rejection();
                return Ok(
                    if transaction.snapshot().status == TransactionStatus::Failed {
                        Progress::Failed
                    } else {
                        Progress::Rejected { attempts_left }
                    },
                );
            }
        }
        Ok(match flow.steps.get(transaction.snapshot().current_step) {
            Some(next) => Progress::Next {
                step: next.key.clone(),
            },
            None => Progress::ReadyToComplete,
        })
    }

    /// The assurance a transaction's satisfied methods amount to, or
    /// `None` if nothing was proved.
    #[must_use]
    pub fn assurance(&self, transaction: &AuthTransaction) -> Option<Assurance> {
        let factors: BTreeSet<Factor> = self
            .authenticators
            .values()
            .map(|a| a.traits())
            .filter(|t| {
                t.method.is_some_and(|m| {
                    transaction
                        .snapshot()
                        .satisfied_methods
                        .iter()
                        .any(|s| s == m)
                })
            })
            .filter_map(|t| t.factor)
            .collect();
        assurance_of(&factors)
    }

    fn authenticator(&self, step: &FlowStep) -> Result<&Arc<dyn Authenticator>, DomainError> {
        self.authenticators
            .get(step.authenticator.as_str())
            .ok_or_else(|| {
                invalid_flow(format!(
                    "the step `{}` names the unknown authenticator `{}`",
                    step.key, step.authenticator
                ))
            })
    }
}

/// One kind of factor is single-factor assurance; two different kinds are
/// multi-factor. Two factors of the same kind are still one.
fn assurance_of(factors: &BTreeSet<Factor>) -> Option<Assurance> {
    match factors.len() {
        0 => None,
        1 => Some(Assurance::SingleFactor),
        _ => Some(Assurance::MultiFactor),
    }
}
