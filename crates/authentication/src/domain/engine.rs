//! The engine that interprets flows.

use crate::domain::authenticator::{Authenticator, Factor, StepInput, StepOutcome};
use crate::domain::flow::{AuthFlow, Condition, FlowStep, Requirement};
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
        let mut past_required = false;
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
            if step.requirement.is_required() {
                if past_required {
                    return Err(invalid_flow(format!(
                        "the required step `{}` comes after a step that is not required",
                        step.key
                    )));
                }
                identified |= traits.identifies;
                factors.extend(traits.factor);
            } else {
                past_required = true;
                if traits.identifies {
                    return Err(invalid_flow(format!(
                        "the step `{}` establishes who is signing in, so it must be required",
                        step.key
                    )));
                }
                if traits.factor.is_none() {
                    return Err(invalid_flow(format!(
                        "the step `{}` is not required and proves nothing",
                        step.key
                    )));
                }
            }
        }
        if !identified {
            return Err(invalid_flow("no step establishes who is signing in"));
        }
        if assurance_of(&factors) < Some(flow.minimum_assurance) {
            return Err(invalid_flow(
                "the steps do not reach the flow's minimum assurance",
            ));
        }
        for alternative in &flow.alternatives {
            if !alternative.substitutes.is_empty() {
                return Err(invalid_flow(format!(
                    "the alternative `{}` has substitutes; only a step that is not required can",
                    alternative.key
                )));
            }
            if !keys.insert(alternative.key.as_str()) {
                return Err(invalid_flow(format!(
                    "the step key `{}` appears twice",
                    alternative.key
                )));
            }
            let traits = self.authenticator(alternative)?.traits();
            let Some(factor) = traits.factor.filter(|_| traits.identifies) else {
                return Err(invalid_flow(format!(
                    "the alternative `{}` must both establish who is signing in and prove it",
                    alternative.key
                )));
            };
            if assurance_of(&BTreeSet::from([factor])) < Some(flow.minimum_assurance) {
                return Err(invalid_flow(format!(
                    "the alternative `{}` does not reach the flow's minimum assurance",
                    alternative.key
                )));
            }
        }
        self.validate_substitutes(flow, &keys)
    }

    /// Every substitute stands for a step that is not required, proves a
    /// factor without establishing who is signing in, and has a key no step
    /// and no alternative has.
    fn validate_substitutes(
        &self,
        flow: &AuthFlow,
        keys: &BTreeSet<&str>,
    ) -> Result<(), DomainError> {
        for step in &flow.steps {
            let mut seen = BTreeSet::new();
            for substitute in &step.substitutes {
                if step.requirement.is_required() {
                    return Err(invalid_flow(format!(
                        "the step `{}` is required, so nothing can stand in for it",
                        step.key
                    )));
                }
                if keys.contains(substitute.as_str()) || !seen.insert(substitute.as_str()) {
                    return Err(invalid_flow(format!(
                        "the substitute `{substitute}` of the step `{}` has the key of another step, alternative or substitute",
                        step.key
                    )));
                }
                let traits = self.authenticator_of_kind(&step.key, substitute)?.traits();
                if traits.identifies || traits.factor.is_none() {
                    return Err(invalid_flow(format!(
                        "the substitute `{substitute}` of the step `{}` must prove a factor without establishing who is signing in",
                        step.key
                    )));
                }
            }
        }
        Ok(())
    }

    /// Runs the current step of a transaction with what was submitted and
    /// records the result in the transaction. The caller stores it.
    ///
    /// `demanded` is the assurance the sign-in must reach beyond the
    /// flow's own minimum, from the tenant's policy. Once a step is
    /// satisfied, the steps after it that are to be passed over are passed
    /// over, so that the step the transaction waits for is always one that
    /// is performed.
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
        demanded: Assurance,
        now: Timestamp,
    ) -> Result<Progress, DomainError> {
        transaction.require_in_progress(now)?;
        let current = flow.steps.get(transaction.snapshot().current_step);
        // An alternative is accepted only while no step has been satisfied.
        let alternative = (transaction.snapshot().current_step == 0)
            .then(|| {
                flow.alternatives
                    .iter()
                    .find(|alternative| alternative.key == input.step_key())
            })
            .flatten();
        let (step, kind, is_alternative) = match (alternative, current) {
            (Some(alternative), _) => (alternative, alternative.authenticator.as_str(), true),
            (None, Some(step)) if step.key == input.step_key() => {
                (step, step.authenticator.as_str(), false)
            }
            // A substitute is submitted under its own kind while the
            // sign-in waits for the step it stands in for.
            (None, Some(step))
                if step
                    .substitutes
                    .iter()
                    .any(|substitute| substitute == input.step_key()) =>
            {
                (step, input.step_key(), false)
            }
            (None, Some(step)) => {
                return Err(DomainError::invalid(
                    "authentication.unexpected_step",
                    format!("this sign-in is waiting for the `{}` step", step.key),
                ));
            }
            (None, None) => {
                return Err(DomainError::conflict(
                    "authentication.no_step_pending",
                    "every step of this sign-in is already satisfied",
                ));
            }
        };

        let authenticator = self.authenticator_of_kind(&step.key, kind)?;
        let misbehaved = || {
            DomainError::internal(
                "authentication.authenticator_misbehaved",
                "the sign-in could not continue",
            )
            .with_detail(format!(
                "the authenticator `{kind}` answered in a way its place in the flow does not allow"
            ))
        };
        let before = transaction.clone();
        match authenticator.perform(tenant, transaction, input).await? {
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
            StepOutcome::Authenticated { user } if is_alternative => transaction
                .record_authenticated(user, authenticator.traits().method, flow.required_steps()),
            StepOutcome::Identified {
                candidate,
                identifier_key,
            } if !is_alternative => transaction.record_identified(candidate, identifier_key),
            StepOutcome::Proven if !is_alternative => {
                transaction.record_satisfied(authenticator.traits().method);
            }
            StepOutcome::Authenticated { .. }
            | StepOutcome::Identified { .. }
            | StepOutcome::Proven => return Err(misbehaved()),
        }
        let must_reach = flow.minimum_assurance.max(demanded);
        if let Err(error) = self.pass_over(tenant, flow, transaction, must_reach).await {
            *transaction = before;
            return Err(error);
        }
        Ok(match flow.steps.get(transaction.snapshot().current_step) {
            Some(next) => Progress::Next {
                step: next.key.clone(),
            },
            None => Progress::ReadyToComplete,
        })
    }

    /// Asks the current step's authenticator for a challenge, keeps it in
    /// the transaction in place of any earlier one, and returns what the
    /// browser needs. The caller stores the transaction.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` if the transaction is not in progress, `Invalid`
    /// if `step` is not the current step or needs no challenge, and
    /// whatever error the authenticator reports.
    pub async fn challenge(
        &self,
        tenant: &TenantContext,
        flow: &AuthFlow,
        transaction: &mut AuthTransaction,
        step: &str,
        now: Timestamp,
    ) -> Result<serde_json::Value, DomainError> {
        transaction.require_in_progress(now)?;
        let current = flow
            .steps
            .get(transaction.snapshot().current_step)
            .ok_or_else(|| {
                DomainError::conflict(
                    "authentication.no_step_pending",
                    "every step of this sign-in is already satisfied",
                )
            })?;
        if current.key != step {
            return Err(DomainError::invalid(
                "authentication.unexpected_step",
                format!("this sign-in is waiting for the `{}` step", current.key),
            ));
        }
        let made = self
            .authenticator(current)?
            .challenge(tenant, transaction)
            .await?
            .ok_or_else(|| {
                DomainError::invalid(
                    "authentication.step_has_no_challenge",
                    format!("the `{step}` step needs no challenge"),
                )
            })?;
        transaction.record_challenge(made.challenge);
        Ok(made.options)
    }

    /// Passes over the steps from the current one on that are not to be
    /// performed, and stops at the first that is, or at the end.
    async fn pass_over(
        &self,
        tenant: &TenantContext,
        flow: &AuthFlow,
        transaction: &mut AuthTransaction,
        must_reach: Assurance,
    ) -> Result<(), DomainError> {
        while let Some(step) = flow.steps.get(transaction.snapshot().current_step) {
            let performed = match step.requirement {
                Requirement::Required => true,
                Requirement::Optional => {
                    self.authenticator(step)?
                        .has_means(tenant, transaction)
                        .await?
                }
                Requirement::Conditional(condition) => {
                    self.holds(condition, transaction, must_reach)
                        && self
                            .authenticator(step)?
                            .has_means(tenant, transaction)
                            .await?
                }
            };
            if performed {
                break;
            }
            transaction.record_passed_over();
        }
        Ok(())
    }

    fn holds(
        &self,
        condition: Condition,
        transaction: &AuthTransaction,
        must_reach: Assurance,
    ) -> bool {
        match condition {
            Condition::AssuranceNotReached => self.assurance(transaction) < Some(must_reach),
        }
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
        self.authenticator_of_kind(&step.key, &step.authenticator)
    }

    fn authenticator_of_kind(
        &self,
        step: &str,
        kind: &str,
    ) -> Result<&Arc<dyn Authenticator>, DomainError> {
        self.authenticators.get(kind).ok_or_else(|| {
            invalid_flow(format!(
                "the step `{step}` names the unknown authenticator `{kind}`"
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
