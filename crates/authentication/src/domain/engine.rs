//! The engine that interprets flows.

use crate::domain::authenticator::{Authenticator, ExternalInput, Factor, StepInput, StepOutcome};
use crate::domain::enrollment::Enrolled;
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

/// What submitting a step led to, and what the step put in use, if it was
/// the enrollment step: the recovery codes made with it are to be shown
/// once.
#[derive(Debug, Clone)]
pub struct Submitted {
    /// Where the transaction stands.
    pub progress: Progress,
    /// What the step enrolled, when it enrolled something.
    pub enrolled: Option<Enrolled>,
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
                factors.extend(traits.second_factor);
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
            let proved: BTreeSet<Factor> = std::iter::once(factor)
                .chain(traits.second_factor)
                .collect();
            if assurance_of(&proved) < Some(flow.minimum_assurance) {
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
    /// if the input is for another step, `Forbidden` for an alternative the
    /// tenant does not offer, and whatever error the authenticator reports
    /// when the step could not be performed at all. In every error case
    /// the transaction is left unchanged.
    pub async fn submit(
        &self,
        tenant: &TenantContext,
        flow: &AuthFlow,
        transaction: &mut AuthTransaction,
        input: &StepInput,
        demanded: Assurance,
        now: Timestamp,
    ) -> Result<Progress, DomainError> {
        self.submit_step(tenant, flow, transaction, input, demanded, now)
            .await
            .map(|submitted| submitted.progress)
    }

    /// Runs the current step as [`Self::submit`] does, and also answers
    /// what the step put in use when it was the enrollment step.
    ///
    /// # Errors
    ///
    /// As [`Self::submit`].
    pub async fn submit_step(
        &self,
        tenant: &TenantContext,
        flow: &AuthFlow,
        transaction: &mut AuthTransaction,
        input: &StepInput,
        demanded: Assurance,
        now: Timestamp,
    ) -> Result<Submitted, DomainError> {
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
        if is_alternative {
            Self::require_offered(authenticator, tenant).await?;
        }
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
        let mut enrolled = None;
        match authenticator.perform(tenant, transaction, input).await? {
            StepOutcome::Rejected => {
                let attempts_left = transaction.record_rejection();
                let progress = if transaction.snapshot().status == TransactionStatus::Failed {
                    Progress::Failed
                } else {
                    Progress::Rejected { attempts_left }
                };
                return Ok(Submitted {
                    progress,
                    enrolled: None,
                });
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
            StepOutcome::Enrolled(put_in_use) if !is_alternative => {
                transaction.record_satisfied(authenticator.traits().method);
                enrolled = Some(put_in_use);
            }
            StepOutcome::Authenticated { .. }
            | StepOutcome::Identified { .. }
            | StepOutcome::Proven
            | StepOutcome::Enrolled(_) => return Err(misbehaved()),
        }
        let must_reach = flow.minimum_assurance.max(demanded);
        if let Err(error) = self.pass_over(tenant, flow, transaction, must_reach).await {
            *transaction = before;
            return Err(error);
        }
        let progress = match flow.steps.get(transaction.snapshot().current_step) {
            Some(next) => Progress::Next {
                step: next.key.clone(),
            },
            None => Progress::ReadyToComplete,
        };
        Ok(Submitted { progress, enrolled })
    }

    /// Asks the current step's authenticator for a challenge, keeps it in
    /// the transaction in place of any earlier one, and returns what the
    /// browser needs. While no step has been satisfied, the step may also
    /// be an alternative. The caller stores the transaction.
    ///
    /// `asked` names the step and holds what the person gave with the
    /// request, which only the step's authenticator understands.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` if the transaction is not in progress, `Invalid`
    /// if the step is neither the current step nor an alternative that may
    /// still be taken, or needs no challenge, `Forbidden` for an
    /// alternative the tenant does not offer, and whatever error the
    /// authenticator reports.
    pub async fn challenge(
        &self,
        tenant: &TenantContext,
        flow: &AuthFlow,
        transaction: &mut AuthTransaction,
        asked: &ExternalInput,
        now: Timestamp,
    ) -> Result<serde_json::Value, DomainError> {
        let step = asked.step.as_str();
        transaction.require_in_progress(now)?;
        let alternative = (transaction.snapshot().current_step == 0)
            .then(|| {
                flow.alternatives
                    .iter()
                    .find(|alternative| alternative.key == step)
            })
            .flatten();
        let current = match alternative {
            Some(alternative) => {
                Self::require_offered(self.authenticator(alternative)?, tenant).await?;
                alternative
            }
            None => {
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
                current
            }
        };
        let made = self
            .authenticator(current)?
            .challenge(tenant, transaction, asked)
            .await?
            .ok_or_else(|| {
                DomainError::invalid(
                    "authentication.step_has_no_challenge",
                    format!("the `{step}` step needs no challenge"),
                )
            })?;
        if let Some(challenge) = made.challenge {
            transaction.record_challenge(challenge);
        }
        if let Some(begun) = made.enrollment {
            transaction.record_enrollment(begun);
        }
        Ok(made.options)
    }

    /// The keys of the alternatives of `flow` that the tenant offers, in
    /// the order of the flow.
    ///
    /// # Errors
    ///
    /// Returns an `Invalid` error for an alternative whose authenticator is
    /// unknown, and whatever error an authenticator reports.
    pub async fn offered_alternatives(
        &self,
        tenant: &TenantContext,
        flow: &AuthFlow,
    ) -> Result<Vec<String>, DomainError> {
        let mut offered = Vec::new();
        for alternative in &flow.alternatives {
            if self.authenticator(alternative)?.offered(tenant).await? {
                offered.push(alternative.key.clone());
            }
        }
        Ok(offered)
    }

    /// Refuses an alternative the tenant does not offer.
    async fn require_offered(
        authenticator: &Arc<dyn Authenticator>,
        tenant: &TenantContext,
    ) -> Result<(), DomainError> {
        if authenticator.offered(tenant).await? {
            Ok(())
        } else {
            Err(DomainError::new(
                hodor_kernel::ErrorKind::Forbidden,
                "authentication.method_not_offered",
                "this way of signing in is not offered here",
            ))
        }
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
            Condition::MultiFactorNotReached => {
                self.assurance(transaction) < Some(Assurance::MultiFactor)
            }
            Condition::StrongerAssuranceNeeded => {
                self.assurance(transaction) < Some(must_reach.max(Assurance::MultiFactor))
            }
        }
    }

    /// The assurance a transaction amounts to, from the methods carried
    /// from a session and those satisfied in it, or `None` if nothing was
    /// proved.
    #[must_use]
    pub fn assurance(&self, transaction: &AuthTransaction) -> Option<Assurance> {
        self.assurance_of_methods(&transaction.counted_methods())
    }

    /// The assurance a list of methods amounts to, or `None` if none of
    /// them proves anything. The one table of methods and factors, which
    /// other contexts ask through the service.
    #[must_use]
    pub fn assurance_of_methods(&self, methods: &[String]) -> Option<Assurance> {
        let used: Vec<&Arc<dyn Authenticator>> = self
            .authenticators
            .values()
            .filter(|a| {
                a.traits()
                    .method
                    .is_some_and(|m| methods.iter().any(|given| given == m))
            })
            .collect();
        let factors: BTreeSet<Factor> = used
            .iter()
            .map(|a| a.traits())
            .flat_map(|t| t.factor.into_iter().chain(t.second_factor))
            .collect();
        let resists = used.iter().any(|a| a.resists_phishing());
        assurance_of(&factors).map(|reached| {
            if reached == Assurance::MultiFactor && resists {
                Assurance::PhishingResistant
            } else {
                reached
            }
        })
    }

    /// How many steps of `flow`, from the start, a step-up carrying
    /// `carried` has satisfied already: the steps that only establish who
    /// is signing in, and the required steps whose method is carried. When
    /// a carried method is that of an alternative, every required step is
    /// satisfied, as the alternative itself satisfied them.
    #[must_use]
    pub fn satisfied_by(&self, flow: &AuthFlow, carried: &[String]) -> usize {
        let method_of = |step: &FlowStep| {
            self.authenticators
                .get(step.authenticator.as_str())
                .and_then(|a| a.traits().method)
        };
        let through_alternative = flow.alternatives.iter().any(|alternative| {
            method_of(alternative).is_some_and(|m| carried.iter().any(|given| given == m))
        });
        if through_alternative {
            return flow.required_steps();
        }
        flow.steps
            .iter()
            .take(flow.required_steps())
            .take_while(|step| {
                let traits = self
                    .authenticators
                    .get(step.authenticator.as_str())
                    .map(|a| a.traits());
                match traits {
                    Some(traits) if traits.factor.is_none() => true,
                    Some(_) => {
                        method_of(step).is_some_and(|m| carried.iter().any(|given| given == m))
                    }
                    None => false,
                }
            })
            .count()
    }

    /// Whether a transaction can still reach `must_reach`: the methods it
    /// counts, together with those of every remaining step the person has
    /// the means for, amount to it.
    ///
    /// # Errors
    ///
    /// Returns whatever error an authenticator reports when asked whether
    /// the person has the means for its step.
    pub async fn reachable(
        &self,
        tenant: &TenantContext,
        flow: &AuthFlow,
        transaction: &AuthTransaction,
        must_reach: Assurance,
    ) -> Result<bool, DomainError> {
        let mut methods = transaction.counted_methods();
        for step in flow.steps.iter().skip(transaction.snapshot().current_step) {
            let authenticator = self.authenticator(step)?;
            let performed = step.requirement.is_required()
                || authenticator.has_means(tenant, transaction).await?;
            if performed && let Some(method) = authenticator.traits().method {
                methods.push(method.to_owned());
            }
        }
        Ok(self.assurance_of_methods(&methods) >= Some(must_reach))
    }

    /// Passes over the steps of a step-up that was just started that are
    /// not to be performed, as when a step is satisfied.
    ///
    /// # Errors
    ///
    /// Returns whatever error an authenticator reports.
    pub async fn settle(
        &self,
        tenant: &TenantContext,
        flow: &AuthFlow,
        transaction: &mut AuthTransaction,
        demanded: Assurance,
    ) -> Result<(), DomainError> {
        let must_reach = flow.minimum_assurance.max(demanded);
        self.pass_over(tenant, flow, transaction, must_reach).await
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
