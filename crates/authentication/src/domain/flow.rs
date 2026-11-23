//! Flows: a sign-in procedure as data.

use hodor_session::api::Assurance;

/// A fact about a sign-in that decides whether a conditional step is
/// performed. A small closed set, not a language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    /// The methods satisfied so far do not reach the assurance the sign-in
    /// must reach: the flow's minimum, raised by the tenant's policy.
    AssuranceNotReached,
    /// The methods satisfied so far are not yet multi-factor: a further
    /// factor adds nothing to a sign-in that already is.
    MultiFactorNotReached,
    /// The methods satisfied so far are not yet multi-factor, or do not
    /// reach the assurance the sign-in must reach: the condition of a step
    /// that can make a sign-in phishing-resistant.
    StrongerAssuranceNeeded,
}

/// How a step is required.
///
/// A step that is performed is satisfied in the same way whatever its
/// requirement. Whether a step that is not required is performed is
/// decided by the engine when the sign-in reaches it; the person signing
/// in can never decline it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    /// The step must be satisfied for the flow to continue.
    Required,
    /// The step is performed when the person has the means for it, and
    /// passed over when they do not.
    Optional,
    /// The step is performed when its condition holds and the person has
    /// the means for it, and passed over otherwise.
    Conditional(Condition),
}

impl Requirement {
    /// Whether the step is performed in every sign-in.
    #[must_use]
    pub const fn is_required(self) -> bool {
        matches!(self, Self::Required)
    }
}

/// One step of a flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowStep {
    /// Names the step within the flow, and what input it expects.
    pub key: String,
    /// The kind of authenticator that performs the step.
    pub authenticator: String,
    /// How the step is required.
    pub requirement: Requirement,
    /// Kinds of authenticator that may satisfy the step in its place, each
    /// submitted under its own kind as key. Only for a step that is not
    /// required.
    pub substitutes: Vec<String>,
}

/// A sign-in procedure: an ordered list of steps interpreted by the
/// engine. A published version never changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthFlow {
    /// The flow's name.
    pub name: String,
    /// The flow's version.
    pub version: u32,
    /// The steps, in order.
    pub steps: Vec<FlowStep>,
    /// Steps that, satisfied at the very start, take the place of every
    /// required step of `steps`. The steps that are not required still
    /// apply after them.
    pub alternatives: Vec<FlowStep>,
    /// How strongly the user must have proved their identity for the flow
    /// to complete.
    pub minimum_assurance: Assurance,
}

impl AuthFlow {
    /// The flow every tenant uses in Milestone 1: a login identifier, then
    /// a password.
    #[must_use]
    pub fn built_in() -> Self {
        let step = |key: &str| FlowStep {
            key: key.to_owned(),
            authenticator: key.to_owned(),
            requirement: Requirement::Required,
            substitutes: Vec::new(),
        };
        Self {
            name: "sign-in".to_owned(),
            version: 1,
            steps: vec![step("identifier"), step("password")],
            alternatives: Vec::new(),
            minimum_assurance: Assurance::SingleFactor,
        }
    }

    /// How many steps are required. They come first: a valid flow has
    /// every step that is not required after them.
    #[must_use]
    pub fn required_steps(&self) -> usize {
        self.steps
            .iter()
            .take_while(|step| step.requirement.is_required())
            .count()
    }

    /// The same flow with one more step at the end: this key, performed
    /// by this kind of authenticator, required in this way.
    #[must_use]
    pub fn with_step(mut self, key: &str, authenticator: &str, requirement: Requirement) -> Self {
        self.steps.push(FlowStep {
            key: key.to_owned(),
            authenticator: authenticator.to_owned(),
            requirement,
            substitutes: Vec::new(),
        });
        self
    }

    /// The same flow with one more substitute for the step with this key:
    /// an authenticator of this kind may satisfy it in its place. A key
    /// that names no step changes nothing; validation then still holds.
    #[must_use]
    pub fn with_substitute(mut self, key: &str, authenticator: &str) -> Self {
        if let Some(step) = self.steps.iter_mut().find(|step| step.key == key) {
            step.substitutes.push(authenticator.to_owned());
        }
        self
    }

    /// The same flow with one more alternative: a step with this key,
    /// performed by this kind of authenticator.
    #[must_use]
    pub fn with_alternative(mut self, key: &str, authenticator: &str) -> Self {
        self.alternatives.push(FlowStep {
            key: key.to_owned(),
            authenticator: authenticator.to_owned(),
            requirement: Requirement::Required,
            substitutes: Vec::new(),
        });
        self
    }
}
