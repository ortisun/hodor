//! Flows: a sign-in procedure as data.

use hodor_session::api::Assurance;

/// How a step is required.
///
/// Milestone 1 has one kind. Alternative, conditional and optional steps
/// are further kinds, added in Phase 4 without changing the shape of a
/// flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    /// The step must be satisfied for the flow to continue.
    Required,
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
        };
        Self {
            name: "sign-in".to_owned(),
            version: 1,
            steps: vec![step("identifier"), step("password")],
            minimum_assurance: Assurance::SingleFactor,
        }
    }
}
