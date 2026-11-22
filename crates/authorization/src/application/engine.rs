//! The contract every engine fulfils, and the engines a binary has.
//!
//! See `docs/architecture/contexts/authorization.md`, "Engines", and
//! Decision 0009.

use crate::domain::decision::{EngineAnswer, EngineId, PolicyReference, PolicyRevision};
use crate::domain::request::{Attributes, AuthorizationRequest};
use hodor_kernel::{DomainError, TenantContext};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

/// What an engine is given to decide.
#[derive(Debug, Clone, PartialEq)]
pub struct EvaluationInput {
    /// The request. Its asserted attributes are empty unless the binding
    /// trusts them.
    pub request: AuthorizationRequest,
    /// What Hodor knows about the subject. Empty for a subject it does not
    /// know.
    pub subject_attributes: Attributes,
    /// How long the engine may take. An engine that waits on something
    /// else stops waiting when it is reached.
    pub time_limit: Duration,
}

/// What an engine can do beyond deciding.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EngineCapabilities {
    /// It can evaluate against a draft or a chosen revision.
    pub simulation: bool,
    /// It can say which policies decided.
    pub explanation: bool,
}

/// Decides requests. Engines are chosen at run time per binding, so they
/// are held as `Arc<dyn AuthorizationEngine>`.
#[async_trait::async_trait]
pub trait AuthorizationEngine: Send + Sync {
    /// Its name, such as `native`.
    fn id(&self) -> EngineId;

    /// What it can do beyond deciding.
    fn capabilities(&self) -> EngineCapabilities;

    /// Decides one request in `tenant`.
    ///
    /// # Errors
    ///
    /// Returns an error when it cannot decide; the context makes that
    /// indeterminate.
    async fn evaluate(
        &self,
        tenant: &TenantContext,
        input: &EvaluationInput,
    ) -> Result<EngineAnswer, DomainError>;

    /// Decides several requests, one answer per request in the same order.
    /// One failing request does not fail the others. Unless an engine does
    /// better, the requests are decided one after the other.
    async fn evaluate_batch(
        &self,
        tenant: &TenantContext,
        inputs: &[EvaluationInput],
    ) -> Vec<Result<EngineAnswer, DomainError>> {
        let mut answers = Vec::with_capacity(inputs.len());
        for input in inputs {
            answers.push(self.evaluate(tenant, input).await);
        }
        answers
    }
}

/// The policies a simulation evaluates against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySelection {
    /// What is published now.
    Published,
    /// One revision.
    Revision(PolicyRevision),
    /// A draft that is not published.
    Draft(PolicyReference),
}

/// What a simulation answers: the engine's part, and how it got there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulationAnswer {
    /// What the engine would answer.
    pub answer: EngineAnswer,
    /// The steps it took, in words, for the person simulating.
    pub trace: Vec<String>,
}

/// Evaluates a request against chosen policies, for the engines that can.
/// A simulated answer is never taken as a real decision.
#[async_trait::async_trait]
pub trait PolicySimulator: Send + Sync {
    /// Evaluates `input` in `tenant` against `against`.
    ///
    /// # Errors
    ///
    /// Returns an error when it cannot evaluate, or the selection does not
    /// exist.
    async fn simulate(
        &self,
        tenant: &TenantContext,
        input: &EvaluationInput,
        against: &PolicySelection,
    ) -> Result<SimulationAnswer, DomainError>;
}

#[derive(Clone)]
struct Registered {
    engine: Arc<dyn AuthorizationEngine>,
    simulator: Option<Arc<dyn PolicySimulator>>,
}

/// The engines a binary has, by name. Filled when the binary starts.
#[derive(Clone, Default)]
pub struct EngineRegistry {
    engines: BTreeMap<EngineId, Registered>,
}

impl std::fmt::Debug for EngineRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineRegistry")
            .field("engines", &self.engines.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl EngineRegistry {
    /// No engine.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an engine that cannot simulate.
    ///
    /// # Errors
    ///
    /// Returns `authorization.engine_registered_twice` if an engine of the
    /// same name is already there.
    pub fn register(&mut self, engine: Arc<dyn AuthorizationEngine>) -> Result<(), DomainError> {
        self.add(engine, None)
    }

    /// Adds an engine with its simulator.
    ///
    /// # Errors
    ///
    /// Returns `authorization.engine_registered_twice` if an engine of the
    /// same name is already there.
    pub fn register_with_simulator(
        &mut self,
        engine: Arc<dyn AuthorizationEngine>,
        simulator: Arc<dyn PolicySimulator>,
    ) -> Result<(), DomainError> {
        self.add(engine, Some(simulator))
    }

    fn add(
        &mut self,
        engine: Arc<dyn AuthorizationEngine>,
        simulator: Option<Arc<dyn PolicySimulator>>,
    ) -> Result<(), DomainError> {
        let id = engine.id();
        if self.engines.contains_key(&id) {
            return Err(DomainError::conflict(
                "authorization.engine_registered_twice",
                "an engine of this name is already registered",
            )
            .with_detail(id.as_str().to_owned()));
        }
        self.engines.insert(id, Registered { engine, simulator });
        Ok(())
    }

    /// The engine of a name.
    #[must_use]
    pub fn engine(&self, id: &EngineId) -> Option<Arc<dyn AuthorizationEngine>> {
        self.engines
            .get(id)
            .map(|registered| Arc::clone(&registered.engine))
    }

    /// The simulator of an engine, if it has one.
    #[must_use]
    pub fn simulator(&self, id: &EngineId) -> Option<Arc<dyn PolicySimulator>> {
        self.engines
            .get(id)
            .and_then(|registered| registered.simulator.clone())
    }

    /// Whether an engine of this name is registered.
    #[must_use]
    pub fn contains(&self, id: &EngineId) -> bool {
        self.engines.contains_key(id)
    }
}
