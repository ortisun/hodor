//! Evaluating requests through the bound engine, and keeping the bindings.
//!
//! See `docs/architecture/contexts/authorization.md`, "Evaluating".

use crate::application::engine::{
    AuthorizationEngine, EngineRegistry, EvaluationInput, PolicySelection,
};
use crate::application::native::NativeEngine;
use crate::application::ports::{EngineBindingStore, RoleAssignmentStore, SubjectAttributeSource};
use crate::domain::binding::{BindingSettings, EngineBinding};
use crate::domain::decision::{
    AuthorizationDecision, DecisionId, DecisionMetadata, EngineAnswer, EngineId, ReasonCode,
};
use crate::domain::event::AuthorizationEvent;
use crate::domain::request::{Attributes, AuthorizationRequest, Namespace, Subject};
use crate::domain::role::Effect;
use hodor_kernel::{
    Caller, Clock, DomainError, EventEnvelope, EventMetadata, TenantContext, Timestamp, UnitOfWork,
    UnitOfWorkFactory,
};
use std::collections::BTreeMap;
use std::sync::Arc;

/// The most requests one batch may hold.
pub const MAX_BATCH: usize = 100;

/// A simulated decision: never recorded as a real one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Simulation {
    /// What would have been decided.
    pub decision: AuthorizationDecision,
    /// How the engine got there, in words.
    pub trace: Vec<String>,
}

/// Where a request ended before it became a decision.
enum Outcome {
    /// The engine answered allow or deny in time.
    Decided {
        engine: EngineId,
        answer: EngineAnswer,
        asserted_trusted: bool,
    },
    /// The resource server has no binding.
    Unbound,
    /// It could not be decided.
    Failed {
        binding: Option<EngineBinding>,
        engine: Option<EngineId>,
        cause: ReasonCode,
    },
}

/// A request on its way to an engine.
struct Pending {
    index: usize,
    binding: EngineBinding,
    input: EvaluationInput,
}

/// Evaluates requests through the engine bound to their resource server,
/// and keeps the bindings.
#[derive(Clone)]
pub struct EvaluationService {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    bindings: Arc<dyn EngineBindingStore>,
    subjects: Arc<dyn SubjectAttributeSource>,
    administration: Arc<dyn AuthorizationEngine>,
    registry: EngineRegistry,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for EvaluationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvaluationService")
            .field("registry", &self.registry)
            .finish_non_exhaustive()
    }
}

impl EvaluationService {
    /// Wires the evaluation to its ports. Hodor's administration is
    /// answered by a [`NativeEngine`] over `assignments`, from the built-in
    /// roles, whatever the registry holds.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        assignments: Arc<dyn RoleAssignmentStore>,
        bindings: Arc<dyn EngineBindingStore>,
        subjects: Arc<dyn SubjectAttributeSource>,
        registry: EngineRegistry,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let administration = Arc::new(NativeEngine::administration(
            Arc::clone(&units_of_work),
            assignments,
        ));
        Self {
            units_of_work,
            bindings,
            subjects,
            administration,
            registry,
            clock,
        }
    }

    /// Binds a resource server to an engine, or changes its binding.
    /// Binding again with the same settings changes nothing and announces
    /// nothing.
    ///
    /// # Errors
    ///
    /// - The errors of [`EngineBinding::new`], such as
    ///   `authorization.namespace_reserved` for `hodor:admin`.
    /// - `authorization.unknown_engine` if the engine is not registered.
    /// - Storage errors.
    pub async fn bind(
        &self,
        tenant: &TenantContext,
        settings: BindingSettings,
        caller: Caller,
    ) -> Result<EngineBinding, DomainError> {
        let now = self.clock.now();
        // Checks the settings before anything is read.
        let fresh = EngineBinding::new(settings.clone(), now)?;
        if !self.registry.contains(&settings.engine) {
            return Err(DomainError::invalid(
                "authorization.unknown_engine",
                "no engine of this name is registered",
            )
            .with_detail(settings.engine.as_str().to_owned()));
        }
        let mut uow = self.units_of_work.begin(tenant).await?;
        let binding = match self
            .bindings
            .find(uow.as_mut(), &settings.namespace)
            .await?
        {
            Some(existing) if existing.settings() == &settings => return Ok(existing),
            Some(existing) => existing.changed(settings, now)?,
            None => fresh,
        };
        self.bindings.put(uow.as_mut(), &binding).await?;
        let event = AuthorizationEvent::EngineBound {
            namespace: binding.namespace().as_str().to_owned(),
            engine: binding.engine().as_str().to_owned(),
        };
        self.record(uow.as_mut(), caller, &event)?;
        uow.commit().await?;
        Ok(binding)
    }

    /// Removes a resource server's binding. Afterwards it is denied
    /// everything. Returns whether there was one.
    ///
    /// # Errors
    ///
    /// `authorization.namespace_reserved` for `hodor:admin`, and storage
    /// errors.
    pub async fn unbind(
        &self,
        tenant: &TenantContext,
        namespace: &Namespace,
        caller: Caller,
    ) -> Result<bool, DomainError> {
        if namespace.is_administration() {
            return Err(DomainError::invalid(
                "authorization.namespace_reserved",
                "Hodor's administration is always answered by its own engine and cannot be unbound",
            ));
        }
        let mut uow = self.units_of_work.begin(tenant).await?;
        let removed = self.bindings.remove(uow.as_mut(), namespace).await?;
        if removed {
            let event = AuthorizationEvent::EngineUnbound {
                namespace: namespace.as_str().to_owned(),
            };
            self.record(uow.as_mut(), caller, &event)?;
            uow.commit().await?;
        }
        Ok(removed)
    }

    /// The binding of a namespace: the fixed one for `hodor:admin`.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub async fn binding(
        &self,
        tenant: &TenantContext,
        namespace: &Namespace,
    ) -> Result<Option<EngineBinding>, DomainError> {
        if namespace.is_administration() {
            return Ok(Some(EngineBinding::administration()));
        }
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.bindings.find(uow.as_mut(), namespace).await
    }

    /// The tenant's stored bindings, ordered by namespace. The fixed
    /// binding of `hodor:admin` is not among them.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub async fn bindings(
        &self,
        tenant: &TenantContext,
    ) -> Result<Vec<EngineBinding>, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.bindings.list(uow.as_mut()).await
    }

    /// Decides one request. There is always a decision: whatever fails
    /// makes it indeterminate, unless the binding lets the action fail
    /// open.
    pub async fn evaluate(
        &self,
        tenant: &TenantContext,
        request: &AuthorizationRequest,
    ) -> AuthorizationDecision {
        let mut decisions = self.decide(tenant, std::slice::from_ref(request)).await;
        decisions.pop().unwrap_or_else(|| {
            // `decide` answers every request; this is never reached.
            self.decision(
                Outcome::Failed {
                    binding: None,
                    engine: None,
                    cause: ReasonCode::of(ReasonCode::ENGINE_FAILED),
                },
                self.clock.now(),
            )
        })
    }

    /// Decides up to 100 requests, one decision per request in the same
    /// order. A failure of one does not fail the others.
    ///
    /// # Errors
    ///
    /// `authorization.batch_too_large` beyond 100 requests.
    pub async fn evaluate_batch(
        &self,
        tenant: &TenantContext,
        requests: &[AuthorizationRequest],
    ) -> Result<Vec<AuthorizationDecision>, DomainError> {
        if requests.len() > MAX_BATCH {
            return Err(DomainError::invalid(
                "authorization.batch_too_large",
                "a batch holds at most 100 requests",
            ));
        }
        Ok(self.decide(tenant, requests).await)
    }

    /// What the bound engine would decide against chosen policies. Nothing
    /// is recorded and nothing fails open.
    ///
    /// # Errors
    ///
    /// - `authorization.no_engine_bound` if the resource server has no
    ///   binding.
    /// - `authorization.simulation_unsupported` if its engine cannot
    ///   simulate, which includes Hodor's administration.
    /// - The engine's and the attribute source's errors.
    pub async fn simulate(
        &self,
        tenant: &TenantContext,
        request: &AuthorizationRequest,
        against: &PolicySelection,
    ) -> Result<Simulation, DomainError> {
        let start = self.clock.now();
        let unsupported = || {
            DomainError::invalid(
                "authorization.simulation_unsupported",
                "the engine bound to this resource server cannot simulate",
            )
        };
        if request.namespace.is_administration() {
            return Err(unsupported());
        }
        let binding = self
            .binding(tenant, &request.namespace)
            .await?
            .ok_or_else(|| {
                DomainError::not_found(
                    "authorization.no_engine_bound",
                    "no engine is bound to this resource server",
                )
            })?;
        let simulator = self
            .registry
            .simulator(binding.engine())
            .ok_or_else(unsupported)?;
        let attributes = self
            .subjects
            .attributes_of(tenant, &request.subject)
            .await?;
        let input = Self::input(&binding, request, attributes);
        let simulated = simulator.simulate(tenant, &input, against).await?;
        let decision = self.decision(
            Outcome::Decided {
                engine: binding.engine().clone(),
                answer: simulated.answer,
                asserted_trusted: binding.settings().trust_asserted,
            },
            start,
        );
        Ok(Simulation {
            decision,
            trace: simulated.trace,
        })
    }

    async fn decide(
        &self,
        tenant: &TenantContext,
        requests: &[AuthorizationRequest],
    ) -> Vec<AuthorizationDecision> {
        let start = self.clock.now();
        let mut outcomes: Vec<Option<Outcome>> = requests.iter().map(|_| None).collect();
        let mut groups: BTreeMap<Namespace, Vec<Pending>> = BTreeMap::new();
        let mut bindings: BTreeMap<Namespace, Result<Option<EngineBinding>, ()>> = BTreeMap::new();
        let mut subjects: BTreeMap<Subject, Result<Attributes, ()>> = BTreeMap::new();

        for (index, request) in requests.iter().enumerate() {
            if !bindings.contains_key(&request.namespace) {
                let found = self
                    .binding(tenant, &request.namespace)
                    .await
                    .map_err(|_| ());
                bindings.insert(request.namespace.clone(), found);
            }
            let binding = match bindings.get(&request.namespace) {
                Some(Ok(Some(binding))) => binding.clone(),
                Some(Ok(None)) => {
                    outcomes[index] = Some(Outcome::Unbound);
                    continue;
                }
                _ => {
                    outcomes[index] = Some(Outcome::Failed {
                        binding: None,
                        engine: None,
                        cause: ReasonCode::of(ReasonCode::BINDING_UNAVAILABLE),
                    });
                    continue;
                }
            };
            if self.engine_for(&binding).is_none() {
                outcomes[index] = Some(Outcome::Failed {
                    engine: Some(binding.engine().clone()),
                    binding: Some(binding),
                    cause: ReasonCode::of(ReasonCode::ENGINE_UNAVAILABLE),
                });
                continue;
            }
            if !subjects.contains_key(&request.subject) {
                let resolved = self
                    .subjects
                    .attributes_of(tenant, &request.subject)
                    .await
                    .map_err(|_| ());
                subjects.insert(request.subject.clone(), resolved);
            }
            let Some(Ok(attributes)) = subjects.get(&request.subject) else {
                outcomes[index] = Some(Outcome::Failed {
                    engine: Some(binding.engine().clone()),
                    binding: Some(binding),
                    cause: ReasonCode::of(ReasonCode::SUBJECT_UNAVAILABLE),
                });
                continue;
            };
            let input = Self::input(&binding, request, attributes.clone());
            groups
                .entry(request.namespace.clone())
                .or_default()
                .push(Pending {
                    index,
                    binding,
                    input,
                });
        }

        for pending in groups.into_values() {
            for (index, outcome) in self.ask(tenant, pending).await {
                outcomes[index] = Some(outcome);
            }
        }

        let mut decisions = Vec::with_capacity(requests.len());
        for (request, outcome) in requests.iter().zip(outcomes) {
            let outcome = outcome.unwrap_or(Outcome::Failed {
                binding: None,
                engine: None,
                cause: ReasonCode::of(ReasonCode::ENGINE_FAILED),
            });
            let outcome = self.apply_failure_policy(tenant, request, outcome).await;
            decisions.push(self.decision(outcome, start));
        }
        decisions
    }

    fn engine_for(&self, binding: &EngineBinding) -> Option<Arc<dyn AuthorizationEngine>> {
        if binding.namespace().is_administration() {
            Some(Arc::clone(&self.administration))
        } else {
            self.registry.engine(binding.engine())
        }
    }

    fn input(
        binding: &EngineBinding,
        request: &AuthorizationRequest,
        subject_attributes: Attributes,
    ) -> EvaluationInput {
        let mut request = request.clone();
        if !binding.settings().trust_asserted {
            request.asserted = Attributes::none();
        }
        EvaluationInput {
            request,
            subject_attributes,
            time_limit: binding.settings().time_limit,
        }
    }

    /// Sends the requests of one binding to its engine together. A batch
    /// of n requests has n times the binding's time limit.
    async fn ask(&self, tenant: &TenantContext, pending: Vec<Pending>) -> Vec<(usize, Outcome)> {
        let Some(first) = pending.first() else {
            return Vec::new();
        };
        let binding = first.binding.clone();
        let Some(engine) = self.engine_for(&binding) else {
            return Vec::new();
        };
        let inputs: Vec<EvaluationInput> = pending.iter().map(|p| p.input.clone()).collect();
        let asked_at = self.clock.now();
        let answers = if let [input] = inputs.as_slice() {
            vec![engine.evaluate(tenant, input).await]
        } else {
            engine.evaluate_batch(tenant, &inputs).await
        };
        let elapsed = microseconds(asked_at, self.clock.now());
        let limit = binding
            .settings()
            .time_limit
            .saturating_mul(u32::try_from(inputs.len()).unwrap_or(u32::MAX));
        let engine_id = binding.engine().clone();
        let failed = |binding: &EngineBinding, cause: &'static str| Outcome::Failed {
            binding: Some(binding.clone()),
            engine: Some(engine_id.clone()),
            cause: ReasonCode::of(cause),
        };
        if answers.len() != pending.len() {
            return pending
                .iter()
                .map(|p| (p.index, failed(&p.binding, ReasonCode::ENGINE_FAILED)))
                .collect();
        }
        pending
            .iter()
            .zip(answers)
            .map(|(p, answer)| {
                let outcome = match answer {
                    _ if u128::from(elapsed) > limit.as_micros() => {
                        failed(&p.binding, ReasonCode::ENGINE_TIMED_OUT)
                    }
                    Ok(answer) if !answer.is_well_formed() => {
                        failed(&p.binding, ReasonCode::ENGINE_FAILED)
                    }
                    Ok(answer) if answer.effect == Effect::Indeterminate => Outcome::Failed {
                        binding: Some(p.binding.clone()),
                        engine: Some(engine_id.clone()),
                        cause: answer.reason,
                    },
                    Ok(answer) => Outcome::Decided {
                        engine: engine_id.clone(),
                        answer,
                        asserted_trusted: p.binding.settings().trust_asserted,
                    },
                    Err(_) => failed(&p.binding, ReasonCode::ENGINE_FAILED),
                };
                (p.index, outcome)
            })
            .collect()
    }

    /// A failure allows only when the binding lets the action fail open
    /// and the failure is recorded; otherwise it stays as it is.
    async fn apply_failure_policy(
        &self,
        tenant: &TenantContext,
        request: &AuthorizationRequest,
        outcome: Outcome,
    ) -> Outcome {
        let Outcome::Failed {
            binding: Some(binding),
            engine,
            cause,
        } = outcome
        else {
            return outcome;
        };
        if !binding.fails_open(&request.action) {
            return Outcome::Failed {
                binding: Some(binding),
                engine,
                cause,
            };
        }
        let event = AuthorizationEvent::FailedOpen {
            namespace: request.namespace.as_str().to_owned(),
            action: request.action.as_str().to_owned(),
            engine: engine.as_ref().map(|id| id.as_str().to_owned()),
            cause: cause.as_str().to_owned(),
        };
        match self.record_alone(tenant, &event).await {
            Ok(()) => Outcome::Decided {
                engine: engine.unwrap_or_else(|| binding.engine().clone()),
                answer: EngineAnswer::new(Effect::Allow, ReasonCode::of(ReasonCode::FAIL_OPEN)),
                asserted_trusted: binding.settings().trust_asserted,
            },
            Err(_) => Outcome::Failed {
                binding: Some(binding),
                engine,
                cause,
            },
        }
    }

    fn decision(&self, outcome: Outcome, start: Timestamp) -> AuthorizationDecision {
        let now = self.clock.now();
        let (effect, engine, answer, asserted_trusted) = match outcome {
            Outcome::Decided {
                engine,
                answer,
                asserted_trusted,
            } => (answer.effect, Some(engine), answer, asserted_trusted),
            Outcome::Unbound => (
                Effect::Deny,
                None,
                EngineAnswer::new(Effect::Deny, ReasonCode::of(ReasonCode::NO_ENGINE_BOUND)),
                false,
            ),
            Outcome::Failed { engine, cause, .. } => (
                Effect::Indeterminate,
                engine,
                EngineAnswer::new(Effect::Indeterminate, cause),
                false,
            ),
        };
        AuthorizationDecision {
            decision_id: DecisionId::generate(),
            effect,
            evaluated_at: now,
            engine,
            policy_version: answer.policy_version,
            reason: answer.reason,
            matched_policies: answer.matched_policies,
            metadata: DecisionMetadata {
                duration_microseconds: microseconds(start, now),
                cache_hit: false,
                asserted_trusted,
            },
        }
    }

    async fn record_alone(
        &self,
        tenant: &TenantContext,
        event: &AuthorizationEvent,
    ) -> Result<(), DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.record(uow.as_mut(), Caller::system(), event)?;
        uow.commit().await
    }

    fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        caller: Caller,
        event: &AuthorizationEvent,
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

/// The time from `from` to `to` in whole microseconds; zero if the clock
/// went back.
fn microseconds(from: Timestamp, to: Timestamp) -> u64 {
    u64::try_from((to - from).whole_microseconds()).unwrap_or(0)
}
