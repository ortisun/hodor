//! The native engine: answers from native role-based access control, and
//! always answers Hodor's own administration from the built-in roles. It
//! needs nothing outside this context.
//!
//! See `docs/architecture/contexts/authorization.md`, "How the native
//! engine decides" and "Caching and the role revision".

use crate::application::engine::{
    AuthorizationEngine, EngineCapabilities, EvaluationInput, PolicySelection, PolicySimulator,
    SimulationAnswer,
};
use crate::application::ports::{
    CompiledCondition, ConditionLanguage, NativeRoleStore, RoleAssignmentStore,
};
use crate::domain::condition::{Condition, ConditionInput};
use crate::domain::decision::{
    EngineAnswer, EngineId, PolicyReference, PolicyRevision, ReasonCode,
};
use crate::domain::native::{Grant, PermissionName, RoleGraph, RoleKey, grant_applies, grants_of};
use crate::domain::request::{Attributes, Namespace, Subject, SubjectKind};
use crate::domain::role::Effect;
use hodor_kernel::{Clock, DomainError, TenantContext, TenantId, UnitOfWorkFactory};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The revision the built-in roles report: they change only with Hodor.
pub const FIXED_ROLES_REVISION: &str = "fixed_roles";

/// The reason of an allow from a role a tenant defined.
pub const MATCHING_ROLE: &str = "matching_role";

/// The reason of a deny when the permission is held only with conditions,
/// and none of them held.
pub const CONDITION_NOT_MET: &str = "condition_not_met";

/// The reason of an indeterminate answer when no condition held and at
/// least one failed.
pub const CONDITION_FAILED: &str = "condition_failed";

/// The most conditions run for one decision.
pub const MAX_CONDITIONS_PER_DECISION: usize = 32;

/// The longest one condition may run.
pub const MAX_CONDITION_TIME: Duration = Duration::from_millis(10);

/// How many principals the engine keeps what their assignments come to
/// for, before it forgets them all and starts again.
const CACHE_CAPACITY: usize = 10_000;

/// The most assigned roles one answer names.
const MAX_NAMED_ROLES: usize = 64;

/// A grant with its condition compiled. A condition that does not compile
/// any more, after an upgrade of the language, is kept as failing.
struct CompiledGrant {
    grant: Grant,
    condition: Option<Result<Arc<dyn CompiledCondition>, DomainError>>,
}

struct Cached {
    revision: u64,
    grants: Arc<Vec<CompiledGrant>>,
}

type Cache = BTreeMap<(TenantId, Subject), Cached>;

/// The engine registered as `native`.
#[derive(Clone)]
pub struct NativeEngine {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    assignments: Arc<dyn RoleAssignmentStore>,
    roles: Option<(Arc<dyn NativeRoleStore>, Arc<dyn Clock>)>,
    conditions: Option<Arc<dyn ConditionLanguage>>,
    cache: Arc<Mutex<Cache>>,
}

impl std::fmt::Debug for NativeEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeEngine")
            .field("tenant_roles", &self.roles.is_some())
            .field("conditions", &self.conditions.is_some())
            .finish_non_exhaustive()
    }
}

impl NativeEngine {
    /// The engine over the assignments of the built-in roles and over the
    /// tenant's own roles.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        assignments: Arc<dyn RoleAssignmentStore>,
        roles: Arc<dyn NativeRoleStore>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            units_of_work,
            assignments,
            roles: Some((roles, clock)),
            conditions: None,
            cache: Arc::default(),
        }
    }

    /// The same engine, running conditions in `language`. Without it, a
    /// permission held only with a condition makes the decision
    /// indeterminate.
    #[must_use]
    pub fn with_condition_language(mut self, language: Arc<dyn ConditionLanguage>) -> Self {
        self.conditions = Some(language);
        self
    }

    /// The engine that answers only Hodor's administration, from the
    /// built-in roles.
    #[must_use]
    pub fn administration(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        assignments: Arc<dyn RoleAssignmentStore>,
    ) -> Self {
        Self {
            units_of_work,
            assignments,
            roles: None,
            conditions: None,
            cache: Arc::default(),
        }
    }

    async fn administration_answer(
        &self,
        tenant: &TenantContext,
        input: &EvaluationInput,
    ) -> Result<EngineAnswer, DomainError> {
        let request = &input.request;
        let roles = match request.subject.user_id() {
            Some(user_id) => {
                let mut uow = self.units_of_work.begin(tenant).await?;
                self.assignments.roles_of(uow.as_mut(), user_id).await?
            }
            None => Vec::new(),
        };
        let permission = PermissionName::of(request.resource.kind(), &request.action);
        let graph = RoleGraph::built_in();
        let wanted = (Namespace::administration(), permission);
        // The first role, in the fixed order, that holds the permission.
        let allowing = roles.iter().find(|role| {
            graph
                .permissions_held(&RoleKey::built_in(**role))
                .contains(&wanted)
        });
        let revision = Some(PolicyRevision::parse(FIXED_ROLES_REVISION)?);
        Ok(match allowing {
            Some(role) => EngineAnswer {
                effect: Effect::Allow,
                reason: ReasonCode::parse(role.as_str())?,
                policy_version: revision,
                matched_policies: vec![PolicyReference::parse(role.as_str())?],
            },
            None => EngineAnswer {
                effect: Effect::Deny,
                reason: ReasonCode::of(ReasonCode::NO_MATCHING_ROLE),
                policy_version: revision,
                matched_policies: Vec::new(),
            },
        })
    }

    async fn tenant_answer(
        &self,
        tenant: &TenantContext,
        input: &EvaluationInput,
    ) -> Result<EngineAnswer, DomainError> {
        let Some((store, clock)) = &self.roles else {
            return Err(DomainError::internal(
                "authorization.native_roles_unavailable",
                "the operation could not be completed",
            )
            .with_detail("this native engine answers only Hodor's administration"));
        };
        let started = Instant::now();
        let request = &input.request;
        let mut uow = self.units_of_work.begin(tenant).await?;
        let revision = store.revision(uow.as_mut()).await?;
        // The subject, and for a user every group Hodor resolved for them:
        // each is a principal whose assignments count.
        let mut principals = vec![request.subject.clone()];
        if request.subject.kind() == SubjectKind::User {
            principals.extend(
                listed(&input.subject_attributes, "groups")
                    .into_iter()
                    .filter_map(|group| Subject::new(SubjectKind::Group, &group).ok()),
            );
        }
        let mut grants: Vec<Arc<Vec<CompiledGrant>>> = Vec::with_capacity(principals.len());
        let mut graph: Option<RoleGraph> = None;
        for principal in principals {
            let key = (tenant.tenant_id(), principal.clone());
            let kept = self
                .cache()
                .get(&key)
                .filter(|cached| cached.revision == revision)
                .map(|cached| Arc::clone(&cached.grants));
            if let Some(kept) = kept {
                grants.push(kept);
                continue;
            }
            let assignments = store.assignments_of(uow.as_mut(), &principal).await?;
            if graph.is_none() {
                graph = Some(RoleGraph::new(store.roles(uow.as_mut()).await?));
            }
            let roles = graph
                .as_ref()
                .map_or_else(Vec::new, |graph| grants_of(&assignments, graph));
            let compiled = Arc::new(self.compiled(roles));
            let mut cache = self.cache();
            if cache.len() >= CACHE_CAPACITY {
                cache.clear();
            }
            cache.insert(
                key,
                Cached {
                    revision,
                    grants: Arc::clone(&compiled),
                },
            );
            grants.push(compiled);
        }
        // The organization of the request counts only for a member of it.
        let organization = request
            .context
            .organization
            .as_ref()
            .filter(|organization| {
                listed(&input.subject_attributes, "organizations")
                    .iter()
                    .any(|member_of| member_of == organization.as_str())
            });
        let now = clock.now();
        let permission = PermissionName::of(request.resource.kind(), &request.action);
        let applying: Vec<&CompiledGrant> = grants
            .iter()
            .flat_map(|of_principal| of_principal.iter())
            .filter(|compiled| {
                grant_applies(
                    &compiled.grant,
                    &request.namespace,
                    &permission,
                    request.context.application.as_ref(),
                    organization,
                    now,
                )
            })
            .collect();
        let policy_version = Some(PolicyRevision::parse(&revision.to_string())?);
        if applying.is_empty() {
            return Ok(denied(ReasonCode::NO_MATCHING_ROLE, policy_version));
        }
        let unconditional: BTreeSet<&RoleKey> = applying
            .iter()
            .filter(|compiled| compiled.condition.is_none())
            .map(|compiled| compiled.grant.assignment.role())
            .collect();
        if !unconditional.is_empty() {
            return allowed(unconditional, policy_version);
        }
        // Only conditions are left: run each different one of each role
        // once, at most MAX_CONDITIONS_PER_DECISION; needing more is a
        // failure.
        let condition_input = ConditionInput::of(request, &input.subject_attributes, now);
        let mut outcomes: BTreeMap<(&RoleKey, &Condition), bool> = BTreeMap::new();
        let mut failed = false;
        let mut holding: BTreeSet<&RoleKey> = BTreeSet::new();
        for compiled in &applying {
            let (Some(condition), Some(text)) = (&compiled.condition, &compiled.grant.condition)
            else {
                continue;
            };
            let role = compiled.grant.assignment.role();
            let held = if let Some(held) = outcomes.get(&(role, text)) {
                *held
            } else {
                if outcomes.len() >= MAX_CONDITIONS_PER_DECISION {
                    failed = true;
                    break;
                }
                let left = input.time_limit.saturating_sub(started.elapsed());
                let held = match condition {
                    Ok(condition) => {
                        match condition.holds(&condition_input, left.min(MAX_CONDITION_TIME)) {
                            Ok(held) => held,
                            Err(_) => {
                                failed = true;
                                false
                            }
                        }
                    }
                    Err(_) => {
                        failed = true;
                        false
                    }
                };
                outcomes.insert((role, text), held);
                held
            };
            if held {
                holding.insert(role);
            }
        }
        if !holding.is_empty() {
            return allowed(holding, policy_version);
        }
        if failed {
            return Ok(EngineAnswer {
                effect: Effect::Indeterminate,
                reason: ReasonCode::of(CONDITION_FAILED),
                policy_version,
                matched_policies: Vec::new(),
            });
        }
        Ok(denied(CONDITION_NOT_MET, policy_version))
    }

    /// Compiles the condition of every grant that has one, once per
    /// different condition.
    fn compiled(&self, grants: Vec<Grant>) -> Vec<CompiledGrant> {
        let mut compiled: BTreeMap<Condition, Result<Arc<dyn CompiledCondition>, DomainError>> =
            BTreeMap::new();
        grants
            .into_iter()
            .map(|grant| {
                let condition = grant.condition.as_ref().map(|text| {
                    compiled
                        .entry(text.clone())
                        .or_insert_with(|| match &self.conditions {
                            Some(language) => language.compile(text),
                            None => Err(DomainError::internal(
                                "authorization.conditions_unavailable",
                                "the operation could not be completed",
                            )),
                        })
                        .clone()
                });
                CompiledGrant { grant, condition }
            })
            .collect()
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn denied(reason: &'static str, policy_version: Option<PolicyRevision>) -> EngineAnswer {
    EngineAnswer {
        effect: Effect::Deny,
        reason: ReasonCode::of(reason),
        policy_version,
        matched_policies: Vec::new(),
    }
}

fn allowed(
    roles: BTreeSet<&RoleKey>,
    policy_version: Option<PolicyRevision>,
) -> Result<EngineAnswer, DomainError> {
    let matched_policies = roles
        .into_iter()
        .take(MAX_NAMED_ROLES)
        .map(|role| PolicyReference::parse(&role.reference()))
        .collect::<Result<_, _>>()?;
    Ok(EngineAnswer {
        effect: Effect::Allow,
        reason: ReasonCode::of(MATCHING_ROLE),
        policy_version,
        matched_policies,
    })
}

#[async_trait::async_trait]
impl AuthorizationEngine for NativeEngine {
    fn id(&self) -> EngineId {
        EngineId::native()
    }

    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            simulation: true,
            explanation: true,
        }
    }

    async fn evaluate(
        &self,
        tenant: &TenantContext,
        input: &EvaluationInput,
    ) -> Result<EngineAnswer, DomainError> {
        if input.request.namespace.is_administration() {
            self.administration_answer(tenant, input).await
        } else {
            self.tenant_answer(tenant, input).await
        }
    }
}

/// The native engine simulates against what is published only: its roles
/// have no drafts and no revisions to choose. The simulated answer is the
/// one a real decision would give, with the steps in words.
#[async_trait::async_trait]
impl PolicySimulator for NativeEngine {
    async fn simulate(
        &self,
        tenant: &TenantContext,
        input: &EvaluationInput,
        against: &PolicySelection,
    ) -> Result<SimulationAnswer, DomainError> {
        if *against != PolicySelection::Published {
            return Err(DomainError::invalid(
                "authorization.simulation_unsupported",
                "the native engine simulates against what is published only",
            ));
        }
        let answer = self.evaluate(tenant, input).await?;
        Ok(SimulationAnswer {
            trace: simulation_trace(input, &answer),
            answer,
        })
    }
}

/// How a native decision was reached, in words.
fn simulation_trace(input: &EvaluationInput, answer: &EngineAnswer) -> Vec<String> {
    let request = &input.request;
    let mut trace = vec![format!(
        "asked whether {} {} may {} a {}",
        request.subject.kind().as_str(),
        request.subject.id(),
        request.action.as_str(),
        request.resource.kind()
    )];
    if answer.matched_policies.is_empty() {
        trace.push("no role of the subject decided".to_owned());
    }
    for policy in &answer.matched_policies {
        trace.push(format!("the role {} decided", policy.as_str()));
    }
    trace.push(format!(
        "the answer is {} for the reason {}",
        match answer.effect {
            Effect::Allow => "allow",
            Effect::Deny => "deny",
            Effect::Indeterminate => "indeterminate",
        },
        answer.reason.as_str()
    ));
    trace
}

/// The strings of a list attribute Hodor resolved, such as a user's
/// `groups`; nothing when it is absent or not a list of strings.
fn listed(attributes: &Attributes, name: &str) -> Vec<String> {
    attributes
        .get(name)
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}
