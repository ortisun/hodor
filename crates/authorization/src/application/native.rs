//! The native engine: answers from native role-based access control, and
//! always answers Hodor's own administration from the built-in roles. It
//! needs nothing outside this context.
//!
//! See `docs/architecture/contexts/authorization.md`, "How the native
//! engine decides" and "Caching and the role revision".

use crate::application::engine::{AuthorizationEngine, EngineCapabilities, EvaluationInput};
use crate::application::ports::{NativeRoleStore, RoleAssignmentStore};
use crate::domain::decision::{
    EngineAnswer, EngineId, PolicyReference, PolicyRevision, ReasonCode,
};
use crate::domain::native::{Grant, PermissionName, RoleGraph, RoleKey, allowing_roles, grants_of};
use crate::domain::request::{Namespace, Subject};
use crate::domain::role::Effect;
use hodor_kernel::{Clock, DomainError, TenantContext, TenantId, UnitOfWorkFactory};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// The revision the built-in roles report: they change only with Hodor.
pub const FIXED_ROLES_REVISION: &str = "fixed_roles";

/// The reason of an allow from a role a tenant defined.
pub const MATCHING_ROLE: &str = "matching_role";

/// How many principals the engine keeps what their assignments come to
/// for, before it forgets them all and starts again.
const CACHE_CAPACITY: usize = 10_000;

/// The most assigned roles one answer names.
const MAX_NAMED_ROLES: usize = 64;

struct Cached {
    revision: u64,
    grants: Arc<Vec<Grant>>,
}

type Cache = BTreeMap<(TenantId, Subject), Cached>;

/// The engine registered as `native`.
#[derive(Clone)]
pub struct NativeEngine {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    assignments: Arc<dyn RoleAssignmentStore>,
    roles: Option<(Arc<dyn NativeRoleStore>, Arc<dyn Clock>)>,
    cache: Arc<Mutex<Cache>>,
}

impl std::fmt::Debug for NativeEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeEngine")
            .field("tenant_roles", &self.roles.is_some())
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
            cache: Arc::default(),
        }
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
        let request = &input.request;
        let mut uow = self.units_of_work.begin(tenant).await?;
        let revision = store.revision(uow.as_mut()).await?;
        let key = (tenant.tenant_id(), request.subject.clone());
        let kept = self
            .cache()
            .get(&key)
            .filter(|cached| cached.revision == revision)
            .map(|cached| Arc::clone(&cached.grants));
        let grants = if let Some(grants) = kept {
            grants
        } else {
            let assignments = store.assignments_of(uow.as_mut(), &request.subject).await?;
            let graph = RoleGraph::new(store.roles(uow.as_mut()).await?);
            let grants = Arc::new(grants_of(&assignments, &graph));
            let mut cache = self.cache();
            if cache.len() >= CACHE_CAPACITY {
                cache.clear();
            }
            cache.insert(
                key,
                Cached {
                    revision,
                    grants: Arc::clone(&grants),
                },
            );
            grants
        };
        let permission = PermissionName::of(request.resource.kind(), &request.action);
        let allowing = allowing_roles(
            &grants,
            &request.namespace,
            &permission,
            request.context.application.as_ref(),
            clock.now(),
        );
        let policy_version = Some(PolicyRevision::parse(&revision.to_string())?);
        if allowing.is_empty() {
            return Ok(EngineAnswer {
                effect: Effect::Deny,
                reason: ReasonCode::of(ReasonCode::NO_MATCHING_ROLE),
                policy_version,
                matched_policies: Vec::new(),
            });
        }
        let matched_policies = allowing
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

    fn cache(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait::async_trait]
impl AuthorizationEngine for NativeEngine {
    fn id(&self) -> EngineId {
        EngineId::native()
    }

    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            simulation: false,
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
