//! The engine that answers for Hodor's own administration, from the fixed
//! roles. It needs nothing outside this context.

use crate::application::engine::{AuthorizationEngine, EngineCapabilities, EvaluationInput};
use crate::application::ports::RoleAssignmentStore;
use crate::domain::decision::{
    EngineAnswer, EngineId, PolicyReference, PolicyRevision, ReasonCode,
};
use crate::domain::role::{Decision, Effect, Permission, Role};
use hodor_kernel::{DomainError, TenantContext, UnitOfWorkFactory};
use std::sync::Arc;

/// The revision the fixed roles report: they change only with Hodor.
pub const FIXED_ROLES_REVISION: &str = "fixed_roles";

/// Answers `hodor:admin` from the fixed roles, as the administration
/// interface's check does: the permission is the resource kind and the
/// action, `users:read`. A subject that is not a user holds no role.
#[derive(Clone)]
pub struct FixedRoleEngine {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    assignments: Arc<dyn RoleAssignmentStore>,
}

impl std::fmt::Debug for FixedRoleEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FixedRoleEngine").finish_non_exhaustive()
    }
}

impl FixedRoleEngine {
    /// The engine over the role assignments.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        assignments: Arc<dyn RoleAssignmentStore>,
    ) -> Self {
        Self {
            units_of_work,
            assignments,
        }
    }

    async fn roles(
        &self,
        tenant: &TenantContext,
        input: &EvaluationInput,
    ) -> Result<Vec<Role>, DomainError> {
        let Some(user_id) = input.request.subject.user_id() else {
            return Ok(Vec::new());
        };
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.assignments.roles_of(uow.as_mut(), user_id).await
    }
}

#[async_trait::async_trait]
impl AuthorizationEngine for FixedRoleEngine {
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
        let request = &input.request;
        let name = format!("{}:{}", request.resource.kind(), request.action.as_str());
        let roles = self.roles(tenant, input).await?;
        let decision = Permission::from_name(&name).map_or(
            Decision {
                effect: Effect::Deny,
                reason: ReasonCode::NO_MATCHING_ROLE,
            },
            |permission| Decision::for_roles(&roles, permission),
        );
        let matched_policies = if decision.is_allowed() {
            vec![PolicyReference::parse(decision.reason)?]
        } else {
            Vec::new()
        };
        Ok(EngineAnswer {
            effect: decision.effect,
            reason: ReasonCode::parse(decision.reason)?,
            policy_version: Some(PolicyRevision::parse(FIXED_ROLES_REVISION)?),
            matched_policies,
        })
    }
}
