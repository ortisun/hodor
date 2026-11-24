//! The authorization context.
//!
//! Answers one question: may this subject do this? Hodor's administration
//! asks it through the built-in roles; applications ask it through the
//! engine bound to their resource server, such as the native engine over
//! the roles the tenant defined. Whoever asks obeys the answer.
//!
//! The specification of what is built is
//! `docs/architecture/contexts/authorization.md`; this crate follows it.

mod application;
mod domain;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// What other crates may use from this context.
pub mod api {
    pub use crate::application::decision_log::{Decided, DecisionLog};
    pub use crate::application::engine::{
        AuthorizationEngine, EngineCapabilities, EngineRegistry, EvaluationInput, PolicySelection,
        PolicySimulator, SimulationAnswer,
    };
    pub use crate::application::evaluation::{EvaluationService, MAX_BATCH, Simulation};
    pub use crate::application::native::{
        CONDITION_FAILED, CONDITION_NOT_MET, FIXED_ROLES_REVISION, MATCHING_ROLE,
        MAX_CONDITION_TIME, MAX_CONDITIONS_PER_DECISION, NativeEngine,
    };
    pub use crate::application::ports::{
        CompiledCondition, ConditionLanguage, DecisionLogStore, EngineBindingStore,
        NativeRoleStore, RoleAssignmentStore, SubjectAttributeSource,
    };
    pub use crate::application::roles::{RoleService, Validity};
    pub use crate::application::service::AuthorizationService;
    pub use crate::domain::binding::{BindingSettings, DEFAULT_TIME_LIMIT, EngineBinding};
    pub use crate::domain::condition::{
        Condition, ConditionContext, ConditionInput, ConditionResource, ConditionSubject,
        MAX_CONDITION_LENGTH, failed as condition_failed, invalid as condition_invalid,
        too_costly as condition_too_costly,
    };
    pub use crate::domain::decision::{
        AuthorizationDecision, DecisionId, DecisionMetadata, EngineAnswer, EngineId,
        PolicyReference, PolicyRevision, ReasonCode,
    };
    pub use crate::domain::decision_log::{
        DEFAULT_RETENTION_DAYS, DecisionFilter, DecisionLogMode, DecisionLogSettings,
        DecisionRecord, MAX_MASK_LENGTH, MAX_MASKS, MAX_RETENTION_DAYS, MIN_RETENTION_DAYS,
        MaskPath,
    };
    pub use crate::domain::event::AuthorizationEvent;
    pub use crate::domain::native::{
        AssignmentScope, Grant, Holding, MAX_DESCRIPTION_LENGTH, MAX_INCLUDED_ROLES,
        MAX_INCLUSION_DEPTH, MAX_ROLE_PERMISSIONS, PermissionDefinition, PermissionName,
        RoleAssignment, RoleContents, RoleDefinition, RoleGraph, RoleKey, RoleName,
    };
    pub use crate::domain::request::{
        Action, ApplicationReference, Attributes, AuthorizationRequest, EvaluationContext,
        Namespace, OrganizationReference, Resource, Subject, SubjectKind,
    };
    pub use crate::domain::role::{
        AUTHORIZATION_API_SCOPES, Decision, Effect, Permission, Role, check_key_scopes,
    };
}
