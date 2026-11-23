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
    pub use crate::application::engine::{
        AuthorizationEngine, EngineCapabilities, EngineRegistry, EvaluationInput, PolicySelection,
        PolicySimulator, SimulationAnswer,
    };
    pub use crate::application::evaluation::{EvaluationService, MAX_BATCH, Simulation};
    pub use crate::application::native::{FIXED_ROLES_REVISION, MATCHING_ROLE, NativeEngine};
    pub use crate::application::ports::{
        EngineBindingStore, NativeRoleStore, RoleAssignmentStore, SubjectAttributeSource,
    };
    pub use crate::application::roles::{RoleService, Validity};
    pub use crate::application::service::AuthorizationService;
    pub use crate::domain::binding::{BindingSettings, DEFAULT_TIME_LIMIT, EngineBinding};
    pub use crate::domain::decision::{
        AuthorizationDecision, DecisionId, DecisionMetadata, EngineAnswer, EngineId,
        PolicyReference, PolicyRevision, ReasonCode,
    };
    pub use crate::domain::event::AuthorizationEvent;
    pub use crate::domain::native::{
        AssignmentScope, Grant, MAX_DESCRIPTION_LENGTH, MAX_INCLUDED_ROLES, MAX_INCLUSION_DEPTH,
        MAX_ROLE_PERMISSIONS, PermissionDefinition, PermissionName, RoleAssignment, RoleContents,
        RoleDefinition, RoleGraph, RoleKey, RoleName,
    };
    pub use crate::domain::request::{
        Action, ApplicationReference, Attributes, AuthorizationRequest, EvaluationContext,
        Namespace, Resource, Subject, SubjectKind,
    };
    pub use crate::domain::role::{Decision, Effect, Permission, Role};
}
