//! The identity context.
//!
//! Owns users: who exists inside a tenant, how they are found, and whether
//! they may act. It does not know how a user proves who they are.
//!
//! The specification is `docs/architecture/contexts/identity.md`; this
//! crate follows it.

mod application;
mod domain;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// What other crates may use from this context.
pub mod api {
    pub use crate::application::groups::GroupService;
    pub use crate::application::organizations::{InvitationFound, OrganizationService};
    pub use crate::application::ports::{GroupPolicy, GroupRepository, UserRepository};
    pub use crate::application::ports::{InvitationRepository, OrganizationRepository};
    pub use crate::application::ports::{WorkloadAccess, WorkloadRepository};
    pub use crate::application::service::{CreateUser, IdentityService};
    pub use crate::application::workloads::{
        ChangeWorkload, CreateWorkload, WORKLOAD_DELETED, WORKLOAD_DISABLED, WorkloadService,
    };
    pub use crate::domain::claims::{
        ClaimField, LONGEST_ADDRESS_PART, LONGEST_BIRTHDATE, LONGEST_FORMATTED_ADDRESS,
        LONGEST_GENDER, LONGEST_NAME, LONGEST_PAGE_ADDRESS, LONGEST_PHONE_NUMBER,
        LONGEST_POSTAL_CODE, LONGEST_STREET_ADDRESS, LONGEST_ZONEINFO, PostalAddress,
        StandardClaims,
    };
    pub use crate::domain::event::UserEvent;
    pub use crate::domain::group::{
        Group, GroupEvent, GroupMember, GroupName, GroupSnapshot, MAX_DESCRIPTION_CHARACTERS,
        MAX_NAME_CHARACTERS, check_nesting, depth, effective_groups,
    };
    pub use crate::domain::identifier::{
        IdentifierId, IdentifierKind, LoginIdentifier, NormalizedIdentifier,
    };
    pub use crate::domain::organization::{
        INVITATION_LIFETIME, Invitation, InvitationId, InvitationStatus, MAX_UNIT_LEVELS,
        Membership, Organization, OrganizationEvent, OrganizationName, OrganizationSnapshot, Tree,
        Unit, UnitChange, UnitId, UnitKind, check_placement,
    };
    pub use crate::domain::user::{Profile, User, UserKind, UserSnapshot, UserStatus};
    pub use crate::domain::workload::{
        MAX_WORKLOAD_OWNERS, Workload, WorkloadEvent, WorkloadStatus, checked_owners,
        workload_profile,
    };
}
