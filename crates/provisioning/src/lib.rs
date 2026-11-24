//! The provisioning context.
//!
//! Makes Hodor a SCIM 2.0 server: other systems create, read, replace
//! and list a tenant's users and groups through it. It owns no users and
//! no groups; it maps SCIM's resources to the identity context's, reads
//! the filters SCIM clients send, and keeps what SCIM carries that the
//! identity context has no place for.
//!
//! The specification is `docs/architecture/contexts/provisioning.md`;
//! this crate follows it.

mod application;
mod domain;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// What other crates may use from this context.
pub mod api {
    pub use crate::application::ports::{
        AccessRevoker, Deprovisioning, DeprovisioningPolicy, ProvisionedGroupRepository,
        ProvisionedUserRepository,
    };
    pub use crate::application::service::{Listed, ProvisioningPorts, ProvisioningService};
    pub use crate::domain::attribute::{
        Attribute, AttributeType, ENTERPRISE_USER_SCHEMA, GROUP_SCHEMA, GroupAttribute,
        USER_SCHEMA, UserAttribute, fold_case,
    };
    pub use crate::domain::bulk::{
        BULK_REQUEST_SCHEMA, BULK_RESPONSE_SCHEMA, BulkMethod, BulkOperation, BulkRequest,
        MAX_BULK_BYTES, MAX_BULK_ID_CHARACTERS, MAX_BULK_OPERATIONS, check_bulk_id, method_of,
        read_bulk, resolve_data, resolve_path,
    };
    pub use crate::domain::error::{
        INVALID_FILTER, INVALID_PATH, INVALID_SYNTAX, INVALID_VALUE, MUTABILITY, NO_TARGET,
        TOO_MANY, VERSION_MISMATCH,
    };
    pub use crate::domain::evaluate::{Fact, Facts, matches, sort_order};
    pub use crate::domain::event::ProvisioningEvent;
    pub use crate::domain::filter::{
        ElementFilter, Filter, FilterRefusal, MAX_FILTER_CHARACTERS, MAX_FILTER_COMPARISONS,
        MAX_FILTER_DEPTH, Operator, Value, ValueFilter, parse, parse_element_filter,
    };
    pub use crate::domain::patch::{
        MAX_PATCH_OPERATIONS, MAX_PATH_CHARACTERS, PATCH_SCHEMA, PatchOp, PatchOperation,
        PatchPath, PatchRequest, Shape, apply_patch, read_patch, read_path,
    };
    pub use crate::domain::query::{
        DEFAULT_COUNT, Found, ListParameters, ListQuery, MAX_COUNT, SortOrder,
    };
    pub use crate::domain::replace::{Replaced, replace_user};
    pub use crate::domain::resource::{
        DEPROVISIONED, GROUP_SHAPE, GroupFacts, GroupRequest, GroupResource, GroupSupplement,
        MAX_KEPT_CHARACTERS, MAX_MEMBERS_PER_REQUEST, MemberKind, MemberReference, MemberView,
        StoredGroupSupplement, StoredUserSupplement, USER_SHAPE, UserFacts, UserRequest,
        UserResource, UserSupplement, group_last_modified, read_group, read_group_bounded,
        read_user, shown, user_last_modified, user_name_of,
    };
    pub use crate::domain::schema::{
        ERROR_SCHEMA, LIST_RESPONSE_SCHEMA, list_response, resource_type, resource_types,
        schema_named, schemas, service_provider_config,
    };
    pub use crate::domain::version::{Precondition, version_of};
}
