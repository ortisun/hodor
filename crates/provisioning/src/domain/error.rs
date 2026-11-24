//! The refusals of the provisioning context, by the codes the HTTP layer
//! turns into the `scimType` of RFC 7644.
//!
//! Specified in `docs/architecture/contexts/provisioning.md`, "Errors".

use crate::domain::filter::FilterRefusal;
use hodor_kernel::DomainError;

/// The code of a refused filter: `invalidFilter`.
pub const INVALID_FILTER: &str = "provisioning.invalid_filter";
/// The code of a body that cannot be read: `invalidSyntax`.
pub const INVALID_SYNTAX: &str = "provisioning.invalid_syntax";
/// The code of a value that breaks a rule: `invalidValue`.
pub const INVALID_VALUE: &str = "provisioning.invalid_value";
/// The code of an attribute that cannot be written: `mutability`.
pub const MUTABILITY: &str = "provisioning.mutability";

/// A filter refused for `refusal`.
#[must_use]
pub(crate) fn invalid_filter(refusal: &FilterRefusal) -> DomainError {
    DomainError::invalid(INVALID_FILTER, refusal.to_string())
}

/// A body that is not what the resource's schema reads.
#[must_use]
pub(crate) fn invalid_syntax(detail: impl Into<String>) -> DomainError {
    DomainError::invalid(INVALID_SYNTAX, detail.into())
}

/// A value that breaks a rule.
#[must_use]
pub(crate) fn invalid_value(detail: impl Into<String>) -> DomainError {
    DomainError::invalid(INVALID_VALUE, detail.into())
}

/// No such user in the tenant, or one SCIM does not show.
#[must_use]
pub(crate) fn user_not_found() -> DomainError {
    DomainError::not_found("provisioning.user_not_found", "the user does not exist")
}

/// No such group in the tenant.
#[must_use]
pub(crate) fn group_not_found() -> DomainError {
    DomainError::not_found("provisioning.group_not_found", "the group does not exist")
}
