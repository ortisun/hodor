//! Conditions on attributes: an expression in Common Expression Language
//! that a role's permission may carry, and what it reads.
//!
//! See `docs/architecture/contexts/authorization.md`, "Conditions", and
//! Decision 0025.

use crate::domain::request::{Attributes, AuthorizationRequest};
use hodor_kernel::{DomainError, Timestamp};
use serde::Serialize;

/// The longest condition, in characters.
pub const MAX_CONDITION_LENGTH: usize = 1000;

/// The text of a condition, as a tenant wrote it. Whether it compiles is
/// checked by the condition language when a role is defined.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Condition(String);

impl Condition {
    /// Reads the text of a condition.
    ///
    /// # Errors
    ///
    /// Returns `authorization.condition_invalid` for an empty text, one
    /// longer than 1000 characters, or one holding a control character
    /// other than a line break or a tab.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let shaped = !value.trim().is_empty()
            && value.chars().count() <= MAX_CONDITION_LENGTH
            && !value
                .chars()
                .any(|character| character.is_control() && character != '\n' && character != '\t');
        if shaped {
            Ok(Self(value.to_owned()))
        } else {
            Err(invalid(
                "a condition has 1 to 1000 characters and no control character other than a \
                 line break or a tab",
            ))
        }
    }

    /// The text as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The refusal of a condition that cannot be used: the detail says why.
#[must_use]
pub fn invalid(detail: &str) -> DomainError {
    DomainError::invalid(
        "authorization.condition_invalid",
        "a condition must be a valid expression over subject, resource, action and context",
    )
    .with_detail(detail)
}

/// The refusal of a condition that would cost too much to run.
#[must_use]
pub fn too_costly(detail: &str) -> DomainError {
    DomainError::invalid(
        "authorization.condition_too_costly",
        "a condition has at most 256 nodes and comprehensions nested at most two deep",
    )
    .with_detail(detail)
}

/// The failure of a condition that ran: it never allows.
#[must_use]
pub fn failed(detail: &str) -> DomainError {
    DomainError::invalid(
        "authorization.condition_failed",
        "a condition could not be evaluated",
    )
    .with_detail(detail)
}

/// The subject, as a condition reads it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConditionSubject {
    /// `user` or `client`.
    pub kind: String,
    /// Its identifier.
    pub id: String,
    /// What Hodor resolved about it.
    pub attributes: Attributes,
    /// What the caller claims about it: empty unless the binding trusts it.
    pub asserted: Attributes,
}

/// The resource, as a condition reads it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConditionResource {
    /// Its kind.
    pub kind: String,
    /// Its identifier, if the request names one.
    pub id: Option<String>,
    /// Its attributes.
    pub attributes: Attributes,
}

/// The moment, as a condition reads it.
#[derive(Debug, Clone, PartialEq)]
pub struct ConditionContext {
    /// The attributes of the moment the request carries.
    pub attributes: Attributes,
    /// The application the request is made for, if any.
    pub application: Option<String>,
    /// When the decision is made, by Hodor's clock.
    pub time: Timestamp,
}

/// Everything a condition may read: the variables `subject`, `resource`,
/// `action` and `context`.
#[derive(Debug, Clone, PartialEq)]
pub struct ConditionInput {
    /// The variable `subject`.
    pub subject: ConditionSubject,
    /// The variable `resource`.
    pub resource: ConditionResource,
    /// The variable `action`.
    pub action: String,
    /// The variable `context`.
    pub context: ConditionContext,
}

impl ConditionInput {
    /// What a condition reads about `request`, with the subject's resolved
    /// attributes, at `now`. The request's asserted attributes are given as
    /// they are: the evaluation has already emptied them unless the binding
    /// trusts them.
    #[must_use]
    pub fn of(
        request: &AuthorizationRequest,
        subject_attributes: &Attributes,
        now: Timestamp,
    ) -> Self {
        Self {
            subject: ConditionSubject {
                kind: request.subject.kind().as_str().to_owned(),
                id: request.subject.id().to_owned(),
                attributes: subject_attributes.clone(),
                asserted: request.asserted.clone(),
            },
            resource: ConditionResource {
                kind: request.resource.kind().to_owned(),
                id: request.resource.id().map(str::to_owned),
                attributes: request.resource.attributes().clone(),
            },
            action: request.action.as_str().to_owned(),
            context: ConditionContext {
                attributes: request.context.attributes.clone(),
                application: request
                    .context
                    .application
                    .as_ref()
                    .map(|application| application.as_str().to_owned()),
                time: now,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_condition_is_bounded_printable_text() {
        assert_eq!(
            Condition::parse("subject.id == 'ana'\n  && action == 'read'")
                .expect("condition")
                .as_str(),
            "subject.id == 'ana'\n  && action == 'read'"
        );
        for bad in ["", "   ", "a\u{0}b", "a\rb"] {
            assert_eq!(
                Condition::parse(bad).map_err(|e| e.code().to_owned()),
                Err("authorization.condition_invalid".to_owned()),
                "{bad:?}"
            );
        }
        assert!(Condition::parse(&"x".repeat(MAX_CONDITION_LENGTH)).is_ok());
        assert!(Condition::parse(&"x".repeat(MAX_CONDITION_LENGTH + 1)).is_err());
    }
}
