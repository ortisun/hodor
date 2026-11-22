//! The answer to a request: what an engine says, and the decision Hodor
//! makes of it.
//!
//! See `docs/architecture/contexts/authorization.md`, "The answer".

use crate::domain::role::Effect;
use hodor_kernel::{DomainError, Timestamp};
use serde::Serialize;

hodor_kernel::define_id!(
    /// Identifies one decision.
    DecisionId
);

/// The longest reason code or engine name.
const MAX_CODE_LENGTH: usize = 64;
/// The longest policy revision or policy reference.
const MAX_REFERENCE_LENGTH: usize = 255;
/// The most policies an answer may name.
const MAX_MATCHED_POLICIES: usize = 64;

/// Whether `value` is a code: a lower-case letter, then lower-case letters,
/// digits and `_`, at most 64 characters.
fn is_code(value: &str, also: &[char]) -> bool {
    let mut characters = value.chars();
    value.len() <= MAX_CODE_LENGTH
        && characters
            .next()
            .is_some_and(|first| first.is_ascii_lowercase())
        && characters.all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || character == '_'
                || also.contains(&character)
        })
}

/// Whether `value` is printable text of 1 to 255 characters.
fn is_reference(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_REFERENCE_LENGTH && !value.chars().any(char::is_control)
}

/// Why a decision is what it is: a stable code, safe to show to the caller.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ReasonCode(String);

impl ReasonCode {
    /// The resource server has no binding.
    pub const NO_ENGINE_BOUND: &'static str = "no_engine_bound";
    /// The binding could not be read.
    pub const BINDING_UNAVAILABLE: &'static str = "binding_unavailable";
    /// The binding names an engine this binary does not have.
    pub const ENGINE_UNAVAILABLE: &'static str = "engine_unavailable";
    /// The subject's attributes could not be resolved.
    pub const SUBJECT_UNAVAILABLE: &'static str = "subject_unavailable";
    /// The engine returned an error or a batch of the wrong length.
    pub const ENGINE_FAILED: &'static str = "engine_failed";
    /// The engine answered after the time limit.
    pub const ENGINE_TIMED_OUT: &'static str = "engine_timed_out";
    /// A failure allowed, because the binding lets the action fail open.
    pub const FAIL_OPEN: &'static str = "fail_open";
    /// No role of the subject holds the permission.
    pub const NO_MATCHING_ROLE: &'static str = "no_matching_role";

    /// Reads a reason code.
    ///
    /// # Errors
    ///
    /// Returns `authorization.reason_invalid` unless the value is a
    /// lower-case letter followed by lower-case letters, digits and `_`, at
    /// most 64 characters.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        if is_code(value, &[]) {
            Ok(Self(value.to_owned()))
        } else {
            Err(DomainError::invalid(
                "authorization.reason_invalid",
                "a reason is lower-case letters, digits and `_`, starting with a letter, at most \
                 64 characters",
            ))
        }
    }

    /// One of the reasons Hodor itself gives.
    pub(crate) fn of(value: &'static str) -> Self {
        debug_assert!(is_code(value, &[]), "{value}");
        Self(value.to_owned())
    }

    /// The reason as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The name of an engine, such as `native`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct EngineId(String);

impl EngineId {
    /// The name of the engine inside Hodor.
    pub const NATIVE: &'static str = "native";

    /// The engine inside Hodor.
    #[must_use]
    pub fn native() -> Self {
        Self(Self::NATIVE.to_owned())
    }

    /// Reads an engine name.
    ///
    /// # Errors
    ///
    /// Returns `authorization.engine_name_invalid` unless the value is a
    /// lower-case letter followed by lower-case letters, digits, `_` and
    /// `-`, at most 64 characters.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        if is_code(value, &['-']) {
            Ok(Self(value.to_owned()))
        } else {
            Err(DomainError::invalid(
                "authorization.engine_name_invalid",
                "an engine's name is lower-case letters, digits, `_` and `-`, starting with a \
                 letter, at most 64 characters",
            ))
        }
    }

    /// The name as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The revision of the policies an engine decided with.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct PolicyRevision(String);

impl PolicyRevision {
    /// Reads a revision.
    ///
    /// # Errors
    ///
    /// Returns `authorization.revision_invalid` if the value is empty,
    /// longer than 255 characters or holds a control character.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        if is_reference(value) {
            Ok(Self(value.to_owned()))
        } else {
            Err(DomainError::invalid(
                "authorization.revision_invalid",
                "a revision has 1 to 255 characters and no control character",
            ))
        }
    }

    /// The revision as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Names one policy that decided, or a draft to simulate against.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct PolicyReference(String);

impl PolicyReference {
    /// Reads a policy reference.
    ///
    /// # Errors
    ///
    /// Returns `authorization.policy_reference_invalid` if the value is
    /// empty, longer than 255 characters or holds a control character.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        if is_reference(value) {
            Ok(Self(value.to_owned()))
        } else {
            Err(DomainError::invalid(
                "authorization.policy_reference_invalid",
                "a policy reference has 1 to 255 characters and no control character",
            ))
        }
    }

    /// The reference as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An engine's part of a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineAnswer {
    /// Allow, deny, or indeterminate when the engine could not decide.
    pub effect: Effect,
    /// Why.
    pub reason: ReasonCode,
    /// The revision of the policies it used, if it has revisions.
    pub policy_version: Option<PolicyRevision>,
    /// The policies that decided, at most 64.
    pub matched_policies: Vec<PolicyReference>,
}

impl EngineAnswer {
    /// An answer with no revision and no policies named.
    #[must_use]
    pub const fn new(effect: Effect, reason: ReasonCode) -> Self {
        Self {
            effect,
            reason,
            policy_version: None,
            matched_policies: Vec::new(),
        }
    }

    /// Whether an engine could have given this answer: it names at most 64
    /// policies.
    pub(crate) fn is_well_formed(&self) -> bool {
        self.matched_policies.len() <= MAX_MATCHED_POLICIES
    }
}

/// How a decision was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DecisionMetadata {
    /// How long the evaluation took, in microseconds, by Hodor's clock.
    pub duration_microseconds: u64,
    /// Whether the answer came from a cache.
    pub cache_hit: bool,
    /// Whether the engine received the caller's asserted attributes.
    pub asserted_trusted: bool,
}

/// The decision on one request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorizationDecision {
    /// A new identifier for every decision.
    pub decision_id: DecisionId,
    /// Allow, deny or indeterminate. Only allow permits.
    pub effect: Effect,
    /// When it was made.
    pub evaluated_at: Timestamp,
    /// The engine that answered; absent when none was reached.
    pub engine: Option<EngineId>,
    /// The revision of the policies used, when the engine has one.
    pub policy_version: Option<PolicyRevision>,
    /// Why, as a stable code.
    pub reason: ReasonCode,
    /// The policies that decided. Shown only to callers allowed to see
    /// explanations.
    pub matched_policies: Vec<PolicyReference>,
    /// How it was made.
    pub metadata: DecisionMetadata,
}

impl AuthorizationDecision {
    /// Whether the decision lets the action be done. Only allow does:
    /// deny and indeterminate both refuse.
    #[must_use]
    pub fn permits(&self) -> bool {
        self.effect == Effect::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_lower_case() {
        for good in ["no_matching_role", "a", "deny_2"] {
            assert!(ReasonCode::parse(good).is_ok(), "{good}");
        }
        for bad in ["", "No", "with space", "with-dash", "1st", &"a".repeat(65)] {
            assert!(ReasonCode::parse(bad).is_err(), "{bad}");
        }
        assert!(EngineId::parse("open_policy_agent").is_ok());
        assert!(EngineId::parse("open-policy-agent").is_ok());
        assert!(EngineId::parse("Open").is_err());
        assert_eq!(EngineId::native().as_str(), "native");
    }

    #[test]
    fn hodor_reasons_are_codes() {
        for reason in [
            ReasonCode::NO_ENGINE_BOUND,
            ReasonCode::BINDING_UNAVAILABLE,
            ReasonCode::ENGINE_UNAVAILABLE,
            ReasonCode::SUBJECT_UNAVAILABLE,
            ReasonCode::ENGINE_FAILED,
            ReasonCode::ENGINE_TIMED_OUT,
            ReasonCode::FAIL_OPEN,
            ReasonCode::NO_MATCHING_ROLE,
        ] {
            assert_eq!(ReasonCode::parse(reason).ok(), Some(ReasonCode::of(reason)));
        }
    }

    #[test]
    fn references_are_printable() {
        assert!(PolicyRevision::parse("bundle-2026-11-22.3").is_ok());
        assert!(PolicyReference::parse("documents/owner can read").is_ok());
        for bad in ["", "a\u{0}", &"a".repeat(256)] {
            assert!(PolicyRevision::parse(bad).is_err());
            assert!(PolicyReference::parse(bad).is_err());
        }
    }

    #[test]
    fn only_allow_permits() {
        let decision = |effect| AuthorizationDecision {
            decision_id: DecisionId::generate(),
            effect,
            evaluated_at: Timestamp::UNIX_EPOCH,
            engine: None,
            policy_version: None,
            reason: ReasonCode::of(ReasonCode::NO_ENGINE_BOUND),
            matched_policies: Vec::new(),
            metadata: DecisionMetadata {
                duration_microseconds: 0,
                cache_hit: false,
                asserted_trusted: false,
            },
        };
        assert!(decision(Effect::Allow).permits());
        assert!(!decision(Effect::Deny).permits());
        assert!(!decision(Effect::Indeterminate).permits());
    }
}
