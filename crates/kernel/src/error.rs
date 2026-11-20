//! Error vocabulary shared by all contexts.

use std::borrow::Cow;

/// Broad class of a domain error. The HTTP layer maps it to a status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The target does not exist, or is not visible to the caller.
    NotFound,
    /// The operation conflicts with the current state.
    Conflict,
    /// The input violates a rule.
    Invalid,
    /// The caller is not allowed to do this.
    Forbidden,
    /// The caller is not authenticated.
    Unauthenticated,
    /// A limit was exceeded; retrying later may succeed.
    RateLimited,
    /// A dependency is unavailable; retrying later may succeed.
    Unavailable,
    /// A bug or an unexpected infrastructure failure.
    Internal,
}

/// An error raised by domain or application code.
///
/// `code` is a stable, machine-readable identifier (`user.identifier_taken`).
/// `message` is safe to show to the caller and never contains secrets or
/// details about other tenants.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {message}")]
pub struct DomainError {
    kind: ErrorKind,
    code: Cow<'static, str>,
    message: Cow<'static, str>,
    detail: Option<String>,
}

impl DomainError {
    /// Creates an error.
    #[must_use]
    pub fn new(
        kind: ErrorKind,
        code: impl Into<Cow<'static, str>>,
        message: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            kind,
            code: code.into(),
            message: message.into(),
            detail: None,
        }
    }

    /// Attaches diagnostic detail for operators, such as the text of an
    /// infrastructure error. It is logged, never returned to callers.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Shorthand for [`ErrorKind::NotFound`].
    #[must_use]
    pub fn not_found(
        code: impl Into<Cow<'static, str>>,
        message: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::new(ErrorKind::NotFound, code, message)
    }

    /// Shorthand for [`ErrorKind::Conflict`].
    #[must_use]
    pub fn conflict(
        code: impl Into<Cow<'static, str>>,
        message: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::new(ErrorKind::Conflict, code, message)
    }

    /// Shorthand for [`ErrorKind::Invalid`].
    #[must_use]
    pub fn invalid(
        code: impl Into<Cow<'static, str>>,
        message: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::new(ErrorKind::Invalid, code, message)
    }

    /// Shorthand for [`ErrorKind::Internal`].
    #[must_use]
    pub fn internal(
        code: impl Into<Cow<'static, str>>,
        message: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::new(ErrorKind::Internal, code, message)
    }

    /// The broad class of the error.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The stable machine-readable code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// The caller-safe message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Diagnostic detail for operators, if any. Not for callers.
    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_exposes_kind_code_and_message() {
        let error = DomainError::conflict("user.identifier_taken", "identifier already in use");
        assert_eq!(error.kind(), ErrorKind::Conflict);
        assert_eq!(error.code(), "user.identifier_taken");
        assert_eq!(error.message(), "identifier already in use");
        assert_eq!(
            error.to_string(),
            "user.identifier_taken: identifier already in use"
        );
    }

    #[test]
    fn detail_is_kept_out_of_the_displayed_text() {
        let error = DomainError::internal("database.error", "the operation could not be completed")
            .with_detail("connection reset by peer");
        assert_eq!(error.detail(), Some("connection reset by peer"));
        assert!(!error.to_string().contains("connection reset"));
    }

    #[test]
    fn owned_messages_are_accepted() {
        let error = DomainError::invalid("slug.invalid", format!("{} is too short", "ab"));
        assert_eq!(error.message(), "ab is too short");
    }
}
