//! What the authorization endpoint answers with, and where: the response
//! type a request asks for, and the response mode that carries the answer
//! to the client (OAuth 2.0 Multiple Response Type Encoding Practices, and
//! OAuth 2.0 Form Post Response Mode).
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Response modes",
//! and Decision 0046.

use serde::{Deserialize, Serialize};

/// What the authorization endpoint answers a request with.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseType {
    /// An authorization code.
    #[default]
    #[serde(rename = "code")]
    Code,
}

impl ResponseType {
    /// Every type Hodor answers, as discovery lists them.
    pub const ALL: [Self; 1] = [Self::Code];

    /// The name OAuth gives it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Code => "code",
        }
    }

    /// The type a request names, if Hodor answers it.
    #[must_use]
    pub fn read(value: &str) -> Option<Self> {
        match value {
            "code" => Some(Self::Code),
            _ => None,
        }
    }

    /// The mode its answer comes in unless the request names one.
    #[must_use]
    pub const fn default_mode(self) -> ResponseMode {
        match self {
            Self::Code => ResponseMode::Query,
        }
    }

    /// Whether its answer may come in `mode`. A code may come in any mode;
    /// a type that returns a token will never be answered in the query.
    #[must_use]
    pub const fn allows(self, mode: ResponseMode) -> bool {
        match (self, mode) {
            (Self::Code, ResponseMode::Query | ResponseMode::FormPost) => true,
        }
    }
}

/// Where the parameters of an answer go.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseMode {
    /// The query of the redirect address, by a redirect.
    #[default]
    #[serde(rename = "query")]
    Query,
    /// The body of a form that a page of Hodor's posts to the redirect
    /// address.
    #[serde(rename = "form_post")]
    FormPost,
}

impl ResponseMode {
    /// Every mode Hodor offers, as discovery lists them.
    pub const ALL: [Self; 2] = [Self::Query, Self::FormPost];

    /// The name OAuth gives it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::FormPost => "form_post",
        }
    }

    /// The mode a request names, if Hodor offers it.
    #[must_use]
    pub fn read(value: &str) -> Option<Self> {
        match value {
            "query" => Some(Self::Query),
            "form_post" => Some(Self::FormPost),
            _ => None,
        }
    }
}

/// The mode an error goes back in, given the `response_type` and the
/// `response_mode` a request names, as they were given: the mode it names
/// when Hodor offers it and the type allows it; else the default of the
/// type when the type can be read; else the query.
#[must_use]
pub fn error_mode(response_type: Option<&str>, response_mode: Option<&str>) -> ResponseMode {
    let kind = response_type.and_then(ResponseType::read);
    let asked = response_mode.and_then(ResponseMode::read);
    match (kind, asked) {
        (Some(kind), Some(asked)) if kind.allows(asked) => asked,
        (Some(kind), _) => kind.default_mode(),
        (None, Some(asked)) => asked,
        (None, None) => ResponseMode::Query,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_read_by_their_names_and_nothing_else() {
        assert_eq!(ResponseMode::read("query"), Some(ResponseMode::Query));
        assert_eq!(
            ResponseMode::read("form_post"),
            Some(ResponseMode::FormPost)
        );
        for other in [
            "",
            "fragment",
            "jwt",
            "query.jwt",
            "fragment.jwt",
            "form_post.jwt",
            "Query",
            "FORM_POST",
            "form-post",
            " form_post",
        ] {
            assert_eq!(ResponseMode::read(other), None, "{other:?}");
        }
        for mode in ResponseMode::ALL {
            assert_eq!(ResponseMode::read(mode.as_str()), Some(mode));
        }
    }

    #[test]
    fn a_code_comes_in_the_query_by_default_and_in_either_mode_when_asked() {
        assert_eq!(ResponseType::read("code"), Some(ResponseType::Code));
        assert_eq!(ResponseType::read("token"), None);
        assert_eq!(ResponseType::Code.default_mode(), ResponseMode::Query);
        for mode in ResponseMode::ALL {
            assert!(ResponseType::Code.allows(mode), "{mode:?}");
        }
    }

    #[test]
    fn an_error_comes_in_the_mode_the_answer_would_have_had() {
        let cases = [
            (Some("code"), Some("form_post"), ResponseMode::FormPost),
            (Some("code"), Some("query"), ResponseMode::Query),
            (Some("code"), None, ResponseMode::Query),
            // A mode Hodor does not offer: the default of the type.
            (Some("code"), Some("fragment"), ResponseMode::Query),
            (Some("code"), Some("form_post.jwt"), ResponseMode::Query),
            // A type that cannot be read: the mode, when it can be.
            (Some("token"), Some("form_post"), ResponseMode::FormPost),
            (None, Some("form_post"), ResponseMode::FormPost),
            (None, Some("jwt"), ResponseMode::Query),
            (None, None, ResponseMode::Query),
        ];
        for (kind, mode, expected) in cases {
            assert_eq!(error_mode(kind, mode), expected, "{kind:?} {mode:?}");
        }
    }

    #[test]
    fn a_kept_mode_reads_back_and_a_request_kept_before_modes_reads_as_the_query() {
        let written = serde_json::to_string(&ResponseMode::FormPost).expect("JSON");
        assert_eq!(written, r#""form_post""#);
        assert_eq!(
            serde_json::from_str::<ResponseMode>(&written).expect("read"),
            ResponseMode::FormPost
        );
        assert_eq!(ResponseMode::default(), ResponseMode::Query);
    }
}
