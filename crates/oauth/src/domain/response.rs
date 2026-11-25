//! What the authorization endpoint answers with, and where: the response
//! types a client registers and a request asks for, and the response modes
//! that carry the answer (OAuth 2.0 Multiple Response Type Encoding
//! Practices, and OAuth 2.0 Form Post Response Mode).
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Response types of
//! a client", "Response types and modes" and "Response modes", and
//! Decisions 0046 and 0072.

use crate::domain::client::GrantType;
use hodor_kernel::DomainError;
use serde::{Deserialize, Serialize};

/// What the authorization endpoint answers a request with.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ResponseType {
    /// An authorization code.
    #[default]
    #[serde(rename = "code")]
    Code,
    /// An ID token, and nothing to redeem.
    #[serde(rename = "id_token")]
    IdToken,
    /// A code and an ID token that names it.
    #[serde(rename = "code id_token")]
    CodeIdToken,
    /// Nothing but `state` and `iss`.
    #[serde(rename = "none")]
    None,
}

/// How a `response_type` reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadResponseType {
    /// A type Hodor offers.
    Offered(ResponseType),
    /// A type that returns an access token through the browser: known, and
    /// not offered (Issue-128). Its default mode is the fragment.
    ReturnsAccessToken,
    /// Anything else.
    Unknown,
}

impl ReadResponseType {
    /// The type, when it is one Hodor offers.
    #[must_use]
    pub const fn offered(self) -> Option<ResponseType> {
        match self {
            Self::Offered(kind) => Some(kind),
            Self::ReturnsAccessToken | Self::Unknown => None,
        }
    }
}

impl ResponseType {
    /// Every type, in the order a client's are kept and discovery lists
    /// them.
    pub const ALL: [Self; 4] = [Self::Code, Self::IdToken, Self::CodeIdToken, Self::None];

    /// The name OAuth gives it, which is also the stored name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Code => "code",
            Self::IdToken => "id_token",
            Self::CodeIdToken => "code id_token",
            Self::None => "none",
        }
    }

    /// Reads a `response_type` as a request or an administrator writes it:
    /// words separated by one space, in any order, each once.
    #[must_use]
    pub fn read(value: &str) -> ReadResponseType {
        let mut words: Vec<&str> = value.split(' ').collect();
        let count = words.len();
        words.sort_unstable();
        words.dedup();
        if words.len() != count || words.iter().any(|word| word.is_empty()) {
            return ReadResponseType::Unknown;
        }
        match words.as_slice() {
            ["code"] => ReadResponseType::Offered(Self::Code),
            ["id_token"] => ReadResponseType::Offered(Self::IdToken),
            ["code", "id_token"] => ReadResponseType::Offered(Self::CodeIdToken),
            ["none"] => ReadResponseType::Offered(Self::None),
            ["token"]
            | ["id_token", "token"]
            | ["code", "token"]
            | ["code", "id_token", "token"] => ReadResponseType::ReturnsAccessToken,
            _ => ReadResponseType::Unknown,
        }
    }

    /// Reads a response type a client is registered with.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_response_types_invalid` for anything but
    /// `code`, `id_token`, `code id_token` and `none`.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        match Self::read(value) {
            ReadResponseType::Offered(kind) => Ok(kind),
            ReadResponseType::ReturnsAccessToken => Err(response_types_invalid(
                "a response type that returns an access token is not offered",
            )),
            ReadResponseType::Unknown => Err(response_types_invalid(
                "the response type is not one Hodor knows",
            )),
        }
    }

    /// Whether it returns an authorization code.
    #[must_use]
    pub const fn returns_code(self) -> bool {
        matches!(self, Self::Code | Self::CodeIdToken)
    }

    /// Whether it returns an ID token through the browser.
    #[must_use]
    pub const fn returns_id_token(self) -> bool {
        matches!(self, Self::IdToken | Self::CodeIdToken)
    }

    /// Whether it makes a grant: every type that signs the person in to
    /// the client, that is every type but `none`.
    #[must_use]
    pub const fn makes_grant(self) -> bool {
        !matches!(self, Self::None)
    }

    /// The mode its answer comes in unless the request names one.
    #[must_use]
    pub const fn default_mode(self) -> ResponseMode {
        if self.returns_id_token() {
            ResponseMode::Fragment
        } else {
            ResponseMode::Query
        }
    }

    /// Whether its answer may come in `mode`: a token never goes into a
    /// query, and every type may come in the fragment or as a form.
    #[must_use]
    pub const fn allows(self, mode: ResponseMode) -> bool {
        !(self.returns_id_token() && matches!(mode, ResponseMode::Query))
    }
}

pub(crate) fn response_types_invalid(reason: &'static str) -> DomainError {
    DomainError::invalid(
        "oauth.client_response_types_invalid",
        "a client with `authorization_code` has at least one response type, of `code`, \
         `id_token`, `code id_token` and `none`, and a client without it has none",
    )
    .with_detail(reason)
}

/// Whether two `response_type` values name the same type: the same words
/// in any order for a type Hodor offers, the same text otherwise.
#[must_use]
pub fn same_response_type(one: &str, other: &str) -> bool {
    match (ResponseType::read(one), ResponseType::read(other)) {
        (ReadResponseType::Offered(one), ReadResponseType::Offered(other)) => one == other,
        _ => one == other,
    }
}

/// The response types of a client after a change that did not name them:
/// those it had while it keeps `authorization_code`, `code` when it gains
/// the grant without any, none when it loses it.
#[must_use]
pub fn response_types_kept(current: &[ResponseType], grants: &[GrantType]) -> Vec<ResponseType> {
    match (
        grants.contains(&GrantType::AuthorizationCode),
        current.is_empty(),
    ) {
        (false, _) => Vec::new(),
        (true, true) => vec![ResponseType::Code],
        (true, false) => current.to_vec(),
    }
}

/// Where the parameters of an answer go.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseMode {
    /// The query of the redirect address, by a redirect.
    #[default]
    #[serde(rename = "query")]
    Query,
    /// The fragment of the redirect address, by a redirect.
    #[serde(rename = "fragment")]
    Fragment,
    /// The body of a form that a page of Hodor's posts to the redirect
    /// address.
    #[serde(rename = "form_post")]
    FormPost,
}

impl ResponseMode {
    /// Every mode Hodor offers, as discovery lists them.
    pub const ALL: [Self; 3] = [Self::Query, Self::Fragment, Self::FormPost];

    /// The name OAuth gives it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Fragment => "fragment",
            Self::FormPost => "form_post",
        }
    }

    /// The mode a request names, if Hodor offers it.
    #[must_use]
    pub fn read(value: &str) -> Option<Self> {
        match value {
            "query" => Some(Self::Query),
            "fragment" => Some(Self::Fragment),
            "form_post" => Some(Self::FormPost),
            _ => None,
        }
    }
}

/// The mode an error goes back in, given the `response_type` and the
/// `response_mode` a request names, as they were given: the mode it names
/// when Hodor offers it and the type allows it; else the default of the
/// type when the type can be read, the fragment for a type that returns an
/// access token; else the query.
#[must_use]
pub fn error_mode(response_type: Option<&str>, response_mode: Option<&str>) -> ResponseMode {
    let default = match response_type.map(ResponseType::read) {
        Some(ReadResponseType::Offered(kind)) => kind.default_mode(),
        // A type that returns a token defaults to the fragment, as every
        // such type does, and is never answered in the query.
        Some(ReadResponseType::ReturnsAccessToken) => ResponseMode::Fragment,
        Some(ReadResponseType::Unknown) | None => ResponseMode::Query,
    };
    match response_mode.and_then(ResponseMode::read) {
        Some(ResponseMode::Query) if default == ResponseMode::Fragment => default,
        Some(asked) => asked,
        None => default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_response_type_reads_in_any_order_of_its_words() {
        for (written, kind) in [
            ("code", ResponseType::Code),
            ("id_token", ResponseType::IdToken),
            ("code id_token", ResponseType::CodeIdToken),
            ("id_token code", ResponseType::CodeIdToken),
            ("none", ResponseType::None),
        ] {
            assert_eq!(ResponseType::read(written), ReadResponseType::Offered(kind));
            assert_eq!(
                ResponseType::parse(written).map(ResponseType::as_str),
                Ok(kind.as_str())
            );
        }
    }

    #[test]
    fn the_same_type_is_the_same_words_in_any_order() {
        assert!(same_response_type("code id_token", "id_token code"));
        assert!(same_response_type("code", "code"));
        assert!(!same_response_type("code", "code id_token"));
        assert!(same_response_type("token", "token"));
        assert!(!same_response_type("id_token token", "token id_token"));
    }

    #[test]
    fn a_type_that_returns_an_access_token_is_known_and_not_offered() {
        for written in [
            "token",
            "id_token token",
            "token code",
            "code token id_token",
        ] {
            assert_eq!(
                ResponseType::read(written),
                ReadResponseType::ReturnsAccessToken,
                "{written}"
            );
            let error = ResponseType::parse(written).expect_err("not offered");
            assert_eq!(error.code(), "oauth.client_response_types_invalid");
        }
    }

    #[test]
    fn anything_else_is_unknown() {
        for written in [
            "",
            "code ",
            " code",
            "code  id_token",
            "code code",
            "none code",
            "CODE",
            "code id_token none",
            "device_code",
        ] {
            assert_eq!(
                ResponseType::read(written),
                ReadResponseType::Unknown,
                "{written:?}"
            );
        }
    }

    #[test]
    fn a_type_that_returns_an_id_token_answers_in_the_fragment_and_never_in_the_query() {
        assert_eq!(ResponseType::Code.default_mode(), ResponseMode::Query);
        assert_eq!(ResponseType::None.default_mode(), ResponseMode::Query);
        assert_eq!(ResponseType::IdToken.default_mode(), ResponseMode::Fragment);
        assert_eq!(
            ResponseType::CodeIdToken.default_mode(),
            ResponseMode::Fragment
        );
        assert!(!ResponseType::IdToken.allows(ResponseMode::Query));
        assert!(!ResponseType::CodeIdToken.allows(ResponseMode::Query));
        for kind in ResponseType::ALL {
            assert!(kind.allows(ResponseMode::Fragment));
        }
        assert!(ResponseType::Code.allows(ResponseMode::Query));
        assert!(ResponseType::None.allows(ResponseMode::Query));
    }

    #[test]
    fn every_type_may_come_as_a_form() {
        for kind in ResponseType::ALL {
            assert!(kind.allows(ResponseMode::FormPost), "{kind:?}");
        }
    }

    #[test]
    fn only_none_makes_no_grant() {
        assert!(!ResponseType::None.makes_grant());
        assert!(!ResponseType::None.returns_code());
        assert!(!ResponseType::None.returns_id_token());
        assert!(ResponseType::IdToken.makes_grant());
        assert!(!ResponseType::IdToken.returns_code());
        assert!(ResponseType::CodeIdToken.returns_code());
        assert!(ResponseType::CodeIdToken.returns_id_token());
    }

    #[test]
    fn response_types_follow_the_grant_unless_named() {
        let code = [GrantType::AuthorizationCode];
        assert_eq!(
            response_types_kept(&[], &code),
            vec![ResponseType::Code],
            "gaining the grant gives code"
        );
        assert_eq!(
            response_types_kept(&[ResponseType::IdToken], &code),
            vec![ResponseType::IdToken]
        );
        assert!(
            response_types_kept(&[ResponseType::IdToken], &[GrantType::ClientCredentials])
                .is_empty(),
            "losing the grant drops them"
        );
    }

    #[test]
    fn modes_read_by_their_names_and_nothing_else() {
        assert_eq!(ResponseMode::read("query"), Some(ResponseMode::Query));
        assert_eq!(ResponseMode::read("fragment"), Some(ResponseMode::Fragment));
        assert_eq!(
            ResponseMode::read("form_post"),
            Some(ResponseMode::FormPost)
        );
        for other in [
            "",
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
    fn an_error_comes_in_the_mode_the_answer_would_have_had() {
        let cases = [
            (Some("code"), Some("form_post"), ResponseMode::FormPost),
            (Some("code"), Some("query"), ResponseMode::Query),
            (Some("code"), Some("fragment"), ResponseMode::Fragment),
            (Some("code"), None, ResponseMode::Query),
            (Some("id_token"), None, ResponseMode::Fragment),
            (Some("id_token"), Some("form_post"), ResponseMode::FormPost),
            // A token never goes into the query, not even with an error.
            (Some("code id_token"), Some("query"), ResponseMode::Fragment),
            (Some("token"), None, ResponseMode::Fragment),
            (Some("token"), Some("query"), ResponseMode::Fragment),
            // A mode Hodor does not offer: the default of the type.
            (Some("code"), Some("form_post.jwt"), ResponseMode::Query),
            (Some("id_token"), Some("jwt"), ResponseMode::Fragment),
            // A type that cannot be read: the mode, when it can be.
            (Some("device"), Some("form_post"), ResponseMode::FormPost),
            (None, Some("form_post"), ResponseMode::FormPost),
            (None, Some("jwt"), ResponseMode::Query),
            (None, None, ResponseMode::Query),
        ];
        for (kind, mode, expected) in cases {
            assert_eq!(error_mode(kind, mode), expected, "{kind:?} {mode:?}");
        }
    }

    #[test]
    fn a_kept_request_reads_its_type_and_mode_back() {
        let written = serde_json::to_string(&(ResponseType::CodeIdToken, ResponseMode::Fragment))
            .expect("JSON");
        assert_eq!(written, r#"["code id_token","fragment"]"#);
        let read: (ResponseType, ResponseMode) = serde_json::from_str(&written).expect("read");
        assert_eq!(read, (ResponseType::CodeIdToken, ResponseMode::Fragment));
        let written = serde_json::to_string(&ResponseMode::FormPost).expect("JSON");
        assert_eq!(written, r#""form_post""#);
        assert_eq!(ResponseMode::default(), ResponseMode::Query);
    }
}
