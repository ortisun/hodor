//! The question an engine answers: may this subject do this action to this
//! resource of this resource server?
//!
//! See `docs/architecture/contexts/authorization.md`, "The request".

use hodor_kernel::{CorrelationId, DomainError, UserId};
use serde::Serialize;
use std::collections::BTreeMap;

/// The longest namespace.
const MAX_NAMESPACE_LENGTH: usize = 255;
/// The longest subject or resource identifier.
const MAX_IDENTIFIER_LENGTH: usize = 255;
/// The longest name: of a resource kind, an action or an attribute.
const MAX_NAME_LENGTH: usize = 64;
/// The most attributes one set may hold.
pub(crate) const MAX_ATTRIBUTES: usize = 64;

fn invalid(code: &'static str, message: &'static str) -> DomainError {
    DomainError::invalid(code, message)
}

/// Whether `value` is a name: a lower-case letter, then lower-case
/// letters, digits, `-`, `_` and `.`, at most 64 characters.
fn is_name(value: &str) -> bool {
    let mut characters = value.chars();
    value.len() <= MAX_NAME_LENGTH
        && characters
            .next()
            .is_some_and(|first| first.is_ascii_lowercase())
        && characters.all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '-' | '_' | '.')
        })
}

/// The resource server a request is about.
///
/// Either a resource server's audience, an `https://` address or a `urn:`
/// name, or `hodor:admin`, Hodor's own administration.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Namespace(String);

impl Namespace {
    /// The namespace of Hodor's own administration.
    pub const ADMINISTRATION: &'static str = "hodor:admin";

    /// Hodor's own administration.
    #[must_use]
    pub fn administration() -> Self {
        Self(Self::ADMINISTRATION.to_owned())
    }

    /// Reads a namespace.
    ///
    /// # Errors
    ///
    /// Returns `authorization.namespace_invalid` unless the value is
    /// `hodor:admin`, or an `https://` address or a `urn:` name of at
    /// most 255 characters without a fragment or a space.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        if value == Self::ADMINISTRATION {
            return Ok(Self::administration());
        }
        let shaped = value.len() <= MAX_NAMESPACE_LENGTH
            && (value.len() > "https://".len() && value.starts_with("https://")
                || value.len() > "urn:".len() && value.starts_with("urn:"))
            && !value.contains('#')
            && !value
                .chars()
                .any(|character| character.is_whitespace() || character.is_control());
        if shaped {
            Ok(Self(value.to_owned()))
        } else {
            Err(invalid(
                "authorization.namespace_invalid",
                "a namespace is a resource server's audience, an `https://` address or a `urn:` \
                 name of at most 255 characters without a fragment, or `hodor:admin`",
            ))
        }
    }

    /// Whether this is Hodor's own administration.
    #[must_use]
    pub fn is_administration(&self) -> bool {
        self.0 == Self::ADMINISTRATION
    }

    /// The namespace as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What kind of principal a subject is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    /// A person, a user of the identity context.
    User,
    /// An application acting for itself, a client of the OAuth context.
    Client,
}

impl SubjectKind {
    /// The kind as written.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Client => "client",
        }
    }

    /// Reads a kind.
    ///
    /// # Errors
    ///
    /// Returns `authorization.subject_kind_invalid` unless the value is
    /// `user` or `client`.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        match value {
            "user" => Ok(Self::User),
            "client" => Ok(Self::Client),
            _ => Err(invalid(
                "authorization.subject_kind_invalid",
                "a subject is a `user` or a `client`",
            )),
        }
    }
}

/// Whether `value` is an identifier: 1 to 255 characters, none of them a
/// control character.
fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_LENGTH
        && !value.chars().any(char::is_control)
}

/// Who wants to act.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Subject {
    kind: SubjectKind,
    id: String,
}

impl Subject {
    /// Reads a subject.
    ///
    /// # Errors
    ///
    /// Returns `authorization.subject_invalid` if the identifier is empty,
    /// longer than 255 characters or holds a control character.
    pub fn new(kind: SubjectKind, id: &str) -> Result<Self, DomainError> {
        if is_identifier(id) {
            Ok(Self {
                kind,
                id: id.to_owned(),
            })
        } else {
            Err(invalid(
                "authorization.subject_invalid",
                "a subject's identifier has 1 to 255 characters and no control character",
            ))
        }
    }

    /// A user as a subject.
    #[must_use]
    pub fn user(user_id: UserId) -> Self {
        Self {
            kind: SubjectKind::User,
            id: user_id.to_string(),
        }
    }

    /// What kind of principal it is.
    #[must_use]
    pub const fn kind(&self) -> SubjectKind {
        self.kind
    }

    /// Its identifier, as the caller gave it.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The user it is, if it is a user with a well-formed identifier.
    #[must_use]
    pub fn user_id(&self) -> Option<UserId> {
        match self.kind {
            SubjectKind::User => self.id.parse().ok(),
            SubjectKind::Client => None,
        }
    }
}

/// Names with JSON values: what is known about a subject, a resource or
/// the moment.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Attributes(BTreeMap<String, serde_json::Value>);

impl Attributes {
    /// No attributes.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Reads a set of attributes.
    ///
    /// # Errors
    ///
    /// Returns `authorization.attributes_invalid` if there are more than 64,
    /// or a name is not a name: a lower-case letter, then lower-case
    /// letters, digits, `-`, `_` and `.`, at most 64 characters.
    pub fn new(
        values: impl IntoIterator<Item = (String, serde_json::Value)>,
    ) -> Result<Self, DomainError> {
        let values: BTreeMap<String, serde_json::Value> = values.into_iter().collect();
        if values.len() > MAX_ATTRIBUTES || !values.keys().all(|name| is_name(name)) {
            return Err(invalid(
                "authorization.attributes_invalid",
                "a set holds at most 64 attributes, each named with lower-case letters, digits, \
                 `-`, `_` and `.`, starting with a letter, at most 64 characters",
            ));
        }
        Ok(Self(values))
    }

    /// The value of one attribute.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&serde_json::Value> {
        self.0.get(name)
    }

    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Every attribute, by name.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &serde_json::Value)> {
        self.0.iter().map(|(name, value)| (name.as_str(), value))
    }
}

/// What is to be done, such as `read`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Action(String);

impl Action {
    /// Reads an action.
    ///
    /// # Errors
    ///
    /// Returns `authorization.action_invalid` unless the value is a
    /// lower-case letter followed by lower-case letters, digits, `-`, `_`
    /// and `.`, at most 64 characters.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        if is_name(value) {
            Ok(Self(value.to_owned()))
        } else {
            Err(invalid(
                "authorization.action_invalid",
                "an action is lower-case letters, digits, `-`, `_` and `.`, starting with a \
                 letter, at most 64 characters",
            ))
        }
    }

    /// The action as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What a request is about: a kind of resource, possibly one of them, and
/// what is known about it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Resource {
    kind: String,
    id: Option<String>,
    attributes: Attributes,
}

impl Resource {
    /// Reads a resource.
    ///
    /// # Errors
    ///
    /// Returns `authorization.resource_invalid` if the kind is not a name
    /// or the identifier is empty, longer than 255 characters or holds a
    /// control character.
    pub fn new(kind: &str, id: Option<&str>, attributes: Attributes) -> Result<Self, DomainError> {
        if !is_name(kind) || id.is_some_and(|id| !is_identifier(id)) {
            return Err(invalid(
                "authorization.resource_invalid",
                "a resource kind is lower-case letters, digits, `-`, `_` and `.`, starting with a \
                 letter, at most 64 characters; an identifier has 1 to 255 characters and no \
                 control character",
            ));
        }
        Ok(Self {
            kind: kind.to_owned(),
            id: id.map(str::to_owned),
            attributes,
        })
    }

    /// The kind of resource.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// The one resource, when the request is about one.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    /// What the caller says about it.
    #[must_use]
    pub const fn attributes(&self) -> &Attributes {
        &self.attributes
    }
}

/// What is known about the moment of the request.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct EvaluationContext {
    /// Attributes of the moment, such as the address the request came from.
    pub attributes: Attributes,
    /// Ties the decision to the request that asked for it.
    pub correlation_id: Option<CorrelationId>,
}

/// The question: may this subject do this action to this resource of this
/// resource server? It never names a tenant: the tenant is the caller's.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AuthorizationRequest {
    /// The resource server asked about.
    pub namespace: Namespace,
    /// Who wants to act. Hodor resolves what it knows about them.
    pub subject: Subject,
    /// What the caller claims about the subject. Untrusted: an engine
    /// receives it only when the binding trusts it.
    pub asserted: Attributes,
    /// What it is about.
    pub resource: Resource,
    /// What is to be done.
    pub action: Action,
    /// The moment.
    pub context: EvaluationContext,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_namespace_is_an_audience_or_the_administration() {
        for good in [
            "https://api.example.com",
            "urn:example:documents",
            "hodor:admin",
        ] {
            assert_eq!(Namespace::parse(good).expect(good).as_str(), good);
        }
        assert!(
            Namespace::parse("hodor:admin")
                .expect("admin")
                .is_administration()
        );
        assert!(
            !Namespace::parse("urn:hodor:admin")
                .expect("urn")
                .is_administration()
        );
        let long = format!("urn:{}", "a".repeat(252));
        for bad in [
            "",
            "https://",
            "urn:",
            "http://api.example.com",
            "api.example.com",
            "https://api.example.com/#part",
            "urn:a b",
            "urn:a\u{7}",
            "hodor:administration",
            long.as_str(),
        ] {
            assert_eq!(
                Namespace::parse(bad).map_err(|e| e.code().to_owned()),
                Err("authorization.namespace_invalid".to_owned()),
                "{bad:?}"
            );
        }
        assert!(Namespace::parse(&format!("urn:{}", "a".repeat(251))).is_ok());
    }

    #[test]
    fn names_are_lower_case_and_short() {
        for good in [
            "read",
            "identity-providers",
            "a",
            "v2.read_all",
            &"a".repeat(64),
        ] {
            assert!(Action::parse(good).is_ok(), "{good}");
            assert!(
                Resource::new(good, None, Attributes::none()).is_ok(),
                "{good}"
            );
        }
        for bad in [
            "",
            "Read",
            "1read",
            "-read",
            "re ad",
            "réad",
            &"a".repeat(65),
        ] {
            assert!(Action::parse(bad).is_err(), "{bad}");
            assert!(
                Resource::new(bad, None, Attributes::none()).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn identifiers_have_no_control_characters() {
        assert!(Subject::new(SubjectKind::Client, "billing").is_ok());
        assert!(Subject::new(SubjectKind::User, &"x".repeat(255)).is_ok());
        for bad in ["", "a\nb", &"x".repeat(256)] {
            assert!(Subject::new(SubjectKind::User, bad).is_err(), "{bad:?}");
            assert!(
                Resource::new("document", Some(bad), Attributes::none()).is_err(),
                "{bad:?}"
            );
        }
        assert_eq!(SubjectKind::parse("user").ok(), Some(SubjectKind::User));
        assert_eq!(SubjectKind::parse("client").ok(), Some(SubjectKind::Client));
        assert!(SubjectKind::parse("group").is_err());
    }

    #[test]
    fn a_user_subject_gives_back_its_user() {
        let user = UserId::generate();
        assert_eq!(Subject::user(user).user_id(), Some(user));
        let client = Subject::new(SubjectKind::Client, &user.to_string()).expect("client");
        assert_eq!(client.user_id(), None);
        let malformed = Subject::new(SubjectKind::User, "ana").expect("user");
        assert_eq!(malformed.user_id(), None);
    }

    #[test]
    fn attributes_are_bounded() {
        let many = |count: usize| {
            (0..count).map(|index| (format!("a{index}"), serde_json::Value::Bool(true)))
        };
        assert!(Attributes::new(many(MAX_ATTRIBUTES)).is_ok());
        assert!(Attributes::new(many(MAX_ATTRIBUTES + 1)).is_err());
        assert!(Attributes::new([("Roles".to_owned(), serde_json::Value::Null)]).is_err());
        let set = Attributes::new([("department".to_owned(), serde_json::json!("finance"))])
            .expect("set");
        assert_eq!(set.get("department"), Some(&serde_json::json!("finance")));
        assert!(!set.is_empty());
        assert!(Attributes::none().is_empty());
    }
}
