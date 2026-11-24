//! The attributes a filter may name and a list may be sorted by.
//!
//! Specified in `docs/architecture/contexts/provisioning.md`, "What can be
//! filtered on". The set is fixed: an attribute is one of these, or it
//! cannot be filtered on.

use std::fmt::Debug;

/// The URI of the core User schema.
pub const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
/// The URI of the enterprise extension of the User schema.
pub const ENTERPRISE_USER_SCHEMA: &str =
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
/// The URI of the core Group schema.
pub const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";

/// What sort of values an attribute holds, which decides the operators
/// and values a filter may compare it with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeType {
    /// Text. `exact` says whether case matters when it is compared.
    Text {
        /// Compared exactly, or without regard to the case of `A` to `Z`.
        exact: bool,
    },
    /// `true` or `false`.
    Boolean,
    /// A date and time.
    DateTime,
}

/// An attribute of one resource type that a filter may name.
pub trait Attribute: Copy + Eq + Debug + Send + Sync + 'static {
    /// The URI of the resource's core schema, which may be written before
    /// an attribute's name.
    const SCHEMA: &'static str;

    /// The attribute a path names, written in lower case and without the
    /// schema; `None` when it cannot be filtered on.
    fn named(path: &str) -> Option<Self>;

    /// The name as SCIM writes it, such as `name.givenName`.
    fn name(self) -> &'static str;

    /// What sort of values it holds.
    fn value_type(self) -> AttributeType;

    /// Whether it holds several values, each of which a comparison may
    /// match. Only these may be written with a value path.
    fn multi_valued(self) -> bool;

    /// Whether a list may be sorted by it.
    fn sortable(self) -> bool;

    /// The attribute a list may be sorted by that `name` names, compared
    /// without regard to case and with or without the schema.
    fn sort_named(name: &str) -> Option<Self> {
        let lowered = name.to_ascii_lowercase();
        let path = without_schema(&lowered, Self::SCHEMA)?;
        Self::named(path).filter(|attribute| attribute.sortable())
    }
}

/// The path without the schema's URI and its colon, when it starts with
/// it; the path as it is when it names no schema. `None` for a path that
/// starts with another schema. `lowered` and the schema are compared in
/// lower case.
pub(crate) fn without_schema<'a>(lowered: &'a str, schema: &str) -> Option<&'a str> {
    let schema = schema.to_ascii_lowercase();
    match lowered.strip_prefix(&schema) {
        Some(rest) => rest.strip_prefix(':'),
        None if lowered.starts_with("urn:") => None,
        None => Some(lowered),
    }
}

/// The attributes of a User that a filter may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UserAttribute {
    /// `id`.
    Id,
    /// `externalId`.
    ExternalId,
    /// `userName`.
    UserName,
    /// `displayName`.
    DisplayName,
    /// `name.givenName`.
    GivenName,
    /// `name.familyName`.
    FamilyName,
    /// `emails.value`, of every email address.
    Emails,
    /// `active`.
    Active,
    /// `meta.created`.
    Created,
    /// `meta.lastModified`.
    LastModified,
}

impl Attribute for UserAttribute {
    const SCHEMA: &'static str = USER_SCHEMA;

    fn named(path: &str) -> Option<Self> {
        Some(match path {
            "id" => Self::Id,
            "externalid" => Self::ExternalId,
            "username" => Self::UserName,
            "displayname" => Self::DisplayName,
            "name.givenname" => Self::GivenName,
            "name.familyname" => Self::FamilyName,
            "emails" | "emails.value" => Self::Emails,
            "active" => Self::Active,
            "meta.created" => Self::Created,
            "meta.lastmodified" => Self::LastModified,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Self::Id => "id",
            Self::ExternalId => "externalId",
            Self::UserName => "userName",
            Self::DisplayName => "displayName",
            Self::GivenName => "name.givenName",
            Self::FamilyName => "name.familyName",
            Self::Emails => "emails.value",
            Self::Active => "active",
            Self::Created => "meta.created",
            Self::LastModified => "meta.lastModified",
        }
    }

    fn value_type(self) -> AttributeType {
        match self {
            Self::Id | Self::ExternalId => AttributeType::Text { exact: true },
            Self::UserName
            | Self::DisplayName
            | Self::GivenName
            | Self::FamilyName
            | Self::Emails => AttributeType::Text { exact: false },
            Self::Active => AttributeType::Boolean,
            Self::Created | Self::LastModified => AttributeType::DateTime,
        }
    }

    fn multi_valued(self) -> bool {
        self == Self::Emails
    }

    fn sortable(self) -> bool {
        matches!(
            self,
            Self::UserName | Self::DisplayName | Self::Created | Self::LastModified
        )
    }
}

/// The attributes of a Group that a filter may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GroupAttribute {
    /// `id`.
    Id,
    /// `externalId`.
    ExternalId,
    /// `displayName`.
    DisplayName,
    /// `members.value`, of every direct member.
    Members,
    /// `meta.created`.
    Created,
    /// `meta.lastModified`.
    LastModified,
}

impl Attribute for GroupAttribute {
    const SCHEMA: &'static str = GROUP_SCHEMA;

    fn named(path: &str) -> Option<Self> {
        Some(match path {
            "id" => Self::Id,
            "externalid" => Self::ExternalId,
            "displayname" => Self::DisplayName,
            "members" | "members.value" => Self::Members,
            "meta.created" => Self::Created,
            "meta.lastmodified" => Self::LastModified,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Self::Id => "id",
            Self::ExternalId => "externalId",
            Self::DisplayName => "displayName",
            Self::Members => "members.value",
            Self::Created => "meta.created",
            Self::LastModified => "meta.lastModified",
        }
    }

    fn value_type(self) -> AttributeType {
        match self {
            Self::Id | Self::ExternalId | Self::Members => AttributeType::Text { exact: true },
            Self::DisplayName => AttributeType::Text { exact: false },
            Self::Created | Self::LastModified => AttributeType::DateTime,
        }
    }

    fn multi_valued(self) -> bool {
        self == Self::Members
    }

    fn sortable(self) -> bool {
        matches!(self, Self::DisplayName | Self::Created | Self::LastModified)
    }
}

/// Text with the letters `A` to `Z` made `a` to `z`, and nothing else
/// changed: how text is compared without regard to case.
#[must_use]
pub fn fold_case(text: &str) -> String {
    text.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_read_without_regard_to_case_and_with_or_without_the_schema() {
        assert_eq!(
            UserAttribute::sort_named("USERNAME"),
            Some(UserAttribute::UserName)
        );
        assert_eq!(
            UserAttribute::sort_named("urn:ietf:params:scim:schemas:core:2.0:User:meta.created"),
            Some(UserAttribute::Created)
        );
        assert_eq!(UserAttribute::sort_named("emails.value"), None);
        assert_eq!(GroupAttribute::sort_named("userName"), None);
        assert_eq!(
            without_schema("urn:example:other:username", USER_SCHEMA),
            None
        );
    }

    #[test]
    fn only_the_letters_a_to_z_change_case() {
        assert_eq!(fold_case("Ana ÉMILE"), "ana Émile");
    }
}
