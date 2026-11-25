//! Claim mappers: the claims an administrator adds to the tokens of one
//! client, from what Hodor knows of the person, their groups, the
//! organization of the sign-in, or a constant. Every rule is checked when
//! a mapper is saved, the bound on the size of a token included, so that
//! nothing is refused or cut when a token is issued.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Claim mappers",
//! and Decision 0041.

use crate::domain::client::ClientId;
use crate::domain::event::OauthEvent;
use crate::domain::text;
use crate::domain::token::MOST_GROUPS_IN_A_TOKEN;
use hodor_kernel::{DomainError, GroupId, OrganizationId, Timestamp};
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;

hodor_kernel::define_id!(
    /// Identifies a claim mapper.
    ClaimMapperId
);

/// The most mappers a client has.
pub const MAX_CLAIM_MAPPERS: usize = 20;
/// The most bytes the mappers of one client add to one target, in the
/// worst case, as JSON writes them.
pub const MOST_MAPPED_BYTES: usize = 4096;
/// The largest constant, as JSON writes it.
pub const MAX_CONSTANT_BYTES: usize = 1024;
/// The longest locale a mapper writes, in characters (RFC 5646, section
/// 4.4.1).
pub const LONGEST_LOCALE: usize = 35;

/// The longest display name the identity context allows.
const LONGEST_DISPLAY_NAME: usize = 200;
/// The longest username the identity context allows.
const LONGEST_USERNAME: usize = 64;
/// The longest email address the identity context allows.
const LONGEST_EMAIL: usize = 254;
/// The longest name of an organization the identity context allows.
const LONGEST_ORGANIZATION_NAME: usize = 100;
/// The length of an identifier written as a UUID.
const IDENTIFIER_LENGTH: usize = 36;

/// The names a mapper may not use: every claim Hodor writes in an ID
/// token, an access token or an answer of UserInfo, and those the
/// specifications Hodor follows give a meaning to there. Compared without
/// regard to case.
pub const RESERVED_CLAIMS: [&str; 33] = [
    // JSON Web Token (RFC 7519).
    "iss",
    "sub",
    "aud",
    "exp",
    "nbf",
    "iat",
    "jti",
    // OpenID Connect Core.
    "auth_time",
    "nonce",
    "acr",
    "amr",
    "azp",
    "at_hash",
    "c_hash",
    "s_hash",
    "sid",
    "_claim_names",
    "_claim_sources",
    // Access tokens (RFC 9068), token exchange (RFC 8693), proof of
    // possession (RFC 7800) and logout tokens.
    "scope",
    "client_id",
    "act",
    "may_act",
    "cnf",
    "events",
    // Hodor's own.
    "org_id",
    "groups",
    "principal_kind",
    // What UserInfo answers.
    "name",
    "preferred_username",
    "locale",
    "updated_at",
    "email",
    "email_verified",
];

/// Whether `claim` is a name Hodor sets, without regard to case.
#[must_use]
pub fn is_reserved(claim: &str) -> bool {
    RESERVED_CLAIMS
        .iter()
        .any(|reserved| reserved.eq_ignore_ascii_case(claim))
}

/// Which of a client's tokens a mapper writes into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClaimTarget {
    /// The ID token of a code.
    IdToken,
    /// The access token of a code or a refresh.
    AccessToken,
    /// The answer of UserInfo.
    UserInfo,
}

impl ClaimTarget {
    /// Every target, in the order they are written.
    pub const ALL: [Self; 3] = [Self::IdToken, Self::AccessToken, Self::UserInfo];

    /// How the interface writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IdToken => "id_token",
            Self::AccessToken => "access_token",
            Self::UserInfo => "userinfo",
        }
    }

    /// Reads a target.
    ///
    /// # Errors
    ///
    /// Returns `oauth.claim_mapper_targets_invalid` for anything else.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        Self::ALL
            .into_iter()
            .find(|target| target.as_str() == value)
            .ok_or_else(targets_invalid)
    }
}

/// What a mapper may read of the person.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersonAttribute {
    /// The display name.
    DisplayName,
    /// The primary username.
    Username,
    /// The primary email address.
    Email,
    /// Whether the primary email address is verified.
    EmailVerified,
    /// The language tag.
    Locale,
}

impl PersonAttribute {
    const ALL: [Self; 5] = [
        Self::DisplayName,
        Self::Username,
        Self::Email,
        Self::EmailVerified,
        Self::Locale,
    ];

    /// How the interface writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DisplayName => "display_name",
            Self::Username => "username",
            Self::Email => "email",
            Self::EmailVerified => "email_verified",
            Self::Locale => "locale",
        }
    }

    /// Reads an attribute.
    ///
    /// # Errors
    ///
    /// Returns `oauth.claim_mapper_source_invalid` for anything else.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        Self::ALL
            .into_iter()
            .find(|attribute| attribute.as_str() == value)
            .ok_or_else(|| {
                source_invalid(
                    "an attribute is display_name, username, email, email_verified or locale",
                )
            })
    }

    /// The largest value it writes, as JSON writes it.
    const fn largest(self) -> usize {
        match self {
            Self::DisplayName => text_bound(LONGEST_DISPLAY_NAME),
            Self::Username => text_bound(LONGEST_USERNAME),
            Self::Email => text_bound(LONGEST_EMAIL),
            Self::EmailVerified => "false".len(),
            Self::Locale => text_bound(LONGEST_LOCALE),
        }
    }
}

/// What a mapper may read of the organization of the sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrganizationAttribute {
    /// Its identifier.
    Id,
    /// Its name.
    Name,
}

impl OrganizationAttribute {
    /// How the interface writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Id => "id",
            Self::Name => "name",
        }
    }

    /// Reads an attribute.
    ///
    /// # Errors
    ///
    /// Returns `oauth.claim_mapper_source_invalid` for anything else.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        match value {
            "id" => Ok(Self::Id),
            "name" => Ok(Self::Name),
            _ => Err(source_invalid(
                "an attribute of the organization is id or name",
            )),
        }
    }
}

/// Where a mapper's value comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimSource {
    /// An attribute of the person.
    Attribute(PersonAttribute),
    /// The identifiers of the person's effective groups.
    Groups,
    /// Whether the person is in one group, effectively.
    GroupMember(GroupId),
    /// The organization of the sign-in.
    Organization(OrganizationAttribute),
    /// A constant: any JSON value but `null`.
    Constant(Value),
}

impl ClaimSource {
    /// How the interface names its kind.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Attribute(_) => "attribute",
            Self::Groups => "groups",
            Self::GroupMember(_) => "group_member",
            Self::Organization(_) => "organization",
            Self::Constant(_) => "constant",
        }
    }

    /// The source as the interface and storage write it.
    #[must_use]
    pub fn to_json(&self) -> Value {
        match self {
            Self::Attribute(attribute) => {
                json!({"kind": self.kind(), "attribute": attribute.as_str()})
            }
            Self::Groups => json!({"kind": self.kind()}),
            Self::GroupMember(group) => {
                json!({"kind": self.kind(), "group_id": group.to_string()})
            }
            Self::Organization(attribute) => {
                json!({"kind": self.kind(), "attribute": attribute.as_str()})
            }
            Self::Constant(value) => json!({"kind": self.kind(), "value": value}),
        }
    }

    /// Reads a source as the interface and storage write it.
    ///
    /// # Errors
    ///
    /// Returns `oauth.claim_mapper_source_invalid` for an unknown kind or
    /// attribute, a member that does not belong, or one missing.
    pub fn from_json(value: &Value) -> Result<Self, DomainError> {
        let object = value
            .as_object()
            .ok_or_else(|| source_invalid("a source is an object with a kind"))?;
        let kind = object
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let allowed: &[&str] = match kind {
            "attribute" | "organization" => &["kind", "attribute"],
            "groups" => &["kind"],
            "group_member" => &["kind", "group_id"],
            "constant" => &["kind", "value"],
            _ => {
                return Err(source_invalid(
                    "a source is attribute, groups, group_member, organization or constant",
                ));
            }
        };
        if object.keys().any(|key| !allowed.contains(&key.as_str())) {
            return Err(source_invalid(
                "the source has a member its kind does not take",
            ));
        }
        let attribute = || {
            object
                .get("attribute")
                .and_then(Value::as_str)
                .unwrap_or_default()
        };
        Ok(match kind {
            "attribute" => Self::Attribute(PersonAttribute::parse(attribute())?),
            "organization" => Self::Organization(OrganizationAttribute::parse(attribute())?),
            "groups" => Self::Groups,
            "group_member" => Self::GroupMember(
                object
                    .get("group_id")
                    .and_then(Value::as_str)
                    .and_then(|group| group.parse().ok())
                    .ok_or_else(|| {
                        source_invalid("group_member names a group by its identifier")
                    })?,
            ),
            _ => Self::Constant(object.get("value").cloned().unwrap_or(Value::Null)),
        })
    }

    /// The largest value it can write, as JSON writes it.
    fn largest(&self) -> usize {
        match self {
            Self::Attribute(attribute) => attribute.largest(),
            // Brackets, each identifier with its quotes, and the commas.
            Self::Groups => {
                2 + MOST_GROUPS_IN_A_TOKEN * (IDENTIFIER_LENGTH + 2) + MOST_GROUPS_IN_A_TOKEN - 1
            }
            Self::GroupMember(_) => "false".len(),
            Self::Organization(OrganizationAttribute::Id) => IDENTIFIER_LENGTH + 2,
            Self::Organization(OrganizationAttribute::Name) => {
                text_bound(LONGEST_ORGANIZATION_NAME)
            }
            Self::Constant(value) => value.to_string().len(),
        }
    }

    const fn reads_attributes(&self) -> bool {
        matches!(self, Self::Attribute(_))
    }

    const fn reads_groups(&self) -> bool {
        matches!(self, Self::Groups | Self::GroupMember(_))
    }

    const fn reads_organization_name(&self) -> bool {
        matches!(self, Self::Organization(OrganizationAttribute::Name))
    }
}

/// The largest text of at most `characters` characters, as JSON writes it:
/// four bytes for each character and two quotes.
const fn text_bound(characters: usize) -> usize {
    4 * characters + 2
}

fn targets_invalid() -> DomainError {
    DomainError::invalid(
        "oauth.claim_mapper_targets_invalid",
        "a mapper names one or more of id_token, access_token and userinfo, each once",
    )
}

fn source_invalid(message: &'static str) -> DomainError {
    DomainError::invalid("oauth.claim_mapper_source_invalid", message)
}

/// What an administrator decided about a mapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimMapperSettings {
    /// The claim's name.
    pub claim: String,
    /// The tokens it writes into, in the order of [`ClaimTarget::ALL`].
    pub targets: Vec<ClaimTarget>,
    /// The scope the token must hold for the claim to be added.
    pub scope: Option<String>,
    /// Where the value comes from.
    pub source: ClaimSource,
}

impl ClaimMapperSettings {
    /// The settings, checked on their own, with the targets in their
    /// order. `allowed_scopes` are the scopes the client may ask for.
    ///
    /// # Errors
    ///
    /// Returns an `Invalid` error naming the rule broken.
    pub fn checked(self, allowed_scopes: &[String]) -> Result<Self, DomainError> {
        if !text::is_scope(&self.claim) {
            return Err(DomainError::invalid(
                "oauth.claim_mapper_name_invalid",
                "a claim is 1 to 128 printable characters without spaces, double quotes or \
                 backslashes",
            ));
        }
        if is_reserved(&self.claim) {
            return Err(DomainError::invalid(
                "oauth.claim_mapper_name_reserved",
                format!(
                    "`{}` is a claim Hodor sets, and cannot be mapped",
                    self.claim
                ),
            ));
        }
        let given: BTreeSet<ClaimTarget> = self.targets.iter().copied().collect();
        if given.is_empty() || given.len() != self.targets.len() {
            return Err(targets_invalid());
        }
        if let Some(scope) = &self.scope
            && !allowed_scopes.iter().any(|allowed| allowed == scope)
        {
            return Err(DomainError::invalid(
                "oauth.claim_mapper_scope_not_allowed",
                "a mapper's scope is one the client may ask for",
            ));
        }
        if let ClaimSource::Constant(value) = &self.source
            && (value.is_null() || value.to_string().len() > MAX_CONSTANT_BYTES)
        {
            return Err(source_invalid(
                "a constant is any JSON value but null, at most 1024 bytes",
            ));
        }
        Ok(Self {
            targets: given.into_iter().collect(),
            ..self
        })
    }

    /// What it adds to a token in the worst case: the largest value of its
    /// source, its name with two quotes, the colon and a comma.
    #[must_use]
    pub fn worst_case(&self) -> usize {
        self.claim.len() + 4 + self.source.largest()
    }

    fn writes_into(&self, target: ClaimTarget) -> bool {
        self.targets.contains(&target)
    }

    fn applies(&self, target: ClaimTarget, scopes: &[String]) -> bool {
        self.writes_into(target)
            && self
                .scope
                .as_ref()
                .is_none_or(|scope| scopes.iter().any(|given| given == scope))
    }
}

/// Checks the mappers of one client together: at most 20, one per claim
/// name without regard to case, and at most [`MOST_MAPPED_BYTES`] added to
/// each target in the worst case.
///
/// # Errors
///
/// Returns `oauth.claim_mappers_too_many`, `oauth.claim_mapper_name_taken`
/// or `oauth.claim_mapper_token_too_large`.
pub fn check_together(mappers: &[&ClaimMapperSettings]) -> Result<(), DomainError> {
    if mappers.len() > MAX_CLAIM_MAPPERS {
        return Err(DomainError::conflict(
            "oauth.claim_mappers_too_many",
            "a client has at most 20 claim mappers",
        ));
    }
    let mut names = BTreeSet::new();
    for mapper in mappers {
        if !names.insert(mapper.claim.to_ascii_lowercase()) {
            return Err(DomainError::conflict(
                "oauth.claim_mapper_name_taken",
                format!("the client already has a mapper of `{}`", mapper.claim),
            ));
        }
    }
    for target in ClaimTarget::ALL {
        let worst: usize = mappers
            .iter()
            .filter(|mapper| mapper.writes_into(target))
            .map(|mapper| mapper.worst_case())
            .sum();
        if worst > MOST_MAPPED_BYTES {
            return Err(DomainError::invalid(
                "oauth.claim_mapper_token_too_large",
                format!(
                    "the client's mappers could add {worst} bytes to the {}, more than {MOST_MAPPED_BYTES}",
                    target.as_str()
                ),
            ));
        }
    }
    Ok(())
}

/// Everything stored about a mapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimMapperSnapshot {
    /// Its identifier.
    pub id: ClaimMapperId,
    /// The client whose tokens it writes into. Never changes.
    pub client_id: ClientId,
    /// What an administrator decided.
    pub settings: ClaimMapperSettings,
    /// When it was created.
    pub created_at: Timestamp,
    /// When it was last changed.
    pub updated_at: Timestamp,
    /// Incremented on every stored change, for optimistic locking.
    pub version: u32,
}

/// A claim mapper of a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimMapper {
    state: ClaimMapperSnapshot,
}

impl ClaimMapper {
    /// A new mapper of `client_id`, its settings checked on their own; the
    /// use case checks it with the client's other mappers.
    ///
    /// # Errors
    ///
    /// Returns an `Invalid` error naming the rule broken.
    pub fn create(
        client_id: ClientId,
        settings: ClaimMapperSettings,
        allowed_scopes: &[String],
        now: Timestamp,
    ) -> Result<(Self, OauthEvent), DomainError> {
        let mapper = Self {
            state: ClaimMapperSnapshot {
                id: ClaimMapperId::generate(),
                client_id,
                settings: settings.checked(allowed_scopes)?,
                created_at: now,
                updated_at: now,
                version: 0,
            },
        };
        let event = OauthEvent::ClaimMapperCreated {
            claim_mapper_id: mapper.id(),
            client_id,
            claim: mapper.state.settings.claim.clone(),
            targets: mapper.target_names(),
            source: mapper.state.settings.source.kind(),
        };
        Ok((mapper, event))
    }

    /// Replaces its settings, checked on their own.
    ///
    /// # Errors
    ///
    /// Returns an `Invalid` error naming the rule broken.
    pub fn replace(
        &mut self,
        settings: ClaimMapperSettings,
        allowed_scopes: &[String],
        now: Timestamp,
    ) -> Result<OauthEvent, DomainError> {
        self.state.settings = settings.checked(allowed_scopes)?;
        self.state.updated_at = now;
        Ok(OauthEvent::ClaimMapperChanged {
            claim_mapper_id: self.id(),
            client_id: self.state.client_id,
            claim: self.state.settings.claim.clone(),
            targets: self.target_names(),
            source: self.state.settings.source.kind(),
        })
    }

    /// The event of its deletion.
    #[must_use]
    pub fn deleted(&self) -> OauthEvent {
        OauthEvent::ClaimMapperDeleted {
            claim_mapper_id: self.id(),
            client_id: self.state.client_id,
            claim: self.state.settings.claim.clone(),
        }
    }

    /// Rebuilds a mapper from storage.
    #[must_use]
    pub const fn from_snapshot(state: ClaimMapperSnapshot) -> Self {
        Self { state }
    }

    /// Everything stored about it.
    #[must_use]
    pub const fn snapshot(&self) -> &ClaimMapperSnapshot {
        &self.state
    }

    /// Its identifier.
    #[must_use]
    pub const fn id(&self) -> ClaimMapperId {
        self.state.id
    }

    /// The client whose tokens it writes into.
    #[must_use]
    pub const fn client_id(&self) -> ClientId {
        self.state.client_id
    }

    /// Its settings.
    #[must_use]
    pub const fn settings(&self) -> &ClaimMapperSettings {
        &self.state.settings
    }

    fn target_names(&self) -> Vec<&'static str> {
        self.state
            .settings
            .targets
            .iter()
            .map(|target| target.as_str())
            .collect()
    }
}

/// What Hodor knows of a person that a mapper may read.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PersonAttributes {
    /// The display name.
    pub display_name: Option<String>,
    /// The primary username.
    pub username: Option<String>,
    /// The primary email address, and whether it is verified.
    pub email: Option<(String, bool)>,
    /// The language tag.
    pub locale: Option<String>,
}

/// What must be read for the mappers that apply to a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Needs {
    /// The person's attributes.
    pub attributes: bool,
    /// The person's effective groups.
    pub groups: bool,
    /// The name of the organization of the sign-in.
    pub organization_name: bool,
}

/// What must be read for those of `mappers` that apply to any of
/// `targets` for a token of `scopes`.
#[must_use]
pub(crate) fn needs(mappers: &[ClaimMapper], targets: &[ClaimTarget], scopes: &[String]) -> Needs {
    let mut needs = Needs::default();
    for mapper in mappers {
        let settings = mapper.settings();
        if targets
            .iter()
            .any(|target| settings.applies(*target, scopes))
        {
            needs.attributes |= settings.source.reads_attributes();
            needs.groups |= settings.source.reads_groups();
            needs.organization_name |= settings.source.reads_organization_name();
        }
    }
    needs
}

/// What was read of the person and the sign-in, for the mappers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PersonFacts {
    /// The person's attributes, when a mapper reads them.
    pub attributes: PersonAttributes,
    /// The person's effective groups, sorted, when a mapper reads them.
    pub groups: Vec<GroupId>,
    /// The organization of the sign-in, if it named one.
    pub organization: Option<OrganizationId>,
    /// Its name, when a mapper reads it and it still exists.
    pub organization_name: Option<String>,
}

/// A text, unless it has more than `characters` characters or would be
/// written larger than its bound.
fn bounded_text(value: Option<&String>, characters: usize) -> Option<Value> {
    let value = value.filter(|value| value.chars().count() <= characters)?;
    let value = json!(value);
    (value.to_string().len() <= text_bound(characters)).then_some(value)
}

/// The value of `source` for `facts`, or none to leave the claim out.
fn value_of(source: &ClaimSource, facts: &PersonFacts) -> Option<Value> {
    let attributes = &facts.attributes;
    match source {
        ClaimSource::Attribute(PersonAttribute::DisplayName) => {
            bounded_text(attributes.display_name.as_ref(), LONGEST_DISPLAY_NAME)
        }
        ClaimSource::Attribute(PersonAttribute::Username) => {
            bounded_text(attributes.username.as_ref(), LONGEST_USERNAME)
        }
        ClaimSource::Attribute(PersonAttribute::Email) => bounded_text(
            attributes.email.as_ref().map(|(email, _)| email),
            LONGEST_EMAIL,
        ),
        ClaimSource::Attribute(PersonAttribute::EmailVerified) => attributes
            .email
            .as_ref()
            .map(|(_, verified)| json!(verified)),
        ClaimSource::Attribute(PersonAttribute::Locale) => {
            bounded_text(attributes.locale.as_ref(), LONGEST_LOCALE)
        }
        ClaimSource::Groups => (facts.groups.len() <= MOST_GROUPS_IN_A_TOKEN).then(|| {
            let names: Vec<String> = facts.groups.iter().map(ToString::to_string).collect();
            json!(names)
        }),
        ClaimSource::GroupMember(group) => Some(json!(facts.groups.contains(group))),
        ClaimSource::Organization(OrganizationAttribute::Id) => facts
            .organization
            .map(|organization| json!(organization.to_string())),
        ClaimSource::Organization(OrganizationAttribute::Name) => facts.organization.and(
            bounded_text(facts.organization_name.as_ref(), LONGEST_ORGANIZATION_NAME),
        ),
        ClaimSource::Constant(value) => Some(value.clone()),
    }
}

/// The claims `mappers` add to `target` of a token of `scopes`, by claim
/// name. A value the person does not have leaves its claim out.
#[must_use]
pub fn mapped_claims(
    mappers: &[ClaimMapper],
    target: ClaimTarget,
    scopes: &[String],
    facts: &PersonFacts,
) -> Map<String, Value> {
    let mut applying: Vec<&ClaimMapperSettings> = mappers
        .iter()
        .map(ClaimMapper::settings)
        .filter(|settings| settings.applies(target, scopes))
        .collect();
    applying.sort_by(|one, other| one.claim.cmp(&other.claim));
    let mut claims = Map::new();
    for settings in applying {
        if let Some(value) = value_of(&settings.source, facts) {
            claims.insert(settings.claim.clone(), value);
        }
    }
    claims
}

/// Adds `mapped` to the `claims` Hodor wrote, after them. A claim Hodor
/// wrote is never replaced: a mapper cannot name one, and this keeps it so
/// whatever is stored.
pub fn add_mapped_claims(claims: &mut Value, mapped: &Map<String, Value>) {
    if let Some(object) = claims.as_object_mut() {
        for (name, value) in mapped {
            if !is_reserved(name) && !object.contains_key(name) {
                object.insert(name.clone(), value.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests;
