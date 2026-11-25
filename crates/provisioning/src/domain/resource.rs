//! SCIM's Users and Groups, mapped to and from the identity context's
//! users and groups.
//!
//! Specified in `docs/architecture/contexts/provisioning.md`, "Users" and
//! "Groups". Reading a request turns a JSON body into what the use cases
//! need; writing a resource turns a user or a group, with what this
//! context keeps of it, into the JSON a SCIM client reads.

use crate::domain::attribute::{
    ENTERPRISE_USER_SCHEMA, GROUP_SCHEMA, GroupAttribute, USER_SCHEMA, UserAttribute,
};
use crate::domain::error::{MUTABILITY, invalid_syntax, invalid_value};
use crate::domain::evaluate::{Fact, Facts};
use crate::domain::patch::Shape;
use crate::domain::version::version_of;
use hodor_identity::api::{
    Group, GroupMember, IdentifierKind, LoginIdentifier, NormalizedIdentifier, User, UserKind,
    UserStatus,
};
use hodor_kernel::{DomainError, GroupId, Timestamp, UserId};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use time::format_description::well_known::Rfc3339;

/// The most characters of each text attribute this context keeps.
pub const MAX_KEPT_CHARACTERS: usize = 256;
/// The most members a group takes in one request.
pub const MAX_MEMBERS_PER_REQUEST: usize = 1000;
/// Why the sessions and grants of a deprovisioned person ended.
pub const DEPROVISIONED: &str = "deprovisioned";

/// What a `PATCH` of a user needs to know of its attributes.
pub const USER_SHAPE: Shape = Shape {
    core: USER_SCHEMA,
    extensions: &[ENTERPRISE_USER_SCHEMA],
    read_only: &["id", "meta", "groups"],
    multi_valued: &[
        "emails",
        "phoneNumbers",
        "ims",
        "photos",
        "addresses",
        "entitlements",
        "roles",
        "x509Certificates",
    ],
};
/// What a `PATCH` of a group needs to know of its attributes.
pub const GROUP_SHAPE: Shape = Shape {
    core: GROUP_SCHEMA,
    extensions: &[],
    read_only: &["id", "meta"],
    multi_valued: &["members"],
};

/// What SCIM carries of a user that the identity context has no place
/// for. Each value is text of 1 to 256 characters.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UserSupplement {
    /// `externalId`.
    pub external_id: Option<String>,
    /// `name.formatted`.
    pub formatted_name: Option<String>,
    /// `name.givenName`.
    pub given_name: Option<String>,
    /// `name.familyName`.
    pub family_name: Option<String>,
    /// `employeeNumber`, of the enterprise extension.
    pub employee_number: Option<String>,
    /// `costCenter`, of the enterprise extension.
    pub cost_center: Option<String>,
    /// `organization`, of the enterprise extension.
    pub organization: Option<String>,
    /// `division`, of the enterprise extension.
    pub division: Option<String>,
    /// `department`, of the enterprise extension.
    pub department: Option<String>,
    /// `manager.value`, of the enterprise extension.
    pub manager: Option<String>,
    /// The `type` of each email address, by the address in its normalized
    /// form.
    pub email_types: BTreeMap<String, String>,
}

impl UserSupplement {
    /// Whether it holds no value at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    fn has_enterprise(&self) -> bool {
        self.employee_number.is_some()
            || self.cost_center.is_some()
            || self.organization.is_some()
            || self.division.is_some()
            || self.department.is_some()
            || self.manager.is_some()
    }
}

/// A user's supplement as it is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredUserSupplement {
    /// The user of the identity context it belongs to.
    pub user_id: UserId,
    /// The values.
    pub supplement: UserSupplement,
    /// When it was first stored.
    pub created_at: Timestamp,
    /// When it last changed.
    pub updated_at: Timestamp,
    /// When a `DELETE` deprovisioned the user while the policy was to
    /// deactivate; from then on SCIM does not show them while they stay
    /// Deactivated.
    pub removed_at: Option<Timestamp>,
}

/// What SCIM carries of a group that the identity context has no place
/// for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GroupSupplement {
    /// `externalId`.
    pub external_id: Option<String>,
}

/// A group's supplement as it is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredGroupSupplement {
    /// The group of the identity context it belongs to.
    pub group_id: GroupId,
    /// The values.
    pub supplement: GroupSupplement,
    /// When it was first stored.
    pub created_at: Timestamp,
    /// When it, or the group's members through SCIM, last changed.
    pub updated_at: Timestamp,
}

/// What a request to create or replace a user asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRequest {
    /// The username, when `userName` is one.
    pub username: Option<NormalizedIdentifier>,
    /// Every email address, the primary one first, without repeats; the
    /// `userName` first when it is an address.
    pub emails: Vec<NormalizedIdentifier>,
    /// The display name: `displayName`, or else `name.formatted`.
    pub display_name: Option<String>,
    /// `active`; `true` when the request leaves it out.
    pub active: bool,
    /// What this context keeps.
    pub supplement: UserSupplement,
}

impl UserRequest {
    /// Every login identifier the user must have, the `userName` first.
    #[must_use]
    pub fn identifiers(&self) -> Vec<NormalizedIdentifier> {
        self.username
            .iter()
            .chain(self.emails.iter())
            .cloned()
            .collect()
    }
}

/// What a member of a group is said to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberKind {
    /// `User`.
    User,
    /// `Group`.
    Group,
}

/// A member a request names: an identifier, and what it is said to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberReference {
    /// The identifier of a user or a group, as a UUID.
    pub value: String,
    /// `type`, when the request gives it.
    pub kind: Option<MemberKind>,
}

/// What a request to create or replace a group asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRequest {
    /// `displayName`: the group's name.
    pub display_name: String,
    /// What this context keeps.
    pub supplement: GroupSupplement,
    /// The direct members, without repeats.
    pub members: Vec<MemberReference>,
}

/// The field of `object` whose name is `name`, compared without regard to
/// case, as SCIM compares attribute names.
fn field<'a>(object: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
    object
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
        .filter(|value| !value.is_null())
}

fn object_of<'a>(value: &'a Value, name: &str) -> Result<&'a Map<String, Value>, DomainError> {
    value
        .as_object()
        .ok_or_else(|| invalid_value(format!("{name} is an object")))
}

fn text_of<'a>(value: &'a Value, name: &str) -> Result<&'a str, DomainError> {
    value
        .as_str()
        .ok_or_else(|| invalid_value(format!("{name} is a string")))
}

/// A text attribute this context keeps: 1 to 256 characters without
/// control characters, or no value when it is missing or empty.
fn kept(
    object: &Map<String, Value>,
    name: &str,
    called: &str,
) -> Result<Option<String>, DomainError> {
    let Some(value) = field(object, name) else {
        return Ok(None);
    };
    let text = text_of(value, called)?;
    if text.is_empty() {
        return Ok(None);
    }
    if text.chars().count() > MAX_KEPT_CHARACTERS {
        return Err(invalid_value(format!(
            "{called} holds at most {MAX_KEPT_CHARACTERS} characters"
        )));
    }
    if text.chars().any(char::is_control) {
        return Err(invalid_value(format!(
            "{called} holds no control characters"
        )));
    }
    Ok(Some(text.to_owned()))
}

/// A boolean, written as JSON's or, as some SCIM clients write it, as the
/// string `"true"` or `"false"` in any case.
fn boolean(value: &Value, called: &str) -> Result<bool, DomainError> {
    match value {
        Value::Bool(value) => Ok(*value),
        Value::String(text) if text.eq_ignore_ascii_case("true") => Ok(true),
        Value::String(text) if text.eq_ignore_ascii_case("false") => Ok(false),
        _ => Err(invalid_value(format!("{called} is true or false"))),
    }
}

fn body_object(body: &Value) -> Result<&Map<String, Value>, DomainError> {
    body.as_object()
        .ok_or_else(|| invalid_syntax("the body is not a JSON object"))
}

/// Checks that `schemas` names `core`, and no schema but `core` and
/// `extensions`.
fn check_schemas(
    object: &Map<String, Value>,
    core: &str,
    extensions: &[&str],
) -> Result<(), DomainError> {
    let named = field(object, "schemas")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_syntax(format!("schemas is a list that names {core}")))?;
    let mut found = false;
    for schema in named {
        let schema = schema
            .as_str()
            .ok_or_else(|| invalid_syntax("schemas is a list of strings"))?;
        if schema.eq_ignore_ascii_case(core) {
            found = true;
        } else if !extensions
            .iter()
            .any(|known| schema.eq_ignore_ascii_case(known))
        {
            return Err(invalid_syntax(format!(
                "the schema {schema} is not known here"
            )));
        }
    }
    if found {
        Ok(())
    } else {
        Err(invalid_syntax(format!("schemas names {core}")))
    }
}

/// What a login identifier refused for its rules is, as a SCIM value.
fn identifier(kind: IdentifierKind, value: &str) -> Result<NormalizedIdentifier, DomainError> {
    NormalizedIdentifier::parse(kind, value)
        .map_err(|error| invalid_value(error.message().to_owned()))
}

/// Reads the body of a request that creates or replaces a user.
///
/// # Errors
///
/// `Invalid` with code `provisioning.invalid_syntax` for a body that is
/// not a JSON object of the User schema, `provisioning.mutability` for a
/// `password`, and `provisioning.invalid_value` for a value that breaks a
/// rule.
pub fn read_user(body: &Value) -> Result<UserRequest, DomainError> {
    let object = body_object(body)?;
    check_schemas(object, USER_SCHEMA, &[ENTERPRISE_USER_SCHEMA])?;
    if field(object, "password").is_some() {
        return Err(DomainError::invalid(
            MUTABILITY,
            "passwords are not set through SCIM",
        ));
    }
    let user_name = field(object, "userName")
        .map(|value| text_of(value, "userName"))
        .transpose()?
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| invalid_value("userName is required"))?;
    let user_name = if user_name.contains('@') {
        identifier(IdentifierKind::Email, user_name)?
    } else {
        identifier(IdentifierKind::Username, user_name)?
    };

    let name = field(object, "name")
        .map(|value| object_of(value, "name"))
        .transpose()?;
    let empty = Map::new();
    let name = name.unwrap_or(&empty);
    let enterprise = field(object, ENTERPRISE_USER_SCHEMA)
        .map(|value| object_of(value, ENTERPRISE_USER_SCHEMA))
        .transpose()?
        .unwrap_or(&empty);
    let manager = field(enterprise, "manager")
        .map(|value| object_of(value, "manager"))
        .transpose()?
        .unwrap_or(&empty);
    let supplement = UserSupplement {
        external_id: kept(object, "externalId", "externalId")?,
        formatted_name: kept(name, "formatted", "name.formatted")?,
        given_name: kept(name, "givenName", "name.givenName")?,
        family_name: kept(name, "familyName", "name.familyName")?,
        employee_number: kept(enterprise, "employeeNumber", "employeeNumber")?,
        cost_center: kept(enterprise, "costCenter", "costCenter")?,
        organization: kept(enterprise, "organization", "organization")?,
        division: kept(enterprise, "division", "division")?,
        department: kept(enterprise, "department", "department")?,
        manager: kept(manager, "value", "manager.value")?,
        email_types: BTreeMap::new(),
    };

    let display_name = field(object, "displayName")
        .map(|value| text_of(value, "displayName"))
        .transpose()?
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .or_else(|| supplement.formatted_name.clone());

    let active = field(object, "active")
        .map(|value| boolean(value, "active"))
        .transpose()?
        .unwrap_or(true);

    let mut marked: Option<NormalizedIdentifier> = None;
    let mut addresses: Vec<NormalizedIdentifier> = Vec::new();
    let mut email_types: BTreeMap<String, String> = BTreeMap::new();
    if let Some(emails) = field(object, "emails") {
        let emails = emails
            .as_array()
            .ok_or_else(|| invalid_value("emails is a list"))?;
        for email in emails {
            let email = object_of(email, "an email")?;
            let value = field(email, "value")
                .map(|value| text_of(value, "an email's value"))
                .transpose()?
                .ok_or_else(|| invalid_value("an email has a value"))?;
            let address = identifier(IdentifierKind::Email, value)?;
            let primary = field(email, "primary")
                .map(|value| boolean(value, "an email's primary"))
                .transpose()?
                .unwrap_or(false);
            if let Some(kind) = kept(email, "type", "an email's type")? {
                email_types.insert(address.normalized().to_owned(), kind);
            }
            if primary {
                if marked
                    .as_ref()
                    .is_some_and(|other| !other.same_as(&address))
                {
                    return Err(invalid_value("at most one email address is primary"));
                }
                marked = Some(address.clone());
            }
            addresses.push(address);
        }
    }
    let (username, first) = match user_name.kind() {
        IdentifierKind::Email => (None, Some(user_name)),
        IdentifierKind::Username => (Some(user_name), marked),
    };
    let mut emails: Vec<NormalizedIdentifier> = Vec::new();
    for address in first.into_iter().chain(addresses) {
        if !emails.iter().any(|known| known.same_as(&address)) {
            emails.push(address);
        }
    }
    let mut supplement = supplement;
    supplement.email_types = email_types;
    Ok(UserRequest {
        username,
        emails,
        display_name,
        active,
        supplement,
    })
}

/// Reads the body of a request that creates or replaces a group.
///
/// # Errors
///
/// As [`read_user`], and `provisioning.invalid_value` for more than
/// [`MAX_MEMBERS_PER_REQUEST`] members or a member that cannot be a user
/// or a group.
pub fn read_group(body: &Value) -> Result<GroupRequest, DomainError> {
    read_group_bounded(body, Some(MAX_MEMBERS_PER_REQUEST))
}

/// As [`read_group`], with `bound` on the members the body lists, or none:
/// the result of a `PATCH` holds every member of the group, and the bound
/// is on what its operations name.
///
/// # Errors
///
/// As [`read_group`].
pub fn read_group_bounded(body: &Value, bound: Option<usize>) -> Result<GroupRequest, DomainError> {
    let object = body_object(body)?;
    check_schemas(object, GROUP_SCHEMA, &[])?;
    let display_name = field(object, "displayName")
        .map(|value| text_of(value, "displayName"))
        .transpose()?
        .filter(|name| !name.is_empty())
        .ok_or_else(|| invalid_value("displayName is required"))?
        .to_owned();
    let supplement = GroupSupplement {
        external_id: kept(object, "externalId", "externalId")?,
    };
    let mut members: Vec<MemberReference> = Vec::new();
    if let Some(listed) = field(object, "members") {
        let listed = listed
            .as_array()
            .ok_or_else(|| invalid_value("members is a list"))?;
        if bound.is_some_and(|bound| listed.len() > bound) {
            return Err(invalid_value(format!(
                "a group takes at most {MAX_MEMBERS_PER_REQUEST} members in one request"
            )));
        }
        for member in listed {
            let member = object_of(member, "a member")?;
            let value = field(member, "value")
                .map(|value| text_of(value, "a member's value"))
                .transpose()?
                .ok_or_else(|| invalid_value("a member has a value"))?;
            let value = value
                .parse::<UserId>()
                .map_err(|_| {
                    invalid_value(format!(
                        "the member {value} is not a user or a group of the tenant"
                    ))
                })?
                .to_string();
            let kind = field(member, "type")
                .map(|kind| match text_of(kind, "a member's type")? {
                    kind if kind.eq_ignore_ascii_case("User") => Ok(MemberKind::User),
                    kind if kind.eq_ignore_ascii_case("Group") => Ok(MemberKind::Group),
                    _ => Err(invalid_value("a member's type is User or Group")),
                })
                .transpose()?;
            if !members.iter().any(|known| known.value == value) {
                members.push(MemberReference { value, kind });
            }
        }
    }
    Ok(GroupRequest {
        display_name,
        supplement,
        members,
    })
}

/// Whether SCIM shows a user: a person, not marked Deleted, and not
/// deprovisioned by a `DELETE` while they stay Deactivated.
#[must_use]
pub fn shown(user: &User, stored: Option<&StoredUserSupplement>) -> bool {
    let removed = user.status() == UserStatus::Deactivated
        && stored.is_some_and(|stored| stored.removed_at.is_some());
    user.snapshot().kind == UserKind::Human && user.status() != UserStatus::Deleted && !removed
}

/// The user's userName identifier: its primary username, or else its
/// primary email address.
#[must_use]
pub fn user_name_of(user: &User) -> Option<&LoginIdentifier> {
    user.primary_identifier(IdentifierKind::Username)
        .or_else(|| user.primary_identifier(IdentifierKind::Email))
}

/// When a user last changed, as SCIM says it: the later of the identity
/// context's change and this context's.
#[must_use]
pub fn user_last_modified(user: &User, stored: Option<&StoredUserSupplement>) -> Timestamp {
    let updated = user.snapshot().updated_at;
    stored.map_or(updated, |stored| updated.max(stored.updated_at))
}

/// When a group last changed, as SCIM says it.
#[must_use]
pub fn group_last_modified(group: &Group, stored: Option<&StoredGroupSupplement>) -> Timestamp {
    let updated = group.snapshot().updated_at;
    stored.map_or(updated, |stored| updated.max(stored.updated_at))
}

fn time_text(at: Timestamp) -> String {
    at.format(&Rfc3339).unwrap_or_default()
}

/// A user as a SCIM client reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserResource {
    /// The user of the identity context.
    pub user: User,
    /// What this context keeps of it, if anything.
    pub stored: Option<StoredUserSupplement>,
    /// The groups it is directly in, with their names.
    pub groups: Vec<(GroupId, String)>,
}

impl UserResource {
    /// The user's display name, or else its userName: what a group's
    /// member reads as.
    #[must_use]
    pub fn display(user: &User) -> String {
        user.snapshot()
            .profile
            .display_name
            .clone()
            .or_else(|| user_name_of(user).map(|name| name.value.display().to_owned()))
            .unwrap_or_default()
    }

    /// The resource as JSON, with its version in `meta.version`. `base`
    /// is the address of the tenant's SCIM surface, such as
    /// `https://id.example.com/t/acme/scim/v2`.
    #[must_use]
    pub fn document(&self, base: &str) -> Value {
        let mut document = self.written(base);
        document["meta"]["version"] = json!(self.version());
        document
    }

    /// The resource's version: the same at every address of the surface.
    #[must_use]
    pub fn version(&self) -> String {
        version_of(&self.written(""))
    }

    /// The resource as a `PATCH` changes it, without its version.
    #[must_use]
    pub fn patchable(&self) -> Map<String, Value> {
        match self.written("") {
            Value::Object(document) => document,
            _ => Map::new(),
        }
    }

    fn written(&self, base: &str) -> Value {
        let state = self.user.snapshot();
        let empty = UserSupplement::default();
        let supplement = self
            .stored
            .as_ref()
            .map_or(&empty, |stored| &stored.supplement);
        let mut schemas = vec![json!(USER_SCHEMA)];
        if supplement.has_enterprise() {
            schemas.push(json!(ENTERPRISE_USER_SCHEMA));
        }
        let mut document = Map::new();
        document.insert("schemas".into(), Value::Array(schemas));
        document.insert("id".into(), json!(state.id.to_string()));
        if let Some(external_id) = &supplement.external_id {
            document.insert("externalId".into(), json!(external_id));
        }
        document.insert(
            "userName".into(),
            json!(user_name_of(&self.user).map_or("", |name| name.value.display())),
        );
        let mut name = Map::new();
        for (key, value) in [
            ("formatted", &supplement.formatted_name),
            ("givenName", &supplement.given_name),
            ("familyName", &supplement.family_name),
        ] {
            if let Some(value) = value {
                name.insert(key.into(), json!(value));
            }
        }
        if !name.is_empty() {
            document.insert("name".into(), Value::Object(name));
        }
        if let Some(display_name) = &state.profile.display_name {
            document.insert("displayName".into(), json!(display_name));
        }
        let emails: Vec<Value> = state
            .identifiers
            .iter()
            .filter(|identifier| identifier.value.kind() == IdentifierKind::Email)
            .map(|identifier| {
                let mut email =
                    json!({ "value": identifier.value.display(), "primary": identifier.primary });
                if let Some(kind) = supplement.email_types.get(identifier.value.normalized()) {
                    email["type"] = json!(kind);
                }
                email
            })
            .collect();
        if !emails.is_empty() {
            document.insert("emails".into(), Value::Array(emails));
        }
        document.insert("active".into(), json!(state.status == UserStatus::Active));
        if !self.groups.is_empty() {
            let groups: Vec<Value> = self
                .groups
                .iter()
                .map(|(id, name)| {
                    json!({
                        "value": id.to_string(),
                        "display": name,
                        "type": "direct",
                        "$ref": format!("{base}/Groups/{id}"),
                    })
                })
                .collect();
            document.insert("groups".into(), Value::Array(groups));
        }
        if supplement.has_enterprise() {
            let mut enterprise = Map::new();
            for (key, value) in [
                ("employeeNumber", &supplement.employee_number),
                ("costCenter", &supplement.cost_center),
                ("organization", &supplement.organization),
                ("division", &supplement.division),
                ("department", &supplement.department),
            ] {
                if let Some(value) = value {
                    enterprise.insert(key.into(), json!(value));
                }
            }
            if let Some(manager) = &supplement.manager {
                enterprise.insert("manager".into(), json!({ "value": manager }));
            }
            document.insert(ENTERPRISE_USER_SCHEMA.into(), Value::Object(enterprise));
        }
        document.insert(
            "meta".into(),
            json!({
                "resourceType": "User",
                "created": time_text(state.created_at),
                "lastModified": time_text(user_last_modified(&self.user, self.stored.as_ref())),
                "location": format!("{base}/Users/{}", state.id),
            }),
        );
        Value::Object(document)
    }
}

/// A member of a group, with what it reads as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberView {
    /// The member.
    pub member: GroupMember,
    /// A user's display name or else its userName; a group's name.
    pub display: String,
}

/// A group as a SCIM client reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupResource {
    /// The group of the identity context.
    pub group: Group,
    /// What this context keeps of it, if anything.
    pub stored: Option<StoredGroupSupplement>,
    /// Its direct members.
    pub members: Vec<MemberView>,
}

impl GroupResource {
    /// The resource as JSON, with its version; `base` as for
    /// [`UserResource::document`].
    #[must_use]
    pub fn document(&self, base: &str) -> Value {
        let mut document = self.written(base);
        document["meta"]["version"] = json!(self.version());
        document
    }

    /// The resource's version.
    #[must_use]
    pub fn version(&self) -> String {
        version_of(&self.written(""))
    }

    /// The resource as a `PATCH` changes it, without its version.
    #[must_use]
    pub fn patchable(&self) -> Map<String, Value> {
        match self.written("") {
            Value::Object(document) => document,
            _ => Map::new(),
        }
    }

    fn written(&self, base: &str) -> Value {
        let state = self.group.snapshot();
        let mut document = Map::new();
        document.insert("schemas".into(), json!([GROUP_SCHEMA]));
        document.insert("id".into(), json!(state.id.to_string()));
        if let Some(external_id) = self
            .stored
            .as_ref()
            .and_then(|stored| stored.supplement.external_id.as_ref())
        {
            document.insert("externalId".into(), json!(external_id));
        }
        document.insert("displayName".into(), json!(state.name.as_str()));
        let members: Vec<Value> = self
            .members
            .iter()
            .map(|view| {
                let (kind, path) = match view.member {
                    GroupMember::User(_) => ("User", "Users"),
                    GroupMember::Group(_) => ("Group", "Groups"),
                };
                let id = view.member.id_text();
                json!({
                    "value": id,
                    "type": kind,
                    "display": view.display,
                    "$ref": format!("{base}/{path}/{id}"),
                })
            })
            .collect();
        document.insert("members".into(), Value::Array(members));
        document.insert(
            "meta".into(),
            json!({
                "resourceType": "Group",
                "created": time_text(state.created_at),
                "lastModified": time_text(group_last_modified(&self.group, self.stored.as_ref())),
                "location": format!("{base}/Groups/{}", state.id),
            }),
        );
        Value::Object(document)
    }
}

/// A user's values for the attributes a filter may name.
#[derive(Debug, Clone, Copy)]
pub struct UserFacts<'a> {
    /// The user of the identity context.
    pub user: &'a User,
    /// What this context keeps of it.
    pub stored: Option<&'a StoredUserSupplement>,
}

impl Facts<UserAttribute> for UserFacts<'_> {
    fn value(&self, attribute: UserAttribute) -> Option<Fact> {
        let state = self.user.snapshot();
        let kept = |pick: fn(&UserSupplement) -> &Option<String>| {
            self.stored
                .and_then(|stored| pick(&stored.supplement).clone())
                .map(Fact::Text)
        };
        match attribute {
            UserAttribute::Id => Some(Fact::Text(state.id.to_string())),
            UserAttribute::ExternalId => kept(|supplement| &supplement.external_id),
            UserAttribute::UserName => {
                user_name_of(self.user).map(|name| Fact::Text(name.value.normalized().to_owned()))
            }
            UserAttribute::DisplayName => state.profile.display_name.clone().map(Fact::Text),
            UserAttribute::GivenName => kept(|supplement| &supplement.given_name),
            UserAttribute::FamilyName => kept(|supplement| &supplement.family_name),
            UserAttribute::Active => Some(Fact::Boolean(state.status == UserStatus::Active)),
            UserAttribute::Created => Some(Fact::DateTime(state.created_at)),
            UserAttribute::LastModified => {
                Some(Fact::DateTime(user_last_modified(self.user, self.stored)))
            }
            UserAttribute::Emails => None,
        }
    }

    fn values(&self, attribute: UserAttribute) -> Vec<Fact> {
        match attribute {
            UserAttribute::Emails => self
                .user
                .identifiers()
                .iter()
                .filter(|identifier| identifier.value.kind() == IdentifierKind::Email)
                .map(|identifier| Fact::Text(identifier.value.normalized().to_owned()))
                .collect(),
            _ => Vec::new(),
        }
    }
}

/// A group's values for the attributes a filter may name.
#[derive(Debug, Clone, Copy)]
pub struct GroupFacts<'a> {
    /// The group of the identity context.
    pub group: &'a Group,
    /// What this context keeps of it.
    pub stored: Option<&'a StoredGroupSupplement>,
    /// Its direct members.
    pub members: &'a [GroupMember],
}

impl Facts<GroupAttribute> for GroupFacts<'_> {
    fn value(&self, attribute: GroupAttribute) -> Option<Fact> {
        let state = self.group.snapshot();
        match attribute {
            GroupAttribute::Id => Some(Fact::Text(state.id.to_string())),
            GroupAttribute::ExternalId => self
                .stored
                .and_then(|stored| stored.supplement.external_id.clone())
                .map(Fact::Text),
            GroupAttribute::DisplayName => Some(Fact::Text(state.name.as_str().to_owned())),
            GroupAttribute::Created => Some(Fact::DateTime(state.created_at)),
            GroupAttribute::LastModified => {
                Some(Fact::DateTime(group_last_modified(self.group, self.stored)))
            }
            GroupAttribute::Members => None,
        }
    }

    fn values(&self, attribute: GroupAttribute) -> Vec<Fact> {
        match attribute {
            GroupAttribute::Members => self
                .members
                .iter()
                .map(|member| Fact::Text(member.id_text()))
                .collect(),
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_body(extra: Value) -> Value {
        let mut body = json!({
            "schemas": [USER_SCHEMA],
            "userName": "bjensen",
        });
        if let (Some(body), Some(extra)) = (body.as_object_mut(), extra.as_object()) {
            body.extend(extra.clone());
        }
        body
    }

    #[test]
    fn a_username_and_its_addresses_are_read_with_the_primary_first() {
        let read = read_user(&user_body(json!({
            "emails": [
                { "value": "babs@jensen.org" },
                { "value": "BJensen@Example.com", "primary": true },
                { "value": "babs@jensen.org" }
            ],
            "name": { "formatted": "Barbara Jensen", "givenName": "Barbara" },
        })))
        .expect("read");
        assert_eq!(
            read.username.as_ref().map(NormalizedIdentifier::normalized),
            Some("bjensen")
        );
        let emails: Vec<&str> = read
            .emails
            .iter()
            .map(NormalizedIdentifier::normalized)
            .collect();
        assert_eq!(emails, ["bjensen@example.com", "babs@jensen.org"]);
        assert_eq!(read.display_name.as_deref(), Some("Barbara Jensen"));
        assert!(read.active);
        assert_eq!(read.supplement.given_name.as_deref(), Some("Barbara"));
    }

    #[test]
    fn a_user_name_with_an_at_sign_is_the_primary_address() {
        let read = read_user(&json!({
            "schemas": [USER_SCHEMA],
            "userName": "ana@example.com",
            "emails": [{ "value": "ana@home.org", "primary": true }],
            "active": false,
        }))
        .expect("read");
        assert_eq!(read.username, None);
        let emails: Vec<&str> = read
            .emails
            .iter()
            .map(NormalizedIdentifier::normalized)
            .collect();
        assert_eq!(emails, ["ana@example.com", "ana@home.org"]);
        assert!(!read.active);
    }

    #[test]
    fn what_cannot_be_read_is_refused_with_its_code() {
        let code = |body: Value| read_user(&body).expect_err("refused").code().to_owned();
        assert_eq!(code(json!([])), "provisioning.invalid_syntax");
        assert_eq!(
            code(json!({ "userName": "bjensen" })),
            "provisioning.invalid_syntax"
        );
        assert_eq!(
            code(json!({ "schemas": [USER_SCHEMA, "urn:example:other"], "userName": "bjensen" })),
            "provisioning.invalid_syntax"
        );
        assert_eq!(
            code(json!({ "schemas": [USER_SCHEMA] })),
            "provisioning.invalid_value"
        );
        assert_eq!(code(user_body(json!({ "password": "secret" }))), MUTABILITY);
        assert_eq!(
            code(user_body(json!({ "userName": "not a username" }))),
            "provisioning.invalid_value"
        );
        assert_eq!(
            code(user_body(json!({ "externalId": "x".repeat(257) }))),
            "provisioning.invalid_value"
        );
        assert_eq!(
            code(user_body(json!({ "emails": [
                { "value": "a@example.com", "primary": true },
                { "value": "b@example.com", "primary": true }
            ] }))),
            "provisioning.invalid_value"
        );
    }

    #[test]
    fn a_group_takes_a_bounded_number_of_members() {
        let member = json!({ "value": UserId::generate().to_string() });
        let body = |count: usize| {
            json!({
                "schemas": [GROUP_SCHEMA],
                "displayName": "finance",
                "members": vec![member.clone(); count],
            })
        };
        let read = read_group(&body(MAX_MEMBERS_PER_REQUEST)).expect("at the bound");
        assert_eq!(read.members.len(), 1, "repeats are one member");
        assert_eq!(
            read_group(&body(MAX_MEMBERS_PER_REQUEST + 1))
                .expect_err("past the bound")
                .code(),
            "provisioning.invalid_value"
        );
        assert!(
            read_group(&json!({
                "schemas": [GROUP_SCHEMA],
                "displayName": "finance",
                "members": [{ "value": "not-an-identifier" }],
            }))
            .is_err()
        );
    }
}
