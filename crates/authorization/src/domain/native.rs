//! Native role-based access control: the permissions of a resource server,
//! roles that hold them and include other roles, and assignments of roles
//! to users and clients.
//!
//! See `docs/architecture/contexts/authorization.md`, "Native role-based
//! access control".

use crate::domain::condition::Condition;
use crate::domain::request::{
    Action, ApplicationReference, Namespace, OrganizationReference, Subject, is_name,
};
use crate::domain::role::{Permission, Role};
use hodor_kernel::{DomainError, Timestamp};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// The longest description of a permission or a role.
pub const MAX_DESCRIPTION_LENGTH: usize = 500;
/// The most permissions one role may hold.
pub const MAX_ROLE_PERMISSIONS: usize = 200;
/// The most roles one role may include.
pub const MAX_INCLUDED_ROLES: usize = 50;
/// How deep inclusion may go: a role that includes a role that includes a
/// role is two deep.
pub const MAX_INCLUSION_DEPTH: usize = 10;

fn invalid(code: &'static str, message: &'static str) -> DomainError {
    DomainError::invalid(code, message)
}

fn reserved() -> DomainError {
    invalid(
        "authorization.namespace_reserved",
        "Hodor's administration has only its built-in roles and permissions",
    )
}

fn checked_description(description: &str) -> Result<String, DomainError> {
    if description.chars().count() > MAX_DESCRIPTION_LENGTH
        || description.chars().any(char::is_control)
    {
        return Err(invalid(
            "authorization.description_invalid",
            "a description has at most 500 characters and no control character",
        ));
    }
    Ok(description.to_owned())
}

/// A permission written `resource:action`: the resource kind and the
/// action of a request.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct PermissionName(String);

impl PermissionName {
    /// Reads a permission name.
    ///
    /// # Errors
    ///
    /// Returns `authorization.permission_invalid` unless the value is two
    /// names joined by one `:`, each following the rules of a resource kind
    /// and an action.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        match value.split_once(':') {
            Some((kind, action)) if is_name(kind) && is_name(action) => Ok(Self(value.to_owned())),
            _ => Err(invalid(
                "authorization.permission_invalid",
                "a permission is written `resource:action`, each half lower-case letters, \
                 digits, `-`, `_` and `.`, starting with a letter, at most 64 characters",
            )),
        }
    }

    /// The permission a request asks for: its resource kind and action.
    #[must_use]
    pub fn of(kind: &str, action: &Action) -> Self {
        Self(format!("{kind}:{}", action.as_str()))
    }

    /// One of the fixed permissions of Hodor's administration.
    #[must_use]
    pub fn fixed(permission: Permission) -> Self {
        Self(permission.as_str().to_owned())
    }

    /// The permission as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The name of a role, unique in its namespace.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct RoleName(String);

impl RoleName {
    /// Reads a role name.
    ///
    /// # Errors
    ///
    /// Returns `authorization.role_name_invalid` unless the value is a
    /// lower-case letter followed by lower-case letters, digits, `-`, `_`
    /// and `.`, at most 64 characters.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        if is_name(value) {
            Ok(Self(value.to_owned()))
        } else {
            Err(invalid(
                "authorization.role_name_invalid",
                "a role's name is lower-case letters, digits, `-`, `_` and `.`, starting with a \
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

/// A role, by its namespace and its name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct RoleKey {
    /// The resource server the role belongs to.
    pub namespace: Namespace,
    /// Its name in that namespace.
    pub name: RoleName,
}

impl RoleKey {
    /// A role by namespace and name.
    #[must_use]
    pub const fn new(namespace: Namespace, name: RoleName) -> Self {
        Self { namespace, name }
    }

    /// One of the built-in roles of Hodor's administration.
    #[must_use]
    pub fn built_in(role: Role) -> Self {
        Self {
            namespace: Namespace::administration(),
            name: RoleName(role.as_str().to_owned()),
        }
    }

    /// The role written `namespace#name`, as decisions name it.
    #[must_use]
    pub fn reference(&self) -> String {
        format!("{}#{}", self.namespace.as_str(), self.name.as_str())
    }
}

/// A permission a tenant declared for one of its resource servers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionDefinition {
    namespace: Namespace,
    name: PermissionName,
    description: String,
}

impl PermissionDefinition {
    /// Declares a permission.
    ///
    /// # Errors
    ///
    /// - `authorization.namespace_reserved` for `hodor:admin`.
    /// - `authorization.description_invalid` for a description longer than
    ///   500 characters or holding a control character.
    pub fn new(
        namespace: Namespace,
        name: PermissionName,
        description: &str,
    ) -> Result<Self, DomainError> {
        if namespace.is_administration() {
            return Err(reserved());
        }
        Ok(Self {
            namespace,
            name,
            description: checked_description(description)?,
        })
    }

    /// The resource server it belongs to.
    #[must_use]
    pub const fn namespace(&self) -> &Namespace {
        &self.namespace
    }

    /// The permission.
    #[must_use]
    pub const fn name(&self) -> &PermissionName {
        &self.name
    }

    /// What it allows, in words.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }
}

/// What a role is made of, as given when it is defined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleContents {
    /// What it is for, in words.
    pub description: String,
    /// The permissions of its own namespace it holds.
    pub permissions: BTreeSet<PermissionName>,
    /// The roles it includes.
    pub includes: BTreeSet<RoleKey>,
    /// The conditions some of its permissions are held with: each key is
    /// one of `permissions`.
    pub conditions: BTreeMap<PermissionName, Condition>,
}

impl RoleContents {
    /// Contents with these permissions and included roles, and no
    /// condition.
    #[must_use]
    pub fn unconditional(
        description: &str,
        permissions: BTreeSet<PermissionName>,
        includes: BTreeSet<RoleKey>,
    ) -> Self {
        Self {
            description: description.to_owned(),
            permissions,
            includes,
            conditions: BTreeMap::new(),
        }
    }
}

/// A role: a named set of permissions of one resource server, that may
/// include other roles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleDefinition {
    key: RoleKey,
    contents: RoleContents,
    created_at: Timestamp,
    updated_at: Timestamp,
}

impl RoleDefinition {
    /// Defines a role. What it may hold and include is checked against the
    /// tenant's other roles by [`RoleGraph::check`].
    ///
    /// # Errors
    ///
    /// - `authorization.namespace_reserved` for a role of `hodor:admin`, or
    ///   one that includes a role of `hodor:admin`.
    /// - `authorization.description_invalid`.
    /// - `authorization.too_many_permissions` beyond 200 permissions.
    /// - `authorization.too_many_included_roles` beyond 50 included roles.
    /// - `authorization.role_cycle` for a role that includes itself.
    pub fn new(key: RoleKey, contents: RoleContents, now: Timestamp) -> Result<Self, DomainError> {
        let contents = Self::checked(&key, contents)?;
        Ok(Self {
            key,
            contents,
            created_at: now,
            updated_at: now,
        })
    }

    /// The same role with new contents, defined again at `now`.
    ///
    /// # Errors
    ///
    /// The errors of [`RoleDefinition::new`].
    pub fn replaced(&self, contents: RoleContents, now: Timestamp) -> Result<Self, DomainError> {
        let contents = Self::checked(&self.key, contents)?;
        Ok(Self {
            key: self.key.clone(),
            contents,
            created_at: self.created_at,
            updated_at: now,
        })
    }

    /// A role read back from storage.
    ///
    /// # Errors
    ///
    /// The errors of [`RoleDefinition::new`]: what is stored must still
    /// follow the rules.
    pub fn restore(
        key: RoleKey,
        contents: RoleContents,
        created_at: Timestamp,
        updated_at: Timestamp,
    ) -> Result<Self, DomainError> {
        let contents = Self::checked(&key, contents)?;
        Ok(Self {
            key,
            contents,
            created_at,
            updated_at,
        })
    }

    /// One of the built-in roles of Hodor's administration, with exactly
    /// the permissions [`Role::permissions`] gives it.
    #[must_use]
    pub fn built_in(role: Role) -> Self {
        Self {
            key: RoleKey::built_in(role),
            contents: RoleContents {
                description: String::new(),
                permissions: role
                    .permissions()
                    .iter()
                    .map(|permission| PermissionName::fixed(*permission))
                    .collect(),
                includes: BTreeSet::new(),
                conditions: BTreeMap::new(),
            },
            created_at: Timestamp::UNIX_EPOCH,
            updated_at: Timestamp::UNIX_EPOCH,
        }
    }

    fn checked(key: &RoleKey, contents: RoleContents) -> Result<RoleContents, DomainError> {
        if key.namespace.is_administration()
            || contents
                .includes
                .iter()
                .any(|included| included.namespace.is_administration())
        {
            return Err(reserved());
        }
        let description = checked_description(&contents.description)?;
        if contents.permissions.len() > MAX_ROLE_PERMISSIONS {
            return Err(invalid(
                "authorization.too_many_permissions",
                "a role holds at most 200 permissions",
            ));
        }
        if contents.includes.len() > MAX_INCLUDED_ROLES {
            return Err(invalid(
                "authorization.too_many_included_roles",
                "a role includes at most 50 roles",
            ));
        }
        if contents.includes.contains(key) {
            return Err(cycle());
        }
        if let Some(stray) = contents
            .conditions
            .keys()
            .find(|permission| !contents.permissions.contains(*permission))
        {
            return Err(invalid(
                "authorization.condition_without_permission",
                "a condition is given only for a permission the role holds",
            )
            .with_detail(stray.as_str()));
        }
        Ok(RoleContents {
            description,
            ..contents
        })
    }

    /// The role's namespace and name.
    #[must_use]
    pub const fn key(&self) -> &RoleKey {
        &self.key
    }

    /// What it is made of.
    #[must_use]
    pub const fn contents(&self) -> &RoleContents {
        &self.contents
    }

    /// When it was first defined.
    #[must_use]
    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// When it was last defined.
    #[must_use]
    pub const fn updated_at(&self) -> Timestamp {
        self.updated_at
    }
}

fn cycle() -> DomainError {
    invalid(
        "authorization.role_cycle",
        "a role cannot include itself, directly or through other roles",
    )
}

/// A tenant's roles, with what inclusion makes of them.
#[derive(Debug, Clone, Default)]
pub struct RoleGraph {
    roles: BTreeMap<RoleKey, RoleDefinition>,
}

impl RoleGraph {
    /// The graph of these roles.
    #[must_use]
    pub fn new(roles: impl IntoIterator<Item = RoleDefinition>) -> Self {
        Self {
            roles: roles
                .into_iter()
                .map(|role| (role.key.clone(), role))
                .collect(),
        }
    }

    /// The built-in roles of Hodor's administration.
    #[must_use]
    pub fn built_in() -> Self {
        Self::new(Role::ALL.into_iter().map(RoleDefinition::built_in))
    }

    /// A role, if the graph has it.
    #[must_use]
    pub fn get(&self, key: &RoleKey) -> Option<&RoleDefinition> {
        self.roles.get(key)
    }

    /// Every role, ordered by namespace and name.
    pub fn roles(&self) -> impl Iterator<Item = &RoleDefinition> {
        self.roles.values()
    }

    /// The roles that include `key`, ordered.
    #[must_use]
    pub fn including(&self, key: &RoleKey) -> Vec<&RoleKey> {
        self.roles
            .values()
            .filter(|role| role.contents.includes.contains(key))
            .map(|role| &role.key)
            .collect()
    }

    /// Whether holding `key` is holding a role of `namespace`: `key`
    /// itself, or a role it includes as far as inclusion goes, belongs to
    /// it. A role the graph does not have includes nothing.
    #[must_use]
    pub fn reaches(&self, key: &RoleKey, namespace: &Namespace) -> bool {
        let mut pending = vec![key];
        let mut seen = BTreeSet::new();
        while let Some(next) = pending.pop() {
            if !seen.insert(next) {
                continue;
            }
            if &next.namespace == namespace {
                return true;
            }
            if let Some(role) = self.roles.get(next) {
                pending.extend(role.contents.includes.iter());
            }
        }
        false
    }

    /// Checks that `candidate` may replace or join the graph: what it
    /// includes exists, it holds only declared permissions of its
    /// namespace, and no cycle and no chain deeper than ten roles comes of
    /// it, through it or anywhere else.
    ///
    /// # Errors
    ///
    /// - `authorization.permission_not_declared` for a permission that is
    ///   not in `declared`.
    /// - `authorization.role_not_found` for an included role that does not
    ///   exist.
    /// - `authorization.role_cycle`.
    /// - `authorization.role_inclusion_too_deep`.
    pub fn check(
        &self,
        candidate: &RoleDefinition,
        declared: &BTreeSet<PermissionName>,
    ) -> Result<(), DomainError> {
        if !candidate.contents.permissions.is_subset(declared) {
            return Err(DomainError::invalid(
                "authorization.permission_not_declared",
                "a role holds only permissions declared for its resource server",
            ));
        }
        let mut after = self.roles.clone();
        after.insert(candidate.key.clone(), candidate.clone());
        for included in &candidate.contents.includes {
            if !after.contains_key(included) {
                return Err(DomainError::invalid(
                    "authorization.role_not_found",
                    "a role includes only roles that exist",
                )
                .with_detail(included.reference()));
            }
        }
        let mut depths: BTreeMap<RoleKey, usize> = BTreeMap::new();
        for key in after.keys() {
            let depth = depth_of(&after, key, &mut depths, &mut BTreeSet::new())?;
            if depth > MAX_INCLUSION_DEPTH {
                return Err(invalid(
                    "authorization.role_inclusion_too_deep",
                    "inclusion goes at most ten roles deep",
                ));
            }
        }
        Ok(())
    }

    /// Every permission that holding `start` gives: its own and those of
    /// every role it includes, as far as inclusion goes. Included roles the
    /// graph does not have give nothing.
    #[must_use]
    pub fn permissions_held(&self, start: &RoleKey) -> BTreeSet<(Namespace, PermissionName)> {
        self.holdings(start)
            .into_iter()
            .map(|holding| (holding.namespace, holding.permission))
            .collect()
    }

    /// Every permission that holding `start` gives, each with the condition
    /// the role holding it attaches, if any. The same permission held with
    /// different conditions, or with and without one, appears once for
    /// each.
    #[must_use]
    pub fn holdings(&self, start: &RoleKey) -> BTreeSet<Holding> {
        let mut held = BTreeSet::new();
        let mut seen = BTreeSet::new();
        let mut waiting = vec![start];
        while let Some(key) = waiting.pop() {
            if !seen.insert(key) {
                continue;
            }
            let Some(role) = self.roles.get(key) else {
                continue;
            };
            held.extend(role.contents.permissions.iter().map(|permission| Holding {
                namespace: key.namespace.clone(),
                permission: permission.clone(),
                condition: role.contents.conditions.get(permission).cloned(),
            }));
            waiting.extend(role.contents.includes.iter());
        }
        held
    }
}

/// A permission held through a role, with the condition it is held with.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Holding {
    /// The resource server of the permission.
    pub namespace: Namespace,
    /// The permission.
    pub permission: PermissionName,
    /// The condition that must also hold, if any.
    pub condition: Option<Condition>,
}

/// How deep inclusion goes from `key`: zero for a role that includes
/// nothing. Fails on a cycle.
fn depth_of(
    roles: &BTreeMap<RoleKey, RoleDefinition>,
    key: &RoleKey,
    depths: &mut BTreeMap<RoleKey, usize>,
    path: &mut BTreeSet<RoleKey>,
) -> Result<usize, DomainError> {
    if let Some(depth) = depths.get(key) {
        return Ok(*depth);
    }
    if !path.insert(key.clone()) {
        return Err(cycle());
    }
    let mut depth = 0;
    if let Some(role) = roles.get(key) {
        for included in &role.contents.includes {
            depth = depth.max(depth_of(roles, included, depths, path)? + 1);
        }
    }
    path.remove(key);
    depths.insert(key.clone(), depth);
    Ok(depth)
}

/// Where an assignment applies.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AssignmentScope {
    /// Every request in the tenant.
    Tenant,
    /// Only requests made for this application.
    Application(ApplicationReference),
    /// Only requests made in this organization, by a member of it.
    Organization(OrganizationReference),
}

impl AssignmentScope {
    /// Whether it applies to a request made for `application` and in
    /// `organization`. The organization is given only when the subject is a
    /// member of the one the request names.
    #[must_use]
    pub fn applies_to(
        &self,
        application: Option<&ApplicationReference>,
        organization: Option<&OrganizationReference>,
    ) -> bool {
        match self {
            Self::Tenant => true,
            Self::Application(scoped) => application == Some(scoped),
            Self::Organization(scoped) => organization == Some(scoped),
        }
    }

    /// The organization, for an assignment scoped to one.
    #[must_use]
    pub const fn organization(&self) -> Option<&OrganizationReference> {
        match self {
            Self::Organization(organization) => Some(organization),
            _ => None,
        }
    }

    /// The application, or nothing for the whole tenant.
    #[must_use]
    pub const fn application(&self) -> Option<&ApplicationReference> {
        match self {
            Self::Tenant | Self::Organization(_) => None,
            Self::Application(application) => Some(application),
        }
    }
}

/// A role given to a principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleAssignment {
    principal: Subject,
    role: RoleKey,
    scope: AssignmentScope,
    valid_from: Option<Timestamp>,
    valid_until: Option<Timestamp>,
    assigned_at: Timestamp,
}

impl RoleAssignment {
    /// Gives `role` to `principal`.
    ///
    /// # Errors
    ///
    /// - `authorization.namespace_reserved` for a built-in role: those are
    ///   given by the bootstrap command.
    /// - `authorization.validity_invalid` when the end is not after the
    ///   start.
    pub fn new(
        principal: Subject,
        role: RoleKey,
        scope: AssignmentScope,
        valid_from: Option<Timestamp>,
        valid_until: Option<Timestamp>,
        assigned_at: Timestamp,
    ) -> Result<Self, DomainError> {
        if role.namespace.is_administration() {
            return Err(reserved());
        }
        if let (Some(from), Some(until)) = (valid_from, valid_until)
            && until <= from
        {
            return Err(invalid(
                "authorization.validity_invalid",
                "an assignment ends after it starts",
            ));
        }
        Ok(Self {
            principal,
            role,
            scope,
            valid_from,
            valid_until,
            assigned_at,
        })
    }

    /// Who holds the role.
    #[must_use]
    pub const fn principal(&self) -> &Subject {
        &self.principal
    }

    /// The role.
    #[must_use]
    pub const fn role(&self) -> &RoleKey {
        &self.role
    }

    /// Where it applies.
    #[must_use]
    pub const fn scope(&self) -> &AssignmentScope {
        &self.scope
    }

    /// From when it allows, if it has a start.
    #[must_use]
    pub const fn valid_from(&self) -> Option<Timestamp> {
        self.valid_from
    }

    /// Until when it allows, if it has an end.
    #[must_use]
    pub const fn valid_until(&self) -> Option<Timestamp> {
        self.valid_until
    }

    /// When it was given, or its start and end last changed.
    #[must_use]
    pub const fn assigned_at(&self) -> Timestamp {
        self.assigned_at
    }

    /// Whether it allows at `now`: from its start, up to but not at its
    /// end.
    #[must_use]
    pub fn in_force_at(&self, now: Timestamp) -> bool {
        self.valid_from.is_none_or(|from| from <= now)
            && self.valid_until.is_none_or(|until| now < until)
    }

    /// Whether it is the same grant as `other`: same principal, role and
    /// scope, whatever its start and end.
    #[must_use]
    pub fn same_grant(&self, other: &Self) -> bool {
        self.principal == other.principal && self.role == other.role && self.scope == other.scope
    }
}

/// One permission a principal holds through one assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// The resource server of the permission.
    pub namespace: Namespace,
    /// The permission.
    pub permission: PermissionName,
    /// The condition that must also hold, if any.
    pub condition: Option<Condition>,
    /// The assignment that gives it.
    pub assignment: RoleAssignment,
}

/// What a principal's assignments come to, through every role they
/// include.
#[must_use]
pub(crate) fn grants_of(assignments: &[RoleAssignment], graph: &RoleGraph) -> Vec<Grant> {
    let mut grants = Vec::new();
    for assignment in assignments {
        for holding in graph.holdings(&assignment.role) {
            grants.push(Grant {
                namespace: holding.namespace,
                permission: holding.permission,
                condition: holding.condition,
                assignment: assignment.clone(),
            });
        }
    }
    grants
}

/// Whether `grant` gives `permission` of `namespace` at `now` for a request
/// made for `application`, its condition aside.
#[must_use]
pub(crate) fn grant_applies(
    grant: &Grant,
    namespace: &Namespace,
    permission: &PermissionName,
    application: Option<&ApplicationReference>,
    organization: Option<&OrganizationReference>,
    now: Timestamp,
) -> bool {
    &grant.namespace == namespace
        && &grant.permission == permission
        && grant.assignment.scope.applies_to(application, organization)
        && grant.assignment.in_force_at(now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::request::SubjectKind;

    fn ns(value: &str) -> Namespace {
        Namespace::parse(value).expect("namespace")
    }

    fn key(namespace: &str, name: &str) -> RoleKey {
        RoleKey::new(ns(namespace), RoleName::parse(name).expect("name"))
    }

    fn permission(value: &str) -> PermissionName {
        PermissionName::parse(value).expect("permission")
    }

    fn role(
        namespace: &str,
        name: &str,
        permissions: &[&str],
        includes: &[RoleKey],
    ) -> RoleDefinition {
        RoleDefinition::new(
            key(namespace, name),
            RoleContents {
                description: String::new(),
                permissions: permissions.iter().map(|p| permission(p)).collect(),
                includes: includes.iter().cloned().collect(),
                conditions: BTreeMap::new(),
            },
            Timestamp::UNIX_EPOCH,
        )
        .expect("role")
    }

    fn declared(values: &[&str]) -> BTreeSet<PermissionName> {
        values.iter().map(|value| permission(value)).collect()
    }

    const DOCS: &str = "urn:example:documents";
    const BILLING: &str = "https://billing.example.com";

    #[test]
    fn a_permission_is_a_kind_and_an_action() {
        for good in ["document:read", "v2.files:read_all", "a:b"] {
            assert_eq!(permission(good).as_str(), good);
        }
        for bad in [
            "document",
            "document:",
            ":read",
            "Document:read",
            "a:b:c",
            "a :b",
        ] {
            assert!(PermissionName::parse(bad).is_err(), "{bad}");
        }
        let action = Action::parse("read").expect("action");
        assert_eq!(
            PermissionName::of("document", &action),
            permission("document:read")
        );
    }

    #[test]
    fn nothing_can_be_defined_in_the_administration() {
        let admin = Namespace::administration();
        assert_eq!(
            PermissionDefinition::new(admin.clone(), permission("users:read"), "")
                .map_err(|e| e.code().to_owned()),
            Err("authorization.namespace_reserved".to_owned())
        );
        let contents = RoleContents {
            description: String::new(),
            permissions: BTreeSet::new(),
            includes: BTreeSet::new(),
            conditions: BTreeMap::new(),
        };
        assert!(
            RoleDefinition::new(
                RoleKey::built_in(Role::TenantAuditor),
                contents.clone(),
                Timestamp::UNIX_EPOCH
            )
            .is_err()
        );
        let including_admin = RoleContents {
            includes: [RoleKey::built_in(Role::TenantAdministrator)].into(),
            ..contents
        };
        assert_eq!(
            RoleDefinition::new(key(DOCS, "sneaky"), including_admin, Timestamp::UNIX_EPOCH)
                .map_err(|e| e.code().to_owned()),
            Err("authorization.namespace_reserved".to_owned())
        );
        let user = Subject::new(SubjectKind::User, "ana").expect("subject");
        assert!(
            RoleAssignment::new(
                user,
                RoleKey::built_in(Role::TenantAdministrator),
                AssignmentScope::Tenant,
                None,
                None,
                Timestamp::UNIX_EPOCH
            )
            .is_err()
        );
    }

    #[test]
    fn a_role_reaches_the_namespaces_of_what_it_includes() {
        let viewer = role(DOCS, "viewer", &[], &[]);
        let editor = role(DOCS, "editor", &[], &[key(DOCS, "viewer")]);
        let reader = role(BILLING, "reader", &[], &[]);
        let support = role(
            "urn:example:support",
            "support",
            &[],
            &[key(DOCS, "editor"), key(BILLING, "reader")],
        );
        let lonely = role("urn:example:support", "lonely", &[], &[]);
        let graph = RoleGraph::new([viewer, editor, reader, support, lonely]);
        assert!(graph.reaches(&key(DOCS, "viewer"), &ns(DOCS)));
        assert!(graph.reaches(&key(DOCS, "editor"), &ns(DOCS)));
        assert!(!graph.reaches(&key(DOCS, "editor"), &ns(BILLING)));
        let composite = key("urn:example:support", "support");
        assert!(graph.reaches(&composite, &ns(DOCS)));
        assert!(graph.reaches(&composite, &ns(BILLING)));
        assert!(!graph.reaches(&key("urn:example:support", "lonely"), &ns(DOCS)));
        assert!(!graph.reaches(&key(BILLING, "absent"), &ns(DOCS)));
    }

    #[test]
    fn a_role_is_bounded() {
        let many: Vec<String> = (0..=MAX_ROLE_PERMISSIONS)
            .map(|i| format!("p{i}:read"))
            .collect();
        let contents = RoleContents {
            description: String::new(),
            permissions: many.iter().map(|p| permission(p)).collect(),
            includes: BTreeSet::new(),
            conditions: BTreeMap::new(),
        };
        assert_eq!(
            RoleDefinition::new(key(DOCS, "big"), contents, Timestamp::UNIX_EPOCH)
                .map_err(|e| e.code().to_owned()),
            Err("authorization.too_many_permissions".to_owned())
        );
        let contents = RoleContents {
            description: String::new(),
            permissions: BTreeSet::new(),
            includes: (0..=MAX_INCLUDED_ROLES)
                .map(|i| key(DOCS, &format!("r{i}")))
                .collect(),
            conditions: BTreeMap::new(),
        };
        assert_eq!(
            RoleDefinition::new(key(DOCS, "wide"), contents, Timestamp::UNIX_EPOCH)
                .map_err(|e| e.code().to_owned()),
            Err("authorization.too_many_included_roles".to_owned())
        );
        let contents = RoleContents {
            description: "x".repeat(MAX_DESCRIPTION_LENGTH + 1),
            permissions: BTreeSet::new(),
            includes: BTreeSet::new(),
            conditions: BTreeMap::new(),
        };
        assert!(RoleDefinition::new(key(DOCS, "wordy"), contents, Timestamp::UNIX_EPOCH).is_err());
    }

    #[test]
    fn a_role_cannot_include_itself_directly_or_through_others() {
        let contents = RoleContents {
            description: String::new(),
            permissions: BTreeSet::new(),
            includes: [key(DOCS, "self")].into(),
            conditions: BTreeMap::new(),
        };
        assert_eq!(
            RoleDefinition::new(key(DOCS, "self"), contents, Timestamp::UNIX_EPOCH)
                .map_err(|e| e.code().to_owned()),
            Err("authorization.role_cycle".to_owned())
        );

        // viewer <- editor <- owner; making viewer include owner closes a
        // loop through two roles, and across namespaces through a composite.
        let viewer = role(DOCS, "viewer", &["document:read"], &[]);
        let editor = role(DOCS, "editor", &["document:write"], &[key(DOCS, "viewer")]);
        let owner = role(DOCS, "owner", &[], &[key(DOCS, "editor")]);
        let support = role(BILLING, "support", &[], &[key(DOCS, "owner")]);
        let graph = RoleGraph::new([viewer.clone(), editor, owner, support]);
        let all = declared(&["document:read", "document:write"]);
        let looping = role(DOCS, "viewer", &["document:read"], &[key(DOCS, "owner")]);
        assert_eq!(
            graph.check(&looping, &all).map_err(|e| e.code().to_owned()),
            Err("authorization.role_cycle".to_owned())
        );
        let through_composite = role(
            DOCS,
            "viewer",
            &["document:read"],
            &[key(BILLING, "support")],
        );
        assert_eq!(
            graph
                .check(&through_composite, &all)
                .map_err(|e| e.code().to_owned()),
            Err("authorization.role_cycle".to_owned())
        );
        assert!(graph.check(&viewer, &all).is_ok());
    }

    #[test]
    fn a_role_holds_only_declared_permissions_and_includes_only_roles_that_exist() {
        let graph = RoleGraph::default();
        let reader = role(DOCS, "reader", &["document:read"], &[]);
        assert_eq!(
            graph
                .check(&reader, &declared(&["document:write"]))
                .map_err(|e| e.code().to_owned()),
            Err("authorization.permission_not_declared".to_owned())
        );
        let composite = role(DOCS, "composite", &[], &[key(DOCS, "missing")]);
        assert_eq!(
            graph
                .check(&composite, &declared(&[]))
                .map_err(|e| e.code().to_owned()),
            Err("authorization.role_not_found".to_owned())
        );
    }

    #[test]
    fn inclusion_goes_at_most_ten_deep() {
        let mut roles = vec![role(DOCS, "r0", &[], &[])];
        for level in 1..=MAX_INCLUSION_DEPTH {
            roles.push(role(
                DOCS,
                &format!("r{level}"),
                &[],
                &[key(DOCS, &format!("r{}", level - 1))],
            ));
        }
        let graph = RoleGraph::new(roles);
        let deepest = role(DOCS, "r10", &[], &[key(DOCS, "r9")]);
        assert!(graph.check(&deepest, &declared(&[])).is_ok());
        let deeper = role(DOCS, "r11", &[], &[key(DOCS, "r10")]);
        assert_eq!(
            graph
                .check(&deeper, &declared(&[]))
                .map_err(|e| e.code().to_owned()),
            Err("authorization.role_inclusion_too_deep".to_owned())
        );
    }

    #[test]
    fn a_role_holds_what_it_includes_across_namespaces() {
        let viewer = role(DOCS, "viewer", &["document:read"], &[]);
        let editor = role(DOCS, "editor", &["document:write"], &[key(DOCS, "viewer")]);
        let payer = role(BILLING, "payer", &["invoice:pay"], &[]);
        let support = role(
            BILLING,
            "support",
            &[],
            &[key(DOCS, "editor"), key(BILLING, "payer")],
        );
        let graph = RoleGraph::new([viewer, editor, payer, support]);
        let held = graph.permissions_held(&key(BILLING, "support"));
        assert_eq!(
            held,
            [
                (ns(BILLING), permission("invoice:pay")),
                (ns(DOCS), permission("document:read")),
                (ns(DOCS), permission("document:write")),
            ]
            .into()
        );
        assert_eq!(
            graph.including(&key(DOCS, "viewer")),
            [&key(DOCS, "editor")]
        );
        assert!(graph.permissions_held(&key(DOCS, "nobody")).is_empty());
    }

    fn condition(text: &str) -> Condition {
        Condition::parse(text).expect("condition")
    }

    #[test]
    fn a_condition_is_given_only_for_a_permission_the_role_holds() {
        let contents = RoleContents {
            description: String::new(),
            permissions: [permission("document:read")].into(),
            includes: BTreeSet::new(),
            conditions: [(permission("document:write"), condition("true"))].into(),
        };
        assert_eq!(
            RoleDefinition::new(key(DOCS, "odd"), contents, Timestamp::UNIX_EPOCH)
                .map_err(|e| e.code().to_owned()),
            Err("authorization.condition_without_permission".to_owned())
        );
    }

    #[test]
    fn a_permission_is_held_with_the_condition_of_the_role_that_holds_it() {
        let same_department = condition("subject.attributes.department == 'sales'");
        let editor = RoleDefinition::new(
            key(DOCS, "editor"),
            RoleContents {
                description: String::new(),
                permissions: [permission("document:read"), permission("document:write")].into(),
                includes: BTreeSet::new(),
                conditions: [(permission("document:write"), same_department.clone())].into(),
            },
            Timestamp::UNIX_EPOCH,
        )
        .expect("role");
        let owner = role(DOCS, "owner", &["document:write"], &[key(DOCS, "editor")]);
        let graph = RoleGraph::new([editor, owner]);
        let held = graph.holdings(&key(DOCS, "owner"));
        let write = |condition: Option<Condition>| Holding {
            namespace: ns(DOCS),
            permission: permission("document:write"),
            condition,
        };
        assert!(held.contains(&write(None)), "the owner's own, without");
        assert!(
            held.contains(&write(Some(same_department))),
            "the editor's, with its condition"
        );
        assert_eq!(held.len(), 3);
        assert_eq!(graph.permissions_held(&key(DOCS, "owner")).len(), 2);
    }

    #[test]
    fn the_built_in_roles_hold_exactly_the_fixed_permissions() {
        let graph = RoleGraph::built_in();
        for fixed in Role::ALL {
            let held = graph.permissions_held(&RoleKey::built_in(fixed));
            for granted in Permission::ALL {
                assert_eq!(
                    held.contains(&(Namespace::administration(), PermissionName::fixed(granted))),
                    fixed.allows(granted),
                    "{} {}",
                    fixed.as_str(),
                    granted.as_str()
                );
            }
            assert_eq!(held.len(), fixed.permissions().len());
        }
    }

    #[test]
    fn an_assignment_has_a_scope_and_a_time() {
        let ana = Subject::new(SubjectKind::User, "ana").expect("subject");
        let start = Timestamp::UNIX_EPOCH + time::Duration::days(1);
        let end = start + time::Duration::days(1);
        assert_eq!(
            RoleAssignment::new(
                ana.clone(),
                key(DOCS, "viewer"),
                AssignmentScope::Tenant,
                Some(end),
                Some(start),
                start
            )
            .map_err(|e| e.code().to_owned()),
            Err("authorization.validity_invalid".to_owned())
        );
        let app = ApplicationReference::parse("portal").expect("application");
        let other = ApplicationReference::parse("billing").expect("application");
        let scoped = RoleAssignment::new(
            ana,
            key(DOCS, "viewer"),
            AssignmentScope::Application(app.clone()),
            Some(start),
            Some(end),
            start,
        )
        .expect("assignment");
        assert!(!scoped.in_force_at(start - time::Duration::seconds(1)));
        assert!(scoped.in_force_at(start));
        assert!(!scoped.in_force_at(end));
        assert!(scoped.scope().applies_to(Some(&app), None));
        assert!(!scoped.scope().applies_to(Some(&other), None));
        assert!(!scoped.scope().applies_to(None, None));
        assert!(AssignmentScope::Tenant.applies_to(None, None));
        assert!(AssignmentScope::Tenant.applies_to(Some(&other), None));
        let acme = OrganizationReference::parse("acme").expect("organization");
        let organization = AssignmentScope::Organization(acme.clone());
        assert!(organization.applies_to(None, Some(&acme)));
        assert!(
            !organization.applies_to(Some(&app), None),
            "only in its organization"
        );
        assert!(AssignmentScope::Tenant.applies_to(None, Some(&acme)));
    }
}
