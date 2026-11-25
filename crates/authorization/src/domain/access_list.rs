//! Per-resource access control lists: entries that let one principal do
//! what one permission says to one resource of a resource server.
//!
//! See `docs/architecture/contexts/authorization.md`, "Access control
//! lists", and Decision 0035.

use crate::domain::native::PermissionName;
use crate::domain::request::{Namespace, Subject, SubjectKind, is_identifier};
use hodor_kernel::{DomainError, Timestamp};

hodor_kernel::define_id!(
    /// Identifies one entry of an access control list.
    AccessEntryId
);

/// The reason of an allow by an entry.
pub const MATCHING_ENTRY: &str = "matching_entry";

/// The most entries one decision reads and names.
pub const MAX_ENTRIES_PER_DECISION: usize = 64;

/// An entry: `principal` may do what `permission` says to the resource
/// `resource_id` of the resource server `namespace`. It only allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessEntry {
    id: AccessEntryId,
    namespace: Namespace,
    permission: PermissionName,
    resource_id: String,
    principal: Subject,
    granted_at: Timestamp,
}

impl AccessEntry {
    /// An entry, new or read back from storage.
    ///
    /// # Errors
    ///
    /// - `authorization.namespace_reserved` for `hodor:admin`, which has
    ///   only its built-in roles.
    /// - `authorization.resource_invalid` for a resource identifier that is
    ///   empty, longer than 255 characters or holds a control character.
    pub fn new(
        id: AccessEntryId,
        namespace: Namespace,
        permission: PermissionName,
        resource_id: &str,
        principal: Subject,
        granted_at: Timestamp,
    ) -> Result<Self, DomainError> {
        if namespace.is_administration() {
            return Err(DomainError::invalid(
                "authorization.namespace_reserved",
                "Hodor's administration has only its built-in roles and permissions",
            ));
        }
        if !is_identifier(resource_id) {
            return Err(DomainError::invalid(
                "authorization.resource_invalid",
                "a resource's identifier has 1 to 255 characters and no control character",
            ));
        }
        Ok(Self {
            id,
            namespace,
            permission,
            resource_id: resource_id.to_owned(),
            principal,
            granted_at,
        })
    }

    /// Its identifier.
    #[must_use]
    pub const fn id(&self) -> AccessEntryId {
        self.id
    }

    /// The resource server of the resource.
    #[must_use]
    pub const fn namespace(&self) -> &Namespace {
        &self.namespace
    }

    /// What it lets the principal do.
    #[must_use]
    pub const fn permission(&self) -> &PermissionName {
        &self.permission
    }

    /// The kind of the resource: the first half of the permission.
    #[must_use]
    pub fn resource_kind(&self) -> &str {
        self.permission
            .as_str()
            .split_once(':')
            .map_or("", |(kind, _)| kind)
    }

    /// The resource's identifier.
    #[must_use]
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }

    /// Who it lets.
    #[must_use]
    pub const fn principal(&self) -> &Subject {
        &self.principal
    }

    /// When it was granted.
    #[must_use]
    pub const fn granted_at(&self) -> Timestamp {
        self.granted_at
    }

    /// Whether it gives the same thing as `other`: the same principal, the
    /// same permission on the same resource of the same resource server.
    #[must_use]
    pub fn same_grant(&self, other: &Self) -> bool {
        self.namespace == other.namespace
            && self.permission == other.permission
            && self.resource_id == other.resource_id
            && self.principal == other.principal
    }

    /// How a decision names it: `entry:<identifier>`.
    #[must_use]
    pub fn reference(&self) -> String {
        format!("entry:{}", self.id)
    }

    /// Whether it allows `permission` on the resource `resource_id` of
    /// `namespace` to one of `principals`.
    #[must_use]
    pub fn allows(
        &self,
        namespace: &Namespace,
        permission: &PermissionName,
        resource_id: &str,
        principals: &[Subject],
    ) -> bool {
        &self.namespace == namespace
            && &self.permission == permission
            && self.resource_id == resource_id
            && principals.contains(&self.principal)
    }
}

/// Which entries of one resource server a listing answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessEntryFilter {
    /// The resource server.
    pub namespace: Namespace,
    /// Only entries on resources of this kind.
    pub resource_kind: Option<String>,
    /// Only entries on the resource of this identifier.
    pub resource_id: Option<String>,
    /// Only entries of this principal.
    pub principal: Option<Subject>,
}

impl AccessEntryFilter {
    /// Every entry of `namespace`.
    #[must_use]
    pub const fn of(namespace: Namespace) -> Self {
        Self {
            namespace,
            resource_kind: None,
            resource_id: None,
            principal: None,
        }
    }

    /// Whether `entry` passes.
    #[must_use]
    pub fn passes(&self, entry: &AccessEntry) -> bool {
        entry.namespace == self.namespace
            && self
                .resource_kind
                .as_deref()
                .is_none_or(|kind| entry.resource_kind() == kind)
            && self
                .resource_id
                .as_deref()
                .is_none_or(|id| entry.resource_id == id)
            && self
                .principal
                .as_ref()
                .is_none_or(|principal| &entry.principal == principal)
    }
}

/// The principals whose entries count for a request: the subject and, for
/// a user, every group Hodor resolved for them.
#[must_use]
pub(crate) fn principals_of(subject: &Subject, groups: &[String]) -> Vec<Subject> {
    let mut principals = vec![subject.clone()];
    if subject.kind() == SubjectKind::User {
        principals.extend(
            groups
                .iter()
                .filter_map(|group| Subject::new(SubjectKind::Group, group).ok()),
        );
    }
    principals
}

#[cfg(test)]
mod tests {
    use super::*;

    fn documents() -> Namespace {
        Namespace::parse("urn:example:documents").expect("namespace")
    }

    fn read() -> PermissionName {
        PermissionName::parse("document:read").expect("permission")
    }

    fn finance() -> Subject {
        Subject::new(SubjectKind::Group, "finance").expect("group")
    }

    fn entry(resource: &str) -> AccessEntry {
        AccessEntry::new(
            AccessEntryId::generate(),
            documents(),
            read(),
            resource,
            finance(),
            Timestamp::UNIX_EPOCH,
        )
        .expect("entry")
    }

    #[test]
    fn an_entry_allows_only_on_its_resource_of_its_resource_server() {
        let shared = entry("d-42");
        let members = [finance()];
        assert!(shared.allows(&documents(), &read(), "d-42", &members));
        assert!(!shared.allows(&documents(), &read(), "d-43", &members));
        let elsewhere = Namespace::parse("https://billing.example.com").expect("namespace");
        assert!(!shared.allows(&elsewhere, &read(), "d-42", &members));
        let write = PermissionName::parse("document:write").expect("permission");
        assert!(!shared.allows(&documents(), &write, "d-42", &members));
        let someone = Subject::new(SubjectKind::User, "ana").expect("user");
        assert!(!shared.allows(&documents(), &read(), "d-42", &[someone]));
        assert_eq!(shared.resource_kind(), "document");
        assert_eq!(shared.reference(), format!("entry:{}", shared.id()));
    }

    #[test]
    fn an_entry_is_never_of_the_administration_and_names_one_resource() {
        for bad in ["", &"x".repeat(256), "d\n42"] {
            assert_eq!(
                AccessEntry::new(
                    AccessEntryId::generate(),
                    documents(),
                    read(),
                    bad,
                    finance(),
                    Timestamp::UNIX_EPOCH
                )
                .map_err(|e| e.code().to_owned()),
                Err("authorization.resource_invalid".to_owned()),
                "{bad:?}"
            );
        }
        assert_eq!(
            AccessEntry::new(
                AccessEntryId::generate(),
                Namespace::administration(),
                PermissionName::parse("users:read").expect("permission"),
                "d-42",
                finance(),
                Timestamp::UNIX_EPOCH
            )
            .map_err(|e| e.code().to_owned()),
            Err("authorization.namespace_reserved".to_owned())
        );
    }

    #[test]
    fn the_same_grant_is_the_same_principal_permission_and_resource() {
        let one = entry("d-42");
        let again = entry("d-42");
        assert_ne!(one.id(), again.id());
        assert!(one.same_grant(&again));
        assert!(!one.same_grant(&entry("d-43")));
    }

    #[test]
    fn a_filter_narrows_by_kind_resource_and_principal() {
        let shared = entry("d-42");
        let mut filter = AccessEntryFilter::of(documents());
        assert!(filter.passes(&shared));
        filter.resource_kind = Some("document".to_owned());
        filter.resource_id = Some("d-42".to_owned());
        filter.principal = Some(finance());
        assert!(filter.passes(&shared));
        filter.resource_kind = Some("folder".to_owned());
        assert!(!filter.passes(&shared));
        filter.resource_kind = None;
        filter.resource_id = Some("d-43".to_owned());
        assert!(!filter.passes(&shared));
        filter.resource_id = None;
        filter.principal = Some(Subject::new(SubjectKind::User, "ana").expect("user"));
        assert!(!filter.passes(&shared));
        let other = Namespace::parse("https://billing.example.com").expect("namespace");
        assert!(!AccessEntryFilter::of(other).passes(&shared));
    }

    #[test]
    fn a_user_counts_with_their_groups_and_a_client_alone() {
        let ana = Subject::new(SubjectKind::User, "ana").expect("user");
        let groups = vec!["finance".to_owned(), "staff".to_owned()];
        assert_eq!(
            principals_of(&ana, &groups),
            [
                ana.clone(),
                finance(),
                Subject::new(SubjectKind::Group, "staff").expect("group")
            ]
        );
        let client = Subject::new(SubjectKind::Client, "billing").expect("client");
        assert_eq!(principals_of(&client, &groups), [client]);
    }
}
