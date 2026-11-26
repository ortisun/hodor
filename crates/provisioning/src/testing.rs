//! In-memory ports, the contract every implementation of them passes, and
//! the corpus of filters.
//!
//! The in-memory stores and the PostgreSQL ones both run the contract, so
//! the stores agree on what each filter of the corpus finds, and on every
//! order and page. The in-memory stores evaluate the tree of a filter
//! directly; they read the identity context's users and groups through
//! its repositories.

use crate::api::{
    AccessRevoker, Attribute, Deprovisioning, DeprovisioningPolicy, Fact, Facts, FilterRefusal,
    Found, GroupAttribute, GroupFacts, GroupSupplement, ListParameters, ListQuery,
    ProvisionedGroupRepository, ProvisionedUserRepository, SortOrder, StoredGroupSupplement,
    StoredUserSupplement, UserAttribute, UserFacts, UserSupplement, matches, shown, sort_order,
};
use hodor_identity::api::{
    Group, GroupMember, GroupName, GroupRepository, IdentifierKind, NormalizedIdentifier, Profile,
    StandardClaims, User, UserKind, UserRepository,
};
use hodor_kernel::{
    DomainError, GroupId, TenantContext, TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory, UserId,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use time::Duration;

const PAGE: u32 = 1000;

/// Puts identifiers in the order a list asks for and takes its page:
/// stable, so that resources that sort alike stay in the order they were
/// created.
fn page_of<I: Copy, A: Attribute>(
    mut rows: Vec<(I, Option<Fact>)>,
    query: &ListQuery<A>,
) -> Found<I> {
    if let Some((attribute, order)) = query.sort {
        rows.sort_by(|(_, left), (_, right)| {
            let ordering = sort_order(left.as_ref(), right.as_ref(), attribute.value_type());
            match order {
                SortOrder::Ascending => ordering,
                SortOrder::Descending => ordering.reverse(),
            }
        });
    }
    let total = rows.len() as u64;
    let ids = rows
        .into_iter()
        .skip(usize::try_from(query.offset()).unwrap_or(usize::MAX))
        .take(query.count as usize)
        .map(|(id, _)| id)
        .collect();
    Found { total, ids }
}

fn sort_value<A: Attribute>(facts: &dyn Facts<A>, query: &ListQuery<A>) -> Option<Fact> {
    query.sort.and_then(|(attribute, _)| facts.value(attribute))
}

/// What is kept of users, in memory. It finds users by reading the
/// identity context's users through their repository.
#[derive(Clone)]
pub struct InMemoryProvisionedUsers {
    rows: Arc<Mutex<BTreeMap<(TenantId, UserId), StoredUserSupplement>>>,
    users: Arc<dyn UserRepository>,
}

impl std::fmt::Debug for InMemoryProvisionedUsers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryProvisionedUsers")
            .finish_non_exhaustive()
    }
}

impl InMemoryProvisionedUsers {
    /// A store that finds the users of `users`.
    #[must_use]
    pub fn new(users: Arc<dyn UserRepository>) -> Self {
        Self {
            rows: Arc::default(),
            users,
        }
    }

    fn rows(
        &self,
    ) -> std::sync::MutexGuard<'_, BTreeMap<(TenantId, UserId), StoredUserSupplement>> {
        self.rows.lock().unwrap_or_else(|error| error.into_inner())
    }
}

async fn every_user(
    users: &dyn UserRepository,
    uow: &mut dyn UnitOfWork,
) -> Result<Vec<User>, DomainError> {
    let mut all: Vec<User> = Vec::new();
    loop {
        let page = users.list(uow, all.last().map(User::id), PAGE).await?;
        let done = page.len() < PAGE as usize;
        all.extend(page);
        if done {
            return Ok(all);
        }
    }
}

#[async_trait::async_trait]
impl ProvisionedUserRepository for InMemoryProvisionedUsers {
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        user: UserId,
    ) -> Result<Option<StoredUserSupplement>, DomainError> {
        Ok(self.rows().get(&(uow.tenant().tenant_id(), user)).cloned())
    }

    async fn put(
        &self,
        uow: &mut dyn UnitOfWork,
        stored: &StoredUserSupplement,
    ) -> Result<(), DomainError> {
        self.rows()
            .insert((uow.tenant().tenant_id(), stored.user_id), stored.clone());
        Ok(())
    }

    async fn remove(&self, uow: &mut dyn UnitOfWork, user: UserId) -> Result<(), DomainError> {
        self.rows().remove(&(uow.tenant().tenant_id(), user));
        Ok(())
    }

    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        query: &ListQuery<UserAttribute>,
    ) -> Result<Found<UserId>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let users = every_user(self.users.as_ref(), uow).await?;
        let rows = self.rows();
        let found = users
            .iter()
            .filter(|user| shown(user, rows.get(&(tenant, user.id()))))
            .filter_map(|user| {
                let facts = UserFacts {
                    user,
                    stored: rows.get(&(tenant, user.id())),
                };
                query
                    .filter
                    .as_ref()
                    .is_none_or(|filter| matches(filter, &facts))
                    .then(|| (user.id(), sort_value(&facts, query)))
            })
            .collect();
        Ok(page_of(found, query))
    }
}

/// What is kept of groups, in memory. It finds groups by reading the
/// identity context's groups through their repository.
#[derive(Clone)]
pub struct InMemoryProvisionedGroups {
    rows: Arc<Mutex<BTreeMap<(TenantId, GroupId), StoredGroupSupplement>>>,
    groups: Arc<dyn GroupRepository>,
}

impl std::fmt::Debug for InMemoryProvisionedGroups {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryProvisionedGroups")
            .finish_non_exhaustive()
    }
}

impl InMemoryProvisionedGroups {
    /// A store that finds the groups of `groups`.
    #[must_use]
    pub fn new(groups: Arc<dyn GroupRepository>) -> Self {
        Self {
            rows: Arc::default(),
            groups,
        }
    }

    fn rows(
        &self,
    ) -> std::sync::MutexGuard<'_, BTreeMap<(TenantId, GroupId), StoredGroupSupplement>> {
        self.rows.lock().unwrap_or_else(|error| error.into_inner())
    }
}

#[async_trait::async_trait]
impl ProvisionedGroupRepository for InMemoryProvisionedGroups {
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        group: GroupId,
    ) -> Result<Option<StoredGroupSupplement>, DomainError> {
        Ok(self.rows().get(&(uow.tenant().tenant_id(), group)).cloned())
    }

    async fn put(
        &self,
        uow: &mut dyn UnitOfWork,
        stored: &StoredGroupSupplement,
    ) -> Result<(), DomainError> {
        self.rows()
            .insert((uow.tenant().tenant_id(), stored.group_id), stored.clone());
        Ok(())
    }

    async fn remove(&self, uow: &mut dyn UnitOfWork, group: GroupId) -> Result<(), DomainError> {
        self.rows().remove(&(uow.tenant().tenant_id(), group));
        Ok(())
    }

    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        query: &ListQuery<GroupAttribute>,
    ) -> Result<Found<GroupId>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut groups: Vec<Group> = Vec::new();
        loop {
            let page = self
                .groups
                .list(uow, groups.last().map(Group::id), PAGE)
                .await?;
            let done = page.len() < PAGE as usize;
            groups.extend(page);
            if done {
                break;
            }
        }
        let mut found = Vec::new();
        for group in &groups {
            let mut members: Vec<GroupMember> = Vec::new();
            loop {
                let page = self
                    .groups
                    .members(uow, group.id(), members.last().copied(), PAGE)
                    .await?;
                let done = page.len() < PAGE as usize;
                members.extend(page);
                if done {
                    break;
                }
            }
            let rows = self.rows();
            let facts = GroupFacts {
                group,
                stored: rows.get(&(tenant, group.id())),
                members: &members,
            };
            if query
                .filter
                .as_ref()
                .is_none_or(|filter| matches(filter, &facts))
            {
                found.push((group.id(), sort_value(&facts, query)));
            }
        }
        Ok(page_of(found, query))
    }
}

/// A deprovisioning policy, the same for every tenant, that a test may
/// change.
#[derive(Debug, Clone, Default)]
pub struct FixedDeprovisioning(Arc<Mutex<Deprovisioning>>);

impl FixedDeprovisioning {
    /// Makes `policy` the policy of every tenant.
    pub fn set(&self, policy: Deprovisioning) {
        *self.0.lock().unwrap_or_else(|error| error.into_inner()) = policy;
    }
}

#[async_trait::async_trait]
impl DeprovisioningPolicy for FixedDeprovisioning {
    async fn deprovisioning(
        &self,
        _uow: &mut dyn UnitOfWork,
    ) -> Result<Deprovisioning, DomainError> {
        Ok(*self.0.lock().unwrap_or_else(|error| error.into_inner()))
    }
}

/// An [`AccessRevoker`] that remembers whose access it ended, and why.
#[derive(Debug, Clone, Default)]
pub struct RecordingAccessRevoker(Arc<Mutex<Vec<Revoked>>>);

/// Whose access was ended, in which tenant, and why.
pub type Revoked = (TenantId, UserId, &'static str);

impl RecordingAccessRevoker {
    /// Every person whose access was ended, in order, with the reason.
    #[must_use]
    pub fn revoked(&self) -> Vec<Revoked> {
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
}

#[async_trait::async_trait]
impl AccessRevoker for RecordingAccessRevoker {
    async fn revoke_access(
        &self,
        uow: &mut dyn UnitOfWork,
        user: UserId,
        reason: &'static str,
        _caller: hodor_kernel::Caller,
    ) -> Result<(), DomainError> {
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push((uow.tenant().tenant_id(), user, reason));
        Ok(())
    }
}

/// What a filter of the corpus is answered with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expected {
    /// The resources it finds, by the names the contract gives them, in
    /// the order they were created.
    Finds(&'static [&'static str]),
    /// The refusal, and so the detail of `invalidFilter`.
    Refused(FilterRefusal),
}

/// One filter of the corpus. `{name}` in the filter stands for the
/// identifier of the resource the contract calls `name`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusCase {
    /// The filter as a SCIM client writes it.
    pub filter: String,
    /// What it is answered with.
    pub expected: Expected,
}

fn case(filter: &str, expected: Expected) -> CorpusCase {
    CorpusCase {
        filter: filter.to_owned(),
        expected,
    }
}

fn not_filterable(path: &str) -> Expected {
    Expected::Refused(FilterRefusal::NotFilterable(path.to_owned()))
}

fn unreadable(why: &'static str) -> Expected {
    Expected::Refused(FilterRefusal::Unreadable(why))
}

/// The corpus of filters on users: each answered, or refused for its own
/// reason. The users are those of [`run_contract`]: `bjensen`, `jsmith`,
/// `ana` and `omalley`.
#[must_use]
#[allow(clippy::too_many_lines, reason = "a list of cases, read one by one")]
pub fn user_corpus() -> Vec<CorpusCase> {
    use Expected::{Finds, Refused};
    vec![
        // Text compared without regard to case.
        case(r#"userName eq "bjensen""#, Finds(&["bjensen"])),
        case(r#"userName eq "BJensen""#, Finds(&["bjensen"])),
        case(r#"userName eq "Ana.Silva@example.com""#, Finds(&["ana"])),
        case(r#"userName sw "J""#, Finds(&["jsmith"])),
        case(r#"userName co "o""#, Finds(&["ana", "omalley"])),
        case(r#"userName ew "LEY""#, Finds(&["omalley"])),
        case(r#"userName gt "c""#, Finds(&["jsmith", "omalley"])),
        case(r#"userName le "bjensen""#, Finds(&["bjensen", "ana"])),
        case(
            r#"userName ne "bjensen""#,
            Finds(&["jsmith", "ana", "omalley"]),
        ),
        case(r#"displayName eq "babs jensen""#, Finds(&["bjensen"])),
        case(r#"displayName co "SIL""#, Finds(&["ana"])),
        case("displayName pr", Finds(&["bjensen", "ana", "omalley"])),
        case(r#"name.familyName eq "o'malley""#, Finds(&["omalley"])),
        case(r#"name.givenName sw "j""#, Finds(&["jsmith"])),
        case("name.givenName pr", Finds(&["bjensen", "jsmith"])),
        // Text compared exactly, and missing values.
        case(r#"externalId eq "701984""#, Finds(&["bjensen"])),
        case(r#"externalId eq "a-1""#, Finds(&[])),
        case(r#"externalId eq "A-1""#, Finds(&["ana"])),
        case("externalId pr", Finds(&["bjensen", "ana"])),
        case("externalId eq null", Finds(&["jsmith", "omalley"])),
        case("externalId ne null", Finds(&["bjensen", "ana"])),
        case("not (externalId pr)", Finds(&["jsmith", "omalley"])),
        case(r#"externalId ne "701984""#, Finds(&["ana"])),
        case(
            r#"not (externalId eq "701984")"#,
            Finds(&["jsmith", "ana", "omalley"]),
        ),
        case(r#"id eq "{bjensen}""#, Finds(&["bjensen"])),
        case(r#"id eq "not-an-identifier""#, Finds(&[])),
        case(r#"id ne "{bjensen}""#, Finds(&["jsmith", "ana", "omalley"])),
        // Multi-valued attributes and value paths.
        case(r#"emails co "example.com""#, Finds(&["bjensen", "ana"])),
        case(r#"emails.value ew ".ORG""#, Finds(&["bjensen", "jsmith"])),
        case(
            r#"emails[value sw "babs" and value ew ".org"]"#,
            Finds(&["bjensen"]),
        ),
        case(
            r#"emails[value sw "bjensen" and value ew ".org"]"#,
            Finds(&[]),
        ),
        case(
            r#"emails.value sw "bjensen" and emails.value ew ".org""#,
            Finds(&["bjensen"]),
        ),
        case(
            r#"emails.value ne "bjensen@example.com""#,
            Finds(&["bjensen", "jsmith", "ana"]),
        ),
        case("emails pr", Finds(&["bjensen", "jsmith", "ana"])),
        case("not (emails pr)", Finds(&["omalley"])),
        case("emails.value eq null", Finds(&["omalley"])),
        case(
            r#"emails[not (value ew ".com")]"#,
            Finds(&["bjensen", "jsmith"]),
        ),
        // Booleans and dates.
        case("active eq true", Finds(&["bjensen", "ana"])),
        case("active eq false", Finds(&["jsmith", "omalley"])),
        case("active ne true", Finds(&["jsmith", "omalley"])),
        case(
            r#"meta.created gt "2026-11-24T12:00:00Z""#,
            Finds(&["ana", "omalley"]),
        ),
        case(
            r#"meta.created le "2026-11-24T12:00:00Z""#,
            Finds(&["bjensen", "jsmith"]),
        ),
        case(r#"meta.created eq "2026-11-24T13:00:00Z""#, Finds(&["ana"])),
        case(
            r#"meta.created ge "2026-11-24T13:00:00+01:00""#,
            Finds(&["jsmith", "ana", "omalley"]),
        ),
        case(
            r#"meta.lastModified ge "2026-11-24T20:00:00Z""#,
            Finds(&["jsmith"]),
        ),
        // Logic, precedence, case of words and schemas.
        case(
            r#"(userName eq "bjensen" or userName eq "omalley") and active eq true"#,
            Finds(&["bjensen"]),
        ),
        case(
            r#"userName eq "bjensen" or userName eq "omalley" and active eq true"#,
            Finds(&["bjensen"]),
        ),
        case(
            r#"not (active eq true) and not (emails pr)"#,
            Finds(&["omalley"]),
        ),
        case(r#"USERNAME Eq "jsmith""#, Finds(&["jsmith"])),
        case(
            r#"urn:ietf:params:scim:schemas:core:2.0:User:userName eq "jsmith""#,
            Finds(&["jsmith"]),
        ),
        case(
            r#"userName eq "bjensen" OR active EQ TRUE"#,
            Finds(&["bjensen", "ana"]),
        ),
        case(r#"((((userName eq "jsmith"))))"#, Finds(&["jsmith"])),
        // Attributes that cannot be filtered on.
        case("title pr", not_filterable("title")),
        case(r#"userType eq "Employee""#, not_filterable("userType")),
        case(r#"emails[type eq "work"]"#, not_filterable("emails.type")),
        case(r#"emails.type eq "work""#, not_filterable("emails.type")),
        case(r#"name eq "Ana""#, not_filterable("name")),
        case(
            r#"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq "x""#,
            not_filterable("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department"),
        ),
        case(r#"members eq "x""#, not_filterable("members")),
        case(
            r#"userName eq "a" and nickName pr"#,
            not_filterable("nickName"),
        ),
        // Operators and values the type does not take.
        case(
            r#"active eq "true""#,
            Refused(FilterRefusal::ValueNotAllowed {
                attribute: "active",
                expected: "true or false",
            }),
        ),
        case(
            "active gt true",
            Refused(FilterRefusal::OperatorNotAllowed {
                attribute: "active",
                operator: crate::api::Operator::Greater,
            }),
        ),
        case(
            r#"meta.created co "2026""#,
            Refused(FilterRefusal::OperatorNotAllowed {
                attribute: "meta.created",
                operator: crate::api::Operator::Contains,
            }),
        ),
        case(
            r#"meta.created gt "yesterday""#,
            Refused(FilterRefusal::ValueNotAllowed {
                attribute: "meta.created",
                expected: "a date and time of RFC 3339",
            }),
        ),
        case(
            "userName eq 42",
            Refused(FilterRefusal::ValueNotAllowed {
                attribute: "userName",
                expected: "a string",
            }),
        ),
        case(
            "userName eq true",
            Refused(FilterRefusal::ValueNotAllowed {
                attribute: "userName",
                expected: "a string",
            }),
        ),
        case("userName gt null", Refused(FilterRefusal::NullNotAllowed)),
        // The grammar.
        case("", unreadable("the filter is empty")),
        case("   ", unreadable("the filter is empty")),
        case(
            r#"userName xx "a""#,
            unreadable("an operator is not one SCIM defines"),
        ),
        case(
            "userName eq",
            unreadable("a value is expected after an operator"),
        ),
        case(
            "userName",
            unreadable("an operator is expected after an attribute"),
        ),
        case(r#"userName eq "a"#, unreadable("a string is not closed")),
        case(
            r#"userName eq "\q""#,
            unreadable("a string is not valid JSON"),
        ),
        case(
            r#"(userName eq "a""#,
            unreadable("a parenthesis is not closed"),
        ),
        case(
            r#"userName eq "a")"#,
            unreadable("there is more after the end of the filter"),
        ),
        case(
            r#"userName eq "a" userName eq "b""#,
            unreadable("there is more after the end of the filter"),
        ),
        case(
            r#"not userName eq "a""#,
            unreadable("not is followed by a parenthesis"),
        ),
        case(
            r#"userName eq "a" and"#,
            unreadable("the filter ends too early"),
        ),
        case(
            r#"and userName eq "a""#,
            unreadable("an attribute is expected before and and or"),
        ),
        case(
            r#"emails[value eq "a""#,
            unreadable("a value path's bracket is not closed"),
        ),
        case(
            r#"emails[value[value eq "a"]]"#,
            unreadable("a value path cannot hold another"),
        ),
        case(
            r#"userName[value eq "a"]"#,
            unreadable("only a multi-valued attribute takes a value path"),
        ),
        case(
            r#"userName eq "a" ; drop table"#,
            unreadable("it holds a character that is not part of a filter"),
        ),
        case("userName eq 1.2.3", unreadable("a number cannot be read")),
        case(
            r#")userName eq "a""#,
            unreadable("an attribute, a parenthesis or not is expected"),
        ),
        // The bounds, which come before every other reason.
        case(
            &format!(r#"title eq "{}""#, "a".repeat(1000)),
            Refused(FilterRefusal::TooLong),
        ),
        case(
            &format!("{}userName pr{}", "(".repeat(11), ")".repeat(11)),
            Refused(FilterRefusal::TooDeep),
        ),
        case(
            &format!("{}userName pr{}", "not (".repeat(11), ")".repeat(11)),
            Refused(FilterRefusal::TooDeep),
        ),
        case(
            &format!("{}emails[value pr]{}", "(".repeat(10), ")".repeat(10)),
            Refused(FilterRefusal::TooDeep),
        ),
        case(
            &vec!["title pr"; 21].join(" or "),
            Refused(FilterRefusal::TooManyComparisons),
        ),
        case(
            &format!("emails[{}]", vec!["value pr"; 21].join(" and ")),
            Refused(FilterRefusal::TooManyComparisons),
        ),
        // At the bounds, answered.
        case(
            &format!("{}userName pr{}", "(".repeat(10), ")".repeat(10)),
            Finds(&["bjensen", "jsmith", "ana", "omalley"]),
        ),
        case(
            &vec![r#"userName eq "jsmith""#; 20].join(" or "),
            Finds(&["jsmith"]),
        ),
        case(&format!(r#"userName eq "{}""#, "a".repeat(985)), Finds(&[])),
    ]
}

/// The corpus of filters on groups. The groups are those of
/// [`run_contract`]: `finance`, with `bjensen` and `payables` in it;
/// `payables`, with `jsmith`; and `on-call`, with nobody.
#[must_use]
pub fn group_corpus() -> Vec<CorpusCase> {
    use Expected::{Finds, Refused};
    vec![
        case(r#"displayName eq "FINANCE""#, Finds(&["finance"])),
        case(r#"displayName sw "p""#, Finds(&["payables"])),
        case(r#"displayName co "-""#, Finds(&["on-call"])),
        case(r#"externalId eq "F-1""#, Finds(&["finance"])),
        case(r#"externalId eq "f-1""#, Finds(&[])),
        case("externalId pr", Finds(&["finance"])),
        case(r#"members.value eq "{jsmith}""#, Finds(&["payables"])),
        case(r#"members eq "{payables}""#, Finds(&["finance"])),
        case(r#"members[value eq "{bjensen}"]"#, Finds(&["finance"])),
        case("members pr", Finds(&["finance", "payables"])),
        case("not (members pr)", Finds(&["on-call"])),
        case(r#"id eq "{finance}""#, Finds(&["finance"])),
        case(
            r#"meta.created ge "2026-11-24T10:00:00Z""#,
            Finds(&["finance", "payables", "on-call"]),
        ),
        case(r#"userName eq "bjensen""#, not_filterable("userName")),
        case(
            r#"members.display eq "x""#,
            not_filterable("members.display"),
        ),
        case(r#"members[type eq "User"]"#, not_filterable("members.type")),
        case(
            "displayName eq 1",
            Refused(FilterRefusal::ValueNotAllowed {
                attribute: "displayName",
                expected: "a string",
            }),
        ),
        case(
            r#"urn:ietf:params:scim:schemas:core:2.0:User:displayName eq "x""#,
            not_filterable("urn:ietf:params:scim:schemas:core:2.0:User:displayName"),
        ),
    ]
}

/// The filter with each `{name}` replaced by the identifier `names` gives
/// that name.
#[must_use]
pub fn with_identifiers(filter: &str, names: &BTreeMap<&'static str, String>) -> String {
    names.iter().fold(filter.to_owned(), |filter, (name, id)| {
        filter.replace(&format!("{{{name}}}"), id)
    })
}

/// The ports the contract runs against.
#[derive(Clone, Copy)]
pub struct ContractPorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// Where the identity context's users are stored.
    pub users: &'a dyn UserRepository,
    /// Where the identity context's groups are stored.
    pub groups: &'a dyn GroupRepository,
    /// The store of users under test.
    pub provisioned_users: &'a dyn ProvisionedUserRepository,
    /// The store of groups under test.
    pub provisioned_groups: &'a dyn ProvisionedGroupRepository,
}

impl std::fmt::Debug for ContractPorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContractPorts").finish_non_exhaustive()
    }
}

/// The moment the contract's resources are made at, and later ones.
/// 2026-11-24 at 10:00 UTC.
const START: Timestamp = Timestamp::UNIX_EPOCH.saturating_add(Duration::seconds(1_795_514_400));

fn at(hours: i64) -> Timestamp {
    START + Duration::hours(hours)
}

fn identifier(kind: IdentifierKind, value: &str) -> NormalizedIdentifier {
    NormalizedIdentifier::parse(kind, value).expect("a valid identifier")
}

fn person(
    username: Option<&str>,
    emails: &[&str],
    display_name: Option<&str>,
    created: Timestamp,
) -> User {
    let identifiers = username
        .map(|name| identifier(IdentifierKind::Username, name))
        .into_iter()
        .chain(
            emails
                .iter()
                .map(|email| identifier(IdentifierKind::Email, email)),
        )
        .collect();
    User::create(
        UserKind::Human,
        identifiers,
        Profile {
            display_name: display_name.map(str::to_owned),
            locale: None,
        },
        true,
        created,
    )
    .expect("a user")
    .0
}

fn kept(text: &str) -> Option<String> {
    Some(text.to_owned())
}

/// Runs a step in a unit of work of its own, committed.
macro_rules! within {
    ($ports:expr, $tenant:expr, |$uow:ident| $body:expr) => {{
        let mut $uow = $ports.units_of_work.begin($tenant).await.expect("begin");
        let value = $body;
        $uow.commit().await.expect("commit");
        value
    }};
}

struct Population {
    names: BTreeMap<&'static str, String>,
    users: BTreeMap<String, &'static str>,
    groups: BTreeMap<String, &'static str>,
}

impl Population {
    fn user_names(&self, found: &[UserId]) -> Vec<&'static str> {
        found
            .iter()
            .map(|id| {
                self.users
                    .get(&id.to_string())
                    .copied()
                    .unwrap_or("someone else")
            })
            .collect()
    }

    fn group_names(&self, found: &[GroupId]) -> Vec<&'static str> {
        found
            .iter()
            .map(|id| {
                self.groups
                    .get(&id.to_string())
                    .copied()
                    .unwrap_or("another group")
            })
            .collect()
    }
}

#[allow(clippy::too_many_lines, reason = "the population, written out")]
async fn populate(ports: ContractPorts<'_>, home: &TenantContext) -> Population {
    let names = |user: &mut User, given: Option<&str>, family: &str, moment: Timestamp| {
        let claims = StandardClaims {
            given_name: given.map(str::to_owned),
            family_name: Some(family.to_owned()),
            ..StandardClaims::default()
        };
        user.change_claims(claims, moment).expect("names");
    };
    let mut bjensen = person(
        Some("bjensen"),
        &["bjensen@example.com", "babs@jensen.org"],
        Some("Babs Jensen"),
        at(1),
    );
    names(&mut bjensen, Some("Barbara"), "Jensen", at(1));
    let mut jsmith = person(Some("JSmith"), &["john.smith@example.org"], None, at(2));
    jsmith.suspend("on leave", at(2)).expect("suspended");
    names(&mut jsmith, Some("John"), "Smith", at(2));
    let mut ana = person(None, &["Ana.Silva@Example.com"], Some("Ana Silva"), at(3));
    names(&mut ana, None, "Silva", at(3));
    let (mut omalley, _) = User::create(
        UserKind::Human,
        vec![identifier(IdentifierKind::Username, "omalley")],
        Profile {
            display_name: kept("Ryan O'Malley"),
            locale: None,
        },
        false,
        at(4),
    )
    .expect("a pending user");
    names(&mut omalley, None, "O'Malley", at(4));
    let (robot, _) = User::create(
        UserKind::ServiceAccount,
        vec![],
        Profile::default(),
        true,
        at(5),
    )
    .expect("a service account");
    let mut gone = person(Some("gone"), &["gone@example.com"], None, at(6));
    gone.deactivate(at(6)).expect("deactivated");
    gone.mark_deleted(at(6)).expect("deleted");
    // Deprovisioned by a DELETE while the policy deactivates: never found.
    let mut left = person(Some("left"), &["left@example.com"], Some("Left"), at(6));
    left.deactivate(at(6)).expect("deactivated");

    for user in [&bjensen, &jsmith, &ana, &omalley, &robot, &gone, &left] {
        within!(ports, home, |uow| ports
            .users
            .insert(uow.as_mut(), user)
            .await
            .expect("insert"));
    }
    let supplements = [
        (
            bjensen.id(),
            UserSupplement {
                external_id: kept("701984"),
                formatted_name: kept("Barbara Jensen"),
                department: kept("Tour Operations"),
                email_types: BTreeMap::from([(
                    "bjensen@example.com".to_owned(),
                    "work".to_owned(),
                )]),
                ..UserSupplement::default()
            },
            at(1),
        ),
        (jsmith.id(), UserSupplement::default(), at(10)),
        (
            ana.id(),
            UserSupplement {
                external_id: kept("A-1"),
                ..UserSupplement::default()
            },
            at(3),
        ),
        (omalley.id(), UserSupplement::default(), at(4)),
        (
            robot.id(),
            UserSupplement {
                external_id: kept("701984"),
                ..UserSupplement::default()
            },
            at(5),
        ),
    ];
    for (user_id, supplement, updated_at) in supplements {
        within!(ports, home, |uow| ports
            .provisioned_users
            .put(
                uow.as_mut(),
                &StoredUserSupplement {
                    user_id,
                    supplement,
                    created_at: updated_at.min(at(4)),
                    updated_at,
                    removed_at: None,
                },
            )
            .await
            .expect("put"));
    }

    within!(ports, home, |uow| ports
        .provisioned_users
        .put(
            uow.as_mut(),
            &StoredUserSupplement {
                user_id: left.id(),
                supplement: UserSupplement {
                    external_id: kept("701984"),
                    ..UserSupplement::default()
                },
                created_at: at(6),
                updated_at: at(6),
                removed_at: Some(at(6)),
            },
        )
        .await
        .expect("put"));

    let group = |name: &str, hours: i64| {
        Group::create(GroupName::parse(name).expect("a name"), None, at(hours))
            .expect("a group")
            .0
    };
    let (finance, payables, on_call) = (
        group("Finance", 1),
        group("payables", 2),
        group("on-call", 3),
    );
    for made in [&finance, &payables, &on_call] {
        within!(ports, home, |uow| ports
            .groups
            .insert(uow.as_mut(), made)
            .await
            .expect("insert"));
    }
    for (container, member) in [
        (finance.id(), GroupMember::User(bjensen.id())),
        (finance.id(), GroupMember::Group(payables.id())),
        (payables.id(), GroupMember::User(jsmith.id())),
    ] {
        within!(ports, home, |uow| ports
            .groups
            .add_member(uow.as_mut(), container, member, at(5))
            .await
            .expect("a member"));
    }
    within!(ports, home, |uow| ports
        .provisioned_groups
        .put(
            uow.as_mut(),
            &StoredGroupSupplement {
                group_id: finance.id(),
                supplement: GroupSupplement {
                    external_id: kept("F-1"),
                },
                created_at: at(1),
                updated_at: at(1),
            },
        )
        .await
        .expect("put"));

    let mut names = BTreeMap::new();
    let mut users = BTreeMap::new();
    for (name, id) in [
        ("bjensen", bjensen.id()),
        ("jsmith", jsmith.id()),
        ("ana", ana.id()),
        ("omalley", omalley.id()),
    ] {
        names.insert(name, id.to_string());
        users.insert(id.to_string(), name);
    }
    let mut groups = BTreeMap::new();
    for (name, id) in [
        ("finance", finance.id()),
        ("payables", payables.id()),
        ("on-call", on_call.id()),
    ] {
        names.insert(name, id.to_string());
        groups.insert(id.to_string(), name);
    }
    Population {
        names,
        users,
        groups,
    }
}

/// Another tenant with a person as alike to `bjensen` as can be, and a
/// group named as `finance`, all of which the home tenant never finds.
async fn populate_elsewhere(ports: ContractPorts<'_>, elsewhere: &TenantContext) {
    let twin = person(
        Some("bjensen"),
        &["bjensen@example.com"],
        Some("Babs Jensen"),
        at(1),
    );
    within!(ports, elsewhere, |uow| ports
        .users
        .insert(uow.as_mut(), &twin)
        .await
        .expect("insert"));
    within!(ports, elsewhere, |uow| ports
        .provisioned_users
        .put(
            uow.as_mut(),
            &StoredUserSupplement {
                user_id: twin.id(),
                supplement: UserSupplement {
                    external_id: kept("701984"),
                    ..UserSupplement::default()
                },
                created_at: at(1),
                updated_at: at(1),
                removed_at: None,
            },
        )
        .await
        .expect("put"));
    let finance = Group::create(GroupName::parse("Finance").expect("a name"), None, at(1))
        .expect("a group")
        .0;
    within!(ports, elsewhere, |uow| ports
        .groups
        .insert(uow.as_mut(), &finance)
        .await
        .expect("insert"));
    within!(ports, elsewhere, |uow| ports
        .groups
        .add_member(
            uow.as_mut(),
            finance.id(),
            GroupMember::User(twin.id()),
            at(1)
        )
        .await
        .expect("a member"));
}

fn query<A: Attribute>(
    filter: Option<&str>,
    sort_by: Option<&str>,
    sort_order: Option<&str>,
    start_index: Option<&str>,
    count: Option<&str>,
) -> ListQuery<A> {
    ListQuery::read(&ListParameters {
        filter,
        sort_by,
        sort_order,
        start_index,
        count,
    })
    .expect("a query")
}

/// Runs the contract of the provisioning stores. Each run uses tenants of
/// its own.
///
/// # Panics
///
/// Panics when the implementation breaks the contract.
#[allow(clippy::too_many_lines, reason = "the cases of one contract")]
pub async fn run_contract(ports: ContractPorts<'_>) {
    let (home, elsewhere) = (
        TenantContext::assume(TenantId::generate()),
        TenantContext::assume(TenantId::generate()),
    );
    let population = populate(ports, &home).await;
    populate_elsewhere(ports, &elsewhere).await;

    // What is kept of a user is loaded as stored, replaced by a later put,
    // and invisible from another tenant.
    let bjensen: UserId = population.names["bjensen"].parse().expect("an identifier");
    let stored = within!(ports, &home, |uow| ports
        .provisioned_users
        .get(uow.as_mut(), bjensen)
        .await
        .expect("get"))
    .expect("stored");
    assert_eq!(stored.supplement.external_id.as_deref(), Some("701984"));
    assert_eq!(
        stored.supplement.department.as_deref(),
        Some("Tour Operations")
    );
    assert_eq!((stored.created_at, stored.updated_at), (at(1), at(1)));
    assert_eq!(stored.removed_at, None);
    assert_eq!(
        stored
            .supplement
            .email_types
            .get("bjensen@example.com")
            .map(String::as_str),
        Some("work")
    );
    let hidden = within!(ports, &elsewhere, |uow| ports
        .provisioned_users
        .get(uow.as_mut(), bjensen)
        .await
        .expect("get"));
    assert_eq!(
        hidden, None,
        "what one tenant keeps is not seen from another"
    );

    // Every filter of the corpus finds what it says, in the order the
    // users were created.
    for corpus_case in user_corpus() {
        let Expected::Finds(expected) = corpus_case.expected else {
            continue;
        };
        let filter = with_identifiers(&corpus_case.filter, &population.names);
        let found = within!(ports, &home, |uow| ports
            .provisioned_users
            .find(
                uow.as_mut(),
                &query::<UserAttribute>(Some(&filter), None, None, None, None)
            )
            .await
            .expect("find"));
        assert_eq!(
            population.user_names(&found.ids),
            expected,
            "the filter {filter}"
        );
        assert_eq!(found.total, expected.len() as u64, "the filter {filter}");
    }
    for corpus_case in group_corpus() {
        let Expected::Finds(expected) = corpus_case.expected else {
            continue;
        };
        let filter = with_identifiers(&corpus_case.filter, &population.names);
        let found = within!(ports, &home, |uow| ports
            .provisioned_groups
            .find(
                uow.as_mut(),
                &query::<GroupAttribute>(Some(&filter), None, None, None, None)
            )
            .await
            .expect("find"));
        assert_eq!(
            population.group_names(&found.ids),
            expected,
            "the filter {filter}"
        );
    }

    // Orders, with a missing value last when ascending and first when
    // descending, and pages.
    let users = |filter: Option<&'static str>,
                 sort_by: Option<&'static str>,
                 order: Option<&'static str>,
                 start: Option<&'static str>,
                 count: Option<&'static str>| {
        query::<UserAttribute>(filter, sort_by, order, start, count)
    };
    for (asked, expected, total) in [
        (
            users(None, None, None, None, None),
            vec!["bjensen", "jsmith", "ana", "omalley"],
            4,
        ),
        (
            users(None, Some("userName"), None, None, None),
            vec!["ana", "bjensen", "jsmith", "omalley"],
            4,
        ),
        (
            users(None, Some("userName"), Some("descending"), None, None),
            vec!["omalley", "jsmith", "bjensen", "ana"],
            4,
        ),
        (
            users(None, Some("displayName"), None, None, None),
            vec!["ana", "bjensen", "omalley", "jsmith"],
            4,
        ),
        (
            users(None, Some("displayName"), Some("descending"), None, None),
            vec!["jsmith", "omalley", "bjensen", "ana"],
            4,
        ),
        (
            users(None, Some("meta.created"), Some("descending"), None, None),
            vec!["omalley", "ana", "jsmith", "bjensen"],
            4,
        ),
        (
            users(None, Some("meta.lastModified"), None, None, None),
            vec!["bjensen", "ana", "omalley", "jsmith"],
            4,
        ),
        (
            users(None, Some("userName"), None, Some("2"), Some("2")),
            vec!["bjensen", "jsmith"],
            4,
        ),
        (users(None, None, None, Some("5"), None), vec![], 4),
        (users(None, None, None, None, Some("0")), vec![], 4),
        (
            users(Some("active eq false"), None, None, Some("2"), Some("1")),
            vec!["omalley"],
            2,
        ),
    ] {
        let found = within!(ports, &home, |uow| ports
            .provisioned_users
            .find(uow.as_mut(), &asked)
            .await
            .expect("find"));
        assert_eq!(population.user_names(&found.ids), expected, "{asked:?}");
        assert_eq!(found.total, total, "{asked:?}");
    }
    let groups = query::<GroupAttribute>(None, Some("displayName"), Some("descending"), None, None);
    let found = within!(ports, &home, |uow| ports
        .provisioned_groups
        .find(uow.as_mut(), &groups)
        .await
        .expect("find"));
    assert_eq!(
        population.group_names(&found.ids),
        ["payables", "on-call", "finance"]
    );

    // Another tenant finds only its own.
    let found = within!(ports, &elsewhere, |uow| ports
        .provisioned_users
        .find(
            uow.as_mut(),
            &query::<UserAttribute>(Some(r#"externalId eq "701984""#), None, None, None, None)
        )
        .await
        .expect("find"));
    assert_eq!(found.total, 1);
    assert!(
        population.user_names(&found.ids) == ["someone else"],
        "another tenant's users are never found"
    );
    let found = within!(ports, &elsewhere, |uow| ports
        .provisioned_groups
        .find(
            uow.as_mut(),
            &query::<GroupAttribute>(
                Some(&format!(r#"members eq "{bjensen}""#)),
                None,
                None,
                None,
                None
            )
        )
        .await
        .expect("find"));
    assert_eq!(
        found.total, 0,
        "a member of one tenant is in no group of another"
    );

    // What is kept of a user is removed, in its tenant only.
    within!(ports, &elsewhere, |uow| ports
        .provisioned_users
        .remove(uow.as_mut(), bjensen)
        .await
        .expect("remove nothing"));
    assert!(
        within!(ports, &home, |uow| ports
            .provisioned_users
            .get(uow.as_mut(), bjensen)
            .await
            .expect("get"))
        .is_some(),
        "another tenant removes nothing of this one"
    );
    within!(ports, &home, |uow| ports
        .provisioned_users
        .remove(uow.as_mut(), bjensen)
        .await
        .expect("remove"));
    assert_eq!(
        within!(ports, &home, |uow| ports
            .provisioned_users
            .get(uow.as_mut(), bjensen)
            .await
            .expect("get")),
        None
    );

    // What is kept of a group is replaced and removed, in its tenant only.
    let finance: GroupId = population.names["finance"].parse().expect("an identifier");
    let hidden = within!(ports, &elsewhere, |uow| ports
        .provisioned_groups
        .get(uow.as_mut(), finance)
        .await
        .expect("get"));
    assert_eq!(hidden, None);
    within!(ports, &elsewhere, |uow| ports
        .provisioned_groups
        .remove(uow.as_mut(), finance)
        .await
        .expect("remove nothing"));
    let replaced = StoredGroupSupplement {
        group_id: finance,
        supplement: GroupSupplement {
            external_id: kept("F-2"),
        },
        created_at: at(1),
        updated_at: at(7),
    };
    within!(ports, &home, |uow| ports
        .provisioned_groups
        .put(uow.as_mut(), &replaced)
        .await
        .expect("put"));
    let stored = within!(ports, &home, |uow| ports
        .provisioned_groups
        .get(uow.as_mut(), finance)
        .await
        .expect("get"));
    assert_eq!(stored, Some(replaced));
    within!(ports, &home, |uow| ports
        .provisioned_groups
        .remove(uow.as_mut(), finance)
        .await
        .expect("remove"));
    let stored = within!(ports, &home, |uow| ports
        .provisioned_groups
        .get(uow.as_mut(), finance)
        .await
        .expect("get"));
    assert_eq!(stored, None);
}
