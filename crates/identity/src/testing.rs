//! In-memory port and the contract every implementation of it passes.
//!
//! The in-memory fake and the PostgreSQL adapter both run the contract,
//! which is what makes the fake a faithful stand-in in use case tests.

use crate::api::{
    Group, GroupMember, GroupName, GroupPolicy, GroupRepository, IdentifierKind, Invitation,
    InvitationId, InvitationRepository, InvitationStatus, Membership, NormalizedIdentifier,
    Organization, OrganizationName, OrganizationRepository, PostalAddress, Profile, StandardClaims,
    Unit, UnitId, UnitKind, User, UserKind, UserRepository,
};
use hodor_kernel::{
    DomainError, GroupId, OrganizationId, TenantContext, TenantId, Timestamp, UnitOfWork,
    UnitOfWorkFactory, UserId,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// Users kept in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemoryUsers {
    rows: Arc<Mutex<BTreeMap<(TenantId, UserId), User>>>,
}

type Rows<'a> = std::sync::MutexGuard<'a, BTreeMap<(TenantId, UserId), User>>;

impl InMemoryUsers {
    fn rows(&self) -> Rows<'_> {
        self.rows.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn taken(rows: &Rows<'_>, tenant: TenantId, user: &User) -> bool {
    rows.iter().any(|((other_tenant, other_id), other)| {
        *other_tenant == tenant
            && *other_id != user.id()
            && user
                .identifiers()
                .iter()
                .any(|mine| other.identifier_matching(&mine.value).is_some())
    })
}

fn identifier_taken() -> DomainError {
    DomainError::conflict(
        "identity.identifier_taken",
        "this login identifier is already in use",
    )
}

fn with_version(user: &User, version: u32) -> User {
    let mut state = user.snapshot().clone();
    state.version = version;
    User::from_snapshot(state)
}

#[async_trait::async_trait]
impl UserRepository for InMemoryUsers {
    async fn insert(&self, uow: &mut dyn UnitOfWork, user: &User) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut rows = self.rows();
        if taken(&rows, tenant, user) {
            return Err(identifier_taken());
        }
        rows.insert((tenant, user.id()), user.clone());
        Ok(())
    }

    async fn get(&self, uow: &mut dyn UnitOfWork, id: UserId) -> Result<Option<User>, DomainError> {
        Ok(self.rows().get(&(uow.tenant().tenant_id(), id)).cloned())
    }

    async fn find_by_identifier(
        &self,
        uow: &mut dyn UnitOfWork,
        identifier: &NormalizedIdentifier,
    ) -> Result<Option<User>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(self
            .rows()
            .iter()
            .find(|((other, _), user)| {
                *other == tenant && user.identifier_matching(identifier).is_some()
            })
            .map(|(_, user)| user.clone()))
    }

    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        after: Option<UserId>,
        limit: u32,
    ) -> Result<Vec<User>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        // The map is ordered by tenant and then by identifier, and
        // identifiers sort by creation time.
        Ok(self
            .rows()
            .iter()
            .filter(|((owner, id), _)| *owner == tenant && after.is_none_or(|after| *id > after))
            .take(limit as usize)
            .map(|(_, user)| user.clone())
            .collect())
    }

    async fn update(&self, uow: &mut dyn UnitOfWork, user: &User) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut rows = self.rows();
        let stored = rows.get(&(tenant, user.id())).ok_or_else(|| {
            DomainError::not_found("identity.user_not_found", "the user does not exist")
        })?;
        if stored.snapshot().version != user.snapshot().version {
            return Err(DomainError::conflict(
                "identity.user_modified_concurrently",
                "the user was changed by someone else; reload and try again",
            ));
        }
        if taken(&rows, tenant, user) {
            return Err(identifier_taken());
        }
        rows.insert(
            (tenant, user.id()),
            with_version(user, user.snapshot().version + 1),
        );
        Ok(())
    }
}

/// The ports under test.
#[derive(Clone)]
pub struct Ports<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The repository under test.
    pub users: &'a dyn UserRepository,
}

impl std::fmt::Debug for Ports<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ports").finish_non_exhaustive()
    }
}

/// A fixed, whole-second moment, so that stored timestamps compare equal
/// after a round trip through any storage.
const MOMENT: Timestamp = Timestamp::UNIX_EPOCH;

fn email(value: &str) -> NormalizedIdentifier {
    NormalizedIdentifier::parse(IdentifierKind::Email, value).expect("valid email")
}

fn username(value: &str) -> NormalizedIdentifier {
    NormalizedIdentifier::parse(IdentifierKind::Username, value).expect("valid username")
}

fn person(identifiers: Vec<NormalizedIdentifier>) -> User {
    let profile = Profile {
        display_name: Some("Ana Silva".to_owned()),
        locale: Some("pt-BR".to_owned()),
    };
    User::create(UserKind::Human, identifiers, profile, true, MOMENT)
        .expect("valid user")
        .0
}

async fn store(ports: &Ports<'_>, tenant: &TenantContext, user: &User) -> Result<(), DomainError> {
    let mut uow = ports.units_of_work.begin(tenant).await?;
    ports.users.insert(uow.as_mut(), user).await?;
    uow.commit().await
}

async fn save(ports: &Ports<'_>, tenant: &TenantContext, user: &User) -> Result<(), DomainError> {
    let mut uow = ports.units_of_work.begin(tenant).await?;
    ports.users.update(uow.as_mut(), user).await?;
    uow.commit().await
}

async fn load(ports: &Ports<'_>, tenant: &TenantContext, id: UserId) -> Option<User> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports.users.get(uow.as_mut(), id).await.expect("get")
}

async fn find(
    ports: &Ports<'_>,
    tenant: &TenantContext,
    value: &NormalizedIdentifier,
) -> Option<User> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .users
        .find_by_identifier(uow.as_mut(), value)
        .await
        .expect("find")
}

/// Runs the whole contract. Each case uses tenants of its own, so runs can
/// share one database.
///
/// # Panics
///
/// Panics when the implementation breaks the contract.
pub async fn run_contract(ports: Ports<'_>) {
    a_stored_user_is_loaded_unchanged(&ports).await;
    a_user_is_found_by_any_of_its_identifiers(&ports).await;
    an_identifier_belongs_to_one_user_per_tenant(&ports).await;
    the_same_identifier_can_exist_in_two_tenants(&ports).await;
    a_user_is_invisible_from_another_tenant(&ports).await;
    changes_to_identifiers_are_stored(&ports).await;
    a_stale_update_is_rejected(&ports).await;
    an_update_cannot_take_another_users_identifier(&ports).await;
    an_update_cannot_reach_another_tenant(&ports).await;
    an_erased_user_frees_its_identifiers(&ports).await;
    users_are_listed_in_the_order_they_were_created(&ports).await;
    standard_claims_are_stored_changed_and_erased(&ports).await;
}

/// Every standard claim with a value, the longest of each kind where it
/// matters, so that a store that cuts or loses one is caught.
#[must_use]
pub fn every_standard_claim() -> StandardClaims {
    StandardClaims {
        given_name: Some("Ana".to_owned()),
        family_name: Some("é".repeat(200)),
        middle_name: Some("Maria".to_owned()),
        nickname: Some("Aninha".to_owned()),
        profile: Some("https://example.com/ana".to_owned()),
        picture: Some(format!("https://example.com/{}", "p".repeat(1000))),
        website: Some("http://ana.example.org".to_owned()),
        gender: Some("female".to_owned()),
        birthdate: Some("1960-04-12".to_owned()),
        zoneinfo: Some("America/Sao_Paulo".to_owned()),
        phone_number: Some("+5511912345678;ext=12".to_owned()),
        phone_number_verified: true,
        address: Some(PostalAddress {
            formatted: Some("Rua Augusta, 100\nSão Paulo".to_owned()),
            street_address: Some("Rua Augusta, 100\nApto 2".to_owned()),
            locality: Some("São Paulo".to_owned()),
            region: Some("SP".to_owned()),
            postal_code: Some("01304-000".to_owned()),
            country: Some("BR".to_owned()),
        }),
    }
}

async fn standard_claims_are_stored_changed_and_erased(ports: &Ports<'_>) {
    let tenant = tenant();
    let mut user = person(vec![email("ana@example.com")]);
    user.change_claims(every_standard_claim(), MOMENT)
        .expect("good claims");
    store(ports, &tenant, &user).await.expect("insert");
    assert_eq!(load(ports, &tenant, user.id()).await, Some(user.clone()));

    let mut changed = load(ports, &tenant, user.id()).await.expect("exists");
    let fewer = StandardClaims {
        nickname: Some("Ana".to_owned()),
        address: Some(PostalAddress {
            country: Some("PT".to_owned()),
            ..PostalAddress::default()
        }),
        ..StandardClaims::default()
    };
    changed.change_claims(fewer.clone(), MOMENT).expect("good");
    save(ports, &tenant, &changed).await.expect("update");
    let stored = load(ports, &tenant, user.id()).await.expect("exists");
    assert_eq!(stored.snapshot().claims, fewer);

    let mut leaving = stored;
    leaving.deactivate(MOMENT).expect("deactivate");
    leaving.mark_deleted(MOMENT).expect("delete");
    save(ports, &tenant, &leaving).await.expect("update");
    let erased = load(ports, &tenant, user.id())
        .await
        .expect("the row remains");
    assert!(erased.snapshot().claims.is_empty());
}

fn tenant() -> TenantContext {
    TenantContext::assume(TenantId::generate())
}

async fn a_stored_user_is_loaded_unchanged(ports: &Ports<'_>) {
    let tenant = tenant();
    let user = person(vec![email("Ana@Example.com"), username("Ana.Silva")]);
    store(ports, &tenant, &user).await.expect("insert");
    assert_eq!(load(ports, &tenant, user.id()).await, Some(user));
}

async fn a_user_is_found_by_any_of_its_identifiers(ports: &Ports<'_>) {
    let tenant = tenant();
    let user = person(vec![email("ana@example.com"), username("ana")]);
    store(ports, &tenant, &user).await.expect("insert");

    for typed in ["ANA@example.com", "Ana"] {
        let value = NormalizedIdentifier::from_login(typed).expect("well formed");
        assert_eq!(
            find(ports, &tenant, &value).await.map(|u| u.id()),
            Some(user.id()),
            "{typed}"
        );
    }
    assert_eq!(
        find(ports, &tenant, &email("nobody@example.com")).await,
        None
    );
    // The same text as another kind of identifier is a different name.
    assert_eq!(find(ports, &tenant, &username("example")).await, None);
}

async fn an_identifier_belongs_to_one_user_per_tenant(ports: &Ports<'_>) {
    let tenant = tenant();
    store(ports, &tenant, &person(vec![email("ana@example.com")]))
        .await
        .expect("first");
    let error = store(
        ports,
        &tenant,
        &person(vec![username("other"), email("ANA@EXAMPLE.COM")]),
    )
    .await
    .expect_err("second");
    assert_eq!(error.code(), "identity.identifier_taken");
    // The rejected user left nothing behind, not even its free identifier.
    assert_eq!(find(ports, &tenant, &username("other")).await, None);
}

async fn the_same_identifier_can_exist_in_two_tenants(ports: &Ports<'_>) {
    let (first, second) = (tenant(), tenant());
    let in_first = person(vec![email("ana@example.com")]);
    let in_second = person(vec![email("ana@example.com")]);
    store(ports, &first, &in_first).await.expect("first tenant");
    store(ports, &second, &in_second)
        .await
        .expect("second tenant");

    let value = email("ana@example.com");
    assert_eq!(
        find(ports, &first, &value).await.map(|u| u.id()),
        Some(in_first.id())
    );
    assert_eq!(
        find(ports, &second, &value).await.map(|u| u.id()),
        Some(in_second.id())
    );
}

async fn a_user_is_invisible_from_another_tenant(ports: &Ports<'_>) {
    let (home, elsewhere) = (tenant(), tenant());
    let user = person(vec![email("ana@example.com")]);
    store(ports, &home, &user).await.expect("insert");

    assert_eq!(load(ports, &elsewhere, user.id()).await, None);
    assert_eq!(
        find(ports, &elsewhere, &email("ana@example.com")).await,
        None
    );
}

async fn changes_to_identifiers_are_stored(ports: &Ports<'_>) {
    let tenant = tenant();
    let user = person(vec![email("first@example.com")]);
    store(ports, &tenant, &user).await.expect("insert");

    let mut loaded = load(ports, &tenant, user.id()).await.expect("exists");
    loaded
        .add_identifier(email("second@example.com"), MOMENT)
        .expect("add");
    let (first, second) = (loaded.identifiers()[0].id, loaded.identifiers()[1].id);
    loaded.verify_identifier(second, MOMENT).expect("verify");
    loaded.choose_primary(second, MOMENT).expect("primary");
    loaded.remove_identifier(first, MOMENT).expect("remove");
    loaded.suspend("contract test", MOMENT).expect("suspend");
    save(ports, &tenant, &loaded).await.expect("update");

    let stored = load(ports, &tenant, user.id()).await.expect("exists");
    assert_eq!(stored.snapshot().version, user.snapshot().version + 1);
    assert_eq!(stored.status(), loaded.status());
    assert_eq!(
        stored.snapshot().status_reason.as_deref(),
        Some("contract test")
    );
    assert_eq!(stored.identifiers(), loaded.identifiers());
    assert!(stored.identifiers()[0].is_verified() && stored.identifiers()[0].primary);
    // The removed identifier no longer finds the user, and is free again.
    assert_eq!(
        find(ports, &tenant, &email("first@example.com")).await,
        None
    );
    store(ports, &tenant, &person(vec![email("first@example.com")]))
        .await
        .expect("the removed identifier can be taken by someone else");
}

async fn a_stale_update_is_rejected(ports: &Ports<'_>) {
    let tenant = tenant();
    let user = person(vec![email("ana@example.com")]);
    store(ports, &tenant, &user).await.expect("insert");

    // Two readers load the same version; the first to write wins.
    let mut first = load(ports, &tenant, user.id()).await.expect("exists");
    let mut second = first.clone();
    first.suspend("first", MOMENT).expect("suspend");
    second.suspend("second", MOMENT).expect("suspend");
    save(ports, &tenant, &first).await.expect("first update");
    let error = save(ports, &tenant, &second)
        .await
        .expect_err("stale update");
    assert_eq!(error.code(), "identity.user_modified_concurrently");

    let stored = load(ports, &tenant, user.id()).await.expect("exists");
    assert_eq!(stored.snapshot().status_reason.as_deref(), Some("first"));
}

async fn an_update_cannot_take_another_users_identifier(ports: &Ports<'_>) {
    let tenant = tenant();
    let owner = person(vec![email("owner@example.com")]);
    let other = person(vec![email("other@example.com")]);
    store(ports, &tenant, &owner).await.expect("owner");
    store(ports, &tenant, &other).await.expect("other");

    let mut grabbing = load(ports, &tenant, other.id()).await.expect("exists");
    grabbing
        .add_identifier(email("owner@example.com"), MOMENT)
        .expect("allowed by the aggregate, which sees only one user");
    let error = save(ports, &tenant, &grabbing).await.expect_err("taken");
    assert_eq!(error.code(), "identity.identifier_taken");

    // Nothing of the rejected update was kept.
    assert_eq!(load(ports, &tenant, other.id()).await, Some(other));
    assert_eq!(
        find(ports, &tenant, &email("owner@example.com"))
            .await
            .map(|u| u.id()),
        Some(owner.id())
    );
}

async fn an_update_cannot_reach_another_tenant(ports: &Ports<'_>) {
    let (home, elsewhere) = (tenant(), tenant());
    let victim = person(vec![email("victim@example.com")]);
    store(ports, &home, &victim).await.expect("insert");

    let mut tampered = victim.clone();
    tampered.suspend("tampering", MOMENT).expect("suspend");
    let error = save(ports, &elsewhere, &tampered)
        .await
        .expect_err("cross-tenant");
    assert_eq!(error.code(), "identity.user_not_found");
    assert_eq!(load(ports, &home, victim.id()).await, Some(victim));
}

async fn an_erased_user_frees_its_identifiers(ports: &Ports<'_>) {
    let tenant = tenant();
    let user = person(vec![email("ana@example.com")]);
    store(ports, &tenant, &user).await.expect("insert");

    let mut leaving = load(ports, &tenant, user.id()).await.expect("exists");
    leaving.deactivate(MOMENT).expect("deactivate");
    leaving.mark_deleted(MOMENT).expect("delete");
    save(ports, &tenant, &leaving).await.expect("update");

    let stored = load(ports, &tenant, user.id())
        .await
        .expect("the row remains");
    assert!(stored.identifiers().is_empty());
    assert_eq!(stored.snapshot().profile, Profile::default());
    store(ports, &tenant, &person(vec![email("ana@example.com")]))
        .await
        .expect("the address can be registered again");
}

async fn users_are_listed_in_the_order_they_were_created(ports: &Ports<'_>) {
    let (home, elsewhere) = (tenant(), tenant());
    let mut created = Vec::new();
    for index in 0..5 {
        let user = person(vec![email(&format!("person{index}@example.com"))]);
        store(ports, &home, &user).await.expect("insert");
        created.push(user);
    }
    store(ports, &elsewhere, &person(vec![email("other@example.com")]))
        .await
        .expect("insert");
    // Identifiers are made from the time, so creation order is their order.
    created.sort_by_key(User::id);

    let home = &home;
    let list = |after: Option<UserId>, limit: u32| async move {
        let mut uow = ports.units_of_work.begin(home).await.expect("begin");
        ports
            .users
            .list(uow.as_mut(), after, limit)
            .await
            .expect("list")
    };
    assert_eq!(list(None, 100).await, created);
    assert_eq!(list(None, 2).await, created[..2]);
    assert_eq!(list(Some(created[1].id()), 2).await, created[2..4]);
    assert!(list(Some(created[4].id()), 10).await.is_empty());
}

/// Groups and their members kept in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemoryGroups {
    state: Arc<Mutex<GroupRows>>,
}

#[derive(Debug, Default)]
struct GroupRows {
    groups: BTreeMap<(TenantId, GroupId), Group>,
    members: std::collections::BTreeSet<(TenantId, GroupId, GroupMember)>,
}

impl InMemoryGroups {
    fn state(&self) -> std::sync::MutexGuard<'_, GroupRows> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn name_taken() -> DomainError {
    DomainError::conflict(
        "identity.group_name_taken",
        "another group of the tenant has this name",
    )
}

fn group_with_version(group: &Group, version: u32) -> Group {
    let mut state = group.snapshot().clone();
    state.version = version;
    Group::from_snapshot(state)
}

fn name_used(rows: &GroupRows, tenant: TenantId, group: &Group) -> bool {
    rows.groups.iter().any(|((owner, id), other)| {
        *owner == tenant
            && *id != group.id()
            && other.name().normalized() == group.name().normalized()
    })
}

#[async_trait::async_trait]
impl GroupRepository for InMemoryGroups {
    async fn insert(&self, uow: &mut dyn UnitOfWork, group: &Group) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut rows = self.state();
        if name_used(&rows, tenant, group) {
            return Err(name_taken());
        }
        rows.groups.insert((tenant, group.id()), group.clone());
        Ok(())
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: GroupId,
    ) -> Result<Option<Group>, DomainError> {
        Ok(self
            .state()
            .groups
            .get(&(uow.tenant().tenant_id(), id))
            .cloned())
    }

    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        after: Option<GroupId>,
        limit: u32,
    ) -> Result<Vec<Group>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(self
            .state()
            .groups
            .iter()
            .filter(|((owner, id), _)| *owner == tenant && after.is_none_or(|after| *id > after))
            .take(limit as usize)
            .map(|(_, group)| group.clone())
            .collect())
    }

    async fn update(&self, uow: &mut dyn UnitOfWork, group: &Group) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut rows = self.state();
        let stored = rows.groups.get(&(tenant, group.id())).ok_or_else(|| {
            DomainError::not_found("identity.group_not_found", "the group does not exist")
        })?;
        if stored.snapshot().version != group.snapshot().version {
            return Err(DomainError::conflict(
                "identity.group_modified_concurrently",
                "the group was changed by someone else; reload and try again",
            ));
        }
        if name_used(&rows, tenant, group) {
            return Err(name_taken());
        }
        rows.groups.insert(
            (tenant, group.id()),
            group_with_version(group, group.snapshot().version + 1),
        );
        Ok(())
    }

    async fn delete(
        &self,
        uow: &mut dyn UnitOfWork,
        id: GroupId,
    ) -> Result<Option<u64>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut rows = self.state();
        if rows.groups.remove(&(tenant, id)).is_none() {
            return Ok(None);
        }
        let before = rows.members.len();
        rows.members
            .retain(|(owner, group, _)| !(*owner == tenant && *group == id));
        let members = (before - rows.members.len()) as u64;
        rows.members
            .retain(|(owner, _, member)| !(*owner == tenant && *member == GroupMember::Group(id)));
        Ok(Some(members))
    }

    async fn add_member(
        &self,
        uow: &mut dyn UnitOfWork,
        group: GroupId,
        member: GroupMember,
        _now: Timestamp,
    ) -> Result<bool, DomainError> {
        Ok(self
            .state()
            .members
            .insert((uow.tenant().tenant_id(), group, member)))
    }

    async fn remove_member(
        &self,
        uow: &mut dyn UnitOfWork,
        group: GroupId,
        member: GroupMember,
    ) -> Result<bool, DomainError> {
        Ok(self
            .state()
            .members
            .remove(&(uow.tenant().tenant_id(), group, member)))
    }

    async fn members(
        &self,
        uow: &mut dyn UnitOfWork,
        group: GroupId,
        after: Option<GroupMember>,
        limit: u32,
    ) -> Result<Vec<GroupMember>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(self
            .state()
            .members
            .iter()
            .filter(|(owner, of, member)| {
                *owner == tenant && *of == group && after.is_none_or(|after| *member > after)
            })
            .take(limit as usize)
            .map(|(_, _, member)| *member)
            .collect())
    }

    async fn lock_nesting(&self, _uow: &mut dyn UnitOfWork) -> Result<(), DomainError> {
        // One process, and every call below finishes before the next.
        Ok(())
    }

    async fn nesting(
        &self,
        uow: &mut dyn UnitOfWork,
    ) -> Result<Vec<(GroupId, GroupId)>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(self
            .state()
            .members
            .iter()
            .filter_map(|(owner, group, member)| match member {
                GroupMember::Group(inner) if *owner == tenant => Some((*group, *inner)),
                _ => None,
            })
            .collect())
    }

    async fn groups_of(
        &self,
        uow: &mut dyn UnitOfWork,
        user: UserId,
    ) -> Result<Vec<GroupId>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(self
            .state()
            .members
            .iter()
            .filter(|(owner, _, member)| *owner == tenant && *member == GroupMember::User(user))
            .map(|(_, group, _)| *group)
            .collect())
    }
}

/// A group policy with one bound for every tenant.
#[derive(Debug, Clone, Copy)]
pub struct FixedGroupPolicy(pub u8);

#[async_trait::async_trait]
impl GroupPolicy for FixedGroupPolicy {
    async fn max_depth(&self, _uow: &mut dyn UnitOfWork) -> Result<u8, DomainError> {
        Ok(self.0)
    }
}

/// The ports the contract of groups runs against.
#[derive(Clone)]
pub struct GroupPorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// Where the users that become members are stored.
    pub users: &'a dyn UserRepository,
    /// The repository under test.
    pub groups: &'a dyn GroupRepository,
}

impl std::fmt::Debug for GroupPorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupPorts").finish_non_exhaustive()
    }
}

fn a_group(name: &str) -> Group {
    let name = GroupName::parse(name).expect("a name");
    Group::create(name, Some("Who pays the bills".to_owned()), MOMENT)
        .expect("a group")
        .0
}

/// Runs the contract of groups. Each case uses tenants of its own.
///
/// # Panics
///
/// Panics when the implementation breaks the contract.
pub async fn run_group_contract(ports: GroupPorts<'_>) {
    let ports = &ports;
    // In one unit of work per step, committed, as the use cases do.
    macro_rules! within {
        ($tenant:expr, |$uow:ident| $body:expr) => {{
            let mut $uow = ports.units_of_work.begin($tenant).await.expect("begin");
            let value = $body;
            $uow.commit().await.expect("commit");
            value
        }};
    }

    // A stored group is loaded unchanged, and is invisible elsewhere.
    let (home, elsewhere) = (tenant(), tenant());
    let finance = a_group("Finance");
    within!(&home, |uow| ports
        .groups
        .insert(uow.as_mut(), &finance)
        .await
        .expect("insert"));
    let loaded = within!(&home, |uow| ports
        .groups
        .get(uow.as_mut(), finance.id())
        .await
        .expect("get"));
    assert_eq!(loaded.as_ref(), Some(&finance));
    let hidden = within!(&elsewhere, |uow| ports
        .groups
        .get(uow.as_mut(), finance.id())
        .await
        .expect("get"));
    assert_eq!(
        hidden, None,
        "a group of one tenant is not seen from another"
    );

    // Names are unique in a tenant without regard to case, and only there.
    let taken = within!(&home, |uow| ports
        .groups
        .insert(uow.as_mut(), &a_group("finance"))
        .await);
    assert_eq!(
        taken.expect_err("taken").code(),
        "identity.group_name_taken"
    );
    within!(&elsewhere, |uow| ports
        .groups
        .insert(uow.as_mut(), &a_group("finance"))
        .await
        .expect("another tenant"));

    // A change is stored with a higher version; a stale one is refused, and
    // so is a name another group has.
    let payables = a_group("payables");
    within!(&home, |uow| ports
        .groups
        .insert(uow.as_mut(), &payables)
        .await
        .expect("insert"));
    let mut renamed = finance.clone();
    renamed
        .change(
            GroupName::parse("Finance team").expect("a name"),
            None,
            MOMENT,
        )
        .expect("a change");
    within!(&home, |uow| ports
        .groups
        .update(uow.as_mut(), &renamed)
        .await
        .expect("update"));
    let stored = within!(&home, |uow| ports
        .groups
        .get(uow.as_mut(), finance.id())
        .await
        .expect("get"))
    .expect("stored");
    assert_eq!(stored.name().as_str(), "Finance team");
    assert_eq!(stored.description(), None);
    assert_eq!(stored.snapshot().version, finance.snapshot().version + 1);
    let stale = within!(&home, |uow| ports
        .groups
        .update(uow.as_mut(), &renamed)
        .await);
    assert_eq!(
        stale.expect_err("stale").code(),
        "identity.group_modified_concurrently"
    );
    let mut clash = stored.clone();
    clash
        .change(GroupName::parse("PAYABLES").expect("a name"), None, MOMENT)
        .expect("a change");
    let clash = within!(&home, |uow| ports.groups.update(uow.as_mut(), &clash).await);
    assert_eq!(
        clash.expect_err("taken").code(),
        "identity.group_name_taken"
    );
    let mut abroad = stored.clone();
    abroad
        .change(GroupName::parse("Elsewhere").expect("a name"), None, MOMENT)
        .expect("a change");
    let abroad = within!(&elsewhere, |uow| ports
        .groups
        .update(uow.as_mut(), &abroad)
        .await);
    assert_eq!(
        abroad.expect_err("not there").code(),
        "identity.group_not_found"
    );

    // Members: users first, then groups, each in the order of identifiers,
    // once each; the links between groups and the groups of a user follow.
    let mut people = Vec::new();
    for index in 0..3 {
        let user = person(vec![email(&format!("member{index}@example.com"))]);
        store(
            &Ports {
                units_of_work: ports.units_of_work,
                users: ports.users,
            },
            &home,
            &user,
        )
        .await
        .expect("a user");
        people.push(user.id());
    }
    people.sort();
    let mut expected: Vec<GroupMember> = people.iter().copied().map(GroupMember::User).collect();
    expected.push(GroupMember::Group(payables.id()));
    for member in expected.iter().rev() {
        let added = within!(&home, |uow| ports
            .groups
            .add_member(uow.as_mut(), finance.id(), *member, MOMENT)
            .await
            .expect("add"));
        assert!(added);
    }
    let again = within!(&home, |uow| ports
        .groups
        .add_member(uow.as_mut(), finance.id(), expected[0], MOMENT)
        .await
        .expect("add"));
    assert!(!again, "a member is in a group once");
    let all = within!(&home, |uow| ports
        .groups
        .members(uow.as_mut(), finance.id(), None, 10)
        .await
        .expect("members"));
    assert_eq!(all, expected);
    let page = within!(&home, |uow| ports
        .groups
        .members(uow.as_mut(), finance.id(), Some(expected[1]), 2)
        .await
        .expect("members"));
    assert_eq!(page, expected[2..4]);
    let nesting = within!(&home, |uow| ports
        .groups
        .nesting(uow.as_mut())
        .await
        .expect("nesting"));
    assert_eq!(nesting, [(finance.id(), payables.id())]);
    let of = within!(&home, |uow| ports
        .groups
        .groups_of(uow.as_mut(), people[0])
        .await
        .expect("groups of"));
    assert_eq!(of, [finance.id()]);
    let elsewhere_nesting = within!(&elsewhere, |uow| ports
        .groups
        .nesting(uow.as_mut())
        .await
        .expect("nesting"));
    assert!(elsewhere_nesting.is_empty(), "another tenant sees no link");
    within!(&home, |uow| ports
        .groups
        .lock_nesting(uow.as_mut())
        .await
        .expect("the lock"));

    // Taking a member out.
    let removed = within!(&home, |uow| ports
        .groups
        .remove_member(uow.as_mut(), finance.id(), expected[0])
        .await
        .expect("remove"));
    assert!(removed);
    let removed_again = within!(&home, |uow| ports
        .groups
        .remove_member(uow.as_mut(), finance.id(), expected[0])
        .await
        .expect("remove"));
    assert!(!removed_again);

    // Deleting a group takes its members out of it and it out of others.
    let accounts = a_group("accounts");
    within!(&home, |uow| ports
        .groups
        .insert(uow.as_mut(), &accounts)
        .await
        .expect("insert"));
    within!(&home, |uow| ports
        .groups
        .add_member(
            uow.as_mut(),
            payables.id(),
            GroupMember::Group(accounts.id()),
            MOMENT
        )
        .await
        .expect("add"));
    within!(&home, |uow| ports
        .groups
        .add_member(
            uow.as_mut(),
            payables.id(),
            GroupMember::User(people[1]),
            MOMENT
        )
        .await
        .expect("add"));
    let deleted = within!(&home, |uow| ports
        .groups
        .delete(uow.as_mut(), payables.id())
        .await
        .expect("delete"));
    assert_eq!(deleted, Some(2), "two direct members");
    let nesting = within!(&home, |uow| ports
        .groups
        .nesting(uow.as_mut())
        .await
        .expect("nesting"));
    assert!(
        nesting.is_empty(),
        "no link to or from a deleted group remains"
    );
    let of = within!(&home, |uow| ports
        .groups
        .groups_of(uow.as_mut(), people[1])
        .await
        .expect("groups of"));
    assert_eq!(of, [finance.id()]);
    let gone = within!(&home, |uow| ports
        .groups
        .delete(uow.as_mut(), payables.id())
        .await
        .expect("delete"));
    assert_eq!(gone, None);

    // Listing in the order of creation.
    let listed = within!(&home, |uow| ports
        .groups
        .list(uow.as_mut(), None, 10)
        .await
        .expect("list"));
    let ids: Vec<GroupId> = listed.iter().map(Group::id).collect();
    assert_eq!(ids, [finance.id(), accounts.id()]);
    let after = within!(&home, |uow| ports
        .groups
        .list(uow.as_mut(), Some(finance.id()), 10)
        .await
        .expect("list"));
    assert_eq!(after.len(), 1);
}

/// Organizations, their units and their members kept in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemoryOrganizations {
    state: Arc<Mutex<OrganizationRows>>,
}

#[derive(Debug, Default)]
struct OrganizationRows {
    organizations: BTreeMap<(TenantId, OrganizationId), Organization>,
    units: BTreeMap<(TenantId, UnitId), Unit>,
    memberships: BTreeMap<(TenantId, OrganizationId, UserId), Membership>,
}

impl InMemoryOrganizations {
    fn state(&self) -> std::sync::MutexGuard<'_, OrganizationRows> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn organization_name_used(
    rows: &OrganizationRows,
    tenant: TenantId,
    organization: &Organization,
) -> bool {
    rows.organizations.iter().any(|((owner, id), other)| {
        *owner == tenant
            && *id != organization.id()
            && other.name().normalized() == organization.name().normalized()
    })
}

fn organization_name_taken() -> DomainError {
    DomainError::conflict(
        "identity.organization_name_taken",
        "another organization of the tenant has this name",
    )
}

#[async_trait::async_trait]
impl OrganizationRepository for InMemoryOrganizations {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        organization: &Organization,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut rows = self.state();
        if organization_name_used(&rows, tenant, organization) {
            return Err(organization_name_taken());
        }
        rows.organizations
            .insert((tenant, organization.id()), organization.clone());
        Ok(())
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: OrganizationId,
    ) -> Result<Option<Organization>, DomainError> {
        Ok(self
            .state()
            .organizations
            .get(&(uow.tenant().tenant_id(), id))
            .cloned())
    }

    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        after: Option<OrganizationId>,
        limit: u32,
    ) -> Result<Vec<Organization>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(self
            .state()
            .organizations
            .iter()
            .filter(|((owner, id), _)| *owner == tenant && after.is_none_or(|after| *id > after))
            .take(limit as usize)
            .map(|(_, organization)| organization.clone())
            .collect())
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        organization: &Organization,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut rows = self.state();
        let stored = rows
            .organizations
            .get(&(tenant, organization.id()))
            .ok_or_else(|| {
                DomainError::not_found(
                    "identity.organization_not_found",
                    "the organization does not exist",
                )
            })?;
        if stored.snapshot().version != organization.snapshot().version {
            return Err(DomainError::conflict(
                "identity.organization_modified_concurrently",
                "the organization was changed by someone else; reload and try again",
            ));
        }
        if organization_name_used(&rows, tenant, organization) {
            return Err(organization_name_taken());
        }
        let mut state = organization.snapshot().clone();
        state.version += 1;
        rows.organizations.insert(
            (tenant, organization.id()),
            Organization::from_snapshot(state),
        );
        Ok(())
    }

    async fn delete(
        &self,
        uow: &mut dyn UnitOfWork,
        id: OrganizationId,
    ) -> Result<Option<u64>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut rows = self.state();
        if rows.organizations.remove(&(tenant, id)).is_none() {
            return Ok(None);
        }
        rows.units
            .retain(|(owner, _), unit| !(*owner == tenant && unit.organization == id));
        let before = rows.memberships.len();
        rows.memberships
            .retain(|(owner, organization, _), _| !(*owner == tenant && *organization == id));
        Ok(Some((before - rows.memberships.len()) as u64))
    }

    async fn lock_tree(
        &self,
        _uow: &mut dyn UnitOfWork,
        _organization: OrganizationId,
    ) -> Result<(), DomainError> {
        Ok(())
    }

    async fn units(
        &self,
        uow: &mut dyn UnitOfWork,
        organization: OrganizationId,
    ) -> Result<Vec<Unit>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(self
            .state()
            .units
            .iter()
            .filter(|((owner, _), unit)| *owner == tenant && unit.organization == organization)
            .map(|(_, unit)| unit.clone())
            .collect())
    }

    async fn save_unit(&self, uow: &mut dyn UnitOfWork, unit: &Unit) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut rows = self.state();
        let taken = rows.units.iter().any(|((owner, id), other)| {
            *owner == tenant
                && *id != unit.id
                && other.organization == unit.organization
                && other.parent == unit.parent
                && other.name.normalized() == unit.name.normalized()
        });
        if taken {
            return Err(DomainError::conflict(
                "identity.unit_name_taken",
                "another unit with the same parent has this name",
            ));
        }
        rows.units.insert((tenant, unit.id), unit.clone());
        Ok(())
    }

    async fn delete_unit(
        &self,
        uow: &mut dyn UnitOfWork,
        organization: OrganizationId,
        unit: UnitId,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut rows = self.state();
        let exists = rows
            .units
            .get(&(tenant, unit))
            .is_some_and(|stored| stored.organization == organization);
        if !exists {
            return Ok(false);
        }
        if rows
            .units
            .iter()
            .any(|((owner, _), other)| *owner == tenant && other.parent == Some(unit))
        {
            return Err(DomainError::conflict(
                "identity.unit_not_empty",
                "a unit with units below it cannot be deleted",
            ));
        }
        rows.units.remove(&(tenant, unit));
        for ((owner, _, _), membership) in &mut rows.memberships {
            if *owner == tenant {
                membership.units.remove(&unit);
            }
        }
        Ok(true)
    }

    async fn membership(
        &self,
        uow: &mut dyn UnitOfWork,
        organization: OrganizationId,
        user: UserId,
    ) -> Result<Option<Membership>, DomainError> {
        Ok(self
            .state()
            .memberships
            .get(&(uow.tenant().tenant_id(), organization, user))
            .cloned())
    }

    async fn save_membership(
        &self,
        uow: &mut dyn UnitOfWork,
        membership: &Membership,
    ) -> Result<(), DomainError> {
        let key = (
            uow.tenant().tenant_id(),
            membership.organization,
            membership.user,
        );
        self.state().memberships.insert(key, membership.clone());
        Ok(())
    }

    async fn remove_membership(
        &self,
        uow: &mut dyn UnitOfWork,
        organization: OrganizationId,
        user: UserId,
    ) -> Result<bool, DomainError> {
        Ok(self
            .state()
            .memberships
            .remove(&(uow.tenant().tenant_id(), organization, user))
            .is_some())
    }

    async fn members(
        &self,
        uow: &mut dyn UnitOfWork,
        organization: OrganizationId,
        after: Option<UserId>,
        limit: u32,
    ) -> Result<Vec<Membership>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(self
            .state()
            .memberships
            .iter()
            .filter(|((owner, of, user), _)| {
                *owner == tenant && *of == organization && after.is_none_or(|after| *user > after)
            })
            .take(limit as usize)
            .map(|(_, membership)| membership.clone())
            .collect())
    }

    async fn memberships_of(
        &self,
        uow: &mut dyn UnitOfWork,
        user: UserId,
    ) -> Result<Vec<Membership>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(self
            .state()
            .memberships
            .iter()
            .filter(|((owner, _, of), _)| *owner == tenant && *of == user)
            .map(|(_, membership)| membership.clone())
            .collect())
    }
}

/// The ports the contract of organizations runs against.
#[derive(Clone)]
pub struct OrganizationPorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// Where the users that become members are stored.
    pub users: &'a dyn UserRepository,
    /// The repository under test.
    pub organizations: &'a dyn OrganizationRepository,
}

impl std::fmt::Debug for OrganizationPorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrganizationPorts").finish_non_exhaustive()
    }
}

fn an_organization(name: &str) -> Organization {
    let name = OrganizationName::parse(name).expect("a name");
    Organization::create(name, None, MOMENT)
        .expect("an organization")
        .0
}

fn a_unit(organization: OrganizationId, parent: Option<UnitId>, name: &str) -> Unit {
    Unit {
        id: UnitId::generate(),
        organization,
        parent,
        name: OrganizationName::parse(name).expect("a name"),
        kind: UnitKind::Department,
        created_at: MOMENT,
        updated_at: MOMENT,
    }
}

/// Runs the contract of organizations. Each case uses tenants of its own.
///
/// # Panics
///
/// Panics when the implementation breaks the contract.
pub async fn run_organization_contract(ports: OrganizationPorts<'_>) {
    let ports = &ports;
    macro_rules! within {
        ($tenant:expr, |$uow:ident| $body:expr) => {{
            let mut $uow = ports.units_of_work.begin($tenant).await.expect("begin");
            let value = $body;
            $uow.commit().await.expect("commit");
            value
        }};
    }
    let repository = ports.organizations;
    let (home, elsewhere) = (tenant(), tenant());

    // Stored, loaded unchanged, invisible elsewhere, names unique in a tenant.
    let acme = an_organization("Acme");
    within!(&home, |uow| repository
        .insert(uow.as_mut(), &acme)
        .await
        .expect("insert"));
    let loaded = within!(&home, |uow| repository
        .get(uow.as_mut(), acme.id())
        .await
        .expect("get"));
    assert_eq!(loaded.as_ref(), Some(&acme));
    let hidden = within!(&elsewhere, |uow| repository
        .get(uow.as_mut(), acme.id())
        .await
        .expect("get"));
    assert_eq!(hidden, None);
    let taken = within!(&home, |uow| repository
        .insert(uow.as_mut(), &an_organization("ACME"))
        .await);
    assert_eq!(
        taken.expect_err("taken").code(),
        "identity.organization_name_taken"
    );
    within!(&elsewhere, |uow| repository
        .insert(uow.as_mut(), &an_organization("Acme"))
        .await
        .expect("another tenant"));

    // A change, a stale change.
    let mut renamed = acme.clone();
    renamed
        .change(
            OrganizationName::parse("Acme Inc").expect("a name"),
            Some("Rockets".to_owned()),
            MOMENT,
        )
        .expect("a change");
    within!(&home, |uow| repository
        .update(uow.as_mut(), &renamed)
        .await
        .expect("update"));
    let stale = within!(&home, |uow| repository.update(uow.as_mut(), &renamed).await);
    assert_eq!(
        stale.expect_err("stale").code(),
        "identity.organization_modified_concurrently"
    );

    // Units: names unique among siblings only.
    let engineering = a_unit(acme.id(), None, "Engineering");
    let platform = a_unit(acme.id(), Some(engineering.id), "Platform");
    let sales = a_unit(acme.id(), None, "Sales");
    let sales_platform = a_unit(acme.id(), Some(sales.id), "Platform");
    for unit in [&engineering, &platform, &sales, &sales_platform] {
        within!(&home, |uow| repository
            .save_unit(uow.as_mut(), unit)
            .await
            .expect("a unit"));
    }
    let twin = a_unit(acme.id(), Some(engineering.id), "platform");
    let twin = within!(&home, |uow| repository.save_unit(uow.as_mut(), &twin).await);
    assert_eq!(
        twin.expect_err("a sibling's name").code(),
        "identity.unit_name_taken"
    );
    let units = within!(&home, |uow| repository
        .units(uow.as_mut(), acme.id())
        .await
        .expect("units"));
    assert_eq!(units.len(), 4);
    let mut moved = platform.clone();
    moved.parent = None;
    moved.name = OrganizationName::parse("Platform team").expect("a name");
    within!(&home, |uow| repository
        .save_unit(uow.as_mut(), &moved)
        .await
        .expect("a change"));
    let units = within!(&home, |uow| repository
        .units(uow.as_mut(), acme.id())
        .await
        .expect("units"));
    assert!(units.contains(&moved));
    let refused = within!(&home, |uow| repository
        .delete_unit(uow.as_mut(), acme.id(), sales.id)
        .await);
    assert_eq!(
        refused.expect_err("not empty").code(),
        "identity.unit_not_empty"
    );

    // Memberships.
    let mut people = Vec::new();
    for index in 0..3 {
        let user = person(vec![email(&format!("staff{index}@example.com"))]);
        store(
            &Ports {
                units_of_work: ports.units_of_work,
                users: ports.users,
            },
            &home,
            &user,
        )
        .await
        .expect("a user");
        people.push(user.id());
    }
    people.sort();
    for user in &people {
        let membership = Membership {
            organization: acme.id(),
            user: *user,
            units: std::collections::BTreeSet::from([sales_platform.id, engineering.id]),
            added_at: MOMENT,
        };
        within!(&home, |uow| repository
            .save_membership(uow.as_mut(), &membership)
            .await
            .expect("a member"));
    }
    let first = within!(&home, |uow| repository
        .membership(uow.as_mut(), acme.id(), people[0])
        .await
        .expect("one"))
    .expect("a membership");
    assert_eq!(first.units.len(), 2);
    let mut fewer = first.clone();
    fewer.units = std::collections::BTreeSet::from([engineering.id]);
    within!(&home, |uow| repository
        .save_membership(uow.as_mut(), &fewer)
        .await
        .expect("replace"));
    let again = within!(&home, |uow| repository
        .membership(uow.as_mut(), acme.id(), people[0])
        .await
        .expect("one"));
    assert_eq!(again, Some(fewer));
    let page = within!(&home, |uow| repository
        .members(uow.as_mut(), acme.id(), Some(people[0]), 1)
        .await
        .expect("members"));
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].user, people[1]);
    let of = within!(&home, |uow| repository
        .memberships_of(uow.as_mut(), people[2])
        .await
        .expect("of"));
    assert_eq!(of.len(), 1);
    assert_eq!(of[0].organization, acme.id());

    // Deleting a unit takes members out of it, not out of the organization.
    within!(&home, |uow| assert!(
        repository
            .delete_unit(uow.as_mut(), acme.id(), sales_platform.id)
            .await
            .expect("delete")
    ));
    let left = within!(&home, |uow| repository
        .membership(uow.as_mut(), acme.id(), people[1])
        .await
        .expect("one"))
    .expect("still a member");
    assert_eq!(
        left.units,
        std::collections::BTreeSet::from([engineering.id])
    );
    let removed = within!(&home, |uow| repository
        .remove_membership(uow.as_mut(), acme.id(), people[2])
        .await
        .expect("remove"));
    assert!(removed);
    let removed = within!(&home, |uow| repository
        .remove_membership(uow.as_mut(), acme.id(), people[2])
        .await
        .expect("remove"));
    assert!(!removed);

    // Deleting the organization deletes its units and memberships.
    let deleted = within!(&home, |uow| repository
        .delete(uow.as_mut(), acme.id())
        .await
        .expect("delete"));
    assert_eq!(deleted, Some(2));
    let units = within!(&home, |uow| repository
        .units(uow.as_mut(), acme.id())
        .await
        .expect("units"));
    assert!(units.is_empty());
    let of = within!(&home, |uow| repository
        .memberships_of(uow.as_mut(), people[0])
        .await
        .expect("of"));
    assert!(of.is_empty());
}

/// Invitations kept in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemoryInvitations {
    rows: Arc<Mutex<BTreeMap<(TenantId, InvitationId), Invitation>>>,
}

impl InMemoryInvitations {
    fn rows(&self) -> std::sync::MutexGuard<'_, BTreeMap<(TenantId, InvitationId), Invitation>> {
        self.rows.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait::async_trait]
impl InvitationRepository for InMemoryInvitations {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        invitation: &Invitation,
    ) -> Result<(), DomainError> {
        self.rows().insert(
            (uow.tenant().tenant_id(), invitation.id),
            invitation.clone(),
        );
        Ok(())
    }

    async fn withdraw_pending(
        &self,
        uow: &mut dyn UnitOfWork,
        organization: OrganizationId,
        email: &str,
        now: Timestamp,
    ) -> Result<Option<InvitationId>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut rows = self.rows();
        let found = rows.iter_mut().find(|((owner, _), invitation)| {
            *owner == tenant
                && invitation.organization == organization
                && invitation.email == email
                && invitation.status == InvitationStatus::Pending
        });
        Ok(found.map(|(_, invitation)| {
            invitation.status = InvitationStatus::Withdrawn;
            invitation.withdrawn_at = Some(now);
            invitation.id
        }))
    }

    async fn withdraw(
        &self,
        uow: &mut dyn UnitOfWork,
        organization: OrganizationId,
        id: InvitationId,
        now: Timestamp,
    ) -> Result<bool, DomainError> {
        let mut rows = self.rows();
        let Some(invitation) = rows.get_mut(&(uow.tenant().tenant_id(), id)) else {
            return Ok(false);
        };
        if invitation.organization != organization || invitation.status != InvitationStatus::Pending
        {
            return Ok(false);
        }
        invitation.status = InvitationStatus::Withdrawn;
        invitation.withdrawn_at = Some(now);
        Ok(true)
    }

    async fn find_by_hash(
        &self,
        uow: &mut dyn UnitOfWork,
        token_hash: &[u8; 32],
    ) -> Result<Option<Invitation>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(self
            .rows()
            .iter()
            .find(|((owner, _), invitation)| {
                *owner == tenant && invitation.token_hash == *token_hash
            })
            .map(|(_, invitation)| invitation.clone()))
    }

    async fn use_up(
        &self,
        uow: &mut dyn UnitOfWork,
        id: InvitationId,
        user: UserId,
        now: Timestamp,
    ) -> Result<bool, DomainError> {
        let mut rows = self.rows();
        let Some(invitation) = rows.get_mut(&(uow.tenant().tenant_id(), id)) else {
            return Ok(false);
        };
        if !invitation.is_good_at(now) {
            return Ok(false);
        }
        invitation.status = InvitationStatus::Accepted;
        invitation.accepted = Some((user, now));
        Ok(true)
    }

    async fn pending(
        &self,
        uow: &mut dyn UnitOfWork,
        organization: OrganizationId,
    ) -> Result<Vec<Invitation>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut found: Vec<Invitation> = self
            .rows()
            .iter()
            .filter(|((owner, _), invitation)| {
                *owner == tenant
                    && invitation.organization == organization
                    && invitation.status == InvitationStatus::Pending
            })
            .map(|(_, invitation)| invitation.clone())
            .collect();
        found.reverse();
        Ok(found)
    }
}

/// The ports the contract of invitations runs against.
#[derive(Clone)]
pub struct InvitationPorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// Where the organizations invitations are to are stored.
    pub organizations: &'a dyn OrganizationRepository,
    /// Where the users who accept are stored.
    pub users: &'a dyn UserRepository,
    /// The repository under test.
    pub invitations: &'a dyn InvitationRepository,
}

impl std::fmt::Debug for InvitationPorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvitationPorts").finish_non_exhaustive()
    }
}

fn an_invitation(organization: OrganizationId, email: &str, seed: u8) -> Invitation {
    Invitation {
        id: InvitationId::generate(),
        organization,
        email: email.to_owned(),
        units: std::collections::BTreeSet::new(),
        token_hash: [seed; 32],
        status: InvitationStatus::Pending,
        created_at: MOMENT,
        expires_at: MOMENT + time::Duration::days(7),
        accepted: None,
        withdrawn_at: None,
    }
}

/// Runs the contract of invitations. Each case uses tenants of its own.
///
/// # Panics
///
/// Panics when the implementation breaks the contract.
pub async fn run_invitation_contract(ports: InvitationPorts<'_>) {
    let ports = &ports;
    macro_rules! within {
        ($tenant:expr, |$uow:ident| $body:expr) => {{
            let mut $uow = ports.units_of_work.begin($tenant).await.expect("begin");
            let value = $body;
            $uow.commit().await.expect("commit");
            value
        }};
    }
    let repository = ports.invitations;
    let (home, elsewhere) = (tenant(), tenant());
    let acme = an_organization("Acme");
    let globex = an_organization("Globex");
    for organization in [&acme, &globex] {
        within!(&home, |uow| ports
            .organizations
            .insert(uow.as_mut(), organization)
            .await
            .expect("insert"));
    }

    // Stored and found by its hash, in its tenant only.
    let first = an_invitation(acme.id(), "ana@example.com", 1);
    within!(&home, |uow| repository
        .insert(uow.as_mut(), &first)
        .await
        .expect("insert"));
    let found = within!(&home, |uow| repository
        .find_by_hash(uow.as_mut(), &[1; 32])
        .await
        .expect("find"));
    assert_eq!(found.as_ref(), Some(&first));
    let hidden = within!(&elsewhere, |uow| repository
        .find_by_hash(uow.as_mut(), &[1; 32])
        .await
        .expect("find"));
    assert_eq!(hidden, None);

    // A newer invitation to the same address withdraws the earlier one, of
    // the same organization only.
    let other_organization = an_invitation(globex.id(), "ana@example.com", 2);
    within!(&home, |uow| repository
        .insert(uow.as_mut(), &other_organization)
        .await
        .expect("insert"));
    let withdrawn = within!(&home, |uow| repository
        .withdraw_pending(uow.as_mut(), acme.id(), "ana@example.com", MOMENT)
        .await
        .expect("withdraw"));
    assert_eq!(withdrawn, Some(first.id));
    let second = an_invitation(acme.id(), "ana@example.com", 3);
    within!(&home, |uow| repository
        .insert(uow.as_mut(), &second)
        .await
        .expect("insert"));
    let earlier = within!(&home, |uow| repository
        .find_by_hash(uow.as_mut(), &[1; 32])
        .await
        .expect("find"))
    .expect("kept");
    assert_eq!(earlier.status, InvitationStatus::Withdrawn);
    let still = within!(&home, |uow| repository
        .find_by_hash(uow.as_mut(), &[2; 32])
        .await
        .expect("find"))
    .expect("kept");
    assert_eq!(
        still.status,
        InvitationStatus::Pending,
        "another organization's invitation stays"
    );
    let pending = within!(&home, |uow| repository
        .pending(uow.as_mut(), acme.id())
        .await
        .expect("pending"));
    assert_eq!(
        pending
            .iter()
            .map(|invitation| invitation.id)
            .collect::<Vec<_>>(),
        [second.id]
    );

    // Used up once, by one user.
    let user = person(vec![email("ana@example.com")]);
    store(
        &Ports {
            units_of_work: ports.units_of_work,
            users: ports.users,
        },
        &home,
        &user,
    )
    .await
    .expect("a user");
    let used = within!(&home, |uow| repository
        .use_up(uow.as_mut(), second.id, user.id(), MOMENT)
        .await
        .expect("use"));
    assert!(used);
    let again = within!(&home, |uow| repository
        .use_up(uow.as_mut(), second.id, user.id(), MOMENT)
        .await
        .expect("use"));
    assert!(!again, "an invitation is accepted once");
    let accepted = within!(&home, |uow| repository
        .find_by_hash(uow.as_mut(), &[3; 32])
        .await
        .expect("find"))
    .expect("kept");
    assert_eq!(accepted.status, InvitationStatus::Accepted);
    assert_eq!(accepted.accepted.map(|(by, _)| by), Some(user.id()));

    // An expired invitation is not used up, and a withdrawn one cannot be
    // withdrawn again.
    let late = MOMENT + time::Duration::days(8);
    let expired = within!(&home, |uow| repository
        .use_up(uow.as_mut(), still.id, user.id(), late)
        .await
        .expect("use"));
    assert!(!expired);
    let twice = within!(&home, |uow| repository
        .withdraw(uow.as_mut(), acme.id(), first.id, MOMENT)
        .await
        .expect("withdraw"));
    assert!(!twice);
    let mismatched = within!(&home, |uow| repository
        .withdraw(uow.as_mut(), acme.id(), still.id, MOMENT)
        .await
        .expect("withdraw"));
    assert!(
        !mismatched,
        "an invitation of another organization is not withdrawn through this one"
    );
    let withdrawn = within!(&home, |uow| repository
        .withdraw(uow.as_mut(), globex.id(), still.id, MOMENT)
        .await
        .expect("withdraw"));
    assert!(withdrawn);
}

/// The owners of each workload, by tenant and workload, with when each
/// became one.
type OwnerRows = BTreeMap<(TenantId, UserId), Vec<(Timestamp, UserId)>>;

/// What a [`RecordingWorkloadAccess`] was asked to end: the tenant, the
/// workload and the reason.
type AccessCall = (TenantId, UserId, &'static str);

/// The owners of service accounts and agents kept in memory, beside the
/// users they list from.
#[derive(Debug, Clone, Default)]
pub struct InMemoryWorkloads {
    users: InMemoryUsers,
    owners: Arc<Mutex<OwnerRows>>,
}

impl InMemoryWorkloads {
    /// Workloads listed from `users`, which must be the users the use
    /// cases store.
    #[must_use]
    pub fn over(users: InMemoryUsers) -> Self {
        Self {
            users,
            owners: Arc::default(),
        }
    }

    fn owner_rows(&self) -> std::sync::MutexGuard<'_, OwnerRows> {
        self.owners.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait::async_trait]
impl crate::api::WorkloadRepository for InMemoryWorkloads {
    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        kind: UserKind,
        after: Option<UserId>,
        limit: u32,
    ) -> Result<Vec<User>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(self
            .users
            .rows()
            .iter()
            .filter(|((owner, id), user)| {
                *owner == tenant
                    && after.is_none_or(|after| *id > after)
                    && user.kind() == kind
                    && user.status() != crate::api::UserStatus::Deleted
            })
            .take(limit as usize)
            .map(|(_, user)| user.clone())
            .collect())
    }

    async fn owners(
        &self,
        uow: &mut dyn UnitOfWork,
        workload: UserId,
    ) -> Result<Vec<UserId>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut owners = self
            .owner_rows()
            .get(&(tenant, workload))
            .cloned()
            .unwrap_or_default();
        owners.sort();
        Ok(owners.into_iter().map(|(_, owner)| owner).collect())
    }

    async fn replace_owners(
        &self,
        uow: &mut dyn UnitOfWork,
        workload: UserId,
        owners: &[UserId],
        now: Timestamp,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        {
            let users = self.users.rows();
            if owners
                .iter()
                .chain([&workload])
                .any(|user| !users.contains_key(&(tenant, *user)))
            {
                return Err(DomainError::not_found(
                    "identity.user_not_found",
                    "the user does not exist",
                ));
            }
        }
        let mut rows = self.owner_rows();
        let before = rows.remove(&(tenant, workload)).unwrap_or_default();
        let after = owners
            .iter()
            .map(|owner| {
                before
                    .iter()
                    .find(|(_, kept)| kept == owner)
                    .copied()
                    .unwrap_or((now, *owner))
            })
            .collect();
        rows.insert((tenant, workload), after);
        Ok(())
    }

    async fn forget_owners(
        &self,
        uow: &mut dyn UnitOfWork,
        workload: UserId,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        self.owner_rows().remove(&(tenant, workload));
        Ok(())
    }
}

/// A [`crate::api::WorkloadAccess`] that remembers what it was asked to
/// end, and records nothing else.
#[derive(Debug, Clone, Default)]
pub struct RecordingWorkloadAccess {
    calls: Arc<Mutex<Vec<AccessCall>>>,
}

impl RecordingWorkloadAccess {
    /// What it was asked to end: the tenant, the workload and the reason,
    /// in order.
    ///
    /// # Panics
    ///
    /// Never in practice: the lock is only poisoned by a panic elsewhere.
    #[must_use]
    pub fn calls(&self) -> Vec<AccessCall> {
        self.calls.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

#[async_trait::async_trait]
impl crate::api::WorkloadAccess for RecordingWorkloadAccess {
    async fn revoke_access(
        &self,
        uow: &mut dyn UnitOfWork,
        workload: UserId,
        reason: &'static str,
        _caller: hodor_kernel::Caller,
    ) -> Result<(), DomainError> {
        self.calls.lock().unwrap_or_else(|e| e.into_inner()).push((
            uow.tenant().tenant_id(),
            workload,
            reason,
        ));
        Ok(())
    }

    /// Recorded with the reason `credentials`.
    async fn revoke_credentials(
        &self,
        uow: &mut dyn UnitOfWork,
        workload: UserId,
        _caller: hodor_kernel::Caller,
    ) -> Result<(), DomainError> {
        self.calls.lock().unwrap_or_else(|e| e.into_inner()).push((
            uow.tenant().tenant_id(),
            workload,
            "credentials",
        ));
        Ok(())
    }
}

/// The ports the contract of workloads runs against.
#[derive(Clone)]
pub struct WorkloadPorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// Where the workloads and their owners are stored as users.
    pub users: &'a dyn UserRepository,
    /// The repository under test.
    pub workloads: &'a dyn crate::api::WorkloadRepository,
}

impl std::fmt::Debug for WorkloadPorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkloadPorts").finish_non_exhaustive()
    }
}

fn a_workload(kind: UserKind, name: &str) -> User {
    User::create(
        kind,
        vec![],
        crate::api::workload_profile(name).expect("a name"),
        true,
        MOMENT,
    )
    .expect("a workload")
    .0
}

/// Runs the contract of workloads. Each case uses tenants of its own.
///
/// # Panics
///
/// Panics when the implementation breaks the contract.
pub async fn run_workload_contract(ports: WorkloadPorts<'_>) {
    let ports = &ports;
    macro_rules! within {
        ($tenant:expr, |$uow:ident| $body:expr) => {{
            let mut $uow = ports.units_of_work.begin($tenant).await.expect("begin");
            let value = $body;
            $uow.commit().await.expect("commit");
            value
        }};
    }
    let later = MOMENT + time::Duration::seconds(1);
    let (home, elsewhere) = (tenant(), tenant());
    let ana = person(vec![email("ana@example.com")]);
    let bob = person(vec![email("bob@example.com")]);
    let carla = person(vec![email("carla@example.com")]);
    let export = a_workload(UserKind::ServiceAccount, "Nightly export");
    let helper = a_workload(UserKind::Agent, "Support helper");
    let sync = a_workload(UserKind::ServiceAccount, "Directory sync");
    let mut gone = a_workload(UserKind::ServiceAccount, "Gone");
    for user in [&ana, &bob, &carla, &export, &helper, &sync, &gone] {
        within!(&home, |uow| ports
            .users
            .insert(uow.as_mut(), user)
            .await
            .expect("insert"));
    }
    gone.deactivate(MOMENT).expect("deactivate");
    within!(&home, |uow| ports
        .users
        .update(uow.as_mut(), &gone)
        .await
        .expect("update"));
    let mut gone = within!(&home, |uow| ports
        .users
        .get(uow.as_mut(), gone.id())
        .await
        .expect("get"))
    .expect("stored");
    gone.mark_deleted(MOMENT).expect("delete");
    within!(&home, |uow| ports
        .users
        .update(uow.as_mut(), &gone)
        .await
        .expect("update"));
    let other = a_workload(UserKind::ServiceAccount, "Another tenant's");
    within!(&elsewhere, |uow| ports
        .users
        .insert(uow.as_mut(), &other)
        .await
        .expect("insert"));

    // Workloads are listed by kind, in the order they were created, not
    // deleted, in their tenant only, a page at a time.
    let ids = |users: Vec<User>| users.iter().map(User::id).collect::<Vec<_>>();
    let accounts = within!(&home, |uow| ports
        .workloads
        .list(uow.as_mut(), UserKind::ServiceAccount, None, 10)
        .await
        .expect("list"));
    assert_eq!(ids(accounts), vec![export.id(), sync.id()]);
    let agents = within!(&home, |uow| ports
        .workloads
        .list(uow.as_mut(), UserKind::Agent, None, 10)
        .await
        .expect("list"));
    assert_eq!(ids(agents), vec![helper.id()]);
    let first = within!(&home, |uow| ports
        .workloads
        .list(uow.as_mut(), UserKind::ServiceAccount, None, 1)
        .await
        .expect("list"));
    assert_eq!(ids(first), vec![export.id()]);
    let next = within!(&home, |uow| ports
        .workloads
        .list(
            uow.as_mut(),
            UserKind::ServiceAccount,
            Some(export.id()),
            10
        )
        .await
        .expect("list"));
    assert_eq!(ids(next), vec![sync.id()]);
    let people = within!(&home, |uow| ports
        .workloads
        .list(uow.as_mut(), UserKind::Human, None, 10)
        .await
        .expect("list"));
    assert_eq!(people.len(), 3, "a kind lists its own users");
    let theirs = within!(&elsewhere, |uow| ports
        .workloads
        .list(uow.as_mut(), UserKind::ServiceAccount, None, 10)
        .await
        .expect("list"));
    assert_eq!(ids(theirs), vec![other.id()]);

    // Owners are kept in the order they became owners; replacing keeps
    // when the ones that stay became owners.
    within!(&home, |uow| ports
        .workloads
        .replace_owners(uow.as_mut(), export.id(), &[bob.id()], MOMENT)
        .await
        .expect("replace"));
    within!(&home, |uow| ports
        .workloads
        .replace_owners(uow.as_mut(), export.id(), &[ana.id(), bob.id()], later)
        .await
        .expect("replace"));
    let owners = within!(&home, |uow| ports
        .workloads
        .owners(uow.as_mut(), export.id())
        .await
        .expect("owners"));
    assert_eq!(owners, vec![bob.id(), ana.id()]);
    within!(&home, |uow| ports
        .workloads
        .replace_owners(uow.as_mut(), export.id(), &[carla.id(), ana.id()], later)
        .await
        .expect("replace"));
    let owners = within!(&home, |uow| ports
        .workloads
        .owners(uow.as_mut(), export.id())
        .await
        .expect("owners"));
    let mut expected = vec![ana.id(), carla.id()];
    expected.sort();
    assert_eq!(owners, expected, "at the same moment, by identifier");

    // Owners of one tenant's workload are seen from no other, and a user of
    // another tenant cannot be made an owner.
    let hidden = within!(&elsewhere, |uow| ports
        .workloads
        .owners(uow.as_mut(), export.id())
        .await
        .expect("owners"));
    assert!(hidden.is_empty());
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    let refused = ports
        .workloads
        .replace_owners(uow.as_mut(), other.id(), &[ana.id()], MOMENT)
        .await;
    assert!(refused.is_err(), "an owner of another tenant is refused");
    drop(uow);

    // Forgetting the owners leaves none, and touches no other workload.
    within!(&home, |uow| ports
        .workloads
        .replace_owners(uow.as_mut(), sync.id(), &[ana.id()], MOMENT)
        .await
        .expect("replace"));
    within!(&home, |uow| ports
        .workloads
        .forget_owners(uow.as_mut(), export.id())
        .await
        .expect("forget"));
    let none = within!(&home, |uow| ports
        .workloads
        .owners(uow.as_mut(), export.id())
        .await
        .expect("owners"));
    assert!(none.is_empty());
    let kept = within!(&home, |uow| ports
        .workloads
        .owners(uow.as_mut(), sync.id())
        .await
        .expect("owners"));
    assert_eq!(kept, vec![ana.id()]);
}
