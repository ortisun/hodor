//! In-memory port and the contract every implementation of it passes.
//!
//! The in-memory fake and the PostgreSQL adapter both run the contract,
//! which is what makes the fake a faithful stand-in in use case tests.

use crate::api::{IdentifierKind, NormalizedIdentifier, Profile, User, UserKind, UserRepository};
use hodor_kernel::{
    DomainError, TenantContext, TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory, UserId,
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
