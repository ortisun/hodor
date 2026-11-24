//! The use cases of groups, run against the in-memory ports.

use hodor_identity::api::{
    CreateUser, GroupMember, GroupService, IdentifierKind, IdentityService, Profile, UserKind,
};
use hodor_identity::testing::{
    FixedGroupPolicy, GroupPorts, InMemoryGroups, InMemoryUsers, run_group_contract,
};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, GroupId, PageRequest, TenantContext, TenantId, Timestamp, UserId};
use std::collections::BTreeSet;
use std::sync::Arc;

struct World {
    groups: GroupService,
    identity: IdentityService,
    units_of_work: InMemoryUnitOfWorkFactory,
    tenant: TenantContext,
}

fn world_with_depth(depth: u8) -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let users = Arc::new(InMemoryUsers::default());
    let store = Arc::new(InMemoryGroups::default());
    let clock = Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH));
    World {
        groups: GroupService::new(
            Arc::new(units_of_work.clone()),
            store.clone(),
            users.clone(),
            Arc::new(FixedGroupPolicy(depth)),
            clock.clone(),
        ),
        identity: IdentityService::new(Arc::new(units_of_work.clone()), users, clock)
            .with_groups(store),
        units_of_work,
        tenant: TenantContext::assume(TenantId::generate()),
    }
}

fn world() -> World {
    world_with_depth(5)
}

impl World {
    async fn group(&self, name: &str) -> GroupId {
        self.groups
            .create(&self.tenant, name, None, Caller::system())
            .await
            .expect("a group")
            .id()
    }

    async fn person(&self, email: &str) -> UserId {
        self.identity
            .create(
                &self.tenant,
                CreateUser {
                    kind: UserKind::Human,
                    identifiers: vec![(IdentifierKind::Email, email.to_owned())],
                    profile: Profile::default(),
                    confirmed: true,
                },
                Caller::system(),
            )
            .await
            .expect("a person")
            .id()
    }

    async fn put(
        &self,
        container: GroupId,
        member: GroupMember,
    ) -> Result<(), hodor_kernel::DomainError> {
        self.groups
            .add_member(&self.tenant, container, member, Caller::system())
            .await
    }

    fn event_types(&self) -> Vec<String> {
        self.units_of_work
            .committed_events()
            .into_iter()
            .map(|event| event.event_type)
            .collect()
    }
}

#[tokio::test]
async fn the_in_memory_ports_pass_the_contract() {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    run_group_contract(GroupPorts {
        units_of_work: &units_of_work,
        users: &InMemoryUsers::default(),
        groups: &InMemoryGroups::default(),
    })
    .await;
}

#[tokio::test]
async fn members_of_groups_inside_a_group_are_in_it_too() {
    let world = world();
    let (finance, payables, receivables) = (
        world.group("finance").await,
        world.group("payables").await,
        world.group("receivables").await,
    );
    let (ana, bruno, carla) = (
        world.person("ana@example.com").await,
        world.person("bruno@example.com").await,
        world.person("carla@example.com").await,
    );
    world
        .put(finance, GroupMember::Group(payables))
        .await
        .expect("nest");
    world
        .put(finance, GroupMember::Group(receivables))
        .await
        .expect("nest");
    world
        .put(payables, GroupMember::User(ana))
        .await
        .expect("add");
    world
        .put(receivables, GroupMember::User(bruno))
        .await
        .expect("add");
    world
        .put(finance, GroupMember::User(carla))
        .await
        .expect("add");

    let of = |user| world.groups.effective_groups(&world.tenant, user);
    assert_eq!(
        of(ana).await.expect("groups"),
        BTreeSet::from([payables, finance])
    );
    assert_eq!(
        of(bruno).await.expect("groups"),
        BTreeSet::from([receivables, finance])
    );
    assert_eq!(of(carla).await.expect("groups"), BTreeSet::from([finance]));

    // Taking payables out of finance takes Ana out of finance at once.
    world
        .groups
        .remove_member(
            &world.tenant,
            finance,
            GroupMember::Group(payables),
            Caller::system(),
        )
        .await
        .expect("remove");
    assert_eq!(of(ana).await.expect("groups"), BTreeSet::from([payables]));
}

#[tokio::test]
async fn a_cycle_is_refused_however_it_is_made() {
    let world = world();
    let (a, b, c) = (
        world.group("a").await,
        world.group("b").await,
        world.group("c").await,
    );
    world.put(a, GroupMember::Group(b)).await.expect("nest");
    world.put(b, GroupMember::Group(c)).await.expect("nest");
    for (container, member) in [(c, a), (b, a), (a, a)] {
        let refused = world
            .put(container, GroupMember::Group(member))
            .await
            .expect_err("a cycle");
        assert_eq!(refused.code(), "identity.group_cycle");
    }
}

#[tokio::test]
async fn nesting_past_the_tenants_bound_is_refused() {
    let world = world_with_depth(2);
    let (a, b, c) = (
        world.group("a").await,
        world.group("b").await,
        world.group("c").await,
    );
    world.put(a, GroupMember::Group(b)).await.expect("depth 2");
    let refused = world
        .put(b, GroupMember::Group(c))
        .await
        .expect_err("depth 3");
    assert_eq!(refused.code(), "identity.group_nesting_too_deep");
    let refused = world
        .put(c, GroupMember::Group(a))
        .await
        .expect_err("depth 3");
    assert_eq!(refused.code(), "identity.group_nesting_too_deep");
}

#[tokio::test]
async fn only_users_and_groups_of_the_tenant_can_be_members() {
    let world = world();
    let finance = world.group("finance").await;
    let elsewhere = world_with_depth(5);
    let stranger = elsewhere.person("ana@example.com").await;
    let foreign_group = elsewhere.group("foreign").await;

    let refused = world
        .put(finance, GroupMember::User(stranger))
        .await
        .expect_err("not here");
    assert_eq!(refused.code(), "identity.user_not_found");
    let refused = world
        .put(finance, GroupMember::Group(foreign_group))
        .await
        .expect_err("not here");
    assert_eq!(refused.code(), "identity.group_not_found");
    let refused = world
        .put(GroupId::generate(), GroupMember::User(stranger))
        .await
        .expect_err("no such group");
    assert_eq!(refused.code(), "identity.group_not_found");
}

#[tokio::test]
async fn a_user_marked_deleted_leaves_every_group_and_cannot_join_one() {
    let world = world();
    let (finance, payables) = (world.group("finance").await, world.group("payables").await);
    let ana = world.person("ana@example.com").await;
    world
        .put(finance, GroupMember::User(ana))
        .await
        .expect("add");
    world
        .put(payables, GroupMember::User(ana))
        .await
        .expect("add");

    world
        .identity
        .deactivate(&world.tenant, ana, Caller::system())
        .await
        .expect("deactivate");
    assert_eq!(
        world
            .groups
            .effective_groups(&world.tenant, ana)
            .await
            .expect("groups")
            .len(),
        2,
        "a deactivated user is still in their groups"
    );
    world
        .identity
        .mark_deleted(&world.tenant, ana, Caller::system())
        .await
        .expect("delete");
    assert!(
        world
            .groups
            .effective_groups(&world.tenant, ana)
            .await
            .expect("groups")
            .is_empty()
    );
    let removed = world
        .event_types()
        .into_iter()
        .filter(|event| event == "identity.group_member_removed")
        .count();
    assert_eq!(removed, 2, "one event per group left");

    let refused = world
        .put(finance, GroupMember::User(ana))
        .await
        .expect_err("deleted");
    assert_eq!(refused.code(), "identity.user_not_found");
}

#[tokio::test]
async fn each_change_records_one_event_and_a_repeat_records_none() {
    let world = world();
    let finance = world.group("finance").await;
    let ana = world.person("ana@example.com").await;
    world
        .put(finance, GroupMember::User(ana))
        .await
        .expect("add");
    world
        .put(finance, GroupMember::User(ana))
        .await
        .expect("add again");
    world
        .groups
        .change(&world.tenant, finance, "finance", None, Caller::system())
        .await
        .expect("the same");
    world
        .groups
        .change(
            &world.tenant,
            finance,
            "Finance",
            Some("Bills".to_owned()),
            Caller::system(),
        )
        .await
        .expect("a change");
    world
        .groups
        .delete(&world.tenant, finance, Caller::system())
        .await
        .expect("delete");

    let groups: Vec<String> = world
        .event_types()
        .into_iter()
        .filter(|event| event.starts_with("identity.group"))
        .collect();
    assert_eq!(
        groups,
        [
            "identity.group_created",
            "identity.group_member_added",
            "identity.group_changed",
            "identity.group_deleted",
        ]
    );
    let deleted = world
        .units_of_work
        .committed_events()
        .into_iter()
        .find(|event| event.event_type == "identity.group_deleted")
        .expect("deleted");
    assert_eq!(deleted.payload["members"], 1);
    let published = format!("{:?}", world.units_of_work.committed_events());
    assert!(
        !published.contains("Bills") && !published.contains("Finance"),
        "names and descriptions stay out of events: {published}"
    );
}

#[tokio::test]
async fn members_and_groups_are_listed_a_page_at_a_time() {
    let world = world();
    let finance = world.group("finance").await;
    let payables = world.group("payables").await;
    let mut people = Vec::new();
    for index in 0..3 {
        let user = world.person(&format!("person{index}@example.com")).await;
        world
            .put(finance, GroupMember::User(user))
            .await
            .expect("add");
        people.push(user);
    }
    world
        .put(finance, GroupMember::Group(payables))
        .await
        .expect("nest");
    people.sort();

    let first = world
        .groups
        .members(&world.tenant, finance, &PageRequest::new(Some(2), None))
        .await
        .expect("members");
    assert_eq!(
        first.items,
        [GroupMember::User(people[0]), GroupMember::User(people[1])]
    );
    let second = world
        .groups
        .members(
            &world.tenant,
            finance,
            &PageRequest::new(Some(2), first.next_cursor),
        )
        .await
        .expect("members");
    assert_eq!(
        second.items,
        [GroupMember::User(people[2]), GroupMember::Group(payables)]
    );
    assert!(second.next_cursor.is_none());

    let listed = world
        .groups
        .list(&world.tenant, &PageRequest::new(Some(1), None))
        .await
        .expect("groups");
    assert_eq!(listed.items.len(), 1);
    assert!(listed.next_cursor.is_some());
    let bad = world
        .groups
        .members(
            &world.tenant,
            finance,
            &PageRequest::new(None, Some(hodor_kernel::Cursor::new("nonsense".to_owned()))),
        )
        .await
        .expect_err("a cursor of nobody's");
    assert_eq!(bad.code(), "request.cursor_invalid");
}
