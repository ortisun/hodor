//! The use cases of service accounts and agents, run against the
//! in-memory ports.

use hodor_identity::api::{
    ChangeWorkload, CreateUser, CreateWorkload, GroupMember, GroupService, IdentifierKind,
    IdentityService, Profile, UserKind, UserStatus, WORKLOAD_DELETED, WORKLOAD_DISABLED,
    WorkloadService, WorkloadStatus,
};
use hodor_identity::testing::{
    FixedGroupPolicy, InMemoryGroups, InMemoryUsers, InMemoryWorkloads, RecordingWorkloadAccess,
    WorkloadPorts, run_workload_contract,
};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, PageRequest, TenantContext, TenantId, Timestamp, UserId};
use std::sync::Arc;

struct World {
    workloads: WorkloadService,
    identity: IdentityService,
    groups: GroupService,
    access: RecordingWorkloadAccess,
    units_of_work: InMemoryUnitOfWorkFactory,
    tenant: TenantContext,
}

fn world() -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let users = InMemoryUsers::default();
    let groups = Arc::new(InMemoryGroups::default());
    let clock = Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH));
    let identity = IdentityService::new(
        Arc::new(units_of_work.clone()),
        Arc::new(users.clone()),
        clock.clone(),
    )
    .with_groups(groups.clone());
    let access = RecordingWorkloadAccess::default();
    World {
        workloads: WorkloadService::new(
            Arc::new(units_of_work.clone()),
            identity.clone(),
            Arc::new(InMemoryWorkloads::over(users.clone())),
            Arc::new(access.clone()),
            clock.clone(),
        ),
        groups: GroupService::new(
            Arc::new(units_of_work.clone()),
            groups,
            Arc::new(users),
            Arc::new(FixedGroupPolicy(5)),
            clock,
        ),
        identity,
        access,
        units_of_work,
        tenant: TenantContext::assume(TenantId::generate()),
    }
}

impl World {
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

    async fn create(
        &self,
        kind: UserKind,
        name: &str,
        owners: &[UserId],
    ) -> Result<hodor_identity::api::Workload, hodor_kernel::DomainError> {
        self.workloads
            .create(
                &self.tenant,
                CreateWorkload {
                    kind,
                    name: name.to_owned(),
                    owners: owners.to_vec(),
                },
                Caller::system(),
            )
            .await
    }
}

#[tokio::test]
async fn the_in_memory_store_passes_the_contract() {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let users = InMemoryUsers::default();
    run_workload_contract(WorkloadPorts {
        units_of_work: &units_of_work,
        users: &users,
        workloads: &InMemoryWorkloads::over(users.clone()),
    })
    .await;
}

#[tokio::test]
async fn a_workload_is_created_active_with_its_owners_and_no_identifier() {
    let world = world();
    let ana = world.person("ana@example.com").await;
    let bob = world.person("bob@example.com").await;
    let created = world
        .create(
            UserKind::ServiceAccount,
            "  Nightly export ",
            &[ana, bob, ana],
        )
        .await
        .expect("created");
    assert_eq!(created.kind(), UserKind::ServiceAccount);
    assert_eq!(created.name(), "Nightly export");
    assert_eq!(created.status(), WorkloadStatus::Active);
    assert_eq!(created.owners(), [ana, bob]);
    assert!(created.user().identifiers().is_empty());
    assert!(!created.user().may_sign_in(), "a workload never signs in");
    assert_eq!(
        world.units_of_work.committed_event_types()[4..],
        [
            "identity.user_created",
            "identity.workload_owner_added",
            "identity.workload_owner_added"
        ]
    );
    let read = world
        .workloads
        .get(&world.tenant, UserKind::ServiceAccount, created.id())
        .await
        .expect("read");
    assert_eq!(read, created);
}

#[tokio::test]
async fn an_owner_is_a_person_of_the_tenant_who_is_not_deleted() {
    let world = world();
    let ana = world.person("ana@example.com").await;
    let robot = world
        .create(UserKind::ServiceAccount, "Robot", &[ana])
        .await
        .expect("created");
    let cases = [
        (vec![], "identity.workload_owner_required"),
        (
            (0..11).map(|_| UserId::generate()).collect(),
            "identity.too_many_workload_owners",
        ),
        (vec![UserId::generate()], "identity.user_not_found"),
        (vec![robot.id()], "identity.workload_owner_invalid"),
    ];
    for (owners, code) in cases {
        let refused = world
            .create(UserKind::Agent, "Helper", &owners)
            .await
            .expect_err("refused");
        assert_eq!(refused.code(), code);
    }
    let gone = world.person("gone@example.com").await;
    world
        .identity
        .deactivate(&world.tenant, gone, Caller::system())
        .await
        .expect("deactivate");
    world
        .identity
        .mark_deleted(&world.tenant, gone, Caller::system())
        .await
        .expect("delete");
    let refused = world
        .create(UserKind::Agent, "Helper", &[gone])
        .await
        .expect_err("refused");
    assert_eq!(refused.code(), "identity.user_not_found");
    let elsewhere = World {
        tenant: TenantContext::assume(TenantId::generate()),
        ..world
    };
    let refused = elsewhere
        .create(UserKind::Agent, "Helper", &[ana])
        .await
        .expect_err("refused");
    assert_eq!(
        refused.code(),
        "identity.user_not_found",
        "a person of another tenant"
    );
    let refused = elsewhere
        .create(UserKind::Human, "Not a workload", &[ana])
        .await
        .expect_err("refused");
    assert_eq!(refused.code(), "identity.workload_kind_invalid");
}

#[tokio::test]
async fn a_workload_is_read_and_listed_under_its_own_kind_only() {
    let world = world();
    let ana = world.person("ana@example.com").await;
    let export = world
        .create(UserKind::ServiceAccount, "Export", &[ana])
        .await
        .expect("created");
    let helper = world
        .create(UserKind::Agent, "Helper", &[ana])
        .await
        .expect("created");
    let sync = world
        .create(UserKind::ServiceAccount, "Sync", &[ana])
        .await
        .expect("created");
    for (kind, id) in [
        (UserKind::Agent, export.id()),
        (UserKind::ServiceAccount, helper.id()),
        (UserKind::ServiceAccount, ana),
        (UserKind::ServiceAccount, UserId::generate()),
    ] {
        let missing = world
            .workloads
            .get(&world.tenant, kind, id)
            .await
            .expect_err("not found");
        assert_eq!(missing.code(), "identity.workload_not_found");
    }
    let first = world
        .workloads
        .list(
            &world.tenant,
            UserKind::ServiceAccount,
            &PageRequest::new(Some(1), None),
        )
        .await
        .expect("list");
    assert_eq!(
        first.items.iter().map(|w| w.id()).collect::<Vec<_>>(),
        [export.id()]
    );
    let next = world
        .workloads
        .list(
            &world.tenant,
            UserKind::ServiceAccount,
            &PageRequest::new(Some(1), first.next_cursor),
        )
        .await
        .expect("list");
    assert_eq!(
        next.items.iter().map(|w| w.id()).collect::<Vec<_>>(),
        [sync.id()]
    );
    assert_eq!(next.next_cursor, None);
    let agents = world
        .workloads
        .list(&world.tenant, UserKind::Agent, &PageRequest::default())
        .await
        .expect("list");
    assert_eq!(agents.items, [helper]);
}

#[tokio::test]
async fn a_change_renames_and_replaces_the_owners_at_once() {
    let world = world();
    let ana = world.person("ana@example.com").await;
    let bob = world.person("bob@example.com").await;
    let export = world
        .create(UserKind::ServiceAccount, "Export", &[ana])
        .await
        .expect("created");
    let before = world.units_of_work.committed_event_types().len();
    let changed = world
        .workloads
        .change(
            &world.tenant,
            UserKind::ServiceAccount,
            export.id(),
            ChangeWorkload {
                name: Some("Nightly export".to_owned()),
                owners: Some(vec![bob]),
            },
            Caller::system(),
        )
        .await
        .expect("changed");
    assert_eq!(changed.name(), "Nightly export");
    assert_eq!(changed.owners(), [bob]);
    assert_eq!(
        world.units_of_work.committed_event_types()[before..],
        [
            "identity.profile_changed",
            "identity.workload_owner_added",
            "identity.workload_owner_removed"
        ]
    );
    let unchanged = world
        .workloads
        .change(
            &world.tenant,
            UserKind::ServiceAccount,
            export.id(),
            ChangeWorkload {
                name: Some("Nightly export".to_owned()),
                owners: Some(vec![bob]),
            },
            Caller::system(),
        )
        .await
        .expect("nothing changed");
    assert_eq!(unchanged, changed);
    assert_eq!(
        world.units_of_work.committed_event_types().len(),
        before + 3
    );
    for (change, code) in [
        (
            ChangeWorkload {
                name: None,
                owners: Some(vec![]),
            },
            "identity.workload_owner_required",
        ),
        (
            ChangeWorkload {
                name: Some(" ".to_owned()),
                owners: None,
            },
            "identity.display_name_invalid",
        ),
    ] {
        let refused = world
            .workloads
            .change(
                &world.tenant,
                UserKind::ServiceAccount,
                export.id(),
                change,
                Caller::system(),
            )
            .await
            .expect_err("refused");
        assert_eq!(refused.code(), code);
    }
}

#[tokio::test]
async fn disabling_revokes_its_access_and_enabling_brings_it_back() {
    let world = world();
    let ana = world.person("ana@example.com").await;
    let export = world
        .create(UserKind::ServiceAccount, "Export", &[ana])
        .await
        .expect("created");
    let disabled = world
        .workloads
        .disable(
            &world.tenant,
            UserKind::ServiceAccount,
            export.id(),
            Caller::system(),
        )
        .await
        .expect("disabled");
    assert_eq!(disabled.status(), WorkloadStatus::Disabled);
    assert_eq!(disabled.user().status(), UserStatus::Deactivated);
    assert_eq!(
        world.access.calls(),
        [(world.tenant.tenant_id(), export.id(), WORKLOAD_DISABLED)]
    );
    assert_eq!(
        world
            .units_of_work
            .committed_event_types()
            .last()
            .map(String::as_str),
        Some("identity.user_deactivated")
    );

    // Disabling again changes nothing and ends nothing more.
    let before = world.units_of_work.committed_event_types().len();
    world
        .workloads
        .disable(
            &world.tenant,
            UserKind::ServiceAccount,
            export.id(),
            Caller::system(),
        )
        .await
        .expect("disabled");
    assert_eq!(world.access.calls().len(), 1);
    assert_eq!(world.units_of_work.committed_event_types().len(), before);

    let enabled = world
        .workloads
        .enable(
            &world.tenant,
            UserKind::ServiceAccount,
            export.id(),
            Caller::system(),
        )
        .await
        .expect("enabled");
    assert_eq!(enabled.status(), WorkloadStatus::Active);
    assert_eq!(
        world
            .units_of_work
            .committed_event_types()
            .last()
            .map(String::as_str),
        Some("identity.user_restored")
    );
    assert_eq!(world.access.calls().len(), 1, "enabling revokes nothing");
}

#[tokio::test]
async fn a_workload_suspended_as_a_user_is_disabled_and_enabled_like_any_other() {
    let world = world();
    let ana = world.person("ana@example.com").await;
    let export = world
        .create(UserKind::ServiceAccount, "Export", &[ana])
        .await
        .expect("created");
    world
        .identity
        .suspend(&world.tenant, export.id(), "review", Caller::system())
        .await
        .expect("suspended");
    let read = world
        .workloads
        .get(&world.tenant, UserKind::ServiceAccount, export.id())
        .await
        .expect("read");
    assert_eq!(read.status(), WorkloadStatus::Disabled);
    // Enabling it revokes what it was issued before it was suspended.
    let enabled = world
        .workloads
        .enable(
            &world.tenant,
            UserKind::ServiceAccount,
            export.id(),
            Caller::system(),
        )
        .await
        .expect("enabled");
    assert_eq!(enabled.user().status(), UserStatus::Active);
    assert_eq!(
        world.access.calls(),
        [(world.tenant.tenant_id(), export.id(), WORKLOAD_DISABLED)]
    );
    world
        .identity
        .suspend(&world.tenant, export.id(), "review", Caller::system())
        .await
        .expect("suspended");
    let disabled = world
        .workloads
        .disable(
            &world.tenant,
            UserKind::ServiceAccount,
            export.id(),
            Caller::system(),
        )
        .await
        .expect("disabled");
    assert_eq!(disabled.user().status(), UserStatus::Deactivated);
    assert_eq!(world.access.calls().len(), 2);
}

#[tokio::test]
async fn deleting_erases_it_takes_it_out_of_its_groups_and_revokes_its_access() {
    let world = world();
    let ana = world.person("ana@example.com").await;
    let helper = world
        .create(UserKind::Agent, "Helper", &[ana])
        .await
        .expect("created");
    let group = world
        .groups
        .create(&world.tenant, "bots", None, Caller::system())
        .await
        .expect("a group")
        .id();
    world
        .groups
        .add_member(
            &world.tenant,
            group,
            GroupMember::User(helper.id()),
            Caller::system(),
        )
        .await
        .expect("a member");
    world
        .workloads
        .delete(
            &world.tenant,
            UserKind::Agent,
            helper.id(),
            Caller::system(),
        )
        .await
        .expect("deleted");
    assert_eq!(
        world.access.calls(),
        [
            (world.tenant.tenant_id(), helper.id(), WORKLOAD_DELETED),
            (world.tenant.tenant_id(), helper.id(), "credentials")
        ]
    );
    let missing = world
        .workloads
        .get(&world.tenant, UserKind::Agent, helper.id())
        .await
        .expect_err("gone");
    assert_eq!(missing.code(), "identity.workload_not_found");
    let user = world
        .identity
        .get(&world.tenant, helper.id())
        .await
        .expect("the identifier remains");
    assert_eq!(user.status(), UserStatus::Deleted);
    assert_eq!(user.snapshot().profile.display_name, None);
    let groups = world
        .groups
        .effective_groups(&world.tenant, helper.id())
        .await
        .expect("groups");
    assert!(groups.is_empty(), "{groups:?}");
    let types = world.units_of_work.committed_event_types();
    let tail = &types[types.len() - 3..];
    assert_eq!(
        tail,
        [
            "identity.user_deactivated",
            "identity.user_deleted",
            "identity.group_member_removed"
        ]
    );
    let again = world
        .workloads
        .delete(
            &world.tenant,
            UserKind::Agent,
            helper.id(),
            Caller::system(),
        )
        .await
        .expect_err("gone");
    assert_eq!(again.code(), "identity.workload_not_found");
}
