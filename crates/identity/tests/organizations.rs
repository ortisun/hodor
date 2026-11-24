//! The use cases of organizations, run against the in-memory ports.

use hodor_identity::api::{
    CreateUser, IdentifierKind, IdentityService, OrganizationService, Profile, UnitChange, UnitId,
    UnitKind, UserKind,
};
use hodor_identity::testing::{
    InMemoryOrganizations, InMemoryUsers, OrganizationPorts, run_organization_contract,
};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, OrganizationId, PageRequest, TenantContext, TenantId, Timestamp, UserId,
};
use std::collections::BTreeSet;
use std::sync::Arc;

struct World {
    organizations: OrganizationService,
    identity: IdentityService,
    units_of_work: InMemoryUnitOfWorkFactory,
    tenant: TenantContext,
}

fn world() -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let users = Arc::new(InMemoryUsers::default());
    let store = Arc::new(InMemoryOrganizations::default());
    let clock = Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH));
    World {
        organizations: OrganizationService::new(
            Arc::new(units_of_work.clone()),
            store.clone(),
            users.clone(),
            clock.clone(),
        ),
        identity: IdentityService::new(Arc::new(units_of_work.clone()), users, clock)
            .with_organizations(store),
        units_of_work,
        tenant: TenantContext::assume(TenantId::generate()),
    }
}

impl World {
    async fn organization(&self, name: &str) -> OrganizationId {
        self.organizations
            .create(&self.tenant, name, None, Caller::system())
            .await
            .expect("an organization")
            .id()
    }

    async fn unit(
        &self,
        organization: OrganizationId,
        parent: Option<UnitId>,
        name: &str,
    ) -> UnitId {
        self.organizations
            .create_unit(
                &self.tenant,
                organization,
                parent,
                name,
                UnitKind::Department,
                Caller::system(),
            )
            .await
            .expect("a unit")
            .id
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

    async fn move_unit(
        &self,
        organization: OrganizationId,
        unit: UnitId,
        parent: Option<UnitId>,
        name: &str,
    ) -> Result<(), hodor_kernel::DomainError> {
        self.organizations
            .change_unit(
                &self.tenant,
                organization,
                unit,
                UnitChange {
                    parent,
                    name: name.to_owned(),
                    kind: UnitKind::Unit,
                },
                Caller::system(),
            )
            .await
            .map(|_| ())
    }
}

#[tokio::test]
async fn the_in_memory_ports_pass_the_contract() {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    run_organization_contract(OrganizationPorts {
        units_of_work: &units_of_work,
        users: &InMemoryUsers::default(),
        organizations: &InMemoryOrganizations::default(),
    })
    .await;
}

#[tokio::test]
async fn the_tree_of_units_keeps_its_rules() {
    let world = world();
    let acme = world.organization("Acme").await;
    let engineering = world.unit(acme, None, "Engineering").await;
    let platform = world.unit(acme, Some(engineering), "Platform").await;

    let refused = world
        .move_unit(acme, engineering, Some(platform), "Engineering")
        .await
        .expect_err("a cycle");
    assert_eq!(refused.code(), "identity.unit_cycle");
    world
        .move_unit(acme, platform, None, "Platform")
        .await
        .expect("to the top");

    // Ten levels, and not an eleventh.
    let mut parent = None;
    for level in 1..=10 {
        parent = Some(world.unit(acme, parent, &format!("level {level}")).await);
    }
    let refused = world
        .organizations
        .create_unit(
            &world.tenant,
            acme,
            parent,
            "too deep",
            UnitKind::Unit,
            Caller::system(),
        )
        .await
        .expect_err("an eleventh level");
    assert_eq!(refused.code(), "identity.unit_tree_too_deep");

    // A parent of another organization is not found here.
    let globex = world.organization("Globex").await;
    let refused = world
        .organizations
        .create_unit(
            &world.tenant,
            globex,
            Some(engineering),
            "Lost",
            UnitKind::Unit,
            Caller::system(),
        )
        .await
        .expect_err("another organization's unit");
    assert_eq!(refused.code(), "identity.unit_not_found");

    // A unit with units below it is not deleted.
    let sales = world.unit(acme, None, "Sales").await;
    world.unit(acme, Some(sales), "Inside sales").await;
    let refused = world
        .organizations
        .delete_unit(&world.tenant, acme, sales, Caller::system())
        .await
        .expect_err("not empty");
    assert_eq!(refused.code(), "identity.unit_not_empty");
}

#[tokio::test]
async fn members_join_with_units_of_their_organization_only() {
    let world = world();
    let acme = world.organization("Acme").await;
    let globex = world.organization("Globex").await;
    let engineering = world.unit(acme, None, "Engineering").await;
    let sales = world.unit(globex, None, "Sales").await;
    let ana = world.person("ana@example.com").await;

    let refused = world
        .organizations
        .add_member(
            &world.tenant,
            acme,
            ana,
            BTreeSet::from([sales]),
            Caller::system(),
        )
        .await
        .expect_err("a unit of another organization");
    assert_eq!(refused.code(), "identity.unit_not_found");

    let joined = world
        .organizations
        .add_member(
            &world.tenant,
            acme,
            ana,
            BTreeSet::from([engineering]),
            Caller::system(),
        )
        .await
        .expect("a member");
    assert_eq!(joined.units, BTreeSet::from([engineering]));
    let again = world
        .organizations
        .add_member(&world.tenant, acme, ana, BTreeSet::new(), Caller::system())
        .await
        .expect("already a member");
    assert_eq!(
        again.units,
        BTreeSet::from([engineering]),
        "adding again changes nothing"
    );

    world
        .organizations
        .add_member(
            &world.tenant,
            globex,
            ana,
            BTreeSet::new(),
            Caller::system(),
        )
        .await
        .expect("a second organization");
    let of = world
        .organizations
        .organizations_of(&world.tenant, ana)
        .await
        .expect("of");
    assert_eq!(of.len(), 2);

    // Deleting a unit takes her out of it, not out of the organization.
    world
        .organizations
        .delete_unit(&world.tenant, acme, engineering, Caller::system())
        .await
        .expect("delete");
    let members = world
        .organizations
        .members(&world.tenant, acme, &PageRequest::new(None, None))
        .await
        .expect("members");
    assert_eq!(members.items.len(), 1);
    assert!(members.items[0].units.is_empty());
}

#[tokio::test]
async fn a_user_marked_deleted_ends_every_membership() {
    let world = world();
    let (acme, globex) = (
        world.organization("Acme").await,
        world.organization("Globex").await,
    );
    let ana = world.person("ana@example.com").await;
    for organization in [acme, globex] {
        world
            .organizations
            .add_member(
                &world.tenant,
                organization,
                ana,
                BTreeSet::new(),
                Caller::system(),
            )
            .await
            .expect("a member");
    }
    world
        .identity
        .deactivate(&world.tenant, ana, Caller::system())
        .await
        .expect("deactivate");
    world
        .identity
        .mark_deleted(&world.tenant, ana, Caller::system())
        .await
        .expect("delete");
    assert!(
        world
            .organizations
            .organizations_of(&world.tenant, ana)
            .await
            .expect("of")
            .is_empty()
    );
    let refused = world
        .organizations
        .add_member(&world.tenant, acme, ana, BTreeSet::new(), Caller::system())
        .await
        .expect_err("deleted");
    assert_eq!(refused.code(), "identity.user_not_found");
}

#[tokio::test]
async fn changes_record_events_that_name_nothing_but_identifiers() {
    let world = world();
    let acme = world.organization("Acme").await;
    let engineering = world.unit(acme, None, "Engineering").await;
    let ana = world.person("ana@example.com").await;
    world
        .organizations
        .add_member(&world.tenant, acme, ana, BTreeSet::new(), Caller::system())
        .await
        .expect("a member");
    world
        .organizations
        .change_member_units(
            &world.tenant,
            acme,
            ana,
            BTreeSet::from([engineering]),
            Caller::system(),
        )
        .await
        .expect("units");
    world
        .organizations
        .remove_member(&world.tenant, acme, ana, Caller::system())
        .await
        .expect("leave");
    world
        .organizations
        .delete(&world.tenant, acme, Caller::system())
        .await
        .expect("delete");

    let types: Vec<String> = world
        .units_of_work
        .committed_events()
        .into_iter()
        .map(|event| event.event_type)
        .filter(|event| {
            event.starts_with("identity.organization") || event.starts_with("identity.unit")
        })
        .collect();
    assert_eq!(
        types,
        [
            "identity.organization_created",
            "identity.unit_created",
            "identity.organization_member_added",
            "identity.organization_member_changed",
            "identity.organization_member_removed",
            "identity.organization_deleted",
        ]
    );
    let published = format!("{:?}", world.units_of_work.committed_events());
    assert!(
        !published.contains("Acme") && !published.contains("Engineering"),
        "{published}"
    );
}
