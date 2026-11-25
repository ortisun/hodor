//! Groups on PostgreSQL.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgGroupPolicy, PgGroupRepository, PgTenantDirectory, PgTenantRepository, PgUserRepository,
};
use hodor_identity::api::{
    CreateUser, GroupMember, GroupService, IdentifierKind, IdentityService, Profile, UserKind,
};
use hodor_identity::testing::{GroupPorts, run_group_contract};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::{Caller, GroupId, TenantContext, Timestamp, UserId};
use hodor_tenant::api::{CreateTenant, TenantService};
use std::sync::Arc;

struct World {
    groups: GroupService,
    identity: IdentityService,
    tenants: TenantService,
    tenant: TenantContext,
}

async fn world(database: &TestDatabase, slug: &str) -> World {
    let units = || Arc::new(database.app().clone());
    let clock = Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH));
    let tenants = TenantService::new(
        units(),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.app().clone())),
        clock.clone(),
    );
    let tenant = tenants
        .create(
            CreateTenant {
                slug: slug.to_owned(),
                display_name: "Acme".to_owned(),
                open_registration: false,
                system: false,
            },
            Caller::system(),
        )
        .await
        .expect("a tenant");
    World {
        groups: GroupService::new(
            units(),
            Arc::new(PgGroupRepository),
            Arc::new(PgUserRepository),
            Arc::new(PgGroupPolicy),
            clock.clone(),
        ),
        identity: IdentityService::new(units(), Arc::new(PgUserRepository), clock)
            .with_groups(Arc::new(PgGroupRepository)),
        tenants,
        tenant: TenantContext::assume(tenant.id()),
    }
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
}

#[tokio::test]
async fn the_postgres_ports_pass_the_contract() {
    let database = TestDatabase::start().await;
    run_group_contract(GroupPorts {
        units_of_work: database.app(),
        users: &PgUserRepository,
        groups: &PgGroupRepository,
    })
    .await;
}

#[tokio::test]
async fn two_additions_that_would_make_a_cycle_together_cannot_both_succeed() {
    let database = TestDatabase::start().await;
    let world = world(&database, "acme").await;
    // Many rounds, so that the two requests really overlap in some.
    for round in 0..20 {
        let one = world.group(&format!("one-{round}")).await;
        let two = world.group(&format!("two-{round}")).await;
        let (first, second) = tokio::join!(
            world.groups.add_member(
                &world.tenant,
                one,
                GroupMember::Group(two),
                Caller::system()
            ),
            world.groups.add_member(
                &world.tenant,
                two,
                GroupMember::Group(one),
                Caller::system()
            ),
        );
        let succeeded = [&first, &second]
            .iter()
            .filter(|result| result.is_ok())
            .count();
        assert_eq!(succeeded, 1, "round {round}: {first:?} {second:?}");
        let refused = first.err().or(second.err()).expect("one refused");
        assert_eq!(refused.code(), "identity.group_cycle");
    }
}

#[tokio::test]
async fn the_bound_on_depth_is_read_from_the_tenants_settings() {
    let database = TestDatabase::start().await;
    let world = world(&database, "acme").await;
    let (a, b, c) = (
        world.group("a").await,
        world.group("b").await,
        world.group("c").await,
    );
    world
        .groups
        .add_member(&world.tenant, a, GroupMember::Group(b), Caller::system())
        .await
        .expect("depth 2 under the default of 5");

    let mut settings = world
        .tenants
        .get(&world.tenant)
        .await
        .expect("tenant")
        .snapshot()
        .settings
        .clone();
    settings.groups.max_depth = 2;
    world
        .tenants
        .change_settings(&world.tenant, settings, Caller::system())
        .await
        .expect("settings");
    let refused = world
        .groups
        .add_member(&world.tenant, b, GroupMember::Group(c), Caller::system())
        .await
        .expect_err("depth 3 under 2");
    assert_eq!(refused.code(), "identity.group_nesting_too_deep");
}

#[tokio::test]
async fn a_user_marked_deleted_leaves_every_group_in_the_same_transaction() {
    let database = TestDatabase::start().await;
    let world = world(&database, "acme").await;
    let (finance, payables) = (world.group("finance").await, world.group("payables").await);
    let ana = world.person("ana@example.com").await;
    for group in [finance, payables] {
        world
            .groups
            .add_member(
                &world.tenant,
                group,
                GroupMember::User(ana),
                Caller::system(),
            )
            .await
            .expect("add");
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

    let (left, removed): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM identity.group_member),
                (SELECT count(*) FROM platform.outbox WHERE event_type = 'identity.group_member_removed')",
    )
    .fetch_one(database.owner())
    .await
    .expect("counts");
    assert_eq!((left, removed), (0, 2));
}

#[tokio::test]
async fn a_member_of_another_tenant_is_refused_by_the_database_too() {
    let database = TestDatabase::start().await;
    let home = world(&database, "acme").await;
    let other = world(&database, "globex").await;
    let finance = home.group("finance").await;
    let stranger = other.person("ana@example.com").await;

    // Past the use case's own check: the foreign key holds the tenant.
    let refused = sqlx::query(
        "INSERT INTO identity.group_member (tenant_id, group_id, user_id, added_at)
         VALUES ($1, $2, $3, now())",
    )
    .bind(home.tenant.tenant_id().as_uuid())
    .bind(finance.as_uuid())
    .bind(stranger.as_uuid())
    .execute(database.owner())
    .await;
    assert!(
        refused.is_err(),
        "a user of another tenant cannot be a member"
    );
}
