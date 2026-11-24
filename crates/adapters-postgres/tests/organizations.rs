//! Organizations on PostgreSQL.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{PgOrganizationRepository, PgUserRepository};
use hodor_identity::api::{
    CreateUser, IdentifierKind, IdentityService, OrganizationService, Profile, UnitChange,
    UnitKind, UserKind,
};
use hodor_identity::testing::{OrganizationPorts, run_organization_contract};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::{Caller, TenantContext, TenantId, Timestamp};
use std::collections::BTreeSet;
use std::sync::Arc;

fn services(database: &TestDatabase) -> (OrganizationService, IdentityService) {
    let units = || Arc::new(database.app().clone());
    let clock = Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH));
    (
        OrganizationService::new(
            units(),
            Arc::new(PgOrganizationRepository),
            Arc::new(PgUserRepository),
            clock.clone(),
        ),
        IdentityService::new(units(), Arc::new(PgUserRepository), clock)
            .with_organizations(Arc::new(PgOrganizationRepository)),
    )
}

#[tokio::test]
async fn the_postgres_ports_pass_the_contract() {
    let database = TestDatabase::start().await;
    run_organization_contract(OrganizationPorts {
        units_of_work: database.app(),
        users: &PgUserRepository,
        organizations: &PgOrganizationRepository,
    })
    .await;
}

#[tokio::test]
async fn two_moves_that_would_make_a_cycle_together_cannot_both_succeed() {
    let database = TestDatabase::start().await;
    let (organizations, _) = services(&database);
    let tenant = TenantContext::assume(TenantId::generate());
    let acme = organizations
        .create(&tenant, "Acme", None, Caller::system())
        .await
        .expect("an organization")
        .id();
    for round in 0..20 {
        let one = organizations
            .create_unit(
                &tenant,
                acme,
                None,
                &format!("one {round}"),
                UnitKind::Unit,
                Caller::system(),
            )
            .await
            .expect("a unit");
        let two = organizations
            .create_unit(
                &tenant,
                acme,
                None,
                &format!("two {round}"),
                UnitKind::Unit,
                Caller::system(),
            )
            .await
            .expect("a unit");
        let under = |parent: &hodor_identity::api::Unit, name: &str| UnitChange {
            parent: Some(parent.id),
            name: name.to_owned(),
            kind: UnitKind::Unit,
        };
        let (first, second) = tokio::join!(
            organizations.change_unit(
                &tenant,
                acme,
                one.id,
                under(&two, one.name.as_str()),
                Caller::system()
            ),
            organizations.change_unit(
                &tenant,
                acme,
                two.id,
                under(&one, two.name.as_str()),
                Caller::system()
            ),
        );
        let succeeded = [&first, &second]
            .iter()
            .filter(|result| result.is_ok())
            .count();
        assert_eq!(succeeded, 1, "round {round}: {first:?} {second:?}");
        let refused = first.err().or(second.err()).expect("one refused");
        assert_eq!(refused.code(), "identity.unit_cycle");
    }
}

#[tokio::test]
async fn the_database_keeps_units_and_members_inside_their_organization() {
    let database = TestDatabase::start().await;
    let (organizations, identity) = services(&database);
    let tenant = TenantContext::assume(TenantId::generate());
    let acme = organizations
        .create(&tenant, "Acme", None, Caller::system())
        .await
        .expect("acme")
        .id();
    let globex = organizations
        .create(&tenant, "Globex", None, Caller::system())
        .await
        .expect("globex")
        .id();
    let sales = organizations
        .create_unit(
            &tenant,
            globex,
            None,
            "Sales",
            UnitKind::Department,
            Caller::system(),
        )
        .await
        .expect("a unit");
    let ana = identity
        .create(
            &tenant,
            CreateUser {
                kind: UserKind::Human,
                identifiers: vec![(IdentifierKind::Email, "ana@example.com".to_owned())],
                profile: Profile::default(),
                confirmed: true,
            },
            Caller::system(),
        )
        .await
        .expect("a person")
        .id();
    organizations
        .add_member(&tenant, acme, ana, BTreeSet::new(), Caller::system())
        .await
        .expect("a member");

    // Past the use case's own checks: a unit of Globex in a membership of
    // Acme, and a parent of Globex for a unit of Acme.
    let refused = sqlx::query(
        "INSERT INTO identity.organization_member_unit (tenant_id, organization_id, user_id, unit_id)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(tenant.tenant_id().as_uuid())
    .bind(acme.as_uuid())
    .bind(ana.as_uuid())
    .bind(sales.id.as_uuid())
    .execute(database.owner())
    .await;
    assert!(
        refused.is_err(),
        "a unit of another organization in a membership"
    );
    let refused = sqlx::query(
        "INSERT INTO identity.organization_unit
             (tenant_id, id, organization_id, parent_id, name, name_normalized, kind, created_at, updated_at)
         VALUES ($1, gen_random_uuid(), $2, $3, 'Lost', 'lost', 'unit', now(), now())",
    )
    .bind(tenant.tenant_id().as_uuid())
    .bind(acme.as_uuid())
    .bind(sales.id.as_uuid())
    .execute(database.owner())
    .await;
    assert!(refused.is_err(), "a parent of another organization");

    // Marking the person Deleted ends the membership in the same transaction.
    identity
        .deactivate(&tenant, ana, Caller::system())
        .await
        .expect("deactivate");
    identity
        .mark_deleted(&tenant, ana, Caller::system())
        .await
        .expect("delete");
    let (left, removed): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM identity.organization_member),
                (SELECT count(*) FROM platform.outbox WHERE event_type = 'identity.organization_member_removed')",
    )
    .fetch_one(database.owner())
    .await
    .expect("counts");
    assert_eq!((left, removed), (0, 1));
}
