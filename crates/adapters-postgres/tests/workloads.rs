//! Service accounts and agents on PostgreSQL.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgGroupRepository, PgOrganizationRepository, PgTenantDirectory, PgTenantRepository,
    PgUserRepository, PgWorkloadRepository,
};
use hodor_identity::api::{
    CreateUser, CreateWorkload, IdentifierKind, IdentityService, Profile, UserKind, WorkloadService,
};
use hodor_identity::testing::{RecordingWorkloadAccess, WorkloadPorts, run_workload_contract};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::{Caller, TenantContext, Timestamp};
use hodor_tenant::api::{CreateTenant, TenantService};
use std::sync::Arc;

#[tokio::test]
async fn the_postgres_ports_pass_the_contract() {
    let database = TestDatabase::start().await;
    run_workload_contract(WorkloadPorts {
        units_of_work: database.app(),
        users: &PgUserRepository,
        workloads: &PgWorkloadRepository,
    })
    .await;
}

#[tokio::test]
async fn a_workload_is_created_changed_and_deleted_in_one_transaction_each() {
    let database = TestDatabase::start().await;
    let units = || Arc::new(database.app().clone());
    let clock = Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH));
    let tenant = TenantService::new(
        units(),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.app().clone())),
        clock.clone(),
    )
    .create(
        CreateTenant {
            slug: "acme".to_owned(),
            display_name: "Acme".to_owned(),
            open_registration: false,
            system: false,
        },
        Caller::system(),
    )
    .await
    .expect("a tenant");
    let tenant = TenantContext::assume(tenant.id());
    let identity = IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone())
        .with_groups(Arc::new(PgGroupRepository))
        .with_organizations(Arc::new(PgOrganizationRepository));
    let access = RecordingWorkloadAccess::default();
    let workloads = WorkloadService::new(
        units(),
        identity.clone(),
        Arc::new(PgWorkloadRepository),
        Arc::new(access.clone()),
        clock,
    );
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
    let export = workloads
        .create(
            &tenant,
            CreateWorkload {
                kind: UserKind::ServiceAccount,
                name: "Nightly export".to_owned(),
                owners: vec![ana],
            },
            Caller::system(),
        )
        .await
        .expect("created");
    assert_eq!(export.owners(), [ana]);
    let disabled = workloads
        .disable(
            &tenant,
            UserKind::ServiceAccount,
            export.id(),
            Caller::system(),
        )
        .await
        .expect("disabled");
    assert_eq!(disabled.status().as_str(), "disabled");
    workloads
        .delete(
            &tenant,
            UserKind::ServiceAccount,
            export.id(),
            Caller::system(),
        )
        .await
        .expect("deleted");
    assert_eq!(access.calls().len(), 3);
    let owners: i64 = sqlx::query_scalar("SELECT count(*) FROM identity.workload_owner")
        .fetch_one(database.owner())
        .await
        .expect("count");
    assert_eq!(owners, 0, "a deleted workload's owners are forgotten");
    let (status, name): (String, Option<String>) =
        sqlx::query_as(r#"SELECT status, display_name FROM identity."user" WHERE id = $1"#)
            .bind(export.id().as_uuid())
            .fetch_one(database.owner())
            .await
            .expect("the row remains");
    assert_eq!((status.as_str(), name), ("deleted", None));
}

#[tokio::test]
async fn the_database_keeps_the_grants_of_a_client_with_a_principal() {
    let database = TestDatabase::start().await;
    for (name, expected) in [
        (
            "client_principal_grants",
            &[
                "principal_id IS NULL",
                "'client_credentials'",
                "token-exchange",
            ][..],
        ),
        (
            "client_token_exchange_needs_principal",
            &["token-exchange", "principal_id IS NOT NULL"][..],
        ),
    ] {
        let definition: String = sqlx::query_scalar(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = $1",
        )
        .bind(name)
        .fetch_one(database.owner())
        .await
        .unwrap_or_else(|_| panic!("the constraint {name} exists"));
        for part in expected {
            assert!(definition.contains(part), "{name}: {definition}");
        }
    }
}
