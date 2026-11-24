//! The provisioning context on PostgreSQL.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgGroupPolicy, PgGroupRepository, PgProvisionedGroupRepository, PgProvisionedUserRepository,
    PgUserRepository,
};
use hodor_identity::api::{GroupService, IdentityService};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::{
    Actor, Caller, ClientActorId, CorrelationId, TenantContext, TenantId, Timestamp, UserId,
};
use hodor_provisioning::api::{
    GROUP_SCHEMA, ProvisioningPorts, ProvisioningService, USER_SCHEMA, read_group, read_user,
};
use hodor_provisioning::testing::{ContractPorts, run_contract};
use serde_json::json;
use std::sync::Arc;

#[tokio::test]
async fn the_postgres_stores_pass_the_contract() {
    let database = TestDatabase::start().await;
    run_contract(ContractPorts {
        units_of_work: database.app(),
        users: &PgUserRepository,
        groups: &PgGroupRepository,
        provisioned_users: &PgProvisionedUserRepository,
        provisioned_groups: &PgProvisionedGroupRepository,
    })
    .await;
}

fn service(database: &TestDatabase) -> ProvisioningService {
    let units = || Arc::new(database.app().clone());
    let clock = Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH));
    ProvisioningService::new(ProvisioningPorts {
        units_of_work: units(),
        identity: IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone())
            .with_groups(Arc::new(PgGroupRepository)),
        groups: GroupService::new(
            units(),
            Arc::new(PgGroupRepository),
            Arc::new(PgUserRepository),
            Arc::new(PgGroupPolicy),
            clock.clone(),
        ),
        users: Arc::new(PgProvisionedUserRepository),
        provisioned_groups: Arc::new(PgProvisionedGroupRepository),
        clock,
    })
}

fn client() -> Caller {
    Caller {
        actor: Actor::Client(ClientActorId::generate()),
        correlation_id: CorrelationId::generate(),
    }
}

async fn count(database: &TestDatabase, statement: &'static str) -> i64 {
    sqlx::query_scalar(statement)
        .fetch_one(database.owner())
        .await
        .expect("a count")
}

#[tokio::test]
async fn a_request_that_is_refused_part_way_changes_nothing() {
    let database = TestDatabase::start().await;
    let service = service(&database);
    let tenant = TenantContext::assume(TenantId::generate());
    let ana = service
        .create_user(
            &tenant,
            &read_user(&json!({
                "schemas": [USER_SCHEMA],
                "userName": "ana",
                "externalId": "A-1",
                "emails": [{ "value": "ana@example.com" }],
            }))
            .expect("a request"),
            client(),
        )
        .await
        .expect("ana");
    let before = (
        count(&database, "SELECT count(*) FROM identity.\"user\"").await,
        count(&database, "SELECT count(*) FROM platform.outbox").await,
    );

    // Bob's second address is Ana's: Bob is not created at all.
    let refused = service
        .create_user(
            &tenant,
            &read_user(&json!({
                "schemas": [USER_SCHEMA],
                "userName": "bob",
                "externalId": "B-1",
                "emails": [{ "value": "bob@example.com" }, { "value": "ANA@example.com" }],
            }))
            .expect("a request"),
            client(),
        )
        .await
        .expect_err("taken");
    assert_eq!(refused.code(), "identity.identifier_taken");

    // A group whose second member does not exist is not created at all.
    let refused = service
        .create_group(
            &tenant,
            &read_group(&json!({
                "schemas": [GROUP_SCHEMA],
                "displayName": "finance",
                "externalId": "F-1",
                "members": [
                    { "value": ana.user.id().to_string() },
                    { "value": UserId::generate().to_string() }
                ],
            }))
            .expect("a request"),
            client(),
        )
        .await
        .expect_err("no such member");
    assert_eq!(refused.code(), "provisioning.invalid_value");

    let after = (
        count(&database, "SELECT count(*) FROM identity.\"user\"").await,
        count(&database, "SELECT count(*) FROM platform.outbox").await,
    );
    assert_eq!(before, after, "nothing was stored and nothing recorded");
    assert_eq!(
        count(&database, "SELECT count(*) FROM identity.\"group\"").await,
        0
    );
    assert_eq!(
        count(
            &database,
            "SELECT count(*) FROM provisioning.group_attribute"
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &database,
            "SELECT count(*) FROM provisioning.user_attribute"
        )
        .await,
        1
    );
}

#[tokio::test]
async fn deleting_a_group_through_scim_takes_what_is_kept_of_it_and_events_name_the_client() {
    let database = TestDatabase::start().await;
    let service = service(&database);
    let tenant = TenantContext::assume(TenantId::generate());
    let caller = client();
    let group = service
        .create_group(
            &tenant,
            &read_group(&json!({
                "schemas": [GROUP_SCHEMA],
                "displayName": "finance",
                "externalId": "F-1",
            }))
            .expect("a request"),
            caller,
        )
        .await
        .expect("a group");
    service
        .delete_group(&tenant, group.group.id(), caller)
        .await
        .expect("deleted");
    assert_eq!(
        count(
            &database,
            "SELECT count(*) FROM provisioning.group_attribute"
        )
        .await,
        0
    );
    let Actor::Client(client_id) = caller.actor else {
        panic!("a client");
    };
    let actors: Vec<(String, serde_json::Value)> =
        sqlx::query_as("SELECT event_type, actor FROM platform.outbox ORDER BY id")
            .fetch_all(database.owner())
            .await
            .expect("events");
    assert_eq!(
        actors
            .iter()
            .map(|(kind, _)| kind.as_str())
            .collect::<Vec<_>>(),
        [
            "identity.group_created",
            "provisioning.group_attributes_changed",
            "identity.group_deleted"
        ]
    );
    for (_, actor) in actors {
        assert_eq!(
            actor,
            json!({ "kind": "client", "id": client_id.to_string() })
        );
    }
}
