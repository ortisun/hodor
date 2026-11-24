//! The use cases of the provisioning context, on the in-memory stores.

use hodor_identity::api::{
    CreateUser, GroupService, IdentifierKind, IdentityService, Profile, UserKind, UserStatus,
};
use hodor_identity::testing::{FixedGroupPolicy, InMemoryGroups, InMemoryUsers};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Actor, Caller, ClientActorId, CorrelationId, ErrorKind, TenantContext, TenantId, Timestamp,
    UserId,
};
use hodor_provisioning::api::{
    GROUP_SCHEMA, ListParameters, ListQuery, ProvisioningPorts, ProvisioningService, USER_SCHEMA,
    read_group, read_user,
};
use hodor_provisioning::testing::{
    ContractPorts, InMemoryProvisionedGroups, InMemoryProvisionedUsers, run_contract,
};
use serde_json::{Value, json};
use std::sync::Arc;
use time::Duration;

const BASE: &str = "https://id.example.com/t/acme/scim/v2";

struct World {
    units: InMemoryUnitOfWorkFactory,
    clock: Arc<FixedClock>,
    identity: IdentityService,
    service: ProvisioningService,
    tenant: TenantContext,
    client: Caller,
}

fn world() -> World {
    let units = InMemoryUnitOfWorkFactory::default();
    let users = InMemoryUsers::default();
    let groups = InMemoryGroups::default();
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + Duration::days(20_000),
    ));
    let identity = IdentityService::new(
        Arc::new(units.clone()),
        Arc::new(users.clone()),
        clock.clone(),
    )
    .with_groups(Arc::new(groups.clone()));
    let group_service = GroupService::new(
        Arc::new(units.clone()),
        Arc::new(groups.clone()),
        Arc::new(users.clone()),
        Arc::new(FixedGroupPolicy(5)),
        clock.clone(),
    );
    let service = ProvisioningService::new(ProvisioningPorts {
        units_of_work: Arc::new(units.clone()),
        identity: identity.clone(),
        groups: group_service,
        users: Arc::new(InMemoryProvisionedUsers::new(Arc::new(users))),
        provisioned_groups: Arc::new(InMemoryProvisionedGroups::new(Arc::new(groups))),
        clock: clock.clone(),
    });
    World {
        units,
        clock,
        identity,
        service,
        tenant: TenantContext::assume(TenantId::generate()),
        client: Caller {
            actor: Actor::Client(ClientActorId::generate()),
            correlation_id: CorrelationId::generate(),
        },
    }
}

fn user(body: &Value) -> hodor_provisioning::api::UserRequest {
    read_user(body).expect("a user request")
}

fn group(body: &Value) -> hodor_provisioning::api::GroupRequest {
    read_group(body).expect("a group request")
}

fn bjensen() -> Value {
    json!({
        "schemas": [USER_SCHEMA, "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
        "externalId": "701984",
        "userName": "bjensen",
        "name": { "formatted": "Barbara Jensen", "givenName": "Barbara", "familyName": "Jensen" },
        "emails": [{ "value": "bjensen@example.com", "primary": true }, { "value": "babs@jensen.org" }],
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
            "department": "Tour Operations",
            "manager": { "value": "26118915" }
        }
    })
}

#[tokio::test]
async fn the_in_memory_stores_pass_the_contract() {
    let units = InMemoryUnitOfWorkFactory::default();
    let users = InMemoryUsers::default();
    let groups = InMemoryGroups::default();
    let provisioned_users = InMemoryProvisionedUsers::new(Arc::new(users.clone()));
    let provisioned_groups = InMemoryProvisionedGroups::new(Arc::new(groups.clone()));
    run_contract(ContractPorts {
        units_of_work: &units,
        users: &users,
        groups: &groups,
        provisioned_users: &provisioned_users,
        provisioned_groups: &provisioned_groups,
    })
    .await;
}

#[tokio::test]
async fn a_user_is_created_with_its_addresses_verified_and_read_back_as_scim_writes_it() {
    let world = world();
    let created = world
        .service
        .create_user(&world.tenant, &user(&bjensen()), world.client)
        .await
        .expect("created");
    let document = created.document(BASE);
    let id = created.user.id();
    assert_eq!(document["userName"], "bjensen");
    assert_eq!(
        document["displayName"], "Barbara Jensen",
        "name.formatted stands in"
    );
    assert_eq!(document["name"]["givenName"], "Barbara");
    assert_eq!(document["externalId"], "701984");
    assert_eq!(document["active"], true);
    assert_eq!(
        document["emails"],
        json!([
            { "value": "bjensen@example.com", "primary": true },
            { "value": "babs@jensen.org", "primary": false }
        ])
    );
    assert_eq!(
        document["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]["manager"]["value"],
        "26118915"
    );
    assert_eq!(document["meta"]["location"], format!("{BASE}/Users/{id}"));
    assert_eq!(document["meta"]["resourceType"], "User");
    assert!(
        created
            .user
            .identifiers()
            .iter()
            .filter(|held| held.value.kind() == IdentifierKind::Email)
            .all(|held| held.is_verified()),
        "addresses SCIM sets count as verified"
    );

    let events = world.units.committed_events();
    let types: Vec<&str> = events
        .iter()
        .map(|event| event.event_type.as_str())
        .collect();
    assert!(types.contains(&"identity.user_created"));
    assert!(types.contains(&"identity.identifier_verified"));
    assert!(types.contains(&"provisioning.user_attributes_changed"));
    assert!(
        events
            .iter()
            .all(|event| event.metadata.actor == world.client.actor),
        "the calling client is the actor of every change"
    );
    let payloads = serde_json::to_string(
        &events
            .iter()
            .map(|event| event.payload.clone())
            .collect::<Vec<_>>(),
    )
    .expect("json");
    for value in [
        "701984",
        "Tour Operations",
        "bjensen@example.com",
        "Barbara",
    ] {
        assert!(!payloads.contains(value), "an event carried {value}");
    }
}

#[tokio::test]
async fn a_user_name_that_is_taken_is_refused_as_not_unique() {
    let world = world();
    world
        .service
        .create_user(&world.tenant, &user(&bjensen()), world.client)
        .await
        .expect("created");
    let again = world
        .service
        .create_user(
            &world.tenant,
            &user(&json!({ "schemas": [USER_SCHEMA], "userName": "BJENSEN" })),
            world.client,
        )
        .await
        .expect_err("taken");
    assert_eq!(again.code(), "identity.identifier_taken");
    assert_eq!(again.kind(), ErrorKind::Conflict);
}

#[tokio::test]
async fn active_false_suspends_and_active_true_reactivates() {
    let world = world();
    let created = world
        .service
        .create_user(
            &world.tenant,
            &user(&json!({ "schemas": [USER_SCHEMA], "userName": "ana@example.com", "active": false })),
            world.client,
        )
        .await
        .expect("created");
    assert_eq!(created.user.status(), UserStatus::Suspended);
    assert_eq!(created.document(BASE)["active"], false);
    assert_eq!(created.document(BASE)["userName"], "ana@example.com");
    let id = created.user.id();
    let replaced = world
        .service
        .replace_user(
            &world.tenant,
            id,
            &user(&json!({ "schemas": [USER_SCHEMA], "userName": "ana@example.com" })),
            world.client,
        )
        .await
        .expect("replaced");
    assert_eq!(replaced.user.status(), UserStatus::Active);
}

#[tokio::test]
async fn replacing_removes_what_the_request_leaves_out_and_the_same_request_changes_nothing() {
    let world = world();
    let created = world
        .service
        .create_user(&world.tenant, &user(&bjensen()), world.client)
        .await
        .expect("created");
    let id = created.user.id();
    world.clock.advance(Duration::hours(1));
    let request = user(&json!({
        "schemas": [USER_SCHEMA],
        "userName": "barbara.jensen",
        "displayName": "Babs",
        "emails": [{ "value": "babs@jensen.org" }],
    }));
    let replaced = world
        .service
        .replace_user(&world.tenant, id, &request, world.client)
        .await
        .expect("replaced");
    let document = replaced.document(BASE);
    assert_eq!(document["userName"], "barbara.jensen");
    assert_eq!(document["displayName"], "Babs");
    assert_eq!(
        document["emails"],
        json!([{ "value": "babs@jensen.org", "primary": true }])
    );
    assert!(document.get("externalId").is_none());
    assert!(document.get("name").is_none());
    assert!(
        document
            .get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")
            .is_none()
    );
    assert_ne!(
        document["meta"]["lastModified"],
        document["meta"]["created"]
    );

    let before = world.units.committed_events().len();
    world.clock.advance(Duration::hours(1));
    let again = world
        .service
        .replace_user(&world.tenant, id, &request, world.client)
        .await
        .expect("again");
    assert_eq!(
        world.units.committed_events().len(),
        before,
        "the same request records nothing"
    );
    assert_eq!(again.document(BASE)["meta"], document["meta"]);
}

#[tokio::test]
async fn users_scim_does_not_show_are_not_found() {
    let world = world();
    let robot = world
        .identity
        .create(
            &world.tenant,
            CreateUser {
                kind: UserKind::ServiceAccount,
                identifiers: vec![(IdentifierKind::Username, "robot".to_owned())],
                profile: Profile::default(),
                confirmed: true,
            },
            Caller::system(),
        )
        .await
        .expect("a service account")
        .id();
    for id in [robot, UserId::generate()] {
        let error = world
            .service
            .get_user(&world.tenant, id)
            .await
            .expect_err("not shown");
        assert_eq!(error.code(), "provisioning.user_not_found");
    }
    let created = world
        .service
        .create_user(&world.tenant, &user(&bjensen()), world.client)
        .await
        .expect("created");
    let elsewhere = TenantContext::assume(TenantId::generate());
    let error = world
        .service
        .get_user(&elsewhere, created.user.id())
        .await
        .expect_err("another tenant's");
    assert_eq!(error.kind(), ErrorKind::NotFound);
    let listed = world
        .service
        .list_users(&world.tenant, &ListQuery::default())
        .await
        .expect("listed");
    assert_eq!(listed.total, 1, "the service account is not listed");
}

#[tokio::test]
async fn a_group_is_created_replaced_and_deleted_with_its_members() {
    let world = world();
    let ana = world
        .service
        .create_user(
            &world.tenant,
            &user(
                &json!({ "schemas": [USER_SCHEMA], "userName": "ana", "displayName": "Ana Silva" }),
            ),
            world.client,
        )
        .await
        .expect("ana")
        .user
        .id();
    let bob = world
        .service
        .create_user(
            &world.tenant,
            &user(&json!({ "schemas": [USER_SCHEMA], "userName": "bob" })),
            world.client,
        )
        .await
        .expect("bob")
        .user
        .id();
    let payables = world
        .service
        .create_group(
            &world.tenant,
            &group(&json!({ "schemas": [GROUP_SCHEMA], "displayName": "payables" })),
            world.client,
        )
        .await
        .expect("payables")
        .group
        .id();
    let finance = world
        .service
        .create_group(
            &world.tenant,
            &group(&json!({
                "schemas": [GROUP_SCHEMA],
                "displayName": "finance",
                "externalId": "F-1",
                "members": [
                    { "value": ana.to_string(), "type": "User" },
                    { "value": payables.to_string() }
                ]
            })),
            world.client,
        )
        .await
        .expect("finance");
    let document = finance.document(BASE);
    assert_eq!(document["externalId"], "F-1");
    assert_eq!(
        document["members"],
        json!([
            { "value": ana.to_string(), "type": "User", "display": "Ana Silva", "$ref": format!("{BASE}/Users/{ana}") },
            { "value": payables.to_string(), "type": "Group", "display": "payables", "$ref": format!("{BASE}/Groups/{payables}") }
        ])
    );
    let ana_now = world
        .service
        .get_user(&world.tenant, ana)
        .await
        .expect("ana");
    assert_eq!(
        ana_now.document(BASE)["groups"][0]["display"],
        "finance",
        "a user reads the groups it is directly in"
    );

    // A wrong type, an unknown member and a cycle are refused.
    let id = finance.group.id();
    for (members, code) in [
        (
            json!([{ "value": ana.to_string(), "type": "Group" }]),
            "provisioning.invalid_value",
        ),
        (
            json!([{ "value": UserId::generate().to_string() }]),
            "provisioning.invalid_value",
        ),
        (json!([{ "value": id.to_string() }]), "identity.group_cycle"),
    ] {
        let error = world
            .service
            .replace_group(
                &world.tenant,
                id,
                &group(&json!({ "schemas": [GROUP_SCHEMA], "displayName": "finance", "members": members })),
                world.client,
            )
            .await
            .expect_err("refused");
        assert_eq!(error.code(), code);
    }

    world.clock.advance(Duration::hours(1));
    let replaced = world
        .service
        .replace_group(
            &world.tenant,
            id,
            &group(&json!({
                "schemas": [GROUP_SCHEMA],
                "displayName": "Finance team",
                "members": [{ "value": bob.to_string() }]
            })),
            world.client,
        )
        .await
        .expect("replaced");
    let document = replaced.document(BASE);
    assert_eq!(document["displayName"], "Finance team");
    assert!(document.get("externalId").is_none());
    assert_eq!(document["members"][0]["value"], bob.to_string());
    assert_eq!(document["members"].as_array().map(Vec::len), Some(1));
    assert_ne!(
        document["meta"]["lastModified"],
        document["meta"]["created"]
    );

    let listed = world
        .service
        .list_groups(
            &world.tenant,
            &ListQuery::read(&ListParameters {
                filter: Some(&format!(r#"members eq "{bob}""#)),
                ..ListParameters::default()
            })
            .expect("a query"),
        )
        .await
        .expect("listed");
    assert_eq!(listed.total, 1);

    world
        .service
        .delete_group(&world.tenant, id, world.client)
        .await
        .expect("deleted");
    let error = world
        .service
        .get_group(&world.tenant, id)
        .await
        .expect_err("gone");
    assert_eq!(error.code(), "provisioning.group_not_found");
    let error = world
        .service
        .delete_group(&world.tenant, id, world.client)
        .await
        .expect_err("gone");
    assert_eq!(error.kind(), ErrorKind::NotFound);
    let types = world.units.committed_event_types();
    assert!(types.iter().any(|kind| kind == "identity.group_deleted"));
    assert!(
        types
            .iter()
            .any(|kind| kind == "provisioning.group_attributes_changed")
    );
}
