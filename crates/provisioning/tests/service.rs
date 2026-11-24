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
    ContractPorts, FixedDeprovisioning, InMemoryProvisionedGroups, InMemoryProvisionedUsers,
    RecordingAccessRevoker, run_contract,
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
    policy: FixedDeprovisioning,
    access: RecordingAccessRevoker,
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
    let policy = FixedDeprovisioning::default();
    let access = RecordingAccessRevoker::default();
    let service = ProvisioningService::new(ProvisioningPorts {
        units_of_work: Arc::new(units.clone()),
        identity: identity.clone(),
        groups: group_service,
        users: Arc::new(InMemoryProvisionedUsers::new(Arc::new(users))),
        provisioned_groups: Arc::new(InMemoryProvisionedGroups::new(Arc::new(groups))),
        deprovisioning: Arc::new(policy.clone()),
        access: Arc::new(access.clone()),
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
        policy,
        access,
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
async fn active_false_creates_a_user_deactivated_and_active_true_restores_it() {
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
    assert_eq!(created.user.status(), UserStatus::Deactivated);
    assert_eq!(created.document(BASE)["active"], false);
    assert_eq!(created.document(BASE)["userName"], "ana@example.com");
    let id = created.user.id();
    let replaced = world
        .service
        .replace_user(
            &world.tenant,
            id,
            &user(&json!({ "schemas": [USER_SCHEMA], "userName": "ana@example.com" })),
            None,
            world.client,
        )
        .await
        .expect("replaced")
        .expect("still there");
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
        .replace_user(&world.tenant, id, &request, None, world.client)
        .await
        .expect("replaced")
        .expect("still there");
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
        .replace_user(&world.tenant, id, &request, None, world.client)
        .await
        .expect("again")
        .expect("still there");
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
                identifiers: vec![],
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
                None,
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
            None,
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
        .delete_group(&world.tenant, id, None, world.client)
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
        .delete_group(&world.tenant, id, None, world.client)
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

fn patch(operations: Value) -> hodor_provisioning::api::PatchRequest {
    hodor_provisioning::api::read_patch(
        &json!({ "schemas": [hodor_provisioning::api::PATCH_SCHEMA], "Operations": operations }),
        &hodor_provisioning::api::USER_SHAPE,
    )
    .expect("a patch")
}

fn group_patch(operations: Value) -> hodor_provisioning::api::PatchRequest {
    hodor_provisioning::api::read_patch(
        &json!({ "schemas": [hodor_provisioning::api::PATCH_SCHEMA], "Operations": operations }),
        &hodor_provisioning::api::GROUP_SHAPE,
    )
    .expect("a patch")
}

#[tokio::test]
async fn a_patch_changes_part_of_a_user_and_a_stale_version_is_refused() {
    let world = world();
    let created = world
        .service
        .create_user(&world.tenant, &user(&bjensen()), world.client)
        .await
        .expect("created");
    let id = created.user.id();
    let first = created.version();
    let patched = world
        .service
        .patch_user(
            &world.tenant,
            id,
            &patch(json!([
                { "op": "add", "path": "emails[type eq \"work\"].value", "value": "babs@example.org" },
                { "op": "replace", "path": "name.givenName", "value": "Babs" },
                { "op": "remove", "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager" }
            ])),
            Some(&hodor_provisioning::api::Precondition::read(&first)),
            world.client,
        )
        .await
        .expect("patched")
        .expect("still there");
    let document = patched.document(BASE);
    assert_eq!(document["name"]["givenName"], "Babs");
    assert!(
        document["emails"]
            .as_array()
            .expect("emails")
            .iter()
            .any(|email| email["value"] == "babs@example.org" && email["type"] == "work")
    );
    assert!(
        document["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]
            .get("manager")
            .is_none()
    );
    assert_ne!(patched.version(), first, "a change makes a new version");
    assert_eq!(document["meta"]["version"], patched.version());

    let stale = world
        .service
        .patch_user(
            &world.tenant,
            id,
            &patch(json!([{ "op": "replace", "path": "displayName", "value": "Late" }])),
            Some(&hodor_provisioning::api::Precondition::read(&first)),
            world.client,
        )
        .await
        .expect_err("a stale version");
    assert_eq!(stale.code(), "provisioning.version_mismatch");
    let unchanged = world
        .service
        .get_user(&world.tenant, id)
        .await
        .expect("read");
    assert_eq!(unchanged.version(), patched.version(), "nothing changed");

    let refused = world
        .service
        .patch_user(
            &world.tenant,
            id,
            &patch(json!([{ "op": "remove", "path": "userName" }])),
            None,
            world.client,
        )
        .await
        .expect_err("userName is required");
    assert_eq!(refused.code(), "provisioning.invalid_value");
}

#[tokio::test]
async fn deprovisioning_follows_the_policy_and_ends_access() {
    let world = world();
    let ana = world
        .service
        .create_user(
            &world.tenant,
            &user(&json!({ "schemas": [USER_SCHEMA], "userName": "ana", "externalId": "A-1" })),
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

    // active: false deactivates and keeps the user seen.
    let patched = world
        .service
        .patch_user(
            &world.tenant,
            ana,
            &patch(json!([{ "op": "replace", "value": { "active": "False" } }])),
            None,
            world.client,
        )
        .await
        .expect("patched")
        .expect("still seen");
    assert_eq!(patched.user.status(), UserStatus::Deactivated);
    assert_eq!(
        world.access.revoked(),
        [(world.tenant.tenant_id(), ana, "deprovisioned")]
    );

    // DELETE deactivates and hides; the identity stays restorable.
    world
        .service
        .delete_user(&world.tenant, ana, None, world.client)
        .await
        .expect("deleted");
    assert_eq!(
        world
            .service
            .get_user(&world.tenant, ana)
            .await
            .expect_err("hidden")
            .code(),
        "provisioning.user_not_found"
    );
    let still = world
        .identity
        .get(&world.tenant, ana)
        .await
        .expect("still there");
    assert_eq!(still.status(), UserStatus::Deactivated);
    let listed = world
        .service
        .list_users(&world.tenant, &ListQuery::default())
        .await
        .expect("listed");
    assert_eq!(listed.total, 1, "a deleted user is never listed");

    // Under delete, the user is erased.
    world
        .policy
        .set(hodor_provisioning::api::Deprovisioning::Delete);
    let gone = world
        .service
        .replace_user(
            &world.tenant,
            bob,
            &user(&json!({ "schemas": [USER_SCHEMA], "userName": "bob", "active": false })),
            None,
            world.client,
        )
        .await
        .expect("deprovisioned");
    assert!(gone.is_none(), "nothing is left to answer");
    let erased = world
        .identity
        .get(&world.tenant, bob)
        .await
        .expect("the identifier stays");
    assert_eq!(erased.status(), UserStatus::Deleted);
    assert!(erased.identifiers().is_empty());
    assert_eq!(world.access.revoked().len(), 3);
    let types = world.units.committed_event_types();
    for kind in ["identity.user_deactivated", "identity.user_deleted"] {
        assert!(types.iter().any(|event| event == kind), "{kind}");
    }
}

#[tokio::test]
async fn a_patch_adds_and_removes_members_one_by_one() {
    let world = world();
    let mut people = Vec::new();
    for name in ["ana", "bob", "carla"] {
        people.push(
            world
                .service
                .create_user(
                    &world.tenant,
                    &user(&json!({ "schemas": [USER_SCHEMA], "userName": name })),
                    world.client,
                )
                .await
                .expect("a person")
                .user
                .id(),
        );
    }
    let group = world
        .service
        .create_group(
            &world.tenant,
            &read_group(&json!({
                "schemas": [GROUP_SCHEMA],
                "displayName": "finance",
                "members": [{ "value": people[0].to_string() }],
            }))
            .expect("a request"),
            world.client,
        )
        .await
        .expect("a group");
    let id = group.group.id();
    let patched = world
        .service
        .patch_group(
            &world.tenant,
            id,
            &group_patch(json!([
                { "op": "add", "path": "members", "value": [{ "value": people[1].to_string() }, { "value": people[2].to_string() }] },
                { "op": "remove", "path": format!("members[value eq \"{}\"]", people[0]) },
                { "op": "replace", "path": "displayName", "value": "Finance" }
            ])),
            Some(&hodor_provisioning::api::Precondition::read(&group.version())),
            world.client,
        )
        .await
        .expect("patched");
    let members: Vec<String> = patched
        .members
        .iter()
        .map(|view| view.member.id_text())
        .collect();
    assert_eq!(members.len(), 2);
    assert!(!members.contains(&people[0].to_string()));
    assert_eq!(patched.group.name().as_str(), "Finance");

    let too_many: Vec<Value> = (0..1001)
        .map(|_| json!({ "value": UserId::generate().to_string() }))
        .collect();
    let refused = world
        .service
        .patch_group(
            &world.tenant,
            id,
            &group_patch(json!([{ "op": "add", "path": "members", "value": too_many }])),
            None,
            world.client,
        )
        .await
        .expect_err("too many members");
    assert_eq!(refused.code(), "provisioning.invalid_value");
    let stale = world
        .service
        .delete_group(
            &world.tenant,
            id,
            Some(&hodor_provisioning::api::Precondition::read(
                &group.version(),
            )),
            world.client,
        )
        .await
        .expect_err("stale");
    assert_eq!(stale.code(), "provisioning.version_mismatch");
}
