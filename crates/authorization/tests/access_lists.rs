//! Access control lists: the use cases and the native engine reading
//! entries beside roles, against the in-memory stores.
//!
//! Specified in `docs/architecture/contexts/authorization.md`, "Access
//! control lists".

use hodor_authorization::api::{
    AccessEntryFilter, AccessListService, Action, AssignmentScope, Attributes, AuthorizationEngine,
    AuthorizationRequest, Effect, EngineAnswer, EvaluationContext, EvaluationInput, MATCHING_ENTRY,
    MATCHING_ROLE, Namespace, NativeEngine, PermissionName, PolicySelection, PolicySimulator,
    Resource, RoleContents, RoleKey, RoleName, RoleService, Subject, SubjectKind, Validity,
};
use hodor_authorization::testing::{
    AccessListPorts, InMemoryNativeRoles, InMemoryRoleAssignments, run_access_list_contract,
};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, PageRequest, TenantContext, TenantId, Timestamp};
use std::sync::Arc;
use std::time::Duration;

const DOCUMENTS: &str = "urn:example:documents";
const BILLING: &str = "https://billing.example.com";

struct World {
    roles: RoleService,
    lists: AccessListService,
    engine: NativeEngine,
    units: InMemoryUnitOfWorkFactory,
    tenant: TenantContext,
}

fn world() -> World {
    let units = InMemoryUnitOfWorkFactory::default();
    let store = InMemoryNativeRoles::default();
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + time::Duration::days(20_000),
    ));
    let engine = NativeEngine::new(
        Arc::new(units.clone()),
        Arc::new(InMemoryRoleAssignments::default()),
        Arc::new(store.clone()),
        clock.clone(),
    )
    .with_access_lists(Arc::new(store.clone()));
    World {
        roles: RoleService::new(
            Arc::new(units.clone()),
            Arc::new(store.clone()),
            clock.clone(),
        ),
        lists: AccessListService::new(
            Arc::new(units.clone()),
            Arc::new(store.clone()),
            Arc::new(store),
            clock,
        ),
        engine,
        units,
        tenant: TenantContext::assume(TenantId::generate()),
    }
}

fn namespace(value: &str) -> Namespace {
    Namespace::parse(value).expect("namespace")
}

fn permission(value: &str) -> PermissionName {
    PermissionName::parse(value).expect("permission")
}

fn user(name: &str) -> Subject {
    Subject::new(SubjectKind::User, name).expect("user")
}

fn group(name: &str) -> Subject {
    Subject::new(SubjectKind::Group, name).expect("group")
}

fn request(
    space: &str,
    subject: &Subject,
    kind: &str,
    id: Option<&str>,
    action: &str,
) -> AuthorizationRequest {
    AuthorizationRequest {
        namespace: namespace(space),
        subject: subject.clone(),
        asserted: Attributes::none(),
        resource: Resource::new(kind, id, Attributes::none()).expect("resource"),
        action: Action::parse(action).expect("action"),
        context: EvaluationContext::default(),
    }
}

impl World {
    async fn declare(&self, space: &str, names: &[&str]) {
        for name in names {
            self.roles
                .declare_permission(
                    &self.tenant,
                    namespace(space),
                    permission(name),
                    "",
                    Caller::system(),
                )
                .await
                .expect("declare");
        }
    }

    async fn grant(&self, space: &str, granted: &str, resource: &str, to: &Subject) -> String {
        self.lists
            .grant(
                &self.tenant,
                namespace(space),
                permission(granted),
                resource,
                to.clone(),
                Caller::system(),
            )
            .await
            .expect("grant")
            .entry
            .id()
            .to_string()
    }

    /// The answer for a subject Hodor resolved in `groups`.
    async fn answer(&self, request: AuthorizationRequest, groups: &[&str]) -> EngineAnswer {
        self.answer_in(&self.tenant, request, groups).await
    }

    async fn answer_in(
        &self,
        tenant: &TenantContext,
        request: AuthorizationRequest,
        groups: &[&str],
    ) -> EngineAnswer {
        let attributes = Attributes::new([("groups".to_owned(), serde_json::json!(groups))])
            .expect("attributes");
        self.engine
            .evaluate(
                tenant,
                &EvaluationInput {
                    request,
                    subject_attributes: attributes,
                    time_limit: Duration::from_millis(200),
                },
            )
            .await
            .expect("answer")
    }
}

#[tokio::test]
async fn the_in_memory_store_passes_the_contract() {
    let units = InMemoryUnitOfWorkFactory::default();
    let store = InMemoryNativeRoles::default();
    run_access_list_contract(AccessListPorts {
        units_of_work: &units,
        roles: &store,
        entries: &store,
    })
    .await;
}

#[tokio::test]
async fn an_entry_allows_only_on_its_resource() {
    let world = world();
    world
        .declare(DOCUMENTS, &["document:read", "document:write"])
        .await;
    world.declare(BILLING, &["document:read"]).await;
    let ana = user("ana");
    let entry = world.grant(DOCUMENTS, "document:read", "d-42", &ana).await;

    let allowed = world
        .answer(
            request(DOCUMENTS, &ana, "document", Some("d-42"), "read"),
            &[],
        )
        .await;
    assert_eq!(allowed.effect, Effect::Allow);
    assert_eq!(allowed.reason.as_str(), MATCHING_ENTRY);
    let named: Vec<&str> = allowed
        .matched_policies
        .iter()
        .map(|policy| policy.as_str())
        .collect();
    assert_eq!(named, [format!("entry:{entry}")]);

    for (space, id, action, why) in [
        (DOCUMENTS, Some("d-43"), "read", "another document"),
        (DOCUMENTS, Some("d-42"), "write", "another permission"),
        (DOCUMENTS, None, "read", "no resource named"),
        (BILLING, Some("d-42"), "read", "another resource server"),
    ] {
        let answer = world
            .answer(request(space, &ana, "document", id, action), &[])
            .await;
        assert_eq!(answer.effect, Effect::Deny, "{why}");
        assert_eq!(answer.reason.as_str(), "no_matching_role", "{why}");
    }
    let folder = world
        .answer(
            request(DOCUMENTS, &ana, "folder", Some("d-42"), "read"),
            &[],
        )
        .await;
    assert_eq!(folder.effect, Effect::Deny, "a resource of another kind");
    let bob = world
        .answer(
            request(DOCUMENTS, &user("bob"), "document", Some("d-42"), "read"),
            &[],
        )
        .await;
    assert_eq!(bob.effect, Effect::Deny, "someone else");
}

#[tokio::test]
async fn leaving_a_group_an_entry_names_stops_allowing_on_the_next_decision() {
    let world = world();
    world.declare(DOCUMENTS, &["document:read"]).await;
    world
        .grant(DOCUMENTS, "document:read", "d-42", &group("finance"))
        .await;
    let ana = user("ana");
    let reading = request(DOCUMENTS, &ana, "document", Some("d-42"), "read");

    let member = world.answer(reading.clone(), &["staff", "finance"]).await;
    assert_eq!(member.effect, Effect::Allow);
    assert_eq!(member.reason.as_str(), MATCHING_ENTRY);
    let left = world.answer(reading.clone(), &["staff"]).await;
    assert_eq!(left.effect, Effect::Deny);
    let back = world.answer(reading, &["finance"]).await;
    assert_eq!(back.effect, Effect::Allow);

    // A client is in no group, whatever its attributes say.
    let client = Subject::new(SubjectKind::Client, "billing").expect("client");
    let asking = request(DOCUMENTS, &client, "document", Some("d-42"), "read");
    assert_eq!(
        world.answer(asking, &["finance"]).await.effect,
        Effect::Deny
    );
}

#[tokio::test]
async fn entries_name_clients_and_workloads_and_stand_beside_roles() {
    let world = world();
    world.declare(DOCUMENTS, &["document:read"]).await;
    let client = Subject::new(SubjectKind::Client, "indexer").expect("client");
    // A service account is a user.
    let account = user("0193f2c0-0000-7000-8000-000000000001");
    world
        .grant(DOCUMENTS, "document:read", "d-1", &client)
        .await;
    world
        .grant(DOCUMENTS, "document:read", "d-2", &account)
        .await;
    for (subject, resource) in [(&client, "d-1"), (&account, "d-2")] {
        let answer = world
            .answer(
                request(DOCUMENTS, subject, "document", Some(resource), "read"),
                &[],
            )
            .await;
        assert_eq!(answer.effect, Effect::Allow, "{resource}");
    }

    // A role still allows every document, an entry or not.
    world
        .roles
        .define_role(
            &world.tenant,
            RoleKey::new(
                namespace(DOCUMENTS),
                RoleName::parse("viewer").expect("name"),
            ),
            RoleContents::unconditional(
                "",
                [permission("document:read")].into(),
                std::collections::BTreeSet::new(),
            ),
            Caller::system(),
        )
        .await
        .expect("role");
    let ana = user("ana");
    world
        .roles
        .assign(
            &world.tenant,
            ana.clone(),
            RoleKey::new(
                namespace(DOCUMENTS),
                RoleName::parse("viewer").expect("name"),
            ),
            AssignmentScope::Tenant,
            Validity::default(),
            Caller::system(),
        )
        .await
        .expect("assign");
    let by_role = world
        .answer(
            request(DOCUMENTS, &ana, "document", Some("d-9"), "read"),
            &[],
        )
        .await;
    assert_eq!(by_role.effect, Effect::Allow);
    assert_eq!(by_role.reason.as_str(), MATCHING_ROLE);
    // An entry decides before the roles when both would allow.
    world.grant(DOCUMENTS, "document:read", "d-9", &ana).await;
    let by_entry = world
        .answer(
            request(DOCUMENTS, &ana, "document", Some("d-9"), "read"),
            &[],
        )
        .await;
    assert_eq!(by_entry.reason.as_str(), MATCHING_ENTRY);
}

#[tokio::test]
async fn granting_twice_changes_nothing_and_removing_stops_allowing_at_once() {
    let world = world();
    world.declare(DOCUMENTS, &["document:read"]).await;
    let ana = user("ana");
    let first = world
        .lists
        .grant(
            &world.tenant,
            namespace(DOCUMENTS),
            permission("document:read"),
            "d-42",
            ana.clone(),
            Caller::system(),
        )
        .await
        .expect("grant");
    assert!(first.created);
    let again = world
        .lists
        .grant(
            &world.tenant,
            namespace(DOCUMENTS),
            permission("document:read"),
            "d-42",
            ana.clone(),
            Caller::system(),
        )
        .await
        .expect("grant");
    assert!(!again.created);
    assert_eq!(again.entry, first.entry);
    let granted: Vec<String> = world
        .units
        .committed_event_types()
        .into_iter()
        .filter(|event| event.contains("access_entry"))
        .collect();
    assert_eq!(granted, ["authorization.access_entry_granted"]);

    let reading = request(DOCUMENTS, &ana, "document", Some("d-42"), "read");
    assert_eq!(
        world.answer(reading.clone(), &[]).await.effect,
        Effect::Allow
    );
    let id = first.entry.id();
    assert_eq!(
        world.lists.entry(&world.tenant, id).await.expect("entry"),
        Some(first.entry.clone())
    );
    assert!(
        world
            .lists
            .remove(&world.tenant, id, Caller::system())
            .await
            .expect("remove")
    );
    assert_eq!(world.answer(reading, &[]).await.effect, Effect::Deny);
    assert!(
        !world
            .lists
            .remove(&world.tenant, id, Caller::system())
            .await
            .expect("remove")
    );
    assert_eq!(
        world.lists.entry(&world.tenant, id).await.expect("entry"),
        None
    );
    assert_eq!(
        world
            .units
            .committed_event_types()
            .into_iter()
            .filter(|event| event.contains("access_entry"))
            .collect::<Vec<_>>(),
        [
            "authorization.access_entry_granted",
            "authorization.access_entry_removed"
        ]
    );
}

#[tokio::test]
async fn an_entry_names_a_declared_permission_of_a_tenant_resource_server() {
    let world = world();
    world.declare(DOCUMENTS, &["document:read"]).await;
    let ana = user("ana");
    let refused = |space: Namespace, granted: &str, resource: &str| {
        let lists = world.lists.clone();
        let tenant = world.tenant.clone();
        let (ana, granted, resource) = (ana.clone(), permission(granted), resource.to_owned());
        async move {
            lists
                .grant(&tenant, space, granted, &resource, ana, Caller::system())
                .await
                .expect_err("refused")
                .code()
                .to_owned()
        }
    };
    assert_eq!(
        refused(namespace(DOCUMENTS), "document:write", "d-42").await,
        "authorization.permission_not_declared"
    );
    assert_eq!(
        refused(namespace(DOCUMENTS), "document:read", "").await,
        "authorization.resource_invalid"
    );
    assert_eq!(
        refused(Namespace::administration(), "users:read", "d-42").await,
        "authorization.namespace_reserved"
    );
    assert!(
        world
            .units
            .committed_event_types()
            .iter()
            .all(|event| !event.contains("access_entry")),
        "nothing refused is announced"
    );

    // Removing the permission removes its entries.
    world.grant(DOCUMENTS, "document:read", "d-42", &ana).await;
    world
        .roles
        .remove_permission(
            &world.tenant,
            &namespace(DOCUMENTS),
            &permission("document:read"),
            Caller::system(),
        )
        .await
        .expect("remove permission");
    let listed = world
        .lists
        .entries(
            &world.tenant,
            &AccessEntryFilter::of(namespace(DOCUMENTS)),
            &PageRequest::default(),
        )
        .await
        .expect("entries");
    assert!(listed.items.is_empty());
}

#[tokio::test]
async fn an_entry_of_another_tenant_is_never_read() {
    let world = world();
    world.declare(DOCUMENTS, &["document:read"]).await;
    let ana = user("ana");
    let entry = world.grant(DOCUMENTS, "document:read", "d-42", &ana).await;
    let elsewhere = TenantContext::assume(TenantId::generate());
    let reading = request(DOCUMENTS, &ana, "document", Some("d-42"), "read");
    let answer = world.answer_in(&elsewhere, reading, &[]).await;
    assert_eq!(answer.effect, Effect::Deny);
    let id = entry.parse().expect("identifier");
    assert_eq!(
        world.lists.entry(&elsewhere, id).await.expect("entry"),
        None
    );
    assert!(
        !world
            .lists
            .remove(&elsewhere, id, Caller::system())
            .await
            .expect("remove")
    );
    assert!(
        world
            .lists
            .entries(
                &elsewhere,
                &AccessEntryFilter::of(namespace(DOCUMENTS)),
                &PageRequest::default()
            )
            .await
            .expect("entries")
            .items
            .is_empty()
    );
    assert!(
        world
            .lists
            .entry(&world.tenant, id)
            .await
            .expect("entry")
            .is_some(),
        "it is still where it belongs"
    );
}

#[tokio::test]
async fn a_simulation_says_which_entry_decided() {
    let world = world();
    world.declare(DOCUMENTS, &["document:read"]).await;
    let ana = user("ana");
    let entry = world.grant(DOCUMENTS, "document:read", "d-42", &ana).await;
    let simulated = world
        .engine
        .simulate(
            &world.tenant,
            &EvaluationInput {
                request: request(DOCUMENTS, &ana, "document", Some("d-42"), "read"),
                subject_attributes: Attributes::none(),
                time_limit: Duration::from_millis(200),
            },
            &PolicySelection::Published,
        )
        .await
        .expect("simulated");
    assert_eq!(simulated.answer.reason.as_str(), MATCHING_ENTRY);
    assert!(
        simulated.trace.iter().any(|step| step.contains(&entry)),
        "{:?}",
        simulated.trace
    );
}
