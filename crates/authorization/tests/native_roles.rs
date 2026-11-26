//! Native role-based access control: the use cases and the native engine,
//! against the in-memory stores.

use hodor_authorization::api::{
    Action, ApplicationReference, AssignmentScope, Attributes, AuthorizationEngine,
    AuthorizationRequest, AuthorizationService, BindingSettings, Effect, EngineId, EngineRegistry,
    EvaluationContext, EvaluationInput, EvaluationService, MATCHING_ROLE, Namespace, NativeEngine,
    OrganizationReference, Permission, PermissionName, PolicyRevision, PolicySelection,
    PolicySimulator, Resource, Role, RoleContents, RoleKey, RoleName, RoleService, Subject,
    SubjectKind, Validity,
};
use hodor_authorization::testing::{
    InMemoryEngineBindings, InMemoryNativeRoles, InMemoryRoleAssignments, NativeRolePorts,
    StaticSubjectAttributes, run_native_role_contract,
};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, Clock, TenantContext, TenantId, Timestamp, UserId};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

const DOCUMENTS: &str = "urn:example:documents";
const BILLING: &str = "https://billing.example.com";

struct World {
    roles: RoleService,
    engine: NativeEngine,
    evaluation: EvaluationService,
    administration: AuthorizationService,
    units: InMemoryUnitOfWorkFactory,
    clock: Arc<FixedClock>,
    tenant: TenantContext,
}

fn world() -> World {
    let units = InMemoryUnitOfWorkFactory::default();
    let assignments = InMemoryRoleAssignments::default();
    let store = InMemoryNativeRoles::default();
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + time::Duration::days(20_000),
    ));
    let engine = NativeEngine::new(
        Arc::new(units.clone()),
        Arc::new(assignments.clone()),
        Arc::new(store.clone()),
        clock.clone(),
    );
    let mut registry = EngineRegistry::new();
    registry
        .register(Arc::new(engine.clone()))
        .expect("register");
    World {
        roles: RoleService::new(Arc::new(units.clone()), Arc::new(store), clock.clone()),
        evaluation: EvaluationService::new(
            Arc::new(units.clone()),
            Arc::new(assignments.clone()),
            Arc::new(InMemoryEngineBindings::default()),
            Arc::new(StaticSubjectAttributes::default()),
            registry,
            clock.clone(),
        ),
        administration: AuthorizationService::new(
            Arc::new(units.clone()),
            Arc::new(assignments),
            clock.clone(),
        ),
        engine,
        units,
        clock,
        tenant: TenantContext::assume(TenantId::generate()),
    }
}

fn namespace(value: &str) -> Namespace {
    Namespace::parse(value).expect("namespace")
}

fn key(space: &str, name: &str) -> RoleKey {
    RoleKey::new(namespace(space), RoleName::parse(name).expect("name"))
}

fn permission(value: &str) -> PermissionName {
    PermissionName::parse(value).expect("permission")
}

fn contents(permissions: &[&str], includes: &[RoleKey]) -> RoleContents {
    RoleContents {
        description: String::new(),
        permissions: permissions.iter().map(|p| permission(p)).collect(),
        includes: includes.iter().cloned().collect(),
        conditions: std::collections::BTreeMap::new(),
    }
}

fn user(name: &str) -> Subject {
    Subject::new(SubjectKind::User, name).expect("user")
}

fn request(space: &str, subject: &Subject, kind: &str, action: &str) -> AuthorizationRequest {
    AuthorizationRequest {
        namespace: namespace(space),
        subject: subject.clone(),
        asserted: Attributes::none(),
        resource: Resource::new(kind, None, Attributes::none()).expect("resource"),
        action: Action::parse(action).expect("action"),
        context: EvaluationContext::default(),
    }
}

fn for_application(mut request: AuthorizationRequest, application: &str) -> AuthorizationRequest {
    request.context.application =
        Some(ApplicationReference::parse(application).expect("application"));
    request
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

    async fn define(&self, role: RoleKey, permissions: &[&str], includes: &[RoleKey]) {
        self.roles
            .define_role(
                &self.tenant,
                role,
                contents(permissions, includes),
                Caller::system(),
            )
            .await
            .expect("define");
    }

    async fn assign(&self, subject: &Subject, role: RoleKey, scope: AssignmentScope) {
        self.roles
            .assign(
                &self.tenant,
                subject.clone(),
                role,
                scope,
                Validity::default(),
                Caller::system(),
            )
            .await
            .expect("assign");
    }

    async fn answer(
        &self,
        request: AuthorizationRequest,
    ) -> hodor_authorization::api::EngineAnswer {
        self.engine
            .evaluate(
                &self.tenant,
                &EvaluationInput {
                    request,
                    subject_attributes: Attributes::none(),
                    time_limit: Duration::from_millis(200),
                },
            )
            .await
            .expect("answer")
    }

    async fn allows(&self, request: AuthorizationRequest) -> bool {
        self.answer(request).await.effect == Effect::Allow
    }

    fn events(&self) -> Vec<String> {
        self.units.committed_event_types()
    }

    /// The documents server: `viewer` reads, `editor` writes and includes
    /// `viewer`.
    async fn documents(&self) {
        self.declare(DOCUMENTS, &["document:read", "document:write"])
            .await;
        self.define(key(DOCUMENTS, "viewer"), &["document:read"], &[])
            .await;
        self.define(
            key(DOCUMENTS, "editor"),
            &["document:write"],
            &[key(DOCUMENTS, "viewer")],
        )
        .await;
    }
}

#[tokio::test]
async fn the_in_memory_store_passes_the_contract() {
    let units = InMemoryUnitOfWorkFactory::default();
    let roles = InMemoryNativeRoles::default();
    run_native_role_contract(NativeRolePorts {
        units_of_work: &units,
        roles: &roles,
    })
    .await;
}

#[tokio::test]
async fn a_role_allows_what_it_holds_and_what_it_includes() {
    let world = world();
    world.documents().await;
    let ana = user("ana");
    world
        .assign(&ana, key(DOCUMENTS, "editor"), AssignmentScope::Tenant)
        .await;

    let write = world
        .answer(request(DOCUMENTS, &ana, "document", "write"))
        .await;
    assert_eq!(write.effect, Effect::Allow);
    assert_eq!(write.reason.as_str(), MATCHING_ROLE);
    let named: Vec<&str> = write
        .matched_policies
        .iter()
        .map(|policy| policy.as_str())
        .collect();
    assert_eq!(named, ["urn:example:documents#editor"]);
    // Inherited from the role it includes.
    assert!(
        world
            .allows(request(DOCUMENTS, &ana, "document", "read"))
            .await
    );
    // Neither an undeclared permission nor another person.
    let delete = world
        .answer(request(DOCUMENTS, &ana, "document", "delete"))
        .await;
    assert_eq!(delete.effect, Effect::Deny);
    assert_eq!(delete.reason.as_str(), "no_matching_role");
    assert!(delete.matched_policies.is_empty());
    assert!(
        !world
            .allows(request(DOCUMENTS, &user("bia"), "document", "read"))
            .await
    );
}

#[tokio::test]
async fn a_composite_role_holds_roles_of_several_resource_servers() {
    let world = world();
    world.documents().await;
    world.declare(BILLING, &["invoice:pay"]).await;
    world
        .define(key(BILLING, "payer"), &["invoice:pay"], &[])
        .await;
    world
        .define(
            key(BILLING, "support"),
            &[],
            &[key(DOCUMENTS, "viewer"), key(BILLING, "payer")],
        )
        .await;
    let client = Subject::new(SubjectKind::Client, "support-desk").expect("client");
    world
        .assign(&client, key(BILLING, "support"), AssignmentScope::Tenant)
        .await;

    assert!(
        world
            .allows(request(BILLING, &client, "invoice", "pay"))
            .await
    );
    let read = world
        .answer(request(DOCUMENTS, &client, "document", "read"))
        .await;
    assert_eq!(read.effect, Effect::Allow);
    assert_eq!(
        read.matched_policies[0].as_str(),
        "https://billing.example.com#support"
    );
    assert!(
        !world
            .allows(request(DOCUMENTS, &client, "document", "write"))
            .await
    );
    // A permission of one server is not one of another, whatever its name.
    world.declare(BILLING, &["document:read"]).await;
    world
        .define(key(BILLING, "reader"), &["document:read"], &[])
        .await;
    let bia = user("bia");
    world
        .assign(&bia, key(BILLING, "reader"), AssignmentScope::Tenant)
        .await;
    assert!(
        !world
            .allows(request(DOCUMENTS, &bia, "document", "read"))
            .await
    );
    assert!(
        world
            .allows(request(BILLING, &bia, "document", "read"))
            .await
    );
}

#[tokio::test]
async fn a_cycle_is_refused_however_it_is_made() {
    let world = world();
    world.documents().await;
    world
        .define(key(DOCUMENTS, "owner"), &[], &[key(DOCUMENTS, "editor")])
        .await;
    world
        .define(key(BILLING, "support"), &[], &[key(DOCUMENTS, "owner")])
        .await;
    let refused = |result: Result<_, hodor_kernel::DomainError>| {
        result.map(|_| ()).map_err(|e| e.code().to_owned())
    };
    // viewer -> owner -> editor -> viewer.
    let looping = world
        .roles
        .define_role(
            &world.tenant,
            key(DOCUMENTS, "viewer"),
            contents(&["document:read"], &[key(DOCUMENTS, "owner")]),
            Caller::system(),
        )
        .await;
    assert_eq!(refused(looping), Err("authorization.role_cycle".to_owned()));
    // viewer -> support (another server) -> owner -> editor -> viewer.
    let through_composite = world
        .roles
        .define_role(
            &world.tenant,
            key(DOCUMENTS, "viewer"),
            contents(&["document:read"], &[key(BILLING, "support")]),
            Caller::system(),
        )
        .await;
    assert_eq!(
        refused(through_composite),
        Err("authorization.role_cycle".to_owned())
    );
    // Directly.
    let itself = world
        .roles
        .define_role(
            &world.tenant,
            key(DOCUMENTS, "editor"),
            contents(&[], &[key(DOCUMENTS, "editor")]),
            Caller::system(),
        )
        .await;
    assert_eq!(refused(itself), Err("authorization.role_cycle".to_owned()));
    // Nothing changed: the viewer still includes nothing.
    let viewer = world
        .roles
        .role(&world.tenant, &key(DOCUMENTS, "viewer"))
        .await
        .expect("role")
        .expect("exists");
    assert!(viewer.contents().includes.is_empty());
}

#[tokio::test]
async fn a_role_holds_only_declared_permissions_and_includes_only_roles_that_exist() {
    let world = world();
    world.documents().await;
    let undeclared = world
        .roles
        .define_role(
            &world.tenant,
            key(DOCUMENTS, "deleter"),
            contents(&["document:delete"], &[]),
            Caller::system(),
        )
        .await;
    assert_eq!(
        undeclared.map(|_| ()).map_err(|e| e.code().to_owned()),
        Err("authorization.permission_not_declared".to_owned())
    );
    // A permission of another server is not declared for this one.
    world.declare(BILLING, &["invoice:pay"]).await;
    let elsewhere = world
        .roles
        .define_role(
            &world.tenant,
            key(DOCUMENTS, "payer"),
            contents(&["invoice:pay"], &[]),
            Caller::system(),
        )
        .await;
    assert!(elsewhere.is_err());
    let dangling = world
        .roles
        .define_role(
            &world.tenant,
            key(DOCUMENTS, "composite"),
            contents(&[], &[key(DOCUMENTS, "missing")]),
            Caller::system(),
        )
        .await;
    assert_eq!(
        dangling.map(|_| ()).map_err(|e| e.code().to_owned()),
        Err("authorization.role_not_found".to_owned())
    );
    let nobody = world
        .roles
        .assign(
            &world.tenant,
            user("ana"),
            key(DOCUMENTS, "missing"),
            AssignmentScope::Tenant,
            Validity::default(),
            Caller::system(),
        )
        .await;
    assert_eq!(
        nobody.map(|_| ()).map_err(|e| e.code().to_owned()),
        Err("authorization.role_not_found".to_owned())
    );
}

#[tokio::test]
async fn a_revoked_assignment_stops_allowing_on_the_next_decision() {
    let world = world();
    world.documents().await;
    let ana = user("ana");
    world
        .assign(&ana, key(DOCUMENTS, "editor"), AssignmentScope::Tenant)
        .await;
    // Twice, so the second answer comes from what the engine keeps.
    assert!(
        world
            .allows(request(DOCUMENTS, &ana, "document", "read"))
            .await
    );
    assert!(
        world
            .allows(request(DOCUMENTS, &ana, "document", "read"))
            .await
    );

    assert!(
        world
            .roles
            .revoke(
                &world.tenant,
                &ana,
                &key(DOCUMENTS, "editor"),
                &AssignmentScope::Tenant,
                Caller::system(),
            )
            .await
            .expect("revoke")
    );
    assert!(
        !world
            .allows(request(DOCUMENTS, &ana, "document", "read"))
            .await
    );

    // A change to a role also takes effect at once: the viewer stops
    // reading when its permission goes.
    world
        .assign(&ana, key(DOCUMENTS, "viewer"), AssignmentScope::Tenant)
        .await;
    assert!(
        world
            .allows(request(DOCUMENTS, &ana, "document", "read"))
            .await
    );
    world.define(key(DOCUMENTS, "viewer"), &[], &[]).await;
    assert!(
        !world
            .allows(request(DOCUMENTS, &ana, "document", "read"))
            .await
    );
    world
        .define(key(DOCUMENTS, "viewer"), &["document:read"], &[])
        .await;
    assert!(
        world
            .allows(request(DOCUMENTS, &ana, "document", "read"))
            .await
    );
    assert!(
        world
            .roles
            .remove_permission(
                &world.tenant,
                &namespace(DOCUMENTS),
                &permission("document:read"),
                Caller::system(),
            )
            .await
            .expect("remove")
    );
    assert!(
        !world
            .allows(request(DOCUMENTS, &ana, "document", "read"))
            .await
    );
}

#[tokio::test]
async fn an_assignment_applies_in_its_scope_and_its_time() {
    let world = world();
    world.documents().await;
    let ana = user("ana");
    world
        .assign(
            &ana,
            key(DOCUMENTS, "viewer"),
            AssignmentScope::Application(ApplicationReference::parse("portal").expect("app")),
        )
        .await;
    let read = request(DOCUMENTS, &ana, "document", "read");
    assert!(world.allows(for_application(read.clone(), "portal")).await);
    assert!(
        !world
            .allows(for_application(read.clone(), "intranet"))
            .await
    );
    assert!(!world.allows(read.clone()).await);

    let now = world.clock.now();
    let bia = user("bia");
    world
        .roles
        .assign(
            &world.tenant,
            bia.clone(),
            key(DOCUMENTS, "viewer"),
            AssignmentScope::Tenant,
            Validity {
                from: Some(now + time::Duration::hours(1)),
                until: Some(now + time::Duration::hours(2)),
            },
            Caller::system(),
        )
        .await
        .expect("assign");
    let read = request(DOCUMENTS, &bia, "document", "read");
    assert!(!world.allows(read.clone()).await, "before the start");
    world.clock.advance(time::Duration::hours(1));
    assert!(world.allows(read.clone()).await, "from the start");
    world.clock.advance(time::Duration::hours(1));
    assert!(!world.allows(read).await, "at the end");

    let backwards = world
        .roles
        .assign(
            &world.tenant,
            bia,
            key(DOCUMENTS, "viewer"),
            AssignmentScope::Tenant,
            Validity {
                from: Some(now),
                until: Some(now),
            },
            Caller::system(),
        )
        .await;
    assert_eq!(
        backwards.map(|_| ()).map_err(|e| e.code().to_owned()),
        Err("authorization.validity_invalid".to_owned())
    );
}

#[tokio::test]
async fn repeating_a_change_announces_nothing_and_removing_follows_the_rules() {
    let world = world();
    world.documents().await;
    let ana = user("ana");
    world
        .assign(&ana, key(DOCUMENTS, "editor"), AssignmentScope::Tenant)
        .await;
    let before = world.events();
    assert_eq!(
        before,
        [
            "authorization.permission_declared",
            "authorization.permission_declared",
            "authorization.role_defined",
            "authorization.role_defined",
            "authorization.principal_role_assigned",
        ]
    );
    // The same again changes nothing.
    world.declare(DOCUMENTS, &["document:read"]).await;
    world
        .define(key(DOCUMENTS, "viewer"), &["document:read"], &[])
        .await;
    world
        .assign(&ana, key(DOCUMENTS, "editor"), AssignmentScope::Tenant)
        .await;
    assert_eq!(world.events(), before);

    // A role another role includes stays; removing a role removes its
    // assignments.
    let refused = world
        .roles
        .remove_role(&world.tenant, &key(DOCUMENTS, "viewer"), Caller::system())
        .await;
    assert_eq!(
        refused.map_err(|e| e.code().to_owned()),
        Err("authorization.role_in_use".to_owned())
    );
    assert!(
        world
            .roles
            .remove_role(&world.tenant, &key(DOCUMENTS, "editor"), Caller::system())
            .await
            .expect("remove")
    );
    assert!(
        world
            .roles
            .assignments_of(&world.tenant, &ana)
            .await
            .expect("assignments")
            .is_empty()
    );
    assert!(
        !world
            .allows(request(DOCUMENTS, &ana, "document", "write"))
            .await
    );
    assert!(
        !world
            .roles
            .revoke(
                &world.tenant,
                &ana,
                &key(DOCUMENTS, "editor"),
                &AssignmentScope::Tenant,
                Caller::system(),
            )
            .await
            .expect("revoke")
    );
    let tail: Vec<String> = world.events().into_iter().skip(before.len()).collect();
    assert_eq!(tail, ["authorization.role_removed"]);
}

#[tokio::test]
async fn nothing_reaches_the_administration() {
    let world = world();
    let admin = Namespace::administration();
    let declare = world
        .roles
        .declare_permission(
            &world.tenant,
            admin.clone(),
            permission("users:delete"),
            "",
            Caller::system(),
        )
        .await;
    assert_eq!(
        declare.map(|_| ()).map_err(|e| e.code().to_owned()),
        Err("authorization.namespace_reserved".to_owned())
    );
    world.documents().await;
    let sneaky = world
        .roles
        .define_role(
            &world.tenant,
            key(DOCUMENTS, "sneaky"),
            contents(&[], &[RoleKey::built_in(Role::TenantAdministrator)]),
            Caller::system(),
        )
        .await;
    assert_eq!(
        sneaky.map(|_| ()).map_err(|e| e.code().to_owned()),
        Err("authorization.namespace_reserved".to_owned())
    );
    let ana = UserId::generate();
    let assign = world
        .roles
        .assign(
            &world.tenant,
            Subject::user(ana),
            RoleKey::built_in(Role::TenantAuditor),
            AssignmentScope::Tenant,
            Validity::default(),
            Caller::system(),
        )
        .await;
    assert!(assign.is_err());
    // A tenant role holds no administration permission, whatever it is called.
    world.declare(DOCUMENTS, &["users:read"]).await;
    world
        .define(key(DOCUMENTS, "users"), &["users:read"], &[])
        .await;
    world
        .assign(
            &Subject::user(ana),
            key(DOCUMENTS, "users"),
            AssignmentScope::Tenant,
        )
        .await;
    assert!(
        !world
            .administration
            .check(&world.tenant, ana, Permission::UsersRead)
            .await
            .expect("check")
            .is_allowed()
    );
    assert!(
        !world
            .allows(request(
                Namespace::ADMINISTRATION,
                &Subject::user(ana),
                "users",
                "read"
            ))
            .await
    );
}

#[tokio::test]
async fn the_built_in_roles_answer_the_administration_as_the_check_does() {
    let world = world();
    for held in [
        &[][..],
        &[Role::TenantAuditor][..],
        &[Role::TenantAdministrator][..],
        &[Role::TenantAuditor, Role::TenantAdministrator][..],
    ] {
        let person = UserId::generate();
        for role in held {
            world
                .administration
                .assign(&world.tenant, person, *role, Caller::system())
                .await
                .expect("assign");
        }
        for wanted in Permission::ALL {
            let (kind, action) = wanted.as_str().split_once(':').expect("permission");
            let check = world
                .administration
                .check(&world.tenant, person, wanted)
                .await
                .expect("check");
            let answer = world
                .answer(request(
                    Namespace::ADMINISTRATION,
                    &Subject::user(person),
                    kind,
                    action,
                ))
                .await;
            assert_eq!(answer.effect, check.effect, "{}", wanted.as_str());
            assert_eq!(answer.reason.as_str(), check.reason, "{}", wanted.as_str());
            assert_eq!(
                answer.policy_version.as_ref().map(|v| v.as_str()),
                Some("fixed_roles")
            );
        }
    }
}

#[tokio::test]
async fn the_native_engine_answers_through_its_binding() {
    let world = world();
    world.documents().await;
    let ana = user("ana");
    world
        .assign(&ana, key(DOCUMENTS, "viewer"), AssignmentScope::Tenant)
        .await;
    // Unbound: denied, whatever the roles say.
    let unbound = world
        .evaluation
        .evaluate(&world.tenant, &request(DOCUMENTS, &ana, "document", "read"))
        .await;
    assert_eq!(unbound.effect, Effect::Deny);
    assert_eq!(unbound.reason.as_str(), "no_engine_bound");

    world
        .evaluation
        .bind(
            &world.tenant,
            BindingSettings::new(namespace(DOCUMENTS), EngineId::native()),
            Caller::system(),
        )
        .await
        .expect("bind");
    let read = world
        .evaluation
        .evaluate(&world.tenant, &request(DOCUMENTS, &ana, "document", "read"))
        .await;
    assert!(read.permits());
    assert_eq!(read.engine.as_ref().map(|e| e.as_str()), Some("native"));
    let write = world
        .evaluation
        .evaluate(
            &world.tenant,
            &request(DOCUMENTS, &ana, "document", "write"),
        )
        .await;
    assert_eq!(write.effect, Effect::Deny);
}

#[tokio::test]
async fn roles_belong_to_their_tenant() {
    let world = world();
    world.documents().await;
    let ana = user("ana");
    world
        .assign(&ana, key(DOCUMENTS, "editor"), AssignmentScope::Tenant)
        .await;
    let elsewhere = TenantContext::assume(TenantId::generate());
    let input = EvaluationInput {
        request: request(DOCUMENTS, &ana, "document", "read"),
        subject_attributes: Attributes::none(),
        time_limit: Duration::from_millis(200),
    };
    let answer = world
        .engine
        .evaluate(&elsewhere, &input)
        .await
        .expect("answer");
    assert_eq!(answer.effect, Effect::Deny);
    assert!(
        world
            .roles
            .roles(&elsewhere)
            .await
            .expect("roles")
            .is_empty()
    );
    assert!(
        world
            .roles
            .assignments_of(&elsewhere, &ana)
            .await
            .expect("assignments")
            .is_empty()
    );
    // The same role can be defined in another tenant, apart.
    let removed = world
        .roles
        .remove_role(&elsewhere, &key(DOCUMENTS, "editor"), Caller::system())
        .await
        .expect("remove");
    assert!(!removed);
    let held: BTreeSet<_> = world
        .roles
        .roles(&world.tenant)
        .await
        .expect("roles")
        .iter()
        .map(|role| role.key().reference())
        .collect();
    assert_eq!(held.len(), 2);
}

#[tokio::test]
async fn an_administration_only_engine_answers_nothing_else() {
    let world = world();
    let only = NativeEngine::administration(
        Arc::new(world.units.clone()),
        Arc::new(InMemoryRoleAssignments::default()),
    );
    let input = EvaluationInput {
        request: request(DOCUMENTS, &user("ana"), "document", "read"),
        subject_attributes: Attributes::none(),
        time_limit: Duration::from_millis(200),
    };
    assert!(only.evaluate(&world.tenant, &input).await.is_err());
}

#[tokio::test]
async fn the_native_engine_simulates_against_what_is_published_only() {
    let world = world();
    world.documents().await;
    let ana = user("ana");
    world
        .assign(&ana, key(DOCUMENTS, "viewer"), AssignmentScope::Tenant)
        .await;
    let input = EvaluationInput {
        request: request(DOCUMENTS, &ana, "document", "read"),
        subject_attributes: Attributes::none(),
        time_limit: Duration::from_millis(200),
    };
    let simulated = world
        .engine
        .simulate(&world.tenant, &input, &PolicySelection::Published)
        .await
        .expect("simulated");
    assert_eq!(simulated.answer.effect, Effect::Allow);
    assert_eq!(simulated.answer.reason.as_str(), MATCHING_ROLE);
    assert!(
        simulated.trace.iter().any(|step| step.contains("viewer")),
        "{:?}",
        simulated.trace
    );
    assert!(
        simulated
            .trace
            .last()
            .is_some_and(|step| step.contains("allow")),
        "{:?}",
        simulated.trace
    );

    let revision = PolicySelection::Revision(PolicyRevision::parse("rev-1").expect("revision"));
    let refused = world
        .engine
        .simulate(&world.tenant, &input, &revision)
        .await
        .expect_err("no revisions");
    assert_eq!(refused.code(), "authorization.simulation_unsupported");
    // A simulation is not an event.
    assert!(
        !world.events().iter().any(|event| event.contains("simulat")),
        "{:?}",
        world.events()
    );
}

impl World {
    /// The answer for a subject Hodor resolved with `attributes`.
    async fn answer_with(
        &self,
        request: AuthorizationRequest,
        attributes: &[(&str, serde_json::Value)],
    ) -> hodor_authorization::api::EngineAnswer {
        let attributes = Attributes::new(
            attributes
                .iter()
                .map(|(name, value)| ((*name).to_owned(), value.clone())),
        )
        .expect("attributes");
        self.engine
            .evaluate(
                &self.tenant,
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

fn in_organization(mut request: AuthorizationRequest, organization: &str) -> AuthorizationRequest {
    request.context.organization = Some(
        hodor_authorization::api::OrganizationReference::parse(organization).expect("organization"),
    );
    request
}

#[tokio::test]
async fn a_role_given_to_a_group_is_held_by_the_users_in_it() {
    let world = world();
    world.documents().await;
    let finance = Subject::new(SubjectKind::Group, "finance-group").expect("group");
    world
        .assign(&finance, key(DOCUMENTS, "editor"), AssignmentScope::Tenant)
        .await;
    let ana = user("ana");
    let reading = request(DOCUMENTS, &ana, "document", "read");

    let member = world
        .answer_with(
            reading.clone(),
            &[("groups", serde_json::json!(["finance-group"]))],
        )
        .await;
    assert_eq!(
        member.effect,
        Effect::Allow,
        "through the group, and the role it includes"
    );
    assert_eq!(member.matched_policies.len(), 1);
    let outside = world
        .answer_with(reading.clone(), &[("groups", serde_json::json!([]))])
        .await;
    assert_eq!(
        outside.effect,
        Effect::Deny,
        "taken out of the group: nothing through it"
    );
    let nothing = world.answer_with(reading, &[]).await;
    assert_eq!(nothing.effect, Effect::Deny);

    // A client is not in groups, whatever its attributes say.
    let client = Subject::new(SubjectKind::Client, "billing").expect("client");
    let asking = request(DOCUMENTS, &client, "document", "read");
    let answer = world
        .answer_with(asking, &[("groups", serde_json::json!(["finance-group"]))])
        .await;
    assert_eq!(answer.effect, Effect::Deny);
}

#[tokio::test]
async fn a_role_scoped_to_an_organization_counts_for_its_members_in_it() {
    let world = world();
    world.documents().await;
    let ana = user("ana");
    let acme =
        hodor_authorization::api::OrganizationReference::parse("acme").expect("organization");
    world
        .assign(
            &ana,
            key(DOCUMENTS, "viewer"),
            AssignmentScope::Organization(acme),
        )
        .await;
    let reading = request(DOCUMENTS, &ana, "document", "read");
    let member = [("organizations", serde_json::json!(["acme"]))];

    let inside = world
        .answer_with(in_organization(reading.clone(), "acme"), &member)
        .await;
    assert_eq!(inside.effect, Effect::Allow);
    let elsewhere = world
        .answer_with(in_organization(reading.clone(), "globex"), &member)
        .await;
    assert_eq!(elsewhere.effect, Effect::Deny, "another organization");
    let unnamed = world.answer_with(reading.clone(), &member).await;
    assert_eq!(
        unnamed.effect,
        Effect::Deny,
        "a request that names no organization"
    );
    let left = world
        .answer_with(
            in_organization(reading, "acme"),
            &[("organizations", serde_json::json!([]))],
        )
        .await;
    assert_eq!(
        left.effect,
        Effect::Deny,
        "a person who left the organization"
    );
}

#[tokio::test]
async fn the_assignments_on_a_resource_server_are_those_that_could_allow_there() {
    let world = world();
    world.documents().await;
    world.declare(BILLING, &["invoice:read"]).await;
    world
        .define(key(BILLING, "reader"), &["invoice:read"], &[])
        .await;
    let support = "urn:example:support";
    world
        .define(key(support, "support"), &[], &[key(DOCUMENTS, "viewer")])
        .await;
    world.define(key(support, "lonely"), &[], &[]).await;
    let portal = ApplicationReference::parse("portal").expect("application");
    let intranet = ApplicationReference::parse("intranet").expect("application");
    let north = OrganizationReference::parse("north").expect("organization");
    let south = OrganizationReference::parse("south").expect("organization");
    let held = |principals: Vec<Subject>, organizations: Vec<OrganizationReference>| {
        let world = &world;
        let portal = portal.clone();
        async move {
            world
                .roles
                .assignments_on(
                    &world.tenant,
                    &principals,
                    &namespace(DOCUMENTS),
                    &portal,
                    &organizations,
                )
                .await
                .expect("assignments")
                .iter()
                .map(|assignment| assignment.role().reference())
                .collect::<Vec<_>>()
        }
    };

    // A role of the resource server, for the tenant or this application,
    // and a role of another one that includes one of its roles.
    let ana = user("ana");
    world
        .assign(&ana, key(DOCUMENTS, "viewer"), AssignmentScope::Tenant)
        .await;
    let bia = user("bia");
    world
        .assign(
            &bia,
            key(DOCUMENTS, "editor"),
            AssignmentScope::Application(portal.clone()),
        )
        .await;
    let caio = user("caio");
    world
        .assign(&caio, key(support, "support"), AssignmentScope::Tenant)
        .await;
    assert_eq!(
        held(vec![ana], vec![]).await,
        [format!("{DOCUMENTS}#viewer")]
    );
    assert_eq!(
        held(vec![bia], vec![]).await,
        [format!("{DOCUMENTS}#editor")]
    );
    assert_eq!(
        held(vec![caio], vec![]).await,
        [format!("{support}#support")]
    );

    // A role of another resource server, a role that includes nothing of
    // this one, and a role for another application count for nothing.
    let dani = user("dani");
    world
        .assign(&dani, key(BILLING, "reader"), AssignmentScope::Tenant)
        .await;
    world
        .assign(&dani, key(support, "lonely"), AssignmentScope::Tenant)
        .await;
    world
        .assign(
            &dani,
            key(DOCUMENTS, "viewer"),
            AssignmentScope::Application(intranet),
        )
        .await;
    assert!(held(vec![dani.clone()], vec![]).await.is_empty());

    // For an organization, only when the principal is a member of it.
    world
        .assign(
            &dani,
            key(DOCUMENTS, "viewer"),
            AssignmentScope::Organization(north.clone()),
        )
        .await;
    assert!(held(vec![dani.clone()], vec![south]).await.is_empty());
    assert_eq!(
        held(vec![dani], vec![north]).await,
        [format!("{DOCUMENTS}#viewer")]
    );

    // Through a group the principal is in.
    let readers = Subject::new(SubjectKind::Group, "readers").expect("group");
    world
        .assign(&readers, key(DOCUMENTS, "viewer"), AssignmentScope::Tenant)
        .await;
    let eva = user("eva");
    assert!(held(vec![eva.clone()], vec![]).await.is_empty());
    assert_eq!(
        held(vec![eva, readers], vec![]).await,
        [format!("{DOCUMENTS}#viewer")]
    );

    // Only while it is in force.
    let now = world.clock.now();
    let fabio = user("fabio");
    world
        .roles
        .assign(
            &world.tenant,
            fabio.clone(),
            key(DOCUMENTS, "viewer"),
            AssignmentScope::Tenant,
            Validity {
                from: Some(now + time::Duration::hours(1)),
                until: Some(now + time::Duration::hours(2)),
            },
            Caller::system(),
        )
        .await
        .expect("assign");
    assert!(held(vec![fabio.clone()], vec![]).await.is_empty(), "before");
    world.clock.advance(time::Duration::hours(1));
    assert_eq!(held(vec![fabio.clone()], vec![]).await.len(), 1, "from");
    world.clock.advance(time::Duration::hours(1));
    assert!(held(vec![fabio], vec![]).await.is_empty(), "at the end");
}
