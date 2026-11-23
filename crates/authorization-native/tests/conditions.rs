//! Conditions in Common Expression Language through the whole evaluation:
//! `RoleService` refuses what cannot be used, and `EvaluationService` with
//! the native engine decides on the subject, the resource and the moment.

use hodor_authorization::api::{
    Action, AssignmentScope, Attributes, AuthorizationDecision, AuthorizationRequest,
    BindingSettings, Condition, Effect, EngineId, EngineRegistry, EvaluationContext,
    EvaluationService, Namespace, NativeEngine, PermissionName, Resource, RoleContents, RoleKey,
    RoleName, RoleService, Subject, SubjectKind, Validity,
};
use hodor_authorization::testing::{
    InMemoryEngineBindings, InMemoryNativeRoles, InMemoryRoleAssignments, StaticSubjectAttributes,
};
use hodor_authorization_native::CelConditionLanguage;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, Clock, TenantContext, TenantId, Timestamp};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

const DOCUMENTS: &str = "urn:example:documents";

/// Only from the documents of the subject's department, before 2025.
const SAME_DEPARTMENT_BEFORE_2025: &str = "has(resource.attributes.department)
  && resource.attributes.department == subject.attributes.department
  && context.time < '2025-01-01T00:00:00Z'";

struct World {
    roles: RoleService,
    evaluation: EvaluationService,
    subjects: StaticSubjectAttributes,
    clock: Arc<FixedClock>,
    tenant: TenantContext,
}

fn world() -> World {
    let units = InMemoryUnitOfWorkFactory::default();
    let assignments = InMemoryRoleAssignments::default();
    let store = InMemoryNativeRoles::default();
    // 2024-10-04.
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + time::Duration::days(20_000),
    ));
    let language = Arc::new(CelConditionLanguage::new());
    let engine = NativeEngine::new(
        Arc::new(units.clone()),
        Arc::new(assignments.clone()),
        Arc::new(store.clone()),
        clock.clone(),
    )
    .with_condition_language(language.clone());
    let mut registry = EngineRegistry::new();
    registry.register(Arc::new(engine)).expect("register");
    let subjects = StaticSubjectAttributes::default();
    World {
        roles: RoleService::new(Arc::new(units.clone()), Arc::new(store), clock.clone())
            .with_condition_language(language),
        evaluation: EvaluationService::new(
            Arc::new(units),
            Arc::new(assignments),
            Arc::new(InMemoryEngineBindings::default()),
            Arc::new(subjects.clone()),
            registry,
            clock.clone(),
        ),
        subjects,
        clock,
        tenant: TenantContext::assume(TenantId::generate()),
    }
}

fn namespace() -> Namespace {
    Namespace::parse(DOCUMENTS).expect("namespace")
}

fn key(name: &str) -> RoleKey {
    RoleKey::new(namespace(), RoleName::parse(name).expect("name"))
}

fn permission(value: &str) -> PermissionName {
    PermissionName::parse(value).expect("permission")
}

fn attributes(values: &[(&str, serde_json::Value)]) -> Attributes {
    Attributes::new(
        values
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone())),
    )
    .expect("attributes")
}

fn ana() -> Subject {
    Subject::new(SubjectKind::User, "ana").expect("user")
}

fn read(department: Option<&str>) -> AuthorizationRequest {
    let resource_attributes = department.map_or_else(Attributes::none, |department| {
        attributes(&[("department", serde_json::json!(department))])
    });
    AuthorizationRequest {
        namespace: namespace(),
        subject: ana(),
        asserted: Attributes::none(),
        resource: Resource::new("document", Some("d-1"), resource_attributes).expect("resource"),
        action: Action::parse("read").expect("action"),
        context: EvaluationContext::default(),
    }
}

fn reader(condition: &str) -> RoleContents {
    RoleContents {
        description: String::new(),
        permissions: BTreeSet::from([permission("document:read")]),
        includes: BTreeSet::new(),
        conditions: BTreeMap::from([(
            permission("document:read"),
            Condition::parse(condition).expect("condition"),
        )]),
    }
}

impl World {
    async fn bound(&self, settings: impl FnOnce(&mut BindingSettings)) {
        let mut binding = BindingSettings::new(namespace(), EngineId::native());
        settings(&mut binding);
        self.evaluation
            .bind(&self.tenant, binding, Caller::system())
            .await
            .expect("bind");
        self.roles
            .declare_permission(
                &self.tenant,
                namespace(),
                permission("document:read"),
                "",
                Caller::system(),
            )
            .await
            .expect("declare");
    }

    async fn reader_for_ana(&self, condition: &str) {
        self.roles
            .define_role(
                &self.tenant,
                key("reader"),
                reader(condition),
                Caller::system(),
            )
            .await
            .expect("define");
        self.roles
            .assign(
                &self.tenant,
                ana(),
                key("reader"),
                AssignmentScope::Tenant,
                Validity::default(),
                Caller::system(),
            )
            .await
            .expect("assign");
    }

    fn ana_works_in(&self, department: &str) {
        self.subjects.set(
            &self.tenant,
            &ana(),
            attributes(&[("department", serde_json::json!(department))]),
        );
    }

    async fn decide(&self, request: &AuthorizationRequest) -> AuthorizationDecision {
        self.evaluation.evaluate(&self.tenant, request).await
    }
}

#[tokio::test]
async fn the_subject_the_resource_and_the_moment_change_the_answer() {
    let world = world();
    world.bound(|_| {}).await;
    world.reader_for_ana(SAME_DEPARTMENT_BEFORE_2025).await;
    world.ana_works_in("sales");

    let allowed = world.decide(&read(Some("sales"))).await;
    assert!(allowed.permits(), "{allowed:?}");
    assert_eq!(allowed.reason.as_str(), "matching_role");

    // Another resource.
    let denied = world.decide(&read(Some("legal"))).await;
    assert_eq!(denied.effect, Effect::Deny);
    assert_eq!(denied.reason.as_str(), "condition_not_met");

    // Another subject's attributes.
    world.ana_works_in("legal");
    assert_eq!(
        world.decide(&read(Some("sales"))).await.effect,
        Effect::Deny
    );
    world.ana_works_in("sales");

    // Another moment.
    world.clock.advance(time::Duration::days(100));
    assert!(world.clock.now() > Timestamp::UNIX_EPOCH + time::Duration::days(20_090));
    assert_eq!(
        world.decide(&read(Some("sales"))).await.effect,
        Effect::Deny
    );
}

#[tokio::test]
async fn a_condition_that_cannot_be_used_is_refused_when_the_role_is_defined() {
    let world = world();
    world.bound(|_| {}).await;
    let deep = "subject.attributes.groups.all(a, subject.attributes.groups.all(b, \
                subject.attributes.groups.all(c, a == b && b == c)))";
    for (condition, code) in [
        (
            "resource.attributes.department ==",
            "authorization.condition_invalid",
        ),
        (
            "request.tenant == 'acme'",
            "authorization.condition_invalid",
        ),
        (deep, "authorization.condition_too_costly"),
    ] {
        let refused = world
            .roles
            .define_role(
                &world.tenant,
                key("reader"),
                reader(condition),
                Caller::system(),
            )
            .await;
        assert_eq!(
            refused.map(|_| ()).map_err(|e| e.code().to_owned()),
            Err(code.to_owned()),
            "{condition}"
        );
    }
    assert!(
        world
            .roles
            .roles(&world.tenant)
            .await
            .expect("roles")
            .is_empty()
    );
}

#[tokio::test]
async fn a_condition_that_fails_never_allows() {
    let world = world();
    world.bound(|_| {}).await;
    // Unguarded: a resource without a department makes it fail.
    world
        .reader_for_ana("resource.attributes.department == subject.attributes.department")
        .await;
    world.ana_works_in("sales");
    let decision = world.decide(&read(None)).await;
    assert_eq!(decision.effect, Effect::Indeterminate);
    assert_eq!(decision.reason.as_str(), "condition_failed");
    assert!(!decision.permits());
}

#[tokio::test]
async fn a_failing_condition_allows_only_where_the_binding_fails_open() {
    let world = world();
    world
        .bound(|binding| {
            binding.fail_open_actions = BTreeSet::from([Action::parse("read").expect("action")]);
        })
        .await;
    world
        .reader_for_ana("resource.attributes.department == subject.attributes.department")
        .await;
    world.ana_works_in("sales");
    let decision = world.decide(&read(None)).await;
    assert!(decision.permits());
    assert_eq!(decision.reason.as_str(), "fail_open");
}

#[tokio::test]
async fn asserted_attributes_count_only_when_the_binding_trusts_them() {
    let condition = "has(subject.asserted.clearance) && subject.asserted.clearance == 'secret'";
    let claiming = || {
        let mut request = read(Some("sales"));
        request.asserted = attributes(&[("clearance", serde_json::json!("secret"))]);
        request
    };

    let wary = world();
    wary.bound(|_| {}).await;
    wary.reader_for_ana(condition).await;
    let untrusted = wary.decide(&claiming()).await;
    assert_eq!(untrusted.effect, Effect::Deny);
    assert_eq!(untrusted.reason.as_str(), "condition_not_met");

    let trusting = world();
    trusting
        .bound(|binding| binding.trust_asserted = true)
        .await;
    trusting.reader_for_ana(condition).await;
    assert!(trusting.decide(&claiming()).await.permits());
}

#[tokio::test]
async fn a_tenant_s_conditions_answer_only_in_that_tenant() {
    let world = world();
    world.bound(|_| {}).await;
    world.reader_for_ana("true").await;
    assert!(world.decide(&read(Some("sales"))).await.permits());
    let elsewhere = TenantContext::assume(TenantId::generate());
    let decision = world
        .evaluation
        .evaluate(&elsewhere, &read(Some("sales")))
        .await;
    assert_eq!(decision.effect, Effect::Deny);
    assert_eq!(decision.reason.as_str(), "no_engine_bound");
}
