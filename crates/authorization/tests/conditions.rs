//! Conditions in the native engine and in `RoleService`, with the stand-in
//! condition language: how conditions are checked when a role is defined,
//! and how the engine decides with them.

use hodor_authorization::api::{
    Action, AssignmentScope, Attributes, AuthorizationEngine, AuthorizationRequest,
    CONDITION_FAILED, CONDITION_NOT_MET, Condition, Effect, EngineAnswer, EvaluationContext,
    EvaluationInput, MATCHING_ROLE, MAX_CONDITIONS_PER_DECISION, Namespace, NativeEngine,
    PermissionName, Resource, RoleContents, RoleKey, RoleName, RoleService, Subject, SubjectKind,
    Validity,
};
use hodor_authorization::testing::{
    FakeConditionLanguage, InMemoryNativeRoles, InMemoryRoleAssignments,
};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, DomainError, TenantContext, TenantId, Timestamp};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

const DOCUMENTS: &str = "urn:example:documents";

struct World {
    roles: RoleService,
    engine: NativeEngine,
    language: FakeConditionLanguage,
    tenant: TenantContext,
}

fn world() -> World {
    let units = InMemoryUnitOfWorkFactory::default();
    let store = InMemoryNativeRoles::default();
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + time::Duration::days(20_000),
    ));
    let language = FakeConditionLanguage::default();
    let engine = NativeEngine::new(
        Arc::new(units.clone()),
        Arc::new(InMemoryRoleAssignments::default()),
        Arc::new(store.clone()),
        clock.clone(),
    )
    .with_condition_language(Arc::new(language.clone()));
    World {
        roles: RoleService::new(Arc::new(units), Arc::new(store), clock)
            .with_condition_language(Arc::new(language.clone())),
        engine,
        language,
        tenant: TenantContext::assume(TenantId::generate()),
    }
}

fn key(name: &str) -> RoleKey {
    RoleKey::new(
        Namespace::parse(DOCUMENTS).expect("namespace"),
        RoleName::parse(name).expect("name"),
    )
}

fn permission(value: &str) -> PermissionName {
    PermissionName::parse(value).expect("permission")
}

fn contents(permissions: &[&str], conditions: &[(&str, &str)]) -> RoleContents {
    RoleContents {
        description: String::new(),
        permissions: permissions.iter().map(|p| permission(p)).collect(),
        includes: BTreeSet::new(),
        conditions: conditions
            .iter()
            .map(|(p, c)| (permission(p), Condition::parse(c).expect("condition")))
            .collect::<BTreeMap<_, _>>(),
    }
}

fn ana() -> Subject {
    Subject::new(SubjectKind::User, "ana").expect("user")
}

fn read() -> AuthorizationRequest {
    AuthorizationRequest {
        namespace: Namespace::parse(DOCUMENTS).expect("namespace"),
        subject: ana(),
        asserted: Attributes::none(),
        resource: Resource::new("document", None, Attributes::none()).expect("resource"),
        action: Action::parse("read").expect("action"),
        context: EvaluationContext::default(),
    }
}

impl World {
    async fn declare(&self) {
        self.roles
            .declare_permission(
                &self.tenant,
                Namespace::parse(DOCUMENTS).expect("namespace"),
                permission("document:read"),
                "",
                Caller::system(),
            )
            .await
            .expect("declare");
    }

    async fn define(&self, name: &str, contents: RoleContents) -> Result<(), DomainError> {
        self.roles
            .define_role(&self.tenant, key(name), contents, Caller::system())
            .await
            .map(|_| ())
    }

    /// Defines a role reading documents with `condition`, or without one,
    /// and gives it to Ana.
    async fn holding(&self, name: &str, condition: Option<&str>) {
        let conditions: Vec<(&str, &str)> = condition
            .map(|c| ("document:read", c))
            .into_iter()
            .collect();
        self.define(name, contents(&["document:read"], &conditions))
            .await
            .expect("define");
        self.roles
            .assign(
                &self.tenant,
                ana(),
                key(name),
                AssignmentScope::Tenant,
                Validity::default(),
                Caller::system(),
            )
            .await
            .expect("assign");
    }

    async fn answer(&self) -> EngineAnswer {
        self.engine
            .evaluate(
                &self.tenant,
                &EvaluationInput {
                    request: read(),
                    subject_attributes: Attributes::none(),
                    time_limit: Duration::from_millis(200),
                },
            )
            .await
            .expect("answer")
    }
}

fn named(answer: &EngineAnswer) -> Vec<&str> {
    answer
        .matched_policies
        .iter()
        .map(|policy| policy.as_str())
        .collect()
}

#[tokio::test]
async fn a_condition_is_checked_when_the_role_is_defined() {
    let world = world();
    world.declare().await;
    for (text, code) in [
        ("invalid", "authorization.condition_invalid"),
        ("costly", "authorization.condition_too_costly"),
    ] {
        let refused = world
            .define(
                "reader",
                contents(&["document:read"], &[("document:read", text)]),
            )
            .await;
        let error = refused.expect_err("refused");
        assert_eq!(error.code(), code);
        assert!(
            error
                .detail()
                .is_some_and(|d| d.starts_with("document:read: ")),
            "the detail names the permission: {:?}",
            error.detail()
        );
    }
    assert!(
        world
            .define(
                "reader",
                contents(&["document:read"], &[("document:read", "true")])
            )
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn without_a_language_a_condition_is_refused() {
    let units = InMemoryUnitOfWorkFactory::default();
    let roles = RoleService::new(
        Arc::new(units),
        Arc::new(InMemoryNativeRoles::default()),
        Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH)),
    );
    let tenant = TenantContext::assume(TenantId::generate());
    roles
        .declare_permission(
            &tenant,
            Namespace::parse(DOCUMENTS).expect("namespace"),
            permission("document:read"),
            "",
            Caller::system(),
        )
        .await
        .expect("declare");
    let refused = roles
        .define_role(
            &tenant,
            key("reader"),
            contents(&["document:read"], &[("document:read", "true")]),
            Caller::system(),
        )
        .await;
    assert_eq!(
        refused.map(|_| ()).map_err(|e| e.code().to_owned()),
        Err("authorization.conditions_unavailable".to_owned())
    );
}

#[tokio::test]
async fn a_permission_held_without_a_condition_allows_without_running_any() {
    let world = world();
    world.declare().await;
    world.holding("reader", None).await;
    world.holding("guarded", Some("fail")).await;
    let answer = world.answer().await;
    assert_eq!(answer.effect, Effect::Allow);
    assert_eq!(answer.reason.as_str(), MATCHING_ROLE);
    assert_eq!(named(&answer), [format!("{DOCUMENTS}#reader")]);
    assert_eq!(world.language.runs(), 0);
}

#[tokio::test]
async fn a_condition_that_holds_allows_and_one_that_does_not_denies() {
    let world = world();
    world.declare().await;
    world.holding("guarded", Some("false")).await;
    let answer = world.answer().await;
    assert_eq!(answer.effect, Effect::Deny);
    assert_eq!(answer.reason.as_str(), CONDITION_NOT_MET);

    world.holding("open", Some("true")).await;
    let answer = world.answer().await;
    assert_eq!(answer.effect, Effect::Allow);
    assert_eq!(answer.reason.as_str(), MATCHING_ROLE);
    assert_eq!(named(&answer), [format!("{DOCUMENTS}#open")]);
}

#[tokio::test]
async fn a_condition_that_fails_is_indeterminate_unless_another_holds() {
    let world = world();
    world.declare().await;
    world.holding("broken", Some("fail")).await;
    world.holding("closed", Some("false")).await;
    let answer = world.answer().await;
    assert_eq!(answer.effect, Effect::Indeterminate);
    assert_eq!(answer.reason.as_str(), CONDITION_FAILED);

    world.holding("open", Some("true")).await;
    let answer = world.answer().await;
    assert_eq!(answer.effect, Effect::Allow);
}

#[tokio::test]
async fn a_change_of_condition_takes_effect_on_the_next_decision() {
    let world = world();
    world.declare().await;
    world.holding("reader", Some("true")).await;
    assert_eq!(world.answer().await.effect, Effect::Allow);
    world
        .define(
            "reader",
            contents(&["document:read"], &[("document:read", "false")]),
        )
        .await
        .expect("redefine");
    assert_eq!(world.answer().await.effect, Effect::Deny);
}

#[tokio::test]
async fn at_most_so_many_conditions_run_for_one_decision() {
    let world = world();
    world.declare().await;
    for index in 0..=MAX_CONDITIONS_PER_DECISION {
        world
            .holding(&format!("closed-{index:02}"), Some("false"))
            .await;
    }
    let answer = world.answer().await;
    assert_eq!(answer.effect, Effect::Indeterminate);
    assert_eq!(answer.reason.as_str(), CONDITION_FAILED);
    assert_eq!(world.language.runs(), MAX_CONDITIONS_PER_DECISION);
}

#[tokio::test]
async fn an_engine_without_the_language_never_allows_on_a_condition() {
    let units = InMemoryUnitOfWorkFactory::default();
    let store = InMemoryNativeRoles::default();
    let assignments = InMemoryRoleAssignments::default();
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + time::Duration::days(20_000),
    ));
    let language = FakeConditionLanguage::default();
    let roles = RoleService::new(
        Arc::new(units.clone()),
        Arc::new(store.clone()),
        clock.clone(),
    )
    .with_condition_language(Arc::new(language));
    let tenant = TenantContext::assume(TenantId::generate());
    roles
        .declare_permission(
            &tenant,
            Namespace::parse(DOCUMENTS).expect("namespace"),
            permission("document:read"),
            "",
            Caller::system(),
        )
        .await
        .expect("declare");
    roles
        .define_role(
            &tenant,
            key("open"),
            contents(&["document:read"], &[("document:read", "true")]),
            Caller::system(),
        )
        .await
        .expect("define");
    roles
        .assign(
            &tenant,
            ana(),
            key("open"),
            AssignmentScope::Tenant,
            Validity::default(),
            Caller::system(),
        )
        .await
        .expect("assign");
    let engine = NativeEngine::new(
        Arc::new(units),
        Arc::new(assignments),
        Arc::new(store),
        clock,
    );
    let answer = engine
        .evaluate(
            &tenant,
            &EvaluationInput {
                request: read(),
                subject_attributes: Attributes::none(),
                time_limit: Duration::from_millis(200),
            },
        )
        .await
        .expect("answer");
    assert_eq!(answer.effect, Effect::Indeterminate);
    assert_eq!(answer.reason.as_str(), CONDITION_FAILED);
}
