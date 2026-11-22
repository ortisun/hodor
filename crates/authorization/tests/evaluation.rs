//! Evaluating through the engine contract, against in-memory ports.

use hodor_authorization::api::{
    Action, Attributes, AuthorizationEngine, AuthorizationRequest, AuthorizationService,
    BindingSettings, Effect, EngineAnswer, EngineId, EngineRegistry, EvaluationContext,
    EvaluationService, MAX_BATCH, Namespace, Permission, PolicyReference, PolicyRevision,
    PolicySelection, ReasonCode, Resource, Role, Subject, SubjectKind,
};
use hodor_authorization::testing::{
    BindingPorts, InMemoryEngineBindings, InMemoryRoleAssignments, ScriptedEngine,
    StaticSubjectAttributes, run_binding_contract,
};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, DomainError, EventEnvelope, TenantContext, TenantId, Timestamp, UnitOfWork,
    UnitOfWorkFactory, UserId,
};
use serde_json::json;
use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const DOCUMENTS: &str = "https://documents.example.com";

/// Units of work whose commit can be made to fail.
#[derive(Clone, Default)]
struct Units {
    inner: InMemoryUnitOfWorkFactory,
    commits_fail: Arc<AtomicBool>,
}

struct Unit {
    inner: Box<dyn UnitOfWork>,
    fails: bool,
}

#[async_trait::async_trait]
impl UnitOfWork for Unit {
    fn tenant(&self) -> &TenantContext {
        self.inner.tenant()
    }

    fn record_event(&mut self, event: EventEnvelope) {
        self.inner.record_event(event);
    }

    async fn commit(self: Box<Self>) -> Result<(), DomainError> {
        if self.fails {
            return Err(DomainError::internal("test.commit_failed", "commit failed"));
        }
        self.inner.commit().await
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[async_trait::async_trait]
impl UnitOfWorkFactory for Units {
    async fn begin(&self, tenant: &TenantContext) -> Result<Box<dyn UnitOfWork>, DomainError> {
        Ok(Box::new(Unit {
            inner: self.inner.begin(tenant).await?,
            fails: self.commits_fail.load(Ordering::SeqCst),
        }))
    }
}

struct World {
    service: EvaluationService,
    roles: AuthorizationService,
    units: Units,
    bindings: InMemoryEngineBindings,
    subjects: StaticSubjectAttributes,
    engine: ScriptedEngine,
    clock: Arc<FixedClock>,
    tenant: TenantContext,
}

fn allow_readers(
    _: &TenantContext,
    input: &hodor_authorization::api::EvaluationInput,
) -> Result<EngineAnswer, DomainError> {
    let effect = if input.request.action.as_str() == "read" {
        Effect::Allow
    } else {
        Effect::Deny
    };
    Ok(EngineAnswer {
        effect,
        reason: ReasonCode::parse("by_script").expect("reason"),
        policy_version: Some(PolicyRevision::parse("revision-7").expect("revision")),
        matched_policies: vec![PolicyReference::parse("readers").expect("policy")],
    })
}

fn world_with(engine: ScriptedEngine) -> World {
    let units = Units::default();
    let assignments = InMemoryRoleAssignments::default();
    let bindings = InMemoryEngineBindings::default();
    let subjects = StaticSubjectAttributes::default();
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + time::Duration::days(20_000),
    ));
    let mut registry = EngineRegistry::new();
    registry
        .register_with_simulator(Arc::new(engine.clone()), Arc::new(engine.clone()))
        .expect("register");
    World {
        service: EvaluationService::new(
            Arc::new(units.clone()),
            Arc::new(assignments.clone()),
            Arc::new(bindings.clone()),
            Arc::new(subjects.clone()),
            registry,
            clock.clone(),
        ),
        roles: AuthorizationService::new(
            Arc::new(units.clone()),
            Arc::new(assignments),
            clock.clone(),
        ),
        units,
        bindings,
        subjects,
        engine,
        clock,
        tenant: TenantContext::assume(TenantId::generate()),
    }
}

fn world() -> World {
    world_with(ScriptedEngine::new("scripted", allow_readers))
}

fn namespace(value: &str) -> Namespace {
    Namespace::parse(value).expect("namespace")
}

fn request(
    namespace_value: &str,
    subject: Subject,
    kind: &str,
    action: &str,
) -> AuthorizationRequest {
    AuthorizationRequest {
        namespace: namespace(namespace_value),
        subject,
        asserted: Attributes::new([("roles".to_owned(), json!(["owner"]))]).expect("asserted"),
        resource: Resource::new(kind, Some("report-1"), Attributes::none()).expect("resource"),
        action: Action::parse(action).expect("action"),
        context: EvaluationContext::default(),
    }
}

fn ana() -> Subject {
    Subject::new(SubjectKind::User, "ana").expect("subject")
}

impl World {
    fn settings(&self) -> BindingSettings {
        BindingSettings::new(namespace(DOCUMENTS), self.engine.id())
    }

    async fn bind(&self, settings: BindingSettings) {
        self.service
            .bind(&self.tenant, settings, Caller::system())
            .await
            .expect("bind");
    }

    async fn ask(&self, action: &str) -> hodor_authorization::api::AuthorizationDecision {
        self.service
            .evaluate(&self.tenant, &request(DOCUMENTS, ana(), "document", action))
            .await
    }

    fn events(&self) -> Vec<String> {
        self.units.inner.committed_event_types()
    }
}

#[tokio::test]
async fn the_in_memory_binding_store_passes_the_contract() {
    let units = InMemoryUnitOfWorkFactory::default();
    let bindings = InMemoryEngineBindings::default();
    run_binding_contract(BindingPorts {
        units_of_work: &units,
        bindings: &bindings,
    })
    .await;
}

#[tokio::test]
async fn a_resource_server_without_a_binding_is_denied_everything() {
    let world = world();
    let decision = world.ask("read").await;
    assert_eq!(decision.effect, Effect::Deny);
    assert_eq!(decision.reason.as_str(), ReasonCode::NO_ENGINE_BOUND);
    assert_eq!(decision.engine, None);
    assert!(!decision.permits());
    assert!(world.engine.seen().is_empty());
}

#[tokio::test]
async fn the_bound_engine_decides_and_hodor_stamps_the_decision() {
    let world = world();
    world.bind(world.settings()).await;
    let first = world.ask("read").await;
    assert_eq!(first.effect, Effect::Allow);
    assert!(first.permits());
    assert_eq!(first.reason.as_str(), "by_script");
    assert_eq!(first.engine, Some(world.engine.id()));
    assert_eq!(
        first.policy_version.as_ref().map(PolicyRevision::as_str),
        Some("revision-7")
    );
    assert_eq!(first.matched_policies.len(), 1);
    assert_eq!(
        first.evaluated_at,
        hodor_kernel::Clock::now(world.clock.as_ref())
    );

    let second = world.ask("delete").await;
    assert_eq!(second.effect, Effect::Deny);
    assert!(!second.permits());
    assert_ne!(first.decision_id, second.decision_id);
}

#[tokio::test]
async fn a_binding_belongs_to_its_tenant() {
    let world = world();
    world.bind(world.settings()).await;
    let other = TenantContext::assume(TenantId::generate());
    let decision = world
        .service
        .evaluate(&other, &request(DOCUMENTS, ana(), "document", "read"))
        .await;
    assert_eq!(decision.reason.as_str(), ReasonCode::NO_ENGINE_BOUND);
    assert!(world.engine.seen().is_empty());

    world.ask("read").await;
    let seen = world.engine.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, world.tenant.tenant_id());
}

#[tokio::test]
async fn asserted_attributes_reach_the_engine_only_when_the_binding_trusts_them() {
    let world = world();
    world.bind(world.settings()).await;
    let untrusted = world.ask("read").await;
    assert!(!untrusted.metadata.asserted_trusted);
    assert!(world.engine.seen()[0].1.request.asserted.is_empty());

    let mut trusting = world.settings();
    trusting.trust_asserted = true;
    world.bind(trusting).await;
    let trusted = world.ask("read").await;
    assert!(trusted.metadata.asserted_trusted);
    assert_eq!(
        world.engine.seen()[1].1.request.asserted.get("roles"),
        Some(&json!(["owner"]))
    );
}

#[tokio::test]
async fn the_engine_receives_what_hodor_knows_about_the_subject_in_the_tenant() {
    let world = world();
    world.bind(world.settings()).await;
    let known = Attributes::new([("department".to_owned(), json!("finance"))]).expect("set");
    world.subjects.set(&world.tenant, &ana(), known.clone());
    world.subjects.set(
        &TenantContext::assume(TenantId::generate()),
        &ana(),
        Attributes::none(),
    );
    world.ask("read").await;
    let stranger = Subject::new(SubjectKind::Client, "stranger").expect("subject");
    world
        .service
        .evaluate(
            &world.tenant,
            &request(DOCUMENTS, stranger, "document", "read"),
        )
        .await;
    let seen = world.engine.seen();
    assert_eq!(seen[0].1.subject_attributes, known);
    // A subject Hodor does not know has no attributes, like one with none.
    assert!(seen[1].1.subject_attributes.is_empty());
    assert_eq!(seen[0].1.time_limit, Duration::from_millis(200));
}

#[tokio::test]
async fn every_failure_is_indeterminate_with_its_cause() {
    let failing = ScriptedEngine::new("scripted", |_, _| {
        Err(DomainError::internal("engine.broken", "broken"))
    });
    let broken = world_with(failing);
    broken.bind(broken.settings()).await;
    let decision = broken.ask("read").await;
    assert_eq!(decision.effect, Effect::Indeterminate);
    assert!(!decision.permits());
    assert_eq!(decision.reason.as_str(), ReasonCode::ENGINE_FAILED);
    assert_eq!(
        decision.engine,
        Some(EngineId::parse("scripted").expect("id"))
    );

    let world = world();
    world.bind(world.settings()).await;
    world.bindings.fail(true);
    let decision = world.ask("read").await;
    assert_eq!(decision.effect, Effect::Indeterminate);
    assert_eq!(decision.reason.as_str(), ReasonCode::BINDING_UNAVAILABLE);
    assert_eq!(decision.engine, None);
    world.bindings.fail(false);

    world.subjects.fail(true);
    let decision = world.ask("read").await;
    assert_eq!(decision.reason.as_str(), ReasonCode::SUBJECT_UNAVAILABLE);
    assert_eq!(decision.effect, Effect::Indeterminate);
    world.subjects.fail(false);

    world
        .engine
        .take(world.clock.clone(), Duration::from_millis(201));
    let decision = world.ask("read").await;
    assert_eq!(decision.effect, Effect::Indeterminate);
    assert_eq!(decision.reason.as_str(), ReasonCode::ENGINE_TIMED_OUT);
    assert_eq!(decision.metadata.duration_microseconds, 201_000);
    world
        .engine
        .take(world.clock.clone(), Duration::from_millis(200));
    assert_eq!(world.ask("read").await.effect, Effect::Allow);
}

#[tokio::test]
async fn an_engine_that_is_not_registered_cannot_be_bound_or_reached() {
    let world = world();
    let mut settings = world.settings();
    settings.engine = EngineId::parse("open_policy_agent").expect("id");
    let refused = world
        .service
        .bind(&world.tenant, settings.clone(), Caller::system())
        .await
        .expect_err("refused");
    assert_eq!(refused.code(), "authorization.unknown_engine");

    // A binding stored by a binary that had the engine, read by one that
    // does not.
    let mut uow = world.units.begin(&world.tenant).await.expect("begin");
    let binding = hodor_authorization::api::EngineBinding::new(settings, Timestamp::UNIX_EPOCH)
        .expect("binding");
    hodor_authorization::api::EngineBindingStore::put(&world.bindings, uow.as_mut(), &binding)
        .await
        .expect("put");
    uow.commit().await.expect("commit");
    let decision = world.ask("read").await;
    assert_eq!(decision.effect, Effect::Indeterminate);
    assert_eq!(decision.reason.as_str(), ReasonCode::ENGINE_UNAVAILABLE);
    assert_eq!(
        decision.engine,
        Some(EngineId::parse("open_policy_agent").expect("id"))
    );
}

#[tokio::test]
async fn an_engine_that_says_it_cannot_decide_is_indeterminate_and_an_impossible_answer_fails() {
    let unsure = ScriptedEngine::new("scripted", |_, input| {
        if input.request.action.as_str() == "read" {
            Ok(EngineAnswer::new(
                Effect::Indeterminate,
                ReasonCode::parse("missing_data").expect("reason"),
            ))
        } else {
            let mut answer = EngineAnswer::new(
                Effect::Allow,
                ReasonCode::parse("by_script").expect("reason"),
            );
            answer.matched_policies = (0..65)
                .map(|index| PolicyReference::parse(&format!("p{index}")).expect("policy"))
                .collect();
            Ok(answer)
        }
    });
    let world = world_with(unsure);
    world.bind(world.settings()).await;
    let unsure = world.ask("read").await;
    assert_eq!(unsure.effect, Effect::Indeterminate);
    assert_eq!(unsure.reason.as_str(), "missing_data");
    let impossible = world.ask("write").await;
    assert_eq!(impossible.effect, Effect::Indeterminate);
    assert_eq!(impossible.reason.as_str(), ReasonCode::ENGINE_FAILED);
    assert!(impossible.matched_policies.is_empty());
}

#[tokio::test]
async fn a_failure_allows_only_for_actions_that_fail_open_and_only_once_recorded() {
    let failing = ScriptedEngine::new("scripted", |_, _| {
        Err(DomainError::internal("engine.broken", "broken"))
    });
    let world = world_with(failing);
    let mut settings = world.settings();
    settings
        .fail_open_actions
        .insert(Action::parse("read").expect("action"));
    world.bind(settings).await;

    let open = world.ask("read").await;
    assert_eq!(open.effect, Effect::Allow);
    assert_eq!(open.reason.as_str(), ReasonCode::FAIL_OPEN);
    assert_eq!(
        world.events(),
        ["authorization.engine_bound", "authorization.failed_open"]
    );
    let recorded = &world.units.inner.committed_events()[1];
    assert_eq!(recorded.payload["namespace"], DOCUMENTS);
    assert_eq!(recorded.payload["action"], "read");
    assert_eq!(recorded.payload["engine"], "scripted");
    assert_eq!(recorded.payload["cause"], ReasonCode::ENGINE_FAILED);

    let closed = world.ask("write").await;
    assert_eq!(closed.effect, Effect::Indeterminate);
    assert_eq!(closed.reason.as_str(), ReasonCode::ENGINE_FAILED);

    // When the failure cannot be recorded, it does not allow.
    world.units.commits_fail.store(true, Ordering::SeqCst);
    let unrecorded = world.ask("read").await;
    assert_eq!(unrecorded.effect, Effect::Indeterminate);
    assert_eq!(unrecorded.reason.as_str(), ReasonCode::ENGINE_FAILED);
    assert_eq!(world.events().len(), 2);
}

#[tokio::test]
async fn a_binding_that_cannot_be_read_never_fails_open() {
    let world = world();
    let mut settings = world.settings();
    settings
        .fail_open_actions
        .insert(Action::parse("read").expect("action"));
    world.bind(settings).await;
    world.bindings.fail(true);
    let decision = world.ask("read").await;
    assert_eq!(decision.effect, Effect::Indeterminate);
    assert_eq!(decision.reason.as_str(), ReasonCode::BINDING_UNAVAILABLE);
}

#[tokio::test]
async fn the_administration_answers_as_the_fixed_role_check_does() {
    // An engine named `native` in the registry, which allows everything,
    // must not answer for the administration.
    let pretender = ScriptedEngine::new(EngineId::NATIVE, |_, _| {
        Ok(EngineAnswer::new(
            Effect::Allow,
            ReasonCode::parse("anything").expect("reason"),
        ))
    });
    let world = world_with(pretender);
    let user = UserId::generate();
    let combinations: [&[Role]; 4] = [
        &[],
        &[Role::TenantAuditor],
        &[Role::TenantAdministrator],
        &[Role::TenantAuditor, Role::TenantAdministrator],
    ];
    for roles in combinations {
        for role in Role::ALL {
            world
                .roles
                .revoke(&world.tenant, user, role, Caller::system())
                .await
                .expect("revoke");
        }
        for role in roles {
            world
                .roles
                .assign(&world.tenant, user, *role, Caller::system())
                .await
                .expect("assign");
        }
        for permission in Permission::ALL {
            let (kind, action) = permission.as_str().split_once(':').expect("permission");
            let decision = world
                .service
                .evaluate(
                    &world.tenant,
                    &request(Namespace::ADMINISTRATION, Subject::user(user), kind, action),
                )
                .await;
            let check = world
                .roles
                .check(&world.tenant, user, permission)
                .await
                .expect("check");
            assert_eq!(
                decision.effect,
                check.effect,
                "{roles:?} {}",
                permission.as_str()
            );
            assert_eq!(decision.reason.as_str(), check.reason);
            assert_eq!(decision.engine, Some(EngineId::native()));
            assert_eq!(
                decision.policy_version.as_ref().map(PolicyRevision::as_str),
                Some("fixed_roles")
            );
            assert!(!decision.metadata.asserted_trusted);
        }
    }
    assert!(world.engine.seen().is_empty());
}

#[tokio::test]
async fn the_administration_denies_clients_unknown_permissions_and_other_tenants() {
    let world = world();
    let user = UserId::generate();
    world
        .roles
        .assign(
            &world.tenant,
            user,
            Role::TenantAdministrator,
            Caller::system(),
        )
        .await
        .expect("assign");
    let ask =
        |tenant: TenantContext, subject: Subject, kind: &'static str, action: &'static str| {
            let service = world.service.clone();
            async move {
                service
                    .evaluate(
                        &tenant,
                        &request(Namespace::ADMINISTRATION, subject, kind, action),
                    )
                    .await
            }
        };
    let allowed = ask(world.tenant.clone(), Subject::user(user), "users", "read").await;
    assert!(allowed.permits());
    let client = Subject::new(SubjectKind::Client, &user.to_string()).expect("subject");
    for denied in [
        ask(world.tenant.clone(), client, "users", "read").await,
        ask(world.tenant.clone(), Subject::user(user), "users", "delete").await,
        ask(
            TenantContext::assume(TenantId::generate()),
            Subject::user(user),
            "users",
            "read",
        )
        .await,
    ] {
        assert_eq!(denied.effect, Effect::Deny);
        assert_eq!(denied.reason.as_str(), ReasonCode::NO_MATCHING_ROLE);
    }
}

#[tokio::test]
async fn the_administration_cannot_be_bound_unbound_or_simulated() {
    let world = world();
    let mut settings = world.settings();
    settings.namespace = Namespace::administration();
    let bound = world
        .service
        .bind(&world.tenant, settings, Caller::system())
        .await
        .expect_err("refused");
    assert_eq!(bound.code(), "authorization.namespace_reserved");
    let unbound = world
        .service
        .unbind(
            &world.tenant,
            &Namespace::administration(),
            Caller::system(),
        )
        .await
        .expect_err("refused");
    assert_eq!(unbound.code(), "authorization.namespace_reserved");
    let fixed = world
        .service
        .binding(&world.tenant, &Namespace::administration())
        .await
        .expect("binding")
        .expect("fixed");
    assert_eq!(fixed.engine(), &EngineId::native());
    assert!(fixed.settings().sensitive);
    assert!(
        world
            .service
            .bindings(&world.tenant)
            .await
            .expect("list")
            .is_empty()
    );
    let simulated = world
        .service
        .simulate(
            &world.tenant,
            &request(Namespace::ADMINISTRATION, ana(), "users", "read"),
            &PolicySelection::Published,
        )
        .await
        .expect_err("refused");
    assert_eq!(simulated.code(), "authorization.simulation_unsupported");
    assert!(world.events().is_empty());
}

#[tokio::test]
async fn binding_again_with_the_same_settings_announces_nothing() {
    let world = world();
    world.bind(world.settings()).await;
    world.bind(world.settings()).await;
    assert_eq!(world.events(), ["authorization.engine_bound"]);
    let mut changed = world.settings();
    changed.time_limit = Duration::from_millis(400);
    world.bind(changed).await;
    assert_eq!(world.events().len(), 2);
    let binding = world
        .service
        .binding(&world.tenant, &namespace(DOCUMENTS))
        .await
        .expect("binding")
        .expect("found");
    assert_eq!(binding.settings().time_limit, Duration::from_millis(400));

    assert!(
        world
            .service
            .unbind(&world.tenant, &namespace(DOCUMENTS), Caller::system())
            .await
            .expect("unbind")
    );
    assert!(
        !world
            .service
            .unbind(&world.tenant, &namespace(DOCUMENTS), Caller::system())
            .await
            .expect("unbind")
    );
    assert_eq!(
        world.events(),
        [
            "authorization.engine_bound",
            "authorization.engine_bound",
            "authorization.engine_unbound"
        ]
    );
    assert_eq!(
        world.ask("read").await.reason.as_str(),
        ReasonCode::NO_ENGINE_BOUND
    );
}

#[tokio::test]
async fn a_batch_answers_every_request_in_order_and_sends_each_binding_together() {
    let world = world();
    world.bind(world.settings()).await;
    let other = "urn:example:unbound";
    let requests = vec![
        request(DOCUMENTS, ana(), "document", "read"),
        request(other, ana(), "document", "read"),
        request(DOCUMENTS, ana(), "document", "delete"),
        request(DOCUMENTS, ana(), "document", "read"),
    ];
    let decisions = world
        .service
        .evaluate_batch(&world.tenant, &requests)
        .await
        .expect("batch");
    let effects: Vec<Effect> = decisions.iter().map(|d| d.effect).collect();
    assert_eq!(
        effects,
        [Effect::Allow, Effect::Deny, Effect::Deny, Effect::Allow]
    );
    assert_eq!(decisions[1].reason.as_str(), ReasonCode::NO_ENGINE_BOUND);
    assert_eq!(world.engine.batches(), [3]);

    assert!(
        world
            .service
            .evaluate_batch(&world.tenant, &[])
            .await
            .expect("empty")
            .is_empty()
    );
    let too_many = vec![request(DOCUMENTS, ana(), "document", "read"); MAX_BATCH + 1];
    let refused = world
        .service
        .evaluate_batch(&world.tenant, &too_many)
        .await
        .expect_err("refused");
    assert_eq!(refused.code(), "authorization.batch_too_large");
    assert_eq!(
        world
            .service
            .evaluate_batch(&world.tenant, &too_many[..MAX_BATCH])
            .await
            .expect("batch")
            .len(),
        MAX_BATCH
    );
}

#[tokio::test]
async fn a_batch_answer_of_the_wrong_length_fails_only_its_binding() {
    let world = world();
    world.bind(world.settings()).await;
    world.engine.answer_short(true);
    let requests = vec![
        request(DOCUMENTS, ana(), "document", "read"),
        request(Namespace::ADMINISTRATION, ana(), "users", "read"),
        request(DOCUMENTS, ana(), "document", "read"),
    ];
    let decisions = world
        .service
        .evaluate_batch(&world.tenant, &requests)
        .await
        .expect("batch");
    assert_eq!(decisions[0].reason.as_str(), ReasonCode::ENGINE_FAILED);
    assert_eq!(decisions[2].reason.as_str(), ReasonCode::ENGINE_FAILED);
    assert_eq!(decisions[1].effect, Effect::Deny);
    assert_eq!(decisions[1].reason.as_str(), ReasonCode::NO_MATCHING_ROLE);
}

#[tokio::test]
async fn a_batch_has_the_time_limit_of_its_binding_once_per_request() {
    let world = world();
    world.bind(world.settings()).await;
    let pair = vec![request(DOCUMENTS, ana(), "document", "read"); 2];
    world
        .engine
        .take(world.clock.clone(), Duration::from_millis(400));
    let in_time = world
        .service
        .evaluate_batch(&world.tenant, &pair)
        .await
        .expect("batch");
    assert!(in_time.iter().all(|d| d.effect == Effect::Allow));
    world
        .engine
        .take(world.clock.clone(), Duration::from_millis(401));
    let late = world
        .service
        .evaluate_batch(&world.tenant, &pair)
        .await
        .expect("batch");
    assert!(
        late.iter()
            .all(|d| d.reason.as_str() == ReasonCode::ENGINE_TIMED_OUT)
    );
}

#[tokio::test]
async fn a_simulation_asks_the_simulator_and_records_nothing() {
    let world = world();
    let missing = world
        .service
        .simulate(
            &world.tenant,
            &request(DOCUMENTS, ana(), "document", "read"),
            &PolicySelection::Published,
        )
        .await
        .expect_err("refused");
    assert_eq!(missing.code(), "authorization.no_engine_bound");

    world.bind(world.settings()).await;
    let draft = PolicySelection::Draft(PolicyReference::parse("draft-3").expect("draft"));
    let simulation = world
        .service
        .simulate(
            &world.tenant,
            &request(DOCUMENTS, ana(), "document", "read"),
            &draft,
        )
        .await
        .expect("simulation");
    assert_eq!(simulation.decision.effect, Effect::Allow);
    assert_eq!(simulation.trace.len(), 1);
    assert!(simulation.trace[0].contains("draft-3"));
    assert_eq!(world.events(), ["authorization.engine_bound"]);

    // An engine without a simulator.
    let plain = ScriptedEngine::new("plain", allow_readers);
    let mut registry = EngineRegistry::new();
    registry
        .register(Arc::new(plain.clone()))
        .expect("register");
    let service = EvaluationService::new(
        Arc::new(world.units.clone()),
        Arc::new(InMemoryRoleAssignments::default()),
        Arc::new(world.bindings.clone()),
        Arc::new(world.subjects.clone()),
        registry,
        world.clock.clone(),
    );
    let mut settings = world.settings();
    settings.namespace = namespace("urn:example:plain");
    settings.engine = plain.id();
    service
        .bind(&world.tenant, settings, Caller::system())
        .await
        .expect("bind");
    let unsupported = service
        .simulate(
            &world.tenant,
            &request("urn:example:plain", ana(), "document", "read"),
            &PolicySelection::Published,
        )
        .await
        .expect_err("refused");
    assert_eq!(unsupported.code(), "authorization.simulation_unsupported");
}

#[test]
fn an_engine_name_is_registered_once() {
    let mut registry = EngineRegistry::new();
    registry
        .register(Arc::new(ScriptedEngine::new("twice", allow_readers)))
        .expect("first");
    let refused = registry
        .register(Arc::new(ScriptedEngine::new("twice", allow_readers)))
        .expect_err("second");
    assert_eq!(refused.code(), "authorization.engine_registered_twice");
    assert!(registry.contains(&EngineId::parse("twice").expect("id")));
    assert!(
        registry
            .simulator(&EngineId::parse("twice").expect("id"))
            .is_none()
    );
}
