//! The record of decisions, through the evaluation service, against
//! in-memory ports.

use hodor_authorization::api::{
    Action, Attributes, AuthorizationEngine as _, AuthorizationRequest, BindingSettings,
    DecisionFilter, DecisionLog, DecisionLogMode, DecisionLogSettings, Effect, EngineAnswer,
    EngineRegistry, EvaluationContext, EvaluationService, MaskPath, Namespace, PolicyRevision,
    PolicySelection, ReasonCode, Resource, Subject, SubjectKind,
};
use hodor_authorization::testing::{
    DecisionLogPorts, InMemoryDecisionLog, InMemoryEngineBindings, InMemoryRoleAssignments,
    ScriptedEngine, StaticSubjectAttributes, run_decision_log_contract,
};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, DomainError, PageRequest, RandomSource, TenantContext, TenantId, Timestamp,
};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

const DOCUMENTS: &str = "https://documents.example.com";

/// Draws whatever the test set, so that sampling is predictable.
#[derive(Debug, Default)]
struct SetDraw(AtomicU32);

impl RandomSource for SetDraw {
    fn fill(&self, buffer: &mut [u8]) {
        let bytes = self.0.load(Ordering::SeqCst).to_le_bytes();
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = bytes.get(index).copied().unwrap_or(0);
        }
    }
}

struct World {
    service: EvaluationService,
    log: DecisionLog,
    store: InMemoryDecisionLog,
    units: InMemoryUnitOfWorkFactory,
    subjects: StaticSubjectAttributes,
    draw: Arc<SetDraw>,
    tenant: TenantContext,
}

fn decide(
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
        matched_policies: Vec::new(),
    })
}

async fn world() -> World {
    let units = InMemoryUnitOfWorkFactory::default();
    let engine = ScriptedEngine::new("scripted", decide);
    let subjects = StaticSubjectAttributes::default();
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + time::Duration::days(20_000),
    ));
    let mut registry = EngineRegistry::new();
    registry
        .register_with_simulator(Arc::new(engine.clone()), Arc::new(engine.clone()))
        .expect("register");
    let store = InMemoryDecisionLog::default();
    let draw = Arc::new(SetDraw::default());
    let log = DecisionLog::new(
        Arc::new(units.clone()),
        Arc::new(store.clone()),
        draw.clone(),
        clock.clone(),
    );
    let service = EvaluationService::new(
        Arc::new(units.clone()),
        Arc::new(InMemoryRoleAssignments::default()),
        Arc::new(InMemoryEngineBindings::default()),
        Arc::new(subjects.clone()),
        registry,
        clock,
    )
    .with_decision_log(log.clone());
    let tenant = TenantContext::assume(TenantId::generate());
    let mut settings =
        BindingSettings::new(Namespace::parse(DOCUMENTS).expect("namespace"), engine.id());
    settings.trust_asserted = true;
    service
        .bind(&tenant, settings, Caller::system())
        .await
        .expect("bind");
    World {
        service,
        log,
        store,
        units,
        subjects,
        draw,
        tenant,
    }
}

fn ana() -> Subject {
    Subject::new(SubjectKind::User, "ana").expect("subject")
}

fn request(namespace: &str, action: &str) -> AuthorizationRequest {
    AuthorizationRequest {
        namespace: Namespace::parse(namespace).expect("namespace"),
        subject: ana(),
        asserted: Attributes::new([("department".to_owned(), json!("sales"))]).expect("asserted"),
        resource: Resource::new(
            "document",
            Some("42"),
            Attributes::new([("owner".to_owned(), json!("owner@example.com"))]).expect("resource"),
        )
        .expect("resource"),
        action: Action::parse(action).expect("action"),
        context: EvaluationContext {
            attributes: Attributes::new([("ip".to_owned(), json!("203.0.113.7"))])
                .expect("context"),
            ..EvaluationContext::default()
        },
    }
}

impl World {
    async fn set(&self, mode: DecisionLogMode, masks: &[&str]) {
        let masks = masks
            .iter()
            .map(|mask| MaskPath::parse(mask).expect("mask"))
            .collect();
        let settings = DecisionLogSettings::new(mode, masks, 30).expect("settings");
        self.log
            .replace_settings(&self.tenant, settings, Caller::system())
            .await
            .expect("replace");
    }

    async fn ask(&self, action: &str) -> hodor_authorization::api::AuthorizationDecision {
        self.service
            .evaluate(&self.tenant, &request(DOCUMENTS, action))
            .await
    }

    fn records(&self) -> Vec<hodor_authorization::api::DecisionRecord> {
        self.store.records_of(self.tenant.tenant_id())
    }
}

#[tokio::test]
async fn the_in_memory_record_passes_the_contract() {
    let units = InMemoryUnitOfWorkFactory::default();
    let store = InMemoryDecisionLog::default();
    run_decision_log_contract(DecisionLogPorts {
        units_of_work: &units,
        store: &store,
    })
    .await;
}

#[tokio::test]
async fn a_decision_is_recorded_with_what_the_engine_was_given() {
    let world = world().await;
    world.subjects.set(
        &world.tenant,
        &ana(),
        Attributes::new([("status".to_owned(), json!("active"))]).expect("attributes"),
    );
    let decision = world.ask("read").await;

    let records = world.records();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.decision_id, decision.decision_id);
    assert_eq!(record.namespace, DOCUMENTS);
    assert_eq!(
        (record.subject_kind, record.subject_id.as_str()),
        (SubjectKind::User, "ana")
    );
    assert_eq!(record.action, "read");
    assert_eq!(
        (record.resource_type.as_str(), record.resource_id.as_deref()),
        ("document", Some("42"))
    );
    assert_eq!(record.effect, Effect::Allow);
    assert_eq!(record.reason, "by_script");
    assert_eq!(record.engine.as_deref(), Some("scripted"));
    assert_eq!(record.policy_version.as_deref(), Some("revision-7"));
    assert_eq!(record.decided_at, decision.evaluated_at);
    assert_eq!(
        record.input,
        json!({
            "subject": { "attributes": { "status": "active" } },
            "asserted": { "department": "sales" },
            "resource": { "attributes": { "owner": "owner@example.com" } },
            "context": { "attributes": { "ip": "203.0.113.7" } }
        })
    );
    assert!(record.masked.is_empty());
}

#[tokio::test]
async fn a_masked_attribute_is_never_recorded() {
    let world = world().await;
    world.subjects.set(
        &world.tenant,
        &ana(),
        Attributes::new([("email".to_owned(), json!("ana@example.com"))]).expect("attributes"),
    );
    world
        .set(
            DecisionLogMode::Full,
            &[
                "subject.attributes.email",
                "resource.attributes.owner",
                "context.attributes.*",
            ],
        )
        .await;
    world.ask("read").await;

    let records = world.records();
    let written = format!("{records:?}");
    for secret in ["ana@example.com", "owner@example.com", "203.0.113.7"] {
        assert!(!written.contains(secret), "{secret} was recorded");
    }
    assert_eq!(
        records[0].masked,
        [
            "context.attributes.*",
            "resource.attributes.owner",
            "subject.attributes.email"
        ]
    );
}

#[tokio::test]
async fn deny_only_and_off_keep_what_they_say() {
    let world = world().await;
    world.set(DecisionLogMode::DenyOnly, &[]).await;
    world.ask("read").await;
    let refused = world.ask("delete").await;
    let records = world.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].decision_id, refused.decision_id);

    world.set(DecisionLogMode::Off, &[]).await;
    world.ask("delete").await;
    assert_eq!(world.records().len(), 1);
}

#[tokio::test]
async fn sampling_keeps_every_refusal_and_its_share_of_allows() {
    let world = world().await;
    world
        .set(DecisionLogMode::Sampled { allow_percent: 50 }, &[])
        .await;
    world.draw.0.store(49, Ordering::SeqCst);
    let kept = world.ask("read").await;
    world.draw.0.store(50, Ordering::SeqCst);
    world.ask("read").await;
    let refused = world.ask("delete").await;
    let recorded: Vec<_> = world.records().iter().map(|r| r.decision_id).collect();
    assert_eq!(recorded, [kept.decision_id, refused.decision_id]);
}

#[tokio::test]
async fn each_request_of_a_batch_is_recorded() {
    let world = world().await;
    let requests = [request(DOCUMENTS, "read"), request(DOCUMENTS, "delete")];
    let decisions = world
        .service
        .evaluate_batch(&world.tenant, &requests)
        .await
        .expect("batch");
    let recorded: Vec<_> = world.records().iter().map(|r| r.decision_id).collect();
    assert_eq!(
        recorded,
        decisions.iter().map(|d| d.decision_id).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn a_simulated_decision_is_never_recorded() {
    let world = world().await;
    world
        .service
        .simulate(
            &world.tenant,
            &request(DOCUMENTS, "read"),
            &PolicySelection::Published,
        )
        .await
        .expect("simulate");
    assert!(world.records().is_empty());
}

#[tokio::test]
async fn an_unbound_resource_server_is_recorded_as_denied() {
    let world = world().await;
    world
        .service
        .evaluate(&world.tenant, &request("https://other.example.com", "read"))
        .await;
    let records = world.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].effect, Effect::Deny);
    assert_eq!(records[0].reason, "no_engine_bound");
    assert_eq!(records[0].engine, None);
}

#[tokio::test]
async fn a_record_that_cannot_be_written_changes_no_answer() {
    let world = world().await;
    world.store.fail(true);
    let decision = world.ask("read").await;
    assert_eq!(decision.effect, Effect::Allow);
    assert_eq!(world.service.unrecorded(), 1);
    world.store.fail(false);
    world.ask("read").await;
    assert_eq!(world.records().len(), 1);
    assert_eq!(world.service.unrecorded(), 1);
}

#[tokio::test]
async fn changing_the_settings_is_announced_once() {
    let world = world().await;
    assert_eq!(
        world.log.settings(&world.tenant).await.expect("settings"),
        DecisionLogSettings::default()
    );
    world
        .set(DecisionLogMode::DenyOnly, &["subject.attributes.email"])
        .await;
    world
        .set(DecisionLogMode::DenyOnly, &["subject.attributes.email"])
        .await;
    let changes = world
        .units
        .committed_event_types()
        .into_iter()
        .filter(|kind| kind == "authorization.decision_log_changed")
        .count();
    assert_eq!(changes, 1);
    assert_eq!(
        world
            .log
            .settings(&world.tenant)
            .await
            .expect("settings")
            .mode(),
        DecisionLogMode::DenyOnly
    );
}

#[tokio::test]
async fn a_tenant_reads_only_its_own_records() {
    let world = world().await;
    world.ask("read").await;
    let elsewhere = TenantContext::assume(TenantId::generate());
    let page = world
        .log
        .page(
            &elsewhere,
            &DecisionFilter::default(),
            &PageRequest::default(),
        )
        .await
        .expect("page");
    assert!(page.items.is_empty());
    let page = world
        .log
        .page(
            &world.tenant,
            &DecisionFilter::default(),
            &PageRequest::default(),
        )
        .await
        .expect("page");
    assert_eq!(page.items.len(), 1);
}
