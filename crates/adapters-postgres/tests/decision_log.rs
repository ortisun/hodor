//! The record of decisions in PostgreSQL: the contract, masking, the
//! partitions and the retention job.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{DecisionLogMaintenance, PgDecisionLogStore};
use hodor_authorization::api::{
    Action, Attributes, AuthorizationDecision, AuthorizationRequest, Decided, DecisionId,
    DecisionLog, DecisionLogMode, DecisionLogSettings, DecisionLogStore as _, DecisionMetadata,
    Effect, EvaluationContext, MaskPath, Namespace, ReasonCode, Resource, Subject, SubjectKind,
};
use hodor_authorization::testing::{
    DecisionLogPorts, run_decision_log_contract, sample_decision_record,
};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::CountingRandom;
use hodor_kernel::{Caller, TenantContext, TenantId, Timestamp, UnitOfWorkFactory};
use serde_json::json;
use std::sync::Arc;

#[tokio::test]
async fn the_postgres_record_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_decision_log_contract(DecisionLogPorts {
        units_of_work: database.app(),
        store: &PgDecisionLogStore,
    })
    .await;
}

fn decision(at: Timestamp) -> AuthorizationDecision {
    AuthorizationDecision {
        decision_id: DecisionId::generate(),
        effect: Effect::Deny,
        evaluated_at: at,
        engine: None,
        policy_version: None,
        reason: ReasonCode::parse(ReasonCode::NO_ENGINE_BOUND).expect("reason"),
        matched_policies: Vec::new(),
        metadata: DecisionMetadata {
            duration_microseconds: 40,
            cache_hit: false,
            asserted_trusted: true,
        },
    }
}

#[tokio::test]
async fn a_masked_attribute_is_never_stored() {
    let database = TestDatabase::start().await;
    let now = Timestamp::now_utc();
    let log = DecisionLog::new(
        Arc::new(database.app().clone()),
        Arc::new(PgDecisionLogStore),
        Arc::new(CountingRandom::default()),
        Arc::new(FixedClock::at(now)),
    );
    let tenant = TenantContext::assume(TenantId::generate());
    let settings = DecisionLogSettings::new(
        DecisionLogMode::Full,
        vec![
            MaskPath::parse("subject.attributes.email").expect("mask"),
            MaskPath::parse("asserted.*").expect("mask"),
            MaskPath::parse("resource.attributes.owner").expect("mask"),
        ],
        30,
    )
    .expect("settings");
    log.replace_settings(&tenant, settings, Caller::system())
        .await
        .expect("settings");

    let request = AuthorizationRequest {
        namespace: Namespace::parse("https://documents.example.com").expect("namespace"),
        subject: Subject::new(SubjectKind::User, "ana").expect("subject"),
        asserted: Attributes::new([("badge".to_owned(), json!("badge-7731"))]).expect("asserted"),
        resource: Resource::new(
            "document",
            Some("42"),
            Attributes::new([("owner".to_owned(), json!("owner@example.com"))]).expect("resource"),
        )
        .expect("resource"),
        action: Action::parse("read").expect("action"),
        context: EvaluationContext::default(),
    };
    let subject =
        Attributes::new([("email".to_owned(), json!("ana@example.com"))]).expect("attributes");
    let decided = decision(now);
    let recorded = log
        .record(
            &tenant,
            &[Decided {
                request: &request,
                subject_attributes: &subject,
                decision: &decided,
            }],
        )
        .await
        .expect("record");
    assert_eq!(recorded, 1);

    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT row_to_json(record)::text FROM \"authorization\".decision_log record",
    )
    .fetch_all(database.owner())
    .await
    .expect("rows");
    assert_eq!(rows.len(), 1);
    for secret in ["ana@example.com", "badge-7731", "owner@example.com"] {
        assert!(!rows[0].0.contains(secret), "{secret} was stored");
    }
    assert!(rows[0].0.contains("subject.attributes.email"));
}

#[tokio::test]
async fn the_application_role_reaches_records_only_through_the_partitioned_table() {
    let database = TestDatabase::start().await;
    let partition: (String,) = sqlx::query_as(
        "SELECT child.relname::text FROM pg_inherits
         JOIN pg_class child ON child.oid = inhrelid
         JOIN pg_class parent ON parent.oid = inhparent
         WHERE parent.relname = 'decision_log' AND child.relname <> 'decision_log_default'
         LIMIT 1",
    )
    .fetch_one(database.owner())
    .await
    .expect("a partition");
    let tenant = TenantContext::assume(TenantId::generate());
    let mut uow = UnitOfWorkFactory::begin(database.app(), &tenant)
        .await
        .expect("begin");
    let direct = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT * FROM \"authorization\".{}",
        partition.0
    )))
    .execute(hodor_adapters_postgres::connection(uow.as_mut()).expect("connection"))
    .await;
    assert!(direct.is_err(), "a partition is granted to nobody");
}

async fn record_at(database: &TestDatabase, tenant: &TenantContext, at: Timestamp) {
    let mut record = sample_decision_record(0, Effect::Allow, "ana");
    record.decided_at = at;
    let mut uow = UnitOfWorkFactory::begin(database.app(), tenant)
        .await
        .expect("begin");
    PgDecisionLogStore
        .append(uow.as_mut(), &[record])
        .await
        .expect("append");
    uow.commit().await.expect("commit");
}

async fn count(database: &TestDatabase, tenant: &TenantContext) -> i64 {
    let (rows,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM \"authorization\".decision_log WHERE tenant_id = $1")
            .bind(tenant.tenant_id().as_uuid())
            .fetch_one(database.owner())
            .await
            .expect("count");
    rows
}

#[tokio::test]
async fn the_job_keeps_each_tenants_retention_and_prepares_the_days_ahead() {
    let database = TestDatabase::start().await;
    let now = Timestamp::now_utc();
    let short = TenantContext::assume(TenantId::generate());
    let default = TenantContext::assume(TenantId::generate());

    let mut uow = UnitOfWorkFactory::begin(database.app(), &short)
        .await
        .expect("begin");
    let five_days =
        DecisionLogSettings::new(DecisionLogMode::Full, Vec::new(), 5).expect("settings");
    PgDecisionLogStore
        .put_settings(uow.as_mut(), &five_days, now)
        .await
        .expect("settings");
    uow.commit().await.expect("commit");
    for tenant in [&short, &default] {
        record_at(&database, tenant, now - time::Duration::days(10)).await;
        record_at(&database, tenant, now - time::Duration::days(40)).await;
        record_at(&database, tenant, now).await;
    }

    let job = DecisionLogMaintenance::new(database.platform().clone(), database.app().clone());
    let report = job.run(now, 1000).await.expect("maintenance");
    assert_eq!(report.tenants, 2);
    assert_eq!(
        report.removed, 3,
        "two of the short tenant, one of the other"
    );
    assert_eq!(count(&database, &short).await, 1);
    assert_eq!(count(&database, &default).await, 2);
    let again = job.run(now, 1000).await.expect("maintenance");
    assert_eq!((again.tenants, again.removed), (0, 0));

    // A record of a day that has no partition yet lands in the default
    // partition; preparing its day moves it out, and it stays readable.
    let later = now + time::Duration::days(20);
    record_at(&database, &default, later).await;
    let (in_default,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM \"authorization\".decision_log_default")
            .fetch_one(database.owner())
            .await
            .expect("default");
    assert!(in_default >= 1);
    let report = job.run(later, 1000).await.expect("maintenance");
    assert!(report.created >= 1);
    let (left,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM \"authorization\".decision_log_default WHERE decided_at >= $1",
    )
    .bind(later - time::Duration::days(1))
    .fetch_one(database.owner())
    .await
    .expect("default");
    assert_eq!(left, 0, "the day's rows left the default partition");
    let (partitions,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM pg_inherits JOIN pg_class parent ON parent.oid = inhparent
         WHERE parent.relname = 'decision_log'",
    )
    .fetch_one(database.owner())
    .await
    .expect("partitions");
    // The default partition, the day before, the day and the week after.
    assert!(partitions >= 10);
    // Twenty days later the record of ten days before is exactly 30 days
    // old, at the edge of the default retention, and stays with the rest.
    assert_eq!(
        count(&database, &default).await,
        3,
        "the record of the day ahead is kept"
    );
}

#[tokio::test]
async fn only_the_platform_role_may_maintain_the_partitions() {
    let database = TestDatabase::start().await;
    let tenant = TenantContext::assume(TenantId::generate());
    let mut uow = UnitOfWorkFactory::begin(database.app(), &tenant)
        .await
        .expect("begin");
    let refused = sqlx::query(
        "SELECT * FROM \"authorization\".maintain_decision_log_partitions(current_date, 1, 30)",
    )
    .execute(hodor_adapters_postgres::connection(uow.as_mut()).expect("connection"))
    .await;
    assert!(refused.is_err());
}
