//! The policy lifecycle on PostgreSQL: the stores pass the contract, the
//! database refuses what breaks its rules, and the worker's job checks
//! what waits in every tenant, one worker at a time.

use hodor_adapters_crypto::{OsRandom, Sha256Digest};
use hodor_adapters_postgres::testing::{TestDatabase, schema_violations};
use hodor_adapters_postgres::{
    PgBundleStore, PgInstanceStatusStore, PgInstanceStore, PgPolicyVersionStore,
    PgPublicationStore, PgSimulationStore, PgUploadedDecisionStore, PolicyCheckJob,
};
use hodor_authorization::api::Namespace;
use hodor_authorization_opa::api::{
    Author, BundleFile, BundleService, BundleStore as _, PolicyService, SimulationState,
    VersionState, decision_package,
};
use hodor_authorization_opa::testing::{
    FakeChecker, FakeSigner, LifecyclePorts, run_lifecycle_contract,
};
use hodor_kernel::{Caller, SystemClock, TenantContext, TenantId};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::Ordering;

#[tokio::test]
async fn the_postgres_stores_of_the_lifecycle_pass_the_contract() {
    let database = TestDatabase::start().await;
    run_lifecycle_contract(LifecyclePorts {
        units_of_work: database.app(),
        bundles: &PgBundleStore,
        versions: &PgPolicyVersionStore,
        publications: &PgPublicationStore,
        simulations: &PgSimulationStore,
    })
    .await;
    assert_eq!(
        schema_violations(database.owner()).await,
        Vec::<String>::new()
    );
}

fn policies(database: &TestDatabase) -> (PolicyService, BundleService) {
    let bundles = BundleService::new(
        Arc::new(PgInstanceStore::new(database.app().clone())),
        Arc::new(PgBundleStore),
        Arc::new(PgInstanceStatusStore),
        Arc::new(PgUploadedDecisionStore),
        Arc::new(database.app().clone()),
        Arc::new(Sha256Digest),
        Arc::new(OsRandom),
        Arc::new(SystemClock),
    );
    let policies = PolicyService::new(
        Arc::new(PgPolicyVersionStore),
        Arc::new(PgPublicationStore),
        Arc::new(PgSimulationStore),
        bundles.clone(),
        Arc::new(database.app().clone()),
        Arc::new(Sha256Digest),
        Arc::new(SystemClock),
    );
    (policies, bundles)
}

fn files(tenant: &TenantContext, text: &str) -> Vec<BundleFile> {
    let package = decision_package(
        tenant,
        &Namespace::parse("https://documents.example.com").expect("namespace"),
        &Sha256Digest,
    );
    let directory = package.split('.').skip(3).collect::<Vec<_>>().join("/");
    vec![
        BundleFile {
            path: format!("{directory}/policy.rego"),
            contents: format!("package {package}\n\n# {text}\n").into_bytes(),
        },
        BundleFile {
            path: format!("{directory}/policy_test.rego"),
            contents: format!("package {package}\n\n# passes\n").into_bytes(),
        },
    ]
}

#[tokio::test]
async fn the_job_checks_what_waits_in_every_tenant_and_a_version_is_published_with_its_revision() {
    let database = TestDatabase::start().await;
    let (policies, _) = policies(&database);
    let checker = Arc::new(FakeChecker::default());
    let job = PolicyCheckJob::new(
        database.platform().clone(),
        policies.clone(),
        checker.clone(),
    );
    let acme = TenantContext::assume(TenantId::generate());
    let globex = TenantContext::assume(TenantId::generate());

    let mut drafted = Vec::new();
    for (tenant, text) in [(&acme, "allows"), (&globex, "refuse this one")] {
        let version = policies
            .draft(
                tenant,
                Author::Tenant,
                &files(tenant, text),
                Caller::system(),
            )
            .await
            .expect("draft");
        policies
            .validate(tenant, version.number)
            .await
            .expect("validate");
        drafted.push(version.number);
    }
    let pass = job.run().await.expect("pass");
    assert!(!pass.skipped);
    assert_eq!((pass.tenants, pass.versions), (2, 2), "{pass:?}");
    assert!(pass.failures.is_empty());
    assert_eq!(
        policies.version(&acme, 1).await.expect("version").state,
        VersionState::Validated
    );
    let rejected = policies.version(&globex, 1).await.expect("version");
    assert_eq!(rejected.state, VersionState::Rejected);
    assert!(!rejected.report.expect("report").diagnostics.is_empty());

    // Nothing waits: a pass finds no tenant.
    let idle = job.run().await.expect("pass");
    assert_eq!(idle.tenants, 0);

    // Tests, a simulation and a publication.
    policies.test(&acme, 1).await.expect("test");
    let simulation = policies
        .simulate(
            &acme,
            1,
            &Namespace::parse("https://documents.example.com").expect("namespace"),
            vec![json!({"answer": {"allow": true}, "subject": {"id": "made-up"}})],
        )
        .await
        .expect("simulate");
    let pass = job.run().await.expect("pass");
    assert_eq!((pass.versions, pass.simulations), (1, 1), "{pass:?}");
    assert_eq!(
        policies.version(&acme, 1).await.expect("version").state,
        VersionState::Tested
    );
    let done = policies
        .simulation(&acme, simulation.id)
        .await
        .expect("simulation");
    assert_eq!(done.state, SimulationState::Done);
    assert!(done.inputs.is_empty());
    let (inputs,): (Option<serde_json::Value>,) =
        sqlx::query_as("SELECT inputs FROM \"authorization\".policy_simulation WHERE id = $1")
            .bind(simulation.id.as_uuid())
            .fetch_one(database.owner())
            .await
            .expect("row");
    assert_eq!(inputs, None, "the inputs are erased from the database");

    let publication = policies
        .publish(&acme, 1, &FakeSigner, Caller::system())
        .await
        .expect("publish");
    assert_eq!((publication.revision, publication.version), (1, 1));
    let rollback = policies
        .roll_back(&acme, 1, &FakeSigner, Caller::system())
        .await
        .expect("roll back");
    assert_eq!(rollback.revision, 2);
    let mut uow = hodor_kernel::UnitOfWorkFactory::begin(database.app(), &acme)
        .await
        .expect("begin");
    let latest = PgBundleStore
        .latest_revision(uow.as_mut())
        .await
        .expect("latest")
        .expect("a revision");
    uow.commit().await.expect("commit");
    assert_eq!(latest.0, 2);
    let status = policies.status(&acme).await.expect("status");
    assert_eq!(status.publications, [(2, 1), (1, 1)]);

    // The other tenant sees none of it.
    assert!(
        policies
            .status(&globex)
            .await
            .expect("status")
            .latest
            .is_none()
    );
    let _ = drafted;
}

#[tokio::test]
async fn a_run_that_cannot_start_is_a_failure_of_the_pass_and_the_work_keeps_waiting() {
    let database = TestDatabase::start().await;
    let (policies, _) = policies(&database);
    let checker = Arc::new(FakeChecker::default());
    checker.broken.store(true, Ordering::SeqCst);
    let job = PolicyCheckJob::new(
        database.platform().clone(),
        policies.clone(),
        checker.clone(),
    );
    let tenant = TenantContext::assume(TenantId::generate());
    let version = policies
        .draft(
            &tenant,
            Author::Tenant,
            &files(&tenant, "allows"),
            Caller::system(),
        )
        .await
        .expect("draft");
    policies
        .validate(&tenant, version.number)
        .await
        .expect("validate");
    let pass = job.run().await.expect("pass");
    assert_eq!(pass.failures.len(), 1);
    assert_eq!(
        policies.version(&tenant, 1).await.expect("version").state,
        VersionState::Validating
    );
}

#[tokio::test]
async fn two_workers_do_not_check_at_the_same_time() {
    let database = TestDatabase::start().await;
    let (policies, _) = policies(&database);
    let job = PolicyCheckJob::new(
        database.platform().clone(),
        policies,
        Arc::new(FakeChecker::default()),
    );
    let mut other = database.platform().begin().await.expect("begin");
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(0x686f_646f_7270_6f6c_i64)
        .execute(&mut *other)
        .await
        .expect("lock");
    assert!(job.run().await.expect("pass").skipped);
    other.rollback().await.expect("rollback");
    assert!(!job.run().await.expect("pass").skipped);
}

#[tokio::test]
async fn the_database_keeps_versions_and_publications_and_erases_inputs_once_done() {
    let database = TestDatabase::start().await;
    let pool = hodor_adapters_postgres::connect_pool(
        &hodor_kernel::Secret::from(database.app_url().to_owned()),
        1,
    )
    .await
    .expect("pool");
    for statement in [
        "DELETE FROM \"authorization\".policy_version",
        "UPDATE \"authorization\".policy_publication SET version = 1",
        "DELETE FROM \"authorization\".policy_publication",
    ] {
        let refused = sqlx::query(statement).execute(&pool).await;
        assert!(refused.is_err(), "{statement}");
    }

    let tenant = TenantId::generate();
    sqlx::query(
        "INSERT INTO \"authorization\".policy_version
             (tenant_id, number, written_by, files, digest, state, drafted_at, changed_at)
         VALUES ($1, 1, 'tenant', '[]', $2, 'tested', now(), now())",
    )
    .bind(tenant.as_uuid())
    .bind(vec![0_u8; 32])
    .execute(database.owner())
    .await
    .expect("a version");
    for refused in [
        // A state that is not one.
        "INSERT INTO \"authorization\".policy_version
             (tenant_id, number, written_by, files, digest, state, drafted_at, changed_at)
         VALUES ($1, 2, 'tenant', '[]', decode(repeat('00', 32), 'hex'), 'published', now(), now())",
        // A simulation done that keeps its inputs.
        "INSERT INTO \"authorization\".policy_simulation
             (tenant_id, id, version, namespace, inputs, state, asked_at, done_at)
         VALUES ($1, gen_random_uuid(), 1, 'x', '[]', 'done', now(), now())",
        // A simulation waiting without its inputs.
        "INSERT INTO \"authorization\".policy_simulation
             (tenant_id, id, version, namespace, state, asked_at)
         VALUES ($1, gen_random_uuid(), 1, 'x', 'waiting', now())",
        // A publication of a revision that was never a bundle.
        "INSERT INTO \"authorization\".policy_publication (tenant_id, revision, version)
         VALUES ($1, 7, 1)",
    ] {
        let result = sqlx::query(refused)
            .bind(tenant.as_uuid())
            .execute(database.owner())
            .await;
        assert!(result.is_err(), "{refused}");
    }
}
