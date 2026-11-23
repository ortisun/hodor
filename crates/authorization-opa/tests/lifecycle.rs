//! The policy lifecycle over in-memory stores and a checker that stands in
//! for `opa`: what each step allows, what the worker records, what is
//! published and rolled back, and what the status says.

use hodor_adapters_crypto::{OsRandom, Sha256Digest};
use hodor_authorization::api::Namespace;
use hodor_authorization_opa::api::{
    Author, BundleFile, BundleService, BundleStore as _, InstanceStatus, InstanceStatusStore as _,
    PolicyService, PublishedBundle, SimulationState, VersionState, bundle_name, decision_package,
    tenant_root,
};
use hodor_authorization_opa::testing::{
    FakeChecker, FakeSigner, InMemoryBundles, InMemoryInstances, InMemoryPolicyVersions,
    InMemoryPublications, InMemorySimulations, InMemoryStatuses, InMemoryUploadedDecisions, unpack,
};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, Clock as _, TenantContext, TenantId, Timestamp, UnitOfWorkFactory as _,
};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::Ordering;

const DOCUMENTS: &str = "https://documents.example.com";

struct World {
    policies: PolicyService,
    bundles: BundleService,
    bundle_store: Arc<InMemoryBundles>,
    statuses: Arc<InMemoryStatuses>,
    units: Arc<InMemoryUnitOfWorkFactory>,
    clock: Arc<FixedClock>,
    checker: FakeChecker,
    tenant: TenantContext,
}

fn world() -> World {
    let units = Arc::new(InMemoryUnitOfWorkFactory::default());
    let bundle_store = Arc::new(InMemoryBundles::default());
    let statuses = Arc::new(InMemoryStatuses::default());
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + time::Duration::days(20_000),
    ));
    let bundles = BundleService::new(
        Arc::new(InMemoryInstances::default()),
        bundle_store.clone(),
        statuses.clone(),
        Arc::new(InMemoryUploadedDecisions::default()),
        units.clone(),
        Arc::new(Sha256Digest),
        Arc::new(OsRandom),
        clock.clone(),
    );
    let policies = PolicyService::new(
        Arc::new(InMemoryPolicyVersions::default()),
        Arc::new(InMemoryPublications::default()),
        Arc::new(InMemorySimulations::default()),
        bundles.clone(),
        units.clone(),
        Arc::new(Sha256Digest),
        clock.clone(),
    );
    World {
        policies,
        bundles,
        bundle_store,
        statuses,
        units,
        clock,
        checker: FakeChecker::default(),
        tenant: TenantContext::assume(TenantId::generate()),
    }
}

fn package(tenant: &TenantContext) -> String {
    decision_package(
        tenant,
        &Namespace::parse(DOCUMENTS).expect("namespace"),
        &Sha256Digest,
    )
}

/// A policy, its data and, when given, a test whose text is `test`.
fn files(tenant: &TenantContext, policy: &str, test: Option<&str>) -> Vec<BundleFile> {
    let package = package(tenant);
    let directory = package.split('.').skip(3).collect::<Vec<_>>().join("/");
    let mut files = vec![
        BundleFile {
            path: format!("{directory}/policy.rego"),
            contents: format!("package {package}\n\n# {policy}\n").into_bytes(),
        },
        BundleFile {
            path: "data.json".to_owned(),
            contents: br#"{ "b": 1, "a": 2 }"#.to_vec(),
        },
    ];
    if let Some(test) = test {
        files.push(BundleFile {
            path: format!("{directory}/policy_test.rego"),
            contents: format!("package {package}\n\n# {test}\n").into_bytes(),
        });
    }
    files
}

impl World {
    /// Drafts, validates and tests `files` through the worker's passes.
    async fn tested(&self, files: &[BundleFile]) -> u64 {
        let version = self
            .policies
            .draft(&self.tenant, Author::Tenant, files, Caller::system())
            .await
            .expect("draft");
        self.policies
            .validate(&self.tenant, version.number)
            .await
            .expect("validate");
        self.pass().await;
        self.policies
            .test(&self.tenant, version.number)
            .await
            .expect("test");
        self.pass().await;
        assert_eq!(
            self.state(version.number).await,
            VersionState::Tested,
            "{:?}",
            self.policies.version(&self.tenant, version.number).await
        );
        version.number
    }

    async fn pass(&self) {
        self.policies
            .run_waiting(&self.tenant, &self.checker)
            .await
            .expect("pass");
    }

    async fn state(&self, number: u64) -> VersionState {
        self.policies
            .version(&self.tenant, number)
            .await
            .expect("version")
            .state
    }

    async fn latest_files(&self) -> Vec<(String, Vec<u8>)> {
        let mut uow = self.units.begin(&self.tenant).await.expect("begin");
        let latest = self
            .bundle_store
            .latest(uow.as_mut())
            .await
            .expect("latest")
            .expect("a bundle");
        uow.commit().await.expect("commit");
        unpack(&latest.archive)
    }
}

#[tokio::test]
async fn a_version_is_validated_then_tested_by_the_worker_and_only_then_published() {
    let world = world();
    let version = world
        .policies
        .draft(
            &world.tenant,
            Author::Tenant,
            &files(&world.tenant, "allows", Some("passes")),
            Caller::system(),
        )
        .await
        .expect("draft");
    assert_eq!(version.number, 1);
    assert_eq!(version.state, VersionState::Draft);
    let data = version
        .files
        .iter()
        .find(|file| file.path == "data.json")
        .expect("data");
    assert_eq!(data.contents, br#"{"a":2,"b":1}"#, "kept in canonical form");

    // A draft cannot be tested or published, and nothing waits yet.
    let early = world
        .policies
        .test(&world.tenant, 1)
        .await
        .expect_err("not validated");
    assert_eq!(early.code(), "authorization.policy_version_state");
    let unpublishable = world
        .policies
        .publish(&world.tenant, 1, &FakeSigner, Caller::system())
        .await
        .expect_err("not tested");
    assert_eq!(unpublishable.code(), "authorization.policy_version_state");
    world.pass().await;
    assert_eq!(world.checker.runs.load(Ordering::SeqCst), 0);

    // Validation asks; the worker checks.
    let asked = world
        .policies
        .validate(&world.tenant, 1)
        .await
        .expect("validate");
    assert_eq!(asked.state, VersionState::Validating);
    let twice = world
        .policies
        .validate(&world.tenant, 1)
        .await
        .expect_err("only a draft");
    assert_eq!(twice.code(), "authorization.policy_version_state");
    world.pass().await;
    let validated = world
        .policies
        .version(&world.tenant, 1)
        .await
        .expect("version");
    assert_eq!(validated.state, VersionState::Validated);
    assert_eq!(validated.report.as_ref().map(|r| r.passed()), Some(true));

    // Tests, then publication: the bundle holds no test file.
    world.policies.test(&world.tenant, 1).await.expect("test");
    world.pass().await;
    let tested = world
        .policies
        .version(&world.tenant, 1)
        .await
        .expect("version");
    assert_eq!(tested.state, VersionState::Tested);
    assert_eq!(tested.report.as_ref().map(|r| r.tests.len()), Some(1));
    let publication = world
        .policies
        .publish(&world.tenant, 1, &FakeSigner, Caller::system())
        .await
        .expect("publish");
    assert_eq!((publication.revision, publication.version), (1, 1));
    assert!(!publication.rollback);
    let archived: Vec<String> = world
        .latest_files()
        .await
        .into_iter()
        .map(|(path, _)| path)
        .collect();
    let root = tenant_root(world.tenant.tenant_id());
    assert!(archived.iter().any(|path| path.ends_with("/policy.rego")));
    assert!(
        archived
            .iter()
            .any(|path| *path == format!("{root}/data.json"))
    );
    assert!(
        !archived.iter().any(|path| path.ends_with("_test.rego")),
        "{archived:?}"
    );

    let events = world.units.committed_event_types();
    for wanted in [
        "authorization.policy_version_drafted",
        "authorization.policy_version_checked",
        "authorization.policy_bundle_published",
        "authorization.policy_version_published",
    ] {
        assert!(
            events.iter().any(|event| event == wanted),
            "{wanted}: {events:?}"
        );
    }
}

#[tokio::test]
async fn a_version_that_does_not_compile_or_fails_a_test_is_rejected_for_good() {
    let world = world();
    let broken = world
        .policies
        .draft(
            &world.tenant,
            Author::Tenant,
            &files(&world.tenant, "refuse me", None),
            Caller::system(),
        )
        .await
        .expect("draft");
    world
        .policies
        .validate(&world.tenant, broken.number)
        .await
        .expect("validate");
    world.pass().await;
    let rejected = world
        .policies
        .version(&world.tenant, broken.number)
        .await
        .expect("version");
    assert_eq!(rejected.state, VersionState::Rejected);
    let report = rejected.report.expect("report");
    assert_eq!(report.diagnostics.len(), 1);
    assert!(
        report.diagnostics[0]
            .file
            .as_deref()
            .is_some_and(|file| file.ends_with("policy.rego"))
    );
    for refused in [
        world.policies.validate(&world.tenant, broken.number).await,
        world.policies.test(&world.tenant, broken.number).await,
    ] {
        assert_eq!(
            refused.expect_err("rejected is final").code(),
            "authorization.policy_version_state"
        );
    }

    let failing = world
        .policies
        .draft(
            &world.tenant,
            Author::Tenant,
            &files(&world.tenant, "allows", Some("fail on purpose")),
            Caller::system(),
        )
        .await
        .expect("draft");
    world
        .policies
        .validate(&world.tenant, failing.number)
        .await
        .expect("validate");
    world.pass().await;
    world
        .policies
        .test(&world.tenant, failing.number)
        .await
        .expect("test");
    world.pass().await;
    let rejected = world
        .policies
        .version(&world.tenant, failing.number)
        .await
        .expect("version");
    assert_eq!(rejected.state, VersionState::Rejected);
    assert!(!rejected.report.expect("report").tests[0].passed);
    let unpublishable = world
        .policies
        .publish(&world.tenant, failing.number, &FakeSigner, Caller::system())
        .await
        .expect_err("never published");
    assert_eq!(unpublishable.code(), "authorization.policy_version_state");
}

#[tokio::test]
async fn files_that_a_bundle_would_refuse_are_refused_when_drafted() {
    let world = world();
    let other = TenantContext::assume(TenantId::generate());
    let refused = world
        .policies
        .draft(
            &world.tenant,
            Author::Tenant,
            &files(&other, "another tenant's package", None),
            Caller::system(),
        )
        .await
        .expect_err("outside the tenant's tree");
    assert_eq!(refused.code(), "authorization.bundle_file_invalid");
    assert!(
        world
            .policies
            .versions(&world.tenant, 10)
            .await
            .expect("versions")
            .is_empty()
    );
}

#[tokio::test]
async fn a_run_that_cannot_start_leaves_the_version_waiting() {
    let world = world();
    let version = world
        .policies
        .draft(
            &world.tenant,
            Author::Tenant,
            &files(&world.tenant, "allows", None),
            Caller::system(),
        )
        .await
        .expect("draft");
    world
        .policies
        .validate(&world.tenant, version.number)
        .await
        .expect("validate");
    world.checker.broken.store(true, Ordering::SeqCst);
    let error = world
        .policies
        .run_waiting(&world.tenant, &world.checker)
        .await
        .expect_err("the checker is broken");
    assert_eq!(error.code(), "authorization.policy_checker_unavailable");
    assert_eq!(world.state(version.number).await, VersionState::Validating);
    world.checker.broken.store(false, Ordering::SeqCst);
    world.pass().await;
    assert_eq!(world.state(version.number).await, VersionState::Validated);
}

#[tokio::test]
async fn a_rollback_publishes_the_old_version_as_a_new_revision() {
    let world = world();
    let first = world.tested(&files(&world.tenant, "first", None)).await;
    let second = world.tested(&files(&world.tenant, "second", None)).await;
    for number in [first, second] {
        world
            .policies
            .publish(&world.tenant, number, &FakeSigner, Caller::system())
            .await
            .expect("publish");
    }
    let policy_text = |files: Vec<(String, Vec<u8>)>| {
        files
            .into_iter()
            .find(|(path, _)| path.ends_with("policy.rego"))
            .map(|(_, contents)| String::from_utf8(contents).expect("text"))
            .expect("policy")
    };
    assert!(policy_text(world.latest_files().await).contains("second"));

    let rollback = world
        .policies
        .roll_back(&world.tenant, 1, &FakeSigner, Caller::system())
        .await
        .expect("roll back");
    assert_eq!((rollback.revision, rollback.version), (3, first));
    assert!(rollback.rollback);
    let latest = world.latest_files().await;
    assert!(policy_text(latest.clone()).contains("first"));
    let manifest = latest
        .iter()
        .find(|(path, _)| path == ".manifest")
        .map(|(_, contents)| String::from_utf8(contents.clone()).expect("text"))
        .expect("manifest");
    assert!(manifest.contains(r#""revision":"3""#), "{manifest}");

    let status = world.policies.status(&world.tenant).await.expect("status");
    assert_eq!(status.publications, [(3, first), (2, second), (1, first)]);
    assert_eq!(
        status
            .latest
            .map(|(revision, _, _, version)| (revision, version)),
        Some((3, Some(first)))
    );

    // A revision that does not exist, or was not built from a version,
    // cannot be rolled back to.
    let mut uow = world.units.begin(&world.tenant).await.expect("begin");
    world
        .bundle_store
        .append(
            uow.as_mut(),
            &PublishedBundle {
                revision: 4,
                author: Author::Tenant,
                archive: vec![1],
                digest: [0; 32],
                published_at: world.clock.now(),
            },
        )
        .await
        .expect("append");
    uow.commit().await.expect("commit");
    for revision in [4, 99] {
        let refused = world
            .policies
            .roll_back(&world.tenant, revision, &FakeSigner, Caller::system())
            .await
            .expect_err("no version");
        assert_eq!(
            refused.code(),
            "authorization.policy_revision_without_version"
        );
    }
}

#[tokio::test]
async fn a_simulation_compares_a_version_with_the_published_one_and_forgets_its_inputs() {
    let world = world();
    let published = world
        .tested(&files(&world.tenant, "deny everything", None))
        .await;
    world
        .policies
        .publish(&world.tenant, published, &FakeSigner, Caller::system())
        .await
        .expect("publish");
    let candidate = world
        .policies
        .draft(
            &world.tenant,
            Author::Tenant,
            &files(&world.tenant, "answers what it is told", None),
            Caller::system(),
        )
        .await
        .expect("draft");
    let namespace = Namespace::parse(DOCUMENTS).expect("namespace");
    let inputs = vec![
        json!({"action": "read", "answer": {"allow": false}}),
        json!({"action": "read", "answer": {"allow": true}}),
        json!({"action": "write"}),
    ];
    let early = world
        .policies
        .simulate(&world.tenant, candidate.number, &namespace, inputs.clone())
        .await
        .expect_err("a draft is not simulated");
    assert_eq!(early.code(), "authorization.policy_version_state");
    world
        .policies
        .validate(&world.tenant, candidate.number)
        .await
        .expect("validate");
    world.pass().await;

    let invalid = world
        .policies
        .simulate(
            &world.tenant,
            candidate.number,
            &namespace,
            vec![json!([1])],
        )
        .await
        .expect_err("inputs are objects");
    assert_eq!(
        invalid.code(),
        "authorization.policy_simulation_inputs_invalid"
    );

    let asked = world
        .policies
        .simulate(&world.tenant, candidate.number, &namespace, inputs)
        .await
        .expect("simulate");
    assert_eq!(asked.state, SimulationState::Waiting);
    world.pass().await;
    let done = world
        .policies
        .simulation(&world.tenant, asked.id)
        .await
        .expect("simulation");
    assert_eq!(done.state, SimulationState::Done);
    assert!(done.inputs.is_empty(), "the inputs are erased");
    assert_eq!(done.compared_with, Some(published));
    let differs: Vec<bool> = done.results.iter().map(|answer| answer.differs).collect();
    assert_eq!(differs, [false, true, true]);
    assert_eq!(done.results[2].candidate, None, "undefined");
    assert_eq!(done.results[0].published, Some(json!({"allow": false})));

    // Another tenant does not see it.
    let other = TenantContext::assume(TenantId::generate());
    let hidden = world
        .policies
        .simulation(&other, asked.id)
        .await
        .expect_err("not another tenant's");
    assert_eq!(hidden.code(), "authorization.policy_simulation_not_found");
    assert_eq!(
        world
            .policies
            .version(&other, candidate.number)
            .await
            .expect_err("not another tenant's")
            .code(),
        "authorization.policy_version_not_found"
    );
    let _ = package(&world.tenant);
}

#[tokio::test]
async fn activation_is_pending_until_every_instance_that_should_run_the_revision_says_it_does() {
    let world = world();
    let number = world.tested(&files(&world.tenant, "allows", None)).await;
    let (own, _) = world
        .bundles
        .register("own-policy", Some(world.tenant.tenant_id()))
        .await
        .expect("own");
    let (shared, _) = world
        .bundles
        .register("shared-policy", None)
        .await
        .expect("shared");
    world
        .bundles
        .register("elsewhere", Some(TenantId::generate()))
        .await
        .expect("another tenant's");

    let nothing = world.policies.status(&world.tenant).await.expect("status");
    assert_eq!(nothing.latest, None);
    assert!(!nothing.pending_activation);

    world
        .policies
        .publish(&world.tenant, number, &FakeSigner, Caller::system())
        .await
        .expect("publish");
    let published = world.policies.status(&world.tenant).await.expect("status");
    // The tenant wrote it: only its own instance should run it.
    assert_eq!(
        published
            .instances
            .iter()
            .map(|i| i.instance.as_str())
            .collect::<Vec<_>>(),
        ["own-policy"]
    );
    assert!(published.pending_activation, "it has not reported");

    let report = |instance, revision: &str| InstanceStatus {
        instance,
        active_revision: Some(revision.to_owned()),
        last_activation: None,
        error: None,
        reported_at: world.clock.now(),
    };
    let mut uow = world.units.begin(&world.tenant).await.expect("begin");
    world
        .statuses
        .record(uow.as_mut(), &report(own.id(), "1"))
        .await
        .expect("record");
    // A shared instance reporting the tenant does not make it wanted for a
    // bundle the tenant wrote.
    world
        .statuses
        .record(uow.as_mut(), &report(shared.id(), "0"))
        .await
        .expect("record");
    uow.commit().await.expect("commit");
    let active = world.policies.status(&world.tenant).await.expect("status");
    assert!(!active.pending_activation, "{active:?}");
    assert!(active.instances.iter().all(|i| i.current));
    assert_eq!(active.instances.len(), 1);
    let _ = bundle_name(world.tenant.tenant_id());
}

#[tokio::test]
async fn an_operators_bundle_waits_for_the_shared_instances_that_reported_the_tenant() {
    let world = world();
    let version = world
        .policies
        .draft(
            &world.tenant,
            Author::Operator,
            &files(&world.tenant, "allows", None),
            Caller::system(),
        )
        .await
        .expect("draft");
    world
        .policies
        .validate(&world.tenant, version.number)
        .await
        .expect("validate");
    world.pass().await;
    world
        .policies
        .test(&world.tenant, version.number)
        .await
        .expect("test");
    world.pass().await;
    let (shared, _) = world
        .bundles
        .register("shared-a", None)
        .await
        .expect("shared");
    world
        .bundles
        .register("shared-b", None)
        .await
        .expect("shared");
    world
        .policies
        .publish(&world.tenant, version.number, &FakeSigner, Caller::system())
        .await
        .expect("publish");

    // Neither shared instance has shown it pulls this tenant.
    let status = world.policies.status(&world.tenant).await.expect("status");
    assert!(status.instances.is_empty());
    assert!(!status.pending_activation);

    let mut uow = world.units.begin(&world.tenant).await.expect("begin");
    world
        .statuses
        .record(
            uow.as_mut(),
            &InstanceStatus {
                instance: shared.id(),
                active_revision: None,
                last_activation: None,
                error: Some("not activated".to_owned()),
                reported_at: world.clock.now(),
            },
        )
        .await
        .expect("record");
    uow.commit().await.expect("commit");
    let status = world.policies.status(&world.tenant).await.expect("status");
    assert_eq!(status.instances.len(), 1);
    assert_eq!(status.instances[0].error.as_deref(), Some("not activated"));
    assert!(status.pending_activation);
}

#[tokio::test]
async fn the_in_memory_stores_pass_the_contract() {
    let units = InMemoryUnitOfWorkFactory::default();
    hodor_authorization_opa::testing::run_lifecycle_contract(
        hodor_authorization_opa::testing::LifecyclePorts {
            units_of_work: &units,
            bundles: &InMemoryBundles::default(),
            versions: &InMemoryPolicyVersions::default(),
            publications: &InMemoryPublications::default(),
            simulations: &InMemorySimulations::default(),
        },
    )
    .await;
}
