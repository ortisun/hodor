//! The bundles' use cases, on the in-memory stores.

use hodor_authorization_opa::api::{
    Author, BundleFile, BundleService, Pull, bundle_name, gzip, tenant_root,
};
use hodor_authorization_opa::testing::{
    BundlePorts, FakeSigner, InMemoryBundles, InMemoryInstances, InMemoryStatuses,
    InMemoryUploadedDecisions, run_bundle_contract, unpack,
};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::{CountingRandom, FakeDigest};
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, TenantContext, TenantId};
use serde_json::json;
use std::sync::Arc;

struct World {
    service: BundleService,
    units: Arc<InMemoryUnitOfWorkFactory>,
}

fn world() -> World {
    let units = Arc::new(InMemoryUnitOfWorkFactory::default());
    let service = BundleService::new(
        Arc::new(InMemoryInstances::default()),
        Arc::new(InMemoryBundles::default()),
        Arc::new(InMemoryStatuses::default()),
        Arc::new(InMemoryUploadedDecisions::default()),
        units.clone(),
        Arc::new(FakeDigest),
        Arc::new(CountingRandom::default()),
        Arc::new(FixedClock::at(
            hodor_kernel::Timestamp::UNIX_EPOCH + time::Duration::days(20_000),
        )),
    );
    World { service, units }
}

fn policy(tenant: TenantId) -> BundleFile {
    BundleFile {
        path: "resource_servers/rab/policy.rego".to_owned(),
        contents: format!(
            "package {}.resource_servers.rab\n\ndecision := {{\"allow\": true}}\n",
            tenant_root(tenant).replace('/', ".")
        )
        .into_bytes(),
    }
}

async fn publish(world: &World, tenant: TenantId, author: Author) -> u64 {
    world
        .service
        .publish(
            &TenantContext::assume(tenant),
            author,
            &[policy(tenant)],
            &FakeSigner,
            Caller::system(),
        )
        .await
        .expect("publish")
        .revision
}

#[tokio::test]
async fn the_in_memory_stores_pass_the_contract() {
    let units = InMemoryUnitOfWorkFactory::default();
    run_bundle_contract(BundlePorts {
        units_of_work: &units,
        instances: &InMemoryInstances::default(),
        bundles: &InMemoryBundles::default(),
        statuses: &InMemoryStatuses::default(),
        decisions: &InMemoryUploadedDecisions::default(),
    })
    .await;
}

#[tokio::test]
async fn a_credential_is_shown_once_and_is_refused_once_disabled() {
    let world = world();
    let (instance, credential) = world
        .service
        .register("shared", None)
        .await
        .expect("register");
    let found = world
        .service
        .authenticate(Some(credential.expose()))
        .await
        .expect("authenticated");
    assert_eq!(found.id(), instance.id());
    assert!(
        world.service.register("shared", None).await.is_err(),
        "a name is taken once"
    );

    for refused in [None, Some(""), Some("hodor_pa_nonsense")] {
        let error = world
            .service
            .authenticate(refused)
            .await
            .expect_err("refused");
        assert_eq!(error.code(), "authorization.policy_agent_unauthenticated");
    }
    let (_, other) = world
        .service
        .register("other", None)
        .await
        .expect("register");
    assert_ne!(other.expose(), credential.expose());

    assert!(world.service.disable("shared").await.expect("disable"));
    assert!(!world.service.disable("shared").await.expect("again"));
    let error = world
        .service
        .authenticate(Some(credential.expose()))
        .await
        .expect_err("disabled");
    assert_eq!(error.code(), "authorization.policy_agent_unauthenticated");
}

#[tokio::test]
async fn revisions_count_up_per_tenant_and_publishing_is_recorded() {
    let world = world();
    let tenant = TenantId::generate();
    let other = TenantId::generate();
    assert_eq!(publish(&world, tenant, Author::Tenant).await, 1);
    assert_eq!(publish(&world, tenant, Author::Operator).await, 2);
    assert_eq!(publish(&world, other, Author::Operator).await, 1);
    let events = world.units.committed_event_types();
    assert_eq!(
        events,
        vec!["authorization.policy_bundle_published"; 3],
        "one event per publication"
    );
    let payload = &world.units.committed_events()[1].payload;
    assert_eq!(payload["revision"], 2);
    assert_eq!(payload["written_by"], "operator");
    assert_eq!(payload["digest"].as_str().map(str::len), Some(64));
}

#[tokio::test]
async fn an_instance_pulls_only_what_it_may() {
    let world = world();
    let tenant = TenantId::generate();
    let other = TenantId::generate();
    let (own, _) = world
        .service
        .register("own", Some(tenant))
        .await
        .expect("own");
    let (shared, _) = world
        .service
        .register("shared", None)
        .await
        .expect("shared");

    // Nothing published: not found for everyone.
    for instance in [&own, &shared] {
        assert_eq!(
            world
                .service
                .pull(instance, &bundle_name(tenant), None)
                .await
                .expect("pull"),
            Pull::NotFound
        );
    }

    // The tenant writes its own: its own instance gets it, the shared
    // one does not.
    publish(&world, tenant, Author::Tenant).await;
    let Pull::Bundle {
        entity_tag,
        archive,
    } = world
        .service
        .pull(&own, &bundle_name(tenant), None)
        .await
        .expect("pull")
    else {
        panic!("its own instance gets the bundle");
    };
    assert!(entity_tag.starts_with('"') && entity_tag.ends_with('"'));
    let files = unpack(&archive);
    assert_eq!(files[0].0, ".signatures.json");
    assert_eq!(
        world
            .service
            .pull(&shared, &bundle_name(tenant), None)
            .await
            .expect("pull"),
        Pull::NotFound,
        "a shared instance never runs what a tenant wrote"
    );

    // The tag the instance holds: not modified.
    assert_eq!(
        world
            .service
            .pull(&own, &bundle_name(tenant), Some(&format!("W/{entity_tag}")))
            .await
            .expect("pull"),
        Pull::NotModified {
            entity_tag: entity_tag.clone()
        }
    );

    // The operator publishes for the other tenant: the shared instance
    // gets it, the instance of another tenant does not.
    publish(&world, other, Author::Operator).await;
    assert!(matches!(
        world
            .service
            .pull(&shared, &bundle_name(other), None)
            .await
            .expect("pull"),
        Pull::Bundle { .. }
    ));
    assert_eq!(
        world
            .service
            .pull(&own, &bundle_name(other), None)
            .await
            .expect("pull"),
        Pull::NotFound
    );

    // A name that is not a tenant's.
    for name in ["authz", "", "../t0", &bundle_name(tenant).to_uppercase()] {
        assert_eq!(
            world.service.pull(&own, name, None).await.expect("pull"),
            Pull::NotFound,
            "{name}"
        );
    }
}

#[tokio::test]
async fn reports_are_kept_only_for_the_tenants_an_instance_serves() {
    let world = world();
    let tenant = TenantId::generate();
    let other = TenantId::generate();
    let (own, _) = world
        .service
        .register("own", Some(tenant))
        .await
        .expect("own");
    let report = json!({
        "bundles": {
            bundle_name(tenant): {"active_revision": "1"},
            bundle_name(other): {"active_revision": "9"},
        }
    })
    .to_string();
    let kept = world
        .service
        .report_status(&own, report.as_bytes(), false)
        .await
        .expect("status");
    assert_eq!(kept, 1);
    let statuses = world
        .service
        .statuses(&TenantContext::assume(tenant))
        .await
        .expect("statuses");
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].active_revision.as_deref(), Some("1"));
    assert!(
        world
            .service
            .statuses(&TenantContext::assume(other))
            .await
            .expect("statuses")
            .is_empty()
    );
    // Compressed, as well.
    assert_eq!(
        world
            .service
            .report_status(&own, &gzip(report.as_bytes()), true)
            .await
            .expect("compressed"),
        1
    );

    let decision = |tenant: TenantId, id: &str| {
        json!({
            "decision_id": id,
            "path": format!("hodor/tenants/{}/resource_servers/rab/decision", bundle_name(tenant)),
            "input": {"subject": {"id": "a person"}},
            "result": {"allow": false},
            "bundles": {bundle_name(tenant): {"revision": "1"}},
        })
    };
    let upload = json!([
        decision(tenant, "a"),
        decision(other, "b"),
        decision(tenant, "a")
    ])
    .to_string();
    let new = world
        .service
        .upload_decisions(&own, &gzip(upload.as_bytes()), true)
        .await
        .expect("upload");
    assert_eq!(new, 1, "once, and not the other tenant's");
    let uploaded = world
        .service
        .uploaded_decisions(&TenantContext::assume(tenant), 10)
        .await
        .expect("decisions");
    assert_eq!(uploaded.len(), 1);
    assert_eq!(uploaded[0].allowed, Some(false));
    assert_eq!(uploaded[0].revision.as_deref(), Some("1"));
    assert!(
        world
            .service
            .uploaded_decisions(&TenantContext::assume(other), 10)
            .await
            .expect("decisions")
            .is_empty()
    );

    // An upload that is not gzip, or expands beyond the limit, is refused.
    let error = world
        .service
        .upload_decisions(&own, upload.as_bytes(), true)
        .await
        .expect_err("not gzip");
    assert_eq!(error.code(), "authorization.policy_agent_report_invalid");
    let bomb = gzip(&vec![b' '; 9 * 1024 * 1024]);
    assert!(
        world
            .service
            .upload_decisions(&own, &bomb, true)
            .await
            .is_err()
    );
}
