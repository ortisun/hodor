//! The use cases of trust domains and the worker's refreshing of bundles,
//! run against the in-memory store and stand-in bundle endpoints.

use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, Clock as _, PageRequest, TenantContext, TenantId, Timestamp};
use hodor_keys::api::{
    BundleRefresher, MAX_TRUST_DOMAINS, RefreshOutcome, TrustDomainPorts, TrustDomainService,
    TrustSource, TrustSourceRequest,
};
use hodor_keys::testing::{
    FakeBundleEndpoints, InMemoryTrustDomains, TrustDomainContract, run_trust_domain_contract,
    sample_bundle,
};
use std::sync::Arc;
use time::Duration;

const ENDPOINT: &str = "https://spire.example.com/bundle";

struct World {
    service: TrustDomainService,
    refresher: BundleRefresher,
    endpoints: FakeBundleEndpoints,
    clock: Arc<FixedClock>,
    units_of_work: InMemoryUnitOfWorkFactory,
    tenant: TenantContext,
}

fn world() -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let clock = Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH));
    let store = InMemoryTrustDomains::default();
    let endpoints = FakeBundleEndpoints::default();
    let service = TrustDomainService::new(TrustDomainPorts {
        units_of_work: Arc::new(units_of_work.clone()),
        store: Arc::new(store.clone()),
        destinations: Arc::new(endpoints.clone()),
        http: Arc::new(endpoints.clone()),
        digest: Arc::new(FakeDigest),
        clock: clock.clone(),
    });
    World {
        refresher: BundleRefresher::new(service.clone(), Arc::new(store)),
        service,
        endpoints,
        clock,
        units_of_work,
        tenant: TenantContext::assume(TenantId::generate()),
    }
}

fn uploaded(bundle: &serde_json::Value) -> TrustSourceRequest {
    TrustSourceRequest::Uploaded {
        bundle: bundle.to_string().into_bytes(),
    }
}

fn endpoint(url: &str) -> TrustSourceRequest {
    TrustSourceRequest::BundleEndpoint {
        url: url.to_owned(),
    }
}

impl World {
    fn events(&self) -> Vec<String> {
        self.units_of_work.committed_event_types()
    }

    fn payloads(&self) -> Vec<serde_json::Value> {
        self.units_of_work
            .committed_events()
            .into_iter()
            .map(|event| event.payload)
            .collect()
    }

    async fn read(&self, id: hodor_keys::api::TrustDomainId) -> hodor_keys::api::TrustDomain {
        self.service.get(&self.tenant, id).await.expect("read")
    }

    async fn refresh_all(&self) -> Vec<RefreshOutcome> {
        let mut outcomes = Vec::new();
        for lease in self.refresher.lease_due(8).await.expect("leased") {
            outcomes.push(self.refresher.refresh(lease).await.expect("refreshed"));
        }
        outcomes
    }
}

#[tokio::test]
async fn an_uploaded_bundle_is_read_kept_and_audited() {
    let world = world();
    let added = world
        .service
        .add(
            &world.tenant,
            "prod.example.com",
            uploaded(&sample_bundle(Some(4), &["one", "two"])),
            Caller::system(),
        )
        .await
        .expect("added");
    assert_eq!(added.source(), TrustSource::Uploaded);
    let bundle = added.bundle().expect("bundle");
    assert_eq!(bundle.sequence(), Some(4));
    assert!(bundle.jwt_key("two").is_some());
    assert_eq!(
        world
            .service
            .get(&world.tenant, added.id())
            .await
            .expect("read"),
        added
    );
    assert_eq!(
        world
            .service
            .find_by_name(&world.tenant, "prod.example.com")
            .await
            .expect("found"),
        Some(added.clone())
    );
    let page = world
        .service
        .list(&world.tenant, &PageRequest::new(Some(10), None))
        .await
        .expect("list");
    assert_eq!(page.items, vec![added.clone()]);
    assert_eq!(world.events(), ["keys.trust_domain_added"]);
    let payload = &world.payloads()[0];
    assert_eq!(payload["name"], "prod.example.com");
    assert_eq!(payload["source"], "uploaded");
    assert_eq!(payload["sequence"], 4);
    assert_eq!(payload["x509_authorities"], 1);
    assert_eq!(payload["jwt_authorities"], 2);
    assert_eq!(payload["bundle_sha256"].as_str().map(str::len), Some(64));
    assert!(world.endpoints.asked().is_empty());
}

#[tokio::test]
async fn a_bundle_that_does_not_read_is_refused_and_nothing_is_stored() {
    let world = world();
    for (bundle, detail) in [
        (serde_json::json!({"keys": "none"}), "no `keys` array"),
        (
            serde_json::json!({"keys": [{"use": "jwt-svid", "kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"}]}),
            "",
        ),
    ] {
        let error = world
            .service
            .add(
                &world.tenant,
                "bad.example",
                uploaded(&bundle),
                Caller::system(),
            )
            .await
            .expect_err("refused");
        assert_eq!(error.code(), "keys.trust_bundle_invalid");
        assert!(error.detail().unwrap_or_default().contains(detail));
    }
    let error = world
        .service
        .add(
            &world.tenant,
            "bad.example",
            TrustSourceRequest::Uploaded {
                bundle: b"not json".to_vec(),
            },
            Caller::system(),
        )
        .await
        .expect_err("refused");
    assert_eq!(error.code(), "keys.trust_bundle_invalid");
    let error = world
        .service
        .add(
            &world.tenant,
            "Bad",
            TrustSourceRequest::Mesh,
            Caller::system(),
        )
        .await
        .expect_err("refused");
    assert_eq!(error.code(), "keys.trust_domain_name_invalid");
    assert!(
        world
            .service
            .find_by_name(&world.tenant, "bad.example")
            .await
            .expect("find")
            .is_none()
    );
    assert!(world.events().is_empty());
}

#[tokio::test]
async fn a_bundle_endpoint_is_checked_then_fetched_once_and_each_refusal_named() {
    let world = world();
    world
        .endpoints
        .serve(ENDPOINT, &sample_bundle(Some(1), &["one"]));
    let added = world
        .service
        .add(
            &world.tenant,
            "spire.example",
            endpoint(ENDPOINT),
            Caller::system(),
        )
        .await
        .expect("added");
    assert_eq!(added.source(), TrustSource::BundleEndpoint);
    assert_eq!(added.bundle_endpoint_url(), Some(ENDPOINT));
    assert_eq!(world.endpoints.asked(), [ENDPOINT]);
    // The event never names the address.
    assert!(
        !world.payloads()[0]
            .to_string()
            .contains("spire.example.com")
    );

    let private = "https://10.0.0.1/bundle";
    world.endpoints.forbid(private);
    world
        .endpoints
        .serve("https://missing.example/b", &sample_bundle(None, &[]));
    world
        .endpoints
        .answer("https://broken.example/b", 500, b"{}");
    world.endpoints.answer("https://moved.example/b", 302, b"");
    world
        .endpoints
        .answer("https://large.example/b", 200, &vec![b' '; 64 * 1024 + 1]);
    world
        .endpoints
        .answer("https://notabundle.example/b", 200, b"[1, 2]");
    world
        .endpoints
        .fail("https://slow.example/b", "http.timed_out");
    world.endpoints.fail(
        "https://late-private.example/b",
        "http.destination_forbidden",
    );
    for (url, code) in [
        (private, "keys.bundle_endpoint_forbidden"),
        (
            "https://nowhere.example/b",
            "keys.bundle_endpoint_unreachable",
        ),
        (
            "https://broken.example/b",
            "keys.bundle_endpoint_unreachable",
        ),
        (
            "https://moved.example/b",
            "keys.bundle_endpoint_unreachable",
        ),
        (
            "https://large.example/b",
            "keys.bundle_endpoint_unreachable",
        ),
        ("https://notabundle.example/b", "keys.trust_bundle_invalid"),
        ("https://slow.example/b", "keys.bundle_endpoint_unreachable"),
        (
            "https://late-private.example/b",
            "keys.bundle_endpoint_forbidden",
        ),
        ("ftp://spire.example/b", "keys.bundle_endpoint_invalid"),
        (
            "https://user:pass@spire.example/b",
            "keys.bundle_endpoint_invalid",
        ),
    ] {
        let error = world
            .service
            .add(
                &world.tenant,
                "refused.example",
                endpoint(url),
                Caller::system(),
            )
            .await
            .expect_err(url);
        assert_eq!(error.code(), code, "{url}");
    }
    // A forbidden or unreadable address is never fetched.
    let asked = world.endpoints.asked();
    assert!(
        !asked
            .iter()
            .any(|url| url == private || url.starts_with("ftp"))
    );
    assert_eq!(world.events(), ["keys.trust_domain_added"]);
}

#[tokio::test]
async fn a_name_is_taken_once_and_a_tenant_has_at_most_fifty() {
    let world = world();
    world
        .service
        .add(
            &world.tenant,
            "cluster.local",
            TrustSourceRequest::Mesh,
            Caller::system(),
        )
        .await
        .expect("added");
    let error = world
        .service
        .add(
            &world.tenant,
            "cluster.local",
            TrustSourceRequest::Mesh,
            Caller::system(),
        )
        .await
        .expect_err("taken");
    assert_eq!(error.code(), "keys.trust_domain_name_taken");
    for index in 1..MAX_TRUST_DOMAINS {
        world
            .service
            .add(
                &world.tenant,
                &format!("d{index}.example"),
                TrustSourceRequest::Mesh,
                Caller::system(),
            )
            .await
            .expect("added");
    }
    let error = world
        .service
        .add(
            &world.tenant,
            "one-more.example",
            TrustSourceRequest::Mesh,
            Caller::system(),
        )
        .await
        .expect_err("too many");
    assert_eq!(error.code(), "keys.too_many_trust_domains");
}

#[tokio::test]
async fn a_replacement_that_does_not_read_leaves_the_previous_bundle() {
    let world = world();
    let added = world
        .service
        .add(
            &world.tenant,
            "prod.example",
            uploaded(&sample_bundle(Some(3), &["kept"])),
            Caller::system(),
        )
        .await
        .expect("added");
    let error = world
        .service
        .replace(
            &world.tenant,
            added.id(),
            uploaded(&serde_json::json!({"keys": [{"use": "x509-svid", "kty": "EC", "crv": "P-256", "x5c": []}]})),
            Caller::system(),
        )
        .await
        .expect_err("refused");
    assert_eq!(error.code(), "keys.trust_bundle_invalid");
    world.endpoints.answer(ENDPOINT, 503, b"");
    let error = world
        .service
        .replace(
            &world.tenant,
            added.id(),
            endpoint(ENDPOINT),
            Caller::system(),
        )
        .await
        .expect_err("refused");
    assert_eq!(error.code(), "keys.bundle_endpoint_unreachable");
    assert_eq!(
        world
            .service
            .get(&world.tenant, added.id())
            .await
            .expect("read"),
        added
    );

    // An administrator may go back to an older sequence number.
    let replaced = world
        .service
        .replace(
            &world.tenant,
            added.id(),
            uploaded(&sample_bundle(Some(1), &["older"])),
            Caller::system(),
        )
        .await
        .expect("replaced");
    assert!(
        replaced
            .bundle()
            .expect("bundle")
            .jwt_key("older")
            .is_some()
    );
    let replaced = world
        .service
        .replace(
            &world.tenant,
            added.id(),
            TrustSourceRequest::Mesh,
            Caller::system(),
        )
        .await
        .expect("replaced");
    assert_eq!(replaced.bundle(), None);
    assert_eq!(replaced.name().as_str(), "prod.example");
    assert_eq!(
        world.events(),
        [
            "keys.trust_domain_added",
            "keys.trust_domain_replaced",
            "keys.trust_domain_replaced"
        ]
    );
    let error = world
        .service
        .replace(
            &world.tenant,
            hodor_keys::api::TrustDomainId::generate(),
            TrustSourceRequest::Mesh,
            Caller::system(),
        )
        .await
        .expect_err("unknown");
    assert_eq!(error.code(), "keys.trust_domain_not_found");
}

#[tokio::test]
async fn a_removed_trust_domain_is_gone_and_audited() {
    let world = world();
    let added = world
        .service
        .add(
            &world.tenant,
            "cluster.local",
            TrustSourceRequest::Mesh,
            Caller::system(),
        )
        .await
        .expect("added");
    world
        .service
        .remove(&world.tenant, added.id(), Caller::system())
        .await
        .expect("removed");
    assert_eq!(
        world
            .service
            .remove(&world.tenant, added.id(), Caller::system())
            .await
            .expect_err("gone")
            .code(),
        "keys.trust_domain_not_found"
    );
    assert_eq!(
        world.events(),
        ["keys.trust_domain_added", "keys.trust_domain_removed"]
    );
    assert_eq!(world.payloads()[1]["name"], "cluster.local");
}

#[tokio::test]
async fn one_name_in_two_tenants_is_never_read_for_the_other() {
    let world = world();
    let other = TenantContext::assume(TenantId::generate());
    let ours = world
        .service
        .add(
            &world.tenant,
            "cluster.local",
            uploaded(&sample_bundle(Some(1), &["ours"])),
            Caller::system(),
        )
        .await
        .expect("ours");
    let theirs = world
        .service
        .add(
            &other,
            "cluster.local",
            uploaded(&sample_bundle(Some(1), &["theirs"])),
            Caller::system(),
        )
        .await
        .expect("theirs");
    let found = world
        .service
        .find_by_name(&world.tenant, "cluster.local")
        .await
        .expect("find")
        .expect("ours");
    assert_eq!(found.id(), ours.id());
    assert!(found.bundle().expect("bundle").jwt_key("theirs").is_none());
    assert_eq!(
        world
            .service
            .get(&other, ours.id())
            .await
            .expect_err("not theirs")
            .code(),
        "keys.trust_domain_not_found"
    );
    for (tenant, id) in [(&other, ours.id()), (&world.tenant, theirs.id())] {
        let error = world
            .service
            .replace(tenant, id, TrustSourceRequest::Mesh, Caller::system())
            .await
            .expect_err("not found");
        assert_eq!(error.code(), "keys.trust_domain_not_found");
        let error = world
            .service
            .remove(tenant, id, Caller::system())
            .await
            .expect_err("not found");
        assert_eq!(error.code(), "keys.trust_domain_not_found");
    }
}

#[tokio::test]
async fn the_worker_refreshes_keeps_on_failure_and_never_goes_back() {
    let world = world();
    world
        .endpoints
        .serve(ENDPOINT, &sample_bundle(Some(1), &["first"]));
    let added = world
        .service
        .add(
            &world.tenant,
            "spire.example",
            endpoint(ENDPOINT),
            Caller::system(),
        )
        .await
        .expect("added");
    world
        .service
        .add(
            &world.tenant,
            "uploaded.example",
            uploaded(&sample_bundle(None, &[])),
            Caller::system(),
        )
        .await
        .expect("added");
    world
        .service
        .add(
            &world.tenant,
            "cluster.local",
            TrustSourceRequest::Mesh,
            Caller::system(),
        )
        .await
        .expect("added");
    // Nothing is due before five minutes.
    assert!(world.refresh_all().await.is_empty());

    // The same bundle: nothing changes but the time of the fetch.
    world.clock.advance(Duration::minutes(5));
    assert_eq!(world.refresh_all().await, [RefreshOutcome::Unchanged]);
    let first = world.read(added.id()).await;
    assert_eq!(first.snapshot().fetched_at, Some(world.clock.now()));

    // A failure keeps the bundle and is audited once for a run of them.
    world.endpoints.answer(ENDPOINT, 500, b"");
    world.clock.advance(Duration::minutes(5));
    assert_eq!(world.refresh_all().await, [RefreshOutcome::Failed]);
    world.endpoints.serve(
        ENDPOINT,
        &serde_json::json!({"keys": [{"use": "jwt-svid"}]}),
    );
    world.clock.advance(Duration::minutes(5));
    assert_eq!(world.refresh_all().await, [RefreshOutcome::Failed]);
    // An older bundle is refused as well.
    world
        .endpoints
        .serve(ENDPOINT, &sample_bundle(Some(0), &["replayed"]));
    world.clock.advance(Duration::minutes(5));
    assert_eq!(world.refresh_all().await, [RefreshOutcome::Failed]);
    let failing = world.read(added.id()).await;
    assert_eq!(failing.bundle(), first.bundle());
    assert_eq!(
        failing.snapshot().last_error.as_deref(),
        Some("keys.trust_bundle_sequence_invalid")
    );
    assert!(failing.snapshot().failing_since.is_some());

    // A newer bundle replaces it.
    world
        .endpoints
        .serve(ENDPOINT, &sample_bundle(Some(2), &["second"]));
    world.clock.advance(Duration::minutes(5));
    assert_eq!(world.refresh_all().await, [RefreshOutcome::Changed]);
    let refreshed = world.read(added.id()).await;
    assert!(
        refreshed
            .bundle()
            .expect("bundle")
            .jwt_key("second")
            .is_some()
    );
    assert_eq!(refreshed.snapshot().failing_since, None);

    assert_eq!(
        world.events(),
        [
            "keys.trust_domain_added",
            "keys.trust_domain_added",
            "keys.trust_domain_added",
            "keys.trust_bundle_refresh_failed",
            "keys.trust_bundle_refreshed",
        ]
    );
    let payloads = world.payloads();
    assert_eq!(payloads[3]["reason"], "keys.bundle_endpoint_unreachable");
    assert_eq!(payloads[4]["sequence"], 2);
    assert_eq!(payloads[4]["previous_sequence"], 1);
    // Only the bundle endpoint was ever fetched.
    assert!(world.endpoints.asked().iter().all(|url| url == ENDPOINT));
}

#[tokio::test]
async fn a_fetch_is_dropped_when_an_administrator_changed_the_trust_domain_meanwhile() {
    let world = world();
    world
        .endpoints
        .serve(ENDPOINT, &sample_bundle(Some(1), &["first"]));
    let added = world
        .service
        .add(
            &world.tenant,
            "spire.example",
            endpoint(ENDPOINT),
            Caller::system(),
        )
        .await
        .expect("added");
    world.clock.advance(Duration::minutes(5));
    let leases = world.refresher.lease_due(8).await.expect("leased");
    assert_eq!(leases.len(), 1);
    // Leased: no second worker takes it.
    assert!(
        world
            .refresher
            .lease_due(8)
            .await
            .expect("leased")
            .is_empty()
    );
    world
        .service
        .replace(
            &world.tenant,
            added.id(),
            uploaded(&sample_bundle(None, &["by-hand"])),
            Caller::system(),
        )
        .await
        .expect("replaced");
    world
        .endpoints
        .serve(ENDPOINT, &sample_bundle(Some(9), &["fetched"]));
    let outcome = world
        .refresher
        .refresh(leases.into_iter().next().expect("lease"))
        .await
        .expect("refreshed");
    assert_eq!(outcome, RefreshOutcome::Skipped);
    let kept = world
        .service
        .get(&world.tenant, added.id())
        .await
        .expect("read");
    assert_eq!(kept.source(), TrustSource::Uploaded);
    assert!(kept.bundle().expect("bundle").jwt_key("by-hand").is_some());
}

#[tokio::test]
async fn a_lease_that_runs_out_is_taken_again() {
    let world = world();
    world
        .endpoints
        .serve(ENDPOINT, &sample_bundle(Some(1), &["first"]));
    world
        .service
        .add(
            &world.tenant,
            "spire.example",
            endpoint(ENDPOINT),
            Caller::system(),
        )
        .await
        .expect("added");
    world.clock.advance(Duration::minutes(5));
    assert_eq!(world.refresher.lease_due(8).await.expect("leased").len(), 1);
    world.clock.advance(Duration::seconds(71));
    let again = world.refresher.lease_due(8).await.expect("leased");
    assert_eq!(again.len(), 1);
    assert_eq!(
        world
            .refresher
            .refresh(again[0].clone())
            .await
            .expect("refreshed"),
        RefreshOutcome::Unchanged
    );
}

#[tokio::test]
async fn the_in_memory_store_passes_the_contract() {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let store = InMemoryTrustDomains::default();
    run_trust_domain_contract(TrustDomainContract {
        units_of_work: &units_of_work,
        store: &store,
        due: &store,
    })
    .await;
}
