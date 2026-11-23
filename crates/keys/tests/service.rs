//! The keys use cases, run against the in-memory store and the stand-in
//! provider.

use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, Clock as _, Secret, TenantContext, TenantId, Timestamp};
use hodor_keys::api::{
    KeyAlgorithm, KeyProvider, KeyService, KeyState, KeyUse, KeyVersion, KeyVersionId,
    RotationPolicy, RotationReport,
};
use hodor_keys::testing::{FakeKeyProvider, InMemoryKeys, Ports, pending_version, run_contract};
use std::sync::Arc;
use time::Duration;

struct World {
    service: KeyService,
    clock: Arc<FixedClock>,
    units_of_work: InMemoryUnitOfWorkFactory,
    tenant: TenantContext,
}

fn world() -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let clock = Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH));
    let service = KeyService::new(
        Arc::new(units_of_work.clone()),
        Arc::new(InMemoryKeys::default()),
        Arc::new(FakeKeyProvider),
        clock.clone(),
    );
    World {
        service,
        clock,
        units_of_work,
        tenant: TenantContext::assume(TenantId::generate()),
    }
}

impl World {
    async fn made(&self, algorithm: KeyAlgorithm) -> KeyVersion {
        self.service
            .create_version(&self.tenant, algorithm, Caller::system())
            .await
            .expect("create")
    }

    async fn activate(&self, id: KeyVersionId, overlap: Duration) -> KeyVersion {
        self.service
            .activate(&self.tenant, id, overlap, Caller::system())
            .await
            .expect("activate")
    }

    async fn state(&self, id: KeyVersionId) -> KeyState {
        let set = self
            .service
            .key_set(&self.tenant, KeyUse::Signing)
            .await
            .expect("set");
        set.version(id).expect("in the set").state()
    }
}

#[tokio::test]
async fn the_in_memory_store_passes_the_contract() {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    run_contract(Ports {
        units_of_work: &units_of_work,
        keys: &InMemoryKeys::default(),
    })
    .await;
}

#[tokio::test]
async fn a_new_version_is_pending_with_the_providers_key_and_signs_nothing() {
    let world = world();
    let version = world.made(KeyAlgorithm::Es256).await;
    assert_eq!(version.state(), KeyState::Pending);
    assert_eq!(version.snapshot().provider, "fake");
    assert!(version.public_key().is_some());
    assert_eq!(
        world.units_of_work.committed_event_types(),
        vec!["keys.version_created"]
    );

    let error = world
        .service
        .sign(&world.tenant, KeyAlgorithm::Es256, b"message")
        .await
        .expect_err("nothing active");
    assert_eq!(error.code(), "keys.no_active_version");
}

#[tokio::test]
async fn the_active_version_signs_and_says_which_it_is() {
    let world = world();
    let version = world.made(KeyAlgorithm::Es256).await;
    world.activate(version.id(), Duration::ZERO).await;

    let signature = world
        .service
        .sign(&world.tenant, KeyAlgorithm::Es256, b"message")
        .await
        .expect("sign");
    assert_eq!(signature.key_version_id, version.id());
    assert_eq!(signature.algorithm, KeyAlgorithm::Es256);
    assert!(signature.bytes.ends_with(b"message"));

    let error = world
        .service
        .sign(&world.tenant, KeyAlgorithm::Rs256, b"message")
        .await
        .expect_err("no RS256 key");
    assert_eq!(error.code(), "keys.no_active_version");
    let error = world
        .service
        .sign(&world.tenant, KeyAlgorithm::A256Gcm, b"message")
        .await
        .expect_err("does not sign");
    assert_eq!(error.code(), "keys.algorithm_unsuitable");
}

#[tokio::test]
async fn rotating_signs_with_the_new_version_and_keeps_the_old_until_its_time() {
    let world = world();
    let first = world.made(KeyAlgorithm::Es256).await;
    world.activate(first.id(), Duration::ZERO).await;
    let second = world.made(KeyAlgorithm::Es256).await;
    world.activate(second.id(), Duration::minutes(10)).await;

    assert_eq!(world.state(first.id()).await, KeyState::Retiring);
    assert_eq!(world.state(second.id()).await, KeyState::Active);
    let signature = world
        .service
        .sign(&world.tenant, KeyAlgorithm::Es256, b"m")
        .await
        .expect("sign");
    assert_eq!(signature.key_version_id, second.id());

    let error = world
        .service
        .retire(&world.tenant, first.id(), Caller::system())
        .await
        .expect_err("too early");
    assert_eq!(error.code(), "keys.still_needed");
    world.clock.advance(Duration::minutes(10));
    let retired = world
        .service
        .retire(&world.tenant, first.id(), Caller::system())
        .await
        .expect("retire");
    assert_eq!(retired.state(), KeyState::Retired);

    let set = world
        .service
        .key_set(&world.tenant, KeyUse::Signing)
        .await
        .expect("set");
    let checking: Vec<KeyVersionId> = set
        .versions()
        .iter()
        .filter(|version| version.checks())
        .map(KeyVersion::id)
        .collect();
    assert_eq!(checking, vec![second.id()]);
    assert_eq!(
        world.units_of_work.committed_event_types(),
        vec![
            "keys.version_created",
            "keys.version_activated",
            "keys.version_created",
            "keys.version_activated",
            "keys.version_retired",
        ]
    );
}

#[tokio::test]
async fn a_revoked_active_version_never_signs_again() {
    let world = world();
    let version = world.made(KeyAlgorithm::Rs256).await;
    world.activate(version.id(), Duration::ZERO).await;
    let revoked = world
        .service
        .revoke(&world.tenant, version.id(), "leaked", Caller::system())
        .await
        .expect("revoke");
    assert_eq!(revoked.state(), KeyState::Revoked);
    let error = world
        .service
        .sign(&world.tenant, KeyAlgorithm::Rs256, b"m")
        .await
        .expect_err("revoked");
    assert_eq!(error.code(), "keys.no_active_version");

    // Revoking again changes nothing and records nothing.
    let events = world.units_of_work.committed_event_types().len();
    world
        .service
        .revoke(&world.tenant, version.id(), "again", Caller::system())
        .await
        .expect("no change");
    assert_eq!(world.units_of_work.committed_event_types().len(), events);
    let error = world
        .service
        .activate(
            &world.tenant,
            version.id(),
            Duration::ZERO,
            Caller::system(),
        )
        .await
        .expect_err("revoked");
    assert_eq!(error.code(), "keys.not_pending");
}

#[tokio::test]
async fn events_carry_no_key_material() {
    let world = world();
    let version = world.made(KeyAlgorithm::Es256).await;
    world.activate(version.id(), Duration::hours(1)).await;
    world
        .service
        .revoke(&world.tenant, version.id(), "leaked", Caller::system())
        .await
        .expect("revoke");
    let material = String::from_utf8_lossy(version.material().as_bytes()).into_owned();
    for event in world.units_of_work.committed_events() {
        let payload = serde_json::to_string(&event.payload).expect("payload");
        assert!(
            !payload.contains(&material),
            "{} carries key material",
            event.event_type
        );
    }
}

#[tokio::test]
async fn a_version_of_another_tenant_is_not_found() {
    let world = world();
    let version = world.made(KeyAlgorithm::Es256).await;
    let elsewhere = TenantContext::assume(TenantId::generate());
    for error in [
        world
            .service
            .activate(&elsewhere, version.id(), Duration::ZERO, Caller::system())
            .await
            .expect_err("other tenant"),
        world
            .service
            .revoke(&elsewhere, version.id(), "x", Caller::system())
            .await
            .expect_err("other tenant"),
        world
            .service
            .retire(&elsewhere, version.id(), Caller::system())
            .await
            .expect_err("other tenant"),
    ] {
        assert_eq!(error.code(), "keys.version_not_found");
    }
    assert!(
        world
            .service
            .key_set(&elsewhere, KeyUse::Signing)
            .await
            .expect("set")
            .versions()
            .is_empty()
    );
}

#[tokio::test]
async fn the_stand_in_provider_refuses_material_of_another_tenant_or_use() {
    let tenant = TenantContext::assume(TenantId::generate());
    let elsewhere = TenantContext::assume(TenantId::generate());
    let signing = pending_version(&tenant, KeyAlgorithm::Es256, Timestamp::UNIX_EPOCH);
    let data = pending_version(&tenant, KeyAlgorithm::A256Gcm, Timestamp::UNIX_EPOCH);
    let provider = FakeKeyProvider;

    assert!(provider.sign(&tenant, &signing, b"m").await.is_ok());
    assert!(provider.sign(&elsewhere, &signing, b"m").await.is_err());
    assert!(provider.sign(&tenant, &data, b"m").await.is_err());

    let secret = Secret::new(b"secret".to_vec());
    let sealed = provider
        .encrypt(&tenant, &data, b"purpose", &secret)
        .await
        .expect("encrypt");
    let opened = provider
        .decrypt(&tenant, &data, b"purpose", &sealed)
        .await
        .expect("decrypt");
    assert_eq!(opened.expose(), secret.expose());
    assert!(
        provider
            .decrypt(&tenant, &data, b"other", &sealed)
            .await
            .is_err()
    );
    assert!(
        provider
            .encrypt(&tenant, &signing, b"purpose", &secret)
            .await
            .is_err()
    );
}

fn policy() -> RotationPolicy {
    RotationPolicy::DEFAULT
}

impl World {
    async fn rotate_due(&self) -> RotationReport {
        self.service
            .rotate_due(&self.tenant, &policy(), Caller::system())
            .await
            .expect("rotate")
    }

    async fn published(&self) -> Vec<(KeyVersionId, KeyState)> {
        self.service
            .published_keys(&self.tenant)
            .await
            .expect("published")
            .iter()
            .map(|version| (version.id(), version.state()))
            .collect()
    }
}

#[tokio::test]
async fn rotation_gives_a_tenant_its_first_key_then_replaces_it_on_schedule() {
    let world = world();
    let first = world.rotate_due().await;
    assert_eq!(
        first,
        RotationReport {
            created: 1,
            activated: 1,
            retired: 0
        }
    );
    let signature = world
        .service
        .sign(&world.tenant, KeyAlgorithm::Es256, b"token")
        .await
        .expect("the first key signs");
    let original = signature.key_version_id;
    assert_eq!(world.rotate_due().await, RotationReport::default());

    // A day before the period ends, the next key is made and published.
    world
        .clock
        .advance(policy().period() - policy().publication());
    assert_eq!(world.rotate_due().await.created, 1);
    let published = world.published().await;
    assert_eq!(published.len(), 2);
    assert_eq!(published[0].1, KeyState::Pending);
    let next = published[0].0;
    assert_eq!(
        world
            .service
            .sign(&world.tenant, KeyAlgorithm::Es256, b"token")
            .await
            .expect("sign")
            .key_version_id,
        original,
        "a published key does not sign before its time"
    );

    // At the end of the period it signs, and the old one stays published.
    world.clock.advance(policy().publication());
    assert_eq!(world.rotate_due().await.activated, 1);
    assert_eq!(
        world.published().await,
        vec![(next, KeyState::Active), (original, KeyState::Retiring)]
    );
    assert_eq!(
        world
            .service
            .sign(&world.tenant, KeyAlgorithm::Es256, b"token")
            .await
            .expect("sign")
            .key_version_id,
        next
    );

    // After the overlap the old one is retired and leaves the key set.
    world.clock.advance(policy().overlap());
    assert_eq!(world.rotate_due().await.retired, 1);
    assert_eq!(world.published().await, vec![(next, KeyState::Active)]);
    assert_eq!(
        world.units_of_work.committed_event_types(),
        vec![
            "keys.version_created",
            "keys.version_activated",
            "keys.version_created",
            "keys.version_activated",
            "keys.version_retired",
        ]
    );
}

#[tokio::test]
async fn rotating_by_hand_signs_at_once_with_the_published_key_if_there_is_one() {
    let world = world();
    world.rotate_due().await;
    let original = world.published().await[0].0;

    let rotated = world
        .service
        .rotate_now(
            &world.tenant,
            KeyAlgorithm::Es256,
            &policy(),
            Caller::system(),
        )
        .await
        .expect("rotate");
    assert_eq!(rotated.state(), KeyState::Active);
    assert_eq!(
        world.published().await,
        vec![
            (rotated.id(), KeyState::Active),
            (original, KeyState::Retiring)
        ]
    );
    let set = world
        .service
        .key_set(&world.tenant, KeyUse::Signing)
        .await
        .expect("set");
    let replaced = set.version(original).expect("kept").snapshot();
    assert_eq!(
        replaced.retire_after,
        Some(world.clock.now() + policy().overlap()),
        "the replaced key stays for the policy's overlap"
    );

    // With a key already published, that one is activated.
    let pending = world.made(KeyAlgorithm::Es256).await;
    let again = world
        .service
        .rotate_now(
            &world.tenant,
            KeyAlgorithm::Es256,
            &policy(),
            Caller::system(),
        )
        .await
        .expect("rotate");
    assert_eq!(again.id(), pending.id());
}

#[tokio::test]
async fn only_a_signing_key_is_rotated_by_hand() {
    let world = world();
    let error = world
        .service
        .rotate_now(
            &world.tenant,
            KeyAlgorithm::A256Gcm,
            &policy(),
            Caller::system(),
        )
        .await
        .expect_err("refused");
    assert_eq!(error.code(), "keys.algorithm_unsuitable");
    assert!(world.units_of_work.committed_event_types().is_empty());
}

#[tokio::test]
async fn a_revoked_key_leaves_the_published_set_and_rotation_replaces_it() {
    let world = world();
    world.rotate_due().await;
    let original = world.published().await[0].0;
    world
        .service
        .revoke(&world.tenant, original, "leaked", Caller::system())
        .await
        .expect("revoke");
    assert!(world.published().await.is_empty());

    let report = world.rotate_due().await;
    assert_eq!((report.created, report.activated), (1, 1));
    let published = world.published().await;
    assert_eq!(published.len(), 1);
    assert_ne!(published[0].0, original);
}

#[tokio::test]
async fn the_published_keys_of_one_tenant_are_not_those_of_another() {
    let world = world();
    world.rotate_due().await;
    let elsewhere = TenantContext::assume(TenantId::generate());
    assert!(
        world
            .service
            .published_keys(&elsewhere)
            .await
            .expect("published")
            .is_empty()
    );
    world
        .service
        .rotate_due(&elsewhere, &policy(), Caller::system())
        .await
        .expect("rotate");
    let theirs = world
        .service
        .published_keys(&elsewhere)
        .await
        .expect("published");
    let ours = world.published().await;
    assert_eq!((theirs.len(), ours.len()), (1, 1));
    assert_ne!(theirs[0].id(), ours[0].0);
}

#[tokio::test]
async fn an_algorithm_other_than_the_default_gets_its_first_key_when_something_must_sign_with_it() {
    let world = world();
    let made = world
        .service
        .ensure_active(&world.tenant, KeyAlgorithm::Rs256, Caller::system())
        .await
        .expect("made");
    assert_eq!(made.algorithm(), KeyAlgorithm::Rs256);
    assert_eq!(
        made.state(),
        KeyState::Active,
        "it signs at once, as a first key does"
    );
    assert_eq!(
        world.units_of_work.committed_event_types(),
        vec!["keys.version_created", "keys.version_activated"]
    );

    let again = world
        .service
        .ensure_active(&world.tenant, KeyAlgorithm::Rs256, Caller::system())
        .await
        .expect("found");
    assert_eq!(again.id(), made.id(), "the active one is kept");
    assert_eq!(
        world.units_of_work.committed_event_types().len(),
        2,
        "nothing more is made"
    );

    let error = world
        .service
        .ensure_active(&world.tenant, KeyAlgorithm::A256Gcm, Caller::system())
        .await
        .expect_err("does not sign");
    assert_eq!(error.code(), "keys.algorithm_unsuitable");
}
