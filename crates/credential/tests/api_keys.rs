//! The use cases of API keys, run against the in-memory store.

use hodor_credential::api::{
    ApiKeyService, ApiKeySettings, ApiKeyStatus, DEFAULT_API_KEY_LIFETIME, DEFAULT_API_KEY_OVERLAP,
    REVOKED_BY_ADMINISTRATOR,
};
use hodor_credential::testing::{ApiKeyPorts, InMemoryApiKeys, run_api_key_contract};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, Clock as _, RandomSource, TenantContext, TenantId, Timestamp, UnitOfWorkFactory as _,
    UserId,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use time::Duration;

/// Different bytes at every call, so that every key is different.
#[derive(Default)]
struct Counting(AtomicU64);

impl RandomSource for Counting {
    fn fill(&self, buffer: &mut [u8]) {
        let value = self.0.fetch_add(1, Ordering::Relaxed).to_be_bytes();
        for (byte, source) in buffer.iter_mut().zip(value.iter().cycle()) {
            *byte = *source;
        }
    }
}

struct World {
    keys: ApiKeyService,
    clock: Arc<FixedClock>,
    units_of_work: InMemoryUnitOfWorkFactory,
    tenant: TenantContext,
    holder: UserId,
}

fn world() -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let clock = Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH));
    World {
        keys: ApiKeyService::new(
            Arc::new(units_of_work.clone()),
            Arc::new(InMemoryApiKeys::default()),
            Arc::new(FakeDigest),
            Arc::new(Counting::default()),
            clock.clone(),
        ),
        clock,
        units_of_work,
        tenant: TenantContext::assume(TenantId::generate()),
        holder: UserId::generate(),
    }
}

fn settings() -> ApiKeySettings {
    ApiKeySettings {
        name: "Nightly export".to_owned(),
        scopes: vec!["users:read".to_owned()],
        application: None,
    }
}

#[tokio::test]
async fn the_in_memory_store_passes_the_contract() {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    run_api_key_contract(ApiKeyPorts {
        units_of_work: &units_of_work,
        keys: &InMemoryApiKeys::default(),
    })
    .await;
}

#[tokio::test]
async fn a_key_is_shown_once_and_found_by_what_is_presented_until_it_ends() {
    let world = world();
    let (key, secret) = world
        .keys
        .create(
            &world.tenant,
            world.holder,
            settings(),
            DEFAULT_API_KEY_LIFETIME,
            Caller::system(),
        )
        .await
        .expect("made");
    assert_eq!(
        world.units_of_work.committed_event_types(),
        ["credential.api_key_created"]
    );
    let printed = format!("{:?}", world.units_of_work.committed_events());
    assert!(
        !printed.contains(&secret.expose()[9..]),
        "no event carries the key"
    );
    let listed = world
        .keys
        .list(&world.tenant, world.holder)
        .await
        .expect("listed");
    assert_eq!(listed, std::slice::from_ref(&key));
    assert!(!format!("{listed:?}").contains(&secret.expose()[9..]));

    // Found, and its use recorded once a minute.
    let found = world
        .keys
        .authenticate(&world.tenant, secret.expose())
        .await
        .expect("asked")
        .expect("found");
    assert_eq!(found.id(), key.id());
    let used = world
        .keys
        .list(&world.tenant, world.holder)
        .await
        .expect("listed");
    assert_eq!(used[0].snapshot().last_used_at, Some(Timestamp::UNIX_EPOCH));

    // Another tenant, a malformed value and an unknown one find nothing.
    let elsewhere = TenantContext::assume(TenantId::generate());
    assert!(
        world
            .keys
            .authenticate(&elsewhere, secret.expose())
            .await
            .expect("asked")
            .is_none()
    );
    for presented in ["hodor_ak_short", &format!("hodor_ak_{}", "f".repeat(64))] {
        assert!(
            world
                .keys
                .authenticate(&world.tenant, presented)
                .await
                .expect("asked")
                .is_none()
        );
    }

    // Expired, it is refused.
    world.clock.advance(DEFAULT_API_KEY_LIFETIME);
    assert!(
        world
            .keys
            .authenticate(&world.tenant, secret.expose())
            .await
            .expect("asked")
            .is_none()
    );
}

#[tokio::test]
async fn a_revoked_key_is_refused_at_once_and_revoking_it_again_changes_nothing() {
    let world = world();
    let (key, secret) = world
        .keys
        .create(
            &world.tenant,
            world.holder,
            settings(),
            DEFAULT_API_KEY_LIFETIME,
            Caller::system(),
        )
        .await
        .expect("made");
    let revoked = world
        .keys
        .revoke(
            &world.tenant,
            world.holder,
            key.id(),
            REVOKED_BY_ADMINISTRATOR,
            Caller::system(),
        )
        .await
        .expect("revoked");
    assert_eq!(revoked.status_at(world.clock.now()), ApiKeyStatus::Revoked);
    assert!(
        world
            .keys
            .authenticate(&world.tenant, secret.expose())
            .await
            .expect("asked")
            .is_none()
    );
    let before = world.units_of_work.committed_event_types().len();
    world
        .keys
        .revoke(
            &world.tenant,
            world.holder,
            key.id(),
            REVOKED_BY_ADMINISTRATOR,
            Caller::system(),
        )
        .await
        .expect("nothing to do");
    assert_eq!(world.units_of_work.committed_event_types().len(), before);
    // A key is the holder's only.
    let refused = world
        .keys
        .revoke(
            &world.tenant,
            UserId::generate(),
            key.id(),
            REVOKED_BY_ADMINISTRATOR,
            Caller::system(),
        )
        .await
        .expect_err("not theirs");
    assert_eq!(refused.code(), "credential.api_key_not_found");
}

#[tokio::test]
async fn a_rotated_key_works_for_the_overlap_and_then_only_the_new_one_does() {
    let world = world();
    let (old, first) = world
        .keys
        .create(
            &world.tenant,
            world.holder,
            settings(),
            DEFAULT_API_KEY_LIFETIME,
            Caller::system(),
        )
        .await
        .expect("made");
    let (next, second) = world
        .keys
        .rotate(
            &world.tenant,
            world.holder,
            old.id(),
            DEFAULT_API_KEY_LIFETIME,
            DEFAULT_API_KEY_OVERLAP,
            Caller::system(),
        )
        .await
        .expect("rotated");
    assert_eq!(
        world
            .units_of_work
            .committed_event_types()
            .last()
            .map(String::as_str),
        Some("credential.api_key_rotated")
    );
    for presented in [first.expose(), second.expose()] {
        assert!(
            world
                .keys
                .authenticate(&world.tenant, presented)
                .await
                .expect("asked")
                .is_some()
        );
    }
    world.clock.advance(DEFAULT_API_KEY_OVERLAP);
    assert!(
        world
            .keys
            .authenticate(&world.tenant, first.expose())
            .await
            .expect("asked")
            .is_none(),
        "the old key ended with the overlap"
    );
    let found = world
        .keys
        .authenticate(&world.tenant, second.expose())
        .await
        .expect("asked")
        .expect("the new key works");
    assert_eq!(found.id(), next.id());
    let refused = world
        .keys
        .rotate(
            &world.tenant,
            world.holder,
            old.id(),
            DEFAULT_API_KEY_LIFETIME,
            Duration::ZERO,
            Caller::system(),
        )
        .await
        .expect_err("only the newest of a line");
    assert_eq!(refused.code(), "credential.api_key_not_rotatable");
}

#[tokio::test]
async fn a_holder_has_at_most_ten_keys_that_work_and_they_are_revoked_together() {
    let world = world();
    let mut made = Vec::new();
    for _ in 0..10 {
        made.push(
            world
                .keys
                .create(
                    &world.tenant,
                    world.holder,
                    settings(),
                    DEFAULT_API_KEY_LIFETIME,
                    Caller::system(),
                )
                .await
                .expect("made")
                .0,
        );
    }
    let refused = world
        .keys
        .create(
            &world.tenant,
            world.holder,
            settings(),
            DEFAULT_API_KEY_LIFETIME,
            Caller::system(),
        )
        .await
        .expect_err("too many");
    assert_eq!(refused.code(), "credential.too_many_api_keys");
    // Rotating does not count twice.
    world
        .keys
        .rotate(
            &world.tenant,
            world.holder,
            made[0].id(),
            DEFAULT_API_KEY_LIFETIME,
            DEFAULT_API_KEY_OVERLAP,
            Caller::system(),
        )
        .await
        .expect("rotated");

    let mut uow = world
        .units_of_work
        .begin(&world.tenant)
        .await
        .expect("begin");
    let revoked = world
        .keys
        .revoke_all_of_in(
            uow.as_mut(),
            world.holder,
            "workload_deleted",
            Caller::system(),
        )
        .await
        .expect("revoked");
    uow.commit().await.expect("commit");
    assert_eq!(revoked, 11);
    let now = world.clock.now();
    assert!(
        world
            .keys
            .list(&world.tenant, world.holder)
            .await
            .expect("listed")
            .iter()
            .all(|key| key.status_at(now) == ApiKeyStatus::Revoked)
    );
}
