//! The access token use cases, run against the in-memory store.

use hodor_credential::api::{AccessTokenId, AccessTokenService};
use hodor_credential::testing::{
    AccessTokenPorts, InMemoryAccessTokens, run_access_token_contract,
};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::{CountingRandom, FakeDigest};
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, TenantContext, TenantId, Timestamp, UserId};
use std::sync::Arc;
use time::Duration;

struct World {
    service: AccessTokenService,
    clock: Arc<FixedClock>,
    units_of_work: InMemoryUnitOfWorkFactory,
    tenant: TenantContext,
    user: UserId,
}

fn world() -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let clock = Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH));
    World {
        service: AccessTokenService::new(
            Arc::new(units_of_work.clone()),
            Arc::new(InMemoryAccessTokens::default()),
            Arc::new(FakeDigest),
            Arc::new(CountingRandom::default()),
            clock.clone(),
        ),
        clock,
        units_of_work,
        tenant: TenantContext::assume(TenantId::generate()),
        user: UserId::generate(),
    }
}

impl World {
    async fn issue(&self) -> (AccessTokenId, String) {
        let (token, secret) = self
            .service
            .issue(
                &self.tenant,
                self.user,
                "automation",
                Duration::hours(1),
                Caller::system(),
            )
            .await
            .expect("issue");
        (token.id(), secret.expose().to_owned())
    }

    async fn user_of(&self, tenant: &TenantContext, presented: &str) -> Option<UserId> {
        self.service
            .authenticate(tenant, presented)
            .await
            .expect("authenticate")
            .map(|token| token.user_id())
    }
}

#[tokio::test]
async fn the_in_memory_store_passes_the_contract() {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let tokens = InMemoryAccessTokens::default();
    run_access_token_contract(AccessTokenPorts {
        units_of_work: &units_of_work,
        tokens: &tokens,
    })
    .await;
}

#[tokio::test]
async fn an_issued_token_names_its_user_in_its_tenant_only() {
    let world = world();
    let (_, token) = world.issue().await;

    assert_eq!(world.user_of(&world.tenant, &token).await, Some(world.user));
    let other = TenantContext::assume(TenantId::generate());
    assert_eq!(world.user_of(&other, &token).await, None);
}

#[tokio::test]
async fn a_token_that_is_not_good_finds_nothing_whatever_the_reason() {
    let world = world();
    let (revoked_id, revoked) = world.issue().await;
    let (_, expiring) = world.issue().await;
    world
        .service
        .revoke(&world.tenant, revoked_id, Caller::system())
        .await
        .expect("revoke");
    world.clock.advance(Duration::hours(1));

    let unknown = format!("hodor_at_{}", "0".repeat(64));
    for presented in [
        revoked.as_str(),
        expiring.as_str(),
        unknown.as_str(),
        "",
        "Bearer x",
    ] {
        assert_eq!(
            world.user_of(&world.tenant, presented).await,
            None,
            "{presented}"
        );
    }
}

#[tokio::test]
async fn revoking_is_announced_once_and_an_unknown_token_cannot_be_revoked() {
    let world = world();
    let (id, _) = world.issue().await;
    for _ in 0..2 {
        world
            .service
            .revoke(&world.tenant, id, Caller::system())
            .await
            .expect("revoke");
    }
    assert_eq!(
        world.units_of_work.committed_event_types(),
        [
            "credential.access_token_issued",
            "credential.access_token_revoked"
        ]
    );

    let error = world
        .service
        .revoke(&world.tenant, AccessTokenId::generate(), Caller::system())
        .await
        .expect_err("unknown");
    assert_eq!(error.code(), "credential.access_token_not_found");
    let other = TenantContext::assume(TenantId::generate());
    let error = world
        .service
        .revoke(&other, id, Caller::system())
        .await
        .expect_err("another tenant's");
    assert_eq!(error.code(), "credential.access_token_not_found");
}

#[tokio::test]
async fn nothing_announced_contains_the_token() {
    let world = world();
    let (id, token) = world.issue().await;
    world
        .service
        .revoke(&world.tenant, id, Caller::system())
        .await
        .expect("revoke");

    let announced = format!("{:?}", world.units_of_work.committed_events());
    assert!(!announced.contains(&token), "{announced}");
    assert!(!announced.contains(&token[9..]), "{announced}");
    assert!(announced.contains(&id.to_string()));
}

#[tokio::test]
async fn a_token_that_is_not_acceptable_is_not_issued() {
    let world = world();
    let error = world
        .service
        .issue(
            &world.tenant,
            world.user,
            "automation",
            Duration::days(365),
            Caller::system(),
        )
        .await
        .expect_err("too long");
    assert_eq!(error.code(), "credential.access_token_lifetime_invalid");
    assert!(world.units_of_work.committed_events().is_empty());
}
