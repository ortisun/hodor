//! The use cases of recovery codes, run against the in-memory store.

use hodor_credential::api::{
    RECOVERY_CODES_PER_SET, RecoveryCodeCheck, RecoveryCodeService, RecoveryCodes,
};
use hodor_credential::testing::{
    InMemoryRecoveryCodes, RecoveryCodePorts, run_recovery_code_contract,
};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::{CountingRandom, FakeDigest};
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, Secret, TenantContext, TenantId, Timestamp, UserId};
use std::collections::BTreeSet;
use std::sync::Arc;

struct World {
    service: RecoveryCodeService,
    units_of_work: InMemoryUnitOfWorkFactory,
    tenant: TenantContext,
    user: UserId,
}

fn world() -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    World {
        service: RecoveryCodeService::new(
            Arc::new(units_of_work.clone()),
            Arc::new(InMemoryRecoveryCodes::default()),
            Arc::new(FakeDigest),
            Arc::new(CountingRandom::default()),
            Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH)),
        ),
        units_of_work,
        tenant: TenantContext::assume(TenantId::generate()),
        user: UserId::generate(),
    }
}

fn typed(code: &str) -> Secret<String> {
    Secret::from(code.to_owned())
}

impl World {
    async fn generate(&self) -> RecoveryCodes {
        self.service
            .generate(&self.tenant, self.user, Caller::system())
            .await
            .expect("generate")
    }

    async fn verify(&self, code: &str) -> RecoveryCodeCheck {
        self.service
            .verify(
                &self.tenant,
                Some(self.user),
                &typed(code),
                Caller::system(),
            )
            .await
            .expect("verify")
    }

    fn event_types(&self) -> Vec<String> {
        self.units_of_work
            .committed_events()
            .iter()
            .map(|event| event.event_type.clone())
            .collect()
    }
}

#[tokio::test]
async fn the_in_memory_store_passes_the_contract() {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    run_recovery_code_contract(RecoveryCodePorts {
        units_of_work: &units_of_work,
        codes: &InMemoryRecoveryCodes::default(),
    })
    .await;
}

#[tokio::test]
async fn a_set_is_ten_different_codes_in_four_groups() {
    let world = world();
    let codes = world.generate().await;
    let codes: Vec<&str> = codes.codes().collect();
    assert_eq!(codes.len(), RECOVERY_CODES_PER_SET);
    assert_eq!(codes.iter().collect::<BTreeSet<_>>().len(), codes.len());
    for code in &codes {
        let groups: Vec<&str> = code.split('-').collect();
        assert_eq!(groups.len(), 4, "{code}");
        assert!(groups.iter().all(|group| group.len() == 4), "{code}");
    }
    assert_eq!(
        world
            .service
            .unused(&world.tenant, world.user)
            .await
            .expect("unused"),
        10
    );
}

#[tokio::test]
async fn each_code_works_once() {
    let world = world();
    let codes = world.generate().await;
    let first = codes.codes().next().expect("a code").to_owned();
    assert_eq!(
        world.verify(&first).await,
        RecoveryCodeCheck::Verified { remaining: 9 }
    );
    assert_eq!(world.verify(&first).await, RecoveryCodeCheck::Rejected);
    let second = codes.codes().nth(1).expect("a code").to_owned();
    assert_eq!(
        world.verify(&second).await,
        RecoveryCodeCheck::Verified { remaining: 8 }
    );
}

#[tokio::test]
async fn a_code_is_read_as_the_person_may_type_it() {
    let world = world();
    let codes = world.generate().await;
    let code = codes.codes().next().expect("a code").to_owned();
    let sloppy = code.replace('-', " ").to_lowercase();
    assert_eq!(
        world.verify(&sloppy).await,
        RecoveryCodeCheck::Verified { remaining: 9 }
    );
}

#[tokio::test]
async fn anything_else_is_rejected_alike() {
    let world = world();
    let codes = world.generate().await;
    let code = codes.codes().next().expect("a code").to_owned();
    assert_eq!(
        world.verify("0000-0000-0000-0000").await,
        RecoveryCodeCheck::Rejected
    );
    assert_eq!(world.verify("123456").await, RecoveryCodeCheck::Rejected);
    assert_eq!(world.verify("").await, RecoveryCodeCheck::Rejected);
    // Nobody: the identifier of the sign-in belongs to no user.
    assert_eq!(
        world
            .service
            .verify(&world.tenant, None, &typed(&code), Caller::system())
            .await
            .expect("verify"),
        RecoveryCodeCheck::Rejected
    );
    // Another user of the tenant, and the same user in another tenant.
    assert_eq!(
        world
            .service
            .verify(
                &world.tenant,
                Some(UserId::generate()),
                &typed(&code),
                Caller::system()
            )
            .await
            .expect("verify"),
        RecoveryCodeCheck::Rejected
    );
    assert_eq!(
        world
            .service
            .verify(
                &TenantContext::assume(TenantId::generate()),
                Some(world.user),
                &typed(&code),
                Caller::system()
            )
            .await
            .expect("verify"),
        RecoveryCodeCheck::Rejected
    );
    // None of these used the code.
    assert_eq!(
        world.verify(&code).await,
        RecoveryCodeCheck::Verified { remaining: 9 }
    );
}

#[tokio::test]
async fn generating_again_ends_the_whole_old_set() {
    let world = world();
    let old = world.generate().await;
    let used = old.codes().next().expect("a code").to_owned();
    let unused = old.codes().nth(1).expect("a code").to_owned();
    world.verify(&used).await;
    let new = world.generate().await;
    assert_eq!(world.verify(&unused).await, RecoveryCodeCheck::Rejected);
    assert_eq!(world.verify(&used).await, RecoveryCodeCheck::Rejected);
    let fresh = new.codes().next().expect("a code").to_owned();
    assert_eq!(
        world.verify(&fresh).await,
        RecoveryCodeCheck::Verified { remaining: 9 }
    );
}

#[tokio::test]
async fn a_set_is_generated_at_enrollment_only_without_an_unused_code() {
    let world = world();
    let first = world
        .service
        .generate_if_none(&world.tenant, world.user, Caller::system())
        .await
        .expect("first");
    let first = first.expect("a set for a user without one");
    assert!(
        world
            .service
            .generate_if_none(&world.tenant, world.user, Caller::system())
            .await
            .expect("second")
            .is_none(),
        "a user with unused codes keeps them"
    );
    for code in first.codes() {
        world.verify(code).await;
    }
    assert!(
        world
            .service
            .generate_if_none(&world.tenant, world.user, Caller::system())
            .await
            .expect("third")
            .is_some(),
        "a user whose codes are all used gets a new set"
    );
}

#[tokio::test]
async fn removing_takes_the_set_away() {
    let world = world();
    let codes = world.generate().await;
    assert!(
        world
            .service
            .remove(&world.tenant, world.user, Caller::system())
            .await
            .expect("remove")
    );
    let code = codes.codes().next().expect("a code").to_owned();
    assert_eq!(world.verify(&code).await, RecoveryCodeCheck::Rejected);
    assert!(
        !world
            .service
            .remove(&world.tenant, world.user, Caller::system())
            .await
            .expect("again")
    );
}

#[tokio::test]
async fn every_change_and_every_use_is_an_event_that_carries_no_code() {
    let world = world();
    let codes = world.generate().await;
    let code = codes.codes().next().expect("a code").to_owned();
    world.verify(&code).await;
    world.verify(&code).await;
    world
        .service
        .remove(&world.tenant, world.user, Caller::system())
        .await
        .expect("remove");
    assert_eq!(
        world.event_types(),
        [
            "credential.recovery_codes_generated",
            "credential.recovery_code_used",
            "credential.recovery_codes_removed",
        ]
    );
    let payloads: String = world
        .units_of_work
        .committed_events()
        .iter()
        .map(|event| event.payload.to_string())
        .collect();
    for code in codes.codes() {
        assert!(!payloads.contains(code), "{payloads}");
        assert!(!payloads.contains(&code.replace('-', "")), "{payloads}");
    }
    assert!(payloads.contains("\"remaining\":9"), "{payloads}");
}
