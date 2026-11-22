//! The use cases of authenticator applications, run against the in-memory
//! store.

use hodor_credential::api::{
    ENROLLMENT_LIFETIME, STEP_SECONDS, TotpCheck, TotpEnrollment, TotpService, totp_code_at,
};
use hodor_credential::testing::{
    FakeHmacSha1, InMemoryTotps, TotpPorts, base32_secret, run_totp_contract,
};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::CountingRandom;
use hodor_kernel::sealing::testing::FakeSecretBox;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, Clock, Secret, TenantContext, TenantId, Timestamp, UserId};
use std::sync::Arc;
use time::Duration;

struct World {
    service: TotpService,
    clock: Arc<FixedClock>,
    store: InMemoryTotps,
    units_of_work: InMemoryUnitOfWorkFactory,
    tenant: TenantContext,
    user: UserId,
}

fn world() -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let store = InMemoryTotps::default();
    // Some moment well after the epoch, at the start of a step.
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + Duration::seconds(STEP_SECONDS * 60_000_000),
    ));
    World {
        service: TotpService::new(
            Arc::new(units_of_work.clone()),
            Arc::new(store.clone()),
            Arc::new(FakeSecretBox),
            Arc::new(FakeHmacSha1),
            Arc::new(CountingRandom::default()),
            clock.clone(),
        ),
        clock,
        store,
        units_of_work,
        tenant: TenantContext::assume(TenantId::generate()),
        user: UserId::generate(),
    }
}

fn code(value: &str) -> Secret<String> {
    Secret::from(value.to_owned())
}

impl World {
    async fn begin(&self) -> TotpEnrollment {
        self.service
            .begin_enrollment(&self.tenant, self.user, "Acme", "ana@example.com")
            .await
            .expect("begin")
    }

    /// What the person's phone shows now, `steps` steps away.
    fn phone(&self, enrollment: &TotpEnrollment, steps: i64) -> String {
        totp_code_at(
            &FakeHmacSha1,
            &base32_secret(enrollment.secret()),
            self.clock.now() + Duration::seconds(STEP_SECONDS * steps),
        )
    }

    async fn enrolled(&self) -> TotpEnrollment {
        let enrollment = self.begin().await;
        self.service
            .confirm_enrollment(
                &self.tenant,
                self.user,
                &code(&self.phone(&enrollment, 0)),
                Caller::system(),
            )
            .await
            .expect("confirm");
        // The confirming code is used; later checks use later steps.
        self.clock.advance(Duration::seconds(STEP_SECONDS));
        enrollment
    }

    async fn check(&self, typed: &str) -> TotpCheck {
        self.service
            .verify(&self.tenant, Some(self.user), &code(typed))
            .await
            .expect("verify")
    }
}

#[tokio::test]
async fn the_in_memory_store_passes_the_contract() {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let totps = InMemoryTotps::default();
    run_totp_contract(TotpPorts {
        units_of_work: &units_of_work,
        totps: &totps,
    })
    .await;
}

#[tokio::test]
async fn the_secret_is_given_once_and_stored_only_sealed() {
    let world = world();
    let enrollment = world.begin().await;
    let secret = base32_secret(enrollment.secret());
    assert_eq!(secret.len(), 20);
    assert!(
        enrollment
            .address()
            .starts_with("otpauth://totp/Acme:ana%40example.com?secret=")
    );

    let stored = {
        use hodor_credential::api::TotpStore;
        use hodor_kernel::UnitOfWorkFactory;
        let mut uow = world
            .units_of_work
            .begin(&world.tenant)
            .await
            .expect("begin");
        world
            .store
            .pending(uow.as_mut(), world.user)
            .await
            .expect("pending")
            .expect("waiting")
    };
    let sealed = stored.snapshot().sealed_secret.as_bytes();
    assert!(
        !sealed
            .windows(secret.len())
            .any(|window| window == secret.as_slice()),
        "the secret is stored in the clear"
    );
    // Nothing is announced until the enrollment is confirmed.
    assert!(world.units_of_work.committed_event_types().is_empty());
}

#[tokio::test]
async fn an_enrollment_is_put_in_use_only_with_a_right_code() {
    let world = world();
    let enrollment = world.begin().await;
    assert!(
        !world
            .service
            .has_totp(&world.tenant, world.user)
            .await
            .expect("has")
    );

    let error = world
        .service
        .confirm_enrollment(&world.tenant, world.user, &code("000000"), Caller::system())
        .await
        .expect_err("wrong code");
    assert_eq!(error.code(), "credential.totp_code_wrong");
    assert!(
        !world
            .service
            .has_totp(&world.tenant, world.user)
            .await
            .expect("has")
    );

    // The enrollment still waits after a wrong code.
    world
        .service
        .confirm_enrollment(
            &world.tenant,
            world.user,
            &code(&world.phone(&enrollment, 0)),
            Caller::system(),
        )
        .await
        .expect("confirm");
    assert!(
        world
            .service
            .has_totp(&world.tenant, world.user)
            .await
            .expect("has")
    );
    assert_eq!(
        world.units_of_work.committed_event_types(),
        vec!["credential.totp_enrolled"]
    );

    // There is nothing left to confirm.
    let error = world
        .service
        .confirm_enrollment(
            &world.tenant,
            world.user,
            &code(&world.phone(&enrollment, 0)),
            Caller::system(),
        )
        .await
        .expect_err("nothing waits");
    assert_eq!(error.code(), "credential.totp_enrollment_not_found");
}

#[tokio::test]
async fn an_enrollment_not_confirmed_in_time_is_gone() {
    let world = world();
    let enrollment = world.begin().await;
    world.clock.advance(ENROLLMENT_LIFETIME);
    let error = world
        .service
        .confirm_enrollment(
            &world.tenant,
            world.user,
            &code(&world.phone(&enrollment, 0)),
            Caller::system(),
        )
        .await
        .expect_err("too late");
    assert_eq!(error.code(), "credential.totp_enrollment_not_found");
}

#[tokio::test]
async fn the_code_that_confirmed_cannot_sign_in() {
    let world = world();
    let enrollment = world.begin().await;
    let confirming = world.phone(&enrollment, 0);
    world
        .service
        .confirm_enrollment(
            &world.tenant,
            world.user,
            &code(&confirming),
            Caller::system(),
        )
        .await
        .expect("confirm");
    assert_eq!(world.check(&confirming).await, TotpCheck::Rejected);
}

#[tokio::test]
async fn a_right_code_works_once() {
    let world = world();
    let enrollment = world.enrolled().await;
    let now = world.phone(&enrollment, 0);

    assert_eq!(world.check(&now).await, TotpCheck::Verified);
    assert_eq!(world.check(&now).await, TotpCheck::Rejected);
    // Nor does the code of the step before, which is earlier than the one used.
    assert_eq!(
        world.check(&world.phone(&enrollment, -1)).await,
        TotpCheck::Rejected
    );
    // The next step's code is still good.
    assert_eq!(
        world.check(&world.phone(&enrollment, 1)).await,
        TotpCheck::Verified
    );
}

#[tokio::test]
async fn codes_one_step_off_are_accepted_and_two_are_not() {
    for (steps, expected) in [
        (-2, TotpCheck::Rejected),
        (-1, TotpCheck::Verified),
        (1, TotpCheck::Verified),
        (2, TotpCheck::Rejected),
    ] {
        let world = world();
        let enrollment = world.enrolled().await;
        // Move far enough on that the confirming code is behind every case.
        world.clock.advance(Duration::seconds(STEP_SECONDS * 5));
        assert_eq!(
            world.check(&world.phone(&enrollment, steps)).await,
            expected,
            "{steps} steps"
        );
    }
}

#[tokio::test]
async fn anything_that_is_not_a_right_code_is_rejected_alike() {
    let world = world();
    let enrollment = world.enrolled().await;
    let right = world.phone(&enrollment, 0);
    let spaced = format!("{} {}", &right[..3], &right[3..]);
    for typed in ["", "12345", "1234567", "abcdef", "000000"] {
        if typed == right {
            continue;
        }
        assert_eq!(world.check(typed).await, TotpCheck::Rejected, "{typed}");
    }
    // Spaces are taken out, as applications show codes in two groups.
    assert_eq!(world.check(&spaced).await, TotpCheck::Verified);
}

#[tokio::test]
async fn nobody_and_people_without_an_application_are_rejected() {
    let world = world();
    let enrollment = world.begin().await;
    // An enrollment waiting to be confirmed does not sign anyone in.
    assert_eq!(
        world.check(&world.phone(&enrollment, 0)).await,
        TotpCheck::Rejected
    );
    assert_eq!(
        world
            .service
            .verify(&world.tenant, None, &code(&world.phone(&enrollment, 0)))
            .await
            .expect("verify"),
        TotpCheck::Rejected
    );
}

#[tokio::test]
async fn an_application_works_in_its_own_tenant_only() {
    let world = world();
    let enrollment = world.enrolled().await;
    let other = TenantContext::assume(TenantId::generate());
    assert!(
        !world
            .service
            .has_totp(&other, world.user)
            .await
            .expect("has")
    );
    assert_eq!(
        world
            .service
            .verify(
                &other,
                Some(world.user),
                &code(&world.phone(&enrollment, 0))
            )
            .await
            .expect("verify"),
        TotpCheck::Rejected
    );
    // The code was not used up by the other tenant.
    assert_eq!(
        world.check(&world.phone(&enrollment, 0)).await,
        TotpCheck::Verified
    );
}

#[tokio::test]
async fn a_new_application_replaces_the_old_one_only_once_confirmed() {
    let world = world();
    let old = world.enrolled().await;
    let new = world.begin().await;

    // Until the new one is confirmed, the old one still signs in.
    assert_eq!(
        world.check(&world.phone(&old, 0)).await,
        TotpCheck::Verified
    );
    world.clock.advance(Duration::seconds(STEP_SECONDS));
    world
        .service
        .confirm_enrollment(
            &world.tenant,
            world.user,
            &code(&world.phone(&new, 0)),
            Caller::system(),
        )
        .await
        .expect("confirm");
    world.clock.advance(Duration::seconds(STEP_SECONDS));
    assert_eq!(
        world.check(&world.phone(&old, 0)).await,
        TotpCheck::Rejected
    );
    assert_eq!(
        world.check(&world.phone(&new, 0)).await,
        TotpCheck::Verified
    );
}

#[tokio::test]
async fn removing_ends_the_application_and_is_announced_once() {
    let world = world();
    let enrollment = world.enrolled().await;
    assert!(
        world
            .service
            .remove(&world.tenant, world.user, Caller::system())
            .await
            .expect("remove")
    );
    assert!(
        !world
            .service
            .remove(&world.tenant, world.user, Caller::system())
            .await
            .expect("again")
    );
    assert_eq!(
        world.check(&world.phone(&enrollment, 0)).await,
        TotpCheck::Rejected
    );
    assert!(
        !world
            .service
            .has_totp(&world.tenant, world.user)
            .await
            .expect("has")
    );
    assert_eq!(
        world.units_of_work.committed_event_types(),
        vec!["credential.totp_enrolled", "credential.totp_removed"]
    );
}
