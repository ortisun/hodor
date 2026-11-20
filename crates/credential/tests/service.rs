//! The credential use cases, run against the in-memory store and the fake
//! hasher.

use hodor_credential::api::{CredentialService, NewPassword, PasswordCheck, PasswordRules};
use hodor_credential::testing::{FakeHasher, InMemoryPasswords, Ports, run_contract};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, ErrorKind, Secret, TenantContext, TenantId, Timestamp, UserId};
use std::sync::Arc;

const RULES: PasswordRules = PasswordRules {
    min_length: 12,
    max_length: 128,
    history_depth: 2,
};

struct World {
    service: CredentialService,
    hasher: Arc<FakeHasher>,
    units_of_work: InMemoryUnitOfWorkFactory,
    tenant: TenantContext,
    user: UserId,
}

fn world() -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let hasher = Arc::new(FakeHasher::default());
    let service = CredentialService::new(
        Arc::new(units_of_work.clone()),
        Arc::new(InMemoryPasswords::default()),
        hasher.clone(),
        Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH)),
    );
    World {
        service,
        hasher,
        units_of_work,
        tenant: TenantContext::assume(TenantId::generate()),
        user: UserId::generate(),
    }
}

fn secret(value: &str) -> Secret<String> {
    Secret::from(value.to_owned())
}

impl World {
    async fn set(&self, password: &str) -> Result<(), hodor_kernel::DomainError> {
        let password = secret(password);
        let new = NewPassword {
            password: &password,
            rules: RULES,
            own_names: &["ana@example.com"],
        };
        self.service
            .set_password(&self.tenant, self.user, new, false, Caller::system())
            .await
    }

    async fn change(&self, current: &str, password: &str) -> Result<(), hodor_kernel::DomainError> {
        let password = secret(password);
        let new = NewPassword {
            password: &password,
            rules: RULES,
            own_names: &["ana@example.com"],
        };
        self.service
            .change_password(
                &self.tenant,
                self.user,
                &secret(current),
                new,
                Caller::system(),
            )
            .await
    }

    async fn check(&self, user: Option<UserId>, password: &str) -> PasswordCheck {
        self.service
            .verify_password(&self.tenant, user, &secret(password))
            .await
            .expect("verify")
    }
}

#[tokio::test]
async fn the_in_memory_store_passes_the_contract() {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let passwords = InMemoryPasswords::default();
    run_contract(Ports {
        units_of_work: &units_of_work,
        passwords: &passwords,
    })
    .await;
}

#[tokio::test]
async fn a_set_password_verifies_and_a_wrong_one_does_not() {
    let world = world();
    world.set("first password ok").await.expect("set");

    assert_eq!(
        world.check(Some(world.user), "first password ok").await,
        PasswordCheck::Verified { must_change: false }
    );
    assert_eq!(
        world.check(Some(world.user), "first password no").await,
        PasswordCheck::Rejected
    );
    assert_eq!(
        world.units_of_work.committed_event_types(),
        ["credential.password_set"]
    );
}

#[tokio::test]
async fn nothing_derived_from_the_password_reaches_an_event() {
    let world = world();
    world.set("a very private password").await.expect("set");
    world
        .change("a very private password", "another private password")
        .await
        .expect("change");
    let published = format!("{:?}", world.units_of_work.committed_events());
    assert!(!published.contains("private password"), "{published}");
    assert!(!published.contains("fake$"), "{published}");
}

#[tokio::test]
async fn no_user_no_password_and_wrong_password_are_the_same_answer_with_the_same_work() {
    let world = world();
    world.set("first password ok").await.expect("set");
    let nobody = UserId::generate();

    // One real verification for the user with a password...
    assert_eq!(
        world.check(Some(world.user), "wrong password!!").await,
        PasswordCheck::Rejected
    );
    assert_eq!(
        (
            world.hasher.verifications(),
            world.hasher.checks_against_nothing()
        ),
        (1, 0)
    );

    // ...and one computation of equal cost in every other case.
    assert_eq!(
        world.check(Some(nobody), "wrong password!!").await,
        PasswordCheck::Rejected
    );
    assert_eq!(
        world.check(None, "wrong password!!").await,
        PasswordCheck::Rejected
    );
    let oversized = "x".repeat(5000);
    assert_eq!(
        world.check(Some(world.user), &oversized).await,
        PasswordCheck::Rejected
    );
    assert_eq!(
        (
            world.hasher.verifications(),
            world.hasher.checks_against_nothing()
        ),
        (1, 3)
    );
}

#[tokio::test]
async fn unacceptable_passwords_are_refused_before_anything_is_hashed() {
    let world = world();
    for (password, code) in [
        ("too short", "credential.password_too_short"),
        ("ANA@EXAMPLE.COM", "credential.password_is_own_name"),
    ] {
        let error = world.set(password).await.expect_err(password);
        assert_eq!(error.code(), code);
    }
    assert_eq!(world.hasher.hashes(), 0);
    assert!(world.units_of_work.committed_events().is_empty());
    assert!(
        !world
            .service
            .has_password(&world.tenant, world.user)
            .await
            .expect("has")
    );
}

#[tokio::test]
async fn recent_passwords_cannot_be_reused_until_they_leave_the_history() {
    let world = world();
    world.set("password number 1").await.expect("first");
    world
        .change("password number 1", "password number 2")
        .await
        .expect("second");
    world
        .change("password number 2", "password number 3")
        .await
        .expect("third");

    // The current one and the two before it are barred (history depth 2).
    for barred in [
        "password number 3",
        "password number 2",
        "password number 1",
    ] {
        let error = world
            .change("password number 3", barred)
            .await
            .expect_err(barred);
        assert_eq!(error.code(), "credential.password_reused", "{barred}");
    }

    // One more change pushes the oldest out of the history.
    world
        .change("password number 3", "password number 4")
        .await
        .expect("fourth");
    world
        .change("password number 4", "password number 1")
        .await
        .expect("the oldest password is free again");
}

#[tokio::test]
async fn changing_requires_the_current_password() {
    let world = world();
    world.set("the current password").await.expect("set");

    let error = world
        .change("not the current one", "a brand new password")
        .await
        .expect_err("wrong current");
    assert_eq!(error.kind(), ErrorKind::Unauthenticated);
    assert_eq!(error.code(), "credential.current_password_wrong");
    assert_eq!(
        world.check(Some(world.user), "the current password").await,
        PasswordCheck::Verified { must_change: false }
    );

    // A user without a password gets the same error, after equal work.
    let other = World {
        user: UserId::generate(),
        ..world
    };
    let error = other
        .change("anything at all!", "a brand new password")
        .await
        .expect_err("no password");
    assert_eq!(error.code(), "credential.current_password_wrong");
    assert_eq!(other.hasher.checks_against_nothing(), 1);
}

#[tokio::test]
async fn a_password_chosen_by_an_administrator_must_be_changed_and_changing_clears_that() {
    let world = world();
    let temporary = secret("temporary password");
    let new = NewPassword {
        password: &temporary,
        rules: RULES,
        own_names: &[],
    };
    world
        .service
        .set_password(&world.tenant, world.user, new, true, Caller::system())
        .await
        .expect("reset");
    assert_eq!(
        world.check(Some(world.user), "temporary password").await,
        PasswordCheck::Verified { must_change: true }
    );

    world
        .change("temporary password", "my own new password")
        .await
        .expect("change");
    assert_eq!(
        world.check(Some(world.user), "my own new password").await,
        PasswordCheck::Verified { must_change: false }
    );
    assert_eq!(
        world.units_of_work.committed_event_types(),
        ["credential.password_set", "credential.password_changed"]
    );
}

#[tokio::test]
async fn raising_the_parameters_renews_a_hash_at_the_next_successful_check_only() {
    let world = world();
    world.set("a lasting password").await.expect("set");
    world.hasher.raise_parameters();
    let hashes_before = world.hasher.hashes();

    // A wrong password renews nothing.
    world.check(Some(world.user), "a wrong password!").await;
    assert_eq!(world.hasher.hashes(), hashes_before);

    // The right one renews the hash once, silently.
    for _ in 0..3 {
        assert_eq!(
            world.check(Some(world.user), "a lasting password").await,
            PasswordCheck::Verified { must_change: false }
        );
    }
    assert_eq!(
        world.hasher.hashes(),
        hashes_before + 1,
        "renewed once, then current"
    );
    assert_eq!(
        world.units_of_work.committed_event_types(),
        ["credential.password_set"],
        "renewal is not an event"
    );
}

#[tokio::test]
async fn an_overloaded_hasher_is_reported_as_unavailable_not_as_a_wrong_password() {
    let world = world();
    world.set("a lasting password").await.expect("set");
    world.hasher.set_overloaded(true);

    let verify = world
        .service
        .verify_password(
            &world.tenant,
            Some(world.user),
            &secret("a lasting password"),
        )
        .await
        .expect_err("overloaded");
    let set = world
        .set("another good password")
        .await
        .expect_err("overloaded");
    for error in [verify, set] {
        assert_eq!(error.kind(), ErrorKind::Unavailable);
        assert_eq!(error.code(), "credential.hashing_overloaded");
    }

    world.hasher.set_overloaded(false);
    assert_eq!(
        world.check(Some(world.user), "a lasting password").await,
        PasswordCheck::Verified { must_change: false },
        "nothing was lost while overloaded"
    );
}

#[tokio::test]
async fn removing_a_password_is_announced_once() {
    let world = world();
    world.set("a lasting password").await.expect("set");

    world
        .service
        .remove_password(&world.tenant, world.user, Caller::system())
        .await
        .expect("remove");
    world
        .service
        .remove_password(&world.tenant, world.user, Caller::system())
        .await
        .expect("remove again");

    assert_eq!(
        world.check(Some(world.user), "a lasting password").await,
        PasswordCheck::Rejected
    );
    assert_eq!(
        world.units_of_work.committed_event_types(),
        ["credential.password_set", "credential.password_removed"]
    );
}

#[tokio::test]
async fn passwords_of_different_tenants_are_independent() {
    let world = world();
    world.set("the tenant password").await.expect("set");
    let elsewhere = TenantContext::assume(TenantId::generate());

    let check = world
        .service
        .verify_password(&elsewhere, Some(world.user), &secret("the tenant password"))
        .await
        .expect("verify");
    assert_eq!(check, PasswordCheck::Rejected);
}
