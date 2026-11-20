//! The Argon2id hasher, exercised through the port.

use hodor_adapters_crypto::{Argon2Parameters, Argon2idHasher, HashingLimits, OsRandom};
use hodor_credential::api::{PasswordHash, PasswordHasher};
use hodor_kernel::{ErrorKind, Secret};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Cheap parameters, so that tests of behavior are fast.
const LIGHT: Argon2Parameters = Argon2Parameters {
    memory_kibibytes: 1024,
    passes: 1,
    lanes: 1,
};

const ROOMY: HashingLimits = HashingLimits {
    concurrent: 4,
    queued: 64,
};

fn hasher(parameters: Argon2Parameters, limits: HashingLimits) -> Argon2idHasher {
    Argon2idHasher::new(parameters, limits, Arc::new(OsRandom)).expect("valid parameters")
}

fn secret(value: &str) -> Secret<String> {
    Secret::from(value.to_owned())
}

#[tokio::test]
async fn a_password_verifies_against_its_own_hash_only() {
    let hasher = hasher(LIGHT, ROOMY);
    let hash = hasher
        .hash(&secret("correct horse battery staple"))
        .await
        .expect("hash");

    let right = hasher
        .verify(&secret("correct horse battery staple"), &hash)
        .await
        .expect("verify");
    let wrong = hasher
        .verify(&secret("correct horse battery stapl"), &hash)
        .await
        .expect("verify");
    let empty = hasher.verify(&secret(""), &hash).await.expect("verify");

    assert!(right.matches && !right.needs_renewal);
    assert!(!wrong.matches);
    assert!(!empty.matches);
}

#[tokio::test]
async fn the_stored_form_names_the_algorithm_and_parameters_and_never_the_password() {
    let hasher = hasher(LIGHT, ROOMY);
    let hash = hasher
        .hash(&secret("a password to hide"))
        .await
        .expect("hash");

    assert!(
        hash.as_str().starts_with("$argon2id$v=19$m=1024,t=1,p=1$"),
        "{}",
        hash.as_str()
    );
    assert!(!hash.as_str().contains("a password to hide"));
    assert_eq!(
        hash.as_str().split('$').count(),
        6,
        "algorithm, version, parameters, salt, hash"
    );
}

#[tokio::test]
async fn the_same_password_hashes_differently_every_time() {
    let hasher = hasher(LIGHT, ROOMY);
    let first = hasher.hash(&secret("same password")).await.expect("hash");
    let second = hasher.hash(&secret("same password")).await.expect("hash");
    assert_ne!(first, second, "each hash has its own salt");
}

#[tokio::test]
async fn any_characters_are_hashed_exactly_as_typed() {
    let hasher = hasher(LIGHT, ROOMY);
    let password = "  senha com espaços, acentuação e 密码 🔐  ";
    let hash = hasher.hash(&secret(password)).await.expect("hash");

    assert!(
        hasher
            .verify(&secret(password), &hash)
            .await
            .expect("verify")
            .matches
    );
    assert!(
        !hasher
            .verify(&secret(password.trim()), &hash)
            .await
            .expect("verify")
            .matches,
        "surrounding spaces are part of the password"
    );
}

#[tokio::test]
async fn hashes_made_with_other_parameters_verify_and_ask_for_renewal() {
    let old = hasher(LIGHT, ROOMY);
    let stronger = Argon2Parameters {
        memory_kibibytes: 2048,
        passes: 2,
        lanes: 1,
    };
    let current = hasher(stronger, ROOMY);
    let old_hash = old.hash(&secret("unchanged password")).await.expect("hash");

    let verified = current
        .verify(&secret("unchanged password"), &old_hash)
        .await
        .expect("verify");
    assert!(verified.matches, "raising the parameters locks nobody out");
    assert!(verified.needs_renewal);

    let wrong = current
        .verify(&secret("wrong"), &old_hash)
        .await
        .expect("verify");
    assert!(!wrong.matches);

    let renewed = current
        .hash(&secret("unchanged password"))
        .await
        .expect("hash");
    let again = current
        .verify(&secret("unchanged password"), &renewed)
        .await
        .expect("verify");
    assert!(again.matches && !again.needs_renewal);
}

#[tokio::test]
async fn a_stored_value_that_is_not_an_argon2id_hash_is_an_error_not_a_mismatch() {
    let hasher = hasher(LIGHT, ROOMY);
    for stored in [
        "",
        "plaintext-password",
        "$2b$12$abcdefghijklmnopqrstuuJ8Yq0cRz7mGzQ1cZ9yY1mB0cWcXh5nS",
        "$argon2i$v=19$m=1024,t=1,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
        "$argon2id$v=19$m=1024,t=1,p=1$not-valid",
    ] {
        let error = hasher
            .verify(&secret("anything"), &PasswordHash::new(stored.to_owned()))
            .await
            .expect_err(stored);
        assert_eq!(error.kind(), ErrorKind::Internal, "{stored}");
        assert!(!error.message().contains(stored) || stored.is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn checking_against_nothing_costs_as_much_as_a_real_check() {
    // The default parameters, so that the hash dominates the time measured.
    let hasher = hasher(Argon2Parameters::default(), ROOMY);
    let password = secret("a password of ordinary length");
    let hash = hasher.hash(&password).await.expect("hash");

    let timed = async |real: bool| {
        let mut total = Duration::ZERO;
        for _ in 0..5 {
            let started = Instant::now();
            if real {
                hasher.verify(&password, &hash).await.expect("verify");
            } else {
                hasher
                    .verify_nothing(&password)
                    .await
                    .expect("verify nothing");
            }
            total += started.elapsed();
        }
        total
    };
    let (real, nothing) = (timed(true).await, timed(false).await);

    // Generous bounds: the point is that neither is a shortcut.
    assert!(
        nothing * 3 > real,
        "nothing {nothing:?} is much cheaper than real {real:?}"
    );
    assert!(
        real * 3 > nothing,
        "real {real:?} is much cheaper than nothing {nothing:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_full_queue_refuses_at_once_instead_of_piling_up() {
    let limits = HashingLimits {
        concurrent: 1,
        queued: 1,
    };
    let hasher = Arc::new(hasher(Argon2Parameters::default(), limits));

    let attempts: Vec<_> = (0..12)
        .map(|_| {
            let hasher = Arc::clone(&hasher);
            tokio::spawn(async move { hasher.hash(&secret("burst of sign-in attempts")).await })
        })
        .collect();
    let (mut done, mut refused) = (0, 0);
    for attempt in attempts {
        match attempt.await.expect("task") {
            Ok(_) => done += 1,
            Err(error) => {
                assert_eq!(error.kind(), ErrorKind::Unavailable);
                assert_eq!(error.code(), "credential.hashing_overloaded");
                refused += 1;
            }
        }
    }
    assert!(done >= 1, "admitted work completes");
    assert!(refused >= 1, "work beyond the queue is refused");
    assert_eq!(done + refused, 12);

    // Once the burst has passed, the hasher accepts work again.
    hasher
        .hash(&secret("after the burst"))
        .await
        .expect("recovered");
}

#[test]
fn invalid_settings_are_rejected_when_the_hasher_is_built() {
    let no_memory = Argon2Parameters {
        memory_kibibytes: 0,
        ..LIGHT
    };
    assert!(Argon2idHasher::new(no_memory, ROOMY, Arc::new(OsRandom)).is_err());
    let no_work = HashingLimits {
        concurrent: 0,
        queued: 0,
    };
    assert!(Argon2idHasher::new(LIGHT, no_work, Arc::new(OsRandom)).is_err());
}

#[test]
fn the_default_parameters_are_the_documented_baseline() {
    assert_eq!(
        Argon2Parameters::default(),
        Argon2Parameters {
            memory_kibibytes: 19 * 1024,
            passes: 2,
            lanes: 1
        }
    );
}
