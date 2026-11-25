//! Rotation of a tenant's signing keys: the policy every installation
//! sets, and the plan of one step, decided from the key set and the time
//! alone.

use crate::domain::key::{KeyAlgorithm, KeyState, KeyUse, KeyVersion, KeyVersionId};
use crate::domain::key_set::KeySet;
use hodor_kernel::{DomainError, Timestamp};
use time::Duration;

/// How often signing keys are replaced, how long a new one is published
/// before it signs, and how long a replaced one stays published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationPolicy {
    period: Duration,
    publication: Duration,
    overlap: Duration,
}

impl RotationPolicy {
    /// The lifetime of the longest-lived token Hodor signs: access tokens
    /// and ID tokens live at most one hour. A context that signs a token
    /// must not sign one that lives longer.
    pub const LONGEST_SIGNED_LIFETIME: Duration = Duration::hours(1);

    /// Added to the longest signed lifetime for clocks that disagree.
    pub const CLOCK_ALLOWANCE: Duration = Duration::minutes(5);

    /// How long those who read the published key set may keep it: the
    /// `max-age` it is published with.
    pub const PUBLISHED_FOR: Duration = Duration::minutes(5);

    /// The shortest and longest period.
    pub const PERIOD_BOUNDS: (Duration, Duration) = (Duration::days(1), Duration::days(730));

    /// Ninety days of signing, published a day ahead, kept a day after.
    pub const DEFAULT: Self = Self {
        period: Duration::days(90),
        publication: Duration::hours(24),
        overlap: Duration::hours(24),
    };

    /// A policy, checked against its bounds.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` `keys.rotation_policy_invalid` for a period outside
    /// 1 to 730 days, a publication time shorter than the time the key set
    /// may be kept or not shorter than the period, or an overlap shorter
    /// than the longest signed lifetime with the clock allowance.
    pub fn new(
        period: Duration,
        publication: Duration,
        overlap: Duration,
    ) -> Result<Self, DomainError> {
        let (shortest, longest) = Self::PERIOD_BOUNDS;
        let fits = (shortest..=longest).contains(&period)
            && publication >= Self::PUBLISHED_FOR
            && publication < period
            && overlap >= Self::shortest_overlap();
        if !fits {
            return Err(DomainError::invalid(
                "keys.rotation_policy_invalid",
                "a key signs for 1 to 730 days, is published at least 5 minutes and less than \
                 that before it signs, and stays at least 65 minutes after it is replaced",
            ));
        }
        Ok(Self {
            period,
            publication,
            overlap,
        })
    }

    /// The shortest overlap a policy accepts.
    #[must_use]
    pub const fn shortest_overlap() -> Duration {
        Self::LONGEST_SIGNED_LIFETIME.saturating_add(Self::CLOCK_ALLOWANCE)
    }

    /// How long a version is active before it is replaced.
    #[must_use]
    pub const fn period(&self) -> Duration {
        self.period
    }

    /// How long a new version is published before it signs.
    #[must_use]
    pub const fn publication(&self) -> Duration {
        self.publication
    }

    /// How long a replaced version stays published after it stopped
    /// signing.
    #[must_use]
    pub const fn overlap(&self) -> Duration {
        self.overlap
    }
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// One change of a step of rotation, in the order to make them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationChange {
    /// Retire a retiring version whose time has passed.
    Retire(KeyVersionId),
    /// Activate a pending version.
    Activate(KeyVersionId),
    /// Make a pending version of an algorithm, to be published before it
    /// signs.
    Prepare(KeyAlgorithm),
    /// Make a version of an algorithm and activate it at once: the
    /// algorithm has nothing that signs.
    CreateAndActivate(KeyAlgorithm),
}

impl KeySet {
    /// What one step of rotation changes in this signing key set at `now`,
    /// in the order to change it. `docs/architecture/contexts/keys.md`,
    /// "One step of rotation", is the specification. A key set of another
    /// use has nothing to rotate.
    #[must_use]
    pub fn rotation_plan(&self, policy: &RotationPolicy, now: Timestamp) -> Vec<RotationChange> {
        if self.key_use() != KeyUse::Signing {
            return Vec::new();
        }
        let mut plan: Vec<RotationChange> = self
            .versions()
            .iter()
            .filter(|version| version.state() == KeyState::Retiring)
            .filter(|version| {
                version
                    .snapshot()
                    .retire_after
                    .is_some_and(|after| after <= now)
            })
            .map(|version| RotationChange::Retire(version.id()))
            .collect();

        for algorithm in KeyAlgorithm::ALL {
            if algorithm.key_use() != KeyUse::Signing {
                continue;
            }
            let pending = self.oldest_pending(algorithm);
            match self.active(algorithm) {
                None if algorithm == KeyAlgorithm::DEFAULT_SIGNING => plan.push(match pending {
                    Some(pending) => RotationChange::Activate(pending.id()),
                    None => RotationChange::CreateAndActivate(algorithm),
                }),
                // An algorithm other than the default signs only while
                // someone keeps a version of it active.
                None => {}
                Some(active) => {
                    let since = active.snapshot().activated_at.unwrap_or(now);
                    let age = now - since;
                    match pending {
                        None if age >= policy.period() - policy.publication() => {
                            plan.push(RotationChange::Prepare(algorithm));
                        }
                        Some(pending)
                            if age >= policy.period()
                                && now - pending.snapshot().created_at >= policy.publication() =>
                        {
                            plan.push(RotationChange::Activate(pending.id()));
                        }
                        _ => {}
                    }
                }
            }
        }
        plan
    }

    /// The pending version of an algorithm that has been published longest.
    #[must_use]
    pub fn oldest_pending(&self, algorithm: KeyAlgorithm) -> Option<&KeyVersion> {
        // Newest first: the last match is the oldest.
        self.versions()
            .iter()
            .rev()
            .find(|v| v.algorithm() == algorithm && v.state() == KeyState::Pending)
    }

    /// The signing versions that are published: pending, active and
    /// retiring, newest first. Retired and revoked versions are not.
    #[must_use]
    pub fn published(&self) -> Vec<&KeyVersion> {
        if self.key_use() != KeyUse::Signing {
            return Vec::new();
        }
        self.versions()
            .iter()
            .filter(|version| {
                matches!(
                    version.state(),
                    KeyState::Pending | KeyState::Active | KeyState::Retiring
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::key::{GeneratedKey, KeyMaterial};
    use hodor_kernel::PublicKey;

    const NOW: Timestamp = Timestamp::UNIX_EPOCH;

    fn made(algorithm: KeyAlgorithm, at: Timestamp) -> KeyVersion {
        let public_key = match algorithm {
            KeyAlgorithm::Es256 => Some(PublicKey::P256 {
                x: vec![1; 32],
                y: vec![2; 32],
            }),
            KeyAlgorithm::A256Gcm => None,
            KeyAlgorithm::EdDsa => Some(PublicKey::Ed25519 { x: vec![3; 32] }),
            _ => Some(PublicKey::Rsa {
                modulus: vec![1; 256],
                exponent: vec![1, 0, 1],
            }),
        };
        KeyVersion::create(
            KeyVersionId::generate(),
            algorithm,
            "local",
            GeneratedKey {
                public_key,
                material: KeyMaterial::from_stored(vec![9; 8]),
            },
            at,
        )
        .expect("valid")
        .0
    }

    fn set(versions: Vec<KeyVersion>) -> KeySet {
        KeySet::from_versions(KeyUse::Signing, versions).expect("consistent")
    }

    /// A key set whose ES256 version was activated at `at`.
    fn active_since(at: Timestamp) -> (KeySet, KeyVersionId) {
        let version = made(KeyAlgorithm::Es256, at);
        let id = version.id();
        let mut keys = set(vec![version]);
        keys.activate(id, Duration::ZERO, at).expect("activate");
        (keys, id)
    }

    fn policy() -> RotationPolicy {
        RotationPolicy::DEFAULT
    }

    #[test]
    fn the_default_policy_is_within_its_own_bounds() {
        let default = RotationPolicy::DEFAULT;
        assert_eq!(
            RotationPolicy::new(default.period(), default.publication(), default.overlap()),
            Ok(default)
        );
    }

    #[test]
    fn a_policy_cannot_keep_a_replaced_key_shorter_than_the_tokens_it_signed() {
        let refused = |period, publication, overlap| {
            RotationPolicy::new(period, publication, overlap)
                .expect_err("refused")
                .code()
                .to_owned()
        };
        let day = Duration::days(1);
        // The overlap must outlive every signed token, with an allowance.
        assert_eq!(
            refused(Duration::days(90), day, Duration::hours(1)),
            "keys.rotation_policy_invalid"
        );
        assert!(RotationPolicy::new(Duration::days(90), day, Duration::minutes(65)).is_ok());
        // The period has bounds.
        assert_eq!(
            refused(Duration::hours(23), Duration::hours(1), day),
            "keys.rotation_policy_invalid"
        );
        assert_eq!(
            refused(Duration::days(731), day, day),
            "keys.rotation_policy_invalid"
        );
        // A new key is published for at least as long as the key set may be
        // kept, and less than the period.
        assert_eq!(
            refused(Duration::days(90), Duration::minutes(4), day),
            "keys.rotation_policy_invalid"
        );
        assert_eq!(
            refused(Duration::days(1), Duration::days(1), day),
            "keys.rotation_policy_invalid"
        );
    }

    #[test]
    fn a_tenant_without_keys_gets_one_that_signs_at_once() {
        let empty = set(Vec::new());
        assert_eq!(
            empty.rotation_plan(&policy(), NOW),
            vec![RotationChange::CreateAndActivate(KeyAlgorithm::Es256)]
        );
    }

    #[test]
    fn a_pending_default_key_is_activated_at_once_when_nothing_signs() {
        let pending = made(KeyAlgorithm::Es256, NOW);
        let keys = set(vec![pending.clone()]);
        assert_eq!(
            keys.rotation_plan(&policy(), NOW),
            vec![RotationChange::Activate(pending.id())]
        );
    }

    #[test]
    fn a_revoked_active_key_is_replaced_at_once() {
        let (mut keys, id) = active_since(NOW);
        keys.revoke(id, "leaked", NOW).expect("revoke");
        assert_eq!(
            keys.rotation_plan(&policy(), NOW + Duration::minutes(1)),
            vec![RotationChange::CreateAndActivate(KeyAlgorithm::Es256)]
        );
    }

    #[test]
    fn nothing_changes_before_the_next_key_is_due() {
        let (keys, _) = active_since(NOW);
        let before = NOW + policy().period() - policy().publication() - Duration::seconds(1);
        assert!(keys.rotation_plan(&policy(), before).is_empty());
    }

    #[test]
    fn the_next_key_is_published_ahead_of_its_time_and_activated_after() {
        let (mut keys, active) = active_since(NOW);
        let prepared_at = NOW + policy().period() - policy().publication();
        assert_eq!(
            keys.rotation_plan(&policy(), prepared_at),
            vec![RotationChange::Prepare(KeyAlgorithm::Es256)]
        );

        // Prepared: nothing more until the period has passed.
        let next = made(KeyAlgorithm::Es256, prepared_at);
        let mut versions = keys.versions().to_vec();
        versions.push(next.clone());
        keys = set(versions);
        assert!(
            keys.rotation_plan(&policy(), prepared_at + Duration::hours(1))
                .is_empty()
        );
        assert_eq!(keys.published().len(), 2, "the next key is published");

        let due = NOW + policy().period();
        assert_eq!(
            keys.rotation_plan(&policy(), due),
            vec![RotationChange::Activate(next.id())]
        );

        // Activated: the replaced key retires after the overlap, not before.
        keys.activate(next.id(), policy().overlap(), due)
            .expect("activate");
        assert!(
            keys.rotation_plan(&policy(), due + policy().overlap() - Duration::seconds(1))
                .is_empty()
        );
        assert_eq!(
            keys.rotation_plan(&policy(), due + policy().overlap()),
            vec![RotationChange::Retire(active)]
        );
    }

    #[test]
    fn a_key_prepared_late_is_published_for_the_whole_time_before_it_signs() {
        let (keys, _) = active_since(NOW);
        // The worker was stopped: the period passed without a pending key.
        let late = NOW + policy().period() + Duration::days(3);
        assert_eq!(
            keys.rotation_plan(&policy(), late),
            vec![RotationChange::Prepare(KeyAlgorithm::Es256)]
        );
        let next = made(KeyAlgorithm::Es256, late);
        let mut versions = keys.versions().to_vec();
        versions.push(next.clone());
        let keys = set(versions);
        assert!(
            keys.rotation_plan(
                &policy(),
                late + policy().publication() - Duration::seconds(1)
            )
            .is_empty()
        );
        assert_eq!(
            keys.rotation_plan(&policy(), late + policy().publication()),
            vec![RotationChange::Activate(next.id())]
        );
    }

    #[test]
    fn another_algorithm_rotates_while_it_has_an_active_key_and_not_after() {
        let (mut keys, _) = active_since(NOW);
        let rsa = made(KeyAlgorithm::Rs256, NOW);
        let mut versions = keys.versions().to_vec();
        versions.push(rsa.clone());
        keys = set(versions);
        keys.activate(rsa.id(), Duration::ZERO, NOW)
            .expect("activate");
        let due = NOW + policy().period() - policy().publication();
        assert_eq!(
            keys.rotation_plan(&policy(), due),
            vec![
                RotationChange::Prepare(KeyAlgorithm::Es256),
                RotationChange::Prepare(KeyAlgorithm::Rs256),
            ]
        );

        keys.revoke(rsa.id(), "no longer needed", NOW)
            .expect("revoke");
        assert_eq!(
            keys.rotation_plan(&policy(), due),
            vec![RotationChange::Prepare(KeyAlgorithm::Es256)]
        );
    }

    #[test]
    fn only_pending_active_and_retiring_keys_are_published() {
        let (mut keys, first) = active_since(NOW);
        let second = made(KeyAlgorithm::Es256, NOW + Duration::minutes(1));
        let third = made(KeyAlgorithm::Es256, NOW + Duration::minutes(2));
        let fourth = made(KeyAlgorithm::Es256, NOW + Duration::minutes(3));
        let mut versions = keys.versions().to_vec();
        versions.extend([second.clone(), third.clone(), fourth.clone()]);
        keys = set(versions);
        // first: retired; second: retiring; third: active; fourth: revoked.
        let at = NOW + Duration::minutes(10);
        keys.activate(second.id(), Duration::ZERO, at)
            .expect("second");
        keys.retire(first, at).expect("retire");
        keys.activate(third.id(), Duration::hours(2), at)
            .expect("third");
        keys.revoke(fourth.id(), "leaked", at).expect("revoke");

        let published: Vec<KeyVersionId> = keys.published().iter().map(|v| v.id()).collect();
        assert_eq!(published, vec![third.id(), second.id()]);
    }

    #[test]
    fn a_data_key_set_has_nothing_to_rotate_or_publish() {
        let data = KeySet::from_versions(KeyUse::Data, vec![made(KeyAlgorithm::A256Gcm, NOW)])
            .expect("consistent");
        assert!(data.rotation_plan(&policy(), NOW).is_empty());
        assert!(data.published().is_empty());
    }
}
