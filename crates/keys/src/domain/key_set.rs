//! A tenant's key set of one use: the versions of that use, and the rule
//! that one version per algorithm is active.

use crate::domain::event::KeyEvent;
use crate::domain::key::{KeyAlgorithm, KeyState, KeyUse, KeyVersion, KeyVersionId, check_overlap};
use hodor_kernel::{DomainError, Timestamp};
use time::Duration;

/// The versions of one use in a tenant, newest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySet {
    key_use: KeyUse,
    versions: Vec<KeyVersion>,
}

/// What an activation changed, in the order it must be stored: the
/// replaced version first, so that one version per algorithm is active
/// after every write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Activation {
    /// The versions that changed, in the order to store them.
    pub changed: Vec<KeyVersion>,
    /// What other contexts hear about it.
    pub event: KeyEvent,
}

impl KeySet {
    /// Rebuilds a key set from its versions.
    ///
    /// # Errors
    ///
    /// Returns an internal error if a version is of another use, or if two
    /// versions of one algorithm are active: storage that breaks the rules.
    pub fn from_versions(
        key_use: KeyUse,
        mut versions: Vec<KeyVersion>,
    ) -> Result<Self, DomainError> {
        if versions.iter().any(|version| version.key_use() != key_use) {
            return Err(inconsistent("a version of another use is in the key set"));
        }
        for algorithm in KeyAlgorithm::ALL {
            let active = versions
                .iter()
                .filter(|v| v.algorithm() == algorithm && v.state() == KeyState::Active)
                .count();
            if active > 1 {
                return Err(inconsistent("two versions of one algorithm are active"));
            }
        }
        versions.sort_by(|a, b| {
            (b.snapshot().created_at, b.id()).cmp(&(a.snapshot().created_at, a.id()))
        });
        Ok(Self { key_use, versions })
    }

    /// What the keys of this set are for.
    #[must_use]
    pub const fn key_use(&self) -> KeyUse {
        self.key_use
    }

    /// Every version, newest first.
    #[must_use]
    pub fn versions(&self) -> &[KeyVersion] {
        &self.versions
    }

    /// One version of the set.
    #[must_use]
    pub fn version(&self, id: KeyVersionId) -> Option<&KeyVersion> {
        self.versions.iter().find(|version| version.id() == id)
    }

    /// The active version of an algorithm, if there is one.
    #[must_use]
    pub fn active(&self, algorithm: KeyAlgorithm) -> Option<&KeyVersion> {
        self.versions
            .iter()
            .find(|v| v.algorithm() == algorithm && v.state() == KeyState::Active)
    }

    /// Makes a pending version the active one of its algorithm. The version
    /// it replaces starts retiring and may retire once `overlap` has passed.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the version is not in the set, `Conflict`
    /// `keys.not_pending` unless it is pending, and `Invalid` if the overlap
    /// is negative.
    pub fn activate(
        &mut self,
        id: KeyVersionId,
        overlap: Duration,
        now: Timestamp,
    ) -> Result<Activation, DomainError> {
        check_overlap(overlap)?;
        let index = self.index_of(id)?;
        let algorithm = self.versions[index].algorithm();
        if self.versions[index].state() != KeyState::Pending {
            return Err(DomainError::conflict(
                "keys.not_pending",
                "only a key version that was never used can be activated",
            ));
        }
        let mut changed = Vec::with_capacity(2);
        let retire_after = now + overlap;
        let replaced = self
            .versions
            .iter()
            .position(|v| v.algorithm() == algorithm && v.state() == KeyState::Active);
        if let Some(previous) = replaced {
            self.versions[previous].start_retiring(now, retire_after);
            changed.push(self.versions[previous].clone());
        }
        self.versions[index].activate(now)?;
        changed.push(self.versions[index].clone());
        let event = KeyEvent::VersionActivated {
            version_id: id,
            algorithm: algorithm.as_str(),
            replaced_version_id: replaced.map(|previous| self.versions[previous].id()),
            replaced_retire_after: replaced.map(|_| retire_after),
        };
        Ok(Activation { changed, event })
    }

    /// Makes a pending version the active one of its algorithm only if the
    /// algorithm has no active version: for the first key of a set, which
    /// must never replace one made at the same moment by someone else.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` `keys.already_active` if the algorithm already
    /// has an active version, and what [`KeySet::activate`] returns.
    pub fn activate_first(
        &mut self,
        id: KeyVersionId,
        now: Timestamp,
    ) -> Result<Activation, DomainError> {
        let algorithm = self.versions[self.index_of(id)?].algorithm();
        if self
            .versions
            .iter()
            .any(|v| v.algorithm() == algorithm && v.state() == KeyState::Active)
        {
            return Err(DomainError::conflict(
                "keys.already_active",
                "the key set already has an active version of this algorithm",
            ));
        }
        self.activate(id, Duration::ZERO, now)
    }

    /// Retires a retiring version whose time has passed.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the version is not in the set, `Conflict`
    /// `keys.not_retiring` unless it is retiring and `keys.still_needed`
    /// before its time.
    pub fn retire(
        &mut self,
        id: KeyVersionId,
        now: Timestamp,
    ) -> Result<(KeyVersion, KeyEvent), DomainError> {
        let index = self.index_of(id)?;
        let event = self.versions[index].retire(now)?;
        Ok((self.versions[index].clone(), event))
    }

    /// Revokes a version. Revoking a revoked version changes nothing and
    /// answers no event.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the version is not in the set and `Invalid` if
    /// the reason is empty or too long.
    pub fn revoke(
        &mut self,
        id: KeyVersionId,
        reason: &str,
        now: Timestamp,
    ) -> Result<Option<(KeyVersion, KeyEvent)>, DomainError> {
        let index = self.index_of(id)?;
        Ok(self.versions[index]
            .revoke(reason, now)?
            .map(|event| (self.versions[index].clone(), event)))
    }

    fn index_of(&self, id: KeyVersionId) -> Result<usize, DomainError> {
        self.versions
            .iter()
            .position(|version| version.id() == id)
            .ok_or_else(not_found)
    }
}

/// The error of a key version the tenant does not have.
#[must_use]
pub(crate) fn not_found() -> DomainError {
    DomainError::not_found("keys.version_not_found", "the key version does not exist")
}

fn inconsistent(detail: &str) -> DomainError {
    DomainError::internal(
        "keys.stored_data_invalid",
        "the key version could not be loaded",
    )
    .with_detail(detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::key::{GeneratedKey, KeyMaterial};
    use hodor_kernel::PublicKey;

    const NOW: Timestamp = Timestamp::UNIX_EPOCH;

    fn version(algorithm: KeyAlgorithm, at: Timestamp) -> KeyVersion {
        let public_key = algorithm.signature().map(|_| match algorithm {
            KeyAlgorithm::Es256 => PublicKey::P256 {
                x: vec![1; 32],
                y: vec![2; 32],
            },
            _ => PublicKey::Rsa {
                modulus: vec![1; 256],
                exponent: vec![1, 0, 1],
            },
        });
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

    fn signing_set(versions: Vec<KeyVersion>) -> KeySet {
        KeySet::from_versions(KeyUse::Signing, versions).expect("consistent")
    }

    #[test]
    fn a_first_activation_never_replaces_an_active_version() {
        let first = version(KeyAlgorithm::Es256, NOW);
        let second = version(KeyAlgorithm::Es256, NOW + Duration::minutes(1));
        let mut set = signing_set(vec![first.clone(), second.clone()]);

        let activation = set.activate_first(first.id(), NOW).expect("the first");
        assert_eq!(activation.changed.len(), 1, "nothing was replaced");
        let error = set
            .activate_first(second.id(), NOW)
            .expect_err("one is active already");
        assert_eq!(error.code(), "keys.already_active");
        assert_eq!(
            set.versions()
                .iter()
                .find(|v| v.id() == first.id())
                .map(KeyVersion::state),
            Some(KeyState::Active)
        );
    }

    #[test]
    fn versions_are_listed_newest_first() {
        let older = version(KeyAlgorithm::Es256, NOW);
        let newer = version(KeyAlgorithm::Es256, NOW + Duration::minutes(1));
        let set = signing_set(vec![older.clone(), newer.clone()]);
        let ids: Vec<KeyVersionId> = set.versions().iter().map(KeyVersion::id).collect();
        assert_eq!(ids, vec![newer.id(), older.id()]);
    }

    #[test]
    fn a_version_of_another_use_or_two_active_versions_are_refused_from_storage() {
        let data = version(KeyAlgorithm::A256Gcm, NOW);
        assert_eq!(
            KeySet::from_versions(KeyUse::Signing, vec![data])
                .expect_err("other use")
                .code(),
            "keys.stored_data_invalid"
        );

        let mut first = version(KeyAlgorithm::Es256, NOW);
        let mut second = version(KeyAlgorithm::Es256, NOW);
        first.activate(NOW).expect("activate");
        second.activate(NOW).expect("activate");
        assert!(KeySet::from_versions(KeyUse::Signing, vec![first, second]).is_err());
    }

    #[test]
    fn the_first_activation_replaces_nothing() {
        let pending = version(KeyAlgorithm::Es256, NOW);
        let mut set = signing_set(vec![pending.clone()]);
        let activation = set
            .activate(pending.id(), Duration::hours(1), NOW)
            .expect("activate");
        assert_eq!(activation.changed.len(), 1);
        assert_eq!(activation.changed[0].state(), KeyState::Active);
        assert_eq!(
            activation.event,
            KeyEvent::VersionActivated {
                version_id: pending.id(),
                algorithm: "ES256",
                replaced_version_id: None,
                replaced_retire_after: None,
            }
        );
        assert_eq!(
            set.active(KeyAlgorithm::Es256).map(KeyVersion::id),
            Some(pending.id())
        );
    }

    #[test]
    fn activating_a_version_sets_the_one_it_replaces_retiring_first() {
        let first = version(KeyAlgorithm::Es256, NOW);
        let second = version(KeyAlgorithm::Es256, NOW + Duration::minutes(1));
        let mut set = signing_set(vec![first.clone(), second.clone()]);
        set.activate(first.id(), Duration::ZERO, NOW)
            .expect("first");

        let later = NOW + Duration::days(30);
        let activation = set
            .activate(second.id(), Duration::hours(2), later)
            .expect("second");
        let order: Vec<(KeyVersionId, KeyState)> = activation
            .changed
            .iter()
            .map(|v| (v.id(), v.state()))
            .collect();
        assert_eq!(
            order,
            vec![
                (first.id(), KeyState::Retiring),
                (second.id(), KeyState::Active)
            ]
        );
        assert_eq!(
            activation.changed[0].snapshot().retire_after,
            Some(later + Duration::hours(2))
        );
        assert_eq!(
            activation.event,
            KeyEvent::VersionActivated {
                version_id: second.id(),
                algorithm: "ES256",
                replaced_version_id: Some(first.id()),
                replaced_retire_after: Some(later + Duration::hours(2)),
            }
        );
        let active: Vec<&KeyVersion> = set
            .versions()
            .iter()
            .filter(|v| v.state() == KeyState::Active)
            .collect();
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn each_algorithm_has_its_own_active_version() {
        let es256 = version(KeyAlgorithm::Es256, NOW);
        let rs256 = version(KeyAlgorithm::Rs256, NOW);
        let mut set = signing_set(vec![es256.clone(), rs256.clone()]);
        set.activate(es256.id(), Duration::ZERO, NOW)
            .expect("es256");
        let activation = set
            .activate(rs256.id(), Duration::ZERO, NOW)
            .expect("rs256");
        assert_eq!(activation.changed.len(), 1, "RS256 replaces no ES256 key");
        assert_eq!(
            set.active(KeyAlgorithm::Es256).map(KeyVersion::id),
            Some(es256.id())
        );
        assert_eq!(
            set.active(KeyAlgorithm::Rs256).map(KeyVersion::id),
            Some(rs256.id())
        );
    }

    #[test]
    fn an_unknown_or_used_version_is_not_activated_and_nothing_changes() {
        let first = version(KeyAlgorithm::Es256, NOW);
        let mut set = signing_set(vec![first.clone()]);
        assert_eq!(
            set.activate(KeyVersionId::generate(), Duration::ZERO, NOW)
                .expect_err("unknown")
                .code(),
            "keys.version_not_found"
        );
        assert_eq!(
            set.activate(first.id(), Duration::seconds(-1), NOW)
                .expect_err("negative overlap")
                .code(),
            "keys.overlap_invalid"
        );
        set.activate(first.id(), Duration::ZERO, NOW)
            .expect("activate");
        let before = set.clone();
        assert_eq!(
            set.activate(first.id(), Duration::ZERO, NOW)
                .expect_err("active")
                .code(),
            "keys.not_pending"
        );
        assert_eq!(set, before);
    }

    #[test]
    fn revoking_the_active_version_leaves_its_algorithm_without_one() {
        let first = version(KeyAlgorithm::Es256, NOW);
        let mut set = signing_set(vec![first.clone()]);
        set.activate(first.id(), Duration::ZERO, NOW)
            .expect("activate");
        let (revoked, _) = set
            .revoke(first.id(), "leaked", NOW)
            .expect("revoke")
            .expect("changed");
        assert_eq!(revoked.state(), KeyState::Revoked);
        assert!(set.active(KeyAlgorithm::Es256).is_none());
        assert_eq!(
            set.revoke(first.id(), "again", NOW).expect("no change"),
            None
        );
    }

    #[test]
    fn a_replaced_version_is_retired_through_the_set_after_its_overlap() {
        let first = version(KeyAlgorithm::Es256, NOW);
        let second = version(KeyAlgorithm::Es256, NOW);
        let mut set = signing_set(vec![first.clone(), second.clone()]);
        set.activate(first.id(), Duration::ZERO, NOW)
            .expect("first");
        set.activate(second.id(), Duration::minutes(5), NOW)
            .expect("second");
        assert_eq!(
            set.retire(first.id(), NOW).expect_err("early").code(),
            "keys.still_needed"
        );
        let (retired, _) = set
            .retire(first.id(), NOW + Duration::minutes(5))
            .expect("retire");
        assert_eq!(retired.state(), KeyState::Retired);
        assert_eq!(
            set.retire(second.id(), NOW).expect_err("active").code(),
            "keys.not_retiring"
        );
    }
}
