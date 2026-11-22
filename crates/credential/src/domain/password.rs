//! Passwords: what is acceptable, and what is kept about them.

use hodor_kernel::{DomainError, Secret, Timestamp, UserId};
use std::fmt;

/// Longest password accepted at all, in bytes, whatever the policy says.
/// An oversized input is refused before any other work, so that it cannot
/// be used to exhaust the server.
pub const MAX_PASSWORD_BYTES: usize = 4096;

/// The rules a new password must follow. They come from the tenant's
/// password policy; the caller of this context supplies them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordRules {
    /// Fewest characters.
    pub min_length: u16,
    /// Most characters.
    pub max_length: u16,
    /// How many previous passwords cannot be reused.
    pub history_depth: u8,
}

/// Checks a new password against the rules that need no stored data:
/// length, and not being one of the user's own names.
///
/// Reuse of a recent password is checked separately, because it needs the
/// stored hashes.
///
/// # Errors
///
/// Returns an `Invalid` error naming the rule that is broken. The message
/// never contains the password.
pub fn check_acceptable(
    password: &Secret<String>,
    rules: &PasswordRules,
    own_names: &[&str],
) -> Result<(), DomainError> {
    let value = password.expose();
    if value.len() > MAX_PASSWORD_BYTES {
        return Err(DomainError::invalid(
            "credential.password_too_long",
            "the password is too long",
        ));
    }
    let length = value.chars().count();
    if length < usize::from(rules.min_length) {
        return Err(DomainError::invalid(
            "credential.password_too_short",
            format!("a password has at least {} characters", rules.min_length),
        ));
    }
    if length > usize::from(rules.max_length) {
        return Err(DomainError::invalid(
            "credential.password_too_long",
            format!("a password has at most {} characters", rules.max_length),
        ));
    }
    let lowered = value.to_lowercase();
    if own_names.iter().any(|name| name.to_lowercase() == lowered) {
        return Err(DomainError::invalid(
            "credential.password_is_own_name",
            "a password cannot be one of your own login identifiers",
        ));
    }
    Ok(())
}

/// A stored password hash: algorithm, parameters, salt and hash in the
/// standard text format. Opaque to this context; only the hasher reads it.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordHash(String);

impl PasswordHash {
    /// Wraps a hash produced by the hasher or read from storage.
    #[must_use]
    pub const fn new(encoded: String) -> Self {
        Self(encoded)
    }

    /// The encoded hash, for storage and for the hasher.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A hash is not the password, but it is what an attacker would try to
/// crack, so it stays out of logs.
impl fmt::Debug for PasswordHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasswordHash([REDACTED])")
    }
}

/// The hash of a previous password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricHash {
    /// The previous hash.
    pub hash: PasswordHash,
    /// When it stopped being the current password.
    pub replaced_at: Timestamp,
}

/// What is kept about one user's password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordRecord {
    user_id: UserId,
    hash: PasswordHash,
    must_change: bool,
    changed_at: Timestamp,
    history: Vec<HistoricHash>,
    version: u32,
}

impl PasswordRecord {
    /// The record of a user's first password.
    #[must_use]
    pub const fn new(
        user_id: UserId,
        hash: PasswordHash,
        must_change: bool,
        now: Timestamp,
    ) -> Self {
        Self {
            user_id,
            hash,
            must_change,
            changed_at: now,
            history: Vec::new(),
            version: 0,
        }
    }

    /// Rebuilds a record read from storage. `history` is newest first.
    #[must_use]
    pub const fn from_stored(
        user_id: UserId,
        hash: PasswordHash,
        must_change: bool,
        changed_at: Timestamp,
        history: Vec<HistoricHash>,
        version: u32,
    ) -> Self {
        Self {
            user_id,
            hash,
            must_change,
            changed_at,
            history,
            version,
        }
    }

    /// The user this password belongs to.
    #[must_use]
    pub const fn user_id(&self) -> UserId {
        self.user_id
    }

    /// The current hash.
    #[must_use]
    pub const fn hash(&self) -> &PasswordHash {
        &self.hash
    }

    /// Whether the password must be changed at the next sign-in.
    #[must_use]
    pub const fn must_change(&self) -> bool {
        self.must_change
    }

    /// When the password was last changed.
    #[must_use]
    pub const fn changed_at(&self) -> Timestamp {
        self.changed_at
    }

    /// The previous hashes, newest first.
    #[must_use]
    pub fn history(&self) -> &[HistoricHash] {
        &self.history
    }

    /// The version that was loaded, for optimistic locking.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// The hashes a new password must not match: the current one and the
    /// newest `depth` of the history.
    pub fn hashes_barred_from_reuse(&self, depth: u8) -> impl Iterator<Item = &PasswordHash> {
        std::iter::once(&self.hash).chain(
            self.history
                .iter()
                .take(usize::from(depth))
                .map(|h| &h.hash),
        )
    }

    /// Replaces the password. The current hash moves to the front of the
    /// history, which is then trimmed to `history_depth`.
    pub fn replace(
        &mut self,
        hash: PasswordHash,
        must_change: bool,
        history_depth: u8,
        now: Timestamp,
    ) {
        let previous = std::mem::replace(&mut self.hash, hash);
        self.history.insert(
            0,
            HistoricHash {
                hash: previous,
                replaced_at: now,
            },
        );
        self.history.truncate(usize::from(history_depth));
        self.must_change = must_change;
        self.changed_at = now;
    }

    /// Stores a fresh hash of the same password, made with the current
    /// parameters. The password did not change, so neither do the history,
    /// the change date nor the obligation to change it.
    pub fn renew_hash(&mut self, hash: PasswordHash) {
        self.hash = hash;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const NOW: Timestamp = Timestamp::UNIX_EPOCH;
    const RULES: PasswordRules = PasswordRules {
        min_length: 12,
        max_length: 128,
        history_depth: 5,
    };

    fn secret(value: &str) -> Secret<String> {
        Secret::from(value.to_owned())
    }

    fn hash(label: &str) -> PasswordHash {
        PasswordHash::new(format!("hash-of-{label}"))
    }

    #[test]
    fn length_is_counted_in_characters_not_bytes() {
        // Twelve characters, thirty-six bytes.
        let twelve_wide = "密".repeat(12);
        assert!(check_acceptable(&secret(&twelve_wide), &RULES, &[]).is_ok());
        let eleven = "a".repeat(11);
        let error = check_acceptable(&secret(&eleven), &RULES, &[]).expect_err("short");
        assert_eq!(error.code(), "credential.password_too_short");
        let too_many = "a".repeat(129);
        let error = check_acceptable(&secret(&too_many), &RULES, &[]).expect_err("long");
        assert_eq!(error.code(), "credential.password_too_long");
    }

    #[test]
    fn there_are_no_composition_rules_and_nothing_is_trimmed() {
        for password in [
            "aaaaaaaaaaaa",
            "            ",
            "correct horse battery staple",
            "  spaces kept  ",
        ] {
            assert!(
                check_acceptable(&secret(password), &RULES, &[]).is_ok(),
                "{password:?}"
            );
        }
    }

    #[test]
    fn a_password_cannot_be_one_of_the_users_own_names() {
        let names = ["ana.silva@example.com", "ana.silva.long.name"];
        for password in [
            "ana.silva@example.com",
            "ANA.SILVA@EXAMPLE.COM",
            "Ana.Silva.Long.Name",
        ] {
            let error = check_acceptable(&secret(password), &RULES, &names).expect_err(password);
            assert_eq!(error.code(), "credential.password_is_own_name");
        }
        assert!(check_acceptable(&secret("ana.silva@example.com!"), &RULES, &names).is_ok());
    }

    #[test]
    fn an_oversized_password_is_refused_whatever_the_policy() {
        let generous = PasswordRules {
            max_length: u16::MAX,
            ..RULES
        };
        let huge = "a".repeat(MAX_PASSWORD_BYTES + 1);
        let error = check_acceptable(&secret(&huge), &generous, &[]).expect_err("oversized");
        assert_eq!(error.code(), "credential.password_too_long");
    }

    #[test]
    fn error_messages_never_contain_the_password() {
        let password = "tiny-secret";
        let error = check_acceptable(&secret(password), &RULES, &[]).expect_err("short");
        assert!(!format!("{error:?} {error}").contains(password));
    }

    #[test]
    fn a_hash_does_not_appear_in_debug_output() {
        let record = PasswordRecord::new(UserId::generate(), hash("first"), false, NOW);
        assert!(!format!("{record:?}").contains("hash-of-first"));
    }

    #[test]
    fn replacing_moves_the_current_hash_to_the_front_of_the_history() {
        let mut record = PasswordRecord::new(UserId::generate(), hash("1"), true, NOW);
        record.replace(hash("2"), false, 5, NOW);
        record.replace(hash("3"), false, 5, NOW);

        assert_eq!(record.hash(), &hash("3"));
        assert!(!record.must_change());
        let history: Vec<&str> = record.history().iter().map(|h| h.hash.as_str()).collect();
        assert_eq!(history, ["hash-of-2", "hash-of-1"]);
    }

    #[test]
    fn a_history_depth_of_zero_keeps_nothing_but_still_bars_the_current_password() {
        let mut record = PasswordRecord::new(UserId::generate(), hash("1"), false, NOW);
        record.replace(hash("2"), false, 0, NOW);
        assert!(record.history().is_empty());
        let barred: Vec<&PasswordHash> = record.hashes_barred_from_reuse(0).collect();
        assert_eq!(barred, [&hash("2")]);
    }

    #[test]
    fn renewing_a_hash_changes_only_the_hash() {
        let mut record = PasswordRecord::new(UserId::generate(), hash("old-parameters"), true, NOW);
        record.replace(hash("current"), true, 5, NOW);
        let before = record.clone();

        record.renew_hash(hash("new-parameters"));

        assert_eq!(record.hash(), &hash("new-parameters"));
        assert_eq!(record.history(), before.history());
        assert_eq!(record.changed_at(), before.changed_at());
        assert_eq!(record.must_change(), before.must_change());
    }

    proptest! {
        /// However many times a password is replaced, the history holds the
        /// newest previous hashes, in order, and never more than the depth.
        #[test]
        fn the_history_is_the_newest_previous_hashes(depth in 0_u8..8, changes in 0_usize..20) {
            let mut record = PasswordRecord::new(UserId::generate(), hash("0"), false, NOW);
            for n in 1..=changes {
                record.replace(hash(&n.to_string()), false, depth, NOW);
            }
            let expected: Vec<String> = (0..changes)
                .rev()
                .take(usize::from(depth))
                .map(|n| format!("hash-of-{n}"))
                .collect();
            let actual: Vec<&str> = record.history().iter().map(|h| h.hash.as_str()).collect();
            prop_assert_eq!(actual, expected);
            prop_assert_eq!(record.hash().as_str(), format!("hash-of-{changes}"));
            prop_assert_eq!(record.hashes_barred_from_reuse(depth).count(), 1 + changes.min(usize::from(depth)));
        }

        /// A password is accepted exactly when its character count is
        /// within the rules and it is not one of the user's names.
        #[test]
        fn acceptance_depends_only_on_length_and_own_names(password in "\\PC{0,40}", min in 8_u16..16, extra in 0_u16..20) {
            let rules = PasswordRules { min_length: min, max_length: min + extra, history_depth: 0 };
            let length = password.chars().count();
            let expected = (usize::from(rules.min_length)..=usize::from(rules.max_length)).contains(&length);
            prop_assert_eq!(check_acceptable(&secret(&password), &rules, &[]).is_ok(), expected);
        }
    }
}
