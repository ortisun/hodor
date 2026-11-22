//! The policies that apply inside a tenant.
//!
//! Other contexts read these settings; only the tenant context changes
//! them. Settings are validated as a whole: a tenant never holds a partly
//! valid policy.

use hodor_kernel::DomainError;
use serde::{Deserialize, Serialize};
use time::Duration;

const MINUTE: u32 = 60;
const HOUR: u32 = 60 * MINUTE;
const DAY: u32 = 24 * HOUR;

fn invalid(message: &'static str) -> DomainError {
    DomainError::invalid("tenant.settings_invalid", message)
}

/// Rules for the passwords users choose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordPolicy {
    /// Fewest characters a password may have.
    pub min_length: u16,
    /// Most characters a password may have.
    pub max_length: u16,
    /// How many previous passwords cannot be reused.
    pub history_depth: u8,
    /// Whether passwords found in breach lists are rejected.
    pub reject_breached: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 12,
            max_length: 128,
            history_depth: 5,
            reject_breached: true,
        }
    }
}

impl PasswordPolicy {
    fn validate(&self) -> Result<(), DomainError> {
        if !(8..=128).contains(&self.min_length) {
            return Err(invalid(
                "the minimum password length must be between 8 and 128",
            ));
        }
        if self.max_length < self.min_length || self.max_length > 1024 {
            return Err(invalid(
                "the maximum password length must be between the minimum length and 1024",
            ));
        }
        if self.history_depth > 24 {
            return Err(invalid("the password history depth must be at most 24"));
        }
        Ok(())
    }
}

/// How long sessions last.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPolicy {
    /// Seconds of inactivity after which a session ends.
    pub idle_timeout_seconds: u32,
    /// Seconds after which a session ends regardless of activity.
    pub absolute_timeout_seconds: u32,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            idle_timeout_seconds: 30 * MINUTE,
            absolute_timeout_seconds: 12 * HOUR,
        }
    }
}

impl SessionPolicy {
    /// The idle timeout as a duration.
    #[must_use]
    pub fn idle_timeout(&self) -> Duration {
        Duration::seconds(i64::from(self.idle_timeout_seconds))
    }

    /// The absolute timeout as a duration.
    #[must_use]
    pub fn absolute_timeout(&self) -> Duration {
        Duration::seconds(i64::from(self.absolute_timeout_seconds))
    }

    fn validate(&self) -> Result<(), DomainError> {
        if self.idle_timeout_seconds < MINUTE
            || self.idle_timeout_seconds > self.absolute_timeout_seconds
        {
            return Err(invalid(
                "the idle timeout must be between 1 minute and the absolute timeout",
            ));
        }
        if self.absolute_timeout_seconds > 30 * DAY {
            return Err(invalid("the absolute timeout must be at most 30 days"));
        }
        Ok(())
    }
}

/// When repeated failed logins lock an account, and for how long.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockoutPolicy {
    /// Failed attempts that trigger a lockout.
    pub max_failures: u8,
    /// Seconds over which failed attempts are counted.
    pub window_seconds: u32,
    /// Seconds the first lockout lasts; later ones grow from here.
    pub first_lockout_seconds: u32,
    /// Seconds the longest lockout lasts.
    pub longest_lockout_seconds: u32,
}

impl Default for LockoutPolicy {
    fn default() -> Self {
        Self {
            max_failures: 5,
            window_seconds: 15 * MINUTE,
            first_lockout_seconds: MINUTE,
            longest_lockout_seconds: HOUR,
        }
    }
}

impl LockoutPolicy {
    fn validate(&self) -> Result<(), DomainError> {
        if !(3..=20).contains(&self.max_failures) {
            return Err(invalid(
                "failed attempts before lockout must be between 3 and 20",
            ));
        }
        if !(MINUTE..=DAY).contains(&self.window_seconds) {
            return Err(invalid(
                "the lockout window must be between 1 minute and 24 hours",
            ));
        }
        if self.first_lockout_seconds < 10
            || self.first_lockout_seconds > self.longest_lockout_seconds
        {
            return Err(invalid(
                "the first lockout must last between 10 seconds and the longest lockout",
            ));
        }
        if self.longest_lockout_seconds > DAY {
            return Err(invalid("the longest lockout must be at most 24 hours"));
        }
        Ok(())
    }
}

/// Who may create an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationPolicy {
    /// Only administrators and invitations create users.
    #[default]
    Closed,
    /// Anyone can register.
    Open,
}

/// All the policies of one tenant.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TenantSettings {
    /// Rules for passwords.
    pub password: PasswordPolicy,
    /// Session lifetimes.
    pub session: SessionPolicy,
    /// Lockout after failed logins.
    pub lockout: LockoutPolicy,
    /// Who may register.
    pub registration: RegistrationPolicy,
}

impl TenantSettings {
    /// Checks every policy against its allowed range.
    ///
    /// # Errors
    ///
    /// Returns an `Invalid` error naming the first rule that is broken.
    pub fn validate(&self) -> Result<(), DomainError> {
        self.password.validate()?;
        self.session.validate()?;
        self.lockout.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_match_the_specification_and_are_valid() {
        let settings = TenantSettings::default();
        assert_eq!(settings.password.min_length, 12);
        assert_eq!(settings.password.max_length, 128);
        assert_eq!(settings.password.history_depth, 5);
        assert!(settings.password.reject_breached);
        assert_eq!(settings.session.idle_timeout(), Duration::minutes(30));
        assert_eq!(settings.session.absolute_timeout(), Duration::hours(12));
        assert_eq!(settings.lockout.max_failures, 5);
        assert_eq!(settings.lockout.window_seconds, 15 * MINUTE);
        assert_eq!(settings.lockout.first_lockout_seconds, MINUTE);
        assert_eq!(settings.lockout.longest_lockout_seconds, HOUR);
        assert_eq!(settings.registration, RegistrationPolicy::Closed);
        settings.validate().expect("defaults are valid");
    }

    fn rejected(change: impl FnOnce(&mut TenantSettings)) -> bool {
        let mut settings = TenantSettings::default();
        change(&mut settings);
        settings
            .validate()
            .is_err_and(|e| e.code() == "tenant.settings_invalid")
    }

    #[test]
    fn password_policy_bounds_are_enforced() {
        assert!(rejected(|s| s.password.min_length = 7));
        assert!(rejected(|s| s.password.min_length = 129));
        assert!(rejected(|s| s.password.max_length = 11));
        assert!(rejected(|s| s.password.max_length = 1025));
        assert!(rejected(|s| s.password.history_depth = 25));
        assert!(!rejected(|s| s.password.min_length = 8));
        assert!(!rejected(|s| s.password.history_depth = 0));
    }

    #[test]
    fn session_policy_bounds_are_enforced() {
        assert!(rejected(|s| s.session.idle_timeout_seconds = 59));
        assert!(rejected(
            |s| s.session.idle_timeout_seconds = s.session.absolute_timeout_seconds + 1
        ));
        assert!(rejected(
            |s| s.session.absolute_timeout_seconds = 30 * DAY + 1
        ));
        assert!(!rejected(
            |s| s.session.idle_timeout_seconds = s.session.absolute_timeout_seconds
        ));
    }

    #[test]
    fn lockout_policy_bounds_are_enforced() {
        assert!(rejected(|s| s.lockout.max_failures = 2));
        assert!(rejected(|s| s.lockout.max_failures = 21));
        assert!(rejected(|s| s.lockout.window_seconds = 59));
        assert!(rejected(|s| s.lockout.window_seconds = DAY + 1));
        assert!(rejected(|s| s.lockout.first_lockout_seconds = 9));
        assert!(rejected(
            |s| s.lockout.first_lockout_seconds = s.lockout.longest_lockout_seconds + 1
        ));
        assert!(rejected(|s| s.lockout.longest_lockout_seconds = DAY + 1));
    }

    #[test]
    fn settings_round_trip_through_json() {
        let settings = TenantSettings {
            registration: RegistrationPolicy::Open,
            ..TenantSettings::default()
        };
        let json = serde_json::to_value(&settings).expect("serializable");
        assert_eq!(json["registration"], "open");
        assert_eq!(json["session"]["idle_timeout_seconds"], 1800);
        let back: TenantSettings = serde_json::from_value(json).expect("deserializable");
        assert_eq!(back, settings);
    }
}
