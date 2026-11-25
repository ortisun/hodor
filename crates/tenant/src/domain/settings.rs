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

/// Whether a sign-in to the tenant needs a second factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecondFactorPolicy {
    /// One factor is enough, unless the flow asks for more.
    #[default]
    NotRequired,
    /// No sign-in completes with one factor.
    Required,
}

/// How strongly a person proved who they are, as an assurance level of a
/// tenant requires it. Ordered: a sign-in that reaches one reaches every
/// requirement before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceRequirement {
    /// One factor.
    SingleFactor,
    /// Two kinds of factor.
    MultiFactor,
    /// Two kinds of factor, one of them a key held by the person that
    /// answered a challenge for this tenant's address.
    PhishingResistant,
}

impl AssuranceRequirement {
    /// Every requirement, weakest first.
    pub const ALL: [Self; 3] = [
        Self::SingleFactor,
        Self::MultiFactor,
        Self::PhishingResistant,
    ];

    /// The name used in settings, on the command line and in the
    /// administration interface.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SingleFactor => "single_factor",
            Self::MultiFactor => "multi_factor",
            Self::PhishingResistant => "phishing_resistant",
        }
    }

    /// The requirement a name stands for, if any.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|requirement| requirement.as_str() == name)
    }
}

/// The `acr` of a tenant's level for a single-factor sign-in, until the
/// tenant renames it.
pub const ACR_SINGLE_FACTOR: &str = "urn:hodor:acr:single-factor";
/// The `acr` of a tenant's level for a multi-factor sign-in, until the
/// tenant renames it.
pub const ACR_MULTI_FACTOR: &str = "urn:hodor:acr:mfa";

/// One assurance level of a tenant: the `acr` value that names it, and
/// what a sign-in must reach to be at it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssuranceLevel {
    /// The name applications ask for in `acr_values` and tokens carry in
    /// `acr`.
    pub acr: String,
    /// What a sign-in must reach.
    pub requirement: AssuranceRequirement,
}

/// The assurance levels of a tenant. See
/// `docs/architecture/contexts/tenant.md`, "Assurance levels".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AssuranceLevels(Vec<AssuranceLevel>);

impl Default for AssuranceLevels {
    fn default() -> Self {
        Self(vec![
            AssuranceLevel {
                acr: ACR_SINGLE_FACTOR.to_owned(),
                requirement: AssuranceRequirement::SingleFactor,
            },
            AssuranceLevel {
                acr: ACR_MULTI_FACTOR.to_owned(),
                requirement: AssuranceRequirement::MultiFactor,
            },
        ])
    }
}

impl AssuranceLevels {
    /// The most levels a tenant has: one per requirement.
    pub const MAX: usize = 3;
    /// The longest name of a level.
    pub const MAX_NAME: usize = 255;

    /// The levels, weakest first.
    ///
    /// # Errors
    ///
    /// Returns `tenant.settings_invalid` when they break a rule of the
    /// specification.
    pub fn new(mut levels: Vec<AssuranceLevel>) -> Result<Self, DomainError> {
        levels.sort_by_key(|level| level.requirement);
        let levels = Self(levels);
        levels.validate()?;
        Ok(levels)
    }

    /// The levels, weakest first.
    #[must_use]
    pub fn levels(&self) -> Vec<&AssuranceLevel> {
        let mut levels: Vec<&AssuranceLevel> = self.0.iter().collect();
        levels.sort_by_key(|level| level.requirement);
        levels
    }

    /// What a request's `acr_values` asks for: the weakest of the levels
    /// of this tenant it names. `None` when it names none of them.
    #[must_use]
    pub fn asked(&self, acr_values: &str) -> Option<AssuranceRequirement> {
        acr_values
            .split(' ')
            .filter_map(|name| self.0.iter().find(|level| level.acr == name))
            .map(|level| level.requirement)
            .min()
    }

    /// The name of the strongest level that a sign-in reaching `reached`
    /// is at. `None` when it reaches no level of this tenant.
    #[must_use]
    pub fn reached(&self, reached: AssuranceRequirement) -> Option<&str> {
        self.0
            .iter()
            .filter(|level| level.requirement <= reached)
            .max_by_key(|level| level.requirement)
            .map(|level| level.acr.as_str())
    }

    fn validate(&self) -> Result<(), DomainError> {
        if self.0.is_empty() || self.0.len() > Self::MAX {
            return Err(invalid("a tenant has one to three assurance levels"));
        }
        for (index, level) in self.0.iter().enumerate() {
            let named = !level.acr.is_empty()
                && level.acr.len() <= Self::MAX_NAME
                && level.acr.bytes().all(|b| (0x21..=0x7e).contains(&b));
            if !named {
                return Err(invalid(
                    "the name of an assurance level is 1 to 255 characters of printable ASCII without spaces",
                ));
            }
            let repeated = self.0[..index].iter().any(|earlier| {
                earlier.acr == level.acr || earlier.requirement == level.requirement
            });
            if repeated {
                return Err(invalid(
                    "no two assurance levels have the same name or the same requirement",
                ));
            }
        }
        Ok(())
    }
}

/// How people must prove who they are to sign in.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AuthenticationPolicy {
    /// Whether a second factor is required.
    #[serde(default)]
    pub second_factor: SecondFactorPolicy,
    /// The levels applications ask for and tokens name. Settings stored
    /// before they existed read as the default.
    #[serde(default)]
    pub assurance_levels: AssuranceLevels,
    /// Whether people may sign in with a code or a link by email.
    /// Settings stored before this policy existed read as the default.
    #[serde(default)]
    pub email_sign_in: EmailSignInPolicy,
}

/// Whether people of the tenant may sign in with a code or a link sent to
/// their address, each on its own. Both are off by default. Specified in
/// `docs/architecture/contexts/tenant.md`, "Email sign-in policy".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EmailSignInPolicy {
    /// A code sent to the address.
    #[serde(default)]
    pub code: bool,
    /// A link sent to the address, opened in the browser that asked.
    #[serde(default)]
    pub link: bool,
}

/// The bound on how deep groups may be nested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupPolicy {
    /// The deepest a group may be: the longest chain of groups inside it,
    /// counting itself.
    pub max_depth: u8,
}

impl Default for GroupPolicy {
    fn default() -> Self {
        Self { max_depth: 5 }
    }
}

impl GroupPolicy {
    fn validate(&self) -> Result<(), DomainError> {
        if !(1..=10).contains(&self.max_depth) {
            return Err(invalid("the depth of groups must be between 1 and 10"));
        }
        Ok(())
    }
}

/// What deprovisioning a person through SCIM does to them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Deprovisioning {
    /// Deactivate them: they can be restored.
    #[default]
    Deactivate,
    /// Deactivate them and mark them Deleted: they are erased.
    Delete,
}

impl Deprovisioning {
    /// The name the policy is stored and written under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deactivate => "deactivate",
            Self::Delete => "delete",
        }
    }
}

/// What the tenant's SCIM server does. Specified in
/// `docs/architecture/contexts/tenant.md`, "SCIM deprovisioning policy".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ProvisioningPolicy {
    /// What deprovisioning a person does.
    #[serde(default)]
    pub deprovisioning: Deprovisioning,
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
    /// How people must prove who they are. Settings stored before this
    /// policy existed read as the default.
    #[serde(default)]
    pub authentication: AuthenticationPolicy,
    /// How deep groups may be nested. Settings stored before this policy
    /// existed read as the default.
    #[serde(default)]
    pub groups: GroupPolicy,
    /// What the SCIM server does. Settings stored before this policy
    /// existed read as the default.
    #[serde(default)]
    pub provisioning: ProvisioningPolicy,
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
        self.lockout.validate()?;
        self.groups.validate()?;
        self.authentication.assurance_levels.validate()
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
        assert_eq!(
            settings.authentication.second_factor,
            SecondFactorPolicy::NotRequired
        );
        settings.validate().expect("defaults are valid");
    }

    #[test]
    fn settings_stored_before_the_authentication_policy_read_as_the_default() {
        let mut stored = serde_json::to_value(TenantSettings::default()).expect("serializes");
        stored
            .as_object_mut()
            .expect("an object")
            .remove("authentication");
        let read: TenantSettings = serde_json::from_value(stored).expect("still reads");
        assert_eq!(read, TenantSettings::default());
    }

    #[test]
    fn the_depth_of_groups_is_five_by_default_and_bounded() {
        let mut settings = TenantSettings::default();
        assert_eq!(settings.groups.max_depth, 5);
        let mut stored = serde_json::to_value(&settings).expect("serializes");
        stored.as_object_mut().expect("an object").remove("groups");
        let read: TenantSettings = serde_json::from_value(stored).expect("older settings read");
        assert_eq!(
            read.groups.max_depth, 5,
            "settings stored before the policy read as the default"
        );
        for depth in [0, 11] {
            settings.groups.max_depth = depth;
            assert!(settings.validate().is_err(), "{depth}");
        }
        settings.groups.max_depth = 10;
        settings.validate().expect("valid");
    }

    #[test]
    fn deprovisioning_deactivates_by_default_and_is_stored_by_name() {
        let mut settings = TenantSettings::default();
        assert_eq!(
            settings.provisioning.deprovisioning,
            Deprovisioning::Deactivate
        );
        let mut stored = serde_json::to_value(&settings).expect("serializes");
        stored
            .as_object_mut()
            .expect("an object")
            .remove("provisioning");
        let read: TenantSettings = serde_json::from_value(stored).expect("older settings read");
        assert_eq!(read.provisioning.deprovisioning, Deprovisioning::Deactivate);
        settings.provisioning.deprovisioning = Deprovisioning::Delete;
        let stored = serde_json::to_value(&settings).expect("serializes");
        assert_eq!(stored["provisioning"]["deprovisioning"], "delete");
    }

    #[test]
    fn signing_in_by_email_is_off_by_default_and_read_from_older_settings() {
        let mut settings = TenantSettings::default();
        assert_eq!(
            settings.authentication.email_sign_in,
            EmailSignInPolicy {
                code: false,
                link: false
            }
        );
        let mut stored = serde_json::to_value(&settings).expect("serializes");
        stored["authentication"]
            .as_object_mut()
            .expect("an object")
            .remove("email_sign_in");
        let read: TenantSettings = serde_json::from_value(stored).expect("older settings read");
        assert_eq!(read, TenantSettings::default());
        settings.authentication.email_sign_in.link = true;
        let stored = serde_json::to_value(&settings).expect("serializes");
        assert_eq!(
            stored["authentication"]["email_sign_in"],
            serde_json::json!({ "code": false, "link": true })
        );
        settings.validate().expect("valid");
    }

    #[test]
    fn a_required_second_factor_is_stored_by_name() {
        let mut settings = TenantSettings::default();
        settings.authentication.second_factor = SecondFactorPolicy::Required;
        let stored = serde_json::to_value(&settings).expect("serializes");
        assert_eq!(stored["authentication"]["second_factor"], "required");
        settings.validate().expect("valid");
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

    fn level(acr: &str, requirement: AssuranceRequirement) -> AssuranceLevel {
        AssuranceLevel {
            acr: acr.to_owned(),
            requirement,
        }
    }

    #[test]
    fn the_default_levels_are_the_two_of_the_specification() {
        let levels = AssuranceLevels::default();
        let names: Vec<&str> = levels.levels().iter().map(|l| l.acr.as_str()).collect();
        assert_eq!(names, [ACR_SINGLE_FACTOR, ACR_MULTI_FACTOR]);
        let stored = serde_json::to_value(TenantSettings::default()).expect("serializes");
        assert_eq!(
            stored["authentication"]["assurance_levels"][1]["requirement"],
            "multi_factor"
        );
    }

    #[test]
    fn settings_stored_before_the_levels_read_the_default_levels() {
        let mut stored = serde_json::to_value(TenantSettings::default()).expect("serializes");
        stored["authentication"]
            .as_object_mut()
            .expect("an object")
            .remove("assurance_levels");
        let read: TenantSettings = serde_json::from_value(stored).expect("still reads");
        assert_eq!(read, TenantSettings::default());
    }

    #[test]
    fn levels_are_kept_weakest_first_whatever_order_they_come_in() {
        let levels = AssuranceLevels::new(vec![
            level("strong", AssuranceRequirement::PhishingResistant),
            level("weak", AssuranceRequirement::SingleFactor),
        ])
        .expect("valid");
        let names: Vec<&str> = levels.levels().iter().map(|l| l.acr.as_str()).collect();
        assert_eq!(names, ["weak", "strong"]);
    }

    #[test]
    fn the_rules_of_the_levels_are_enforced() {
        let refused = |levels: Vec<AssuranceLevel>| {
            AssuranceLevels::new(levels).is_err_and(|e| e.code() == "tenant.settings_invalid")
        };
        assert!(refused(Vec::new()));
        assert!(refused(vec![
            level("a", AssuranceRequirement::SingleFactor),
            level("b", AssuranceRequirement::MultiFactor),
            level("c", AssuranceRequirement::PhishingResistant),
            level("d", AssuranceRequirement::PhishingResistant),
        ]));
        assert!(refused(vec![level("", AssuranceRequirement::SingleFactor)]));
        assert!(refused(vec![level(
            "with space",
            AssuranceRequirement::SingleFactor
        )]));
        assert!(refused(vec![level(
            "caf\u{e9}",
            AssuranceRequirement::SingleFactor
        )]));
        assert!(refused(vec![level(
            &"x".repeat(256),
            AssuranceRequirement::SingleFactor
        )]));
        assert!(refused(vec![
            level("same", AssuranceRequirement::SingleFactor),
            level("same", AssuranceRequirement::MultiFactor),
        ]));
        assert!(refused(vec![
            level("one", AssuranceRequirement::MultiFactor),
            level("two", AssuranceRequirement::MultiFactor),
        ]));
        assert!(!refused(vec![level(
            &"x".repeat(255),
            AssuranceRequirement::MultiFactor
        )]));
        assert!(rejected(|s| {
            s.authentication.assurance_levels = AssuranceLevels(Vec::new());
        }));
    }

    #[test]
    fn a_request_asks_for_the_weakest_level_of_this_tenant_it_names() {
        let levels = AssuranceLevels::new(vec![
            level("one", AssuranceRequirement::SingleFactor),
            level("mfa", AssuranceRequirement::MultiFactor),
            level("strong", AssuranceRequirement::PhishingResistant),
        ])
        .expect("valid");
        assert_eq!(
            levels.asked("strong"),
            Some(AssuranceRequirement::PhishingResistant)
        );
        assert_eq!(
            levels.asked("strong mfa"),
            Some(AssuranceRequirement::MultiFactor)
        );
        assert_eq!(
            levels.asked("unknown strong"),
            Some(AssuranceRequirement::PhishingResistant)
        );
        assert_eq!(levels.asked("unknown other"), None);
        assert_eq!(levels.asked(""), None);
    }

    #[test]
    fn a_sign_in_is_at_the_strongest_level_it_reaches() {
        let levels = AssuranceLevels::new(vec![
            level("mfa", AssuranceRequirement::MultiFactor),
            level("strong", AssuranceRequirement::PhishingResistant),
        ])
        .expect("valid");
        assert_eq!(levels.reached(AssuranceRequirement::SingleFactor), None);
        assert_eq!(
            levels.reached(AssuranceRequirement::MultiFactor),
            Some("mfa")
        );
        assert_eq!(
            levels.reached(AssuranceRequirement::PhishingResistant),
            Some("strong")
        );
        let defaults = AssuranceLevels::default();
        assert_eq!(
            defaults.reached(AssuranceRequirement::PhishingResistant),
            Some(ACR_MULTI_FACTOR)
        );
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
