//! Which engine answers for a resource server in a tenant, and how a
//! failure is handled.
//!
//! See `docs/architecture/contexts/authorization.md`, "Bindings".

use crate::domain::decision::EngineId;
use crate::domain::request::{Action, Namespace};
use hodor_kernel::{DomainError, Timestamp};
use std::collections::BTreeSet;
use std::time::Duration;

/// The time an engine may take unless the binding says otherwise.
pub const DEFAULT_TIME_LIMIT: Duration = Duration::from_millis(200);
/// The longest time limit a binding may give.
const MAX_TIME_LIMIT: Duration = Duration::from_secs(5);
/// The most actions that may fail open in one binding.
const MAX_FAIL_OPEN_ACTIONS: usize = 50;

/// What a binding is made from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingSettings {
    /// The resource server, by its audience.
    pub namespace: Namespace,
    /// The engine that answers.
    pub engine: EngineId,
    /// How long the engine may take: 1 millisecond to 5 seconds.
    pub time_limit: Duration,
    /// Whether a failure may ever allow.
    pub sensitive: bool,
    /// The actions for which a failure allows instead of being
    /// indeterminate. Empty when the namespace is sensitive.
    pub fail_open_actions: BTreeSet<Action>,
    /// Whether the engine receives what the caller claims.
    pub trust_asserted: bool,
}

impl BindingSettings {
    /// Settings with the defaults: 200 milliseconds, not sensitive,
    /// nothing fails open, asserted attributes not trusted.
    #[must_use]
    pub const fn new(namespace: Namespace, engine: EngineId) -> Self {
        Self {
            namespace,
            engine,
            time_limit: DEFAULT_TIME_LIMIT,
            sensitive: false,
            fail_open_actions: BTreeSet::new(),
            trust_asserted: false,
        }
    }
}

/// A binding as it is kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineBinding {
    settings: BindingSettings,
    created_at: Timestamp,
    updated_at: Timestamp,
}

impl EngineBinding {
    /// Makes a binding.
    ///
    /// # Errors
    ///
    /// - `authorization.namespace_reserved` for `hodor:admin`, which is
    ///   never bound.
    /// - `authorization.time_limit_invalid` unless the limit is 1
    ///   millisecond to 5 seconds, in whole milliseconds.
    /// - `authorization.fail_open_on_sensitive` if a sensitive namespace
    ///   lets an action fail open.
    /// - `authorization.too_many_fail_open_actions` beyond 50.
    pub fn new(settings: BindingSettings, now: Timestamp) -> Result<Self, DomainError> {
        Self::check(&settings)?;
        Ok(Self {
            settings,
            created_at: now,
            updated_at: now,
        })
    }

    /// The binding with new settings for the same namespace, as of `now`.
    ///
    /// # Errors
    ///
    /// The errors of [`EngineBinding::new`], and
    /// `authorization.namespace_changed` if the settings name another
    /// namespace.
    pub fn changed(&self, settings: BindingSettings, now: Timestamp) -> Result<Self, DomainError> {
        if settings.namespace != self.settings.namespace {
            return Err(DomainError::invalid(
                "authorization.namespace_changed",
                "a binding keeps its namespace",
            ));
        }
        Self::check(&settings)?;
        Ok(Self {
            settings,
            created_at: self.created_at,
            updated_at: now,
        })
    }

    fn check(settings: &BindingSettings) -> Result<(), DomainError> {
        if settings.namespace.is_administration() {
            return Err(DomainError::invalid(
                "authorization.namespace_reserved",
                "Hodor's administration is always answered by its own engine and cannot be bound",
            ));
        }
        let whole_milliseconds = settings.time_limit.subsec_nanos().is_multiple_of(1_000_000);
        if settings.time_limit < Duration::from_millis(1)
            || settings.time_limit > MAX_TIME_LIMIT
            || !whole_milliseconds
        {
            return Err(DomainError::invalid(
                "authorization.time_limit_invalid",
                "the time limit is 1 to 5000 milliseconds, in whole milliseconds",
            ));
        }
        if settings.sensitive && !settings.fail_open_actions.is_empty() {
            return Err(DomainError::invalid(
                "authorization.fail_open_on_sensitive",
                "nothing fails open in a sensitive namespace",
            ));
        }
        if settings.fail_open_actions.len() > MAX_FAIL_OPEN_ACTIONS {
            return Err(DomainError::invalid(
                "authorization.too_many_fail_open_actions",
                "at most 50 actions may fail open",
            ));
        }
        Ok(())
    }

    /// The fixed binding of Hodor's administration: its own engine,
    /// sensitive, nothing fails open, nothing asserted is trusted. It is
    /// never stored.
    #[must_use]
    pub fn administration() -> Self {
        let mut settings = BindingSettings::new(Namespace::administration(), EngineId::native());
        settings.sensitive = true;
        Self {
            settings,
            created_at: Timestamp::UNIX_EPOCH,
            updated_at: Timestamp::UNIX_EPOCH,
        }
    }

    /// Rebuilds a binding read from storage, checking it again.
    ///
    /// # Errors
    ///
    /// The errors of [`EngineBinding::new`].
    pub fn restore(
        settings: BindingSettings,
        created_at: Timestamp,
        updated_at: Timestamp,
    ) -> Result<Self, DomainError> {
        Self::check(&settings)?;
        Ok(Self {
            settings,
            created_at,
            updated_at,
        })
    }

    /// Its settings.
    #[must_use]
    pub const fn settings(&self) -> &BindingSettings {
        &self.settings
    }

    /// The resource server it is for.
    #[must_use]
    pub const fn namespace(&self) -> &Namespace {
        &self.settings.namespace
    }

    /// The engine that answers.
    #[must_use]
    pub const fn engine(&self) -> &EngineId {
        &self.settings.engine
    }

    /// When it was made.
    #[must_use]
    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// When it last changed.
    #[must_use]
    pub const fn updated_at(&self) -> Timestamp {
        self.updated_at
    }

    /// Whether a failure on `action` allows. Never for a sensitive
    /// namespace.
    #[must_use]
    pub fn fails_open(&self, action: &Action) -> bool {
        !self.settings.sensitive && self.settings.fail_open_actions.contains(action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> BindingSettings {
        BindingSettings::new(
            Namespace::parse("https://api.example.com").expect("namespace"),
            EngineId::native(),
        )
    }

    fn action(name: &str) -> Action {
        Action::parse(name).expect("action")
    }

    fn refused(settings: BindingSettings) -> String {
        EngineBinding::new(settings, Timestamp::UNIX_EPOCH)
            .map(|_| ())
            .expect_err("refused")
            .code()
            .to_owned()
    }

    #[test]
    fn the_defaults_fail_closed() {
        let binding = EngineBinding::new(settings(), Timestamp::UNIX_EPOCH).expect("binding");
        assert_eq!(binding.settings().time_limit, Duration::from_millis(200));
        assert!(!binding.fails_open(&action("read")));
        assert!(!binding.settings().trust_asserted);
    }

    #[test]
    fn the_administration_is_never_bound() {
        let mut admin = settings();
        admin.namespace = Namespace::administration();
        assert_eq!(refused(admin), "authorization.namespace_reserved");
        let fixed = EngineBinding::administration();
        assert!(fixed.namespace().is_administration());
        assert_eq!(fixed.engine(), &EngineId::native());
        assert!(fixed.settings().sensitive);
        assert!(!fixed.settings().trust_asserted);
    }

    #[test]
    fn the_time_limit_is_bounded() {
        for good in [1, 200, 5000] {
            let mut limited = settings();
            limited.time_limit = Duration::from_millis(good);
            assert!(
                EngineBinding::new(limited, Timestamp::UNIX_EPOCH).is_ok(),
                "{good}"
            );
        }
        for bad in [
            Duration::ZERO,
            Duration::from_micros(500),
            Duration::from_micros(1500),
            Duration::from_millis(5001),
        ] {
            let mut limited = settings();
            limited.time_limit = bad;
            assert_eq!(
                refused(limited),
                "authorization.time_limit_invalid",
                "{bad:?}"
            );
        }
    }

    #[test]
    fn only_listed_actions_of_a_namespace_that_is_not_sensitive_fail_open() {
        let mut open = settings();
        open.fail_open_actions.insert(action("read"));
        let binding = EngineBinding::new(open.clone(), Timestamp::UNIX_EPOCH).expect("binding");
        assert!(binding.fails_open(&action("read")));
        assert!(!binding.fails_open(&action("write")));

        open.sensitive = true;
        assert_eq!(refused(open), "authorization.fail_open_on_sensitive");

        let mut many = settings();
        for index in 0..=MAX_FAIL_OPEN_ACTIONS {
            many.fail_open_actions.insert(action(&format!("a{index}")));
        }
        assert_eq!(refused(many), "authorization.too_many_fail_open_actions");
    }

    #[test]
    fn a_change_keeps_the_namespace_and_the_creation() {
        let created = Timestamp::UNIX_EPOCH;
        let later = created + time::Duration::hours(1);
        let binding = EngineBinding::new(settings(), created).expect("binding");
        let mut slower = settings();
        slower.time_limit = Duration::from_millis(900);
        let changed = binding.changed(slower, later).expect("changed");
        assert_eq!(changed.created_at(), created);
        assert_eq!(changed.updated_at(), later);
        assert_eq!(changed.settings().time_limit, Duration::from_millis(900));

        let mut elsewhere = settings();
        elsewhere.namespace = Namespace::parse("urn:other").expect("namespace");
        assert_eq!(
            binding
                .changed(elsewhere, later)
                .map(|_| ())
                .expect_err("refused")
                .code(),
            "authorization.namespace_changed"
        );
    }
}
