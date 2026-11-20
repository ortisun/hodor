//! Counting failed attempts, and locking out.

use hodor_kernel::Timestamp;
use time::Duration;

/// What failed attempts are counted against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AttemptSubject {
    /// A login identifier, by the digest of its normalized form.
    Identifier([u8; 32]),
    /// A network address, by its digest.
    Address([u8; 32]),
}

impl AttemptSubject {
    /// The name used in storage and in events.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Identifier(_) => "identifier",
            Self::Address(_) => "address",
        }
    }

    /// The digest, for storage.
    #[must_use]
    pub const fn key(&self) -> &[u8; 32] {
        match self {
            Self::Identifier(key) | Self::Address(key) => key,
        }
    }
}

/// When attempts lead to a lockout, and for how long. Comes from the
/// tenant's lockout policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockoutRules {
    /// Attempts allowed for one identifier within the window.
    pub max_failures: u32,
    /// The window over which attempts are counted.
    pub window: Duration,
    /// How long the first lockout lasts.
    pub first_lockout: Duration,
    /// How long the longest lockout lasts.
    pub longest_lockout: Duration,
}

impl LockoutRules {
    /// An address may fail this many times more than an identifier, since
    /// many people can share one address.
    pub const ADDRESS_FACTOR: u32 = 10;

    /// The number of attempts allowed for a subject within the window.
    #[must_use]
    pub const fn limit_for(&self, subject: &AttemptSubject) -> u32 {
        match subject {
            AttemptSubject::Identifier(_) => self.max_failures,
            AttemptSubject::Address(_) => self.max_failures.saturating_mul(Self::ADDRESS_FACTOR),
        }
    }
}

/// The attempts counted against one subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptCounter {
    subject: AttemptSubject,
    failures: u32,
    window_started_at: Timestamp,
    lockouts: u32,
    locked_until: Option<Timestamp>,
}

impl AttemptCounter {
    /// A counter with nothing counted yet.
    #[must_use]
    pub const fn new(subject: AttemptSubject, now: Timestamp) -> Self {
        Self {
            subject,
            failures: 0,
            window_started_at: now,
            lockouts: 0,
            locked_until: None,
        }
    }

    /// Rebuilds a counter read from storage.
    #[must_use]
    pub const fn from_stored(
        subject: AttemptSubject,
        failures: u32,
        window_started_at: Timestamp,
        lockouts: u32,
        locked_until: Option<Timestamp>,
    ) -> Self {
        Self {
            subject,
            failures,
            window_started_at,
            lockouts,
            locked_until,
        }
    }

    /// What the counter is about.
    #[must_use]
    pub const fn subject(&self) -> &AttemptSubject {
        &self.subject
    }

    /// Attempts counted in the current window.
    #[must_use]
    pub const fn failures(&self) -> u32 {
        self.failures
    }

    /// When the current window started.
    #[must_use]
    pub const fn window_started_at(&self) -> Timestamp {
        self.window_started_at
    }

    /// Lockouts so far, which sets the length of the next one.
    #[must_use]
    pub const fn lockouts(&self) -> u32 {
        self.lockouts
    }

    /// The stored end of the last lockout, whether or not it has passed.
    #[must_use]
    pub const fn stored_locked_until(&self) -> Option<Timestamp> {
        self.locked_until
    }

    /// When the lockout in force at `now` ends, or `None` if the subject is
    /// not locked out.
    #[must_use]
    pub fn locked_until(&self, now: Timestamp) -> Option<Timestamp> {
        self.locked_until.filter(|until| now < *until)
    }

    /// Counts one attempt. If that reaches the limit, a lockout starts and
    /// its end is returned; the attempt being counted was still allowed.
    ///
    /// Each lockout of the same subject lasts twice as long as the one
    /// before, up to the longest duration.
    pub fn count(&mut self, rules: &LockoutRules, now: Timestamp) -> Option<Timestamp> {
        if now >= self.window_started_at + rules.window {
            self.failures = 0;
            self.window_started_at = now;
        }
        self.failures += 1;
        if self.failures < rules.limit_for(&self.subject) {
            return None;
        }
        let doublings = self.lockouts.min(30);
        let duration = rules
            .first_lockout
            .saturating_mul(2_i32.saturating_pow(doublings))
            .min(rules.longest_lockout);
        let until = now + duration;
        self.lockouts += 1;
        self.locked_until = Some(until);
        self.failures = 0;
        self.window_started_at = now;
        Some(until)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const START: Timestamp = Timestamp::UNIX_EPOCH;
    const RULES: LockoutRules = LockoutRules {
        max_failures: 5,
        window: Duration::minutes(15),
        first_lockout: Duration::minutes(1),
        longest_lockout: Duration::hours(1),
    };

    fn identifier() -> AttemptCounter {
        AttemptCounter::new(AttemptSubject::Identifier([7; 32]), START)
    }

    #[test]
    fn the_attempt_that_reaches_the_limit_starts_a_lockout() {
        let mut counter = identifier();
        for _ in 0..4 {
            assert_eq!(counter.count(&RULES, START), None);
        }
        assert_eq!(
            counter.count(&RULES, START),
            Some(START + Duration::minutes(1))
        );
        assert_eq!(
            counter.locked_until(START + Duration::seconds(59)),
            Some(START + Duration::minutes(1))
        );
        assert_eq!(
            counter.locked_until(START + Duration::minutes(1)),
            None,
            "over at its end"
        );
    }

    #[test]
    fn each_lockout_doubles_up_to_the_longest() {
        let mut counter = identifier();
        let mut now = START;
        let mut durations = Vec::new();
        for _ in 0..9 {
            let until = loop {
                if let Some(until) = counter.count(&RULES, now) {
                    break until;
                }
            };
            durations.push((until - now).whole_minutes());
            now = until;
        }
        assert_eq!(durations, [1, 2, 4, 8, 16, 32, 60, 60, 60]);
    }

    #[test]
    fn attempts_outside_the_window_are_forgotten() {
        let mut counter = identifier();
        for _ in 0..4 {
            counter.count(&RULES, START);
        }
        let later = START + Duration::minutes(15);
        for _ in 0..4 {
            assert_eq!(
                counter.count(&RULES, later),
                None,
                "the window started again"
            );
        }
        assert!(counter.count(&RULES, later).is_some());
    }

    #[test]
    fn an_address_is_allowed_ten_times_as_many_attempts() {
        let mut counter = AttemptCounter::new(AttemptSubject::Address([9; 32]), START);
        for _ in 0..49 {
            assert_eq!(counter.count(&RULES, START), None);
        }
        assert!(counter.count(&RULES, START).is_some());
    }

    proptest! {
        /// However attempts are spread over time, a lockout starts exactly
        /// when the limit is reached within one window, never lasts longer
        /// than the longest duration, and never shorter than the first.
        #[test]
        fn lockouts_follow_the_rules(gaps in proptest::collection::vec(0_i64..1200, 1..200)) {
            let mut counter = identifier();
            let mut now = START;
            let mut in_window: Vec<Timestamp> = Vec::new();
            let mut window_start = START;
            for gap in gaps {
                now += Duration::seconds(gap);
                if now >= window_start + RULES.window {
                    in_window.clear();
                    window_start = now;
                }
                in_window.push(now);
                let locked = counter.count(&RULES, now);
                prop_assert_eq!(locked.is_some(), in_window.len() == 5);
                if let Some(until) = locked {
                    prop_assert!(until - now >= RULES.first_lockout);
                    prop_assert!(until - now <= RULES.longest_lockout);
                    in_window.clear();
                    window_start = now;
                }
            }
        }
    }
}
