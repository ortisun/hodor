//! Time as a port, so that rules depending on "now" are testable.

/// A point in time, always handled in UTC.
pub type Timestamp = time::OffsetDateTime;

/// Source of the current time.
pub trait Clock: Send + Sync {
    /// Returns the current time in UTC.
    fn now(&self) -> Timestamp;
}

/// Clock backed by the operating system.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::now_utc()
    }
}

/// Deterministic clock for tests.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use super::{Clock, Timestamp};
    use std::sync::Mutex;

    /// Clock that returns a fixed time until it is advanced.
    #[derive(Debug)]
    pub struct FixedClock(Mutex<Timestamp>);

    impl FixedClock {
        /// Creates a clock stopped at `now`.
        #[must_use]
        pub fn at(now: Timestamp) -> Self {
            Self(Mutex::new(now))
        }

        /// Moves the clock forward.
        pub fn advance(&self, by: time::Duration) {
            let mut now = self.0.lock().unwrap_or_else(|e| e.into_inner());
            *now += by;
        }
    }

    impl Clock for FixedClock {
        fn now(&self) -> Timestamp {
            *self.0.lock().unwrap_or_else(|e| e.into_inner())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::FixedClock;
    use super::*;

    #[test]
    fn system_clock_reports_utc() {
        assert!(SystemClock.now().offset().is_utc());
    }

    #[test]
    fn fixed_clock_only_moves_when_advanced() {
        let start = Timestamp::UNIX_EPOCH;
        let clock = FixedClock::at(start);
        assert_eq!(clock.now(), start);
        clock.advance(time::Duration::minutes(5));
        assert_eq!(clock.now(), start + time::Duration::minutes(5));
    }
}
