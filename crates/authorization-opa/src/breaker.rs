//! The circuit breaker of one instance.
//!
//! An instance that keeps failing is not called for a while, so that a
//! decision fails at once instead of waiting out its time limit, and the
//! instance is not asked again while it struggles.

use hodor_kernel::Timestamp;
use std::collections::VecDeque;
use time::Duration;

/// When the circuit opens, and for how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreakerSettings {
    /// Failures in a row that open the circuit.
    pub failures_in_a_row: u32,
    /// The window over which the share of failures is counted.
    pub window: Duration,
    /// The fewest requests in the window for the share to count.
    pub fewest_requests: usize,
    /// How long the circuit stays open before one probe is let through.
    pub open_for: Duration,
}

impl Default for BreakerSettings {
    fn default() -> Self {
        Self {
            failures_in_a_row: 5,
            window: Duration::seconds(10),
            fewest_requests: 10,
            open_for: Duration::seconds(5),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Closed,
    Open {
        until: Timestamp,
    },
    /// One probe is on its way; nothing else is let through.
    Probing,
}

/// The state of one instance's circuit.
#[derive(Debug, Clone)]
pub(crate) struct Breaker {
    settings: BreakerSettings,
    state: State,
    in_a_row: u32,
    /// When each recent request ended, and whether it failed.
    recent: VecDeque<(Timestamp, bool)>,
}

/// Whether a request may be made, and as what.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admission {
    /// The circuit is closed.
    Admitted,
    /// The circuit was open long enough: this request is the probe.
    Probe,
    /// The circuit is open, or a probe is on its way.
    Refused,
}

impl Breaker {
    pub(crate) const fn new(settings: BreakerSettings) -> Self {
        Self {
            settings,
            state: State::Closed,
            in_a_row: 0,
            recent: VecDeque::new(),
        }
    }

    /// Whether a request may be made now.
    pub(crate) fn admit(&mut self, now: Timestamp) -> Admission {
        match self.state {
            State::Closed => Admission::Admitted,
            State::Open { until } if now >= until => {
                self.state = State::Probing;
                Admission::Probe
            }
            State::Open { .. } | State::Probing => Admission::Refused,
        }
    }

    /// Records how a request that was admitted ended.
    pub(crate) fn record(&mut self, now: Timestamp, failed: bool) {
        if self.state == State::Probing {
            if failed {
                self.open(now);
            } else {
                self.close();
            }
            return;
        }
        self.in_a_row = if failed { self.in_a_row + 1 } else { 0 };
        self.recent.push_back((now, failed));
        let since = now - self.settings.window;
        while self.recent.front().is_some_and(|(at, _)| *at < since) {
            self.recent.pop_front();
        }
        let failures = self.recent.iter().filter(|(_, failed)| *failed).count();
        let half_failed =
            self.recent.len() >= self.settings.fewest_requests && failures * 2 >= self.recent.len();
        if self.in_a_row >= self.settings.failures_in_a_row || half_failed {
            self.open(now);
        }
    }

    fn open(&mut self, now: Timestamp) {
        self.state = State::Open {
            until: now + self.settings.open_for,
        };
        self.in_a_row = 0;
        self.recent.clear();
    }

    fn close(&mut self) {
        self.state = State::Closed;
        self.in_a_row = 0;
        self.recent.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start() -> Timestamp {
        Timestamp::UNIX_EPOCH + Duration::days(20_000)
    }

    #[test]
    fn five_failures_in_a_row_open_it() {
        let mut breaker = Breaker::new(BreakerSettings::default());
        let now = start();
        for _ in 0..4 {
            assert_eq!(breaker.admit(now), Admission::Admitted);
            breaker.record(now, true);
        }
        breaker.record(now, false);
        for _ in 0..4 {
            breaker.record(now, true);
        }
        assert_eq!(
            breaker.admit(now),
            Admission::Admitted,
            "a success broke the row"
        );
        breaker.record(now, true);
        assert_eq!(breaker.admit(now), Admission::Refused);
    }

    #[test]
    fn half_of_ten_in_the_window_opens_it() {
        let mut breaker = Breaker::new(BreakerSettings::default());
        let now = start();
        // Alternating: never two failures in a row.
        for index in 0..9 {
            breaker.record(now, index % 2 == 0);
            assert_eq!(breaker.admit(now), Admission::Admitted, "{index}");
        }
        breaker.record(now, false);
        // Ten requests, five failed.
        assert_eq!(breaker.admit(now), Admission::Refused);
    }

    #[test]
    fn old_requests_leave_the_window() {
        let mut breaker = Breaker::new(BreakerSettings::default());
        let now = start();
        for index in 0..9 {
            breaker.record(now, index % 2 == 0);
        }
        let later = now + Duration::seconds(11);
        breaker.record(later, true);
        assert_eq!(breaker.admit(later), Admission::Admitted);
    }

    #[test]
    fn after_a_while_one_probe_closes_or_reopens_it() {
        let settings = BreakerSettings::default();
        let mut breaker = Breaker::new(settings);
        let now = start();
        for _ in 0..5 {
            breaker.record(now, true);
        }
        assert_eq!(
            breaker.admit(now + Duration::seconds(4)),
            Admission::Refused
        );

        let probe_at = now + settings.open_for;
        assert_eq!(breaker.admit(probe_at), Admission::Probe);
        assert_eq!(
            breaker.admit(probe_at),
            Admission::Refused,
            "one probe at a time"
        );
        breaker.record(probe_at, true);
        assert_eq!(
            breaker.admit(probe_at + Duration::seconds(1)),
            Admission::Refused
        );

        let second = probe_at + settings.open_for;
        assert_eq!(breaker.admit(second), Admission::Probe);
        breaker.record(second, false);
        assert_eq!(breaker.admit(second), Admission::Admitted);
        for _ in 0..4 {
            breaker.record(second, true);
        }
        assert_eq!(
            breaker.admit(second),
            Admission::Admitted,
            "closing forgot the failures before it"
        );
    }
}
