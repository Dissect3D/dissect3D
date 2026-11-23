//! The engine's absolute shutdown deadline as the execution side sees it
//! (WE-P07/3, WE-005). Core shutdown owns one 5,000-ms deadline; once it is
//! set, every stop phase of every attempt (cooperative cancel, then external
//! tree termination) is capped by the time remaining before it, never by its
//! own full bound. Running out of time is reported as unconfirmed cleanup,
//! never as a clean stop and never by extending the deadline.
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Time kept back for the outcome write and the final store/session
/// completion after the workers are stopped.
pub(crate) const COMPLETION_RESERVE: Duration = Duration::from_millis(250);

#[derive(Debug, Default)]
pub(crate) struct ShutdownClock(OnceLock<Instant>);
impl ShutdownClock {
    /// Start shutdown with the core deadline. The first deadline stays.
    pub(crate) fn begin(&self, deadline: Instant) {
        let _ = self.0.set(deadline);
    }
    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.0.get().copied()
    }
    /// `bound`, capped by what remains before the deadline minus the
    /// completion reserve. Without a shutdown it is `bound` unchanged.
    pub(crate) fn cap(&self, bound: Duration) -> Duration {
        match self.deadline() {
            Some(deadline) => bound.min(
                deadline
                    .saturating_duration_since(Instant::now())
                    .saturating_sub(COMPLETION_RESERVE),
            ),
            None => bound,
        }
    }
    /// A cooperative phase gets at most half of what remains, so external
    /// termination, which always follows, keeps the other half.
    pub(crate) fn cap_cooperative(&self, bound: Duration) -> Duration {
        match self.deadline() {
            Some(_) => bound.min(self.cap(Duration::MAX) / 2),
            None => bound,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phases_are_capped_by_the_remaining_shared_deadline() {
        let clock = ShutdownClock::default();
        assert_eq!(clock.cap(Duration::from_secs(5)), Duration::from_secs(5));
        clock.begin(Instant::now() + Duration::from_secs(1));
        let capped = clock.cap(Duration::from_secs(5));
        assert!(capped <= Duration::from_millis(750), "{capped:?}");
        assert!(capped > Duration::from_millis(500), "{capped:?}");
        // A later deadline never extends the first one.
        clock.begin(Instant::now() + Duration::from_secs(60));
        assert!(clock.cap(Duration::from_secs(5)) <= Duration::from_millis(750));
        // A passed deadline leaves no time, never a negative or full bound.
        let late = ShutdownClock::default();
        late.begin(Instant::now());
        assert_eq!(late.cap(Duration::from_secs(5)), Duration::ZERO);
        // Cooperation keeps half of the remaining time for termination.
        let half = ShutdownClock::default();
        assert_eq!(
            half.cap_cooperative(Duration::from_secs(2)),
            Duration::from_secs(2)
        );
        half.begin(Instant::now() + Duration::from_millis(1250));
        let cooperative = half.cap_cooperative(Duration::from_secs(2));
        assert!(cooperative <= Duration::from_millis(500), "{cooperative:?}");
    }
}
