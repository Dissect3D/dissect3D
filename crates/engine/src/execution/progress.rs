//! Progress coalescing (ENG-029, WE-002). Pure: callers pass monotonic instants.
//!
//! The supervisor keeps only the latest observation in memory. It is offered
//! for persistence on a phase change or at most once per `min_interval`, so
//! retained event history stays meaningful. Unknown progress is never
//! fabricated: a null fraction or an unlisted stage clears progress, and a new
//! phase starts with unknown progress.
use std::time::{Duration, Instant};

/// Engine-owned public phases of a running attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AttemptPhase {
    Handshake,
    Loading,
    Executing,
    Stopping,
}
impl AttemptPhase {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Handshake => "handshake",
            Self::Loading => "loading",
            Self::Executing => "executing",
            Self::Stopping => "stopping",
        }
    }
}

/// Known progress: an allowlisted stage and a finite fraction in 0..=1.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct KnownProgress {
    pub(crate) stage: &'static str,
    pub(crate) fraction: f64,
}

/// One snapshot the Store may persist.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ObservationUpdate {
    pub(crate) phase: AttemptPhase,
    pub(crate) progress: Option<KnownProgress>,
}

#[derive(Debug)]
pub(super) struct ProgressCoalescer {
    min_interval: Duration,
    stages: &'static [&'static str],
    current: ObservationUpdate,
    offered: Option<ObservationUpdate>,
    last_offer: Option<Instant>,
}

/// How a worker progress report was classified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ProgressClass {
    Known,
    UnknownFraction,
    UnlistedStage,
}

impl ProgressCoalescer {
    pub(crate) fn new(
        phase: AttemptPhase,
        min_interval: Duration,
        stages: &'static [&'static str],
    ) -> Self {
        Self {
            min_interval,
            stages,
            current: ObservationUpdate {
                phase,
                progress: None,
            },
            offered: None,
            last_offer: None,
        }
    }

    /// A phase change is always offered, with unknown progress.
    pub(crate) fn phase(&mut self, phase: AttemptPhase, now: Instant) -> Option<ObservationUpdate> {
        if phase == self.current.phase {
            return None;
        }
        self.current = ObservationUpdate {
            phase,
            progress: None,
        };
        self.offer(now)
    }

    /// Keep the latest report; offer it only when the interval allows.
    pub(crate) fn report(
        &mut self,
        stage: &str,
        fraction: Option<f64>,
        now: Instant,
    ) -> (ProgressClass, Option<ObservationUpdate>) {
        let listed = self.stages.iter().copied().find(|s| *s == stage);
        let (class, progress) = match (listed, fraction) {
            (Some(stage), Some(fraction))
                if fraction.is_finite() && (0.0..=1.0).contains(&fraction) =>
            {
                (
                    ProgressClass::Known,
                    Some(KnownProgress { stage, fraction }),
                )
            }
            (Some(_), _) => (ProgressClass::UnknownFraction, None),
            (None, _) => (ProgressClass::UnlistedStage, None),
        };
        self.current.progress = progress;
        let due = self
            .last_offer
            .is_none_or(|last| now.saturating_duration_since(last) >= self.min_interval);
        (class, if due { self.offer(now) } else { None })
    }

    /// Offer a pending latest snapshot once its interval has passed.
    pub(crate) fn flush(&mut self, now: Instant) -> Option<ObservationUpdate> {
        let due = self
            .last_offer
            .is_none_or(|last| now.saturating_duration_since(last) >= self.min_interval);
        if due { self.offer(now) } else { None }
    }

    /// When the next `flush` could offer something new.
    pub(crate) fn next_due(&self) -> Option<Instant> {
        if self.offered.as_ref() == Some(&self.current) {
            return None;
        }
        Some(
            self.last_offer
                .map_or_else(Instant::now, |l| l + self.min_interval),
        )
    }

    fn offer(&mut self, now: Instant) -> Option<ObservationUpdate> {
        if self.offered.as_ref() == Some(&self.current) {
            return None;
        }
        self.offered = Some(self.current.clone());
        self.last_offer = Some(now);
        self.offered.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAGES: &[&str] = &["copy"];

    #[test]
    fn latest_progress_is_offered_at_a_bounded_rate_and_on_every_phase_change() {
        let t0 = Instant::now();
        let mut c = ProgressCoalescer::new(AttemptPhase::Executing, Duration::from_secs(1), STAGES);
        let first = c.report("copy", Some(0.1), t0).1.unwrap();
        assert_eq!(first.progress.unwrap().fraction, 0.1);
        // Within the interval: kept in memory, not offered.
        for (i, f) in [0.2, 0.3, 0.4].into_iter().enumerate() {
            let at = t0 + Duration::from_millis(100 * (i as u64 + 1));
            assert_eq!(c.report("copy", Some(f), at), (ProgressClass::Known, None));
        }
        assert!(c.flush(t0 + Duration::from_millis(900)).is_none());
        // After the interval only the latest value is offered, once.
        let latest = c.flush(t0 + Duration::from_secs(1)).unwrap();
        assert_eq!(latest.progress.unwrap().fraction, 0.4);
        assert!(c.flush(t0 + Duration::from_secs(5)).is_none());
        assert_eq!(c.next_due(), None);
        // A phase change is offered immediately, with unknown progress.
        let stopping = c
            .phase(AttemptPhase::Stopping, t0 + Duration::from_millis(1_100))
            .unwrap();
        assert_eq!(
            stopping,
            ObservationUpdate {
                phase: AttemptPhase::Stopping,
                progress: None
            }
        );
        assert!(
            c.phase(AttemptPhase::Stopping, t0 + Duration::from_secs(9))
                .is_none()
        );
    }

    #[test]
    fn unknown_fraction_and_unlisted_stages_never_fabricate_progress() {
        let t0 = Instant::now();
        let mut c = ProgressCoalescer::new(AttemptPhase::Executing, Duration::ZERO, STAGES);
        c.report("copy", Some(0.5), t0);
        let (class, update) = c.report("copy", None, t0);
        assert_eq!(class, ProgressClass::UnknownFraction);
        assert_eq!(update.unwrap().progress, None);
        c.report("copy", Some(0.6), t0);
        let (class, update) = c.report("/home/user/secret stage", Some(0.7), t0);
        assert_eq!(class, ProgressClass::UnlistedStage);
        assert_eq!(update.unwrap().progress, None);
        let (class, _) = c.report("copy", Some(f64::NAN), t0);
        assert_eq!(class, ProgressClass::UnknownFraction);
    }
}
