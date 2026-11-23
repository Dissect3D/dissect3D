//! WE-P07/4 restart reconciliation of earlier workers (WE-005, ENG-031/035;
//! user decision 2026-11-24). Runs once at startup of the execution host,
//! after the Store marked formerly running work `interrupted` and before the
//! controller dispatches. For each earlier attempt whose cleanup is not
//! confirmed:
//! - a recorded launch identity is reconciled natively: no recorded member
//!   alive is `owner_death_containment`; a member found alive is ended by its
//!   verified identity (`restart_survivor_terminated`);
//! - no recorded identity (death between spawn and the identity write, or
//!   before launch) leaves a `cleanup_identity_unrecorded` fault: restart
//!   alone is not proof that a survivor died, so the holds stay;
//! - a native failure or a survivor outliving its bound is a fault too.
//!
//! The reservation index already keeps held resources from being dispatched
//! again, so a fault blocks only the resources it holds.
use crate::store::cleanup::{CleanupEvidence, CleanupOutcome, CleanupReport};
use crate::store::{CoreError, Store};
use std::time::Duration;

/// Bound for one attempt's survivors (a guardian finishing its own cleanup
/// gets half of it).
pub(crate) const SURVIVOR_TIMEOUT: Duration = Duration::from_secs(5);
/// Safe fault code when no launch identity was recorded.
pub(crate) const IDENTITY_UNRECORDED: &str = "cleanup_identity_unrecorded";

/// What one recovery pass established.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RecoveryReport {
    /// Attempts whose cleanup is now confirmed (their holds are released).
    pub(crate) confirmed: usize,
    /// Attempts left with a cleanup fault (their holds stay).
    pub(crate) faulted: usize,
}

/// Reconcile every earlier attempt with unconfirmed cleanup (blocking).
pub(crate) fn reconcile(store: &Store) -> Result<RecoveryReport, CoreError> {
    let mut report = RecoveryReport::default();
    for candidate in store.recovery_candidates()? {
        let outcome = match &candidate.identity {
            None => CleanupOutcome::Fault {
                reason: IDENTITY_UNRECORDED.into(),
            },
            Some(identity) => {
                match dissect3d_platform::reconcile_survivors(identity, SURVIVOR_TIMEOUT) {
                    Ok(absent) => CleanupOutcome::Confirmed(CleanupEvidence::after_restart(absent)),
                    Err(fault) => fault.into(),
                }
            }
        };
        let confirmed = matches!(outcome, CleanupOutcome::Confirmed(_));
        store.record_attempt_cleanup(CleanupReport {
            attempt: candidate.attempt,
            outcome,
        })?;
        if confirmed {
            report.confirmed += 1;
        } else {
            report.faulted += 1;
        }
    }
    Ok(report)
}
