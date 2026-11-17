//! Pure worker-session legality (WC-001, WC-003, WE-004). No I/O, no clock.
//!
//! Order: hello -> configure/configured -> load/loaded -> execute -> candidate
//! (or a typed failure). The supervisor creates every identity; a frame for
//! another session or attempt, an acknowledgement of anything but the one
//! outstanding command, or a report out of order is a violation. Execute
//! permission is issued at most once per session, whatever state follows.
//! Loaded evidence, responsiveness (pong) and progress are separate facts, and
//! nothing here renews a phase bound or the attempt deadline.
use crate::worker_protocol::{
    Assignment, CancelReason, CandidateReport, EngineCommand, ExecuteInput, InboundFrame,
    ProtocolViolation, WorkerReport, encode_command, random_id,
};

/// What the hello must match before configuration (exact identities).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WorkerExpectation {
    pub(crate) worker_build_sha256: String,
    pub(crate) adapter_id: String,
    pub(crate) adapter_revision: String,
    pub(crate) required_features: Vec<String>,
    /// The resolution digest `loaded` must echo.
    pub(crate) resolution_sha256: String,
}

/// Supervisor-created identities for one attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionIdentity {
    pub(crate) session_id: String,
    pub(crate) grant_id: String,
    pub(crate) assignment: Assignment,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    AwaitHello,
    Greeted,
    Configuring,
    Configured,
    Loading,
    Loaded,
    Executing,
    /// A candidate or typed failure arrived; only stop traffic remains.
    Finished,
    Canceling,
    ShuttingDown,
}

/// A legal observation the supervisor acts on.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Observation {
    Hello,
    Configured,
    Loaded,
    LoadFailed,
    Progress {
        stage: String,
        fraction: Option<f64>,
    },
    Candidate(CandidateReport),
    Rejected,
    ExecutionFailed,
    CancelAcknowledged,
    Released,
    ShutdownAcknowledged,
    /// Control-loop responsiveness only: never progress, never a renewal.
    Pong,
}

#[derive(Debug)]
pub(crate) struct Session {
    identity: SessionIdentity,
    expectation: WorkerExpectation,
    phase: Phase,
    /// The one outstanding phase command.
    outstanding: Option<String>,
    /// Commands already acknowledged (at most one per phase command).
    acknowledged: Vec<String>,
    ping: Option<String>,
    executed: bool,
    /// An execution report (candidate or typed failure) was accepted.
    reported: bool,
    loaded: bool,
}

impl Session {
    pub(crate) fn new(identity: SessionIdentity, expectation: WorkerExpectation) -> Self {
        Self {
            identity,
            expectation,
            phase: Phase::AwaitHello,
            outstanding: None,
            acknowledged: Vec::new(),
            ping: None,
            executed: false,
            reported: false,
            loaded: false,
        }
    }

    pub(crate) fn phase(&self) -> Phase {
        self.phase
    }
    /// Explicit `loaded` evidence for this grant; process existence is not.
    pub(crate) fn loaded(&self) -> bool {
        self.loaded
    }
    pub(crate) fn execute_issued(&self) -> bool {
        self.executed
    }

    fn send(&mut self, command: &EngineCommand, next: Phase) -> Result<Vec<u8>, ProtocolViolation> {
        let id = random_id("cmd_");
        let frame = encode_command(
            &self.identity.session_id,
            &id,
            &self.identity.assignment,
            command,
        )?;
        self.outstanding = Some(id);
        self.phase = next;
        Ok(frame)
    }
    fn expect(&self, phase: Phase) -> Result<(), ProtocolViolation> {
        if self.phase == phase {
            Ok(())
        } else {
            Err(ProtocolViolation::IllegalSequence)
        }
    }

    pub(crate) fn configure(
        &mut self,
        resolution_handle: String,
    ) -> Result<Vec<u8>, ProtocolViolation> {
        self.expect(Phase::Greeted)?;
        let features = self.expectation.required_features.clone();
        self.send(
            &EngineCommand::Configure {
                resolution_handle,
                features,
            },
            Phase::Configuring,
        )
    }

    pub(crate) fn load(&mut self, resolution_handle: String) -> Result<Vec<u8>, ProtocolViolation> {
        self.expect(Phase::Configured)?;
        let grant_id = self.identity.grant_id.clone();
        self.send(
            &EngineCommand::Load {
                resolution_handle,
                grant_id,
            },
            Phase::Loading,
        )
    }

    /// One-shot execute permission: a second request is refused in every state.
    pub(crate) fn execute(
        &mut self,
        inputs: Vec<ExecuteInput>,
        output_staging_handle: String,
        effective_parameters_handle: String,
    ) -> Result<Vec<u8>, ProtocolViolation> {
        if self.executed {
            return Err(ProtocolViolation::RepeatedExecute);
        }
        self.expect(Phase::Loaded)?;
        let grant_id = self.identity.grant_id.clone();
        let frame = self.send(
            &EngineCommand::Execute {
                grant_id,
                inputs,
                output_staging_handle,
                effective_parameters_handle,
            },
            Phase::Executing,
        )?;
        // Execute has no acknowledgement; its outcome is a report.
        self.outstanding = None;
        self.executed = true;
        Ok(frame)
    }

    /// Cooperative cancellation for loading or executing work. An
    /// acknowledgement is an observation, never termination.
    pub(crate) fn cancel(&mut self, reason: CancelReason) -> Result<Vec<u8>, ProtocolViolation> {
        if !matches!(
            self.phase,
            Phase::Loading | Phase::Loaded | Phase::Executing
        ) {
            return Err(ProtocolViolation::IllegalSequence);
        }
        self.send(&EngineCommand::Cancel { reason }, Phase::Canceling)
    }

    pub(crate) fn shutdown(&mut self, reason: &'static str) -> Result<Vec<u8>, ProtocolViolation> {
        if matches!(self.phase, Phase::AwaitHello | Phase::ShuttingDown) {
            return Err(ProtocolViolation::IllegalSequence);
        }
        self.send(&EngineCommand::Shutdown { reason }, Phase::ShuttingDown)
    }

    /// A ping when none is outstanding; never more than one in flight.
    pub(crate) fn ping(&mut self) -> Result<Option<Vec<u8>>, ProtocolViolation> {
        if self.ping.is_some() || self.phase == Phase::AwaitHello {
            return Ok(None);
        }
        let id = random_id("cmd_");
        let frame = encode_command(
            &self.identity.session_id,
            &id,
            &self.identity.assignment,
            &EngineCommand::Ping,
        )?;
        self.ping = Some(id);
        Ok(Some(frame))
    }
    pub(crate) fn ping_outstanding(&self) -> bool {
        self.ping.is_some()
    }

    fn acknowledge(
        &mut self,
        reply: Option<&String>,
        phase: Phase,
    ) -> Result<(), ProtocolViolation> {
        let reply = reply.ok_or(ProtocolViolation::InvalidRecord)?;
        if self.acknowledged.contains(reply) {
            return Err(ProtocolViolation::StaleAcknowledgement);
        }
        self.expect(phase)?;
        if self.outstanding.as_ref() != Some(reply) {
            return Err(ProtocolViolation::StaleAcknowledgement);
        }
        self.outstanding = None;
        self.acknowledged.push(reply.clone());
        Ok(())
    }

    /// Check one decoded frame against identity and order.
    pub(crate) fn accept(&mut self, frame: InboundFrame) -> Result<Observation, ProtocolViolation> {
        if frame.session_id != self.identity.session_id {
            return Err(ProtocolViolation::WrongSession);
        }
        if frame
            .assignment
            .as_ref()
            .is_some_and(|a| *a != self.identity.assignment)
        {
            return Err(ProtocolViolation::WrongAttempt);
        }
        let reply = frame.in_reply_to.as_ref();
        // Execution reports may race a cancel, but only one is ever accepted.
        let executing_or_racing_cancel = !self.reported
            && (self.phase == Phase::Executing
                || (self.phase == Phase::Canceling && self.executed));
        match frame.report {
            WorkerReport::Hello(hello) => {
                self.expect(Phase::AwaitHello)?;
                let expected = &self.expectation;
                let features_ok = expected
                    .required_features
                    .iter()
                    .all(|f| hello.features.contains(f));
                if hello.worker_build_sha256 != expected.worker_build_sha256
                    || hello.adapter_id != expected.adapter_id
                    || hello.adapter_revision != expected.adapter_revision
                    || !features_ok
                {
                    return Err(ProtocolViolation::IncompatibleHello);
                }
                self.phase = Phase::Greeted;
                Ok(Observation::Hello)
            }
            WorkerReport::Configured => {
                self.acknowledge(reply, Phase::Configuring)?;
                self.phase = Phase::Configured;
                Ok(Observation::Configured)
            }
            WorkerReport::Loaded {
                grant_id,
                resolution_sha256,
            } => {
                if grant_id != self.identity.grant_id {
                    return Err(ProtocolViolation::WrongGrant);
                }
                if resolution_sha256 != self.expectation.resolution_sha256 {
                    return Err(ProtocolViolation::WrongResolution);
                }
                self.acknowledge(reply, Phase::Loading)?;
                self.loaded = true;
                self.phase = Phase::Loaded;
                Ok(Observation::Loaded)
            }
            WorkerReport::LoadFailed => {
                self.acknowledge(reply, Phase::Loading)?;
                self.phase = Phase::Finished;
                Ok(Observation::LoadFailed)
            }
            WorkerReport::Progress { stage, fraction } if executing_or_racing_cancel => {
                Ok(Observation::Progress { stage, fraction })
            }
            WorkerReport::Candidate(report) if executing_or_racing_cancel => {
                self.finish_execution();
                Ok(Observation::Candidate(report))
            }
            WorkerReport::Rejected if executing_or_racing_cancel => {
                self.finish_execution();
                Ok(Observation::Rejected)
            }
            WorkerReport::ExecutionFailed if executing_or_racing_cancel => {
                self.finish_execution();
                Ok(Observation::ExecutionFailed)
            }
            WorkerReport::CancelAck => {
                self.acknowledge(reply, Phase::Canceling)?;
                Ok(Observation::CancelAcknowledged)
            }
            WorkerReport::Released { grant_id } => {
                if grant_id != self.identity.grant_id {
                    return Err(ProtocolViolation::WrongGrant);
                }
                if !self.loaded
                    || !matches!(
                        self.phase,
                        Phase::Finished | Phase::Canceling | Phase::ShuttingDown
                    )
                {
                    return Err(ProtocolViolation::IllegalSequence);
                }
                Ok(Observation::Released)
            }
            WorkerReport::ShutdownAck => {
                self.acknowledge(reply, Phase::ShuttingDown)?;
                Ok(Observation::ShutdownAcknowledged)
            }
            WorkerReport::Pong => {
                let reply = reply.ok_or(ProtocolViolation::InvalidRecord)?;
                if self.ping.as_ref() != Some(reply) {
                    return Err(ProtocolViolation::StaleAcknowledgement);
                }
                self.ping = None;
                Ok(Observation::Pong)
            }
            WorkerReport::Progress { .. }
            | WorkerReport::Candidate(_)
            | WorkerReport::Rejected
            | WorkerReport::ExecutionFailed => Err(ProtocolViolation::IllegalSequence),
        }
    }

    /// The execution report is final; a racing cancel keeps its own phase.
    fn finish_execution(&mut self) {
        self.reported = true;
        if self.phase == Phase::Executing {
            self.phase = Phase::Finished;
        }
    }
}
