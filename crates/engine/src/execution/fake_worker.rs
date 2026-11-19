//! Test-only scripted worker over in-memory streams. It exercises the codec,
//! legality and supervisor; it is not a provider, a process or cleanup proof.
use super::legality::SessionIdentity;
use super::supervisor::{LaunchFailure, LaunchLedger, Launched, SupervisedProcess, WorkerLauncher};
use crate::store::CoreError;
use crate::store::cleanup::{CleanupEvidence, test_identity};
use crate::store::launch_identity::LaunchRecord;
use crate::worker_protocol::random_id;
use dissect3d_platform::{CleanupFault, WorkerIdentity};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, ReadHalf, WriteHalf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum OnLoad {
    Loaded,
    LoadedTwice,
    Fail,
    Hang,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum OnExecute {
    Candidate,
    Fail,
    Hang,
    /// Close the control channel (crash before a report).
    Exit,
    /// Many progress reports, then a candidate.
    ProgressThenCandidate(u32),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LaunchMode {
    Ok,
    NotStarted,
    Uncertain,
}

#[derive(Clone, Debug)]
pub(super) struct Behavior {
    pub(super) session_override: Option<&'static str>,
    pub(super) configured: bool,
    pub(super) on_load: OnLoad,
    pub(super) on_execute: OnExecute,
    pub(super) pong: bool,
    pub(super) cancel_ack: bool,
    pub(super) candidate_after_cancel: bool,
    /// Bytes written to diagnostics before the execution report.
    pub(super) diagnostics: usize,
}
impl Default for Behavior {
    fn default() -> Self {
        Self {
            session_override: None,
            configured: true,
            on_load: OnLoad::Loaded,
            on_execute: OnExecute::Candidate,
            pong: true,
            cancel_ack: true,
            candidate_after_cancel: false,
            diagnostics: 0,
        }
    }
}

/// What the fake observed.
#[derive(Debug, Default)]
pub(super) struct Record {
    pub(super) launches: AtomicU32,
    pub(super) executes: AtomicU32,
    pub(super) pings: AtomicU32,
    pub(super) shutdowns: AtomicU32,
    pub(super) terminations: AtomicU32,
    pub(super) cancels: Mutex<Vec<String>>,
}
impl Record {
    pub(super) fn count(counter: &AtomicU32) -> u32 {
        counter.load(Ordering::SeqCst)
    }
    pub(super) fn cancel_reasons(&self) -> Vec<String> {
        self.cancels.lock().unwrap().clone()
    }
}

pub(super) struct FakeLauncher {
    pub(super) behavior: Behavior,
    pub(super) record: Arc<Record>,
    pub(super) mode: LaunchMode,
    pub(super) cleanup: Result<(), CleanupFault>,
}
impl FakeLauncher {
    pub(super) fn new(behavior: Behavior) -> (Self, Arc<Record>) {
        let record = Arc::new(Record::default());
        (
            Self {
                behavior,
                record: Arc::clone(&record),
                mode: LaunchMode::Ok,
                cleanup: Ok(()),
            },
            record,
        )
    }
}

pub(super) struct FakeProcess {
    record: Arc<Record>,
    worker: tokio::task::AbortHandle,
    cleanup: Result<(), CleanupFault>,
    identity: WorkerIdentity,
}
impl SupervisedProcess for FakeProcess {
    fn identity(&self) -> WorkerIdentity {
        self.identity.clone()
    }
    fn terminate_tree(&mut self, _deadline: Instant) -> Result<CleanupEvidence, CleanupFault> {
        self.record.terminations.fetch_add(1, Ordering::SeqCst);
        self.worker.abort();
        let identity = self.identity.clone();
        self.cleanup.map(|()| CleanupEvidence::for_test(identity))
    }
}

/// How the test ledger answers a launch record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LedgerMode {
    Accept,
    Reject,
    /// Block past any launch bound before accepting.
    Stall,
}
/// Test launch ledger: keeps every record and, with `record`, how many
/// executes the fake worker had already received when the record arrived.
pub(crate) struct TestLedger {
    pub(super) mode: LedgerMode,
    pub(super) records: Mutex<Vec<LaunchRecord>>,
    pub(super) executes_before_record: Mutex<Vec<u32>>,
    pub(super) worker: Option<Arc<Record>>,
}
impl TestLedger {
    pub(crate) fn new(mode: LedgerMode) -> Arc<Self> {
        Self::observing(mode, None)
    }
    pub(super) fn observing(mode: LedgerMode, worker: Option<Arc<Record>>) -> Arc<Self> {
        Arc::new(Self {
            mode,
            records: Mutex::new(Vec::new()),
            executes_before_record: Mutex::new(Vec::new()),
            worker,
        })
    }
    pub(super) fn identities(&self) -> Vec<WorkerIdentity> {
        let records = self.records.lock().unwrap();
        records.iter().map(|r| r.identity.clone()).collect()
    }
}
impl LaunchLedger for TestLedger {
    fn record_launch(&self, record: LaunchRecord) -> Result<(), CoreError> {
        if let Some(worker) = &self.worker {
            self.executes_before_record
                .lock()
                .unwrap()
                .push(Record::count(&worker.executes));
        }
        self.records.lock().unwrap().push(record);
        match self.mode {
            LedgerMode::Accept => Ok(()),
            LedgerMode::Reject => Err(CoreError::Conflict),
            LedgerMode::Stall => {
                std::thread::sleep(std::time::Duration::from_secs(3));
                Ok(())
            }
        }
    }
}

impl WorkerLauncher for FakeLauncher {
    type Process = FakeProcess;
    type Reader = ReadHalf<DuplexStream>;
    type Writer = WriteHalf<DuplexStream>;
    type Diagnostics = DuplexStream;
    fn launch(
        self,
        session: &SessionIdentity,
    ) -> Result<Launched<FakeProcess, Self::Reader, Self::Writer, DuplexStream>, LaunchFailure>
    {
        self.record.launches.fetch_add(1, Ordering::SeqCst);
        match self.mode {
            LaunchMode::NotStarted => return Err(LaunchFailure::NotStarted),
            LaunchMode::Uncertain => return Err(LaunchFailure::Uncertain),
            LaunchMode::Ok => {}
        }
        let (engine, worker) = tokio::io::duplex(65_536);
        let (diagnostics, worker_diagnostics) = tokio::io::duplex(65_536);
        let (engine_read, engine_write) = tokio::io::split(engine);
        let task = tokio::runtime::Handle::current().spawn(run(
            self.behavior,
            Arc::clone(&self.record),
            session.clone(),
            worker,
            worker_diagnostics,
        ));
        Ok(Launched {
            process: FakeProcess {
                record: self.record,
                worker: task.abort_handle(),
                cleanup: self.cleanup,
                identity: test_identity(&session.session_id, "fake"),
            },
            control_from_worker: engine_read,
            control_to_worker: engine_write,
            diagnostics,
        })
    }
}

pub(super) fn line(session: &str, kind: &str, payload: Value, extra: &[(&str, Value)]) -> Vec<u8> {
    let mut object = serde_json::Map::new();
    object.insert("protocol_version".into(), "d3d-worker/1".into());
    object.insert("kind".into(), kind.into());
    object.insert("session_id".into(), session.into());
    object.insert("message_id".into(), random_id("msg_").into());
    object.insert("payload".into(), payload);
    for (key, value) in extra {
        object.insert((*key).into(), value.clone());
    }
    let mut bytes = Value::Object(object).to_string().into_bytes();
    bytes.push(b'\n');
    bytes
}

async fn run(
    behavior: Behavior,
    record: Arc<Record>,
    identity: SessionIdentity,
    control: DuplexStream,
    mut diagnostics: DuplexStream,
) {
    let session = behavior
        .session_override
        .unwrap_or(&identity.session_id)
        .to_owned();
    let scoped = |reply: Option<&str>| {
        let mut extra = vec![
            ("job_id", Value::from(identity.assignment.job_id.clone())),
            ("attempt_id", identity.assignment.attempt_id.clone().into()),
        ];
        if let Some(reply) = reply {
            extra.push(("in_reply_to", reply.into()));
        }
        extra
    };
    let candidate = line(
        &session,
        "candidate",
        json!({"description_handle": "out:desc", "files": [
            {"relative_name": "mesh.obj", "byte_length": 10, "sha256": "d".repeat(64)}
        ]}),
        &scoped(None),
    );
    let (reader, mut writer) = tokio::io::split(control);
    let hello = json!({
        "worker_build_sha256": "a".repeat(64),
        "adapter_id": "test.mesh-copy",
        "adapter_revision": "fixture-r2",
        "features": ["cooperative_cancel"],
    });
    if writer
        .write_all(&line(&session, "hello", hello, &[]))
        .await
        .is_err()
    {
        return;
    }
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(text)) = lines.next_line().await {
        let Ok(command) = serde_json::from_str::<Value>(&text) else {
            return;
        };
        let id = command["command_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let mut out = Vec::new();
        match command["kind"].as_str().unwrap_or_default() {
            "configure" if behavior.configured => out.push(line(
                &session,
                "configured",
                json!({"accepted": true}),
                &[("in_reply_to", id.into())],
            )),
            "load" => {
                let loaded = line(
                    &session,
                    "loaded",
                    json!({"grant_id": identity.grant_id, "resolution_sha256": "b".repeat(64)}),
                    &scoped(Some(&id)),
                );
                match behavior.on_load {
                    OnLoad::Loaded => out.push(loaded),
                    OnLoad::LoadedTwice => out.extend([loaded.clone(), loaded]),
                    OnLoad::Fail => out.push(line(
                        &session,
                        "load_failed",
                        json!({"code": "C:\\models\\weights missing"}),
                        &scoped(Some(&id)),
                    )),
                    OnLoad::Hang => {}
                }
            }
            "execute" => {
                record.executes.fetch_add(1, Ordering::SeqCst);
                if behavior.diagnostics > 0 {
                    // Blocks unless the supervisor drains diagnostics.
                    let _ = diagnostics
                        .write_all(&vec![b'x'; behavior.diagnostics])
                        .await;
                }
                match behavior.on_execute {
                    OnExecute::Candidate => out.push(candidate.clone()),
                    OnExecute::Fail => out.push(line(
                        &session,
                        "execution_failed",
                        json!({"code": "upstream said /home/user/secret"}),
                        &scoped(None),
                    )),
                    OnExecute::Hang => {}
                    OnExecute::Exit => return,
                    OnExecute::ProgressThenCandidate(n) => {
                        for i in 0..n {
                            out.push(line(
                                &session,
                                "progress",
                                json!({"stage": "copy", "fraction": f64::from(i) / f64::from(n)}),
                                &scoped(None),
                            ));
                        }
                        out.push(candidate.clone());
                    }
                }
            }
            "ping" => {
                record.pings.fetch_add(1, Ordering::SeqCst);
                if behavior.pong {
                    out.push(line(
                        &session,
                        "pong",
                        json!({}),
                        &[("in_reply_to", id.into())],
                    ));
                }
            }
            "cancel" => {
                record
                    .cancels
                    .lock()
                    .unwrap()
                    .push(command["payload"]["reason"].as_str().unwrap_or("").into());
                if behavior.cancel_ack {
                    out.push(line(
                        &session,
                        "cancel_ack",
                        json!({"observed": true}),
                        &scoped(Some(&id)),
                    ));
                }
                if behavior.candidate_after_cancel {
                    out.push(candidate.clone());
                }
            }
            "shutdown" => {
                record.shutdowns.fetch_add(1, Ordering::SeqCst);
                out.push(line(
                    &session,
                    "shutdown_ack",
                    json!({"observed": true}),
                    &[("in_reply_to", id.into())],
                ));
            }
            _ => {}
        }
        for bytes in out {
            if writer.write_all(&bytes).await.is_err() {
                return;
            }
        }
    }
}
