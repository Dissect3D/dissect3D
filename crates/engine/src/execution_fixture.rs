//! The WE-P05 controlled CPU worker for `test.mesh-copy@fixture-r2` on
//! `test.cpu@fixture-r2` (task `dissect3d.test.mesh-copy` 1.0, variant
//! `fixture`). Test-only: the normal catalog never advertises it, and only an
//! explicitly prepared, isolated host launches it.
//!
//! It speaks the private protocol over the inherited control pipes and reaches
//! files only through what the engine passed (user decision 2026-11-19):
//! the resolution document, the effective parameters and each input arrive as
//! inherited read-only handles named by value; the output goes into the one
//! engine-created private staging folder named by `output_staging_handle`.
//! The candidate names files relative to that folder; the engine never trusts
//! those names or a worker path. No public listener, network or shell.
//!
//! Declared test parameters only: `hold_before_candidate` (stay responsive
//! until cooperative cancellation) and `fail_execution` (declared failure).
//! Invasive faults live in private test harnesses, never in parameters.
#[path = "../tests/fixtures/execution/adapter.rs"]
mod adapter;
// Admission is Unix-only until the Windows submission services are wired (B-WINDOWS).
#[cfg(all(unix, feature = "test-support"))]
#[path = "execution_fixture/attempts.rs"]
pub(crate) mod attempts;
// Discovery facts of the execution host (WE-P06/6).
#[cfg(all(unix, feature = "test-support"))]
#[path = "execution_fixture/observations.rs"]
pub(crate) mod observations;
#[cfg(feature = "test-support")]
#[path = "execution_fixture/preparation.rs"]
pub(crate) mod preparation;
#[cfg(all(test, feature = "test-support"))]
#[path = "execution_fixture/preparation_tests.rs"]
mod preparation_tests;
#[cfg(all(unix, feature = "test-support"))]
#[path = "execution_fixture/provider_export.rs"]
pub(crate) mod provider_export;

use crate::worker_protocol::{FRAME_BYTES_MAX, PROTOCOL_VERSION, random_id};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

pub(crate) use adapter::{ADAPTER_ID, ADAPTER_REVISION};
/// Worker features announced in `hello` and required by the engine.
pub(crate) const FEATURES: &[&str] = &["cooperative_cancel"];
/// Allowlisted progress stages.
pub(crate) const STAGES: &[&str] = &["copy"];
/// Candidate names inside the staging folder.
pub(crate) const OUTPUT_NAME: &str = "mesh.obj";
pub(crate) const DESCRIPTION_NAME: &str = "output.json";
/// One 1-MiB OBJ per attempt (RP-P02/5 proposed policy).
const MESH_BYTES_MAX: u64 = 1_048_576;
/// Bounds on the engine-written documents the worker reads.
const RESOLUTION_BYTES_MAX: u64 = 262_144;
const PARAMETERS_BYTES_MAX: u64 = 16_384;

/// Safe codes for typed findings (engine-owned categories decide meaning).
const PARAMETERS_INVALID: &str = "parameters_invalid";
const INPUTS_INVALID: &str = "inputs_invalid";
const INPUT_MISMATCH: &str = "input_mismatch";
const DECLARED_FAILURE: &str = "fixture_declared_failure";
const OUTPUT_FAILED: &str = "output_write_failed";

/// The worker's own sources, installed into the package by preparation as
/// `(package name, workspace path, bytes)`. They are part of the build
/// closure below, and preparation checks each against its closure entry.
const SOURCE_FILES: [(&str, &str, &[u8]); 3] = [
    (
        "execution_fixture.rs",
        "crates/engine/src/execution_fixture.rs",
        include_bytes!("execution_fixture.rs"),
    ),
    (
        "adapter.rs",
        "crates/engine/tests/fixtures/execution/adapter.rs",
        include_bytes!("../tests/fixtures/execution/adapter.rs"),
    ),
    (
        "execution_fixture_worker.rs",
        "crates/engine/examples/execution_fixture_worker.rs",
        include_bytes!("../examples/execution_fixture_worker.rs"),
    ),
];

/// The build closure this binary was compiled from (see `build.rs`): every
/// file of the engine and its workspace path dependencies, the workspace
/// manifest, `Cargo.lock`, toolchain configuration, rustc release and target.
const CLOSURE_MANIFEST: &str = include_str!(concat!(env!("OUT_DIR"), "/worker_closure.txt"));
/// SHA-256 of `CLOSURE_MANIFEST`, computed by the build script.
const CLOSURE_SHA256: &str = env!("D3D_R2_WORKER_CLOSURE_SHA256");
const MARKER: &str = concat!(
    "D3D-R2-WORKER-CLOSURE:v2:",
    env!("D3D_R2_WORKER_CLOSURE_SHA256"),
    ";"
);

const fn marker_bytes() -> [u8; MARKER.len()] {
    let mut out = [0u8; MARKER.len()];
    let mut i = 0;
    while i < out.len() {
        out[i] = MARKER.as_bytes()[i];
        i += 1;
    }
    out
}

/// Embedded in every build of the worker and kept alive by `hello`: the
/// digest of the exact build closure this binary was compiled from.
/// Preparation requires the installed worker to contain the marker for the
/// closure it records, so a worker built from any other sources, dependency
/// lock or toolchain is refused (WE-P05/1 and /3: no recorded identity that is
/// never executed).
static SOURCE_MARKER: [u8; MARKER.len()] = marker_bytes();

/// The marker expected for a recorded closure digest (runtime, preparation).
fn expected_marker(closure_sha256: &str) -> Vec<u8> {
    format!("D3D-R2-WORKER-CLOSURE:v2:{closure_sha256};").into_bytes()
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The declared test parameters, closed: unknown keys or non-booleans reject.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FixtureParameters {
    pub(crate) hold_before_candidate: bool,
    pub(crate) fail_execution: bool,
}
impl FixtureParameters {
    pub(crate) fn parse(bytes: &[u8]) -> Option<Self> {
        let Value::Object(map) = serde_json::from_slice::<Value>(bytes).ok()? else {
            return None;
        };
        let mut parameters = Self::default();
        for (key, value) in map {
            let flag = value.as_bool()?;
            match key.as_str() {
                "hold_before_candidate" => parameters.hold_before_candidate = flag,
                "fail_execution" => parameters.fail_execution = flag,
                _ => return None,
            }
        }
        Some(parameters)
    }
    /// The canonical effective document the engine hands the worker.
    pub(crate) fn to_document(self) -> Vec<u8> {
        json!({
            "fail_execution": self.fail_execution,
            "hold_before_candidate": self.hold_before_candidate,
        })
        .to_string()
        .into_bytes()
    }
}

/// Test-only fault hooks for the private harness (never compiled outside tests).
#[cfg(test)]
pub(crate) const FAULT_ENV: &str = "D3D_R2_WORKER_FAULT";

/// Worker process entry. Never returns.
pub fn run_execution_fixture_worker() -> ! {
    std::process::exit(match Worker::start().and_then(Worker::serve) {
        Ok(()) => 0,
        Err(Exit(code)) => code,
    })
}

/// A process exit status for an unrecoverable worker-side condition. The
/// engine observes it as a crash-style failure, never as success.
#[derive(Debug)]
struct Exit(i32);

struct Worker {
    session: String,
    commands: BufReader<File>,
    reports: File,
    resolution: Option<(String, Vec<u8>)>,
    grant: Option<String>,
    /// `job_id`/`attempt_id` of the loaded assignment, for scoped reports.
    scope: [(&'static str, Value); 2],
    executed: bool,
}

/// One engine command, after envelope checks.
struct Command {
    kind: String,
    payload: Map<String, Value>,
    command_id: Option<String>,
    job_id: Value,
    attempt_id: Value,
}

/// Read a listed inherited input from offset 0 with a byte bound.
fn read_inherited(handle: &str, limit: u64) -> Option<Vec<u8>> {
    if handle.is_empty() || handle.len() > 20 || !handle.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut file = dissect3d_platform::worker_inherited_input(handle.parse().ok()?).ok()?;
    file.seek(SeekFrom::Start(0)).ok()?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() as u64 <= limit).then_some(bytes)
}

impl Worker {
    fn start() -> Result<Self, Exit> {
        let session =
            std::env::var(crate::execution::launcher::WORKER_SESSION_ENV).map_err(|_| Exit(2))?;
        let (commands, reports) =
            dissect3d_platform::worker_control_channels().map_err(|_| Exit(2))?;
        let build = std::env::current_exe()
            .and_then(std::fs::read)
            .map_err(|_| Exit(2))?;
        // Keep the source marker in every linked worker.
        std::hint::black_box(&SOURCE_MARKER);
        let mut worker = Self {
            session,
            commands: BufReader::new(commands),
            reports,
            resolution: None,
            grant: None,
            scope: [("job_id", Value::Null), ("attempt_id", Value::Null)],
            executed: false,
        };
        worker.send(
            "hello",
            json!({
                "worker_build_sha256": sha256_hex(&build),
                "adapter_id": ADAPTER_ID,
                "adapter_revision": ADAPTER_REVISION,
                "features": FEATURES,
            }),
            &[],
        )?;
        Ok(worker)
    }

    fn send(&mut self, kind: &str, payload: Value, extra: &[(&str, Value)]) -> Result<(), Exit> {
        let mut object = Map::new();
        object.insert("protocol_version".into(), PROTOCOL_VERSION.into());
        object.insert("kind".into(), kind.into());
        object.insert("session_id".into(), self.session.clone().into());
        object.insert("message_id".into(), random_id("msg_").into());
        object.insert("payload".into(), payload);
        for (key, value) in extra {
            object.insert((*key).into(), value.clone());
        }
        let mut frame = Value::Object(object).to_string().into_bytes();
        frame.push(b'\n');
        #[cfg(test)]
        let frame = test_fault::rewrite(kind, frame);
        if frame.len() > FRAME_BYTES_MAX {
            return Err(Exit(2));
        }
        self.reports.write_all(&frame).map_err(|_| Exit(3))?;
        self.reports.flush().map_err(|_| Exit(3))
    }

    /// The next command; `None` at end of the control channel.
    fn next(&mut self) -> Result<Option<Command>, Exit> {
        let mut line = Vec::new();
        let read = (&mut self.commands)
            .take(FRAME_BYTES_MAX as u64)
            .read_until(b'\n', &mut line)
            .map_err(|_| Exit(2))?;
        if read == 0 {
            return Ok(None);
        }
        if line.pop() != Some(b'\n') {
            return Err(Exit(2));
        }
        let Ok(Value::Object(mut object)) = serde_json::from_slice::<Value>(&line) else {
            return Err(Exit(2));
        };
        if object.get("protocol_version").and_then(Value::as_str) != Some(PROTOCOL_VERSION)
            || object.get("session_id").and_then(Value::as_str) != Some(self.session.as_str())
        {
            return Err(Exit(2));
        }
        let Some(Value::String(kind)) = object.remove("kind") else {
            return Err(Exit(2));
        };
        let Some(Value::Object(payload)) = object.remove("payload") else {
            return Err(Exit(2));
        };
        Ok(Some(Command {
            kind,
            payload,
            command_id: object
                .remove("command_id")
                .and_then(|v| v.as_str().map(str::to_owned)),
            job_id: object.remove("job_id").unwrap_or(Value::Null),
            attempt_id: object.remove("attempt_id").unwrap_or(Value::Null),
        }))
    }

    fn serve(mut self) -> Result<(), Exit> {
        while let Some(command) = self.next()? {
            let reply = || command.command_id.clone().map(Value::from).ok_or(Exit(2));
            let scoped = [
                ("job_id", command.job_id.clone()),
                ("attempt_id", command.attempt_id.clone()),
            ];
            let text = |key: &str| {
                command
                    .payload
                    .get(key)
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or(Exit(2))
            };
            match command.kind.as_str() {
                "configure" => {
                    let handle = text("resolution_handle")?;
                    let bytes = read_inherited(&handle, RESOLUTION_BYTES_MAX).ok_or(Exit(2))?;
                    self.resolution = Some((handle, bytes));
                    self.send(
                        "configured",
                        json!({"accepted": true}),
                        &[("in_reply_to", reply()?)],
                    )?;
                }
                "load" => {
                    let handle = text("resolution_handle")?;
                    let grant = text("grant_id")?;
                    // Load evidence: the digest of the exact resolution read
                    // through the configured handle.
                    let digest = match &self.resolution {
                        Some((configured, bytes)) if *configured == handle => sha256_hex(bytes),
                        _ => return Err(Exit(2)),
                    };
                    self.grant = Some(grant.clone());
                    self.scope = scoped.clone();
                    self.send(
                        "loaded",
                        json!({"grant_id": grant, "resolution_sha256": digest}),
                        &[
                            scoped[0].clone(),
                            scoped[1].clone(),
                            ("in_reply_to", reply()?),
                        ],
                    )?;
                }
                "execute" => {
                    // One-shot permission for the loaded grant only.
                    if self.executed || self.grant.as_deref() != Some(text("grant_id")?.as_str()) {
                        return Err(Exit(2));
                    }
                    self.executed = true;
                    let (kind, payload) = self.execute(&command.payload)?;
                    if let Some(kind) = kind {
                        self.send(kind, payload, &scoped)?;
                    }
                }
                "cancel" => self.send(
                    "cancel_ack",
                    json!({"observed": true}),
                    &[
                        scoped[0].clone(),
                        scoped[1].clone(),
                        ("in_reply_to", reply()?),
                    ],
                )?,
                "ping" => self.send("pong", json!({}), &[("in_reply_to", reply()?)])?,
                "shutdown" => {
                    self.send(
                        "shutdown_ack",
                        json!({"observed": true}),
                        &[("in_reply_to", reply()?)],
                    )?;
                    return Ok(());
                }
                _ => return Err(Exit(2)),
            }
        }
        Ok(())
    }

    /// Run the adapter. `None` kind means hold: stay responsive, report nothing.
    fn execute(
        &mut self,
        payload: &Map<String, Value>,
    ) -> Result<(Option<&'static str>, Value), Exit> {
        let finding = |kind, code: &str| Ok((Some(kind), json!({"code": code})));
        let Some(parameters) = payload
            .get("effective_parameters_handle")
            .and_then(Value::as_str)
            .and_then(|handle| read_inherited(handle, PARAMETERS_BYTES_MAX))
            .and_then(|bytes| FixtureParameters::parse(&bytes))
        else {
            return finding("rejected", PARAMETERS_INVALID);
        };
        let inputs = payload.get("inputs").and_then(Value::as_array);
        let Some([input]) = inputs.map(Vec::as_slice) else {
            return finding("rejected", INPUTS_INVALID);
        };
        let (Some("mesh"), Some(handle), Some(sha256), Some(length)) = (
            input.get("role").and_then(Value::as_str),
            input.get("handle").and_then(Value::as_str),
            input.get("sha256").and_then(Value::as_str),
            input.get("byte_length").and_then(Value::as_u64),
        ) else {
            return finding("rejected", INPUTS_INVALID);
        };
        if length == 0 || length > MESH_BYTES_MAX {
            return finding("rejected", INPUTS_INVALID);
        }
        let Some(bytes) = read_inherited(handle, length) else {
            return finding("rejected", INPUT_MISMATCH);
        };
        if bytes.len() as u64 != length || sha256_hex(&bytes) != sha256 {
            return finding("rejected", INPUT_MISMATCH);
        }
        let scope = self.scope.clone();
        self.send(
            "progress",
            json!({"stage": STAGES[0], "fraction": 0.0}),
            &scope,
        )?;
        if parameters.fail_execution {
            return finding("execution_failed", DECLARED_FAILURE);
        }
        if parameters.hold_before_candidate {
            return Ok((None, Value::Null));
        }
        let Some(staging) = payload.get("output_staging_handle").and_then(Value::as_str) else {
            return finding("execution_failed", OUTPUT_FAILED);
        };
        let output = adapter::copy_mesh(&bytes);
        let description = json!({"mesh": [OUTPUT_NAME]}).to_string().into_bytes();
        let staging = Path::new(staging);
        if !staging.is_absolute()
            || write_new(&staging.join(OUTPUT_NAME), &output).is_err()
            || write_new(&staging.join(DESCRIPTION_NAME), &description).is_err()
        {
            return finding("execution_failed", OUTPUT_FAILED);
        }
        Ok((
            Some("candidate"),
            json!({
                "description_handle": DESCRIPTION_NAME,
                "files": [{
                    "relative_name": OUTPUT_NAME,
                    "byte_length": output.len(),
                    "sha256": sha256_hex(&output),
                }],
            }),
        ))
    }
}

/// Create a new file (never replace) and make its bytes durable.
fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod test_fault {
    /// Private harness faults: rewrite one outgoing report.
    pub(super) fn rewrite(kind: &str, frame: Vec<u8>) -> Vec<u8> {
        match (std::env::var(super::FAULT_ENV).as_deref(), kind) {
            // An unknown field: a closed-schema violation.
            (Ok("malformed_candidate"), "candidate") => {
                let mut value: serde_json::Value =
                    serde_json::from_slice(&frame[..frame.len() - 1]).unwrap();
                value["payload"]["unexpected"] = true.into();
                let mut bytes = value.to_string().into_bytes();
                bytes.push(b'\n');
                bytes
            }
            // Not JSON at all.
            (Ok("garbage_loaded"), "loaded") => b"{not json\n".to_vec(),
            _ => frame,
        }
    }
}
