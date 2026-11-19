//! Per-attempt worker file access (WE-P05, WE-004; user decision 2026-11-19).
//!
//! The resolution document, the effective parameters and each captured input
//! reach the worker only as inherited read-only handles opened on verified
//! private files; `execute` names them by native value. Output goes into one
//! engine-created private folder per attempt, named by
//! `output_staging_handle`, laid out so RP-P02's attempt root and capture can
//! take it over. The worker reports names relative to that folder; nothing
//! here (or later) trusts a worker path. Inactive until WE-P06 composes it.
use crate::worker_protocol::ExecuteInput;
use dissect3d_platform::{
    OwnedRoot, PlatformError, PrivateInputReader, RelativePath, WorkerCommand,
};

/// Engine-private parent of every attempt folder.
const ATTEMPTS_DIR: &str = "execution/attempts";
/// The schema's handle bound.
const HANDLE_BYTES_MAX: usize = 1_024;

/// One verified captured input to hand to the worker.
pub(crate) struct AttemptInput<'a> {
    pub(crate) role: &'a str,
    /// Opened with `OwnedRoot::open_immutable_input` on the captured snapshot.
    pub(crate) reader: &'a PrivateInputReader,
    pub(crate) sha256: &'a str,
    pub(crate) byte_length: u64,
}

/// The private-message values for one attempt, plus what the engine checks.
#[derive(Debug)]
pub(crate) struct AttemptHandles {
    pub(crate) resolution_handle: String,
    pub(crate) inputs: Vec<ExecuteInput>,
    pub(crate) output_staging_handle: String,
    pub(crate) effective_parameters_handle: String,
    /// The digest `loaded` must echo: the exact resolution bytes written here.
    pub(crate) resolution_sha256: String,
    /// The staging folder, relative to the engine root, for later capture.
    pub(crate) staging: RelativePath,
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn relative(path: String) -> Result<RelativePath, PlatformError> {
    RelativePath::parse(path).map_err(|_| PlatformError::InvalidPath)
}

/// Create `execution/attempts/<attempt>/` with the resolution and parameters
/// documents and an empty private `staging/` folder, then add every document
/// and input to `command` as inherited read-only handles. Refuses an existing
/// attempt folder, so a stale or repeated attempt never reuses staging.
pub(crate) fn prepare_attempt_files(
    root: &OwnedRoot,
    attempt_id: &str,
    resolution: &[u8],
    parameters: &[u8],
    inputs: &[AttemptInput<'_>],
    command: &mut WorkerCommand,
) -> Result<AttemptHandles, PlatformError> {
    let digits = attempt_id.strip_prefix("att_").unwrap_or_default();
    if digits.len() != 32
        || !digits
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(PlatformError::InvalidPath);
    }
    let folder = format!("{ATTEMPTS_DIR}/{attempt_id}");
    let folder_path = relative(folder.clone())?;
    if root.path_for_native_vfs(&folder_path).exists() {
        return Err(PlatformError::Busy);
    }
    root.ensure_private_directory(&folder_path)?;
    let staging = relative(format!("{folder}/staging"))?;
    root.ensure_private_directory(&staging)?;
    let mut document = |name: &str, bytes: &[u8]| -> Result<String, PlatformError> {
        let path = relative(format!("{folder}/{name}"))?;
        root.write_atomic(&path, bytes)?;
        let reader = root.open_immutable_input(&path)?;
        Ok(command
            .inherit_read_only(reader.snapshot_file())?
            .to_string())
    };
    let resolution_handle = document("resolution.json", resolution)?;
    let effective_parameters_handle = document("parameters.json", parameters)?;
    let mut handles = Vec::with_capacity(inputs.len());
    for input in inputs {
        let value = command.inherit_read_only(input.reader.snapshot_file())?;
        handles.push(ExecuteInput {
            role: input.role.to_owned(),
            handle: value.to_string(),
            sha256: input.sha256.to_owned(),
            byte_length: input.byte_length,
        });
    }
    let output_staging_handle = root
        .path_for_native_vfs(&staging)
        .into_os_string()
        .into_string()
        .map_err(|_| PlatformError::InvalidPath)?;
    if output_staging_handle.len() > HANDLE_BYTES_MAX {
        return Err(PlatformError::InvalidPath);
    }
    Ok(AttemptHandles {
        resolution_handle,
        inputs: handles,
        output_staging_handle,
        effective_parameters_handle,
        resolution_sha256: sha256_hex(resolution),
        staging,
    })
}
