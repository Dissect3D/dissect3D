//! Native setup protocol for readiness probes and durable client enrollment.
//!
//! The platform channel checks the OS peer before this module reads a request.
//! This module then validates a closed JSON record, removes the raw secret from
//! the request, and gives only its digest to the serialized metadata store.

use crate::{CoreError, Store, VerifiedEnrollment};
use dissect3d_api::{
    ClientId, EnrollmentId, EnrollmentReceipt, InstallationId, InstanceId, decode_json,
};
use dissect3d_platform::{BootstrapListener, OwnerIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;

const BOOTSTRAP_VERSION: &str = "1.0";
pub(crate) const BOOTSTRAP_FRAME_TIMEOUT: Duration = Duration::from_secs(5);

/// Safe result of serving one native bootstrap connection.
///
/// It intentionally contains no request data, path, OS diagnostic or secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapServeError {
    Accept,
    Read,
    Encode,
    Write,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Probe {
        bootstrap_version: String,
        instance_id: InstanceId,
    },
    Enroll {
        bootstrap_version: String,
        installation_id: InstallationId,
        instance_id: InstanceId,
        enrollment_id: EnrollmentId,
        client_id: ClientId,
        client_kind: String,
        secret_hex: SecretHex,
    },
}

/// Owns the encoded secret only while validating and hashing it.
///
/// `String` is used at the serde boundary because the wire form is JSON text;
/// its allocation is overwritten on drop, and it is never formatted or cloned.
struct SecretHex(Vec<u8>);

impl<'de> Deserialize<'de> for SecretHex {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(|value| Self(value.into_bytes()))
    }
}

impl SecretHex {
    fn digest(mut self) -> Result<dissect3d_api::TokenDigest, RequestError> {
        let bytes = self.0.as_slice();
        if bytes.len() != 64
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(RequestError::Invalid);
        }
        let mut secret = [0_u8; 32];
        for (index, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
            // The alphabet and exact byte length were checked above.
            secret[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
        }
        let digest = Sha256::digest(secret);
        secret.fill(0);
        let mut result = [0_u8; 32];
        result.copy_from_slice(&digest);
        self.0.fill(0);
        Ok(dissect3d_api::TokenDigest::new(result))
    }
}

impl Drop for SecretHex {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => unreachable!("secret alphabet was validated before conversion"),
    }
}

#[derive(Serialize)]
struct ProbeReceipt {
    bootstrap_version: &'static str,
    installation_id: InstallationId,
    instance_id: InstanceId,
    ready: bool,
}

#[derive(Serialize)]
struct ErrorResponse {
    bootstrap_version: &'static str,
    error: &'static str,
}

#[derive(Clone, Copy)]
enum RequestError {
    Invalid,
    Conflict,
    Unauthorized,
    LimitReached,
    Unavailable,
}

impl RequestError {
    fn code(self) -> &'static str {
        match self {
            Self::Invalid => "invalid_request",
            Self::Conflict => "conflict",
            Self::Unauthorized => "unauthorized",
            Self::LimitReached => "limit_reached",
            Self::Unavailable => "unavailable",
        }
    }
}

impl From<CoreError> for RequestError {
    fn from(error: CoreError) -> Self {
        match error {
            CoreError::Conflict => Self::Conflict,
            CoreError::Unauthorized => Self::Unauthorized,
            CoreError::LimitReached => Self::LimitReached,
            CoreError::Busy
            | CoreError::InvalidStore
            | CoreError::StoreIncompatible
            | CoreError::NotFound
            | CoreError::StoreUnavailable
            | CoreError::Platform(_) => Self::Unavailable,
        }
    }
}

/// Accept, decode, execute and reply to one bounded native bootstrap request.
///
/// The listener's platform layer verifies the peer OS identity. The request is
/// then limited by the framed channel and decoded with duplicate-key and
/// trailing-data checks before any store operation is performed.
pub fn serve_bootstrap_once(
    listener: &BootstrapListener,
    store: &Store,
    timeout: Duration,
) -> Result<(), BootstrapServeError> {
    serve_bootstrap_once_with_cancel(listener, store, timeout, None)
}

pub(crate) fn serve_bootstrap_once_with_cancel(
    listener: &BootstrapListener,
    store: &Store,
    timeout: Duration,
    cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
) -> Result<(), BootstrapServeError> {
    let mut channel = listener
        .accept_with_frame_timeout(timeout, BOOTSTRAP_FRAME_TIMEOUT)
        .map_err(|_| BootstrapServeError::Accept)?;
    if let Some(cancellation) = cancellation {
        channel.cancel_when(cancellation);
    }
    let mut frame = channel
        .read_frame()
        .map_err(|_| BootstrapServeError::Read)?;
    let peer = channel.peer_identity().clone();
    let decoded = decode_json::<Request>(&frame);
    frame.fill(0);
    let response = match decoded {
        Ok(request) => handle_request(request, store, peer),
        Err(_) => error_response(RequestError::Invalid),
    };
    let encoded = serde_json::to_vec(&response).map_err(|_| BootstrapServeError::Encode)?;
    channel
        .write_frame(&encoded)
        .map_err(|_| BootstrapServeError::Write)?;
    Ok(())
}

enum Response {
    Probe(ProbeReceipt),
    Enrollment(EnrollmentReceipt),
    Error(ErrorResponse),
}

impl Serialize for Response {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Probe(receipt) => receipt.serialize(serializer),
            Self::Enrollment(receipt) => receipt.serialize(serializer),
            Self::Error(error) => error.serialize(serializer),
        }
    }
}

fn handle_request(request: Request, store: &Store, peer: OwnerIdentity) -> Response {
    match process_request(request, store, peer) {
        Ok(response) => response,
        Err(error) => error_response(error),
    }
}

fn process_request(
    request: Request,
    store: &Store,
    peer: OwnerIdentity,
) -> Result<Response, RequestError> {
    let identity = store.identity().map_err(RequestError::from)?;
    match request {
        Request::Probe {
            bootstrap_version,
            instance_id,
        } => {
            if bootstrap_version != BOOTSTRAP_VERSION || instance_id != identity.instance_id {
                return Err(RequestError::Invalid);
            }
            Ok(Response::Probe(ProbeReceipt {
                bootstrap_version: BOOTSTRAP_VERSION,
                installation_id: identity.installation_id,
                instance_id: identity.instance_id,
                ready: true,
            }))
        }
        Request::Enroll {
            bootstrap_version,
            installation_id,
            instance_id,
            enrollment_id,
            client_id,
            client_kind,
            secret_hex,
        } => {
            if bootstrap_version != BOOTSTRAP_VERSION
                || installation_id != identity.installation_id
                || instance_id != identity.instance_id
                || client_kind != "cli"
            {
                return Err(RequestError::Invalid);
            }
            let digest = secret_hex.digest()?;
            let enrollment = VerifiedEnrollment::new(
                // This value came from the channel's OS credential check, never
                // from a client supplied field.
                peer,
                installation_id,
                instance_id,
                enrollment_id,
                client_id,
                digest,
            );
            store
                .enroll(enrollment)
                .map(Response::Enrollment)
                .map_err(Into::into)
        }
    }
}

fn error_response(error: RequestError) -> Response {
    Response::Error(ErrorResponse {
        bootstrap_version: BOOTSTRAP_VERSION,
        error: error.code(),
    })
}
