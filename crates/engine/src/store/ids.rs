//! Generated identifiers, digest encoding and wall-clock milliseconds.

use super::*;

pub(super) fn new_installation_id() -> Result<InstallationId, CoreError> {
    InstallationId::parse(random_id("ins_")?).map_err(|_| CoreError::StoreUnavailable)
}

pub(super) fn new_instance_id() -> Result<InstanceId, CoreError> {
    InstanceId::parse(random_id("eng_")?).map_err(|_| CoreError::StoreUnavailable)
}

pub(crate) fn random_id(prefix: &str) -> Result<String, CoreError> {
    let mut entropy = [0_u8; 16];
    getrandom::fill(&mut entropy).map_err(|_| CoreError::StoreUnavailable)?;
    let mut value = String::with_capacity(prefix.len() + 32);
    value.push_str(prefix);
    for byte in entropy {
        use std::fmt::Write as _;
        write!(value, "{byte:02x}").map_err(|_| CoreError::StoreUnavailable)?;
    }
    Ok(value)
}

#[cfg(unix)]
pub(super) fn digest_hex(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

pub(super) fn now_ms() -> Result<i64, CoreError> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CoreError::StoreUnavailable)?;
    i64::try_from(elapsed.as_millis()).map_err(|_| CoreError::StoreUnavailable)
}
