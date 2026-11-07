//! Finite resource policy for the core service.

/// Finite resource limits used by the metadata actor.
///
/// The queue bounds accepted concurrent store work, the busy timeout bounds
/// SQLite lock waiting, and the value limit caps individual SQLite values. The
/// last limit is not a maximum database-file size.
#[derive(Clone, Debug)]
pub struct CorePolicy {
    pub(crate) queue_capacity: usize,
    pub(crate) busy_timeout_ms: u32,
    pub(crate) maximum_value_bytes: usize,
    pub(crate) control_response_bytes: usize,
    pub(crate) request_timeout_ms: u32,
    pub(crate) shutdown_timeout_ms: u32,
}

impl Default for CorePolicy {
    fn default() -> Self {
        Self {
            queue_capacity: 64,
            busy_timeout_ms: 2_000,
            maximum_value_bytes: 1_048_576,
            control_response_bytes: 262_144,
            request_timeout_ms: 5_000,
            shutdown_timeout_ms: 5_000,
        }
    }
}
