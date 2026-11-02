//! Closed command grammar for implemented client-owned operations.
//!
//! Keeping this parser limited to implemented local commands makes unsupported
//! service actions fail at the CLI boundary instead of appearing accepted.

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "dissect3d",
    version,
    about = "Local 3D model engine client",
    disable_version_flag = true
)]
pub(crate) struct Cli {
    // Global output selection is parsed before configuration so malformed
    // arguments can still honor a caller's request for machine-readable errors.
    #[arg(long, global = true, help = "Write one structured JSON response")]
    pub(crate) json: bool,
    #[arg(long, global = true, help = "Never prompt for a missing choice")]
    pub(crate) non_interactive: bool,
    #[arg(long, global = true, help = "Show the CLI version")]
    pub(crate) version: bool,
    #[arg(long, global = true, value_name = "MS")]
    pub(crate) connect_timeout_ms: Option<u64>,
    #[arg(long, global = true, value_name = "MS")]
    pub(crate) read_timeout_ms: Option<u64>,
    #[arg(long, global = true, value_name = "COUNT")]
    pub(crate) read_attempts: Option<u64>,
    #[arg(long, global = true, value_name = "MS")]
    pub(crate) start_timeout_ms: Option<u64>,
    #[arg(long, global = true, value_name = "MS")]
    pub(crate) stop_timeout_ms: Option<u64>,
    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Inspect and change local client preferences.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Start, inspect, or stop the selected engine.
    Engine {
        #[command(subcommand)]
        command: EngineCommand,
    },
    /// Manage this profile's engine credential.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Inspect declared models and their current non-inference state.
    Models {
        #[command(subcommand)]
        command: ModelsCommand,
    },
    /// Inspect declared runtime profiles.
    Runtimes {
        #[command(subcommand)]
        command: RuntimesCommand,
    },
    /// Inspect versioned support-specific tasks.
    Tasks {
        #[command(subcommand)]
        command: TasksCommand,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum ModelsCommand {
    /// List support records.
    List {
        #[arg(long)]
        task: Option<String>,
        #[arg(long)]
        task_version: Option<String>,
        #[arg(long)]
        limit: Option<u8>,
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Inspect one support record.
    Show {
        selector: String,
        #[arg(long)]
        task: Option<String>,
        #[arg(long)]
        task_version: Option<String>,
        #[arg(long)]
        runtime: Option<String>,
        #[arg(long)]
        variant: Option<String>,
    },
    /// List loaded models (currently empty until worker support exists).
    Loaded {
        #[arg(long)]
        limit: Option<u8>,
        #[arg(long)]
        cursor: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum RuntimesCommand {
    /// List runtime profiles.
    List {
        #[arg(long)]
        limit: Option<u8>,
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Inspect one runtime profile.
    Show { selector: String },
}

#[derive(Debug, Subcommand)]
pub(crate) enum TasksCommand {
    /// List support-specific task bindings.
    List {
        #[arg(long)]
        support: Option<String>,
        #[arg(long)]
        limit: Option<u8>,
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Inspect one task key or binding ID.
    Show {
        selector: String,
        #[arg(long = "task-version")]
        task_version: Option<String>,
        #[arg(long)]
        support: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum EngineCommand {
    /// Start the configured engine and wait for its native readiness probe.
    Start,
    /// Inspect the selected engine without starting it.
    Status,
    /// Read authenticated engine capabilities.
    Info,
    /// Stop the selected engine after the durable stop operation is available.
    Stop,
}

#[derive(Debug, Subcommand)]
pub(crate) enum AuthCommand {
    /// Enroll this profile with the selected engine.
    Setup,
    /// Read this profile's authentication status.
    Status,
    /// Revoke this profile's own credential.
    Revoke,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ConfigCommand {
    /// Show effective preferences and their sources.
    Show,
    /// Read one preference or connection reference.
    Get { key: String },
    /// Store a preference or connection reference override.
    Set { key: String, value: String },
    /// Remove a stored override.
    Unset { key: String },
}
