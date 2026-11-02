//! CLI command entry point, local config orchestration and stable presentation.
#![forbid(unsafe_code)]

mod args;
mod commands;
mod config;
mod connection;
mod output;

use std::path::PathBuf;
use std::time::Duration;

use args::{Cli, Command, ConfigCommand, ModelsCommand, RuntimesCommand, TasksCommand};
use clap::{Parser, error::ErrorKind};
use config::{ConfigEnvironment, ConfigFile, ConfigProblem, default_config_path, resolve_config};
use output::{CommandOutcome, ErrorInfo, render};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Run the offline CLI command subset implemented by the current feature slice.
pub fn run() -> i32 {
    let raw_args = std::env::args_os().collect::<Vec<_>>();
    let explicit_json = raw_args.iter().any(|arg| arg == "--json");
    let environment = ConfigEnvironment::capture();
    let requested_json = explicit_json || environment.output_is_json();

    let cli = match Cli::try_parse_from(&raw_args) {
        Ok(cli) => cli,
        Err(error) if error.kind() == ErrorKind::DisplayHelp => {
            print!("{error}");
            return 0;
        }
        Err(error) if error.kind() == ErrorKind::DisplayVersion => {
            println!("dissect3d {VERSION}");
            return 0;
        }
        Err(error) => {
            let outcome = CommandOutcome::failure(
                "cli",
                ErrorInfo::new("usage_error", "Invalid command or arguments"),
            );
            if requested_json {
                render(&outcome, true);
                eprintln!("Invalid command or arguments");
            } else {
                eprintln!("{}", error.render().to_string().trim());
            }
            return 2;
        }
    };

    if cli.version {
        if cli.json {
            render(
                &CommandOutcome::success(
                    "version",
                    serde_json::json!({
                        "cli_version": VERSION,
                        "cli_output_version": "1.0"
                    }),
                ),
                true,
            );
        } else {
            println!("dissect3d {VERSION}");
        }
        return 0;
    }

    let (config_path, explicitly_selected) = config_path(&environment);
    if !config_path.is_absolute() {
        let outcome = CommandOutcome::failure(
            "config",
            ErrorInfo::new("usage_error", "Configuration path must be absolute"),
        );
        if cli.json || requested_json {
            render(&outcome, true);
        } else {
            eprintln!("Configuration path must be absolute");
        }
        return 2;
    }
    let allow_create = matches!(
        &cli.command,
        Some(Command::Config {
            command: ConfigCommand::Set { .. }
        })
    );
    let config = match ConfigFile::load(&config_path, explicitly_selected, allow_create) {
        Ok(config) => config,
        Err(problem) => {
            let json_output = cli.json || requested_json;
            let outcome = CommandOutcome::failure(
                "config",
                ErrorInfo::new("usage_error", problem.safe_message()),
            );
            if json_output {
                render(&outcome, true);
            } else {
                eprintln!("{}", problem.safe_message());
            }
            return 2;
        }
    };

    let preferences = match resolve_config(&config, &cli, &environment) {
        Ok(preferences) => preferences,
        Err(problem) => {
            let json_output = cli.json || requested_json;
            let outcome = CommandOutcome::failure(
                "config",
                ErrorInfo::new("usage_error", problem.safe_message()),
            );
            if json_output {
                render(&outcome, true);
            } else {
                eprintln!("{}", problem.safe_message());
            }
            return 2;
        }
    };
    let json_output = cli.json || preferences.output.value == "json";
    let client_limits = dissect3d_api::ClientLimits {
        connect_timeout: Duration::from_millis(
            preferences.numeric("connect_timeout_ms").unwrap_or(1_000),
        ),
        request_timeout: Duration::from_millis(
            preferences.numeric("read_timeout_ms").unwrap_or(5_000),
        ),
        read_attempts: preferences.numeric("read_attempts").unwrap_or(1) as u8,
        ..Default::default()
    };

    match cli.command {
        Some(Command::Config { command }) => {
            match run_config(command, &config, &preferences, &config_path) {
                Ok(data) => {
                    render(&CommandOutcome::success("config", data), json_output);
                    0
                }
                Err(problem) => {
                    let outcome = CommandOutcome::failure(
                        "config",
                        ErrorInfo::new("usage_error", problem.safe_message()),
                    );
                    if json_output {
                        render(&outcome, true);
                    } else {
                        eprintln!("{}", problem.safe_message());
                    }
                    2
                }
            }
        }
        Some(Command::Engine { command }) => run_connected_command(
            "engine",
            commands::engine(
                command,
                &config,
                &config_path,
                preferences.numeric("start_timeout_ms").unwrap_or(15_000),
                preferences.numeric("stop_timeout_ms").unwrap_or(15_000),
                client_limits,
            ),
            json_output,
        ),
        Some(Command::Auth { command }) => run_connected_command(
            "auth",
            commands::auth(command, &config, &config_path, client_limits),
            json_output,
        ),
        Some(Command::Models { command }) => {
            let name = match &command {
                ModelsCommand::List { .. } => "models list",
                ModelsCommand::Show { .. } => "models show",
                ModelsCommand::Loaded { .. } => "models loaded",
            };
            run_discovery_command(
                name,
                commands::discovery::models(command, &config, &config_path, client_limits),
                json_output,
            )
        }
        Some(Command::Runtimes { command }) => {
            let name = match &command {
                RuntimesCommand::List { .. } => "runtimes list",
                RuntimesCommand::Show { .. } => "runtimes show",
            };
            run_discovery_command(
                name,
                commands::discovery::runtimes(command, &config, &config_path, client_limits),
                json_output,
            )
        }
        Some(Command::Tasks { command }) => {
            let name = match &command {
                TasksCommand::List { .. } => "tasks list",
                TasksCommand::Show { .. } => "tasks show",
            };
            run_discovery_command(
                name,
                commands::discovery::tasks(command, &config, &config_path, client_limits),
                json_output,
            )
        }
        None => {
            let outcome = CommandOutcome::failure(
                "cli",
                ErrorInfo::new("usage_error", "A command is required"),
            );
            render(&outcome, json_output);
            2
        }
    }
}

fn run_connected_command(
    command: &str,
    result: Result<serde_json::Value, commands::CommandError>,
    json_output: bool,
) -> i32 {
    match result {
        Ok(data) => {
            render(&CommandOutcome::success(command, data), json_output);
            0
        }
        Err(error) => {
            let context = error.context.unwrap_or_default();
            let outcome = CommandOutcome::failure_with_context(
                command,
                ErrorInfo::new(error.category, error.message),
                context.accepted,
                context.operation_id,
                context.data,
            );
            render(&outcome, json_output);
            error.exit_code
        }
    }
}

fn run_discovery_command(
    command: &str,
    result: Result<commands::discovery::Success, commands::CommandError>,
    json_output: bool,
) -> i32 {
    match result {
        Ok(success) => {
            render(
                &CommandOutcome::success_with_warnings(
                    success.command,
                    success.data,
                    success.warnings,
                ),
                json_output,
            );
            0
        }
        Err(error) => {
            let context = error.context.unwrap_or_default();
            let outcome = CommandOutcome::failure_with_context(
                command,
                ErrorInfo::new(error.category, error.message),
                context.accepted,
                context.operation_id,
                context.data,
            );
            render(&outcome, json_output);
            error.exit_code
        }
    }
}

fn config_path(environment: &ConfigEnvironment) -> (PathBuf, bool) {
    if let Some(path) = &environment.config_file {
        return (path.clone(), true);
    }
    (default_config_path(environment), false)
}

fn run_config(
    command: ConfigCommand,
    config: &ConfigFile,
    preferences: &config::EffectivePreferences,
    path: &std::path::Path,
) -> Result<serde_json::Value, ConfigProblem> {
    match command {
        ConfigCommand::Show => Ok(serde_json::json!({
            "effective": preferences.as_json(),
            "connection": config.connection_json(),
        })),
        ConfigCommand::Get { key } => {
            let (value, source) = config.get_value(&key, preferences)?;
            Ok(serde_json::json!({"key": key, "value": value, "source": source.as_str()}))
        }
        ConfigCommand::Set { key, value } => {
            let updated = config.with_override(&key, &value)?;
            updated.save(path)?;
            Ok(serde_json::json!({"key": key, "value": updated.stored_value(&key)?}))
        }
        ConfigCommand::Unset { key } => {
            let updated = config.without_override(&key)?;
            updated.save(path)?;
            Ok(serde_json::json!({"key": key, "removed": true}))
        }
    }
}
