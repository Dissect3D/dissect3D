//! One human or structured response renderer for CLI outcomes.
//!
//! Command handlers return data and safe error categories; this module owns
//! the single formatting boundary so JSON mode never mixes progress text with
//! its machine-readable response.

use serde::Serialize;

#[derive(Debug, Serialize)]
pub(crate) struct CommandOutcome {
    cli_output_version: &'static str,
    command: String,
    ok: bool,
    accepted: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation_id: Option<String>,
    data: Option<serde_json::Value>,
    warnings: Vec<String>,
    error: Option<ErrorInfo>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ErrorInfo {
    pub(crate) category: &'static str,
    message: String,
}

impl ErrorInfo {
    pub(crate) fn new(category: &'static str, message: impl Into<String>) -> Self {
        Self {
            category,
            message: message.into(),
        }
    }
}

impl CommandOutcome {
    pub(crate) fn success(command: &str, data: serde_json::Value) -> Self {
        Self::success_with_warnings(command, data, Vec::new())
    }

    pub(crate) fn success_with_warnings(
        command: &str,
        data: serde_json::Value,
        warnings: Vec<String>,
    ) -> Self {
        let accepted = data
            .get("accepted")
            .filter(|value| !value.is_null())
            .cloned();
        let operation_id = data
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        Self {
            cli_output_version: "1.0",
            command: command.to_owned(),
            ok: true,
            accepted,
            operation_id,
            data: Some(data),
            warnings,
            error: None,
        }
    }

    pub(crate) fn failure(command: &str, error: ErrorInfo) -> Self {
        Self {
            cli_output_version: "1.0",
            command: command.to_owned(),
            ok: false,
            accepted: None,
            operation_id: None,
            data: None,
            warnings: Vec::new(),
            error: Some(error),
        }
    }

    pub(crate) fn failure_with_context(
        command: &str,
        error: ErrorInfo,
        accepted: Option<serde_json::Value>,
        operation_id: Option<String>,
        data: Option<serde_json::Value>,
    ) -> Self {
        Self {
            cli_output_version: "1.0",
            command: command.to_owned(),
            ok: false,
            accepted,
            operation_id,
            data,
            warnings: Vec::new(),
            error: Some(error),
        }
    }
}

pub(crate) fn render(outcome: &CommandOutcome, json: bool) {
    if json {
        match serde_json::to_string(outcome) {
            Ok(encoded) => println!("{encoded}"),
            Err(_) => {
                // Serialization failure must still produce one valid JSON
                // object so scripts can handle the CLI failure consistently.
                println!(
                    "{{\"cli_output_version\":\"1.0\",\"command\":\"cli\",\"ok\":false,\"accepted\":null,\"error\":{{\"category\":\"internal_error\",\"message\":\"Could not encode response\"}}}}"
                )
            }
        }
    } else if outcome.ok {
        println!("{}", safe_terminal_text(&human_success(outcome)));
    } else if outcome.error.is_some() {
        eprintln!("{}", safe_terminal_text(&human_failure(outcome)));
    }
}

fn human_failure(outcome: &CommandOutcome) -> String {
    let mut lines = Vec::new();
    if let Some(error) = &outcome.error {
        lines.push(format!("{}: {}", error.category, error.message));
    }
    if let Some(accepted) = &outcome.accepted {
        lines.push(format!("accepted: {accepted}"));
    }
    if let Some(operation_id) = &outcome.operation_id {
        lines.push(format!("operation_id: {operation_id}"));
    }
    if let Some(data) = &outcome.data {
        lines.push(human_data(data));
    }
    lines.join("\n")
}

fn human_success(outcome: &CommandOutcome) -> String {
    let mut lines = Vec::new();
    if let Some(data) = &outcome.data {
        lines.push(human_data(data));
        if data.get("truncated").and_then(serde_json::Value::as_bool) == Some(true)
            && let Some(cursor) = data.get("next_cursor").and_then(serde_json::Value::as_str)
        {
            lines.push(format!(
                "Next page cursor: {cursor}\nRepeat this command with the same filters and limit, then pass --cursor {cursor}."
            ));
        }
    }
    lines.extend(
        outcome
            .warnings
            .iter()
            .map(|warning| format!("warning: {warning}")),
    );
    lines.join("\n")
}

fn safe_terminal_text(value: &str) -> String {
    use std::fmt::Write;
    let mut safe = String::with_capacity(value.len());
    for character in value.chars() {
        let code = character as u32;
        let bidi = matches!(code, 0x202A..=0x202E | 0x2066..=0x2069);
        if (character.is_control() && character != '\n') || bidi {
            let _ = write!(safe, "\\u{code:04X}");
        } else {
            safe.push(character);
        }
    }
    safe
}

fn human_data(data: &serde_json::Value) -> String {
    if let Some(effective) = data.get("effective").and_then(serde_json::Value::as_object) {
        let mut lines = Vec::new();
        for (key, entry) in effective {
            let value = entry.get("value").unwrap_or(&serde_json::Value::Null);
            let value = value
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| value.to_string());
            let source = entry
                .get("source")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            lines.push(format!("{key}={value} source={source}"));
        }
        if let Some(connection) = data
            .get("connection")
            .and_then(serde_json::Value::as_object)
        {
            for (key, value) in connection {
                lines.push(format!("connection.{key}={} source=configuration", value));
            }
        }
        return lines.join("\n");
    }
    serde_json::to_string_pretty(data).unwrap_or_else(|_| "{}".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn human_shutdown_timeout_keeps_known_acceptance_and_operation() {
        let outcome = CommandOutcome::failure_with_context(
            "engine stop",
            ErrorInfo::new("shutdown_unconfirmed", "Engine exit not confirmed"),
            Some(serde_json::json!(true)),
            Some("op_0123456789abcdef0123456789abcdef".to_owned()),
            Some(serde_json::json!({"process_exit_confirmed":false})),
        );
        let rendered = human_failure(&outcome);
        assert!(rendered.contains("accepted: true"));
        assert!(rendered.contains("op_0123456789abcdef0123456789abcdef"));
        assert!(rendered.contains("\"process_exit_confirmed\": false"));
    }
}
