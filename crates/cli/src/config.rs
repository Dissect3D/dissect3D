//! Client-owned preferences and selected engine connection references.
//!
//! Environment input is snapshotted once, then merged with stored preferences
//! and command-line values. This makes `config show` report the source of each
//! effective value from the same inputs used to execute the command.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use dissect3d_api::decode_json;
use serde::{Deserialize, Serialize};

const MAX_CONFIG_BYTES: u64 = 65_536;

#[derive(Debug)]
pub(crate) enum ConfigProblem {
    Io,
    Invalid,
    UnknownKey,
    InvalidValue,
    Missing,
    Busy,
}

impl ConfigProblem {
    pub(crate) fn safe_message(&self) -> &'static str {
        match self {
            Self::Busy => "The selected configuration is busy; retry the command",
            Self::Io => "Could not read or write the selected configuration",
            Self::Invalid => "The selected configuration is malformed or unsupported",
            Self::UnknownKey => "Unknown configuration key",
            Self::InvalidValue => "Configuration value is outside its accepted form or range",
            Self::Missing => "The explicitly selected configuration file does not exist",
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConfigFile {
    #[serde(skip_serializing_if = "Option::is_none")]
    preferences: Option<Preferences>,
    #[serde(skip_serializing_if = "Option::is_none")]
    connection: Option<Connection>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Preferences {
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    connect_timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    read_timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    read_attempts: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop_timeout_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Connection {
    #[serde(skip_serializing_if = "Option::is_none")]
    data_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    engine_binary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    installation_id: Option<String>,
}

#[derive(Clone, Copy)]
pub(crate) enum Source {
    Arguments,
    Environment,
    Configuration,
    Default,
}

impl Source {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Arguments => "arguments",
            Self::Environment => "environment",
            Self::Configuration => "configuration",
            Self::Default => "default",
        }
    }
}

#[derive(Clone)]
pub(crate) struct EffectiveValue {
    pub(crate) value: serde_json::Value,
    pub(crate) source: Source,
}

pub(crate) struct EffectivePreferences {
    pub(crate) output: EffectiveValue,
    values: std::collections::BTreeMap<String, EffectiveValue>,
}

/// Snapshot of the only environment variables allowed to affect CLI preferences.
pub(crate) struct ConfigEnvironment {
    pub(crate) config_file: Option<std::path::PathBuf>,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    home: Option<std::path::PathBuf>,
    #[cfg(target_os = "linux")]
    xdg_config_home: Option<std::path::PathBuf>,
    #[cfg(target_os = "windows")]
    local_app_data: Option<std::path::PathBuf>,
    output: Option<String>,
    connect_timeout_ms: Option<String>,
    read_timeout_ms: Option<String>,
    read_attempts: Option<String>,
    start_timeout_ms: Option<String>,
    stop_timeout_ms: Option<String>,
}

impl ConfigEnvironment {
    pub(crate) fn capture() -> Self {
        Self {
            config_file: std::env::var_os("DISSECT3D_CONFIG_FILE").map(Into::into),
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            home: std::env::var_os("HOME").map(Into::into),
            #[cfg(target_os = "linux")]
            xdg_config_home: std::env::var_os("XDG_CONFIG_HOME").map(Into::into),
            #[cfg(target_os = "windows")]
            local_app_data: std::env::var_os("LOCALAPPDATA").map(Into::into),
            output: std::env::var("DISSECT3D_OUTPUT").ok(),
            connect_timeout_ms: std::env::var("DISSECT3D_CONNECT_TIMEOUT_MS").ok(),
            read_timeout_ms: std::env::var("DISSECT3D_READ_TIMEOUT_MS").ok(),
            read_attempts: std::env::var("DISSECT3D_READ_ATTEMPTS").ok(),
            start_timeout_ms: std::env::var("DISSECT3D_START_TIMEOUT_MS").ok(),
            stop_timeout_ms: std::env::var("DISSECT3D_STOP_TIMEOUT_MS").ok(),
        }
    }

    pub(crate) fn output_is_json(&self) -> bool {
        self.output.as_deref() == Some("json")
    }
}

impl EffectivePreferences {
    pub(crate) fn numeric(&self, key: &str) -> Option<u64> {
        self.values.get(key)?.value.as_u64()
    }

    pub(crate) fn as_json(&self) -> serde_json::Value {
        serde_json::Value::Object(
            self.values
                .iter()
                .map(|(key, value)| {
                    (
                        key.clone(),
                        serde_json::json!({
                            "value": value.value,
                            "source": value.source.as_str(),
                        }),
                    )
                })
                .collect(),
        )
    }
}

impl ConfigFile {
    pub(crate) fn load(
        path: &Path,
        explicitly_selected: bool,
        allow_create: bool,
    ) -> Result<Self, ConfigProblem> {
        let mut file = match dissect3d_platform::open_regular_file(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if allow_create || !explicitly_selected {
                    return Ok(Self::default());
                }
                return Err(ConfigProblem::Missing);
            }
            Err(_) => return Err(ConfigProblem::Io),
        };
        // Bound bytes before parsing so malformed or unexpectedly large local
        // files cannot cause unbounded allocation during CLI startup.
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ConfigProblem::Io)?;
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            return Err(ConfigProblem::Invalid);
        }
        decode_json(&bytes).map_err(|_| ConfigProblem::Invalid)
    }

    pub(crate) fn connection_json(&self) -> serde_json::Value {
        serde_json::to_value(&self.connection).unwrap_or(serde_json::Value::Null)
    }

    pub(crate) fn connection_value(&self, key: &str) -> Option<&str> {
        let connection = self.connection.as_ref()?;
        match key {
            "data_root" => connection.data_root.as_deref(),
            "engine_binary" => connection.engine_binary.as_deref(),
            "credential_file" => connection.credential_file.as_deref(),
            "installation_id" => connection.installation_id.as_deref(),
            _ => None,
        }
    }

    pub(crate) fn explicit_credential_reference(
        &self,
    ) -> Result<Option<(&str, &str)>, ConfigProblem> {
        let file = self.connection_value("credential_file");
        let installation = self.connection_value("installation_id");
        match (file, installation) {
            (None, None) => Ok(None),
            (Some(file), Some(installation))
                if Path::new(file).is_absolute()
                    && dissect3d_api::InstallationId::parse(installation).is_ok() =>
            {
                Ok(Some((file, installation)))
            }
            _ => Err(ConfigProblem::InvalidValue),
        }
    }

    pub(crate) fn get_value(
        &self,
        key: &str,
        effective: &EffectivePreferences,
    ) -> Result<(serde_json::Value, Source), ConfigProblem> {
        if let Some(value) = effective.values.get(key) {
            return Ok((value.value.clone(), value.source));
        }
        let value = self.stored_value(key)?;
        Ok((value, Source::Configuration))
    }

    pub(crate) fn stored_value(&self, key: &str) -> Result<serde_json::Value, ConfigProblem> {
        let preference = self.preferences.as_ref();
        let value = match key {
            "output" => preference
                .and_then(|p| p.output.as_ref())
                .map(|v| serde_json::json!(v)),
            "connect_timeout_ms" => preference
                .and_then(|p| p.connect_timeout_ms)
                .map(|v| serde_json::json!(v)),
            "read_timeout_ms" => preference
                .and_then(|p| p.read_timeout_ms)
                .map(|v| serde_json::json!(v)),
            "read_attempts" => preference
                .and_then(|p| p.read_attempts)
                .map(|v| serde_json::json!(v)),
            "start_timeout_ms" => preference
                .and_then(|p| p.start_timeout_ms)
                .map(|v| serde_json::json!(v)),
            "stop_timeout_ms" => preference
                .and_then(|p| p.stop_timeout_ms)
                .map(|v| serde_json::json!(v)),
            "connection.data_root" => {
                return self.connection_json_value(|c| c.data_root.as_deref());
            }
            "connection.engine_binary" => {
                return self.connection_json_value(|c| c.engine_binary.as_deref());
            }
            "connection.credential_file" => {
                return self.connection_json_value(|c| c.credential_file.as_deref());
            }
            "connection.installation_id" => {
                return self.connection_json_value(|c| c.installation_id.as_deref());
            }
            _ => return Err(ConfigProblem::UnknownKey),
        };
        Ok(value.unwrap_or(serde_json::Value::Null))
    }

    pub(crate) fn with_override(&self, key: &str, raw: &str) -> Result<Self, ConfigProblem> {
        let mut updated = self.clone();
        match key {
            "output" => {
                if !matches!(raw, "human" | "json") {
                    return Err(ConfigProblem::InvalidValue);
                }
                updated.preferences_mut().output = Some(raw.to_owned());
            }
            "connect_timeout_ms" => {
                let value = bounded(raw, 100, 30_000)?;
                updated.preferences_mut().connect_timeout_ms = Some(value);
            }
            "read_timeout_ms" => {
                let value = bounded(raw, 100, 60_000)?;
                updated.preferences_mut().read_timeout_ms = Some(value);
            }
            "read_attempts" => {
                let value = bounded(raw, 1, 3)?;
                updated.preferences_mut().read_attempts = Some(value);
            }
            "start_timeout_ms" => {
                let value = bounded(raw, 1_000, 60_000)?;
                updated.preferences_mut().start_timeout_ms = Some(value);
            }
            "stop_timeout_ms" => {
                let value = bounded(raw, 1_000, 60_000)?;
                updated.preferences_mut().stop_timeout_ms = Some(value);
            }
            "connection.data_root" => {
                if !Path::new(raw).is_absolute() {
                    return Err(ConfigProblem::InvalidValue);
                }
                updated.connection_mut().data_root = Some(raw.to_owned())
            }
            "connection.engine_binary" => {
                if !Path::new(raw).is_absolute() {
                    return Err(ConfigProblem::InvalidValue);
                }
                updated.connection_mut().engine_binary = Some(raw.to_owned())
            }
            "connection.credential_file" => {
                if !Path::new(raw).is_absolute() {
                    return Err(ConfigProblem::InvalidValue);
                }
                updated.connection_mut().credential_file = Some(raw.to_owned())
            }
            "connection.installation_id" => {
                if dissect3d_api::InstallationId::parse(raw).is_err() {
                    return Err(ConfigProblem::InvalidValue);
                }
                updated.connection_mut().installation_id = Some(raw.to_owned())
            }
            _ => return Err(ConfigProblem::UnknownKey),
        }
        Ok(updated)
    }

    pub(crate) fn without_override(&self, key: &str) -> Result<Self, ConfigProblem> {
        let mut updated = self.clone();
        match key {
            "output" => updated.preferences_mut().output = None,
            "connect_timeout_ms" => updated.preferences_mut().connect_timeout_ms = None,
            "read_timeout_ms" => updated.preferences_mut().read_timeout_ms = None,
            "read_attempts" => updated.preferences_mut().read_attempts = None,
            "start_timeout_ms" => updated.preferences_mut().start_timeout_ms = None,
            "stop_timeout_ms" => updated.preferences_mut().stop_timeout_ms = None,
            "connection.data_root" => updated.connection_mut().data_root = None,
            "connection.engine_binary" => updated.connection_mut().engine_binary = None,
            "connection.credential_file" => {
                // A credential file and installation identity form one selected
                // connection reference; leaving only half would make it stale.
                updated.connection_mut().credential_file = None;
                updated.connection_mut().installation_id = None;
            }
            "connection.installation_id" => {
                updated.connection_mut().installation_id = None;
                updated.connection_mut().credential_file = None;
            }
            _ => return Err(ConfigProblem::UnknownKey),
        }
        Ok(updated)
    }

    pub(crate) fn save(&self, path: &Path) -> Result<(), ConfigProblem> {
        let parent = path.parent().ok_or(ConfigProblem::Io)?;
        fs::create_dir_all(parent).map_err(|_| ConfigProblem::Io)?;
        let bytes = serde_json::to_vec_pretty(self).map_err(|_| ConfigProblem::Invalid)?;
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            return Err(ConfigProblem::Invalid);
        }
        // Publish via a new private sibling so an interrupted write never
        // leaves a truncated configuration at the selected path.
        let temporary = unique_temporary_path(path)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary).map_err(|_| ConfigProblem::Io)?;
        let result = (|| {
            file.write_all(&bytes).map_err(|_| ConfigProblem::Io)?;
            file.sync_all().map_err(|_| ConfigProblem::Io)?;
            fs::rename(&temporary, path).map_err(|_| ConfigProblem::Io)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn preferences_mut(&mut self) -> &mut Preferences {
        self.preferences.get_or_insert_with(Preferences::default)
    }

    fn connection_mut(&mut self) -> &mut Connection {
        self.connection.get_or_insert_with(Connection::default)
    }

    fn connection_json_value(
        &self,
        select: impl FnOnce(&Connection) -> Option<&str>,
    ) -> Result<serde_json::Value, ConfigProblem> {
        let Some(value) = self.connection.as_ref().and_then(select) else {
            return Ok(serde_json::Value::Null);
        };
        Ok(serde_json::Value::String(value.to_owned()))
    }
}

fn unique_temporary_path(path: &Path) -> Result<std::path::PathBuf, ConfigProblem> {
    use std::fmt::Write as _;

    let name = path.file_name().ok_or(ConfigProblem::Io)?;
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| ConfigProblem::Io)?;
    let mut suffix = String::with_capacity(32);
    for byte in nonce {
        write!(&mut suffix, "{byte:02x}").map_err(|_| ConfigProblem::Io)?;
    }
    let mut staged_name = std::ffi::OsString::from(".");
    staged_name.push(name);
    staged_name.push(format!(".tmp-{suffix}"));
    Ok(path.with_file_name(staged_name))
}

fn bounded(raw: &str, minimum: u64, maximum: u64) -> Result<u64, ConfigProblem> {
    let value = raw
        .parse::<u64>()
        .map_err(|_| ConfigProblem::InvalidValue)?;
    if !(minimum..=maximum).contains(&value) {
        return Err(ConfigProblem::InvalidValue);
    }
    Ok(value)
}

pub(crate) fn resolve_config(
    config: &ConfigFile,
    cli: &crate::args::Cli,
    environment: &ConfigEnvironment,
) -> Result<EffectivePreferences, ConfigProblem> {
    // Keep precedence explicit: arguments override environment, then stored
    // preferences, then defaults. Source metadata is returned with each value
    // so diagnostics do not have to infer where an override came from.
    let stored = config.preferences.as_ref();
    let mut values = std::collections::BTreeMap::new();
    let output = if cli.json {
        (serde_json::json!("json"), Source::Arguments)
    } else {
        resolve_string(
            "human",
            stored.and_then(|p| p.output.as_deref()),
            environment.output.as_deref(),
        )?
    };
    let output = EffectiveValue {
        value: output.0.clone(),
        source: output.1,
    };
    values.insert("output".to_owned(), output.clone());

    for (name, env_name, stored_value, argument, default, min, max) in [
        (
            "connect_timeout_ms",
            "DISSECT3D_CONNECT_TIMEOUT_MS",
            stored.and_then(|p| p.connect_timeout_ms),
            cli.connect_timeout_ms,
            1_000,
            100,
            30_000,
        ),
        (
            "read_timeout_ms",
            "DISSECT3D_READ_TIMEOUT_MS",
            stored.and_then(|p| p.read_timeout_ms),
            cli.read_timeout_ms,
            5_000,
            100,
            60_000,
        ),
        (
            "read_attempts",
            "DISSECT3D_READ_ATTEMPTS",
            stored.and_then(|p| p.read_attempts),
            cli.read_attempts,
            1,
            1,
            3,
        ),
        (
            "start_timeout_ms",
            "DISSECT3D_START_TIMEOUT_MS",
            stored.and_then(|p| p.start_timeout_ms),
            cli.start_timeout_ms,
            15_000,
            1_000,
            60_000,
        ),
        (
            "stop_timeout_ms",
            "DISSECT3D_STOP_TIMEOUT_MS",
            stored.and_then(|p| p.stop_timeout_ms),
            cli.stop_timeout_ms,
            15_000,
            1_000,
            60_000,
        ),
    ] {
        let env_value = match env_name {
            "DISSECT3D_CONNECT_TIMEOUT_MS" => environment.connect_timeout_ms.as_deref(),
            "DISSECT3D_READ_TIMEOUT_MS" => environment.read_timeout_ms.as_deref(),
            "DISSECT3D_READ_ATTEMPTS" => environment.read_attempts.as_deref(),
            "DISSECT3D_START_TIMEOUT_MS" => environment.start_timeout_ms.as_deref(),
            "DISSECT3D_STOP_TIMEOUT_MS" => environment.stop_timeout_ms.as_deref(),
            _ => None,
        };
        let (value, source) = if let Some(value) = argument {
            if !(min..=max).contains(&value) {
                return Err(ConfigProblem::InvalidValue);
            }
            (value, Source::Arguments)
        } else if let Some(value) = env_value {
            (bounded(value, min, max)?, Source::Environment)
        } else if let Some(value) = stored_value {
            if !(min..=max).contains(&value) {
                return Err(ConfigProblem::InvalidValue);
            }
            (value, Source::Configuration)
        } else {
            (default, Source::Default)
        };
        values.insert(
            name.to_owned(),
            EffectiveValue {
                value: serde_json::json!(value),
                source,
            },
        );
    }
    Ok(EffectivePreferences { output, values })
}

pub(crate) fn default_config_path(environment: &ConfigEnvironment) -> std::path::PathBuf {
    #[cfg(target_os = "macos")]
    let path = environment
        .home
        .as_ref()
        .map_or_else(std::path::PathBuf::new, |home| {
            home.join("Library/Application Support/Dissect3D-CLI/client.json")
        });
    #[cfg(target_os = "windows")]
    let path = environment
        .local_app_data
        .as_ref()
        .map_or_else(std::path::PathBuf::new, |root| {
            root.join("Dissect3D-CLI/client.json")
        });
    #[cfg(target_os = "linux")]
    let path = environment
        .xdg_config_home
        .as_ref()
        .or(environment.home.as_ref())
        .map(|root| {
            if environment.xdg_config_home.is_some() {
                root.join("dissect3d/client.json")
            } else {
                root.join(".config/dissect3d/client.json")
            }
        })
        .unwrap_or_default();
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    let path = std::path::PathBuf::new();
    path
}

fn resolve_string(
    default: &str,
    stored: Option<&str>,
    environment: Option<&str>,
) -> Result<(serde_json::Value, Source), ConfigProblem> {
    if let Some(value) = environment {
        if !matches!(value, "human" | "json") {
            return Err(ConfigProblem::InvalidValue);
        }
        return Ok((serde_json::json!(value), Source::Environment));
    }
    if let Some(value) = stored {
        if !matches!(value, "human" | "json") {
            return Err(ConfigProblem::InvalidValue);
        }
        return Ok((serde_json::json!(value), Source::Configuration));
    }
    Ok((serde_json::json!(default), Source::Default))
}

/// Persistent sibling identity survives atomic config replacement. Native file
/// locking resolves case and parent-directory aliases without pathname hashing.
/// Never unlink this file, including after owner exit.
pub(crate) fn lock_mutation(path: &Path) -> Result<std::fs::File, ConfigProblem> {
    let parent = path.parent().ok_or(ConfigProblem::Io)?;
    fs::create_dir_all(parent).map_err(|_| ConfigProblem::Io)?;
    let mut name = path.as_os_str().to_os_string();
    name.push(".lock");
    let file =
        dissect3d_platform::open_config_lock(Path::new(&name)).map_err(|_| ConfigProblem::Io)?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(ConfigProblem::Busy),
        Err(std::fs::TryLockError::Error(_)) => Err(ConfigProblem::Io),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_legacy_temporary_file_does_not_block_atomic_config_save() {
        let directory = tempfile::tempdir().expect("temporary config directory");
        let config_path = directory.path().join("client.json");
        let stale = config_path.with_extension("json.tmp");
        fs::write(&stale, b"interrupted prior write").expect("legacy staging file");

        let config = ConfigFile::default()
            .with_override("output", "json")
            .expect("valid output preference");
        config.save(&config_path).expect("unique staged save");

        assert_eq!(
            fs::read(stale).expect("stale file remains untouched"),
            b"interrupted prior write"
        );
        assert_eq!(
            ConfigFile::load(&config_path, true, false)
                .expect("saved config")
                .stored_value("output")
                .expect("output"),
            serde_json::json!("json")
        );
    }
}
