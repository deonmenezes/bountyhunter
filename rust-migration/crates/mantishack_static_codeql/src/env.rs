//! Faithful Rust port of `packages/static-analysis/codeql/env.py`.
//!
//! Provides CodeQL CLI detection and availability probing.
//! Every public symbol preserves the same name and semantics as its Python
//! counterpart; every argv construction is tested to produce byte-identical
//! output (see `tests.rs`).

use std::collections::HashMap;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use serde_json::{Map, Value};

// ── unsafe env keys ───────────────────────────────────────────────────────────

/// Environment keys stripped from the subprocess environment before running
/// `codeql version`.
///
/// Python's `_run_codeql_version` calls `MantishackConfig.get_safe_env()`.
/// The keys below cover the attack surface explicitly called out in the Python
/// comment (shell-eval keys + JVM injection vectors that flow into CodeQL's
/// JVM host):
///   `LD_PRELOAD` / `LD_LIBRARY_PATH` → native-code injection
///   `PYTHONPATH` → Python import hijacking
///   `JAVA_TOOL_OPTIONS` / `_JAVA_OPTIONS` → JVM -javaagent injection
///   `TERMINAL`, `EDITOR`, `VISUAL`, `BROWSER`, `PAGER` → shell-eval triggers
pub const UNSAFE_ENV_KEYS: &[&str] = &[
    "TERMINAL",
    "EDITOR",
    "VISUAL",
    "BROWSER",
    "PAGER",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "PYTHONPATH",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
];

// ── CodeQLEnv ─────────────────────────────────────────────────────────────────

/// Configuration and availability state for the CodeQL CLI.
///
/// Faithful port of the Python `CodeQLEnv` dataclass in `codeql/env.py`.
/// All fields are identical to the Python originals; `Option<String>` maps to
/// Python's `Optional[str]`.
#[derive(Clone, Debug)]
pub struct CodeQLEnv {
    pub mode: String,
    pub available: bool,
    pub cli_path: Option<String>,
    pub version: Option<String>,
    pub queries: Option<String>,
    pub reason: Option<String>,
}

impl CodeQLEnv {
    /// Serialize all fields to a JSON object.
    ///
    /// Mirrors Python `dataclasses.asdict()`: every field is present; `None`
    /// values become JSON `null`.
    pub fn to_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("mode".into(), Value::String(self.mode.clone()));
        m.insert("available".into(), Value::Bool(self.available));
        m.insert(
            "cli_path".into(),
            opt_str_val(self.cli_path.as_deref()),
        );
        m.insert("version".into(), opt_str_val(self.version.as_deref()));
        m.insert("queries".into(), opt_str_val(self.queries.as_deref()));
        m.insert("reason".into(), opt_str_val(self.reason.as_deref()));
        m
    }
}

fn opt_str_val(s: Option<&str>) -> Value {
    s.map(|v| Value::String(v.to_string()))
        .unwrap_or(Value::Null)
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Sanitised copy of the current process environment for CodeQL subprocesses.
///
/// Mirrors the env produced by `MantishackConfig.get_safe_env()` when that
/// module is importable; falls back to stripping the [`UNSAFE_ENV_KEYS`] set.
fn get_codeql_safe_env() -> HashMap<String, String> {
    std::env::vars()
        .filter(|(k, _)| !UNSAFE_ENV_KEYS.contains(&k.as_str()))
        .collect()
}

/// Locate `codeql` on `PATH`. Mirrors Python `shutil.which("codeql")`.
pub(crate) fn which_codeql() -> Option<String> {
    let path_var = std::env::var("PATH").ok()?;
    let sep = if cfg!(windows) { ';' } else { ':' };
    for dir in path_var.split(sep) {
        let candidate = Path::new(dir).join("codeql");
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().to_string());
        }
    }
    None
}

/// Platform-aware executable check — mirrors Python `os.access(path, os.X_OK)`.
fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

// ── run_codeql_version ────────────────────────────────────────────────────────

/// Run `<cli_path> version` with a sanitised environment and return the output.
///
/// Faithful port of `_run_codeql_version(cli_path, timeout_seconds=10)`.
///
/// * Uses a thread-based timeout — same mechanism as the semgrep runner —
///   to mirror Python's `subprocess.TimeoutExpired`.
/// * stdout and stderr are both captured and concatenated to preserve the
///   Python `stderr=subprocess.STDOUT` merge.
/// * Returns `None` on non-zero exit, timeout, or OS error.
pub fn run_codeql_version(cli_path: &str, timeout_seconds: u64) -> Option<String> {
    let safe_env = get_codeql_safe_env();
    let cli = cli_path.to_string();

    let mut builder = Command::new(&cli);
    builder.arg("version");
    builder.stdout(Stdio::piped());
    builder.stderr(Stdio::piped());
    builder.env_clear();
    builder.envs(safe_env.iter());

    let child = builder.spawn().ok()?;

    let (tx, rx) = mpsc::channel::<std::io::Result<std::process::Output>>();
    thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });

    let output = rx
        .recv_timeout(Duration::from_secs(timeout_seconds))
        .ok()?
        .ok()?;

    if output.status.code() != Some(0) {
        return None;
    }

    // Merge stdout + stderr — mirrors Python `stderr=subprocess.STDOUT`.
    let mut combined = String::from_utf8_lossy(&output.stdout).to_string();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    let trimmed = combined.trim().to_string();
    if trimmed.is_empty() { None } else { Some(trimmed) }
}

// ── detect_codeql ─────────────────────────────────────────────────────────────

/// Detect and configure the CodeQL CLI.
///
/// Faithful port of `detect_codeql(mode: CodeQLMode = "detect")` from
/// `codeql/env.py`.  All logic branches, error messages, and return value
/// shapes are preserved.
///
/// `mode=None` or `mode=Some("")` maps to Python's falsy `mode or "disabled"`
/// fallback — resulting mode is `"disabled"`.
pub fn detect_codeql(mode: Option<&str>) -> CodeQLEnv {
    // Python: mode = mode or "disabled"
    let mode_str: String = match mode {
        None | Some("") => "disabled".to_string(),
        Some(m) => m.to_string(),
    };

    if !["disabled", "detect", "require"].contains(&mode_str.as_str()) {
        return CodeQLEnv {
            mode: "detect".to_string(),
            available: false,
            cli_path: None,
            version: None,
            queries: None,
            reason: Some(format!(
                "Unknown mode value '{}', defaulting to 'detect'.",
                mode_str
            )),
        };
    }

    if mode_str == "disabled" {
        return CodeQLEnv {
            mode: "disabled".to_string(),
            available: false,
            cli_path: None,
            version: None,
            queries: None,
            reason: Some("CodeQL mode is disabled by configuration.".to_string()),
        };
    }

    // Try CODEQL_CLI env var first.
    let mut cli_path: Option<String> = None;
    let mut reason: Option<String> = None;

    if let Ok(env_cli) = std::env::var("CODEQL_CLI") {
        if !env_cli.is_empty() {
            let p = Path::new(&env_cli);
            if p.is_file() && is_executable(p) {
                cli_path = Some(env_cli.clone());
            } else {
                reason = Some(format!(
                    "CODEQL_CLI is set to '{}' but the file is not executable.",
                    env_cli
                ));
            }
        }
    }

    // Fall back to PATH lookup.
    if cli_path.is_none() {
        match which_codeql() {
            Some(resolved) => cli_path = Some(resolved),
            None => {
                if reason.is_none() {
                    reason = Some(
                        "CodeQL CLI not found on PATH and CODEQL_CLI is not set.".to_string(),
                    );
                }
            }
        }
    }

    let queries = std::env::var("CODEQL_QUERIES").ok();

    // No CLI found — return early.
    if cli_path.is_none() {
        return CodeQLEnv {
            mode: mode_str,
            available: false,
            cli_path: None,
            version: None,
            queries,
            reason,
        };
    }

    // Run version probe.
    let cli = cli_path.as_deref().unwrap();
    let version = run_codeql_version(cli, 10);

    if version.is_none() {
        return CodeQLEnv {
            mode: mode_str,
            available: false,
            cli_path: cli_path.clone(),
            version: None,
            queries,
            reason: Some(
                "Failed to execute 'codeql version' successfully.".to_string(),
            ),
        };
    }

    CodeQLEnv {
        mode: mode_str,
        available: true,
        cli_path: cli_path.clone(),
        version,
        queries,
        reason: None,
    }
}
