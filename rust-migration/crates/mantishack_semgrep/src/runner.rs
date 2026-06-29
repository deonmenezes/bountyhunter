//! Semgrep runner — faithful port of `packages/semgrep/runner.py`.
//!
//! Wraps the external `semgrep` binary via `std::process::Command`.  The Python
//! package used `subprocess.run`; here we use `Command::output` / `wait_with_output`
//! with a thread-based timeout to mirror Python's `subprocess.TimeoutExpired`.
//!
//! Security invariants preserved from the Python original:
//!   * Argv is always a list — the scanned path is appended as a separate element,
//!     never interpolated into a shell string.
//!   * `get_safe_env()` strips the same five shell-evaluating env keys that
//!     Python's `MantishackConfig.get_safe_env()` strips:
//!     TERMINAL, EDITOR, VISUAL, BROWSER, PAGER.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::models::{parse_json_output, parse_sarif, SemgrepResult};

pub(crate) const SEMGREP_BIN: &str = "semgrep";
pub const DEFAULT_TIMEOUT: u64 = 900;
pub const DEFAULT_RULE_TIMEOUT: u64 = 60;

/// Env keys that might be shell-evaluated by spawned tools.
/// Mirrors Python `MantishackConfig.get_safe_env()`.
pub const UNSAFE_ENV_KEYS: &[&str] = &["TERMINAL", "EDITOR", "VISUAL", "BROWSER", "PAGER"];

// ── is_available / version ────────────────────────────────────────────────────

/// Return `true` if the `semgrep` binary exists on PATH.
/// Mirrors Python `shutil.which(_SEMGREP_BIN) is not None`.
pub fn is_available() -> bool {
    which(SEMGREP_BIN).is_some()
}

/// Return the semgrep version string, or `None` if unavailable.
/// Mirrors Python `version()`.
pub fn version() -> Option<String> {
    if !is_available() {
        return None;
    }
    let output = Command::new(SEMGREP_BIN)
        .arg("--version")
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(if !output.stdout.is_empty() {
        &output.stdout
    } else {
        &output.stderr
    })
    .trim()
    .to_string();
    text.lines().next().map(str::to_string)
}

// ── build_cmd ─────────────────────────────────────────────────────────────────

/// Build the semgrep command argv.
///
/// Pure: no subprocess invocation.  Faithful port of Python `build_cmd`.
/// Argument order is preserved exactly:
///
/// ```text
/// semgrep scan --config <config> --quiet --metrics off --error --sarif
///   --timeout <rule_timeout> [--json-output <path>] [<extra_args>...] <target>
/// ```
///
/// The `target` path is always passed as a separate argv element — never shell
/// interpolated — which is the security-critical property.
pub fn build_cmd(
    target: &Path,
    config: &str,
    json_output_path: Option<&Path>,
    rule_timeout: u64,
    semgrep_bin: Option<&str>,
    extra_args: Option<&[String]>,
) -> Vec<String> {
    // Python: bin_path = semgrep_bin or shutil.which(_SEMGREP_BIN) or _SEMGREP_BIN
    let bin_path = semgrep_bin
        .map(str::to_string)
        .or_else(|| which(SEMGREP_BIN).map(|p| p.to_string_lossy().to_string()))
        .unwrap_or_else(|| SEMGREP_BIN.to_string());

    let mut cmd = vec![
        bin_path,
        "scan".to_string(),
        "--config".to_string(),
        config.to_string(),
        "--quiet".to_string(),
        "--metrics".to_string(),
        "off".to_string(),
        "--error".to_string(),
        "--sarif".to_string(),
        "--timeout".to_string(),
        rule_timeout.to_string(),
    ];

    if let Some(json_path) = json_output_path {
        cmd.push("--json-output".to_string());
        cmd.push(json_path.to_string_lossy().to_string());
    }

    if let Some(extra) = extra_args {
        cmd.extend(extra.iter().cloned());
    }

    // Target is always the final argument, appended as a separate list element.
    cmd.push(target.to_string_lossy().to_string());
    cmd
}

// ── get_safe_env ──────────────────────────────────────────────────────────────

/// Return the current environment with shell-evaluation-risky keys removed.
///
/// Strips `TERMINAL`, `EDITOR`, `VISUAL`, `BROWSER`, `PAGER` — the same keys
/// that Python's `MantishackConfig.get_safe_env()` removes.  Untrusted-target
/// callers should pass this map as `env` to `run_rule`.
pub fn get_safe_env() -> HashMap<String, String> {
    std::env::vars()
        .filter(|(k, _)| !UNSAFE_ENV_KEYS.contains(&k.as_str()))
        .collect()
}

// ── run_rule ──────────────────────────────────────────────────────────────────

/// Arguments for `run_rule`; named struct mirrors Python's keyword-only args.
pub struct RunRuleArgs<'a> {
    pub target: &'a Path,
    pub config: &'a str,
    pub name: &'a str,
    pub timeout: u64,
    pub rule_timeout: u64,
    /// When `Some`, replaces the subprocess environment entirely.
    /// When `None`, the child inherits the current process environment.
    /// Untrusted-target callers should pass `Some(get_safe_env())`.
    pub env: Option<&'a HashMap<String, String>>,
    pub json_output_path: Option<&'a Path>,
    pub semgrep_bin: Option<&'a str>,
    pub extra_args: Option<&'a [String]>,
}

/// Run semgrep with one config against a target.
///
/// Faithful port of Python `run_rule`. Returns a `SemgrepResult` on all paths —
/// errors (unavailable binary, timeout, OS error) are recorded in
/// `SemgrepResult.errors` with `returncode = -1`.
///
/// Note: The Python `subprocess_runner` injection point has no equivalent here;
/// sandbox integration is the caller's responsibility (wrap the `Command` outside
/// this crate, or use `build_cmd` directly with your own runner).
pub fn run_rule(args: RunRuleArgs<'_>) -> SemgrepResult {
    let name = if args.name.is_empty() {
        config_to_name(args.config)
    } else {
        args.name.to_string()
    };

    if !is_available() {
        return SemgrepResult {
            name,
            config: args.config.to_string(),
            target: args.target.to_string_lossy().to_string(),
            errors: vec![
                "semgrep is not installed (semgrep binary not found on PATH)".to_string(),
            ],
            returncode: -1,
            ..Default::default()
        };
    }

    // When no explicit json_output_path, allocate a temp file path.
    let owned_tmp: Option<PathBuf>;
    let json_path: &Path;
    if let Some(p) = args.json_output_path {
        owned_tmp = None;
        json_path = p;
    } else {
        let tmp = make_temp_json_path();
        owned_tmp = Some(tmp);
        json_path = owned_tmp.as_deref().unwrap();
    };
    let cleanup_json = owned_tmp.is_some();

    let cmd = build_cmd(
        args.target,
        args.config,
        Some(json_path),
        args.rule_timeout,
        args.semgrep_bin,
        args.extra_args,
    );

    let start = Instant::now();
    let run_result = run_process(&cmd, args.env, args.timeout);
    let elapsed_ms = start.elapsed().as_millis() as i64;

    // Read the json output file before cleanup.
    let json_text: String = if json_path.exists() {
        std::fs::read_to_string(json_path).unwrap_or_default()
    } else {
        String::new()
    };

    if cleanup_json {
        safe_unlink(json_path);
    }

    match run_result {
        Err(RunError::Timeout) => SemgrepResult {
            name,
            config: args.config.to_string(),
            target: args.target.to_string_lossy().to_string(),
            errors: vec![format!("Timeout after {}s", args.timeout)],
            returncode: -1,
            elapsed_ms,
            ..Default::default()
        },
        Err(RunError::Os(msg)) => SemgrepResult {
            name,
            config: args.config.to_string(),
            target: args.target.to_string_lossy().to_string(),
            errors: vec![msg],
            returncode: -1,
            elapsed_ms,
            ..Default::default()
        },
        Ok((returncode, sarif_text, stderr_text)) => {
            let findings = parse_sarif(&sarif_text);
            let parsed_json = parse_json_output(&json_text);
            SemgrepResult {
                name,
                config: args.config.to_string(),
                target: args.target.to_string_lossy().to_string(),
                findings,
                files_examined: parsed_json.files_examined,
                files_failed: parsed_json.files_failed,
                semgrep_version: parsed_json.semgrep_version,
                returncode,
                stderr: stderr_text,
                sarif: sarif_text,
                json_output: json_text,
                elapsed_ms,
                errors: vec![],
            }
        }
    }
}

// ── run_rules ─────────────────────────────────────────────────────────────────

/// Run multiple semgrep configurations sequentially.
///
/// Faithful port of Python `run_rules`. Callers needing parallelism should
/// orchestrate their own thread pool over `run_rule` (identical to how
/// Python's `scanner.py` uses `ThreadPoolExecutor` over `run_rule`).
pub fn run_rules(
    target: &Path,
    configs: &[(String, String)],
    timeout: u64,
    rule_timeout: u64,
    env: Option<&HashMap<String, String>>,
    semgrep_bin: Option<&str>,
    extra_args: Option<&[String]>,
) -> Vec<SemgrepResult> {
    if !is_available() {
        return configs
            .iter()
            .map(|(name, config)| SemgrepResult {
                name: name.clone(),
                config: config.clone(),
                target: target.to_string_lossy().to_string(),
                errors: vec![
                    "semgrep is not installed (semgrep binary not found on PATH)".to_string(),
                ],
                returncode: -1,
                ..Default::default()
            })
            .collect();
    }

    configs
        .iter()
        .map(|(name, config)| {
            run_rule(RunRuleArgs {
                target,
                config,
                name,
                timeout,
                rule_timeout,
                env,
                json_output_path: None,
                semgrep_bin,
                extra_args,
            })
        })
        .collect()
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Derive a friendly name from a config string.
/// Mirrors Python `_config_to_name`.
pub fn config_to_name(config: &str) -> String {
    if config.is_empty() {
        return "semgrep".to_string();
    }
    // Pack identifiers like "p/security-audit" or "category/injection"
    if config.starts_with("p/") || config.starts_with("category/") {
        return config.to_string();
    }
    // Directory path — use the basename (mirrors Python `Path(config).name or config`)
    let name = Path::new(config)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    if name.is_empty() { config.to_string() } else { name }
}

/// Locate `bin` on PATH.  Mirrors Python `shutil.which`.
fn which(bin: &str) -> Option<PathBuf> {
    let path_var = std::env::var("PATH").ok()?;
    let sep = if cfg!(windows) { ';' } else { ':' };
    for dir in path_var.split(sep) {
        let candidate = Path::new(dir).join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Generate a unique temp file path (replacement for Python's `NamedTemporaryFile`).
fn make_temp_json_path() -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let mut tmp = std::env::temp_dir();
    tmp.push(format!("semgrep_{}_{}.json", pid, nanos));
    tmp
}

/// Remove a path, silently ignoring errors (mirrors Python `_safe_unlink`).
fn safe_unlink(path: &Path) {
    let _ = std::fs::remove_file(path);
}

// ── internal runner with timeout ──────────────────────────────────────────────

enum RunError {
    Timeout,
    Os(String),
}

/// Spawn `cmd[0]` with `cmd[1..]` args, wait up to `timeout` seconds.
///
/// Returns `(returncode, stdout, stderr)` on success.
/// Mirrors Python's `subprocess.run(..., timeout=timeout, capture_output=True, text=True)`.
fn run_process(
    cmd: &[String],
    env: Option<&HashMap<String, String>>,
    timeout: u64,
) -> Result<(i32, String, String), RunError> {
    if cmd.is_empty() {
        return Err(RunError::Os("empty command".to_string()));
    }

    let mut builder = Command::new(&cmd[0]);
    builder.args(&cmd[1..]);
    builder.stdout(Stdio::piped());
    builder.stderr(Stdio::piped());

    if let Some(env_map) = env {
        // Explicit env replaces the child's environment entirely.
        builder.env_clear();
        builder.envs(env_map.iter());
    }
    // else: child inherits current process environment (Python default when env=None)

    let child = builder.spawn().map_err(|e| RunError::Os(e.to_string()))?;

    // Thread-based timeout: mirrors Python's `subprocess.TimeoutExpired`.
    let (tx, rx) = mpsc::channel::<std::io::Result<std::process::Output>>();
    thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });

    match rx.recv_timeout(Duration::from_secs(timeout)) {
        Ok(Ok(output)) => {
            let rc = output.status.code().unwrap_or(-1);
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            Ok((rc, stdout, stderr))
        }
        Ok(Err(e)) => Err(RunError::Os(e.to_string())),
        // recv_timeout elapsed: subprocess never completed in time.
        Err(_) => Err(RunError::Timeout),
    }
}
