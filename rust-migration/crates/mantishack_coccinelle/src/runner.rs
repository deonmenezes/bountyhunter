//! Coccinelle (spatch) runner — faithful port of `packages/coccinelle/runner.py`.
//!
//! The pure parsing/transform surface — [`parse_results`], [`parse_errors`],
//! [`dedup_matches`], [`inject_harness`], [`collect_files_examined`] — is
//! golden-vector verified against the Python oracle. The subprocess glue
//! ([`run_rule`] / [`run_rules`] / [`version`] / [`is_available`]) keeps the
//! `spatch` binary external and is testable via an injected [`SubprocessRunner`]
//! plus an explicit `available` flag (mirroring the Python tests' patching of
//! `is_available` and `subprocess.run`).

use std::collections::{BTreeSet, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use regex::Regex;
use serde_json::{json, Value};

use crate::models::{SpatchMatch, SpatchResult};

pub const RESULT_PREFIX: &str = "COCCIRESULT:";
const SPATCH_BIN: &str = "spatch";

/// Position-metavariable names refused for harness injection (Python keywords,
/// harness-scope locals, builtin foot-guns). Dunder-prefixed names are rejected
/// separately by the `starts_with("__")` check.
const COCCI_POS_VAR_DENY: &[&str] = &[
    "True", "False", "None", "if", "else", "elif", "for", "while", "import", "from", "as", "def",
    "class", "return", "yield", "lambda", "try", "except", "finally", "raise", "with", "pass",
    "break", "continue", "global", "nonlocal", "assert", "in", "is", "not", "and", "or", "json",
    "sys", "_p", "_m", "int", "str", "bytes", "open", "type", "list", "dict", "set", "tuple",
    "object", "print", "id", "input", "exec", "eval", "compile", "globals", "locals", "vars",
    "getattr", "setattr", "hasattr", "delattr",
];

const ERROR_PATTERNS: [&str; 7] = [
    "parse error", "semantic error", "fatal error", "syntax error", "unbound metavariable",
    "already tagged token", "metavariable not used",
];

// ─────────────────────────── pure parsing surface ──────────────────────────

/// Parse `COCCIRESULT:` lines from spatch stdout/stderr into matches.
pub fn parse_results(output: &str, rule_name: &str) -> Vec<SpatchMatch> {
    let mut matches = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        let Some(json_str) = line.strip_prefix(RESULT_PREFIX) else {
            continue;
        };
        let Ok(mut d) = serde_json::from_str::<Value>(json_str) else {
            continue;
        };
        // Skip non-object payloads (a malformed rule could emit array/string/null).
        let Value::Object(ref mut map) = d else {
            continue;
        };
        map.entry("rule".to_string()).or_insert_with(|| json!(rule_name));
        matches.push(SpatchMatch::from_dict(Some(&d)));
    }
    matches
}

/// Extract error messages from spatch stderr, ignoring info lines.
pub fn parse_errors(stderr: &str) -> Vec<String> {
    let mut errors = Vec::new();
    for line in stderr.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with(RESULT_PREFIX)
            || line.starts_with("init_defs_builtins:")
            || line.starts_with("HANDLING:")
        {
            continue;
        }
        let low = line.to_lowercase();
        if ERROR_PATTERNS.iter().any(|p| low.contains(p)) {
            errors.push(line.to_string());
        }
    }
    errors
}

/// Remove duplicate matches keyed on `(file, line, column, rule, message)`,
/// preserving order. `message` is part of the key on purpose — multi-message
/// rules legitimately emit distinct messages at the same `(file, line)`.
pub fn dedup_matches(matches: Vec<SpatchMatch>) -> Vec<SpatchMatch> {
    let mut seen: HashSet<(String, i64, i64, String, String)> = HashSet::new();
    let mut result = Vec::new();
    for m in matches {
        let key = (m.file.clone(), m.line, m.column, m.rule.clone(), m.message.clone());
        if seen.insert(key) {
            result.push(m);
        }
    }
    result
}

/// Build `files_examined` from the target plus any match files. For a directory
/// target, enumerate `*.c` and `*.h` recursively (spatch examines headers too).
pub fn collect_files_examined(target: &Path, match_files: &BTreeSet<String>) -> Vec<String> {
    let mut examined: BTreeSet<String> = BTreeSet::new();
    if target.is_file() {
        examined.insert(target.to_string_lossy().into_owned());
        examined.extend(match_files.iter().cloned());
    } else if target.is_dir() {
        rglob_suffix(target, &[".c", ".h"], &mut examined);
        examined.extend(match_files.iter().cloned());
    } else {
        examined.extend(match_files.iter().cloned());
    }
    examined.into_iter().collect()
}

fn rglob_suffix(dir: &Path, suffixes: &[&str], out: &mut BTreeSet<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rglob_suffix(&path, suffixes, out);
        } else if path.is_file() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if suffixes.iter().any(|s| name.ends_with(s)) {
                    out.insert(path.to_string_lossy().into_owned());
                }
            }
        }
    }
}

/// Wrap a plain SmPL rule with a Python reporting harness emitting COCCIRESULT
/// lines. Returns the rule unchanged when there's no single bindable position
/// metavariable, when the position name is unsafe, or for multi-rule files.
pub fn inject_harness(rule_text: &str, rule_name: &str) -> String {
    // `(?-u)` makes \s ASCII-only, matching Python's `re.ASCII`.
    let pos_present = Regex::new(r"(?-u)position\s+[A-Za-z0-9_]+").unwrap();
    if !pos_present.is_match(rule_text) {
        return rule_text.to_string();
    }
    let pos_capture = Regex::new(r"(?-u)position\s+([A-Za-z0-9_]+)").unwrap();
    let pos_var = pos_capture.captures(rule_text).unwrap()[1].to_string();

    if pos_var.starts_with("__") || COCCI_POS_VAR_DENY.contains(&pos_var.as_str()) {
        return rule_text.to_string();
    }

    let rule_name_re = Regex::new(r"(?-u)@([A-Za-z0-9_]+)@").unwrap();
    let rule_names: Vec<String> =
        rule_name_re.captures_iter(rule_text).map(|c| c[1].to_string()).collect();
    let distinct: HashSet<&String> = rule_names.iter().collect();
    if distinct.len() > 1 || rule_names.is_empty() {
        return rule_text.to_string();
    }
    let rule_id = &rule_names[0];

    let safe_name_re = Regex::new(r"[^a-zA-Z0-9_-]").unwrap();
    let safe_name = safe_name_re.replace_all(rule_name, "_");
    // json.dumps(safe_name): a quoted Python string literal (safe_name is ASCII).
    let safe_name_repr = serde_json::to_string(safe_name.as_ref()).unwrap();

    let harness = format!(
        "\n\n@script:python@\n{pos_var} << {rule_id}.{pos_var};\n@@\n\nimport json, sys\n\
for _p in {pos_var}:\n    _m = {{\"file\": _p.file, \"line\": int(_p.line), \"col\": \
int(_p.column), \"line_end\": int(_p.line_end), \"col_end\": int(_p.column_end), \"rule\": \
{safe_name_repr}}}\n    sys.stderr.write(\"{RESULT_PREFIX}\" + json.dumps(_m) + \"\\n\")\n",
    );
    format!("{rule_text}{harness}")
}

// ──────────────────────────── subprocess glue ──────────────────────────────

/// Output of a completed spatch invocation.
pub struct Spawned {
    pub returncode: i64,
    pub stdout: String,
    pub stderr: String,
}

/// Failure of a spatch invocation. `Timeout` carries any partial output, which
/// the runner still parses for matches (mirroring Python's `exc.stdout` capture).
pub enum SpawnError {
    Timeout { stdout: String, stderr: String },
    Os(String),
}

/// Pluggable subprocess executor (replaces Python's `subprocess_runner` arg).
pub trait SubprocessRunner {
    fn run(
        &self,
        cmd: &[String],
        env: &[(String, String)],
        cwd: Option<&Path>,
        timeout: u64,
    ) -> Result<Spawned, SpawnError>;
}

/// The real spatch executor: spawns the binary with a sanitised env, draining
/// stdout/stderr on threads and enforcing `timeout` (capturing partial output).
pub struct RealSpatch;

impl SubprocessRunner for RealSpatch {
    fn run(
        &self,
        cmd: &[String],
        env: &[(String, String)],
        cwd: Option<&Path>,
        timeout: u64,
    ) -> Result<Spawned, SpawnError> {
        let mut command = Command::new(&cmd[0]);
        command.args(&cmd[1..]).env_clear();
        for (k, v) in env {
            command.env(k, v);
        }
        if let Some(d) = cwd {
            command.current_dir(d);
        }
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|e| SpawnError::Os(e.to_string()))?;
        let mut out = child.stdout.take().unwrap();
        let mut err = child.stderr.take().unwrap();
        let t_out = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = out.read_to_string(&mut s);
            s
        });
        let t_err = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = err.read_to_string(&mut s);
            s
        });
        let deadline = Instant::now() + Duration::from_secs(timeout);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let stdout = t_out.join().unwrap_or_default();
                    let stderr = t_err.join().unwrap_or_default();
                    return Ok(Spawned {
                        returncode: status.code().map(|c| c as i64).unwrap_or(-1),
                        stdout,
                        stderr,
                    });
                }
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        let stdout = t_out.join().unwrap_or_default();
                        let stderr = t_err.join().unwrap_or_default();
                        return Err(SpawnError::Timeout { stdout, stderr });
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Err(SpawnError::Os(e.to_string())),
            }
        }
    }
}

#[cfg(unix)]
fn is_executable_file(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable_file(p: &Path) -> bool {
    p.is_file()
}

/// `shutil.which`-equivalent PATH lookup.
fn which(bin: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        let candidate = dir.join(bin);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Whether spatch is on PATH (re-probed each call, like the Python).
pub fn is_available() -> bool {
    which(SPATCH_BIN).is_some()
}

fn spatch_path() -> String {
    which(SPATCH_BIN).map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|| SPATCH_BIN.to_string())
}

/// Return the spatch version string, or `None` if unavailable.
pub fn version() -> Option<String> {
    version_impl(is_available(), &RealSpatch)
}

pub(crate) fn version_impl(available: bool, runner: &dyn SubprocessRunner) -> Option<String> {
    if !available {
        return None;
    }
    let env: Vec<(String, String)> = std::env::vars().collect();
    let proc = runner
        .run(&[spatch_path(), "--version".to_string()], &env, None, 10)
        .ok()?;
    for line in proc.stdout.lines() {
        // Faithful to Python's `line.startswith("spatch version")` (start-anchored).
        if let Some(after) = line.strip_prefix("spatch version") {
            return Some(after.trim().to_string());
        }
    }
    let trimmed = proc.stdout.trim();
    if trimmed.is_empty() {
        None
    } else {
        trimmed.lines().next().map(str::to_string)
    }
}

/// Options for a spatch invocation (mirrors `run_rule`'s keyword args).
#[derive(Default, Clone)]
pub struct RunOptions {
    pub include_dirs: Vec<PathBuf>,
    pub no_includes: bool,
    pub env: Option<Vec<(String, String)>>,
    pub defines: Vec<(String, String)>,
}

const RULE_MAX_BYTES: u64 = 1024 * 1024;

fn temp_cocci_path() -> PathBuf {
    static CTR: AtomicU64 = AtomicU64::new(0);
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("mantishack-cocci-{pid}-{nanos}-{n}.cocci"))
}

fn err_result(rule_name: &str, rule: &Path, msg: String) -> SpatchResult {
    SpatchResult {
        rule: rule_name.to_string(),
        rule_path: rule.to_string_lossy().into_owned(),
        errors: vec![msg],
        returncode: -1,
        ..Default::default()
    }
}

/// Run a single Coccinelle rule against a target.
pub fn run_rule(
    target: &Path,
    rule: &Path,
    timeout: u64,
    opts: &RunOptions,
    runner: Option<&dyn SubprocessRunner>,
) -> SpatchResult {
    let real = RealSpatch;
    let r: &dyn SubprocessRunner = runner.unwrap_or(&real);
    run_rule_impl(target, rule, timeout, opts, is_available(), r)
}

pub(crate) fn run_rule_impl(
    target: &Path,
    rule: &Path,
    timeout: u64,
    opts: &RunOptions,
    available: bool,
    runner: &dyn SubprocessRunner,
) -> SpatchResult {
    let rule_name =
        rule.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();

    if !available {
        return err_result(
            &rule_name,
            rule,
            "spatch is not installed (coccinelle package not found on PATH)".to_string(),
        );
    }
    if !rule.exists() {
        return err_result(&rule_name, rule, format!("Rule file not found: {}", rule.display()));
    }
    match std::fs::metadata(rule) {
        Ok(meta) => {
            if meta.len() > RULE_MAX_BYTES {
                return err_result(
                    &rule_name,
                    rule,
                    format!("Rule file exceeds {RULE_MAX_BYTES}-byte cap"),
                );
            }
        }
        Err(e) => {
            return err_result(&rule_name, rule, format!("Rule file stat failed: {e}"));
        }
    }

    let Ok(rule_text) = std::fs::read_to_string(rule) else {
        return err_result(&rule_name, rule, format!("Rule file read failed: {}", rule.display()));
    };
    let needs_harness =
        !rule_text.contains(RESULT_PREFIX) && !rule_text.contains("script:python");

    let mut harnessed_rule_path: Option<PathBuf> = None;
    if needs_harness {
        let injected = inject_harness(&rule_text, &rule_name);
        if injected != rule_text {
            let tmp = temp_cocci_path();
            if std::fs::write(&tmp, injected).is_ok() {
                harnessed_rule_path = Some(tmp);
            }
        }
    }

    let sp_file_path = harnessed_rule_path.clone().unwrap_or_else(|| rule.to_path_buf());
    let mut cmd: Vec<String> = vec![
        spatch_path(),
        "--sp-file".to_string(),
        sp_file_path.to_string_lossy().into_owned(),
    ];
    if target.is_dir() {
        cmd.push("--dir".to_string());
        cmd.push(target.to_string_lossy().into_owned());
    } else {
        cmd.push(target.to_string_lossy().into_owned());
    }
    if opts.no_includes {
        cmd.push("--no-includes".to_string());
    }
    for d in &opts.include_dirs {
        cmd.push("-I".to_string());
        cmd.push(d.to_string_lossy().into_owned());
    }
    cmd.push("--very-quiet".to_string());
    for (k, v) in &opts.defines {
        cmd.push("-D".to_string());
        cmd.push(format!("{k}={v}"));
    }

    let run_env: Vec<(String, String)> = match &opts.env {
        Some(e) => e.clone(),
        None => mantishack_core_config::get_safe_env(false, false),
    };
    let spatch_cwd: Option<PathBuf> = if target.is_file() {
        target.parent().map(Path::to_path_buf)
    } else if target.is_dir() {
        Some(target.to_path_buf())
    } else {
        None
    };

    let start = Instant::now();
    let result = match runner.run(&cmd, &run_env, spatch_cwd.as_deref(), timeout) {
        Ok(proc) => {
            let elapsed = start.elapsed().as_millis() as i64;
            let mut all = parse_results(&proc.stdout, &rule_name);
            all.extend(parse_results(&proc.stderr, &rule_name));
            let matches = dedup_matches(all);
            let errors = parse_errors(&proc.stderr);
            let match_files: BTreeSet<String> = matches.iter().map(|m| m.file.clone()).collect();
            let files_examined = collect_files_examined(target, &match_files);
            SpatchResult {
                rule: rule_name.clone(),
                rule_path: rule.to_string_lossy().into_owned(),
                matches,
                files_examined,
                errors,
                elapsed_ms: elapsed,
                returncode: proc.returncode,
            }
        }
        Err(SpawnError::Timeout { stdout, stderr }) => {
            let mut all = parse_results(&stdout, &rule_name);
            all.extend(parse_results(&stderr, &rule_name));
            SpatchResult {
                rule: rule_name.clone(),
                rule_path: rule.to_string_lossy().into_owned(),
                matches: dedup_matches(all),
                errors: vec![format!("Timeout after {timeout}s (partial output captured)")],
                returncode: -1,
                ..Default::default()
            }
        }
        Err(SpawnError::Os(e)) => err_result(&rule_name, rule, e),
    };

    if let Some(tmp) = harnessed_rule_path {
        let _ = std::fs::remove_file(tmp);
    }
    result
}

/// Run all `.cocci` rules in a directory against a target, in filename order.
pub fn run_rules(
    target: &Path,
    rules_dir: &Path,
    timeout_per_rule: u64,
    opts: &RunOptions,
    runner: Option<&dyn SubprocessRunner>,
) -> Vec<SpatchResult> {
    let real = RealSpatch;
    let r: &dyn SubprocessRunner = runner.unwrap_or(&real);
    run_rules_impl(target, rules_dir, timeout_per_rule, opts, is_available(), r)
}

pub(crate) fn run_rules_impl(
    target: &Path,
    rules_dir: &Path,
    timeout_per_rule: u64,
    opts: &RunOptions,
    available: bool,
    runner: &dyn SubprocessRunner,
) -> Vec<SpatchResult> {
    if !rules_dir.is_dir() {
        return Vec::new();
    }
    let mut rule_paths: Vec<PathBuf> = match std::fs::read_dir(rules_dir) {
        Ok(entries) => entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().map(|x| x == "cocci").unwrap_or(false))
            .collect(),
        Err(_) => return Vec::new(),
    };
    if rule_paths.is_empty() {
        return Vec::new();
    }
    rule_paths.sort();

    if !available {
        return vec![SpatchResult {
            rule: "coccinelle".to_string(),
            errors: vec!["spatch is not installed (coccinelle package not found on PATH)".to_string()],
            returncode: -1,
            ..Default::default()
        }];
    }

    rule_paths
        .iter()
        .map(|rp| run_rule_impl(target, rp, timeout_per_rule, opts, available, runner))
        .collect()
}
