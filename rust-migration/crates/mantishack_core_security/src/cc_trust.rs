//! Faithful port of `core/security/cc_trust.py`.
//!
//! Trust check for target-repo Claude Code config files
//! (`.claude/settings.json`, `.claude/settings.local.json`, `.mcp.json`).
//! Returns `true` when the caller should refuse to dispatch Claude Code.
//!
//! ## Cycle break
//! The Python module imports `MantishackConfig.DANGEROUS_ENV_VARS` at import
//! time and unions it onto `_COMPREHENSIVE_DANGEROUS_ENV_VARS`, with a
//! documented fallback to the comprehensive set alone when `core.config` is
//! unimportable. Rust forbids the config→security→config crate cycle, so this
//! crate holds the comprehensive set as the **default** (== the config-absent
//! path) and exposes [`set_config_dangerous_env_vars`] as the injection point
//! the config crate calls at runtime to reproduce the config-present path.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use regex::Regex;

use crate::pyval::PyVal;

// ───────────────────────── process-wide trust override ─────────────────────

static TRUST_OVERRIDE: Mutex<bool> = Mutex::new(false);

/// Set the process-wide trust override. Idempotent. Port of
/// `set_trust_override`.
pub fn set_trust_override(val: bool) {
    *TRUST_OVERRIDE.lock().unwrap() = val;
}

/// Read the process-wide trust override. Port of `is_trust_overridden`.
pub fn is_trust_overridden() -> bool {
    *TRUST_OVERRIDE.lock().unwrap()
}

// ───────────────────────── optional MANTISHACK_DIR skip ─────────────────────

static MANTISHACK_DIR: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Configure the MANTISHACK repo root that is implicitly trusted (skipped).
///
/// Python derives `_MANTISHACK_DIR` from `__file__`; the installed Rust crate
/// has no fixed source path, so callers set it explicitly. Unset → no skip.
pub fn set_mantishack_dir(dir: PathBuf) {
    *MANTISHACK_DIR.lock().unwrap() = Some(dir);
}

// ───────────────────────── dangerous env var set ───────────────────────────

/// `_COMPREHENSIVE_DANGEROUS_ENV_VARS` — verbatim from cc_trust.py:105-152.
/// This is the **config-absent fallback** set.
pub const COMPREHENSIVE_DANGEROUS_ENV_VARS: &[&str] = &[
    "TERMINAL", "BROWSER", "PAGER", "VISUAL", "EDITOR",
    "IFS", "CDPATH",
    "BASH_ENV", "ENV", "PROMPT_COMMAND",
    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FALLBACK_LIBRARY_PATH",
    "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT",
    "NODE_OPTIONS", "NODE_PATH",
    "PERL5OPT", "PERLLIB", "PERL5LIB",
    "RUBYOPT", "RUBYLIB",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
    "http_proxy", "https_proxy", "all_proxy",
    "NO_PROXY", "no_proxy",
    "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH",
    "MAVEN_OPTS", "GRADLE_OPTS",
    "CARGO_HOME", "GEM_HOME", "GEM_PATH", "BUNDLE_GEMFILE",
    "PYTHONUSERBASE", "PYTHONBREAKPOINT",
    "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG",
    "GIT_SSH_COMMAND", "GIT_SSH", "SSH_ASKPASS",
    "OPENSSL_CONF",
    "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
    "SSL_CERT_FILE", "SSL_CERT_DIR",
    "NODE_EXTRA_CA_CERTS", "SSLKEYLOGFILE",
    "KUBECONFIG",
];

/// Additional names injected by the config crate (mirrors
/// `MantishackConfig.DANGEROUS_ENV_VARS`). Empty == config-absent path.
static CONFIG_DANGEROUS_ENV_VARS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Injection point: supply `MantishackConfig.DANGEROUS_ENV_VARS` so the
/// dangerous-env detection matches the **config-present** Python path.
pub fn set_config_dangerous_env_vars(names: Vec<String>) {
    *CONFIG_DANGEROUS_ENV_VARS.lock().unwrap() = names;
}

/// The active dangerous-env set, upper-cased (Python compares against
/// `{v.upper() for v in _DANGEROUS_ENV_VARS}`).
fn dangerous_upper() -> HashSet<String> {
    let mut set: HashSet<String> = COMPREHENSIVE_DANGEROUS_ENV_VARS
        .iter()
        .map(|s| s.to_uppercase())
        .collect();
    for s in CONFIG_DANGEROUS_ENV_VARS.lock().unwrap().iter() {
        set.insert(s.to_uppercase());
    }
    set
}

const MAX_CONFIG_BYTES: u64 = 1_000_000;

const CREDENTIAL_HELPER_KEYS: &[&str] =
    &["apiKeyHelper", "awsAuthHelper", "awsAuthRefresh", "gcpAuthRefresh"];

// ───────────────────────── _safe / _truncate ───────────────────────────────

fn cc_cf_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[\p{Cc}\p{Cf}]").unwrap())
}

/// Port of `cc_trust._safe`. Replaces Unicode control/format chars (Cc/Cf) and
/// U+2028/U+2029 line/paragraph separators with `?`, preserving tab.
pub fn safe(s: &str) -> String {
    let re = cc_cf_re();
    let mut buf = [0u8; 4];
    s.chars()
        .map(|c| {
            if c == '\t' {
                c
            } else if c == '\u{2028}' || c == '\u{2029}' || re.is_match(c.encode_utf8(&mut buf)) {
                '?'
            } else {
                c
            }
        })
        .collect()
}

/// Port of `cc_trust._truncate`. Length is counted in Unicode scalar values
/// (Python `len(str)` counts code points); `safe` is length-preserving.
pub fn truncate(s: &str, limit: usize) -> String {
    let safe_s = safe(s);
    let count = safe_s.chars().count();
    if count > limit {
        let head: String = safe_s.chars().take(limit).collect();
        format!("{}...", head)
    } else {
        safe_s
    }
}

fn truncate80(s: &str) -> String {
    truncate(s, 80)
}

// ───────────────────────── Finding / FileScan ──────────────────────────────

/// One labelled row in the per-file findings table. Port of `cc_trust.Finding`.
#[derive(Clone, Debug, PartialEq)]
pub struct Finding {
    pub label: String,
    pub value: String,
    pub blocking: bool,
}

impl Finding {
    fn new(label: impl Into<String>, value: impl Into<String>, blocking: bool) -> Finding {
        Finding { label: label.into(), value: value.into(), blocking }
    }
}

/// Findings for one inspected file. Port of `cc_trust.FileScan`.
#[derive(Clone, Debug, PartialEq)]
pub struct FileScan {
    pub path: PathBuf,
    pub findings: Vec<Finding>,
}

impl FileScan {
    fn new(path: impl Into<PathBuf>) -> FileScan {
        FileScan { path: path.into(), findings: Vec::new() }
    }
    pub fn has_blocking(&self) -> bool {
        self.findings.iter().any(|f| f.blocking)
    }
}

// ───────────────────────── value-level scanners ────────────────────────────

/// Python truthiness of a JSON value.
fn truthy(v: &serde_json::Value) -> bool {
    use serde_json::Value as J;
    match v {
        J::Null => false,
        J::Bool(b) => *b,
        J::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        J::String(s) => !s.is_empty(),
        J::Array(a) => !a.is_empty(),
        J::Object(o) => !o.is_empty(),
    }
}

/// Scan a parsed settings object. Port of `cc_trust._scan_settings`'s body.
pub fn scan_settings_value(data: &serde_json::Value) -> FileScan {
    use serde_json::Value as J;
    let mut fs = FileScan::new(PathBuf::new());
    let obj = match data.as_object() {
        Some(o) => o,
        None => return fs,
    };

    // Credential helpers.
    for key in CREDENTIAL_HELPER_KEYS {
        if let Some(val) = obj.get(*key) {
            if truthy(val) {
                let value = match val {
                    J::String(s) => s.clone(),
                    _ => PyVal::from_json(val).py_repr(),
                };
                fs.findings.push(Finding::new(*key, truncate80(&value), true));
            }
        }
    }

    // Hooks.
    if let Some(J::Object(hooks)) = obj.get("hooks") {
        for (event_name, matchers) in hooks {
            let matchers = match matchers {
                J::Array(a) => a,
                _ => continue,
            };
            let ev = truncate(event_name, 40);
            for matcher in matchers {
                let inner = match matcher.as_object().and_then(|m| m.get("hooks")) {
                    Some(J::Array(a)) => a,
                    _ => continue,
                };
                for entry in inner {
                    let entry = match entry.as_object() {
                        Some(e) => e,
                        None => continue,
                    };
                    let hook_type = entry.get("type");
                    let is_command = matches!(hook_type, Some(J::String(s)) if s == "command");
                    if is_command {
                        let cmd = entry.get("command");
                        let value = match cmd {
                            Some(J::String(s)) if !s.is_empty() => truncate80(s),
                            _ => "(empty)".to_string(),
                        };
                        fs.findings.push(Finding::new(format!("{} hook", ev), value, true));
                    } else {
                        let type_label = match hook_type {
                            None | Some(J::Null) => "(missing)".to_string(),
                            Some(v) => truncate(&PyVal::from_json(v).py_str(), 40),
                        };
                        let mut keys: Vec<&String> = entry.keys().collect();
                        keys.sort();
                        let keys_summary = keys
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(",");
                        fs.findings.push(Finding::new(
                            format!("{} hook ({}, unknown type)", ev, type_label),
                            truncate80(&keys_summary),
                            true,
                        ));
                    }
                }
            }
        }
    }

    // Dangerous env vars.
    if let Some(J::Object(env_cfg)) = obj.get("env") {
        let dangerous = dangerous_upper();
        for (env_key, env_val) in env_cfg {
            let key_upper = env_key.to_uppercase();
            if dangerous.contains(&key_upper)
                || key_upper.starts_with("MANTISHACK_")
                || key_upper.starts_with("SAGE_")
            {
                let k = truncate(env_key, 40);
                let v = truncate80(&PyVal::from_json(env_val).py_str());
                fs.findings.push(Finding::new(format!("env {}", k), v, true));
            }
        }
    }

    fs
}

/// Scan a parsed `.mcp.json` object. Port of `cc_trust._scan_mcp`'s body.
pub fn scan_mcp_value(data: &serde_json::Value) -> FileScan {
    use serde_json::Value as J;
    let mut fs = FileScan::new(PathBuf::new());
    let obj = match data.as_object() {
        Some(o) => o,
        None => return fs,
    };

    if let Some(J::Object(servers)) = obj.get("mcpServers") {
        for (name, cfg) in servers {
            let n = truncate(name, 40);
            let cfg_obj = match cfg.as_object() {
                Some(c) => c,
                None => {
                    fs.findings.push(Finding::new(
                        format!("unknown server \"{}\"", n),
                        "(not an object)",
                        true,
                    ));
                    continue;
                }
            };
            if cfg_obj.contains_key("command") {
                let cmd_str = match cfg_obj.get("command") {
                    Some(v) => PyVal::from_json(v).py_str(),
                    None => String::new(),
                };
                let mut parts = vec![cmd_str];
                if let Some(J::Array(args)) = cfg_obj.get("args") {
                    for a in args {
                        parts.push(PyVal::from_json(a).py_str());
                    }
                }
                fs.findings.push(Finding::new(
                    format!("stdio server \"{}\"", n),
                    truncate80(&parts.join(" ")),
                    true,
                ));
            } else if cfg_obj.contains_key("url") {
                let url = match cfg_obj.get("url") {
                    Some(v) => PyVal::from_json(v).py_str(),
                    None => String::new(),
                };
                fs.findings.push(Finding::new(
                    format!("url server \"{}\"", n),
                    truncate80(&url),
                    false,
                ));
            } else {
                fs.findings.push(Finding::new(
                    format!("unknown server \"{}\"", n),
                    truncate80(&PyVal::from_json(cfg).py_repr()),
                    true,
                ));
            }
        }
    }

    fs
}

// ───────────────────────── file layer ──────────────────────────────────────

fn path_present(p: &Path) -> bool {
    p.symlink_metadata().is_ok()
}

/// Read up to `MAX_CONFIG_BYTES` from a regular, non-symlink file. None on
/// oversized / non-regular / symlink / unreadable. Port of `_read_capped`.
fn read_capped(path: &Path) -> Option<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return None;
    }
    if meta.len() > MAX_CONFIG_BYTES {
        return None;
    }
    std::fs::read(path).ok()
}

/// Parse a settings/mcp JSON file. None on malformed/unreadable/non-object.
/// Mirrors `_load_json` (utf-8-sig BOM handling + dict-root requirement).
fn load_json(path: &Path) -> Option<serde_json::Value> {
    let raw = read_capped(path)?;
    // utf-8-sig: strip a leading BOM if present.
    let text = if raw.starts_with(&[0xEF, 0xBB, 0xBF]) {
        String::from_utf8(raw[3..].to_vec()).ok()?
    } else {
        String::from_utf8(raw).ok()?
    };
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    if value.is_object() {
        Some(value)
    } else {
        None
    }
}

fn scan_settings_file(path: &Path) -> Option<FileScan> {
    let data = load_json(path)?;
    let mut fs = scan_settings_value(&data);
    fs.path = path.to_path_buf();
    Some(fs)
}

fn scan_mcp_file(path: &Path) -> Option<FileScan> {
    let data = load_json(path)?;
    let mut fs = scan_mcp_value(&data);
    fs.path = path.to_path_buf();
    Some(fs)
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Settings,
    Mcp,
}

/// Pure repo scan. Returns `(scans, any_blocking)`. Port of `_scan_cached`.
pub fn scan_repo(resolved_path: &Path) -> (Vec<FileScan>, bool) {
    if let Some(ref dir) = *MANTISHACK_DIR.lock().unwrap() {
        if resolved_path == dir {
            return (Vec::new(), false);
        }
    }

    let candidates = [
        (Kind::Settings, resolved_path.join(".claude").join("settings.json")),
        (Kind::Settings, resolved_path.join(".claude").join("settings.local.json")),
        (Kind::Mcp, resolved_path.join(".mcp.json")),
    ];
    let present: Vec<&(Kind, PathBuf)> =
        candidates.iter().filter(|(_, p)| path_present(p)).collect();
    if present.is_empty() {
        return (Vec::new(), false);
    }

    let mut scans: Vec<FileScan> = Vec::new();
    for (kind, path) in present {
        let is_symlink = std::fs::symlink_metadata(path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        if is_symlink {
            let mut fs = FileScan::new(path.clone());
            let tgt = std::fs::read_link(path)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "<unreadable>".to_string());
            fs.findings.push(Finding::new("symlink", truncate(&tgt, 120), true));
            scans.push(fs);
            continue;
        }
        let scanned = match kind {
            Kind::Settings => scan_settings_file(path),
            Kind::Mcp => scan_mcp_file(path),
        };
        match scanned {
            None => {
                let mut fs = FileScan::new(path.clone());
                fs.findings
                    .push(Finding::new("(malformed)", "treated as dangerous", true));
                scans.push(fs);
            }
            Some(fs) if !fs.findings.is_empty() => scans.push(fs),
            Some(_) => {}
        }
    }

    let any_blocking = scans.iter().any(|s| s.has_blocking());
    (scans, any_blocking)
}

/// Non-strict path resolution mirroring Python `Path.resolve()` enough for the
/// trust gate: canonicalize when the path exists, else absolutize lexically.
fn resolve(repo_path: &str) -> Option<PathBuf> {
    let p = Path::new(repo_path);
    if let Ok(c) = std::fs::canonicalize(p) {
        return Some(c);
    }
    if p.is_absolute() {
        Some(p.to_path_buf())
    } else {
        std::env::current_dir().ok().map(|cwd| cwd.join(p))
    }
}

/// Check a target repo. Returns `true` if dispatch should be refused. Port of
/// `check_repo_claude_trust`. `trust_override == None` reads the module flag.
pub fn check_repo_claude_trust(repo_path: &str, trust_override: Option<bool>) -> bool {
    if repo_path.is_empty() {
        return false;
    }
    let resolved = match resolve(repo_path) {
        Some(r) => r,
        None => return false,
    };
    let trust = trust_override.unwrap_or_else(is_trust_overridden);
    let (scans, any_blocking) = scan_repo(&resolved);
    if !scans.is_empty() {
        print!("{}", render_scan_report(&resolved, &scans, any_blocking, trust));
    }
    any_blocking && !trust
}

/// Render the operator-visible report. Port of `_render_scan_report` (returns
/// the text rather than printing, so callers/tests choose the sink).
pub fn render_scan_report(
    target: &Path,
    scans: &[FileScan],
    any_blocking: bool,
    trust_override: bool,
) -> String {
    let safe_target = safe(&target.to_string_lossy());
    let mut out = String::new();
    if any_blocking {
        if trust_override {
            out.push_str(&format!(
                "mantishack: {} has dangerous Claude Code config (trust override active):\n",
                safe_target
            ));
        } else {
            out.push_str(&format!(
                "mantishack: {} has dangerous Claude Code config:\n",
                safe_target
            ));
        }
    } else {
        out.push_str(&format!(
            "mantishack: {} has Claude Code config:\n",
            safe_target
        ));
    }

    for fs in scans {
        let rel = fs.path.strip_prefix(target).unwrap_or(&fs.path);
        out.push_str(&format!("  {}\n", safe(&rel.to_string_lossy())));
        if fs.findings.is_empty() {
            continue;
        }
        let label_w = fs.findings.iter().map(|f| f.label.chars().count()).max().unwrap_or(0) + 2;
        for f in &fs.findings {
            let pad = label_w.saturating_sub(f.label.chars().count());
            out.push_str(&format!("    {}{}{}\n", f.label, " ".repeat(pad), f.value));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scan(v: &serde_json::Value, kind: Kind) -> Vec<(String, String, bool)> {
        let fs = match kind {
            Kind::Settings => scan_settings_value(v),
            Kind::Mcp => scan_mcp_value(v),
        };
        fs.findings
            .into_iter()
            .map(|f| (f.label, f.value, f.blocking))
            .collect()
    }

    #[test]
    fn safe_replaces_control_and_separators() {
        // Golden (Python _safe):
        assert_eq!(safe(&format!("a{}[31mb c{}d", '\u{1b}', '\t')), "a?[31mb c\td");
        assert_eq!(safe("a\nb"), "a?b");
        assert_eq!(safe("a\rb"), "a?b");
        assert_eq!(safe("a\u{2028}b"), "a?b");
        assert_eq!(safe("a\u{2029}b"), "a?b");
        assert_eq!(safe("a\u{200b}b"), "a?b"); // ZWSP (Cf)
        assert_eq!(safe("a\u{202e}b"), "a?b"); // RLO bidi (Cf)
        assert_eq!(safe("a\u{00}b"), "a?b"); // NUL
    }

    #[test]
    fn safe_preserves_spaces_tab_nbsp() {
        assert_eq!(safe("x y"), "x y"); // ordinary space (Zs) kept
        assert_eq!(safe("a\tb"), "a\tb"); // tab kept
        assert_eq!(safe("a\u{00a0}b"), "a\u{00a0}b"); // NBSP (Zs) kept
    }

    #[test]
    fn truncate_boundary() {
        // Golden: len 80 unchanged; len 81 -> first 80 + "..."
        assert_eq!(truncate(&"y".repeat(80), 80), "y".repeat(80));
        assert_eq!(truncate(&"y".repeat(81), 80), format!("{}...", "y".repeat(80)));
        // length counted after _safe (which preserves length)
        assert_eq!(truncate(&format!("{}{}", "y".repeat(79), '\u{00}'), 80), format!("{}?", "y".repeat(79)));
    }

    #[test]
    fn settings_dangerous_findings_order() {
        // Golden (Python case A), config-absent path (comprehensive only).
        let v = json!({
            "apiKeyHelper": "curl evil",
            "env": {"LD_PRELOAD": "x.so", "http_proxy": "p", "MANTISHACK_OUT_DIR": "/x", "SAGE_URL": "u", "SAFE": "ok"},
            "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "rm -rf /"}]}]}
        });
        assert_eq!(
            scan(&v, Kind::Settings),
            vec![
                ("apiKeyHelper".into(), "curl evil".into(), true),
                ("SessionStart hook".into(), "rm -rf /".into(), true),
                ("env LD_PRELOAD".into(), "x.so".into(), true),
                ("env http_proxy".into(), "p".into(), true),
                ("env MANTISHACK_OUT_DIR".into(), "/x".into(), true),
                ("env SAGE_URL".into(), "u".into(), true),
            ]
        );
    }

    #[test]
    fn unknown_hook_type_blocks() {
        // Golden (Python case C).
        let v = json!({"hooks": {"PreToolUse": [{"hooks": [{"type": "plugin", "name": "z"}]}]}});
        assert_eq!(
            scan(&v, Kind::Settings),
            vec![(
                "PreToolUse hook (plugin, unknown type)".into(),
                "name,type".into(),
                true
            )]
        );
    }

    #[test]
    fn empty_command_renders_empty_marker() {
        let v = json!({"hooks": {"E": [{"hooks": [{"type": "command", "command": ""}]}]}});
        assert_eq!(scan(&v, Kind::Settings), vec![("E hook".into(), "(empty)".into(), true)]);
    }

    #[test]
    fn mcp_stdio_url_unknown() {
        // Golden (Python case B).
        let v = json!({"mcpServers": {
            "s1": {"command": "node", "args": ["x.js"]},
            "s2": {"url": "https://h"},
            "s3": {}
        }});
        assert_eq!(
            scan(&v, Kind::Mcp),
            vec![
                ("stdio server \"s1\"".into(), "node x.js".into(), true),
                ("url server \"s2\"".into(), "https://h".into(), false),
                ("unknown server \"s3\"".into(), "{}".into(), true),
            ]
        );
    }

    #[test]
    fn mcp_non_object_server() {
        let v = json!({"mcpServers": {"bad": 42}});
        assert_eq!(
            scan(&v, Kind::Mcp),
            vec![("unknown server \"bad\"".into(), "(not an object)".into(), true)]
        );
    }

    #[test]
    fn config_present_path_catches_tmpdir() {
        // config-absent: TMPDIR not flagged. config-present: flagged.
        set_config_dangerous_env_vars(Vec::new());
        let v = json!({"env": {"TMPDIR": "/evil"}});
        assert_eq!(scan(&v, Kind::Settings), vec![]);

        set_config_dangerous_env_vars(vec!["TMPDIR".to_string(), "VIRTUAL_ENV".to_string()]);
        let v2 = json!({"env": {"TMPDIR": "/evil", "VIRTUAL_ENV": "/v"}});
        assert_eq!(
            scan(&v2, Kind::Settings),
            vec![
                ("env TMPDIR".into(), "/evil".into(), true),
                ("env VIRTUAL_ENV".into(), "/v".into(), true),
            ]
        );
        set_config_dangerous_env_vars(Vec::new()); // reset for other tests
    }

    #[test]
    fn env_key_case_insensitive_and_prefixes() {
        // Https_Proxy (case-fold), SAGE_*, MANTISHACK_* all blocked.
        let v = json!({"env": {"Https_Proxy": "p", "SAGE_X": "1", "mantishack_y": "2", "random": "ok"}});
        let got = scan(&v, Kind::Settings);
        let labels: Vec<&str> = got.iter().map(|(l, _, _)| l.as_str()).collect();
        assert!(labels.contains(&"env Https_Proxy"));
        assert!(labels.contains(&"env SAGE_X"));
        assert!(labels.contains(&"env mantishack_y"));
        assert!(!labels.contains(&"env random"));
        assert_eq!(got.len(), 3);
    }

    #[test]
    fn benign_settings_no_findings() {
        // Golden (Python case F).
        let v = json!({"model": "opus", "env": {"SAFEVAR": "1"}});
        assert_eq!(scan(&v, Kind::Settings), vec![]);
    }

    #[test]
    fn trust_override_flag_roundtrip() {
        set_trust_override(true);
        assert!(is_trust_overridden());
        set_trust_override(false);
        assert!(!is_trust_overridden());
    }

    #[test]
    fn check_repo_empty_path_is_false() {
        assert!(!check_repo_claude_trust("", None));
    }

    #[test]
    fn end_to_end_repo_scan_and_override() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let claude = dir.path().join(".claude");
        std::fs::create_dir(&claude).unwrap();
        let mut f = std::fs::File::create(claude.join("settings.json")).unwrap();
        write!(f, "{}", json!({"apiKeyHelper": "x"})).unwrap();
        let p = dir.path().to_string_lossy().into_owned();
        // strict -> refuse dispatch
        assert!(check_repo_claude_trust(&p, Some(false)));
        // trust override -> warn but allow
        assert!(!check_repo_claude_trust(&p, Some(true)));
    }

    #[test]
    fn malformed_json_blocks() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let claude = dir.path().join(".claude");
        std::fs::create_dir(&claude).unwrap();
        let mut f = std::fs::File::create(claude.join("settings.json")).unwrap();
        write!(f, "{{not json").unwrap();
        let (scans, blocking) = scan_repo(&std::fs::canonicalize(dir.path()).unwrap());
        assert!(blocking);
        assert_eq!(scans[0].findings[0].label, "(malformed)");
    }

    #[test]
    fn clean_repo_no_config() {
        let dir = tempfile::tempdir().unwrap();
        let (scans, blocking) = scan_repo(&std::fs::canonicalize(dir.path()).unwrap());
        assert!(scans.is_empty());
        assert!(!blocking);
    }
}
