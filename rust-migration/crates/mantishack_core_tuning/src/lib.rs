//! Hardware-aware resource tuning for MANTISHACK.
//!
//! Faithful Rust port of `core/tuning/__init__.py`.
//!
//! Reads `tuning.json` from the repo root, resolves `"auto"` values using
//! hardware detection, validates per-key, and exposes resolved integers to
//! consumers via `get_tuning()`.
//!
//! Cycle break: Python `core.json.cache` lazily calls `core.tuning.load_tuning()`
//! at cache-construction time. In Rust, `mantishack_core_json` does NOT depend
//! on `mantishack_core_tuning` — instead it exposes `set_max_memo_mb(u64)`.
//! After `load_tuning()` resolves the value, callers should invoke:
//!   `mantishack_core_json::set_max_memo_mb(tuning.max_json_memo_mb as u64)`

use std::path::{Path, PathBuf};
use std::sync::Mutex;

// ── constants ────────────────────────────────────────────────────────────────

const VALID_KEYS: &[&str] = &[
    "codeql_ram_mb",
    "codeql_threads",
    "max_semgrep_workers",
    "max_codeql_workers",
    "max_agentic_parallel",
    "max_fuzz_parallel",
    "max_inventory_workers",
    "max_json_memo_mb",
];

/// Keys where 0 is a valid explicit value (CodeQL's "0 = all CPUs").
const ZERO_ALLOWED: &[&str] = &["codeql_threads"];

// ── Tuning struct ────────────────────────────────────────────────────────────

/// Resolved tuning values — all integers, no `"auto"`. Port of Python `Tuning`.
#[derive(Clone, Debug, PartialEq)]
pub struct Tuning {
    pub codeql_ram_mb: i64,
    pub codeql_threads: i64,
    pub max_semgrep_workers: i64,
    pub max_codeql_workers: i64,
    pub max_agentic_parallel: i64,
    pub max_fuzz_parallel: i64,
    pub max_inventory_workers: i64,
    pub max_json_memo_mb: i64,
}

// ── hardware detection ───────────────────────────────────────────────────────

fn detect_total_ram_mb() -> i64 {
    // Try /proc/meminfo on Linux
    #[cfg(target_os = "linux")]
    if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
        for line in content.lines() {
            if line.starts_with("MemTotal:") {
                let kb: i64 = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                if kb > 0 {
                    return kb / 1024;
                }
            }
        }
    }
    // Conservative fallback (matches Python's 32768)
    32768
}

fn detect_ram_mb() -> i64 {
    // 25% of system RAM, clamped to [2048, 16384] MB
    let total = detect_total_ram_mb();
    (total / 4).max(2048).min(16384)
}

fn detect_threads() -> i64 {
    // 0 tells CodeQL to use all available CPUs — always 0
    0
}

fn detect_available_cpus() -> i64 {
    // Try cgroup CPU quota (Linux)
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/sys/fs/cgroup/cpu.max") {
            let parts: Vec<&str> = content.trim().split_whitespace().collect();
            if parts.len() >= 2 && parts[0] != "max" {
                if let (Ok(quota), Ok(period)) =
                    (parts[0].parse::<i64>(), parts[1].parse::<i64>())
                {
                    if quota > 0 && period > 0 {
                        let cpus = ((quota as f64 / period as f64).ceil() as i64).max(1);
                        // Use the minimum of cgroup and os::cpu_count
                        let os_cpus = std::thread::available_parallelism()
                            .map(|n| n.get() as i64)
                            .unwrap_or(4);
                        return cpus.min(os_cpus).max(1);
                    }
                }
            }
        }
    }
    std::thread::available_parallelism()
        .map(|n| n.get() as i64)
        .unwrap_or(4)
}

fn detect_half_cpu_parallelism(max_workers: Option<i64>) -> i64 {
    let cpus = detect_available_cpus();
    let workers = (cpus / 2).max(1);
    if let Some(max) = max_workers {
        workers.min(max)
    } else {
        workers
    }
}

fn detect_semgrep_workers() -> i64 {
    detect_half_cpu_parallelism(None)
}

fn detect_codeql_workers() -> i64 {
    let per_worker_ram_mb = detect_ram_mb();
    let ram_limited = (detect_total_ram_mb() / per_worker_ram_mb).max(1);
    detect_half_cpu_parallelism(Some(8_i64.min(ram_limited)))
}

fn detect_fuzz_parallel() -> i64 {
    detect_half_cpu_parallelism(None)
}

fn detect_inventory_workers() -> i64 {
    detect_half_cpu_parallelism(Some(8))
}

// ── validation ───────────────────────────────────────────────────────────────

/// Default raw value for a key (before resolution). Mirrors `_DEFAULTS`.
fn default_raw(key: &str) -> serde_json::Value {
    use serde_json::json;
    match key {
        "codeql_ram_mb" => json!("auto"),
        "codeql_threads" => json!("auto"),
        "max_semgrep_workers" => json!(4),
        "max_codeql_workers" => json!(2),
        "max_agentic_parallel" => json!(3),
        "max_fuzz_parallel" => json!(4),
        "max_inventory_workers" => json!("auto"),
        "max_json_memo_mb" => json!(128),
        _ => json!(null),
    }
}

/// Auto-resolver for a key. Returns `None` if key does not support "auto".
fn resolve_auto(key: &str) -> Option<i64> {
    match key {
        "codeql_ram_mb" => Some(detect_ram_mb()),
        "codeql_threads" => Some(detect_threads()),
        "max_semgrep_workers" => Some(detect_semgrep_workers()),
        "max_codeql_workers" => Some(detect_codeql_workers()),
        "max_fuzz_parallel" => Some(detect_fuzz_parallel()),
        "max_inventory_workers" => Some(detect_inventory_workers()),
        _ => None,
    }
}

/// Validate and resolve a single tuning value. Returns `None` if invalid
/// (caller uses the default). Port of Python `_validate_value`.
fn validate_value(key: &str, raw: &serde_json::Value) -> Option<i64> {
    use serde_json::Value;
    if raw == "auto" {
        match resolve_auto(key) {
            Some(v) => return Some(v),
            None => {
                eprintln!(
                    "tuning.json: \"{}\" does not support \"auto\", using default ({:?})",
                    key,
                    default_raw(key)
                );
                return None;
            }
        }
    }
    let min_val: i64 = if ZERO_ALLOWED.contains(&key) { 0 } else { 1 };
    match raw {
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                if i >= min_val {
                    return Some(i);
                }
            } else if let Some(f) = n.as_f64() {
                // Accept integer-valued floats (4.0 → 4)
                if f.fract() == 0.0 && f >= min_val as f64 {
                    return Some(f as i64);
                }
            }
        }
        _ => {}
    }
    eprintln!(
        "tuning.json: \"{}\" must be \"auto\" or a positive integer, using default ({:?})",
        key,
        default_raw(key)
    );
    None
}

/// Resolve raw config dict into a validated `Tuning`. Port of Python `_resolve`.
pub fn resolve(raw_config: &serde_json::Value) -> Tuning {
    let obj = match raw_config.as_object() {
        Some(m) => m,
        None => {
            eprintln!("tuning.json: expected object, using all defaults");
            return resolve(&serde_json::Value::Object(Default::default()));
        }
    };
    // Warn about unknown keys
    for k in obj.keys() {
        if !VALID_KEYS.contains(&k.as_str()) {
            eprintln!("tuning.json: unknown key \"{}\" (ignored)", k);
        }
    }
    let get = |key: &str| -> i64 {
        let raw = obj.get(key).cloned().unwrap_or_else(|| default_raw(key));
        let v = validate_value(key, &raw);
        match v {
            Some(resolved) => resolved,
            None => {
                let def = default_raw(key);
                validate_value(key, &def)
                    .expect("default value must always be valid")
            }
        }
    };
    Tuning {
        codeql_ram_mb: get("codeql_ram_mb"),
        codeql_threads: get("codeql_threads"),
        max_semgrep_workers: get("max_semgrep_workers"),
        max_codeql_workers: get("max_codeql_workers"),
        max_agentic_parallel: get("max_agentic_parallel"),
        max_fuzz_parallel: get("max_fuzz_parallel"),
        max_inventory_workers: get("max_inventory_workers"),
        max_json_memo_mb: get("max_json_memo_mb"),
    }
}

// ── tuning path ──────────────────────────────────────────────────────────────

/// Returns the default tuning.json path from `$MANTISHACK_DIR/tuning.json`.
pub fn default_tuning_path() -> PathBuf {
    if let Ok(dir) = std::env::var("MANTISHACK_DIR") {
        PathBuf::from(dir).join("tuning.json")
    } else {
        PathBuf::from("tuning.json")
    }
}

// ── load_tuning ──────────────────────────────────────────────────────────────

/// Load and resolve tuning from disk. Falls back to defaults if the file
/// does not exist or cannot be parsed. Port of Python `load_tuning`.
pub fn load_tuning(path: Option<&Path>) -> Tuning {
    let default_path = default_tuning_path();
    let p = path.unwrap_or(&default_path);
    let raw = mantishack_core_json::load_json_with_comments(p);
    let raw_val = match raw {
        Some(v) => v,
        None => {
            // If file absent AND we're at the default location, create it
            if path.is_none() && !p.exists() {
                create_default_file(p);
                mantishack_core_json::load_json_with_comments(p)
                    .unwrap_or(serde_json::Value::Object(Default::default()))
            } else {
                serde_json::Value::Object(Default::default())
            }
        }
    };
    let val = if raw_val.is_object() {
        raw_val
    } else {
        eprintln!("tuning.json: expected object, using all defaults");
        serde_json::Value::Object(Default::default())
    };
    resolve(&val)
}

// ── create_default_file ──────────────────────────────────────────────────────

fn create_default_file(path: &Path) {
    let defaults = &[
        ("codeql_ram_mb", "\"auto\"", "MB of RAM for CodeQL analysis"),
        ("codeql_threads", "\"auto\"", "CPUs for CodeQL (0 = all available)"),
        ("max_semgrep_workers", "4", "parallel Semgrep scans (auto = half available CPUs)"),
        ("max_codeql_workers", "2", "parallel CodeQL DB builds (auto = half available CPUs, capped)"),
        ("max_agentic_parallel", "3", "parallel Claude Code agents for analysis"),
        ("max_fuzz_parallel", "4", "ceiling for AFL++ parallel instances (auto = half available CPUs)"),
        ("max_inventory_workers", "\"auto\"", "per-file extractor pool for tree-sitter parse (auto = half CPUs, capped at 8)"),
        ("max_json_memo_mb", "128", "byte budget for JsonCache in-process memo; oldest entries evicted past this"),
    ];
    let col = defaults.iter().map(|(k, v, _)| k.len() + v.len() + 6).max().unwrap_or(40) + 2;
    let mut lines = vec!["{".to_string()];
    let n = defaults.len();
    for (i, (key, val, comment)) in defaults.iter().enumerate() {
        let comma = if i + 1 < n { "," } else { "" };
        let entry = format!("  \"{}\": {}{}", key, val, comma);
        lines.push(format!("{:<width$}// {}", entry, comment, width = col));
    }
    lines.push("}".to_string());
    let content = lines.join("\n") + "\n";

    let pid = std::process::id();
    let tmp_name = format!("{}.tmp.{}", path.file_name().and_then(|n| n.to_str()).unwrap_or("tuning.json"), pid);
    let tmp = path.with_file_name(tmp_name);
    let write_res: std::io::Result<()> = (|| {
        std::fs::write(&tmp, &content)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    })();
    if write_res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
}

// ── get_tuning (mtime-cached) ────────────────────────────────────────────────

struct CachedTuning {
    tuning: Tuning,
    // (mtime_ns, size) fingerprint
    stat: Option<(u128, u64)>,
}

fn file_stat(path: &Path) -> Option<(u128, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    let mtime = meta
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    let mtime_ns = mtime.as_nanos();
    Some((mtime_ns, meta.len()))
}

static CACHED_TUNING: Mutex<Option<CachedTuning>> = Mutex::new(None);

/// Return tuning values, re-reading only when `tuning.json` changes.
/// Thread-safe via a `Mutex`. Port of Python `get_tuning`.
pub fn get_tuning() -> Tuning {
    let path = default_tuning_path();
    let current_stat = file_stat(&path);
    let mut guard = CACHED_TUNING.lock().unwrap();
    if let Some(ref cached) = *guard {
        if cached.stat == current_stat {
            return cached.tuning.clone();
        }
    }
    let tuning = load_tuning(None);
    *guard = Some(CachedTuning {
        tuning: tuning.clone(),
        stat: current_stat,
    });
    tuning
}

// ── PyO3 bindings ─────────────────────────────────────────────────────────────

#[cfg(feature = "python")]
mod python {
    use pyo3::prelude::*;
    use pyo3::types::PyModule;

    #[pyfunction]
    fn load_tuning(py: Python<'_>, path: Option<&str>) -> PyResult<PyObject> {
        let p = path.map(std::path::Path::new);
        let t = super::load_tuning(p);
        let dict = pyo3::types::PyDict::new_bound(py);
        dict.set_item("codeql_ram_mb", t.codeql_ram_mb)?;
        dict.set_item("codeql_threads", t.codeql_threads)?;
        dict.set_item("max_semgrep_workers", t.max_semgrep_workers)?;
        dict.set_item("max_codeql_workers", t.max_codeql_workers)?;
        dict.set_item("max_agentic_parallel", t.max_agentic_parallel)?;
        dict.set_item("max_fuzz_parallel", t.max_fuzz_parallel)?;
        dict.set_item("max_inventory_workers", t.max_inventory_workers)?;
        dict.set_item("max_json_memo_mb", t.max_json_memo_mb)?;
        Ok(dict.into_py(py))
    }

    #[pyfunction]
    fn get_tuning(py: Python<'_>) -> PyResult<PyObject> {
        let t = super::get_tuning();
        let dict = pyo3::types::PyDict::new_bound(py);
        dict.set_item("codeql_ram_mb", t.codeql_ram_mb)?;
        dict.set_item("codeql_threads", t.codeql_threads)?;
        dict.set_item("max_semgrep_workers", t.max_semgrep_workers)?;
        dict.set_item("max_codeql_workers", t.max_codeql_workers)?;
        dict.set_item("max_agentic_parallel", t.max_agentic_parallel)?;
        dict.set_item("max_fuzz_parallel", t.max_fuzz_parallel)?;
        dict.set_item("max_inventory_workers", t.max_inventory_workers)?;
        dict.set_item("max_json_memo_mb", t.max_json_memo_mb)?;
        Ok(dict.into_py(py))
    }

    #[pymodule]
    fn mantishack_core_tuning(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(load_tuning, m)?)?;
        m.add_function(wrap_pyfunction!(get_tuning, m)?)?;
        Ok(())
    }
}

// ── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---------- resolve golden vectors ----------
    // Generated by running the original Python core/tuning/__init__._resolve

    #[test]
    fn defaults_max_json_memo_mb() {
        let t = resolve(&json!({}));
        assert_eq!(t.max_json_memo_mb, 128);
    }

    #[test]
    fn defaults_max_agentic_parallel() {
        let t = resolve(&json!({}));
        assert_eq!(t.max_agentic_parallel, 3);
    }

    #[test]
    fn defaults_max_codeql_workers() {
        let t = resolve(&json!({}));
        assert_eq!(t.max_codeql_workers, 2);
    }

    #[test]
    fn defaults_max_semgrep_workers() {
        let t = resolve(&json!({}));
        assert_eq!(t.max_semgrep_workers, 4);
    }

    #[test]
    fn defaults_max_fuzz_parallel() {
        let t = resolve(&json!({}));
        assert_eq!(t.max_fuzz_parallel, 4);
    }

    #[test]
    fn codeql_threads_auto_always_zero() {
        // Python: _detect_threads() always returns 0
        let t = resolve(&json!({}));
        assert_eq!(t.codeql_threads, 0);
    }

    #[test]
    fn override_max_json_memo_mb() {
        // Python: resolve({'max_json_memo_mb': 256}) → 256
        let t = resolve(&json!({"max_json_memo_mb": 256}));
        assert_eq!(t.max_json_memo_mb, 256);
    }

    #[test]
    fn invalid_auto_max_json_memo_mb_falls_back_to_default() {
        // Python: "auto" not supported for max_json_memo_mb → falls back to 128
        let t = resolve(&json!({"max_json_memo_mb": "auto"}));
        assert_eq!(t.max_json_memo_mb, 128);
    }

    #[test]
    fn invalid_negative_falls_back_to_default() {
        // Python: max_json_memo_mb=-1 → invalid (min_val=1) → default 128
        let t = resolve(&json!({"max_json_memo_mb": -1}));
        assert_eq!(t.max_json_memo_mb, 128);
    }

    #[test]
    fn invalid_zero_falls_back_to_default() {
        // Python: max_json_memo_mb=0 → invalid (min_val=1) → default 128
        let t = resolve(&json!({"max_json_memo_mb": 0}));
        assert_eq!(t.max_json_memo_mb, 128);
    }

    #[test]
    fn float_integer_accepted() {
        // Python: max_json_memo_mb=4.0 → accepted as 4
        let t = resolve(&json!({"max_json_memo_mb": 4.0}));
        assert_eq!(t.max_json_memo_mb, 4);
    }

    #[test]
    fn codeql_threads_zero_is_valid() {
        // Python: ZERO_ALLOWED includes "codeql_threads"; 0 is a valid value
        let t = resolve(&json!({"codeql_threads": 0}));
        assert_eq!(t.codeql_threads, 0);
    }

    #[test]
    fn unknown_key_ignored() {
        // Python: unknown key warns and is ignored; other values resolve normally
        let t = resolve(&json!({"unknown_key": 999}));
        assert_eq!(t.max_json_memo_mb, 128);
        assert_eq!(t.max_agentic_parallel, 3);
    }

    #[test]
    fn codeql_ram_mb_auto_positive() {
        // auto-resolved — just verify it's a positive integer
        let t = resolve(&json!({}));
        assert!(t.codeql_ram_mb >= 1);
    }

    #[test]
    fn max_inventory_workers_auto_positive() {
        // auto-resolved — capped at 8
        let t = resolve(&json!({}));
        assert!(t.max_inventory_workers >= 1);
        assert!(t.max_inventory_workers <= 8);
    }

    #[test]
    fn load_tuning_missing_file_uses_defaults() {
        // Non-existent path → fall back to all defaults
        let t = load_tuning(Some(Path::new("/nonexistent/tuning.json")));
        assert_eq!(t.max_json_memo_mb, 128);
        assert_eq!(t.max_agentic_parallel, 3);
    }

    #[test]
    fn load_tuning_from_file() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, r#"{{"max_json_memo_mb": 64, "max_agentic_parallel": 5}}"#).unwrap();
        let t = load_tuning(Some(f.path()));
        assert_eq!(t.max_json_memo_mb, 64);
        assert_eq!(t.max_agentic_parallel, 5);
    }

    #[test]
    fn load_tuning_from_file_with_comments() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            f,
            "// tuning config\n{{\"max_json_memo_mb\": 32 // thirty-two\n}}"
        )
        .unwrap();
        let t = load_tuning(Some(f.path()));
        assert_eq!(t.max_json_memo_mb, 32);
    }

    #[test]
    fn get_tuning_is_cached_on_same_file() {
        // Calling twice should return same values (at minimum they should be equal)
        let t1 = get_tuning();
        let t2 = get_tuning();
        assert_eq!(t1.max_json_memo_mb, t2.max_json_memo_mb);
        assert_eq!(t1.max_agentic_parallel, t2.max_agentic_parallel);
    }
}
