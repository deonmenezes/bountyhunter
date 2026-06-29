//! Coverage record builder for Semgrep — faithful port of `packages/semgrep/coverage.py`.
//! Same shape as Coccinelle/CodeQL records.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::SemgrepResult;

/// Build a `coverage-semgrep.json` record from in-memory `SemgrepResult` objects.
///
/// Aggregates `files_examined` and `files_failed` across all results. Returns
/// `None` if no files were examined across any result (no point writing an empty
/// record). Mirrors Python `to_coverage_record`.
pub fn to_coverage_record(
    results: &[SemgrepResult],
    rules_applied: Option<&[String]>,
) -> Option<serde_json::Value> {
    let mut files: HashSet<String> = HashSet::new();
    let mut failures: Vec<serde_json::Value> = Vec::new();
    let mut versions: Vec<String> = Vec::new();
    // Python: dict.fromkeys(derived_rules) — preserves insertion order, deduplicates.
    let mut derived_rules: Vec<String> = Vec::new();
    let mut seen_rules: HashSet<String> = HashSet::new();

    for r in results {
        for f in &r.files_examined {
            files.insert(f.clone());
        }
        for f in &r.files_failed {
            // Python: failures.append({"rule": r.name or "semgrep", "path": ..., "reason": ...})
            let rule_label = if r.name.is_empty() {
                "semgrep".to_string()
            } else {
                r.name.clone()
            };
            failures.push(serde_json::json!({
                "rule":   rule_label,
                "path":   f.get("path").map(|s| s.as_str()).unwrap_or(""),
                "reason": f.get("reason").map(|s| s.as_str()).unwrap_or("error"),
            }));
        }
        for err in &r.errors {
            let rule_label = if r.name.is_empty() {
                "semgrep".to_string()
            } else {
                r.name.clone()
            };
            failures.push(serde_json::json!({
                "rule":   rule_label,
                "reason": err,
            }));
        }
        if !r.semgrep_version.is_empty() {
            versions.push(r.semgrep_version.clone());
        }
        if !r.name.is_empty() && !seen_rules.contains(&r.name) {
            seen_rules.insert(r.name.clone());
            derived_rules.push(r.name.clone());
        }
    }

    // Python: `if not files: return None`
    if files.is_empty() {
        return None;
    }

    let mut files_sorted: Vec<String> = files.into_iter().collect();
    files_sorted.sort();

    let mut record = serde_json::json!({
        "tool":           "semgrep",
        "timestamp":      utc_now_iso(),
        "files_examined": files_sorted,
    });

    // Python: rules = rules_applied if rules_applied is not None else list(dict.fromkeys(...))
    let rules: Vec<String> = if let Some(ra) = rules_applied {
        ra.to_vec()
    } else {
        derived_rules
    };
    if !rules.is_empty() {
        record["rules_applied"] = serde_json::Value::Array(
            rules.into_iter().map(serde_json::Value::String).collect(),
        );
    }
    // Python: if versions: record["version"] = versions[0]
    if let Some(v) = versions.first() {
        record["version"] = serde_json::Value::String(v.clone());
    }
    if !failures.is_empty() {
        record["files_failed"] = serde_json::Value::Array(failures);
    }

    Some(record)
}

// ── timestamp helper ──────────────────────────────────────────────────────────

/// Format the current UTC time as an ISO 8601 string.
/// Mirrors Python `datetime.now(timezone.utc).isoformat()`.
fn utc_now_iso() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let (year, month, day, hour, min, sec) = unix_secs_to_datetime(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}+00:00",
        year, month, day, hour, min, sec
    )
}

/// Convert Unix seconds to (year, month, day, hour, min, sec) in UTC.
/// Uses the algorithm from <http://howardhinnant.github.io/date_algorithms.html>
/// `civil_from_days`.
fn unix_secs_to_datetime(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
    let time_of_day = secs % 86400;
    let h = (time_of_day / 3600) as u32;
    let m = ((time_of_day % 3600) / 60) as u32;
    let s = (time_of_day % 60) as u32;

    // civil_from_days: converts days-since-epoch (1970-01-01) to Gregorian date.
    let z: i64 = (secs / 86400) as i64 + 719_468;
    let era: i64 = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe: i64 = z - era * 146_097; // [0, 146096]
    let yoe: i64 = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let year: i32 = (yoe + era * 400) as i32;
    let doy: i64 = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp: i64 = (5 * doy + 2) / 153; // [0, 11]
    let day: u32 = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month: u32 = if mp < 10 { (mp + 3) as u32 } else { (mp - 9) as u32 }; // [1, 12]
    let year: i32 = if month <= 2 { year + 1 } else { year };

    (year, month, day, h, m, s)
}
