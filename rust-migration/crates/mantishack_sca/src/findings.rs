//! Findings-layer pure helpers — Rust port of the self-contained functions in
//! `packages/sca/findings.py`. The full finding-assembly pipeline
//! (`build_vuln_findings`, `_assemble_finding`) depends on the KEV/EPSS/
//! Vulnrichment HTTP clients and stays in Python; the pure advisory helpers +
//! severity ranking port here. Advisories are modelled as OSV `Value` dicts
//! (`osv_id`, `aliases`, `severity.severity`).

use std::collections::HashMap;

use serde_json::Value;

use crate::models::Dependency;

/// Rank for a severity string (`_SEVERITY_RANK`). `info`/`none` = 0.
fn severity_rank_lookup(sev: &str) -> Option<i32> {
    match sev {
        "info" | "none" => Some(0),
        "low" => Some(1),
        "medium" => Some(2),
        "high" => Some(3),
        "critical" => Some(4),
        _ => None,
    }
}

/// Return the rank for a severity string (`severity_rank`). Case-insensitive
/// (LLM/hand-edited findings often capitalise); unknown or empty → 0.
pub fn severity_rank(severity: &str) -> i32 {
    if severity.is_empty() {
        return 0;
    }
    severity_rank_lookup(&severity.to_lowercase()).unwrap_or(0)
}

/// Sort priority for an OSV id (`_advisory_priority`); lower is preferred.
pub fn advisory_priority(osv_id: &str) -> i32 {
    let p = osv_id.to_uppercase();
    if p.starts_with("GHSA-") {
        0
    } else if p.starts_with("CVE-") {
        1
    } else if p.starts_with("PYSEC-") || p.starts_with("OSV-") {
        2
    } else {
        3
    }
}

/// Severity string for an advisory (`_severity_for_advisory`); degrades to
/// `"medium"` when there's no valid CVSS severity.
pub fn severity_for_advisory(advisory: &Value) -> String {
    if let Some(sev) = advisory.get("severity").and_then(Value::as_object) {
        if let Some(s) = sev.get("severity").and_then(Value::as_str) {
            if matches!(s, "none" | "low" | "medium" | "high" | "critical") {
                return s.to_string();
            }
        }
    }
    "medium".to_string()
}

/// Per-ecosystem `a < b`, falling back to string comparison on a parse error
/// (mirrors `_Sortable.__lt__`).
fn sortable_lt(ecosystem: &str, a: &str, b: &str) -> bool {
    match mantishack_sca_versions::compare(ecosystem, a, b) {
        Ok(c) => c < 0,
        Err(_) => a < b,
    }
}

/// Leftmost minimum of `list` by the per-ecosystem version order.
fn min_by_version<'a>(ecosystem: &str, list: &'a [String]) -> &'a String {
    let mut best = &list[0];
    for x in &list[1..] {
        if sortable_lt(ecosystem, x, best) {
            best = x;
        }
    }
    best
}

/// Smallest fix version that upgrades from `installed`, else the global smallest
/// (`_smallest_applicable_fix`). `None` when there are no fixes.
pub fn smallest_applicable_fix(
    ecosystem: &str,
    installed: Option<&str>,
    fixed_versions: &[String],
) -> Option<String> {
    if fixed_versions.is_empty() {
        return None;
    }
    if installed.is_none() || fixed_versions.len() == 1 {
        return Some(min_by_version(ecosystem, fixed_versions).clone());
    }
    let installed = installed.unwrap();
    let upgrades: Vec<String> = fixed_versions
        .iter()
        .filter(|v| matches!(mantishack_sca_versions::compare(ecosystem, v, installed), Ok(c) if c > 0))
        .cloned()
        .collect();
    let pool = if upgrades.is_empty() { fixed_versions } else { &upgrades };
    Some(min_by_version(ecosystem, pool).clone())
}

/// Deterministic vuln-finding id (`_vuln_finding_id`).
pub fn vuln_finding_id(dep: &Dependency, osv_id: &str) -> String {
    let version = dep.version.as_deref().filter(|v| !v.is_empty()).unwrap_or("*");
    format!("sca:vuln:{}:{}:{}:{}", dep.ecosystem, dep.name, version, osv_id)
}

/// Collapse advisories pointing at the same CVE (`_dedup_alias_advisories`),
/// keyed on the first `CVE-*` alias (else the OSV id), preferring
/// GHSA > CVE > PYSEC/OSV > other. Order follows first appearance.
pub fn dedup_alias_advisories(advisories: &[Value]) -> Vec<Value> {
    let mut by_key: HashMap<String, Value> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for a in advisories {
        let cve = a
            .get("aliases")
            .and_then(Value::as_array)
            .and_then(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .find(|x| x.to_uppercase().starts_with("CVE-"))
            });
        let osv_id = a.get("osv_id").and_then(Value::as_str).unwrap_or("");
        let key = cve.map(|c| c.to_uppercase()).unwrap_or_else(|| osv_id.to_string());
        if !by_key.contains_key(&key) {
            by_key.insert(key.clone(), a.clone());
            order.push(key);
        } else {
            let existing = by_key[&key].get("osv_id").and_then(Value::as_str).unwrap_or("");
            if advisory_priority(osv_id) < advisory_priority(existing) {
                by_key.insert(key, a.clone());
            }
        }
    }
    order.into_iter().map(|k| by_key[&k].clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ranks_and_case_insensitivity() {
        assert_eq!(severity_rank("info"), 0);
        assert_eq!(severity_rank("none"), 0);
        assert_eq!(severity_rank("low"), 1);
        assert_eq!(severity_rank("medium"), 2);
        assert_eq!(severity_rank("high"), 3);
        assert_eq!(severity_rank("critical"), 4);
        // Case-insensitive.
        assert_eq!(severity_rank("Critical"), 4);
        assert_eq!(severity_rank("HIGH"), 3);
        assert_eq!(severity_rank("Medium"), 2);
        // Unknown + empty -> 0.
        assert_eq!(severity_rank("bogus"), 0);
        assert_eq!(severity_rank(""), 0);
    }

    use crate::models::{Confidence, PinStyle};

    fn dep() -> Dependency {
        Dependency {
            ecosystem: "npm".into(), name: "lodash".into(), version: Some("1.0".into()),
            declared_in: "p".into(), scope: "main".into(), is_lockfile: false,
            pin_style: PinStyle::Exact, direct: true, purl: "p".into(),
            parser_confidence: Confidence::new("high", ""), declared_license: None,
            commented_out: false, source_kind: "manifest".into(), source_extra: None,
        }
    }
    fn vers(vs: &[&str]) -> Vec<String> {
        vs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn advisory_helpers() {
        assert_eq!(advisory_priority("GHSA-a"), 0);
        assert_eq!(advisory_priority("CVE-1"), 1);
        assert_eq!(advisory_priority("PYSEC-2"), 2);
        assert_eq!(advisory_priority("OSV-3"), 2);
        assert_eq!(advisory_priority("RUSTSEC-4"), 3);

        assert_eq!(severity_for_advisory(&json!({"severity": {"severity": "critical"}})), "critical");
        assert_eq!(severity_for_advisory(&json!({"severity": {"severity": "bogus"}})), "medium");
        assert_eq!(severity_for_advisory(&json!({})), "medium");

        assert_eq!(vuln_finding_id(&dep(), "GHSA-xyz"), "sca:vuln:npm:lodash:1.0:GHSA-xyz");
    }

    #[test]
    fn smallest_fix() {
        // Closest upgrade above the installed version (not a cross-major downgrade).
        assert_eq!(smallest_applicable_fix("npm", Some("2.0.0"), &vers(&["1.10.13", "2.4.0", "2.1.0"])).as_deref(), Some("2.1.0"));
        // Installed past every fix -> global smallest.
        assert_eq!(smallest_applicable_fix("npm", Some("9.0.0"), &vers(&["1.0.0", "2.0.0"])).as_deref(), Some("1.0.0"));
        assert_eq!(smallest_applicable_fix("npm", None, &vers(&["2.0.0", "1.0.0"])).as_deref(), Some("1.0.0"));
        assert_eq!(smallest_applicable_fix("npm", Some("5.0.0"), &vers(&["3.0.0"])).as_deref(), Some("3.0.0"));
        assert_eq!(smallest_applicable_fix("npm", Some("1.0"), &[]), None);
    }

    #[test]
    fn dedup_prefers_ghsa() {
        let ads = vec![
            json!({"osv_id": "CVE-100", "aliases": ["CVE-2021-1"]}),
            json!({"osv_id": "GHSA-aa", "aliases": ["CVE-2021-1"]}),
            json!({"osv_id": "PYSEC-9", "aliases": ["CVE-2021-1"]}),
            json!({"osv_id": "OSV-solo", "aliases": []}),
        ];
        let ids: Vec<String> = dedup_alias_advisories(&ads).iter().map(|a| a["osv_id"].as_str().unwrap().to_string()).collect();
        assert_eq!(ids, vec!["GHSA-aa".to_string(), "OSV-solo".to_string()]);
    }
}
